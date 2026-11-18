//! HPACK header-block encoder (RFC 7541 §6).

use bytes::{Bytes, BytesMut};

use super::{
    huffman,
    int::encode_int,
    table::{DynamicTable, ENTRY_OVERHEAD, find_static},
};

/// One header field borrowed for HPACK encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeField<'a> {
    /// Lowercase field name (or `:pseudo` name).
    pub name: &'a [u8],
    /// Field value bytes.
    pub value: &'a [u8],
    /// When `true`, encodes with the Never-Indexed representation (`0001xxxx`)
    /// so neither this connection nor any intermediary caches the value.
    pub sensitive: bool,
}

impl<'a> EncodeField<'a> {
    /// A regular indexable field.
    #[must_use]
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            name,
            value,
            sensitive: false,
        }
    }

    /// A sensitive field encoded as Never-Indexed (`0001xxxx`).
    #[must_use]
    pub const fn sensitive(name: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            name,
            value,
            sensitive: true,
        }
    }
}

/// Stateful HPACK connection encoder.
#[derive(Debug, Clone)]
pub struct Encoder {
    table: DynamicTable,
    local_cap: usize,
    target_size: usize,
    pending_min_size: Option<usize>,
    size_update_queued: bool,
    use_huffman: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new(4_096)
    }
}

impl Encoder {
    /// Creates an encoder capping its own dynamic table at `max_local_size`
    /// bytes (assuming the peer's initial `SETTINGS_HEADER_TABLE_SIZE` of
    /// `4_096` until updated).
    #[must_use]
    pub fn new(max_local_size: u32) -> Self {
        let local_cap = max_local_size as usize;
        let initial = local_cap.min(4_096);
        let size_update_queued = initial < 4_096;
        Self {
            table: DynamicTable::new(initial),
            local_cap,
            target_size: initial,
            pending_min_size: size_update_queued.then_some(initial),
            size_update_queued,
            use_huffman: true,
        }
    }

    /// Enables or disables Huffman coding of string literals (enabled by
    /// default whenever shorter than the raw byte length).
    pub fn set_huffman(&mut self, enabled: bool) {
        self.use_huffman = enabled;
    }

    /// Current byte size of entries stored in the encoder's dynamic table.
    #[must_use]
    pub const fn dynamic_table_size(&self) -> usize {
        self.table.size()
    }

    /// Current dynamic-table capacity.
    #[must_use]
    pub const fn dynamic_table_max_size(&self) -> usize {
        self.table.max_size()
    }

    /// Applies a `SETTINGS_HEADER_TABLE_SIZE` value advertised by the peer
    /// (RFC 7541 §4.2).
    ///
    /// Tracks the minimum size observed since the last encoded header block so
    /// intermediate reductions are signaled before raising the capacity again.
    pub fn set_peer_max_table_size(&mut self, peer_max: u32) {
        let new_target = (peer_max as usize).min(self.local_cap);
        self.pending_min_size = Some(match self.pending_min_size {
            Some(min_seen) => min_seen.min(new_target),
            None => new_target,
        });
        self.target_size = new_target;
        self.size_update_queued = true;
    }

    /// Encodes `fields` as one HPACK header block onto `out`.
    pub fn encode<'a>(
        &mut self,
        fields: impl IntoIterator<Item = EncodeField<'a>>,
        out: &mut BytesMut,
    ) {
        self.flush_size_updates(out);
        for field in fields {
            self.encode_one(field, out);
        }
    }

    /// Emits any pending RFC 7541 §4.2 dynamic table size updates at the start
    /// of a header block.
    pub fn flush_size_updates(&mut self, out: &mut BytesMut) {
        if !self.size_update_queued {
            return;
        }
        self.size_update_queued = false;
        if let Some(min_size) = self.pending_min_size.take()
            && min_size < self.target_size
        {
            self.table.set_max_size(min_size);
            encode_int(min_size as u64, 5, 0x20, out);
        }
        self.table.set_max_size(self.target_size);
        encode_int(self.target_size as u64, 5, 0x20, out);
    }

    /// Encodes a single field (caller must call [`flush_size_updates`](Self::flush_size_updates)
    /// once before the first field of each header block).
    pub fn encode_one(&mut self, field: EncodeField<'_>, out: &mut BytesMut) {
        let sensitive = field.sensitive || is_auto_sensitive(field.name);
        let (static_full, static_name) = find_static(field.name, field.value);

        if !sensitive {
            if let Some(idx) = static_full {
                encode_int(idx as u64, 7, 0x80, out);
                return;
            }
            let (dyn_full, dyn_name) = self.table.find(field.name, field.value);
            if let Some(idx) = dyn_full {
                encode_int(idx as u64, 7, 0x80, out);
                return;
            }
            let name_idx = static_name.or(dyn_name);
            if self.should_index(field.name, field.value) {
                match name_idx {
                    Some(idx) => encode_int(idx as u64, 6, 0x40, out),
                    None => {
                        out.extend_from_slice(&[0x40]);
                        self.encode_string(field.name, out);
                    }
                }
                self.encode_string(field.value, out);
                self.table.insert_raw(
                    Bytes::copy_from_slice(field.name),
                    Bytes::copy_from_slice(field.value),
                );
                return;
            }
            // Without indexing (`0000xxxx`, 4-bit prefix).
            match name_idx {
                Some(idx) => encode_int(idx as u64, 4, 0x00, out),
                None => {
                    out.extend_from_slice(&[0x00]);
                    self.encode_string(field.name, out);
                }
            }
            self.encode_string(field.value, out);
        } else {
            // Never indexed (`0001xxxx`, 4-bit prefix).
            let (_, dyn_name) = self.table.find(field.name, &[]);
            match static_name.or(dyn_name) {
                Some(idx) => encode_int(idx as u64, 4, 0x10, out),
                None => {
                    out.extend_from_slice(&[0x10]);
                    self.encode_string(field.name, out);
                }
            }
            self.encode_string(field.value, out);
        }
    }

    fn should_index(&self, name: &[u8], value: &[u8]) -> bool {
        if self.table.max_size() == 0 {
            return false;
        }
        // Per-request ephemeral values (`content-length`, `:path` when long)
        // churn the dynamic table if indexed unconditionally.
        if name == b"content-length" || (name == b":path" && value.len() > 64) {
            return false;
        }
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
        // Avoid evicting >75% of the dynamic table for a single oversized header.
        entry_size * 4 <= self.table.max_size() * 3
    }

    fn encode_string(&self, bytes: &[u8], out: &mut BytesMut) {
        if self.use_huffman {
            let huff_len = huffman::encoded_len(bytes);
            if huff_len < bytes.len() {
                encode_int(huff_len as u64, 7, 0x80, out);
                huffman::encode(bytes, out);
                return;
            }
        }
        encode_int(bytes.len() as u64, 7, 0x00, out);
        out.extend_from_slice(bytes);
    }
}

#[inline]
fn is_auto_sensitive(name: &[u8]) -> bool {
    matches!(name, b"authorization" | b"proxy-authorization")
}
