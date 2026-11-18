//! HPACK header-block decoder (RFC 7541 §6).

use bytes::Bytes;
use http::{HeaderName, HeaderValue};

use super::{
    HpackError, huffman,
    int::decode_int,
    table::{DynamicTable, ENTRY_OVERHEAD, get_indexed, get_indexed_name},
};

/// One header field emitted by [`Decoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedField {
    /// Raw field name bytes.
    pub name: Bytes,
    /// Raw field value bytes.
    pub value: Bytes,
    /// Cached validated `http::HeaderName` when resolved from the static or
    /// dynamic table.
    pub parsed_name: Option<HeaderName>,
    /// Cached validated `http::HeaderValue` when resolved from the static or
    /// dynamic table.
    pub parsed_value: Option<HeaderValue>,
    /// True if decoded from a Never-Indexed representation (`0001xxxx`).
    pub sensitive: bool,
}

/// Result of decoding one complete HPACK header block under a header-list size
/// budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeOutcome {
    /// All fields fit within `max_header_list_size`.
    Fields(Vec<DecodedField>),
    /// The uncompressed header list exceeded `limit`, while dynamic-table
    /// state remained synchronized across the block (RFC 9113 §10.5.1).
    TooLarge {
        /// Configured `SETTINGS_MAX_HEADER_LIST_SIZE`.
        limit: u32,
    },
}

/// Stateful HPACK connection decoder.
#[derive(Debug, Clone)]
pub struct Decoder {
    table: DynamicTable,
    max_allowed_size: usize,
    pending_min_size: Option<usize>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(4_096)
    }
}

impl Decoder {
    /// Creates a decoder advertising an initial `SETTINGS_HEADER_TABLE_SIZE` of
    /// `max_table_size` bytes.
    #[must_use]
    pub fn new(max_table_size: u32) -> Self {
        let cap = max_table_size as usize;
        Self {
            table: DynamicTable::new(cap),
            max_allowed_size: cap,
            pending_min_size: None,
        }
    }

    /// Current byte size of entries stored in the dynamic table.
    #[must_use]
    pub const fn dynamic_table_size(&self) -> usize {
        self.table.size()
    }

    /// Current dynamic-table capacity set by the peer's encoder.
    #[must_use]
    pub const fn dynamic_table_max_size(&self) -> usize {
        self.table.max_size()
    }

    /// Number of entries currently stored in the dynamic table.
    #[must_use]
    pub fn dynamic_table_len(&self) -> usize {
        self.table.len()
    }

    /// Updates the peer-permitted maximum dynamic table size after a local
    /// `SETTINGS_HEADER_TABLE_SIZE` change takes effect (RFC 7541 §4.2).
    ///
    /// When the new maximum reduces the encoder's current table capacity, the
    /// peer's next non-empty header block must begin with a dynamic table size
    /// update at or below the smallest intermediate maximum.
    pub fn set_max_table_size(&mut self, new_max: u32) {
        let cap = new_max as usize;
        if cap < self.table.max_size() {
            self.pending_min_size = Some(match self.pending_min_size {
                Some(prev) => prev.min(cap),
                None => cap,
            });
        }
        self.max_allowed_size = cap;
    }

    /// Decodes a complete reassembled header block (`HEADERS` + any
    /// `CONTINUATION` payloads) using zero-copy [`Bytes`] slices of `block`
    /// for non-Huffman literals.
    ///
    /// # Errors
    ///
    /// Returns [`HpackError`] on any RFC 7541 wire or dynamic-table violation
    /// (`COMPRESSION_ERROR`).
    pub fn decode(
        &mut self,
        block: &Bytes,
        max_header_list_size: u32,
    ) -> Result<DecodeOutcome, HpackError> {
        let buf = block.as_ref();
        let mut pos = 0usize;

        // Phase 1: zero or more dynamic table size updates (`001xxxxx`), allowed
        // ONLY before the first header field representation (RFC 7541 §4.2).
        while let Some(&first) = buf.get(pos) {
            if (first & 0xE0) != 0x20 {
                break;
            }
            let new_size = decode_int(buf, &mut pos, 5)?;
            let new_size =
                usize::try_from(new_size).map_err(|_| HpackError::InvalidTableSizeUpdate)?;
            if new_size > self.max_allowed_size {
                return Err(HpackError::InvalidTableSizeUpdate);
            }
            if let Some(min_req) = self.pending_min_size
                && new_size <= min_req
            {
                self.pending_min_size = None;
            }
            self.table.set_max_size(new_size);
        }

        if pos < buf.len() && self.pending_min_size.is_some() {
            return Err(HpackError::InvalidTableSizeUpdate);
        }

        let limit = max_header_list_size as usize;
        let mut list_size = 0usize;
        let mut exceeded = false;
        let mut fields = Vec::with_capacity(16);

        // Phase 2: header field representations.
        while let Some(&first) = buf.get(pos) {
            if first & 0x80 != 0 {
                // 6.1 Indexed Header Field (`1xxxxxxx`, 7-bit prefix)
                let index = decode_int(buf, &mut pos, 7)?;
                let (name, value, parsed_name, parsed_value) = get_indexed(&self.table, index)?;
                if !exceeded {
                    let field_size = name
                        .len()
                        .saturating_add(value.len())
                        .saturating_add(ENTRY_OVERHEAD);
                    list_size = list_size.saturating_add(field_size);
                    if list_size <= limit {
                        fields.push(DecodedField {
                            name,
                            value,
                            parsed_name,
                            parsed_value,
                            sensitive: false,
                        });
                    } else {
                        exceeded = true;
                        fields.clear();
                    }
                }
            } else if first & 0x40 != 0 {
                // 6.2.1 Literal Header Field with Incremental Indexing (`01xxxxxx`, 6-bit prefix)
                let name_index = decode_int(buf, &mut pos, 6)?;
                // Even if `exceeded` is already true, an incrementally indexed entry
                // <= `table.max_size()` must still enter the dynamic table; an entry
                // larger than `table.max_size()` merely clears the dynamic table.
                let table_cap = self.table.max_size();
                let str_cap = if exceeded {
                    table_cap
                } else {
                    limit.max(table_cap)
                };

                let (name, known_name) = if name_index == 0 {
                    (decode_string(block, &mut pos, str_cap)?, None)
                } else {
                    let (n, pn) = get_indexed_name(&self.table, name_index)?;
                    (Some(n), pn)
                };
                let value = decode_string(block, &mut pos, str_cap)?;

                match (name, value) {
                    (Some(name), Some(value)) => {
                        let field_size = name
                            .len()
                            .saturating_add(value.len())
                            .saturating_add(ENTRY_OVERHEAD);
                        self.table
                            .insert_decoded(name.clone(), value.clone(), known_name.clone());
                        if !exceeded {
                            list_size = list_size.saturating_add(field_size);
                            if list_size <= limit {
                                // Pull cached `parsed_name` / `parsed_value` if the new entry
                                // fit at index 0 of the dynamic table.
                                let (parsed_name, parsed_value) = match self.table.get(0) {
                                    Some(top)
                                        if top.name.len() == name.len()
                                            && top.value.len() == value.len() =>
                                    {
                                        (top.parsed_name.clone(), top.parsed_value.clone())
                                    }
                                    _ => (known_name, None),
                                };
                                fields.push(DecodedField {
                                    name,
                                    value,
                                    parsed_name,
                                    parsed_value,
                                    sensitive: false,
                                });
                            } else {
                                exceeded = true;
                                fields.clear();
                            }
                        }
                    }
                    _ => {
                        // Name or value alone exceeded `str_cap >= table.max_size()`,
                        // so inserting it empties the dynamic table (RFC 7541 §4.4)
                        // and exceeds `limit`.
                        self.table.clear();
                        exceeded = true;
                        fields.clear();
                    }
                }
            } else if (first & 0xE0) == 0x20 {
                // 6.3 Dynamic Table Size Update after a header field -> forbidden!
                return Err(HpackError::InvalidTableSizeUpdate);
            } else {
                // 6.2.2 Without Indexing (`0000xxxx`) or 6.2.3 Never Indexed (`0001xxxx`)
                let sensitive = (first & 0x10) != 0;
                let name_index = decode_int(buf, &mut pos, 4)?;
                let remaining_budget = if exceeded {
                    0
                } else {
                    limit.saturating_sub(list_size)
                };

                let (name, parsed_name) = if name_index == 0 {
                    (decode_string(block, &mut pos, remaining_budget)?, None)
                } else {
                    let (n, pn) = get_indexed_name(&self.table, name_index)?;
                    (Some(n), pn)
                };
                let value = decode_string(block, &mut pos, remaining_budget)?;

                if !exceeded {
                    match (name, value) {
                        (Some(name), Some(value)) => {
                            let field_size = name
                                .len()
                                .saturating_add(value.len())
                                .saturating_add(ENTRY_OVERHEAD);
                            list_size = list_size.saturating_add(field_size);
                            if list_size <= limit {
                                fields.push(DecodedField {
                                    name,
                                    value,
                                    parsed_name,
                                    parsed_value: None,
                                    sensitive,
                                });
                            } else {
                                exceeded = true;
                                fields.clear();
                            }
                        }
                        _ => {
                            exceeded = true;
                            fields.clear();
                        }
                    }
                }
            }
        }

        if exceeded {
            Ok(DecodeOutcome::TooLarge {
                limit: max_header_list_size,
            })
        } else {
            Ok(DecodeOutcome::Fields(fields))
        }
    }
}

/// Decodes a string literal at `block[*pos]`, returning `Ok(None)` if its
/// decoded length exceeds `max_decoded_len` (while still validating wire
/// framing and Huffman syntax).
fn decode_string(
    block: &Bytes,
    pos: &mut usize,
    max_decoded_len: usize,
) -> Result<Option<Bytes>, HpackError> {
    let buf = block.as_ref();
    let &first = buf.get(*pos).ok_or(HpackError::UnexpectedEof)?;
    let is_huffman = (first & 0x80) != 0;
    let raw_len = decode_int(buf, pos, 7)?;
    let raw_len = usize::try_from(raw_len).map_err(|_| HpackError::UnexpectedEof)?;
    let end = pos.checked_add(raw_len).ok_or(HpackError::UnexpectedEof)?;
    if end > buf.len() {
        return Err(HpackError::UnexpectedEof);
    }
    let start = *pos;
    *pos = end;

    if is_huffman {
        huffman::decode_bounded(&buf[start..end], max_decoded_len)
    } else if raw_len <= max_decoded_len {
        Ok(Some(block.slice(start..end)))
    } else {
        Ok(None)
    }
}
