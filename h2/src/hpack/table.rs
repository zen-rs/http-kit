//! HPACK static table (RFC 7541 Appendix A) and bounded dynamic table
//! (RFC 7541 §2.3.2, §4).

use std::collections::VecDeque;

use bytes::Bytes;
use http::{HeaderName, HeaderValue};

use crate::simd;

use super::HpackError;

/// Per-entry byte overhead defined by RFC 7541 §4.1 (`name.len() + value.len() + 32`).
pub const ENTRY_OVERHEAD: usize = 32;

/// Number of entries in the RFC 7541 Appendix A static table (`1..=61`).
pub const STATIC_TABLE_LEN: usize = 61;

#[derive(Clone)]
pub(super) struct StaticEntry {
    pub(super) name: &'static [u8],
    pub(super) value: &'static [u8],
    pub(super) parsed_name: Option<HeaderName>,
    pub(super) parsed_value: HeaderValue,
}

macro_rules! pseudo {
    ($name:literal, $val:literal) => {
        StaticEntry {
            name: $name.as_bytes(),
            value: $val.as_bytes(),
            parsed_name: None,
            parsed_value: HeaderValue::from_static($val),
        }
    };
}

macro_rules! regular {
    ($name:literal, $val:literal) => {
        StaticEntry {
            name: $name.as_bytes(),
            value: $val.as_bytes(),
            parsed_name: Some(HeaderName::from_static($name)),
            parsed_value: HeaderValue::from_static($val),
        }
    };
}

/// RFC 7541 Appendix A static table (1-indexed on the wire: `STATIC_TABLE[idx - 1]`).
pub(super) const STATIC_TABLE: [StaticEntry; STATIC_TABLE_LEN] = [
    pseudo!(":authority", ""),                    // 1
    pseudo!(":method", "GET"),                    // 2
    pseudo!(":method", "POST"),                   // 3
    pseudo!(":path", "/"),                        // 4
    pseudo!(":path", "/index.html"),              // 5
    pseudo!(":scheme", "http"),                   // 6
    pseudo!(":scheme", "https"),                  // 7
    pseudo!(":status", "200"),                    // 8
    pseudo!(":status", "204"),                    // 9
    pseudo!(":status", "206"),                    // 10
    pseudo!(":status", "304"),                    // 11
    pseudo!(":status", "400"),                    // 12
    pseudo!(":status", "404"),                    // 13
    pseudo!(":status", "500"),                    // 14
    regular!("accept-charset", ""),               // 15
    regular!("accept-encoding", "gzip, deflate"), // 16
    regular!("accept-language", ""),              // 17
    regular!("accept-ranges", ""),                // 18
    regular!("accept", ""),                       // 19
    regular!("access-control-allow-origin", ""),  // 20
    regular!("age", ""),                          // 21
    regular!("allow", ""),                        // 22
    regular!("authorization", ""),                // 23
    regular!("cache-control", ""),                // 24
    regular!("content-disposition", ""),          // 25
    regular!("content-encoding", ""),             // 26
    regular!("content-language", ""),             // 27
    regular!("content-length", ""),               // 28
    regular!("content-location", ""),             // 29
    regular!("content-range", ""),                // 30
    regular!("content-type", ""),                 // 31
    regular!("cookie", ""),                       // 32
    regular!("date", ""),                         // 33
    regular!("etag", ""),                         // 34
    regular!("expect", ""),                       // 35
    regular!("expires", ""),                      // 36
    regular!("from", ""),                         // 37
    regular!("host", ""),                         // 38
    regular!("if-match", ""),                     // 39
    regular!("if-modified-since", ""),            // 40
    regular!("if-none-match", ""),                // 41
    regular!("if-range", ""),                     // 42
    regular!("if-unmodified-since", ""),          // 43
    regular!("last-modified", ""),                // 44
    regular!("link", ""),                         // 45
    regular!("location", ""),                     // 46
    regular!("max-forwards", ""),                 // 47
    regular!("proxy-authenticate", ""),           // 48
    regular!("proxy-authorization", ""),          // 49
    regular!("range", ""),                        // 50
    regular!("referer", ""),                      // 51
    regular!("refresh", ""),                      // 52
    regular!("retry-after", ""),                  // 53
    regular!("server", ""),                       // 54
    regular!("set-cookie", ""),                   // 55
    regular!("strict-transport-security", ""),    // 56
    regular!("transfer-encoding", ""),            // 57
    regular!("user-agent", ""),                   // 58
    regular!("vary", ""),                         // 59
    regular!("via", ""),                          // 60
    regular!("www-authenticate", ""),             // 61
];

/// Looks up `(full_match_index, name_only_index)` in [`STATIC_TABLE`].
#[inline]
pub(super) fn find_static(name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
    let candidates: &[usize] = match name.first() {
        Some(&b':') => match name {
            b":authority" => &[1],
            b":method" => &[2, 3],
            b":path" => &[4, 5],
            b":scheme" => &[6, 7],
            b":status" => &[8, 9, 10, 11, 12, 13, 14],
            _ => return (None, None),
        },
        Some(&b'a') => &[15, 16, 17, 18, 19, 20, 21, 22, 23],
        Some(&b'c') => &[24, 25, 26, 27, 28, 29, 30, 31, 32],
        Some(&b'd') => &[33],
        Some(&b'e') => &[34, 35, 36],
        Some(&b'f') => &[37],
        Some(&b'h') => &[38],
        Some(&b'i') => &[39, 40, 41, 42, 43],
        Some(&b'l') => &[44, 45, 46],
        Some(&b'm') => &[47],
        Some(&b'p') => &[48, 49],
        Some(&b'r') => &[50, 51, 52, 53],
        Some(&b's') => &[54, 55, 56],
        Some(&b't') => &[57],
        Some(&b'u') => &[58],
        Some(&b'v') => &[59, 60],
        Some(&b'w') => &[61],
        _ => return (None, None),
    };

    let mut name_idx = None;
    for &idx in candidates {
        let entry = &STATIC_TABLE[idx - 1];
        if entry.name == name {
            if name_idx.is_none() {
                name_idx = Some(idx);
            }
            if entry.value == value {
                return (Some(idx), Some(idx));
            }
        }
    }
    (None, name_idx)
}

#[derive(Debug, Clone)]
pub(super) struct DynamicEntry {
    pub(super) name: Bytes,
    pub(super) value: Bytes,
    pub(super) parsed_name: Option<HeaderName>,
    pub(super) parsed_value: Option<HeaderValue>,
}

impl DynamicEntry {
    #[inline]
    pub(super) fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// Bounded FIFO dynamic table (`entries[0]` is newest, wire index `62`).
#[derive(Debug, Clone)]
pub(super) struct DynamicTable {
    entries: VecDeque<DynamicEntry>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    pub(super) fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    #[inline]
    pub(super) const fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub(super) const fn max_size(&self) -> usize {
        self.max_size
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn set_max_size(&mut self, new_max: usize) {
        self.max_size = new_max;
        self.evict_to(new_max);
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.size = 0;
    }

    /// Inserts `(name, value)` into the decoder's dynamic table, pre-validating
    /// and caching `HeaderName` and `HeaderValue` once so subsequent indexed
    /// lookups skip validation.
    pub(super) fn insert_decoded(
        &mut self,
        name: Bytes,
        value: Bytes,
        known_name: Option<HeaderName>,
    ) {
        let entry_size = name
            .len()
            .saturating_add(value.len())
            .saturating_add(ENTRY_OVERHEAD);
        if entry_size > self.max_size {
            self.clear();
            return;
        }
        self.evict_to(self.max_size - entry_size);
        let parsed_name = known_name.or_else(|| {
            (!name.starts_with(b":") && simd::validate_field_name(&name))
                .then(|| HeaderName::from_bytes(&name).ok())
                .flatten()
        });
        let parsed_value = simd::validate_field_value(&value)
            .then(|| HeaderValue::from_maybe_shared(value.clone()).ok())
            .flatten();
        self.entries.push_front(DynamicEntry {
            name,
            value,
            parsed_name,
            parsed_value,
        });
        self.size += entry_size;
    }

    /// Inserts `(name, value)` into the encoder's dynamic table (no parsed
    /// `http` types needed).
    pub(super) fn insert_raw(&mut self, name: Bytes, value: Bytes) {
        let entry_size = name
            .len()
            .saturating_add(value.len())
            .saturating_add(ENTRY_OVERHEAD);
        if entry_size > self.max_size {
            self.clear();
            return;
        }
        self.evict_to(self.max_size - entry_size);
        self.entries.push_front(DynamicEntry {
            name,
            value,
            parsed_name: None,
            parsed_value: None,
        });
        self.size += entry_size;
    }

    #[inline]
    pub(super) fn get(&self, dynamic_zero_based: usize) -> Option<&DynamicEntry> {
        self.entries.get(dynamic_zero_based)
    }

    /// Searches recent dynamic entries for `(full, name_only)` 1-based HPACK
    /// wire indices (`>= 62`).
    pub(super) fn find(&self, name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
        let mut name_idx = None;
        for (offset, entry) in self.entries.iter().take(64).enumerate() {
            if entry.name.len() == name.len() && entry.name.as_ref() == name {
                let wire_idx = STATIC_TABLE_LEN + 1 + offset;
                if name_idx.is_none() {
                    name_idx = Some(wire_idx);
                }
                if entry.value.len() == value.len() && entry.value.as_ref() == value {
                    return (Some(wire_idx), name_idx);
                }
            }
        }
        (None, name_idx)
    }

    fn evict_to(&mut self, target: usize) {
        while self.size > target {
            let evicted = self
                .entries
                .pop_back()
                .expect("non-zero size implies non-empty table");
            self.size -= evicted.size();
        }
    }
}

/// Resolves a 1-based HPACK index into `(name, value, parsed_name, parsed_value)`.
#[inline]
pub(super) fn get_indexed(
    table: &DynamicTable,
    index: u64,
) -> Result<(Bytes, Bytes, Option<HeaderName>, Option<HeaderValue>), HpackError> {
    if index == 0 {
        return Err(HpackError::InvalidTableIndex);
    }
    let idx = usize::try_from(index).map_err(|_| HpackError::InvalidTableIndex)?;
    if idx <= STATIC_TABLE_LEN {
        let entry = &STATIC_TABLE[idx - 1];
        Ok((
            Bytes::from_static(entry.name),
            Bytes::from_static(entry.value),
            entry.parsed_name.clone(),
            Some(entry.parsed_value.clone()),
        ))
    } else {
        let entry = table
            .get(idx - STATIC_TABLE_LEN - 1)
            .ok_or(HpackError::InvalidTableIndex)?;
        Ok((
            entry.name.clone(),
            entry.value.clone(),
            entry.parsed_name.clone(),
            entry.parsed_value.clone(),
        ))
    }
}

/// Resolves a 1-based HPACK name index into `(name, parsed_name)`.
#[inline]
pub(super) fn get_indexed_name(
    table: &DynamicTable,
    index: u64,
) -> Result<(Bytes, Option<HeaderName>), HpackError> {
    if index == 0 {
        return Err(HpackError::InvalidTableIndex);
    }
    let idx = usize::try_from(index).map_err(|_| HpackError::InvalidTableIndex)?;
    if idx <= STATIC_TABLE_LEN {
        let entry = &STATIC_TABLE[idx - 1];
        Ok((Bytes::from_static(entry.name), entry.parsed_name.clone()))
    } else {
        let entry = table
            .get(idx - STATIC_TABLE_LEN - 1)
            .ok_or(HpackError::InvalidTableIndex)?;
        Ok((entry.name.clone(), entry.parsed_name.clone()))
    }
}
