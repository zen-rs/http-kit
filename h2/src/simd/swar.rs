//! Safe 64-bit SWAR and table-lookup fallbacks for short inputs and non-SIMD
//! targets.

use super::{is_field_name_byte, is_field_value_byte, is_path_byte};

const NAME_TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = is_field_name_byte(i as u8);
        i += 1;
    }
    table
};

const PATH_TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = is_path_byte(i as u8);
        i += 1;
    }
    table
};

#[inline]
pub(super) fn validate_field_name(bytes: &[u8]) -> bool {
    let (chunks, remainder) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_ne_bytes(*chunk);
        // Reject any byte with bit 7 set (`>= 0x80`) before table check.
        if (word & 0x8080_8080_8080_8080) != 0 {
            return false;
        }
        if !(NAME_TABLE[chunk[0] as usize]
            && NAME_TABLE[chunk[1] as usize]
            && NAME_TABLE[chunk[2] as usize]
            && NAME_TABLE[chunk[3] as usize]
            && NAME_TABLE[chunk[4] as usize]
            && NAME_TABLE[chunk[5] as usize]
            && NAME_TABLE[chunk[6] as usize]
            && NAME_TABLE[chunk[7] as usize])
        {
            return false;
        }
    }
    remainder.iter().all(|&b| NAME_TABLE[b as usize])
}

/// Borrow-free 8-byte-at-a-time SWAR scan rejecting `0x00..=0x08`,
/// `0x0A..=0x1F`, and `0x7F` while accepting `0x09`, `0x20..=0x7E`, and
/// `0x80..=0xFF`.
#[inline]
pub(super) fn validate_field_value_body(bytes: &[u8]) -> bool {
    let (chunks, remainder) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_ne_bytes(*chunk);
        // Bit 7 of each lane is 1 iff that byte is ASCII (`< 0x80`).
        let ascii = !word & 0x8080_8080_8080_8080;
        if ascii == 0 {
            // All 8 bytes are obs-text (`0x80..=0xFF`), all valid.
            continue;
        }
        // Zero bit 7 in every lane (`0..=127`) so none of the additions below
        // can carry across a byte boundary (`127 + 96 = 223`, `127 + 1 = 128`,
        // `127 + 127 = 254`, all `< 256`).
        let lo = word & 0x7F7F_7F7F_7F7F_7F7F;
        let lt_20 = !lo.wrapping_add(0x6060_6060_6060_6060);
        let ne_09 = (lo ^ 0x0909_0909_0909_0909).wrapping_add(0x7F7F_7F7F_7F7F_7F7F);
        let eq_7f = lo.wrapping_add(0x0101_0101_0101_0101);
        if (ascii & ((lt_20 & ne_09) | eq_7f)) != 0 {
            return false;
        }
    }
    remainder.iter().copied().all(is_field_value_byte)
}

#[inline]
pub(super) fn validate_path_bytes(bytes: &[u8]) -> bool {
    let (chunks, remainder) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_ne_bytes(*chunk);
        if (word & 0x8080_8080_8080_8080) != 0 {
            return false;
        }
        if !(PATH_TABLE[chunk[0] as usize]
            && PATH_TABLE[chunk[1] as usize]
            && PATH_TABLE[chunk[2] as usize]
            && PATH_TABLE[chunk[3] as usize]
            && PATH_TABLE[chunk[4] as usize]
            && PATH_TABLE[chunk[5] as usize]
            && PATH_TABLE[chunk[6] as usize]
            && PATH_TABLE[chunk[7] as usize])
        {
            return false;
        }
    }
    remainder.iter().all(|&b| PATH_TABLE[b as usize])
}
