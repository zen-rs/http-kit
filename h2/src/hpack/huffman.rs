//! RFC 7541 Appendix B Huffman encoder and fast 12-bit dual-symbol decoder.
//!
//! Decoding uses a compile-time `[u32; 4096]` lookup table (`DECODE_12`) that
//! resolves two symbols per lookup whenever `len1 + len2 <= 12` (covering most
//! ASCII HTTP header characters of 5–7 bits), falling back to a canonical
//! MSB-aligned range check for rare 13–30 bit codes. All RFC 7541 §5.2 padding
//! invariants (padding `<= 7` bits, all padding bits `1`, EOS symbol rejected)
//! are strictly enforced.

use bytes::{BufMut as _, Bytes, BytesMut};

use super::HpackError;

/// RFC 7541 Appendix B MSB-first codes for byte values `0..=255`.
const ENCODE_CODES: [u32; 256] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8,
    0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed,
    0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8,
    0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb,
    0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75,
    0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe,
    0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4,
    0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb,
    0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda,
    0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd,
    0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0,
    0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4,
    0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
    0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf,
    0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7,
    0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4,
    0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
    0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
    0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
];

/// Bit lengths (`5..=30`) of [`ENCODE_CODES`].
const ENCODE_LENS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

/// EOS code (`30` ones, RFC 7541 Appendix B).
const EOS_CODE: u32 = 0x3FFF_FFFF;

#[inline]
const fn pack_entry(sym1: u8, sym2: u8, consumed: u8, count: u8, len1: u8) -> u32 {
    (sym1 as u32)
        | ((sym2 as u32) << 8)
        | ((consumed as u32) << 16)
        | ((count as u32) << 20)
        | ((len1 as u32) << 24)
}

/// Packed 12-bit dual-symbol lookup table:
/// - `bits 0..8`: `sym1`
/// - `bits 8..16`: `sym2`
/// - `bits 16..20`: `consumed` (`5..=12`, or `0` if `len1 > 12`)
/// - `bits 20..22`: `count` (`0`, `1`, or `2`)
/// - `bits 24..28`: `len1` (`5..=12`, or `0` if `len1 > 12`)
const DECODE_12: [u32; 4096] = {
    let mut table = [0u32; 4096];

    // Pass 1: all single symbols with `len1 <= 12`.
    let mut s1 = 0usize;
    while s1 < 256 {
        let len1 = ENCODE_LENS[s1];
        if len1 <= 12 {
            let shift = 12 - len1;
            let base = (ENCODE_CODES[s1] as usize) << shift;
            let span = 1usize << shift;
            let entry = pack_entry(s1 as u8, 0, len1, 1, len1);
            let mut k = 0usize;
            while k < span {
                table[base + k] = entry;
                k += 1;
            }
        }
        s1 += 1;
    }

    // Pass 2: overwrite prefixes that contain two complete symbols (`len1 + len2 <= 12`).
    let mut a = 0usize;
    while a < 256 {
        let len1 = ENCODE_LENS[a];
        if len1 <= 7 {
            let mut b = 0usize;
            while b < 256 {
                let len2 = ENCODE_LENS[b];
                let total = len1 + len2;
                if total <= 12 {
                    let shift = 12 - total;
                    let combined = ((ENCODE_CODES[a] << len2) | ENCODE_CODES[b]) as usize;
                    let base = combined << shift;
                    let span = 1usize << shift;
                    let entry = pack_entry(a as u8, b as u8, total, 2, len1);
                    let mut k = 0usize;
                    while k < span {
                        table[base + k] = entry;
                        k += 1;
                    }
                }
                b += 1;
            }
        }
        a += 1;
    }

    table
};

/// Canonical long-code metadata (`13..=30` bits).
struct CanonicalLong {
    /// Exclusive upper bound in 30-bit left-aligned space for each bit length `0..=30`.
    limit_top30: [u32; 31],
    /// First `len`-bit code value for each bit length `0..=30`.
    first_code: [u32; 31],
    /// Offset into `symbols` for each bit length `0..=30`.
    offset: [u16; 31],
    /// Symbols with bit length `13..=30`, ordered by `(bit_len, symbol)`.
    symbols: [u8; 256],
}

const LONG_CODES: CanonicalLong = {
    let mut limit_top30 = [0u32; 31];
    let mut first_code = [0u32; 31];
    let mut offset = [0u16; 31];
    let mut symbols = [0u8; 256];
    let mut cursor = 0usize;

    let mut len = 13u8;
    while len <= 30 {
        offset[len as usize] = cursor as u16;
        let mut count = 0u32;
        let mut sym = 0usize;
        while sym < 256 {
            if ENCODE_LENS[sym] == len {
                if count == 0 {
                    first_code[len as usize] = ENCODE_CODES[sym];
                } else {
                    assert!(ENCODE_CODES[sym] == first_code[len as usize] + count);
                }
                symbols[cursor] = sym as u8;
                cursor += 1;
                count += 1;
            }
            sym += 1;
        }
        if count > 0 {
            limit_top30[len as usize] = (first_code[len as usize] + count) << (30 - len);
        }
        len += 1;
    }

    CanonicalLong {
        limit_top30,
        first_code,
        offset,
        symbols,
    }
};

#[inline]
const fn decode_long_top30(top30: u32) -> Option<(u8, u8)> {
    if top30 == EOS_CODE {
        return None;
    }
    let mut len = 13usize;
    while len <= 30 {
        let limit = LONG_CODES.limit_top30[len];
        if limit != 0 && top30 < limit {
            let code = top30 >> (30 - len);
            let idx =
                (LONG_CODES.offset[len] as usize) + ((code - LONG_CODES.first_code[len]) as usize);
            return Some((LONG_CODES.symbols[idx], len as u8));
        }
        len += 1;
    }
    None
}

// Compile-time proof of Kraft's equality (`sum == 2^30`) and bijective decoding
// for all 256 symbols + EOS rejection.
const _: () = {
    let mut kraft = 1u64; // EOS (`len == 30`) contributes `2^(30 - 30) = 1`.
    let mut sym = 0usize;
    while sym < 256 {
        let len = ENCODE_LENS[sym];
        let code = ENCODE_CODES[sym];
        kraft += 1u64 << (30 - len);
        if len <= 12 {
            let idx = (code as usize) << (12 - len);
            let entry = DECODE_12[idx];
            assert!((entry & 0xFF) == sym as u32);
            assert!(((entry >> 24) & 0x0F) == len as u32);
        } else {
            let top30 = code << (30 - len);
            match decode_long_top30(top30) {
                Some((decoded, decoded_len)) => {
                    assert!(decoded == sym as u8);
                    assert!(decoded_len == len);
                }
                None => panic!("long Huffman code failed to decode"),
            }
        }
        sym += 1;
    }
    assert!(kraft == (1u64 << 30));
    assert!(decode_long_top30(EOS_CODE).is_none());
};

/// Returns the exact byte length of `src` when encoded with RFC 7541 Huffman
/// coding (including EOS `1`-bit padding to an octet boundary).
#[must_use]
#[inline]
pub fn encoded_len(src: &[u8]) -> usize {
    let mut bits = 0usize;
    for &b in src {
        bits += ENCODE_LENS[b as usize] as usize;
    }
    bits.div_ceil(8)
}

/// Appends the RFC 7541 Huffman encoding of `src` (padded to an octet boundary
/// with `1` bits) onto `dst`.
pub fn encode(src: &[u8], dst: &mut BytesMut) {
    dst.reserve(src.len());
    let mut acc = 0u64;
    let mut nbits = 0u32;

    for &b in src {
        let code = u64::from(ENCODE_CODES[b as usize]);
        let len = u32::from(ENCODE_LENS[b as usize]);
        acc = (acc << len) | code;
        nbits += len;
        while nbits >= 8 {
            nbits -= 8;
            dst.put_u8((acc >> nbits) as u8);
        }
    }

    if nbits > 0 {
        let pad = 8 - nbits;
        let last = ((acc << pad) | ((1u64 << pad) - 1)) as u8;
        dst.put_u8(last);
    }
}

/// Decodes a Huffman-encoded byte slice into owned [`Bytes`], enforcing all
/// RFC 7541 §5.2 padding and EOS constraints.
///
/// If `max_decoded_len` is exceeded, allocation stops once detected and
/// `Ok(None)` is returned ONLY after validating the remaining Huffman stream so
/// `COMPRESSION_ERROR` (`InvalidHuffmanCode`) always takes precedence over
/// header-list size limits, as RFC 9113 requires.
///
/// # Errors
///
/// Returns [`HpackError::InvalidHuffmanCode`] if `src` contains the EOS symbol,
/// has more than 7 padding bits, has any `0` bit in its trailing padding, or
/// ends in the middle of a symbol.
pub fn decode_bounded(src: &[u8], max_decoded_len: usize) -> Result<Option<Bytes>, HpackError> {
    if src.is_empty() {
        return Ok(Some(Bytes::new()));
    }

    // Worst-case expansion is 8/5 = 1.6x; cap initial reservation by `max_decoded_len`.
    let cap = src.len().saturating_mul(8).div_ceil(5).min(max_decoded_len);
    let mut out = BytesMut::with_capacity(cap);
    let mut exceeded = false;

    let mut bits = 0u64;
    let mut nbits = 0u32;
    let mut idx = 0usize;
    let len = src.len();

    loop {
        // Refill bit reservoir (`<= 56` bits before adding a byte -> `<= 64` bits).
        while nbits <= 56 && idx < len {
            bits = (bits << 8) | u64::from(src[idx]);
            nbits += 8;
            idx += 1;
        }

        if nbits < 12 {
            break;
        }

        let peek12 = ((bits >> (nbits - 12)) & 0xFFF) as usize;
        let entry = DECODE_12[peek12];
        let count = (entry >> 20) & 0x3;
        if count != 0 {
            let consumed = (entry >> 16) & 0xF;
            nbits -= consumed;
            if !exceeded {
                let needed = count as usize;
                if out.len() + needed <= max_decoded_len {
                    out.put_u8(entry as u8);
                    if count == 2 {
                        out.put_u8((entry >> 8) as u8);
                    }
                } else {
                    exceeded = true;
                    out.clear();
                }
            }
        } else {
            // Rare 13..=30 bit code; `nbits` has already been refilled from `src`
            // up to `>= 30` unless we are near the end of `src`.
            let top30 = if nbits >= 30 {
                ((bits >> (nbits - 30)) & 0x3FFF_FFFF) as u32
            } else {
                // Pad on the right with `1`s to probe canonical range, then
                // verify `nbits >= code_len`!
                let shift = 30 - nbits;
                (((bits & ((1u64 << nbits) - 1)) << shift) | ((1u64 << shift) - 1)) as u32
            };
            let (sym, code_len) = decode_long_top30(top30).ok_or(HpackError::InvalidHuffmanCode)?;
            if nbits < u32::from(code_len) {
                return Err(HpackError::InvalidHuffmanCode);
            }
            nbits -= u32::from(code_len);
            if !exceeded {
                if out.len() < max_decoded_len {
                    out.put_u8(sym);
                } else {
                    exceeded = true;
                    out.clear();
                }
            }
        }
    }

    // Drain any complete 5..=11 bit symbols remaining in `bits`.
    while nbits >= 5 {
        let mask = (1u64 << nbits) - 1;
        let shift = 12 - nbits;
        let peek12 = (((bits & mask) << shift) | ((1u64 << shift) - 1)) as usize;
        let entry = DECODE_12[peek12];
        let len1 = (entry >> 24) & 0xF;
        if len1 == 0 || len1 > nbits {
            break;
        }
        nbits -= len1;
        if !exceeded {
            if out.len() < max_decoded_len {
                out.put_u8(entry as u8);
            } else {
                exceeded = true;
                out.clear();
            }
        }
    }

    // RFC 7541 §5.2: remaining bits must be at most 7 bits and all `1`s.
    if nbits > 7 {
        return Err(HpackError::InvalidHuffmanCode);
    }
    if nbits > 0 {
        let pad_mask = (1u64 << nbits) - 1;
        if (bits & pad_mask) != pad_mask {
            return Err(HpackError::InvalidHuffmanCode);
        }
    }

    if exceeded {
        Ok(None)
    } else {
        Ok(Some(out.freeze()))
    }
}

/// Decodes a Huffman-encoded byte slice without an explicit byte cap.
///
/// # Errors
///
/// Returns [`HpackError::InvalidHuffmanCode`] on any RFC 7541 §5.2 violation.
pub fn decode(src: &[u8]) -> Result<Bytes, HpackError> {
    decode_bounded(src, usize::MAX)?.ok_or(HpackError::InvalidHuffmanCode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_256_bytes_and_cjk() {
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let mut encoded = BytesMut::new();
        encode(&all_bytes, &mut encoded);
        assert_eq!(encoded.len(), encoded_len(&all_bytes));
        let decoded = decode(&encoded).unwrap();
        assert_eq!(&decoded[..], &all_bytes[..]);

        // Chinese + Japanese + Korean UTF-8 header value.
        let cjk = "你好世界・こんにちは世界・안녕하세요 세계! 0123456789/index.html";
        encoded.clear();
        encode(cjk.as_bytes(), &mut encoded);
        assert_eq!(decode(&encoded).unwrap(), cjk.as_bytes());
    }

    #[test]
    fn enforces_rfc7541_section_5_2_padding_and_eos_rules() {
        // 1. Padding longer than 7 bits (`0xFF` = 8 bits of 1s -> invalid).
        assert_eq!(decode(&[0xFF]), Err(HpackError::InvalidHuffmanCode));
        // `'0'` (`00000`, 5 bits) + 11 bits of 1s (`0x07, 0xFF`) -> 11 bits padding -> invalid.
        assert_eq!(decode(&[0x07, 0xFF]), Err(HpackError::InvalidHuffmanCode));

        // 2. Non-ones padding (`'0'` = `00000` + `000` -> `0x00` -> valid TWO `'0'`s if 10 bits,
        // here 8 bits = `'0'` (5 bits) + `000` (3 zero bits) -> invalid!).
        assert_eq!(decode(&[0x00]), Err(HpackError::InvalidHuffmanCode));
        // Valid `'0'` padded with `111`: `00000_111` = `0x07`.
        assert_eq!(&decode(&[0x07]).unwrap()[..], b"0");

        // 3. Explicit 30-bit EOS (`0x3FFF_FFFF` + 2 `1` padding bits = 4x `0xFF`).
        assert_eq!(
            decode(&[0xFF, 0xFF, 0xFF, 0xFF]),
            Err(HpackError::InvalidHuffmanCode)
        );
    }
}
