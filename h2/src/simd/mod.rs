//! Isolated SIMD and SWAR byte-class validators for HTTP/2 field names,
//! field values, and request `:path` pseudo-headers (RFC 9113 §8.2.1, §8.3.1).
//!
//! This is the only module in `http-kit-h2` that permits `unsafe` code, used
//! strictly for architecture-specific vector intrinsics (`aarch64` NEON and
//! `x86_64` AVX2/SSE4.2) with explicit bounds proofs on every load.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
mod neon;
mod swar;
#[cfg(target_arch = "x86_64")]
mod x86;

/// Builds a 16-byte low-nibble lookup table for an ASCII predicate (`0..128`).
///
/// Bit `h` (`0..8`) of `LUT[l]` is set iff byte `(h << 4) | l` satisfies
/// `$pred`. Paired with [`HI_BIT_LUT`], `(LUT[b & 0x0F] & HI_BIT_LUT[b >> 4]) != 0`
/// decides membership over all `0x00..=0xFF` in five vector instructions while
/// rejecting every non-ASCII byte (`b >= 0x80`, where `HI_BIT_LUT[b >> 4] == 0`).
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
macro_rules! ascii_nibble_lut {
    ($pred:ident) => {{
        let mut lut = [0u8; 16];
        let mut b = 0u8;
        while b < 128 {
            if $pred(b) {
                lut[(b & 0x0F) as usize] |= 1u8 << (b >> 4);
            }
            b += 1;
        }
        lut
    }};
}

/// Maps high nibble `0..=7` to `1 << h` and `8..=15` (`b >= 0x80`) to `0`.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(super) const HI_BIT_LUT: [u8; 16] = [
    1 << 0,
    1 << 1,
    1 << 2,
    1 << 3,
    1 << 4,
    1 << 5,
    1 << 6,
    1 << 7,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

/// Low-nibble lookup table for lowercase HTTP token characters (RFC 9113 §8.2.1).
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(super) const NAME_LO_LUT: [u8; 16] = ascii_nibble_lut!(is_field_name_byte);

/// Low-nibble lookup table for URI path-and-query bytes (RFC 9113 §8.3.1).
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(super) const PATH_LO_LUT: [u8; 16] = ascii_nibble_lut!(is_path_byte);

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[inline]
pub(super) fn validate_ascii_lut_scalar(bytes: &[u8], lo_lut: &[u8; 16]) -> bool {
    let mut idx = 0;
    while idx < bytes.len() {
        let b = bytes[idx];
        let allowed = lo_lut[(b & 0x0F) as usize];
        let bit = HI_BIT_LUT[(b >> 4) as usize];
        if (allowed & bit) == 0 {
            return false;
        }
        idx += 1;
    }
    true
}

/// Scalar reference for RFC 9113 §8.2.1 field-name bytes: HTTP `tchar`
/// (RFC 9110 §5.6.2) excluding uppercase `A-Z`.
#[inline]
pub(super) const fn is_field_name_byte(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'^'..=b'z' | b'|' | b'~'
    )
}

/// Scalar reference for RFC 9113 §8.2.1 interior field-value bytes:
/// `HTAB` (`0x09`), `SP`..`~` (`0x20..=0x7E`), and `obs-text` (`0x80..=0xFF`).
#[inline]
pub(super) const fn is_field_value_byte(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b != 0x7F)
}

/// Scalar reference for URI `path-abempty [ "?" query ]` bytes accepted by
/// RFC 3986 / `http::uri::PathAndQuery` (rejecting CTLs, SP, `#`, `"`, `<`,
/// `>`, `\`, `^`, `` ` ``, `{`, `|`, `}`, and non-ASCII).
#[inline]
pub(super) const fn is_path_byte(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$'..=b';' | b'=' | b'?'..=b'[' | b']' | b'_' | b'a'..=b'z' | b'~'
    )
}

#[inline]
const fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Validates an HTTP/2 regular field name (RFC 9113 §8.2.1): non-empty,
/// lowercase `tchar`s only.
#[inline]
pub(crate) fn validate_field_name(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    #[cfg(target_arch = "aarch64")]
    {
        if bytes.len() >= 16 {
            return neon::validate_ascii_lut(bytes, &NAME_LO_LUT);
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if bytes.len() >= 16 {
            return x86::validate_ascii_lut(bytes, &NAME_LO_LUT);
        }
    }
    swar::validate_field_name(bytes)
}

/// Validates an HTTP/2 field value (RFC 9113 §8.2.1): no `NUL`, `CR`, `LF`, or
/// other control bytes (`0x00..=0x08`, `0x0A..=0x1F`, `0x7F`), and no leading
/// or trailing `SP` or `HTAB`.
#[inline]
pub(crate) fn validate_field_value(bytes: &[u8]) -> bool {
    let Some((&first, &last)) = bytes.first().zip(bytes.last()) else {
        return true;
    };
    if is_ows(first) || is_ows(last) {
        return false;
    }
    #[cfg(target_arch = "aarch64")]
    {
        if bytes.len() >= 16 {
            return neon::validate_field_value_body(bytes);
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if bytes.len() >= 16 {
            return x86::validate_field_value_body(bytes);
        }
    }
    swar::validate_field_value_body(bytes)
}

/// Validates an HTTP/2 `:path` value: either `"*"` or a non-empty origin-form
/// path starting with `'/'` whose bytes are all valid URI path/query bytes.
#[inline]
pub(crate) fn validate_path(bytes: &[u8]) -> bool {
    match bytes.first() {
        None => false,
        Some(&b'*') => bytes.len() == 1,
        Some(&b'/') => {
            #[cfg(target_arch = "aarch64")]
            {
                if bytes.len() >= 16 {
                    return neon::validate_ascii_lut(bytes, &PATH_LO_LUT);
                }
            }
            #[cfg(target_arch = "x86_64")]
            {
                if bytes.len() >= 16 {
                    return x86::validate_ascii_lut(bytes, &PATH_LO_LUT);
                }
            }
            swar::validate_path_bytes(bytes)
        }
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_field_name(bytes: &[u8]) -> bool {
        !bytes.is_empty() && bytes.iter().copied().all(is_field_name_byte)
    }

    fn scalar_field_value(bytes: &[u8]) -> bool {
        match bytes.first().zip(bytes.last()) {
            None => true,
            Some((&first, &last)) => {
                !is_ows(first) && !is_ows(last) && bytes.iter().copied().all(is_field_value_byte)
            }
        }
    }

    fn scalar_path(bytes: &[u8]) -> bool {
        match bytes.first() {
            None => false,
            Some(&b'*') => bytes.len() == 1,
            Some(&b'/') => bytes.iter().copied().all(is_path_byte),
            Some(_) => false,
        }
    }

    #[test]
    fn path_lut_stays_within_http_path_and_query_grammar() {
        for b in 0u8..=255 {
            let candidate = [b'/', b];
            if is_path_byte(b) && b != b'%' {
                let pq = http::uri::PathAndQuery::try_from(&candidate[..]).unwrap_or_else(|_| {
                    panic!("PathAndQuery rejected valid RFC 3986 byte {b:#04x}")
                });
                // Ensure `PathAndQuery` did not silently truncate (as it does on `#`).
                assert_eq!(pq.as_str().as_bytes(), &candidate[..]);
            }
        }
        for forbidden in [b'#', b' ', b'\t', b'\r', b'\n', 0x00, 0x7F, 0x80, 0xFF] {
            assert!(!is_path_byte(forbidden));
        }
    }

    #[test]
    fn every_single_byte_matches_scalar_at_every_position_and_alignment() {
        let mut backing = vec![b'a'; 512];
        for align in [0usize, 1, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63] {
            for len in [0usize, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65] {
                let slice = &mut backing[align..align + len];
                slice.fill(b'a');
                assert_eq!(validate_field_name(slice), scalar_field_name(slice));
                assert_eq!(validate_field_value(slice), scalar_field_value(slice));
                #[cfg(target_arch = "aarch64")]
                {
                    assert_eq!(
                        neon::validate_ascii_lut(slice, &NAME_LO_LUT),
                        slice.iter().copied().all(is_field_name_byte)
                    );
                    assert_eq!(
                        neon::validate_field_value_body(slice),
                        bytes_all_value(slice)
                    );
                }
                #[cfg(target_arch = "x86_64")]
                {
                    assert_eq!(
                        x86::validate_ascii_lut(slice, &NAME_LO_LUT),
                        slice.iter().copied().all(is_field_name_byte)
                    );
                    assert_eq!(
                        x86::validate_field_value_body(slice),
                        bytes_all_value(slice)
                    );
                }

                if len > 0 {
                    for pos in [0, len / 2, len - 1] {
                        for byte in 0u8..=255 {
                            slice.fill(b'a');
                            slice[pos] = byte;
                            assert_eq!(
                                validate_field_name(slice),
                                scalar_field_name(slice),
                                "name mismatch at align={align} len={len} pos={pos} byte={byte:#04x}"
                            );
                            assert_eq!(
                                validate_field_value(slice),
                                scalar_field_value(slice),
                                "value mismatch at align={align} len={len} pos={pos} byte={byte:#04x}"
                            );
                            assert_eq!(swar::validate_field_name(slice), scalar_field_name(slice));
                            if !is_ows(slice[0]) && !is_ows(slice[len - 1]) {
                                assert_eq!(
                                    swar::validate_field_value_body(slice),
                                    bytes_all_value(slice)
                                );
                            }

                            slice.fill(b'a');
                            slice[0] = b'/';
                            slice[pos] = byte;
                            assert_eq!(
                                validate_path(slice),
                                scalar_path(slice),
                                "path mismatch at align={align} len={len} pos={pos} byte={byte:#04x}"
                            );
                            if slice[0] == b'/' {
                                assert_eq!(swar::validate_path_bytes(slice), scalar_path(slice));
                            }
                        }
                    }
                }
            }
        }
    }

    fn bytes_all_value(bytes: &[u8]) -> bool {
        bytes.iter().copied().all(is_field_value_byte)
    }

    #[test]
    fn cjk_utf8_headers_and_percent_encoded_paths() {
        // Covers Chinese, Japanese, and Korean per CJK test-data rule.
        let cjk = "你好世界 / こんにちは世界 / 안녕하세요 세계 — HTTP/2 헤더 검증 テスト 测试";
        assert!(validate_field_value(cjk.as_bytes()));
        assert!(!validate_field_name(cjk.as_bytes()));
        assert!(!validate_path(format!("/{cjk}").as_bytes()));

        let encoded = b"/%E4%BD%A0%E5%A5%BD/%E6%A4%9C%E7%B4%A2?q=%EC%95%88%EB%85%95&lang=zh,ja,ko";
        assert!(validate_path(encoded));
        assert!(validate_path(b"*"));
        assert!(!validate_path(b"**"));

        // Injecting NUL, CR, LF, or DEL inside CJK multi-byte runs must fail.
        for bad in [0x00u8, b'\r', b'\n', 0x07, 0x1F, 0x7F] {
            let mut corrupted = cjk.as_bytes().to_vec();
            corrupted.insert(19, bad);
            assert!(!validate_field_value(&corrupted));
        }

        // Leading or trailing SP / HTAB around CJK values must fail.
        for ws in *b" \t" {
            let mut leading = vec![ws];
            leading.extend_from_slice(cjk.as_bytes());
            assert!(!validate_field_value(&leading));

            let mut trailing = cjk.as_bytes().to_vec();
            trailing.push(ws);
            assert!(!validate_field_value(&trailing));
        }
    }
}
