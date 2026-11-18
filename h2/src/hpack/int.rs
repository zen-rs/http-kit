//! HPACK prefix integer representation (RFC 7541 §5.1).

use bytes::{BufMut as _, BytesMut};

use super::HpackError;

/// Encodes `value` with an `n`-bit prefix (`1..=8`), OR-ing `first_byte_mask`
/// into the initial octet's upper `8 - n` bits.
#[inline]
pub fn encode_int(mut value: u64, prefix_bits: u8, first_byte_mask: u8, out: &mut BytesMut) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let max_prefix = (1u16 << prefix_bits) - 1;
    if value < u64::from(max_prefix) {
        out.put_u8(first_byte_mask | (value as u8));
        return;
    }
    out.put_u8(first_byte_mask | (max_prefix as u8));
    value -= u64::from(max_prefix);
    while value >= 128 {
        out.put_u8(((value as u8) & 0x7F) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

/// Decodes an `n`-bit prefix integer (`1..=8`) starting at `buf[*pos]`,
/// advancing `*pos` past the consumed octets.
///
/// # Errors
///
/// Returns [`HpackError::UnexpectedEof`] if `buf` ends mid-integer, or
/// [`HpackError::IntegerOverflow`] if the value overflows `u64` or uses
/// redundant continuation bytes past 64 bits.
#[inline]
pub fn decode_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<u64, HpackError> {
    debug_assert!((1..=8).contains(&prefix_bits));
    let &first = buf.get(*pos).ok_or(HpackError::UnexpectedEof)?;
    *pos += 1;

    let max_prefix = ((1u16 << prefix_bits) - 1) as u8;
    let initial = first & max_prefix;
    if initial < max_prefix {
        return Ok(u64::from(initial));
    }

    let mut value = u64::from(initial);
    let mut shift = 0u32;
    loop {
        let &byte = buf.get(*pos).ok_or(HpackError::UnexpectedEof)?;
        *pos += 1;
        // 10 continuation bytes cover 70 bits (`shift == 63` on the 10th byte,
        // where only bit 0 can fit in `u64` alongside `initial <= 255`).
        if shift > 63 || (shift == 63 && (byte & 0x7F) > 1) {
            return Err(HpackError::IntegerOverflow);
        }
        let addend = u64::from(byte & 0x7F) << shift;
        value = value
            .checked_add(addend)
            .ok_or(HpackError::IntegerOverflow)?;
        if (byte & 0x80) == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_appendix_c1_examples() {
        // C.1.1: 10 with 5-bit prefix -> 0x0a
        let mut buf = BytesMut::new();
        encode_int(10, 5, 0, &mut buf);
        assert_eq!(&buf[..], &[0x0a]);
        let mut pos = 0;
        assert_eq!(decode_int(&buf, &mut pos, 5).unwrap(), 10);
        assert_eq!(pos, 1);

        // C.1.2: 1337 with 5-bit prefix -> 0x1f, 0x9a, 0x0a
        buf.clear();
        encode_int(1337, 5, 0, &mut buf);
        assert_eq!(&buf[..], &[0x1f, 0x9a, 0x0a]);
        pos = 0;
        assert_eq!(decode_int(&buf, &mut pos, 5).unwrap(), 1337);
        assert_eq!(pos, 3);

        // C.1.3: 42 at octet boundary (8-bit prefix) -> 0x2a
        buf.clear();
        encode_int(42, 8, 0, &mut buf);
        assert_eq!(&buf[..], &[0x2a]);
        pos = 0;
        assert_eq!(decode_int(&buf, &mut pos, 8).unwrap(), 42);
        assert_eq!(pos, 1);
    }

    #[test]
    fn rejects_overflow_and_redundant_zero_continuations() {
        // u64::MAX round-trips
        let mut buf = BytesMut::new();
        encode_int(u64::MAX, 5, 0xE0, &mut buf);
        let mut pos = 0;
        assert_eq!(decode_int(&buf, &mut pos, 5).unwrap(), u64::MAX);
        assert_eq!(pos, buf.len());

        // Infinite zero-continuation DoS (`0x1f, 0x80, 0x80, ... 0x00`) must fail.
        let mut crafted = vec![0x1f];
        crafted.extend(std::iter::repeat_n(0x80u8, 12));
        crafted.push(0x00);
        pos = 0;
        assert_eq!(
            decode_int(&crafted, &mut pos, 5),
            Err(HpackError::IntegerOverflow)
        );
    }
}
