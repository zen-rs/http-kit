//! `aarch64` NEON 16-byte-at-a-time validators.

use core::arch::aarch64::{
    uint8x16_t, vandq_u8, vbicq_u8, vceqq_u8, vcltq_u8, vdupq_n_u8, vld1q_u8, vmaxvq_u8, vminvq_u8,
    vorrq_u8, vqtbl1q_u8, vshrq_n_u8, vtstq_u8,
};

use super::{HI_BIT_LUT, swar, validate_ascii_lut_scalar};

/// Validates `bytes` against an ASCII nibble-LUT using 16-byte NEON loads.
#[inline]
pub(super) fn validate_ascii_lut(bytes: &[u8], lo_lut: &[u8; 16]) -> bool {
    let len = bytes.len();
    if len < 16 {
        return validate_ascii_lut_scalar(bytes, lo_lut);
    }
    let ptr = bytes.as_ptr();

    // SAFETY: `lo_lut` and `HI_BIT_LUT` are `[u8; 16]` arrays, so loading 16
    // bytes from each pointer is unconditionally in-bounds and unaligned-safe.
    let (lo_tbl, hi_tbl, mask_0f) = unsafe {
        (
            vld1q_u8(lo_lut.as_ptr()),
            vld1q_u8(HI_BIT_LUT.as_ptr()),
            vdupq_n_u8(0x0F),
        )
    };

    let mut offset = 0usize;
    while offset + 16 <= len {
        // SAFETY: The loop guard proves `offset + 16 <= len == bytes.len()`,
        // so `[offset..offset + 16]` lies entirely within `bytes`. `vld1q_u8`
        // performs an unaligned 16-byte load.
        let chunk = unsafe { vld1q_u8(ptr.add(offset)) };
        if !check_lut_chunk(chunk, lo_tbl, hi_tbl, mask_0f) {
            return false;
        }
        offset += 16;
    }

    if offset < len {
        // SAFETY: `len >= 16` was checked at function entry, so `len - 16`
        // cannot underflow and `[len - 16..len]` lies within `bytes`.
        let tail = unsafe { vld1q_u8(ptr.add(len - 16)) };
        if !check_lut_chunk(tail, lo_tbl, hi_tbl, mask_0f) {
            return false;
        }
    }

    true
}

#[inline]
fn check_lut_chunk(
    chunk: uint8x16_t,
    lo_tbl: uint8x16_t,
    hi_tbl: uint8x16_t,
    mask_0f: uint8x16_t,
) -> bool {
    // SAFETY: Pure register-to-register NEON vector instructions on baseline
    // `aarch64` with no memory access.
    unsafe {
        let lo = vandq_u8(chunk, mask_0f);
        let hi = vshrq_n_u8::<4>(chunk);
        let allowed = vqtbl1q_u8(lo_tbl, lo);
        let bit = vqtbl1q_u8(hi_tbl, hi);
        let ok = vtstq_u8(allowed, bit);
        vminvq_u8(ok) != 0
    }
}

/// Validates interior field-value bytes using 16-byte NEON loads, rejecting
/// `0x00..=0x08`, `0x0A..=0x1F`, and `0x7F`.
#[inline]
pub(super) fn validate_field_value_body(bytes: &[u8]) -> bool {
    let len = bytes.len();
    if len < 16 {
        return swar::validate_field_value_body(bytes);
    }
    let ptr = bytes.as_ptr();

    // SAFETY: Register-only splats on baseline `aarch64`.
    let (v20, v09, v7f) = unsafe { (vdupq_n_u8(0x20), vdupq_n_u8(0x09), vdupq_n_u8(0x7F)) };

    let mut offset = 0usize;
    while offset + 16 <= len {
        // SAFETY: `offset + 16 <= len == bytes.len()`, so `[offset..offset + 16]`
        // is in-bounds of `bytes`, and `vld1q_u8` has no alignment requirement.
        let chunk = unsafe { vld1q_u8(ptr.add(offset)) };
        if !check_value_chunk(chunk, v20, v09, v7f) {
            return false;
        }
        offset += 16;
    }

    if offset < len {
        // SAFETY: `len >= 16` was checked at function entry, so `[len - 16..len]`
        // is in-bounds of `bytes`.
        let tail = unsafe { vld1q_u8(ptr.add(len - 16)) };
        if !check_value_chunk(tail, v20, v09, v7f) {
            return false;
        }
    }

    true
}

#[inline]
fn check_value_chunk(chunk: uint8x16_t, v20: uint8x16_t, v09: uint8x16_t, v7f: uint8x16_t) -> bool {
    // SAFETY: Pure register-only NEON vector comparisons and reductions.
    unsafe {
        let lt_20 = vcltq_u8(chunk, v20);
        let is_09 = vceqq_u8(chunk, v09);
        let bad_ctl = vbicq_u8(lt_20, is_09);
        let is_7f = vceqq_u8(chunk, v7f);
        let bad = vorrq_u8(bad_ctl, is_7f);
        vmaxvq_u8(bad) == 0
    }
}
