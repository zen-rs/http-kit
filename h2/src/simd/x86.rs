//! `x86_64` AVX2 (32-byte) and SSE4.2/SSSE3 (16-byte) validators.

use core::arch::x86_64::{
    __m128i, __m256i, _mm_and_si128, _mm_andnot_si128, _mm_cmpeq_epi8, _mm_cmpgt_epi8,
    _mm_loadu_si128, _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8, _mm_setzero_si128,
    _mm_shuffle_epi8, _mm_srli_epi16, _mm256_and_si256, _mm256_andnot_si256,
    _mm256_broadcastsi128_si256, _mm256_cmpeq_epi8, _mm256_cmpgt_epi8, _mm256_loadu_si256,
    _mm256_movemask_epi8, _mm256_or_si256, _mm256_set1_epi8, _mm256_setzero_si256,
    _mm256_shuffle_epi8, _mm256_srli_epi16,
};

use super::{HI_BIT_LUT, swar, validate_ascii_lut_scalar};

#[inline]
pub(super) fn validate_ascii_lut(bytes: &[u8], lo_lut: &[u8; 16]) -> bool {
    if bytes.len() < 16 {
        return validate_ascii_lut_scalar(bytes, lo_lut);
    }
    #[cfg(target_feature = "avx2")]
    {
        // SAFETY: `avx2` is enabled at compile time for this target.
        return unsafe { validate_ascii_lut_avx2(bytes, lo_lut) };
    }
    #[cfg(not(target_feature = "avx2"))]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: Runtime CPUID confirmed AVX2 support.
            return unsafe { validate_ascii_lut_avx2(bytes, lo_lut) };
        }
        if std::arch::is_x86_feature_detected!("sse4.2") {
            // SAFETY: Runtime CPUID confirmed SSE4.2 (which includes SSSE3).
            return unsafe { validate_ascii_lut_sse42(bytes, lo_lut) };
        }
        validate_ascii_lut_scalar(bytes, lo_lut)
    }
}

#[inline]
pub(super) fn validate_field_value_body(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return swar::validate_field_value_body(bytes);
    }
    #[cfg(target_feature = "avx2")]
    {
        // SAFETY: `avx2` is enabled at compile time for this target.
        return unsafe { validate_value_avx2(bytes) };
    }
    #[cfg(not(target_feature = "avx2"))]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: Runtime CPUID confirmed AVX2 support.
            return unsafe { validate_value_avx2(bytes) };
        }
        if std::arch::is_x86_feature_detected!("sse4.2") {
            // SAFETY: Runtime CPUID confirmed SSE4.2 support.
            return unsafe { validate_value_sse42(bytes) };
        }
        swar::validate_field_value_body(bytes)
    }
}

#[target_feature(enable = "avx2")]
unsafe fn validate_ascii_lut_avx2(bytes: &[u8], lo_lut: &[u8; 16]) -> bool {
    let len = bytes.len();
    if len < 32 {
        // SAFETY: `avx2` implies `sse4.2`.
        return unsafe { validate_ascii_lut_sse42(bytes, lo_lut) };
    }
    let ptr = bytes.as_ptr();

    // SAFETY: `lo_lut` and `HI_BIT_LUT` are 16-byte arrays; unaligned 128-bit
    // loads are completely in-bounds and broadcast into both AVX2 lanes.
    let (lo_tbl, hi_tbl, mask_0f, zero) = unsafe {
        let lo128 = _mm_loadu_si128(lo_lut.as_ptr().cast::<__m128i>());
        let hi128 = _mm_loadu_si128(HI_BIT_LUT.as_ptr().cast::<__m128i>());
        (
            _mm256_broadcastsi128_si256(lo128),
            _mm256_broadcastsi128_si256(hi128),
            _mm256_set1_epi8(0x0F),
            _mm256_setzero_si256(),
        )
    };

    let mut offset = 0usize;
    while offset + 32 <= len {
        // SAFETY: Loop condition ensures `offset + 32 <= len == bytes.len()`,
        // so `[offset..offset + 32]` is within `bytes`; `_mm256_loadu_si256`
        // allows arbitrary alignment.
        let chunk = unsafe { _mm256_loadu_si256(ptr.add(offset).cast::<__m256i>()) };
        // SAFETY: AVX2 enabled by enclosing `#[target_feature(enable = "avx2")]`.
        if unsafe { !check_lut_256(chunk, lo_tbl, hi_tbl, mask_0f, zero) } {
            return false;
        }
        offset += 32;
    }

    if offset < len {
        // SAFETY: `len >= 32` was checked at function entry, so `[len - 32..len]`
        // lies wholly within `bytes`.
        let tail = unsafe { _mm256_loadu_si256(ptr.add(len - 32).cast::<__m256i>()) };
        // SAFETY: AVX2 enabled by enclosing `#[target_feature(enable = "avx2")]`.
        if unsafe { !check_lut_256(tail, lo_tbl, hi_tbl, mask_0f, zero) } {
            return false;
        }
    }

    true
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn check_lut_256(
    chunk: __m256i,
    lo_tbl: __m256i,
    hi_tbl: __m256i,
    mask_0f: __m256i,
    zero: __m256i,
) -> bool {
    // SAFETY: Register-only AVX2 operations; note `_mm256_shuffle_epi8` zeroes
    // any lane whose index has bit 7 set, so masking `hi` with `0x0F` ensures
    // `hi` is in `0..=15` (`8..=15` maps to `0` in `HI_BIT_LUT`).
    unsafe {
        let lo = _mm256_and_si256(chunk, mask_0f);
        let hi = _mm256_and_si256(_mm256_srli_epi16::<4>(chunk), mask_0f);
        let allowed = _mm256_shuffle_epi8(lo_tbl, lo);
        let bit = _mm256_shuffle_epi8(hi_tbl, hi);
        let invalid = _mm256_cmpeq_epi8(_mm256_and_si256(allowed, bit), zero);
        _mm256_movemask_epi8(invalid) == 0
    }
}

#[target_feature(enable = "sse4.2")]
unsafe fn validate_ascii_lut_sse42(bytes: &[u8], lo_lut: &[u8; 16]) -> bool {
    let len = bytes.len();
    if len < 16 {
        return validate_ascii_lut_scalar(bytes, lo_lut);
    }
    let ptr = bytes.as_ptr();

    // SAFETY: `lo_lut` and `HI_BIT_LUT` are 16-byte arrays; unaligned loads
    // read exact 16-byte spans.
    let (lo_tbl, hi_tbl, mask_0f, zero) = unsafe {
        (
            _mm_loadu_si128(lo_lut.as_ptr().cast::<__m128i>()),
            _mm_loadu_si128(HI_BIT_LUT.as_ptr().cast::<__m128i>()),
            _mm_set1_epi8(0x0F),
            _mm_setzero_si128(),
        )
    };

    let mut offset = 0usize;
    while offset + 16 <= len {
        // SAFETY: `offset + 16 <= len == bytes.len()`, so `[offset..offset + 16]`
        // lies within `bytes`; `_mm_loadu_si128` permits unaligned pointers.
        let chunk = unsafe { _mm_loadu_si128(ptr.add(offset).cast::<__m128i>()) };
        // SAFETY: SSE4.2 (including SSSE3) is enabled by `#[target_feature]`.
        if unsafe { !check_lut_128(chunk, lo_tbl, hi_tbl, mask_0f, zero) } {
            return false;
        }
        offset += 16;
    }

    if offset < len {
        // SAFETY: `len >= 16` was checked at function entry, so `[len - 16..len]`
        // lies within `bytes`.
        let tail = unsafe { _mm_loadu_si128(ptr.add(len - 16).cast::<__m128i>()) };
        // SAFETY: SSE4.2 enabled by `#[target_feature]`.
        if unsafe { !check_lut_128(tail, lo_tbl, hi_tbl, mask_0f, zero) } {
            return false;
        }
    }

    true
}

#[inline]
#[target_feature(enable = "sse4.2")]
unsafe fn check_lut_128(
    chunk: __m128i,
    lo_tbl: __m128i,
    hi_tbl: __m128i,
    mask_0f: __m128i,
    zero: __m128i,
) -> bool {
    // SAFETY: Register-only SSSE3/SSE2 operations.
    unsafe {
        let lo = _mm_and_si128(chunk, mask_0f);
        let hi = _mm_and_si128(_mm_srli_epi16::<4>(chunk), mask_0f);
        let allowed = _mm_shuffle_epi8(lo_tbl, lo);
        let bit = _mm_shuffle_epi8(hi_tbl, hi);
        let invalid = _mm_cmpeq_epi8(_mm_and_si128(allowed, bit), zero);
        _mm_movemask_epi8(invalid) == 0
    }
}

#[target_feature(enable = "avx2")]
unsafe fn validate_value_avx2(bytes: &[u8]) -> bool {
    let len = bytes.len();
    if len < 32 {
        // SAFETY: `avx2` implies `sse4.2`.
        return unsafe { validate_value_sse42(bytes) };
    }
    let ptr = bytes.as_ptr();

    // SAFETY: Register-only splats.
    let (neg1, v20, v09, v7f) = unsafe {
        (
            _mm256_set1_epi8(-1),
            _mm256_set1_epi8(0x20),
            _mm256_set1_epi8(0x09),
            _mm256_set1_epi8(0x7F),
        )
    };

    let mut offset = 0usize;
    while offset + 32 <= len {
        // SAFETY: `offset + 32 <= len == bytes.len()`, so `[offset..offset + 32]`
        // lies within `bytes`.
        let chunk = unsafe { _mm256_loadu_si256(ptr.add(offset).cast::<__m256i>()) };
        // SAFETY: AVX2 enabled by `#[target_feature]`.
        if unsafe { !check_value_256(chunk, neg1, v20, v09, v7f) } {
            return false;
        }
        offset += 32;
    }

    if offset < len {
        // SAFETY: `len >= 32` checked above, so `[len - 32..len]` is in-bounds.
        let tail = unsafe { _mm256_loadu_si256(ptr.add(len - 32).cast::<__m256i>()) };
        // SAFETY: AVX2 enabled by `#[target_feature]`.
        if unsafe { !check_value_256(tail, neg1, v20, v09, v7f) } {
            return false;
        }
    }

    true
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn check_value_256(
    chunk: __m256i,
    neg1: __m256i,
    v20: __m256i,
    v09: __m256i,
    v7f: __m256i,
) -> bool {
    // SAFETY: Register-only signed `i8` comparisons: `(chunk > -1) & (0x20 > chunk)`
    // selects `0x00..=0x1F` exclusively while leaving `0x80..=0xFF` (`-128..=-1`)
    // untouched.
    unsafe {
        let non_neg = _mm256_cmpgt_epi8(chunk, neg1);
        let lt_20 = _mm256_cmpgt_epi8(v20, chunk);
        let ctl = _mm256_and_si256(non_neg, lt_20);
        let is_09 = _mm256_cmpeq_epi8(chunk, v09);
        let bad_ctl = _mm256_andnot_si256(is_09, ctl);
        let is_7f = _mm256_cmpeq_epi8(chunk, v7f);
        let bad = _mm256_or_si256(bad_ctl, is_7f);
        _mm256_movemask_epi8(bad) == 0
    }
}

#[target_feature(enable = "sse4.2")]
unsafe fn validate_value_sse42(bytes: &[u8]) -> bool {
    let len = bytes.len();
    if len < 16 {
        return swar::validate_field_value_body(bytes);
    }
    let ptr = bytes.as_ptr();

    // SAFETY: Register-only splats.
    let (neg1, v20, v09, v7f) = unsafe {
        (
            _mm_set1_epi8(-1),
            _mm_set1_epi8(0x20),
            _mm_set1_epi8(0x09),
            _mm_set1_epi8(0x7F),
        )
    };

    let mut offset = 0usize;
    while offset + 16 <= len {
        // SAFETY: `offset + 16 <= len == bytes.len()`, so `[offset..offset + 16]`
        // lies within `bytes`.
        let chunk = unsafe { _mm_loadu_si128(ptr.add(offset).cast::<__m128i>()) };
        // SAFETY: SSE4.2 enabled by `#[target_feature]`.
        if unsafe { !check_value_128(chunk, neg1, v20, v09, v7f) } {
            return false;
        }
        offset += 16;
    }

    if offset < len {
        // SAFETY: `len >= 16` was checked at function entry, so `[len - 16..len]`
        // lies within `bytes`.
        let tail = unsafe { _mm_loadu_si128(ptr.add(len - 16).cast::<__m128i>()) };
        // SAFETY: SSE4.2 enabled by `#[target_feature]`.
        if unsafe { !check_value_128(tail, neg1, v20, v09, v7f) } {
            return false;
        }
    }

    true
}

#[inline]
#[target_feature(enable = "sse4.2")]
unsafe fn check_value_128(
    chunk: __m128i,
    neg1: __m128i,
    v20: __m128i,
    v09: __m128i,
    v7f: __m128i,
) -> bool {
    // SAFETY: Register-only SSE2 operations.
    unsafe {
        let non_neg = _mm_cmpgt_epi8(chunk, neg1);
        let lt_20 = _mm_cmpgt_epi8(v20, chunk);
        let ctl = _mm_and_si128(non_neg, lt_20);
        let is_09 = _mm_cmpeq_epi8(chunk, v09);
        let bad_ctl = _mm_andnot_si128(is_09, ctl);
        let is_7f = _mm_cmpeq_epi8(chunk, v7f);
        let bad = _mm_or_si128(bad_ctl, is_7f);
        _mm_movemask_epi8(bad) == 0
    }
}
