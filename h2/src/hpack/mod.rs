//! HPACK header compression and decompression (RFC 7541), implemented in safe
//! Rust.
//!
//! - [`Encoder`]: compresses header blocks using the static table, a bounded
//!   dynamic table, and optional Huffman string literals, honoring
//!   `SETTINGS_HEADER_TABLE_SIZE` updates (RFC 7541 §4.2) and never-indexed
//!   sensitive values (RFC 7541 §7.1.3).
//! - [`Decoder`]: decompresses complete header blocks using a 12-bit
//!   dual-symbol Huffman lookup table, caching validated `http` header names
//!   and values on dynamic-table entries while enforcing
//!   `SETTINGS_MAX_HEADER_LIST_SIZE` before unbounded allocation.

mod decoder;
mod encoder;
pub mod huffman;
pub mod int;
mod table;

pub use self::{
    decoder::{DecodeOutcome, DecodedField, Decoder},
    encoder::{EncodeField, Encoder},
    table::{ENTRY_OVERHEAD, STATIC_TABLE_LEN},
};

/// An RFC 7541 decompression failure, mapped to HTTP/2 `COMPRESSION_ERROR`
/// (`0x9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HpackError {
    /// Input ended in the middle of an integer, string length, or string body.
    #[error("truncated HPACK representation")]
    UnexpectedEof,
    /// Prefix integer overflowed or carried excessive continuation bytes.
    #[error("HPACK prefix integer overflow")]
    IntegerOverflow,
    /// Huffman literal contained EOS, invalid padding (`> 7` bits or non-`1`
    /// bits), or a truncated code (RFC 7541 §5.2).
    #[error("invalid HPACK Huffman code")]
    InvalidHuffmanCode,
    /// Indexed representation referenced index `0` or past the end of the
    /// static + dynamic index space (RFC 7541 §2.3.3, §6.1).
    #[error("HPACK table index out of bounds")]
    InvalidTableIndex,
    /// Dynamic table size update appeared after a header field representation,
    /// exceeded `SETTINGS_HEADER_TABLE_SIZE`, or omitted a required reduction
    /// (RFC 7541 §4.2, §6.3).
    #[error("invalid HPACK dynamic table size update")]
    InvalidTableSizeUpdate,
}
