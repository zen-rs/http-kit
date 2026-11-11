//! Name resolution.

use std::{io, net::IpAddr};

/// An address family a lookup answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv6 (`AAAA` records).
    Ipv6,
    /// IPv4 (`A` records).
    Ipv4,
}

/// One answer of a lookup, delivered as it arrives.
#[derive(Debug)]
pub enum Answer {
    /// One family's addresses in the resolver's order; empty when the name
    /// has none of this family (`NODATA`).
    Family(Family, io::Result<Vec<IpAddr>>),
    /// Every address of the name ranked for destination selection
    /// (RFC 6724), from a resolver that ranks. It may precede, follow or
    /// stand in for the per-family answers.
    Ranked(io::Result<Vec<IpAddr>>),
}

/// Resolves host names to addresses.
///
/// A name that does not exist is [`io::ErrorKind::NotFound`]; any other
/// failure keeps its own kind. The resolver decides its own query plan, so a
/// consumer that races connections (RFC 8305) can start on whichever family
/// answers first.
pub trait Resolve {
    /// Starts resolving `host`; the stream ends when no answer is left.
    fn lookup(&self, host: &str) -> impl futures_core::Stream<Item = Answer>;
}
