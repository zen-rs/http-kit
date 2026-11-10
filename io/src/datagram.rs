//! Datagram sockets with segmentation offload.
//!
//! A QUIC endpoint sends many equal-sized packets to one peer at a time.
//! Generic segmentation offload (GSO) lets it hand the kernel one buffer of
//! back-to-back segments in a single call; receive coalescing (GRO) lets the
//! kernel return several consecutive datagrams from one peer in a single
//! buffer. Both are Linux features. Elsewhere a segmented send becomes one
//! send per segment and every receive returns one datagram, so callers write
//! one code path.

use std::{future::Future, io, net::SocketAddr, num::NonZeroU16, ops::Range};

use compio_buf::{BufResult, IoBuf, IoBufMut};

/// A datagram socket.
///
/// Operations take `&self`: a protocol driver typically receives and sends on
/// one socket at once.
pub trait DatagramSocket {
    /// The address this socket is bound to.
    ///
    /// # Errors
    ///
    /// Fails if the operating system cannot report it.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// How many segments one kernel call can carry: the GSO segment limit
    /// where the kernel offers segmentation offload on this socket, `1` where
    /// it does not. A caller sizes its batches by this.
    fn max_send_segments(&self) -> usize;

    /// Sends `buf` as one datagram to `target`.
    fn send_to<B: IoBuf>(
        &self,
        buf: B,
        target: SocketAddr,
    ) -> impl Future<Output = BufResult<usize, B>>;

    /// Sends `buf` to `target` as consecutive datagrams of `segment_size`
    /// bytes each; the last may be shorter. Returns the bytes sent, all of
    /// `buf` on success.
    ///
    /// Batches of up to [`max_send_segments`](Self::max_send_segments)
    /// segments go out in one kernel call each.
    fn send_segments<B: IoBuf>(
        &self,
        buf: B,
        segment_size: NonZeroU16,
        target: SocketAddr,
    ) -> impl Future<Output = BufResult<usize, B>>;

    /// Receives into `buf`, starting at its beginning, and sets its length to
    /// the bytes received.
    ///
    /// Where the kernel coalesces (Linux GRO), several datagrams from one peer
    /// may arrive in one call; [`RecvMeta::segments`] splits them. Elsewhere
    /// a datagram longer than the buffer is truncated by the kernel, as UDP
    /// specifies. On Linux a truncation could silently drop whole coalesced
    /// datagrams, so there it is an [`io::ErrorKind::InvalidInput`] error
    /// instead, and the buffer should hold [`MAX_COALESCED_BYTES`].
    fn recv_from<B: IoBufMut>(&self, buf: B) -> impl Future<Output = BufResult<RecvMeta, B>>;
}

/// The most bytes one coalesced receive or one segmented send can carry: an
/// IPv4 datagram's 16-bit total length less its 20-byte IP and 8-byte UDP
/// headers. IPv6 allows a little more, so this bound holds for both.
pub const MAX_COALESCED_BYTES: usize = u16::MAX as usize - 20 - 8;

/// What one [`DatagramSocket::recv_from`] received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvMeta {
    len: usize,
    segment_size: usize,
    from: SocketAddr,
}

impl RecvMeta {
    /// A receive of `len` bytes from `from`, coalesced from datagrams of
    /// `segment_size` bytes each (the last may be shorter).
    ///
    /// # Panics
    ///
    /// Panics if `segment_size` is zero while `len` is not: such a receive
    /// cannot be split.
    #[must_use]
    pub fn new(len: usize, segment_size: usize, from: SocketAddr) -> Self {
        assert!(
            segment_size > 0 || len == 0,
            "a non-empty receive needs a segment size"
        );
        Self {
            len,
            segment_size,
            from,
        }
    }

    /// A receive of exactly one datagram.
    #[must_use]
    pub fn single(len: usize, from: SocketAddr) -> Self {
        Self::new(len, len, from)
    }

    /// Total bytes received.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing was received (an empty datagram).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The size of each coalesced datagram; equal to [`len`](Self::len) for a
    /// single one.
    #[must_use]
    pub fn segment_size(&self) -> usize {
        self.segment_size
    }

    /// The sender.
    #[must_use]
    pub fn from(&self) -> SocketAddr {
        self.from
    }

    /// The byte ranges of each datagram within the receive buffer. An empty
    /// datagram yields one empty range.
    pub fn segments(&self) -> impl Iterator<Item = Range<usize>> + use<> {
        let (len, size) = (self.len, self.segment_size);
        let count = if len == 0 { 1 } else { len.div_ceil(size) };
        (0..count).map(move |i| {
            let start = i * size;
            start..(start + size).min(len)
        })
    }
}

/// Sends `buf` as `segment`-sized datagrams, `max_segments` per call to
/// `send`. `send` gets each batch and the GSO segment size when the batch
/// holds more than one segment.
#[cfg(any(feature = "compio", feature = "tokio", feature = "async-io"))]
pub(crate) async fn send_batched<B, F, Fut>(
    buf: B,
    segment: NonZeroU16,
    max_segments: usize,
    mut send: F,
) -> BufResult<usize, B>
where
    B: IoBuf,
    F: FnMut(compio_buf::Slice<B>, Option<NonZeroU16>) -> Fut,
    Fut: Future<Output = BufResult<usize, compio_buf::Slice<B>>>,
{
    use compio_buf::IntoInner;

    let size = usize::from(segment.get());
    let per_call = max_segments.min(MAX_COALESCED_BYTES / size).max(1);
    let len = buf.buf_len();
    let mut buf = buf;
    let mut sent = 0;
    while sent < len {
        let end = (sent + per_call * size).min(len);
        let gso = (end - sent > size).then_some(segment);
        let BufResult(res, slice) = send(buf.slice(sent..end), gso).await;
        buf = slice.into_inner();
        match res {
            Ok(n) if n == end - sent => sent = end,
            Ok(n) => {
                return BufResult(
                    Err(io::Error::other(format!(
                        "datagram socket sent {n} of {} bytes",
                        end - sent
                    ))),
                    buf,
                );
            }
            Err(e) => return BufResult(Err(e), buf),
        }
    }
    BufResult(Ok(sent), buf)
}

/// The error for a truncated receive on Linux, where it may have cut whole
/// coalesced datagrams.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(feature = "compio", feature = "tokio", feature = "async-io")
))]
pub(crate) fn truncated_coalesced() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "receive buffer is smaller than the coalesced datagrams; size it to MAX_COALESCED_BYTES",
    )
}

#[cfg(test)]
mod tests {
    use super::RecvMeta;

    #[test]
    fn segments_split_a_coalesced_receive() {
        let from = "127.0.0.1:4433".parse().unwrap();
        let meta = RecvMeta::new(2500, 1200, from);
        assert_eq!(
            meta.segments().collect::<Vec<_>>(),
            [0..1200, 1200..2400, 2400..2500]
        );
        assert_eq!(RecvMeta::single(0, from).segments().count(), 1);
    }
}
