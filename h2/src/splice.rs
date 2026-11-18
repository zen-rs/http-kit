//! Moving HTTP/2 `DATA` payloads directly between sockets and kernel pipes.

#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
use http_kit::PipeOffer;
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
use http_kit_io::SpliceRead;

#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
use crate::{Error, conn::Recv};

/// Result of attempting to splice an active unpadded `DATA` frame payload into a pipe.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
pub(crate) enum SpliceOutcome {
    /// Spliced `filled.len()` bytes into the consumer's pipe.
    Filled(http_kit_io::splice::FilledPipe),
    /// Socket hit EOF before delivering bytes; the empty pipe was restored to `offer`.
    Eof(PipeOffer),
}

/// Whether `recv` can splice directly into a pipe right now.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
pub(crate) fn can_splice_read<R: SpliceRead>(recv: &Recv<R>) -> bool {
    recv.buf.is_empty() && recv.reader.can_splice()
}

/// Whether `reader` supports kernel splicing at all.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
pub(crate) fn reader_can_splice<R: SpliceRead>(reader: &R) -> bool {
    reader.can_splice()
}

/// Splices up to `min(remaining, offer.max())` bytes from `recv.reader` into `offer`'s pipe.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
pub(crate) async fn splice_data<R: SpliceRead>(
    recv: &mut Recv<R>,
    remaining: usize,
    mut offer: PipeOffer,
) -> Result<SpliceOutcome, Error> {
    use http_kit_io::splice::{Pipe, Spliced};

    let max = remaining.min(offer.max());
    let pipe = match offer.take_pipe() {
        Some(pipe) => pipe,
        None => Pipe::new()?,
    };
    match recv.reader.splice_to_pipe(pipe, max).await {
        Ok(Spliced::Filled(filled)) => Ok(SpliceOutcome::Filled(filled)),
        Ok(Spliced::End(pipe)) => Ok(SpliceOutcome::Eof(PipeOffer::with_pipe(offer.max(), pipe))),
        Err((error, _pipe)) => Err(error.into()),
    }
}
