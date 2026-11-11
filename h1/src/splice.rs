//! Moving a received body's raw bytes from the socket into a pipe.

use std::time::Duration;

use http_kit::PipeOffer;
use http_kit_io::{SpliceRead, Timer};

use crate::{Error, Limits, conn::Recv, proto::BodyDecoder};

/// What came of offering the consumer's pipe to a body's next step.
pub(crate) enum Attempt {
    /// The next step cannot go through a pipe: read and decode it.
    Skip,
    /// A pipe frame.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    Frame(http_kit::BodyFrame),
    /// The body ended with the stream, which is its end.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    End,
}

/// Answers a demand that carried `offer` with a pipe frame, if the socket
/// can splice, nothing is buffered, and the decoder is in a raw run.
///
/// The splice takes at most the run and the offer's `max`, so it never
/// reaches past the body into the next message's bytes, which stay in the
/// socket.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
pub(crate) async fn try_splice<R: SpliceRead, T: Timer>(
    recv: &mut Recv<R>,
    decoder: &mut BodyDecoder,
    limits: &Limits,
    timer: &T,
    read_timeout: Option<Duration>,
    offer: &mut PipeOffer,
) -> Result<Attempt, Error> {
    use http_kit_io::splice::{Pipe, Spliced};

    use crate::{
        Timeout,
        conn::{deadline_after, until},
    };

    if !recv.buf.is_empty() || !recv.reader.can_splice() {
        return Ok(Attempt::Skip);
    }
    let Some(run) = decoder.raw_run() else {
        return Ok(Attempt::Skip);
    };
    let max = usize::try_from(run).map_or(offer.max(), |run| run.min(offer.max()));
    let pipe = match offer.take_pipe() {
        Some(pipe) => pipe,
        None => Pipe::new()?,
    };
    let spliced = until(
        timer,
        deadline_after(read_timeout),
        recv.reader.splice_to_pipe(pipe, max),
    )
    .await
    .ok_or(Error::Timeout(Timeout::BodyRead))?;
    match spliced {
        Ok(Spliced::Filled(filled)) => {
            decoder.consume_raw(filled.len() as u64);
            Ok(Attempt::Frame(http_kit::BodyFrame::Pipe(filled)))
        }
        Ok(Spliced::End(_)) => {
            // Nothing is buffered, so this ends a close-delimited body and
            // fails any other that is incomplete.
            decoder.decode_eof(&mut recv.buf, limits)?;
            Ok(Attempt::End)
        }
        Err((error, _)) => Err(error.into()),
    }
}

/// Where pipes do not exist, or the feature is off, no step goes through one.
#[cfg(not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))))]
#[allow(clippy::unused_async)] // the same signature as the splicing one
pub(crate) async fn try_splice<R: SpliceRead, T: Timer>(
    _recv: &mut Recv<R>,
    _decoder: &mut BodyDecoder,
    _limits: &Limits,
    _timer: &T,
    _read_timeout: Option<Duration>,
    _offer: &mut PipeOffer,
) -> Result<Attempt, Error> {
    Ok(Attempt::Skip)
}
