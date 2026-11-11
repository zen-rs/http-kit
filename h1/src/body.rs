//! The body of a received message, streamed from the connection's driver.
//!
//! The driver owns the socket, so a body cannot read from it directly. It
//! asks the driver for one frame at a time instead: each poll that finds no
//! frame waiting sends one demand, and the driver reads and decodes exactly
//! one frame per demand. Nothing is read ahead of the consumer, which is what
//! lets `100 Continue` wait until the body is first read and keeps
//! backpressure intact.
//!
//! A demand carries the consumer's [`PipeOffer`], if it made one, so the
//! driver can answer with a pipe frame when the bytes are still in the socket.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use async_channel::{Receiver, Sender, TrySendError};
use futures_lite::Stream;
use http_kit::{BodyError, BodyFrame, FrameSource, PipeOffer};

use crate::{Error, ParseError};

pub(crate) enum Message {
    /// A frame, with the consumer's offer when the driver did not use its
    /// pipe.
    Frame(BodyFrame, Option<PipeOffer>),
    End,
    Error(Error),
}

/// Creates the two ends of one body.
pub(crate) fn channel() -> (BodySender, IncomingBody) {
    // Room for the one frame a demand produces and the end behind it.
    let (frames_tx, frames_rx) = async_channel::bounded(2);
    let (demand_tx, demand_rx) = async_channel::bounded(1);
    (
        BodySender {
            frames: frames_tx,
            demand: demand_rx,
        },
        IncomingBody {
            frames: Box::pin(frames_rx),
            demand: demand_tx,
            waiting: false,
            done: false,
        },
    )
}

/// The driver's end.
pub(crate) struct BodySender {
    frames: Sender<Message>,
    demand: Receiver<Option<PipeOffer>>,
}

impl BodySender {
    /// Waits until the consumer wants a frame, and returns what it offered
    /// to take instead of data; `None` once it has dropped the body.
    pub(crate) async fn demanded(&self) -> Option<Option<PipeOffer>> {
        self.demand.recv().await.ok()
    }

    /// Hands a message to the consumer; `false` once it has dropped the body.
    pub(crate) async fn send(&self, message: Message) -> bool {
        self.frames.send(message).await.is_ok()
    }
}

/// The consumer's end: a source of body frames.
pub(crate) struct IncomingBody {
    // Pinned: the receiver's stream keeps a listener that must not move.
    frames: Pin<Box<Receiver<Message>>>,
    demand: Sender<Option<PipeOffer>>,
    waiting: bool,
    done: bool,
}

impl FrameSource for IncomingBody {
    fn poll_next_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut offer: Option<&mut PipeOffer>,
    ) -> Poll<Option<Result<BodyFrame, BodyError>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if !this.waiting {
            let demand = offer.as_deref_mut().map(PipeOffer::detach);
            match this.demand.try_send(demand) {
                // A closed demand channel means the driver is gone; the frame
                // channel reports how it ended.
                Ok(()) | Err(TrySendError::Closed(_)) => this.waiting = true,
                Err(TrySendError::Full(_)) => {
                    unreachable!("one demand is outstanding at a time")
                }
            }
        }
        let message = ready!(this.frames.as_mut().poll_next(cx));
        this.waiting = false;
        Poll::Ready(match message {
            Some(Message::Frame(frame, detached)) => {
                let offered = offer.is_some();
                if let (Some(offer), Some(detached)) = (offer, detached) {
                    offer.reattach(detached);
                }
                Some(if offered { Ok(frame) } else { read_out(frame) })
            }
            Some(Message::End) => {
                this.done = true;
                None
            }
            Some(Message::Error(error)) => {
                this.done = true;
                Some(Err(error.into()))
            }
            None => {
                // The driver stopped without ending the body: never pass a
                // truncated body off as a complete one.
                this.done = true;
                Some(Err(Error::Parse(ParseError::Incomplete).into()))
            }
        })
    }
}

/// A frame for a consumer that offered nothing. The driver answers a demand
/// with a pipe only when it carried an offer, but the consumer that polled
/// again may offer nothing now: the bytes are read out of the pipe then.
fn read_out(frame: BodyFrame) -> Result<BodyFrame, BodyError> {
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    if let BodyFrame::Pipe(pipe) = frame {
        let (data, _pipe) = pipe
            .read_out()
            .map_err(|error| BodyError::from(Error::from(error)))?;
        return Ok(BodyFrame::Data(data));
    }
    Ok(frame)
}
