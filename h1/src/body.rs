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

use async_channel::{Receiver, Sender};
use futures_lite::Stream;
use http_kit::{BodyError, BodyFrame, FrameSource, PipeOffer};

use crate::{Error, ParseError};

pub(crate) enum Message {
    /// A frame, with the consumer's offer when the driver did not use its
    /// pipe.
    Frame(BodyFrame, Option<PipeOffer>),
    /// The end, with the consumer's offer when it answers a demand that
    /// carried one.
    End(Option<PipeOffer>),
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
            demand: demand_rx.clone(),
        },
        IncomingBody {
            frames: Box::pin(frames_rx),
            demand: demand_tx,
            unanswered: Box::new(demand_rx),
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
    /// The demand channel's other end, to take back a demand the driver never
    /// received: the end of a body is queued behind its last frame, so the
    /// demand that finds it went unread, offer and pipe with it. Boxed, since
    /// a receiver is not `Unpin`; only `try_recv` is called on it.
    unanswered: Box<Receiver<Option<PipeOffer>>>,
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
            // The channel stays open while this end holds `unanswered`, also
            // once the driver is gone; the frame channel reports how it ended.
            if this.demand.try_send(demand).is_err() {
                unreachable!("one demand is outstanding at a time");
            }
            this.waiting = true;
        }
        let message = ready!(this.frames.as_mut().poll_next(cx));
        this.waiting = false;
        let (polled, detached) = match message {
            Some(Message::Frame(frame, detached)) => {
                let frame = if offer.is_some() {
                    Ok(frame)
                } else {
                    read_out(frame)
                };
                (Some(frame), detached)
            }
            Some(Message::End(detached)) => {
                this.done = true;
                (None, detached)
            }
            Some(Message::Error(error)) => {
                this.done = true;
                (Some(Err(error.into())), None)
            }
            None => {
                // The driver stopped without ending the body: never pass a
                // truncated body off as a complete one.
                this.done = true;
                (Some(Err(Error::Parse(ParseError::Incomplete).into())), None)
            }
        };
        if let Some(offer) = offer {
            if let Some(detached) = detached {
                offer.reattach(detached);
            }
            if this.done
                && let Ok(Some(detached)) = this.unanswered.try_recv()
            {
                offer.reattach(detached);
            }
        }
        Poll::Ready(polled)
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
