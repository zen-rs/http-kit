//! The body of a received message, streamed from the connection's driver.
//!
//! The driver owns the socket, so a body cannot read from it directly. It
//! asks the driver for one frame at a time instead: each poll that finds no
//! frame waiting sends one demand, and the driver reads and decodes exactly
//! one frame per demand. Nothing is read ahead of the consumer, which is what
//! lets `100 Continue` wait until the body is first read and keeps
//! backpressure intact.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use async_channel::{Receiver, Sender, TrySendError};
use futures_lite::Stream;
use http_kit::{BodyError, BodyFrame};

use crate::{Error, ParseError};

pub(crate) enum Message {
    Frame(BodyFrame),
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
    demand: Receiver<()>,
}

impl BodySender {
    /// Waits until the consumer wants a frame; `false` once it has dropped
    /// the body.
    pub(crate) async fn demanded(&self) -> bool {
        self.demand.recv().await.is_ok()
    }

    /// Hands a message to the consumer; `false` once it has dropped the body.
    pub(crate) async fn send(&self, message: Message) -> bool {
        self.frames.send(message).await.is_ok()
    }
}

/// The consumer's end: a stream of body frames.
pub(crate) struct IncomingBody {
    // Pinned: the receiver's stream keeps a listener that must not move.
    frames: Pin<Box<Receiver<Message>>>,
    demand: Sender<()>,
    waiting: bool,
    done: bool,
}

impl Stream for IncomingBody {
    type Item = Result<BodyFrame, BodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(None);
        }
        if !this.waiting {
            match this.demand.try_send(()) {
                // A closed demand channel means the driver is gone; the frame
                // channel reports how it ended.
                Ok(()) | Err(TrySendError::Closed(())) => this.waiting = true,
                Err(TrySendError::Full(())) => {
                    unreachable!("one demand is outstanding at a time")
                }
            }
        }
        let message = ready!(this.frames.as_mut().poll_next(cx));
        this.waiting = false;
        Poll::Ready(match message {
            Some(Message::Frame(frame)) => Some(Ok(frame)),
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
