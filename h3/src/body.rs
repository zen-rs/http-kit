//! Bodies between an endpoint's driver and the code that reads or writes
//! them.
//!
//! The driver owns every quiche connection, so neither side of a body
//! touches one. A received body asks the driver for one frame at a time
//! through the endpoint's mailbox, and the driver reads exactly one frame
//! per demand: nothing is read off a QUIC stream ahead of its consumer, so
//! QUIC flow control carries backpressure to the peer. An outgoing body is
//! pulled by a pump that waits for a credit before each frame; the driver
//! grants the next credit once quiche has taken the previous frame whole.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use async_channel::{Receiver, Sender};
use bytes::Bytes;
use futures_lite::{Stream, StreamExt as _, future::or};
use http::HeaderMap;
use http_kit::{Body, BodyError, BodyFrame};

use crate::{Error, conn::StreamRef};

/// What a body or a stream's task tells the driver.
pub(crate) enum Command {
    /// A received body wants its next frame.
    Demand(StreamRef),
    /// A received body was dropped before its end.
    Discard(StreamRef),
    /// The head of a response, from a server's service.
    Respond {
        stream: StreamRef,
        parts: http::response::Parts,
        body_len: Option<u64>,
        has_body: bool,
    },
    /// The next data of an outgoing body.
    Data(StreamRef, Bytes),
    /// The trailers that end an outgoing body.
    Trailers(StreamRef, HeaderMap),
    /// The end of an outgoing body.
    End(StreamRef),
    /// An outgoing body failed; the stream is reset.
    Abort(StreamRef, Error),
}

impl Command {
    /// The stream the command is about.
    pub(crate) fn stream(&self) -> StreamRef {
        match self {
            Self::Demand(stream)
            | Self::Discard(stream)
            | Self::Respond { stream, .. }
            | Self::Data(stream, _)
            | Self::Trailers(stream, _)
            | Self::End(stream)
            | Self::Abort(stream, _) => *stream,
        }
    }
}

/// One message per demand.
pub(crate) enum Message {
    Frame(BodyFrame),
    End,
    Error(Error),
}

/// The driver's end of a received body.
pub(crate) type FrameSender = Sender<Message>;

/// Creates a received body for `stream`, and the driver's end of it.
pub(crate) fn incoming(stream: StreamRef, mailbox: Sender<Command>) -> (FrameSender, Body) {
    // Each demand yields one message, and the next demand waits for it.
    let (frames, receiver) = async_channel::bounded(1);
    let body = IncomingBody {
        frames: Box::pin(receiver),
        mailbox,
        stream,
        waiting: false,
        done: false,
    };
    (frames, Body::from_frames(body))
}

/// The consumer's end: a stream of body frames.
struct IncomingBody {
    // Pinned: the receiver's stream keeps a listener that must not move.
    frames: Pin<Box<Receiver<Message>>>,
    mailbox: Sender<Command>,
    stream: StreamRef,
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
            // The mailbox is unbounded; a closed one means the driver is
            // gone, and the frame channel reports how the body ended.
            this.mailbox.try_send(Command::Demand(this.stream)).ok();
            this.waiting = true;
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
                // The driver let the body go without ending it: never pass a
                // truncated body off as a complete one.
                this.done = true;
                Some(Err(Error::ConnectionClosed.into()))
            }
        })
    }
}

impl Drop for IncomingBody {
    fn drop(&mut self) {
        if !self.done {
            self.mailbox.try_send(Command::Discard(self.stream)).ok();
        }
    }
}

/// Waits until the driver withdraws `credit`: the stream was reset or its
/// connection closed. A pump holding a credit is never sent another, so a
/// message here is a broken protocol.
pub(crate) async fn cancelled(credit: &Receiver<()>) {
    assert!(
        credit.recv().await.is_err(),
        "the driver granted a credit while one was held"
    );
}

/// Feeds `body` to the driver, one frame per credit, until it ends, fails,
/// or the driver withdraws the credit.
pub(crate) async fn pump(
    mut body: Body,
    stream: StreamRef,
    mailbox: &Sender<Command>,
    credit: &Receiver<()>,
) {
    let mut held = false;
    loop {
        if !held && credit.recv().await.is_err() {
            return;
        }
        // A credit is held from here until a frame spends it.
        let next = async { Some(body.next().await) };
        let withdrawn = async {
            cancelled(credit).await;
            None
        };
        let Some(frame) = or(next, withdrawn).await else {
            return;
        };
        let command = match frame {
            Some(Ok(BodyFrame::Data(data))) => Command::Data(stream, data),
            Some(Ok(BodyFrame::Trailers(trailers))) => Command::Trailers(stream, trailers),
            #[cfg(feature = "fs")]
            Some(Ok(BodyFrame::File(region))) => {
                match pump_region(region, stream, mailbox, credit).await {
                    Some(still_held) => held = still_held,
                    None => return,
                }
                continue;
            }
            Some(Ok(_)) => Command::Abort(stream, Error::UnsupportedFrame),
            Some(Err(error)) => Command::Abort(stream, error.into()),
            None => Command::End(stream),
        };
        let last = !matches!(command, Command::Data(..));
        mailbox.try_send(command).ok();
        if last {
            return;
        }
        held = false;
    }
}

/// Reads a file region out as data frames: QUIC encrypts in user space, so
/// there is no file-to-socket path to hand it to.
///
/// Called holding a credit. Returns whether a credit is still held once the
/// region is read, or `None` once the stream is gone or the region failed.
#[cfg(feature = "fs")]
async fn pump_region(
    region: http_kit::FileRegion,
    stream: StreamRef,
    mailbox: &Sender<Command>,
    credit: &Receiver<()>,
) -> Option<bool> {
    let mut chunks = region.into_stream();
    let mut held = true;
    loop {
        if !held && credit.recv().await.is_err() {
            return None;
        }
        let next = async { Some(chunks.next().await) };
        let withdrawn = async {
            cancelled(credit).await;
            None
        };
        match or(next, withdrawn).await? {
            None => return Some(true),
            Some(Ok(chunk)) => {
                mailbox.try_send(Command::Data(stream, chunk)).ok();
                held = false;
            }
            Some(Err(error)) => {
                mailbox
                    .try_send(Command::Abort(stream, Error::from(BodyError::from(error))))
                    .ok();
                return None;
            }
        }
    }
}
