//! Streaming incoming HTTP/2 message bodies with demand-driven flow control.
//!
//! Because one HTTP/2 connection multiplexes many streams over a single socket,
//! the connection driver owns the read half and reads frames continuously so no
//! stalled stream blocks siblings or control frames (`PING`, `SETTINGS`,
//! `WINDOW_UPDATE`). Backpressure travels on HTTP/2 flow control instead:
//! received `DATA` slices wait in the stream's bounded window queue, and the
//! driver grants stream and connection `WINDOW_UPDATE` credits only when the
//! consumer pulls each frame through [`IncomingBody`].
//!
//! A consumer that polls with a [`PipeOffer`] parks that offer on the stream's
//! demand slot; when the next bytes on the wire belong to an unpadded `DATA`
//! frame for that stream and nothing sits buffered ahead of them, the driver
//! splices straight from the socket into the offered pipe.

use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender};
use bytes::Bytes;
use futures_lite::Stream;
use http::HeaderMap;
use http_kit::{Body, BodyError, BodyFrame, FrameSource, PipeOffer};

use crate::{Error, proto::StreamId};

/// Commands sent from [`IncomingBody`] handles to the connection driver.
pub(crate) enum BodyCommand {
    /// Consumer wants the next frame on `stream_id`, optionally offering a pipe.
    Demand {
        stream_id: StreamId,
        offer: Option<PipeOffer>,
    },
    /// Consumer dropped [`IncomingBody`] before reaching end-of-stream.
    Discard { stream_id: StreamId },
}

/// One driver reply to a single [`BodyCommand::Demand`].
pub(crate) enum BodyMessage {
    /// A body frame, plus any unused [`PipeOffer`] when the frame did not use it.
    Frame(BodyFrame, Option<PipeOffer>),
    /// Clean end of body, returning any unused [`PipeOffer`].
    End(Option<PipeOffer>),
    /// Stream or connection failure, returning any unused [`PipeOffer`].
    Error(Error, Option<PipeOffer>),
}

enum QueuedFrame {
    Data(Bytes),
    Trailers(HeaderMap),
}

/// Creates a paired driver [`RecvStream`] and consumer [`Body`].
pub(crate) fn channel(
    stream_id: StreamId,
    mailbox: Sender<BodyCommand>,
    body_idle: Option<Duration>,
) -> (RecvStream, Body) {
    let (frames_tx, frames_rx) = async_channel::bounded(1);
    let recv = RecvStream {
        frames: frames_tx,
        queue: VecDeque::new(),
        end_stream: false,
        error: None,
        demand: None,
        body_idle,
        idle_deadline: None,
        done: false,
    };
    let incoming = IncomingBody {
        frames: Box::pin(frames_rx),
        mailbox,
        stream_id,
        waiting: false,
        done: false,
    };
    (recv, Body::from_source(incoming))
}

/// Driver-side state for one stream's incoming body.
pub(crate) struct RecvStream {
    frames: Sender<BodyMessage>,
    queue: VecDeque<QueuedFrame>,
    end_stream: bool,
    error: Option<Error>,
    demand: Option<Option<PipeOffer>>,
    body_idle: Option<Duration>,
    idle_deadline: Option<Instant>,
    done: bool,
}

impl RecvStream {
    /// Whether the consumer side has completed (delivered `End`/`Error` or discarded).
    pub(crate) const fn is_done(&self) -> bool {
        self.done
    }

    /// Active body-read idle deadline, armed only while a consumer demand waits on the wire.
    pub(crate) const fn idle_deadline(&self) -> Option<Instant> {
        self.idle_deadline
    }

    /// Whether this stream currently has an unsatisfied demand carrying a [`PipeOffer`].
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) fn wants_pipe(&self) -> bool {
        !self.done && self.queue.is_empty() && matches!(self.demand, Some(Some(_)))
    }

    /// Takes the waiting [`PipeOffer`] to perform a socket-to-pipe splice.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) fn take_pipe_offer(&mut self) -> Option<PipeOffer> {
        if !self.wants_pipe() {
            return None;
        }
        self.idle_deadline = None;
        self.demand.take().flatten()
    }

    /// Restores a [`PipeOffer`] when a splice attempt skipped or hit EOF before filling.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) fn restore_pipe_offer(&mut self, offer: PipeOffer, now: Instant) {
        if !self.done {
            self.demand = Some(Some(offer));
            self.idle_deadline = self.body_idle.and_then(|d| now.checked_add(d));
        }
    }

    /// Delivers a spliced `BodyFrame::Pipe` directly to the waiting consumer.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) fn deliver_pipe(
        &mut self,
        filled: http_kit_io::splice::FilledPipe,
        end_stream: bool,
    ) {
        if end_stream {
            self.end_stream = true;
        }
        self.idle_deadline = None;
        if self
            .frames
            .try_send(BodyMessage::Frame(BodyFrame::Pipe(filled), None))
            .is_err()
        {
            self.done = true;
        }
    }

    /// Handles a consumer [`BodyCommand::Demand`], returning how many `DATA` bytes
    /// were consumed so the caller can replenish HTTP/2 receive flow-control windows.
    pub(crate) fn on_demand(&mut self, offer: Option<PipeOffer>, now: Instant) -> usize {
        if self.done {
            return 0;
        }
        if let Some(queued) = self.queue.pop_front() {
            self.idle_deadline = None;
            return match queued {
                QueuedFrame::Data(data) => {
                    let len = data.len();
                    if self
                        .frames
                        .try_send(BodyMessage::Frame(BodyFrame::Data(data), offer))
                        .is_err()
                    {
                        self.done = true;
                    }
                    len
                }
                QueuedFrame::Trailers(trailers) => {
                    if self
                        .frames
                        .try_send(BodyMessage::Frame(BodyFrame::Trailers(trailers), offer))
                        .is_err()
                    {
                        self.done = true;
                    }
                    0
                }
            };
        }
        if let Some(error) = self.error.take() {
            self.idle_deadline = None;
            self.done = true;
            let _ = self.frames.try_send(BodyMessage::Error(error, offer));
            return 0;
        }
        if self.end_stream {
            self.idle_deadline = None;
            self.done = true;
            let _ = self.frames.try_send(BodyMessage::End(offer));
            return 0;
        }
        self.demand = Some(offer);
        self.idle_deadline = self.body_idle.and_then(|d| now.checked_add(d));
        0
    }

    /// Queues or immediately delivers incoming `DATA` bytes, returning how many
    /// bytes were immediately consumed (for `release_recv_capacity`).
    pub(crate) fn push_data(&mut self, data: Bytes, end_stream: bool) -> usize {
        if end_stream {
            self.end_stream = true;
        }
        if self.done {
            // Consumer already dropped the body; release connection flow control.
            return data.len();
        }
        if !data.is_empty() {
            if self.queue.is_empty()
                && let Some(offer) = self.demand.take()
            {
                self.idle_deadline = None;
                let len = data.len();
                if self
                    .frames
                    .try_send(BodyMessage::Frame(BodyFrame::Data(data), offer))
                    .is_err()
                {
                    self.done = true;
                }
                return len;
            }
            self.queue.push_back(QueuedFrame::Data(data));
            return 0;
        }
        if self.end_stream
            && self.queue.is_empty()
            && let Some(offer) = self.demand.take()
        {
            self.idle_deadline = None;
            self.done = true;
            let _ = self.frames.try_send(BodyMessage::End(offer));
        }
        0
    }

    /// Queues or immediately delivers trailing headers (which end the stream).
    pub(crate) fn push_trailers(&mut self, trailers: HeaderMap) {
        self.end_stream = true;
        if self.done {
            return;
        }
        if self.queue.is_empty()
            && let Some(offer) = self.demand.take()
        {
            self.idle_deadline = None;
            if self
                .frames
                .try_send(BodyMessage::Frame(BodyFrame::Trailers(trailers), offer))
                .is_err()
            {
                self.done = true;
            }
            return;
        }
        self.queue.push_back(QueuedFrame::Trailers(trailers));
    }

    /// Fails the incoming body with `error`, returning any unconsumed queued byte count
    /// if the body is already done.
    pub(crate) fn fail(&mut self, error: Error) -> usize {
        if self.done {
            return 0;
        }
        self.idle_deadline = None;
        if self.queue.is_empty()
            && let Some(offer) = self.demand.take()
        {
            self.done = true;
            let _ = self.frames.try_send(BodyMessage::Error(error, offer));
            return 0;
        }
        self.error = Some(error);
        0
    }

    /// Discards the body because its consumer dropped [`IncomingBody`].
    ///
    /// Returns `(unconsumed_queued_bytes, peer_still_open)`.
    pub(crate) fn discard(&mut self) -> (usize, bool) {
        let unconsumed = self
            .queue
            .drain(..)
            .map(|frame| match frame {
                QueuedFrame::Data(bytes) => bytes.len(),
                QueuedFrame::Trailers(_) => 0,
            })
            .sum();
        let peer_open = !self.end_stream && self.error.is_none();
        self.done = true;
        self.demand = None;
        self.idle_deadline = None;
        (unconsumed, peer_open)
    }
}

/// Consumer-side body handle implementing [`FrameSource`].
pub(crate) struct IncomingBody {
    frames: Pin<Box<Receiver<BodyMessage>>>,
    mailbox: Sender<BodyCommand>,
    stream_id: StreamId,
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
            let detached = offer.as_deref_mut().map(PipeOffer::detach);
            if let Err(err) = this.mailbox.try_send(BodyCommand::Demand {
                stream_id: this.stream_id,
                offer: detached,
            }) && let BodyCommand::Demand {
                offer: Some(returned),
                ..
            } = err.into_inner()
                && let Some(caller_offer) = offer.as_deref_mut()
            {
                caller_offer.reattach(returned);
            }
            this.waiting = true;
        }
        let message = ready!(this.frames.as_mut().poll_next(cx));
        this.waiting = false;
        let (polled, unused) = match message {
            Some(BodyMessage::Frame(frame, unused)) => {
                let frame = if offer.is_some() {
                    Ok(frame)
                } else {
                    read_out(frame)
                };
                (Some(frame), unused)
            }
            Some(BodyMessage::End(unused)) => {
                this.done = true;
                (None, unused)
            }
            Some(BodyMessage::Error(error, unused)) => {
                this.done = true;
                (Some(Err(error.into())), unused)
            }
            None => {
                this.done = true;
                (Some(Err(Error::ConnectionClosed.into())), None)
            }
        };
        if let (Some(caller_offer), Some(detached)) = (offer, unused) {
            caller_offer.reattach(detached);
        }
        Poll::Ready(polled)
    }
}

impl Drop for IncomingBody {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.mailbox.try_send(BodyCommand::Discard {
                stream_id: self.stream_id,
            });
        }
    }
}

/// Reads a `BodyFrame::Pipe` back into `Bytes` if a consumer offered a pipe on
/// one poll (`Pending`) and then polled again without an offer.
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
