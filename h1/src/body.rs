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
    future::poll_fn,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
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

/// Connection-scoped cache for the shared body slot, reused across
/// keep-alive exchanges whenever the previous body has been dropped.
#[derive(Default)]
pub(crate) struct BodyPool(Option<Arc<Mutex<Slot>>>);

impl BodyPool {
    fn acquire(&mut self, init: Slot) -> Arc<Mutex<Slot>> {
        if let Some(slot) = self.0.as_ref().filter(|slot| Arc::strong_count(slot) == 1) {
            *slot.lock().unwrap_or_else(PoisonError::into_inner) = init;
            return Arc::clone(slot);
        }
        let slot = Arc::new(Mutex::new(init));
        self.0 = Some(Arc::clone(&slot));
        slot
    }

    /// Creates the two ends of a streamed body.
    pub(crate) fn stream(&mut self) -> (BodySender, IncomingBody) {
        let slot = self.acquire(Slot::default());
        (
            BodySender(Arc::clone(&slot)),
            IncomingBody {
                slot,
                waiting: false,
                done: false,
            },
        )
    }

    /// Creates a pre-buffered body whose bytes were already sliced off the
    /// connection's receive buffer, while tracking whether the service read it.
    pub(crate) fn buffered(&mut self, data: Bytes) -> (BufferedBody, IncomingBody) {
        let slot = self.acquire(Slot {
            demand: None,
            demanded_any: false,
            first: Some(Message::Frame(BodyFrame::Data(data), None)),
            second: Some(Message::End(None)),
            consumer_dropped: false,
            driver_dropped: true,
            driver_waker: None,
            consumer_waker: None,
        });
        (
            BufferedBody(Arc::clone(&slot)),
            IncomingBody {
                slot,
                waiting: false,
                done: false,
            },
        )
    }
}

#[derive(Default)]
struct Slot {
    demand: Option<Option<PipeOffer>>,
    demanded_any: bool,
    // Room for the one frame a demand produces and the end behind it.
    first: Option<Message>,
    second: Option<Message>,
    consumer_dropped: bool,
    driver_dropped: bool,
    driver_waker: Option<Waker>,
    consumer_waker: Option<Waker>,
}

impl Slot {
    fn push(&mut self, message: Message) {
        if self.first.is_none() {
            self.first = Some(message);
        } else if self.second.is_none() {
            self.second = Some(message);
        } else {
            unreachable!("at most one frame and end are queued per demand");
        }
    }

    fn pop(&mut self) -> Option<Message> {
        let message = self.first.take()?;
        self.first = self.second.take();
        Some(message)
    }
}

/// Handle checking whether a pre-buffered request body was read by the service.
pub(crate) struct BufferedBody(Arc<Mutex<Slot>>);

impl BufferedBody {
    pub(crate) fn was_demanded(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .demanded_any
    }
}

/// The driver's end.
pub(crate) struct BodySender(Arc<Mutex<Slot>>);

impl BodySender {
    /// Waits until the consumer wants a frame, and returns what it offered
    /// to take instead of data; `None` once it has dropped the body.
    pub(crate) async fn demanded(&self) -> Option<Option<PipeOffer>> {
        poll_fn(|cx| {
            let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if slot.consumer_dropped {
                return Poll::Ready(None);
            }
            if let Some(offer) = slot.demand.take() {
                return Poll::Ready(Some(offer));
            }
            slot.driver_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Hands a message to the consumer; `false` once it has dropped the body.
    pub(crate) fn send(&self, message: Message) -> bool {
        let waker = {
            let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if slot.consumer_dropped {
                return false;
            }
            slot.push(message);
            slot.consumer_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }
}

impl Drop for BodySender {
    fn drop(&mut self) {
        let waker = {
            let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            slot.driver_dropped = true;
            slot.consumer_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The consumer's end: a source of body frames.
pub(crate) struct IncomingBody {
    slot: Arc<Mutex<Slot>>,
    waiting: bool,
    done: bool,
}

impl Drop for IncomingBody {
    fn drop(&mut self) {
        let waker = {
            let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
            slot.consumer_dropped = true;
            slot.driver_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
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
        let (message, unanswered, driver_waker) = {
            let mut slot = this.slot.lock().unwrap_or_else(PoisonError::into_inner);
            slot.demanded_any = true;
            let mut wake_driver = None;
            if !this.waiting && slot.first.is_none() && !slot.driver_dropped {
                let demand = offer.as_deref_mut().map(PipeOffer::detach);
                debug_assert!(slot.demand.is_none(), "one demand is outstanding at a time");
                slot.demand = Some(demand);
                this.waiting = true;
                wake_driver = slot.driver_waker.take();
            }
            match slot.pop() {
                Some(msg) => {
                    this.waiting = false;
                    let unanswered = if matches!(msg, Message::End(_) | Message::Error(_)) {
                        slot.demand.take().flatten()
                    } else {
                        None
                    };
                    (Some(msg), unanswered, wake_driver)
                }
                None if slot.driver_dropped => {
                    this.waiting = false;
                    let unanswered = slot.demand.take().flatten();
                    (None, unanswered, wake_driver)
                }
                None => {
                    slot.consumer_waker = Some(cx.waker().clone());
                    drop(slot);
                    if let Some(waker) = wake_driver {
                        waker.wake();
                    }
                    return Poll::Pending;
                }
            }
        };
        if let Some(waker) = driver_waker {
            waker.wake();
        }
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
            if let Some(detached) = unanswered {
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
