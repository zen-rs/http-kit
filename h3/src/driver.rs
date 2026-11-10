//! What server and client drivers share: waiting on every event source at
//! once, the timer queue, and sending a connection's packets.
//!
//! A driver is one future on one thread. It owns the socket, every
//! connection and every stream task, and waits on all of them together:
//! the socket's receive, the earliest connection deadline, the mailbox the
//! bodies write to, and the stream tasks themselves (service calls and body
//! pumps). Each wakeup handles everything that is ready, then services the
//! connections it touched and sends their packets, so a burst of received
//! datagrams or of stream output is answered with one batch of sends.

use std::{
    collections::BTreeSet,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    num::NonZeroU16,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use async_channel::Receiver;
use futures_lite::Stream as _;
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use http_kit_io::{BufResult, DatagramSocket, IntoInner as _, IoBuf as _};

use crate::{
    body::Command,
    conn::{Conn, ConnKey, Held},
};

/// What one wait returned.
pub(crate) struct Woken<R, X> {
    /// A completed receive.
    pub(crate) received: Option<R>,
    /// The timer passed its deadline.
    pub(crate) timer: bool,
    /// The role's own event source fired.
    pub(crate) extra: Option<X>,
}

/// The event sources of one driver.
pub(crate) struct Sources<'p, R, Sl, Tk> {
    recv: Pin<&'p mut R>,
    recv_armed: bool,
    sleep: Pin<&'p mut Sl>,
    sleep_at: Option<Instant>,
    mailbox: Pin<&'p mut Receiver<Command>>,
    pub(crate) tasks: FuturesUnordered<Tk>,
}

impl<'p, R: Future, Sl: Future<Output = ()>, Tk: Future<Output = ()>> Sources<'p, R, Sl, Tk> {
    /// Sources over a receive already in flight and an unarmed timer.
    pub(crate) fn new(
        recv: Pin<&'p mut R>,
        sleep: Pin<&'p mut Sl>,
        mailbox: Pin<&'p mut Receiver<Command>>,
    ) -> Self {
        Self {
            recv,
            recv_armed: true,
            sleep,
            sleep_at: None,
            mailbox,
            tasks: FuturesUnordered::new(),
        }
    }

    /// Starts the next receive, once the last one's buffer is processed.
    pub(crate) fn rearm_recv(&mut self, recv: R) {
        self.recv.set(recv);
        self.recv_armed = true;
    }

    /// Points the timer at `at`, building its future with `sleep` only when
    /// the deadline moved.
    pub(crate) fn arm_timer(&mut self, at: Option<Instant>, sleep: impl FnOnce(Instant) -> Sl) {
        if at != self.sleep_at {
            if let Some(at) = at {
                self.sleep.set(sleep(at));
            }
            self.sleep_at = at;
        }
    }

    /// Waits until something is ready, polling every source once per
    /// wakeup. Commands land in `commands`; `pending_work` returns at once
    /// after one pass, so a driver with connections to service never sleeps.
    pub(crate) async fn wait<X>(
        &mut self,
        commands: &mut Vec<Command>,
        pending_work: bool,
        mut extra: impl FnMut(&mut Context<'_>) -> Option<X>,
    ) -> Woken<R::Output, X> {
        poll_fn(|cx| {
            // Tasks first: what they produce lands in the mailbox.
            while let Poll::Ready(Some(())) = self.tasks.poll_next_unpin(cx) {}
            while let Poll::Ready(Some(command)) = self.mailbox.as_mut().poll_next(cx) {
                commands.push(command);
            }
            let received = if self.recv_armed {
                match self.recv.as_mut().poll(cx) {
                    Poll::Ready(received) => {
                        self.recv_armed = false;
                        Some(received)
                    }
                    Poll::Pending => None,
                }
            } else {
                None
            };
            let timer = self.sleep_at.is_some() && self.sleep.as_mut().poll(cx).is_ready();
            if timer {
                self.sleep_at = None;
            }
            let extra = extra(cx);
            if received.is_some()
                || timer
                || extra.is_some()
                || !commands.is_empty()
                || pending_work
            {
                Poll::Ready(Woken {
                    received,
                    timer,
                    extra,
                })
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

/// Connection deadlines, earliest first.
#[derive(Default)]
pub(crate) struct Timers {
    queue: BTreeSet<(Instant, ConnKey)>,
}

impl Timers {
    /// Re-files `conn` under its current deadline.
    pub(crate) fn update(&mut self, conn: &mut Conn) {
        let next = conn.next_deadline();
        if next != conn.deadline {
            if let Some(old) = conn.deadline {
                self.queue.remove(&(old, conn.key));
            }
            if let Some(next) = next {
                self.queue.insert((next, conn.key));
            }
            conn.deadline = next;
        }
    }

    pub(crate) fn remove(&mut self, conn: &Conn) {
        if let Some(old) = conn.deadline {
            self.queue.remove(&(old, conn.key));
        }
    }

    pub(crate) fn next(&self) -> Option<Instant> {
        self.queue.first().map(|&(at, _)| at)
    }

    /// The connections whose deadline is at or before `now`.
    pub(crate) fn expired(&self, now: Instant) -> impl Iterator<Item = ConnKey> + '_ {
        self.queue
            .iter()
            .take_while(move |&&(at, _)| at <= now)
            .map(|&(_, key)| key)
    }
}

/// Whether a socket error concerns one peer (an ICMP error surfacing on a
/// later call) rather than the socket itself.
pub(crate) fn peer_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::Interrupted
    )
}

/// A run of datagrams in the send buffer, all for one peer and all of one
/// size but the last, so one segmented send carries them.
struct Batch {
    len: usize,
    segment: usize,
    count: usize,
    to: SocketAddr,
}

/// Sends connections' packets: as many as quiche has, batched for
/// segmentation offload, holding back any quiche paces into the future.
pub(crate) struct Transmit {
    buf: Vec<u8>,
    max_segments: usize,
}

impl Transmit {
    pub(crate) fn new(max_segments: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_segments: max_segments.max(1),
        }
    }

    /// Sends everything `conn` has to send now.
    ///
    /// quiche stamps every packet with its release time, its own clock's
    /// `now` for one that is not paced, so each is compared with a fresh
    /// reading.
    pub(crate) async fn flush<S: DatagramSocket>(&mut self, socket: &S, conn: &mut Conn) {
        let mut batch: Option<Batch> = None;
        loop {
            let start = batch.as_ref().map_or(0, |batch| batch.len);
            let room = conn.quic.max_send_udp_payload_size();
            if self.buf.len() < start + room {
                self.buf.resize(start + room, 0);
            }
            let (len, to) = if let Some(held) = conn.held.take() {
                if held.at > Instant::now() {
                    conn.held = Some(held);
                    break;
                }
                self.buf[start..start + held.len].copy_from_slice(&conn.held_buf[..held.len]);
                (held.len, held.to)
            } else {
                match conn.quic.send(&mut self.buf[start..start + room]) {
                    Ok((len, info)) => {
                        if info.at > Instant::now() {
                            // Paced: keep it until its release time.
                            conn.held_buf.clear();
                            conn.held_buf
                                .extend_from_slice(&self.buf[start..start + len]);
                            conn.held = Some(Held {
                                to: info.to,
                                at: info.at,
                                len,
                            });
                            break;
                        }
                        (len, info.to)
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => {
                        tracing::warn!(%error, "QUIC send failed; closing the connection");
                        conn.quic
                            .close(false, quiche::WireErrorCode::InternalError as u64, b"")
                            .ok();
                        break;
                    }
                }
            };
            let joins = batch
                .as_ref()
                .is_some_and(|batch| batch.to == to && len <= batch.segment);
            if !joins && let Some(full) = batch.take() {
                // The new datagram cannot join: send the batch, then move the
                // datagram to the front of the buffer.
                self.send(socket, &full).await;
                self.buf.copy_within(start..start + len, 0);
            }
            let current = batch.get_or_insert(Batch {
                len: 0,
                segment: len,
                count: 0,
                to,
            });
            current.len += len;
            current.count += 1;
            // A short datagram ends a run: only the last may be shorter.
            if len < current.segment || current.count >= self.max_segments {
                let full = batch.take().expect("inserted above");
                self.send(socket, &full).await;
            }
        }
        if let Some(batch) = batch {
            self.send(socket, &batch).await;
        }
    }

    async fn send<S: DatagramSocket>(&mut self, socket: &S, batch: &Batch) {
        let segment = u16::try_from(batch.segment)
            .ok()
            .and_then(NonZeroU16::new)
            .expect("a QUIC packet is non-empty and fits a UDP datagram");
        let buf = std::mem::take(&mut self.buf);
        let BufResult(result, slice) = socket
            .send_segments(buf.slice(..batch.len), segment, batch.to)
            .await;
        self.buf = slice.into_inner();
        if let Err(error) = result {
            // A datagram that does not leave is a lost packet, which QUIC
            // recovers from; a socket that is broken fails its receive too.
            tracing::warn!(%error, to = %batch.to, datagrams = batch.count, "datagram send failed");
        }
    }
}
