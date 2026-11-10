//! One QUIC connection and its HTTP/3 streams, as the driver holds them.
//!
//! Everything here is synchronous: it moves bytes between quiche and the
//! bodies' channels, and the driver decides when to call it.

use std::{collections::HashMap, net::SocketAddr, time::Instant};

use async_channel::Sender;
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use http::HeaderMap;
use http_kit::{BodyFrame, Response};
use quiche::{
    Shutdown,
    h3::{self, Header, WireErrorCode},
};

use crate::{
    Error, Malformed,
    body::{Command, FrameSender, Message},
    fields,
};

/// An endpoint's name for one of its connections. Keys are never reused, so
/// a command for a connection that has gone cannot reach a new one.
pub(crate) type ConnKey = u64;

/// One stream of one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct StreamRef {
    pub(crate) conn: ConnKey,
    pub(crate) id: u64,
}

/// The addresses of the connection a request arrived on, attached to every
/// request a [`Server`](crate::Server) hands its service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionInfo {
    peer: SocketAddr,
    local: SocketAddr,
}

impl ConnectionInfo {
    /// The client's address, as of the request: QUIC connections can move.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The server socket's address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub(crate) const fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = peer;
    }
}

pub(crate) const fn code(code: WireErrorCode) -> u64 {
    code as u64
}

/// The receiving half of a stream: a body being handed to its consumer.
pub(crate) struct Recv {
    frames: FrameSender,
    /// The consumer asked for a frame and has not had it yet.
    demanded: bool,
    /// quiche reported body data that has not been read yet.
    readable: bool,
    /// The peer finished the stream.
    finished: bool,
    trailers: Option<HeaderMap>,
    expected: Option<u64>,
    received: u64,
}

impl Recv {
    pub(crate) fn new(frames: FrameSender, expected: Option<u64>) -> Self {
        Self {
            frames,
            demanded: false,
            readable: false,
            finished: false,
            trailers: None,
            expected,
            received: 0,
        }
    }
}

/// The sending half of a stream.
pub(crate) enum Send {
    /// Nothing to send yet: a server waiting on its service.
    Waiting,
    /// A response head quiche could not take yet.
    Head {
        fields: Vec<Header>,
        fin: bool,
        declared: Option<u64>,
    },
    /// The head is sent; body frames follow.
    Body(Outgoing),
    /// The message is sent, or the stream was reset.
    Done,
}

pub(crate) struct Outgoing {
    /// Data quiche has not taken yet.
    pending: Bytes,
    tail: Tail,
    /// Whether the pump is owed a credit for its next frame.
    owed: bool,
    declared: Option<u64>,
    sent: u64,
}

impl Outgoing {
    pub(crate) fn new(declared: Option<u64>) -> Self {
        Self {
            pending: Bytes::new(),
            tail: Tail::Open,
            owed: true,
            declared,
            sent: 0,
        }
    }
}

enum Tail {
    Open,
    End,
    Trailers(Vec<Header>),
}

/// One request stream.
pub(crate) struct Stream {
    pub(crate) recv: Option<Recv>,
    pub(crate) send: Send,
    /// The stream task's credits; dropping it withdraws them, which cancels
    /// the task.
    pub(crate) credit: Option<Sender<()>>,
    /// A client's request, until its response head arrives.
    pub(crate) respond: Option<Sender<Result<Response, Error>>>,
    /// A client's `HEAD` request, whose response describes a body it does
    /// not carry.
    pub(crate) head_request: bool,
}

/// A packet quiche paced into the future, held until its release time.
pub(crate) struct Held {
    pub(crate) to: SocketAddr,
    pub(crate) at: Instant,
    pub(crate) len: usize,
}

/// One connection.
pub(crate) struct Conn {
    pub(crate) key: ConnKey,
    pub(crate) quic: quiche::Connection,
    pub(crate) h3: Option<h3::Connection>,
    pub(crate) streams: HashMap<u64, Stream>,
    pub(crate) info: ConnectionInfo,
    pub(crate) read_size: usize,
    /// The packet held for pacing; its bytes are in `held_buf`.
    pub(crate) held: Option<Held>,
    pub(crate) held_buf: Vec<u8>,
    /// The deadline registered for this connection in the endpoint's timers.
    pub(crate) deadline: Option<Instant>,
    /// An extra alarm a role sets (a server's drain).
    pub(crate) alarm: Option<Instant>,
    /// Whether the driver must service this connection before it waits.
    pub(crate) dirty: bool,
    /// Streams finished on this side that quiche has not collected yet.
    unacknowledged: Vec<u64>,
}

impl Conn {
    pub(crate) fn new(
        key: ConnKey,
        quic: quiche::Connection,
        local: SocketAddr,
        peer: SocketAddr,
        read_size: usize,
    ) -> Self {
        Self {
            key,
            quic,
            h3: None,
            streams: HashMap::new(),
            info: ConnectionInfo { peer, local },
            read_size,
            held: None,
            held_buf: Vec::new(),
            deadline: None,
            alarm: None,
            dirty: false,
            unacknowledged: Vec::new(),
        }
    }

    pub(crate) fn stream_ref(&self, id: u64) -> StreamRef {
        StreamRef { conn: self.key, id }
    }

    /// The earliest instant this connection needs the driver.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [
            self.quic.timeout_instant(),
            self.held.as_ref().map(|held| held.at),
            self.alarm,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The code that resets a stream this endpoint gives up on: a server
    /// failed to answer, a client cancels.
    fn abort_code(&self) -> u64 {
        if self.quic.is_server() {
            code(WireErrorCode::InternalError)
        } else {
            code(WireErrorCode::RequestCancelled)
        }
    }

    /// Applies a command from a body or a stream task.
    pub(crate) fn apply(&mut self, command: Command) {
        match command {
            Command::Demand(stream) => {
                if let Some(recv) = self.recv_mut(stream.id) {
                    recv.demanded = true;
                    self.read(stream.id);
                }
            }
            Command::Discard(stream) => self.discard(stream.id),
            Command::Respond {
                stream,
                parts,
                body_len,
                has_body,
            } => self.respond(stream.id, &parts, body_len, has_body),
            Command::Data(stream, data) => {
                let Some(out) = self.outgoing(stream.id) else {
                    return;
                };
                out.sent += data.len() as u64;
                if out.declared.is_some_and(|declared| out.sent > declared) {
                    let declared = out.declared.unwrap_or_default();
                    self.abort(stream.id, &Error::ContentLengthMismatch { declared });
                    return;
                }
                out.pending = data;
                // The pump spent its credit on this frame; it gets the next
                // once quiche has taken this one whole.
                out.owed = true;
                self.write(stream.id);
            }
            Command::Trailers(stream, trailers) => self.finish(
                stream.id,
                Tail::Trailers(fields::encode_trailers(&trailers)),
            ),
            Command::End(stream) => self.finish(stream.id, Tail::End),
            Command::Abort(stream, error) => self.abort(stream.id, &error),
        }
    }

    fn recv_mut(&mut self, id: u64) -> Option<&mut Recv> {
        self.streams.get_mut(&id)?.recv.as_mut()
    }

    fn outgoing(&mut self, id: u64) -> Option<&mut Outgoing> {
        match &mut self.streams.get_mut(&id)?.send {
            Send::Body(out) => Some(out),
            _ => None,
        }
    }

    fn finish(&mut self, id: u64, tail: Tail) {
        let Some(out) = self.outgoing(id) else {
            return;
        };
        if let Some(declared) = out.declared
            && out.sent != declared
        {
            self.abort(id, &Error::ContentLengthMismatch { declared });
            return;
        }
        out.tail = tail;
        self.write(id);
    }

    /// A server's response head, from its service.
    fn respond(
        &mut self,
        id: u64,
        parts: &http::response::Parts,
        body_len: Option<u64>,
        has_body: bool,
    ) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        if !matches!(stream.send, Send::Waiting) {
            return;
        }
        match fields::encode_response(parts, body_len) {
            Ok(fields) => {
                stream.send = Send::Head {
                    fields,
                    fin: !has_body,
                    declared: has_body
                        .then(|| fields::declared_length(&parts.headers).or(body_len))
                        .flatten(),
                };
                self.write(id);
            }
            Err(error) => self.abort(id, &error),
        }
    }

    /// Moves what a stream has queued into quiche, as far as flow control
    /// allows. A stream that cannot take more is reported by
    /// `stream_writable_next` once it can.
    pub(crate) fn write(&mut self, id: u64) {
        let Some(h3) = self.h3.as_mut() else {
            return;
        };
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let quic = &mut self.quic;
        let failed = loop {
            match &mut stream.send {
                Send::Waiting | Send::Done => break None,
                Send::Head {
                    fields,
                    fin,
                    declared,
                } => match h3.send_response(quic, id, fields, *fin) {
                    Ok(()) => {
                        stream.send = if *fin {
                            Send::Done
                        } else {
                            Send::Body(Outgoing::new(*declared))
                        };
                    }
                    Err(h3::Error::StreamBlocked) => break None,
                    Err(error) => break Some(error),
                },
                Send::Body(out) if !out.pending.is_empty() => {
                    match h3.send_body(quic, id, &out.pending, false) {
                        Ok(written) => out.pending.advance(written),
                        Err(h3::Error::Done) => break None,
                        Err(error) => break Some(error),
                    }
                }
                Send::Body(out) => match &out.tail {
                    Tail::Open => {
                        if out.owed
                            && let Some(credit) = &stream.credit
                        {
                            // A closed channel is a task already gone.
                            credit.try_send(()).ok();
                            out.owed = false;
                        }
                        break None;
                    }
                    Tail::End => match h3.send_body(quic, id, &[], true) {
                        Ok(_) => stream.send = Send::Done,
                        Err(h3::Error::Done) => break None,
                        Err(error) => break Some(error),
                    },
                    Tail::Trailers(trailers) => {
                        match h3.send_additional_headers(quic, id, trailers, true, true) {
                            Ok(()) => stream.send = Send::Done,
                            Err(h3::Error::StreamBlocked) => break None,
                            Err(error) => break Some(error),
                        }
                    }
                },
            }
        };
        if let Some(error) = failed {
            self.on_send_error(id, error);
            return;
        }
        if matches!(stream.send, Send::Done) {
            stream.credit = None;
        }
        self.settle(id);
    }

    fn on_send_error(&mut self, id: u64, error: h3::Error) {
        match error {
            h3::Error::TransportError(quiche::Error::StreamStopped(code)) => {
                // The peer wants no more of this message.
                tracing::debug!(stream = id, code, "peer stopped the stream");
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.send = Send::Done;
                    stream.credit = None;
                }
                if self.quic.is_server() {
                    // A server's response is cancelled with it.
                    self.fail(id, &Error::StreamReset(code), code);
                } else {
                    self.settle(id);
                }
            }
            error => {
                tracing::debug!(stream = id, %error, "stream send failed");
                let code = self.abort_code();
                self.fail(id, &Error::H3(error), code);
            }
        }
    }

    /// Hands the consumer of a stream's body its next frame, if it asked
    /// and one is there.
    pub(crate) fn read(&mut self, id: u64) {
        let Some(h3) = self.h3.as_mut() else {
            return;
        };
        let Some(recv) = self
            .streams
            .get_mut(&id)
            .and_then(|stream| stream.recv.as_mut())
        else {
            return;
        };
        if !recv.demanded {
            return;
        }
        if recv.readable {
            let mut buf = BytesMut::new();
            match h3.recv_body_buf(&mut self.quic, id, (&mut buf).limit(self.read_size)) {
                Ok(read) => {
                    recv.received += read as u64;
                    if recv
                        .expected
                        .is_some_and(|expected| recv.received > expected)
                    {
                        self.malformed(id, Malformed::ContentLengthMismatch);
                        return;
                    }
                    recv.demanded = false;
                    deliver(&recv.frames, Message::Frame(BodyFrame::Data(buf.freeze())));
                    return;
                }
                Err(h3::Error::Done) => recv.readable = false,
                Err(error) => {
                    tracing::debug!(stream = id, %error, "stream receive failed");
                    let code = self.abort_code();
                    self.fail(id, &Error::H3(error), code);
                    return;
                }
            }
        }
        if let Some(trailers) = recv.trailers.take() {
            recv.demanded = false;
            deliver(&recv.frames, Message::Frame(BodyFrame::Trailers(trailers)));
            return;
        }
        if recv.finished {
            if recv
                .expected
                .is_some_and(|expected| recv.received != expected)
            {
                self.malformed(id, Malformed::ContentLengthMismatch);
                return;
            }
            deliver(&recv.frames, Message::End);
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.recv = None;
            }
            self.settle(id);
        }
    }

    /// quiche reported body data on `id`.
    pub(crate) fn on_data(&mut self, id: u64) {
        if let Some(recv) = self.recv_mut(id) {
            recv.readable = true;
            self.read(id);
        }
    }

    /// The peer finished `id`.
    pub(crate) fn on_finished(&mut self, id: u64) {
        if let Some(recv) = self.recv_mut(id) {
            recv.finished = true;
            self.read(id);
        }
    }

    /// A trailer section arrived on `id`.
    pub(crate) fn on_trailers(&mut self, id: u64, list: &[Header], more_frames: bool) {
        match fields::decode_trailers(list) {
            Ok(trailers) => {
                if let Some(recv) = self.recv_mut(id) {
                    recv.trailers = Some(trailers);
                    // Nothing may follow a trailer section (RFC 9114 §4.1).
                    recv.finished |= !more_frames;
                    self.read(id);
                }
            }
            Err(malformed) => self.malformed(id, malformed),
        }
    }

    /// The peer reset `id` with `code`.
    pub(crate) fn on_reset(&mut self, id: u64, error: &Error) {
        tracing::debug!(stream = id, %error, "peer reset the stream");
        let code = code(WireErrorCode::RequestCancelled);
        self.fail(id, error, code);
    }

    /// The consumer dropped a body before its end.
    fn discard(&mut self, id: u64) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let Some(recv) = stream.recv.take() else {
            return;
        };
        if self.quic.is_server() {
            // Only the request body is unwanted; the response goes on
            // (RFC 9114 §4.1.1).
            if !recv.finished {
                self.quic
                    .stream_shutdown(id, Shutdown::Read, code(WireErrorCode::NoError))
                    .ok();
            }
            self.settle(id);
        } else {
            // Dropping the response cancels the request.
            self.fail(
                id,
                &Error::ConnectionClosed,
                code(WireErrorCode::RequestCancelled),
            );
        }
    }

    /// The peer sent an invalid message on `id`: a stream error.
    pub(crate) fn malformed(&mut self, id: u64, malformed: Malformed) {
        tracing::debug!(stream = id, %malformed, "malformed message");
        self.fail(
            id,
            &Error::Malformed(malformed),
            code(WireErrorCode::MessageError),
        );
    }

    /// Gives up on a stream: the local side cannot send its message.
    fn abort(&mut self, id: u64, error: &Error) {
        tracing::warn!(stream = id, %error, "outgoing message failed; resetting the stream");
        let code = self.abort_code();
        self.fail(id, error, code);
    }

    /// Ends a stream in both directions with `code`, handing `error` to
    /// whatever still waits on it.
    pub(crate) fn fail(&mut self, id: u64, error: &Error, code: u64) {
        let Some(stream) = self.streams.remove(&id) else {
            return;
        };
        if let Some(respond) = stream.respond {
            respond.try_send(Err(error.clone())).ok();
        }
        if let Some(recv) = stream.recv {
            // A frame the consumer has not taken yet is moot now.
            recv.frames.force_send(Message::Error(error.clone())).ok();
            if !recv.finished {
                self.quic.stream_shutdown(id, Shutdown::Read, code).ok();
            }
        }
        if !matches!(stream.send, Send::Done) {
            self.quic.stream_shutdown(id, Shutdown::Write, code).ok();
        }
    }

    /// Fails every stream at or above `first`: a GOAWAY said they will not
    /// be processed.
    pub(crate) fn reject_from(&mut self, first: u64) {
        let rejected: Vec<u64> = self
            .streams
            .keys()
            .copied()
            .filter(|&id| id >= first)
            .collect();
        for id in rejected {
            self.fail(
                id,
                &Error::RequestRejected,
                code(WireErrorCode::RequestRejected),
            );
        }
    }

    /// Fails every stream: the connection is gone.
    pub(crate) fn fail_all(&mut self, error: &Error) {
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            if let Some(stream) = self.streams.remove(&id) {
                if let Some(respond) = stream.respond {
                    respond.try_send(Err(error.clone())).ok();
                }
                if let Some(recv) = stream.recv {
                    recv.frames.force_send(Message::Error(error.clone())).ok();
                }
            }
        }
    }

    /// Forgets a stream both halves of which are done. A server whose
    /// response is complete stops reading a request body nobody read
    /// (RFC 9114 §4.1.1).
    pub(crate) fn settle(&mut self, id: u64) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        if !matches!(stream.send, Send::Done) || stream.respond.is_some() {
            return;
        }
        if let Some(recv) = &stream.recv {
            if !self.quic.is_server() {
                return;
            }
            if !recv.finished {
                self.quic
                    .stream_shutdown(id, Shutdown::Read, code(WireErrorCode::NoError))
                    .ok();
            }
        }
        self.streams.remove(&id);
        self.unacknowledged.push(id);
    }

    /// Whether every stream this side finished has been delivered: quiche
    /// collects a stream once the peer acknowledged all of it, and a
    /// connection closed before then would drop what is still unsent or
    /// unacknowledged. Forgets the streams that were.
    pub(crate) fn delivered(&mut self) -> bool {
        let quic = &mut self.quic;
        self.unacknowledged.retain(|&id| {
            !matches!(
                quic.stream_capacity(id),
                Err(quiche::Error::InvalidStreamState(_))
            )
        });
        self.unacknowledged.is_empty()
    }

    /// Writes every stream quiche reports as writable again.
    pub(crate) fn write_unblocked(&mut self) {
        while let Some(id) = self.quic.stream_writable_next() {
            self.write(id);
        }
    }

    /// Runs quiche's timers if they are due.
    pub(crate) fn on_timer(&mut self, now: Instant) {
        if self.quic.timeout_instant().is_some_and(|at| at <= now) {
            self.quic.on_timeout();
        }
    }

    /// How the connection ended, once quiche has closed it.
    pub(crate) fn outcome(&self) -> Result<(), Error> {
        let clean = |error: &quiche::ConnectionError| {
            error.error_code
                == if error.is_app {
                    code(WireErrorCode::NoError)
                } else {
                    0
                }
        };
        if let Some(error) = self.quic.peer_error()
            && !clean(error)
        {
            return Err(Error::PeerClosed {
                application: error.is_app,
                code: error.error_code,
            });
        }
        if let Some(error) = self.quic.local_error()
            && !clean(error)
        {
            return Err(Error::LocallyClosed {
                application: error.is_app,
                code: error.error_code,
            });
        }
        Ok(())
    }
}

/// Hands one message to a body's consumer. Each demand makes room for
/// exactly one, so the channel is never full; a closed one is a consumer
/// that has gone, and its drop told the driver so.
fn deliver(frames: &FrameSender, message: Message) {
    frames.try_send(message).ok();
}
