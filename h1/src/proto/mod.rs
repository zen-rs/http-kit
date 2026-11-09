//! The sans-IO protocol core: pure functions and state machines over byte
//! buffers, with no socket, runtime or clock.
//!
//! The receive side works on the connection's [`BytesMut`](bytes::BytesMut)
//! receive buffer. [`parse_request_head`] and [`parse_response_head`] split a
//! head off its front; a [`BodyDecoder`] then splits the body off as
//! [`Bytes`](bytes::Bytes) slices of the same allocation, so received data
//! reaches its consumer without a copy. Whatever is left belongs to the next
//! message (pipelining) or to the protocol switched to (upgrade).
//!
//! The send side is [`encode_response_head`] and [`encode_request_head`],
//! which write a head and decide its body's framing, and a [`BodyEncoder`],
//! which produces the framing bytes around each piece of body (data, a file
//! region sent separately, trailers) without copying the body itself.
//!
//! The drivers in [`server`](crate::server) and [`client`](crate::client)
//! run these over [`http_kit_io`] sockets; anything else that moves bytes
//! can run them too.

mod decode;
mod encode;
mod head;

pub use decode::{BodyDecoder, Decoded};
pub use encode::{
    BodyEncoder, Framing, RequestPlan, ResponsePlan, encode_request_head, encode_response_head,
};
pub use head::{
    BodyKind, RequestHead, RequestInfo, ResponseHead, parse_request_head, parse_response_head,
};
