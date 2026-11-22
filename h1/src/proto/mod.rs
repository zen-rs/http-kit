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
    BodyEncoder, Framing, RequestPlan, RequestTarget, ResponsePlan, encode_request_head,
    encode_response_head,
};
pub use head::{
    BodyKind, RequestHead, RequestInfo, ResponseHead, parse_request_head, parse_response_head,
};

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use bytes::{Bytes, BytesMut};
    use http::{Method, Request, Response, StatusCode};

    use super::*;
    use crate::Limits;

    #[test]
    fn roundtrip_request_and_chunked_response_without_io() {
        let limits = Limits::default();
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://api.example.com/v1/telemetry")
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let (parts, ()) = req.into_parts();

        let mut wire_req = BytesMut::new();
        let payload = b"{\"chip\":\"esp32c6\"}";
        let mut plan = encode_request_head(
            &parts,
            RequestTarget::Origin,
            Some(payload.len() as u64),
            &mut wire_req,
        )
        .unwrap();
        let mut req_chunks = Vec::new();
        plan.encoder
            .data(Bytes::from_static(payload), &mut req_chunks)
            .unwrap();
        if let Some(tail) = plan.encoder.finish().unwrap() {
            req_chunks.push(tail);
        }
        for chunk in req_chunks {
            wire_req.extend_from_slice(&chunk);
        }

        let parsed_req = parse_request_head(&mut wire_req, &limits).unwrap().unwrap();
        assert_eq!(parsed_req.parts.method, Method::POST);
        assert_eq!(parsed_req.parts.uri.path(), "/v1/telemetry");
        assert_eq!(
            parsed_req.parts.headers.get("host").unwrap(),
            "api.example.com"
        );
        let mut req_decoder = BodyDecoder::new(parsed_req.body);
        assert_eq!(
            req_decoder.decode(&mut wire_req, &limits).unwrap(),
            Some(Decoded::Data(Bytes::from_static(payload)))
        );
        assert_eq!(
            req_decoder.decode(&mut wire_req, &limits).unwrap(),
            Some(Decoded::End)
        );

        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("x-device", "esp32c6")
            .body(())
            .unwrap();
        let (resp_parts, ()) = resp.into_parts();
        let mut wire_resp = BytesMut::new();
        let mut resp_plan = encode_response_head(
            &parsed_req.info(),
            &resp_parts,
            None,
            false,
            None,
            &mut wire_resp,
        )
        .unwrap();
        let mut resp_chunks = Vec::new();
        resp_plan
            .encoder
            .data(Bytes::from_static(b"ok"), &mut resp_chunks)
            .unwrap();
        resp_chunks.extend(resp_plan.encoder.finish().unwrap());
        for chunk in resp_chunks {
            wire_resp.extend_from_slice(&chunk);
        }

        let parsed_resp = parse_response_head(&mut wire_resp, &limits, &Method::POST)
            .unwrap()
            .unwrap();
        assert_eq!(parsed_resp.parts.status, StatusCode::OK);
        assert_eq!(parsed_resp.body, BodyKind::Chunked);
        let mut resp_decoder = BodyDecoder::new(parsed_resp.body);
        assert_eq!(
            resp_decoder.decode(&mut wire_resp, &limits).unwrap(),
            Some(Decoded::Data(Bytes::from_static(b"ok")))
        );
        assert_eq!(
            resp_decoder.decode(&mut wire_resp, &limits).unwrap(),
            Some(Decoded::End)
        );
    }
}
