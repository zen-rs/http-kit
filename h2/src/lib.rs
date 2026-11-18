//! HTTP/2 sans-IO protocol core, HPACK, SIMD validation, configuration and
//! error types (`feat/h2-proto-core`).

#![deny(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod frame;
pub mod hpack;
pub mod proto;

mod config;
mod error;
mod fields;
mod simd;

pub use http_kit_io;

pub use crate::{
    config::{ClientConfig, FlowControlConfig, Limits, ServerConfig},
    error::{Error, Malformed, Reason, Timeout, TrySendError},
    fields::{InvalidProtocol, Protocol},
    proto::StreamId,
};
