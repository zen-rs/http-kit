//! Why a handshake failed, and the crate's own view of a failed TLS call.

use std::{io, time::Duration};

/// Why a TLS handshake failed.
///
/// Once a handshake has succeeded the stream reports failures as
/// [`io::Error`]: every TLS-layer failure (a fatal alert included) is
/// [`io::ErrorKind::InvalidData`], and a socket failure keeps its own kind.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// rustls refused the peer, or the peer refused us: the certificate, a
    /// received alert ([`rustls::Error::AlertReceived`]), the protocol.
    #[error("TLS handshake failed: {0}")]
    Tls(#[source] rustls::Error),
    /// The handshake did not complete within the connector's or acceptor's
    /// deadline.
    #[error("the TLS handshake did not complete within {0:?}")]
    TimedOut(Duration),
    /// The transport failed, or the peer closed it, during the handshake.
    #[error("the transport failed during the TLS handshake: {0}")]
    Io(#[source] io::Error),
    /// Kernel TLS was negotiated and could not be set up.
    #[cfg(feature = "kernel")]
    #[error("kernel TLS could not be set up: {0}")]
    Kernel(#[source] io::Error),
}

/// A failure inside the engine, with rustls's error kept typed until the
/// boundary decides what to report: [`HandshakeError`] during a handshake,
/// [`io::Error`] on an established stream.
#[derive(Debug)]
pub(crate) enum Fault {
    /// rustls's own error.
    Tls(rustls::Error),
    /// The transport, or something that is not rustls's to name.
    Io(io::Error),
}

impl From<rustls::Error> for Fault {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}

impl From<io::Error> for Fault {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Fault> for io::Error {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Tls(error) => Self::new(io::ErrorKind::InvalidData, error),
            Fault::Io(error) => error,
        }
    }
}

impl From<Fault> for HandshakeError {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Tls(error) => Self::Tls(error),
            Fault::Io(error) => Self::Io(error),
        }
    }
}
