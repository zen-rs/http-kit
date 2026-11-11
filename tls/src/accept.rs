//! Handshake entry points: [`TlsAcceptor`] for servers, [`TlsConnector`] for
//! clients.

use std::{
    future::{Future, pending},
    sync::Arc,
    time::{Duration, Instant},
};

use futures_lite::future::or;
use http_kit_io::Timer;
use rustls::{
    ClientConfig, ServerConfig, client::UnbufferedClientConnection, pki_types::ServerName,
    server::UnbufferedServerConnection,
};

use crate::{
    HandshakeError,
    engine::Engine,
    side::{Client, Server, Side},
    stream::{Negotiated, TlsReadHalf, TlsStream, TlsWriteHalf, Transport},
};

/// How long a handshake may take unless configured otherwise.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Accepts TLS connections: runs the server handshake over an accepted
/// stream.
///
/// Cloning is cheap; one acceptor serves every connection of every thread.
#[derive(Debug, Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    handshake_timeout: Option<Duration>,
    #[cfg(feature = "kernel")]
    kernel: Option<crate::KernelTls>,
}

/// Opens TLS connections: runs the client handshake over a connected
/// stream.
#[derive(Debug, Clone)]
pub struct TlsConnector {
    config: Arc<ClientConfig>,
    handshake_timeout: Option<Duration>,
    #[cfg(feature = "kernel")]
    kernel: Option<crate::KernelTls>,
}

impl TlsAcceptor {
    /// An acceptor for `config`, encrypting in user space, with a 10-second
    /// handshake deadline. Its ALPN protocols are the server's preference
    /// order.
    #[must_use]
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            handshake_timeout: Some(HANDSHAKE_TIMEOUT),
            #[cfg(feature = "kernel")]
            kernel: None,
        }
    }

    /// Bounds the handshake: a peer that has not finished it in `timeout`
    /// is refused with [`HandshakeError::TimedOut`]. `None` waits forever.
    #[must_use]
    pub const fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Hands each connection's record layer to the kernel once its handshake
    /// completes, where `kernel` says the negotiated cipher suite is
    /// supported (see [`KernelTls`](crate::KernelTls)). Turns on rustls's
    /// secret extraction, which that needs.
    #[cfg(feature = "kernel")]
    #[must_use]
    pub fn with_kernel_tls(mut self, kernel: crate::KernelTls) -> Self {
        Arc::make_mut(&mut self.config).enable_secret_extraction = true;
        self.kernel = Some(kernel);
        self
    }

    /// The configuration connections are accepted with.
    #[must_use]
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.config
    }

    /// Runs the server handshake over `stream`, its deadline driven by
    /// `timer`.
    ///
    /// # Errors
    ///
    /// The peer is not a TLS client this configuration accepts, or sent an
    /// alert ([`HandshakeError::Tls`]); the handshake missed its deadline
    /// ([`HandshakeError::TimedOut`]); the transport failed or the peer closed
    /// it ([`HandshakeError::Io`]); or kernel TLS was negotiated and could
    /// not be set up for a reason other than the kernel not having it
    /// (`HandshakeError::Kernel`, with the `kernel` feature).
    pub async fn accept<S: Transport, T: Timer>(
        &self,
        stream: S,
        timer: &T,
    ) -> Result<TlsStream<S, Server>, HandshakeError> {
        let conn =
            UnbufferedServerConnection::new(self.config.clone()).map_err(HandshakeError::Tls)?;
        let handshake = establish::<S, Server>(
            conn,
            stream,
            #[cfg(feature = "kernel")]
            self.kernel.as_ref(),
        );
        within(timer, self.handshake_timeout, handshake).await
    }
}

impl TlsConnector {
    /// A connector for `config`, encrypting in user space, with a 10-second
    /// handshake deadline. Its ALPN protocols are what the client offers.
    #[must_use]
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            config,
            handshake_timeout: Some(HANDSHAKE_TIMEOUT),
            #[cfg(feature = "kernel")]
            kernel: None,
        }
    }

    /// As [`TlsAcceptor::with_handshake_timeout`].
    #[must_use]
    pub const fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// As [`TlsAcceptor::with_kernel_tls`].
    #[cfg(feature = "kernel")]
    #[must_use]
    pub fn with_kernel_tls(mut self, kernel: crate::KernelTls) -> Self {
        Arc::make_mut(&mut self.config).enable_secret_extraction = true;
        self.kernel = Some(kernel);
        self
    }

    /// The configuration connections are opened with.
    #[must_use]
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.config
    }

    /// Runs the client handshake for `server_name` over `stream`, its
    /// deadline driven by `timer`.
    ///
    /// # Errors
    ///
    /// As [`TlsAcceptor::accept`]; a server whose certificate does not
    /// verify for `server_name` is [`HandshakeError::Tls`] carrying
    /// [`rustls::Error::InvalidCertificate`].
    pub async fn connect<S: Transport, T: Timer>(
        &self,
        server_name: ServerName<'static>,
        stream: S,
        timer: &T,
    ) -> Result<TlsStream<S, Client>, HandshakeError> {
        let conn = UnbufferedClientConnection::new(self.config.clone(), server_name)
            .map_err(HandshakeError::Tls)?;
        let handshake = establish::<S, Client>(
            conn,
            stream,
            #[cfg(feature = "kernel")]
            self.kernel.as_ref(),
        );
        within(timer, self.handshake_timeout, handshake).await
    }
}

/// Runs `handshake` until `timeout` passes.
async fn within<T: Timer, F: Future<Output = Result<O, HandshakeError>>, O>(
    timer: &T,
    timeout: Option<Duration>,
    handshake: F,
) -> Result<O, HandshakeError> {
    let deadline =
        timeout.and_then(|timeout| Some((timeout, Instant::now().checked_add(timeout)?)));
    let expired = async {
        match deadline {
            Some((timeout, deadline)) => {
                timer.sleep_until(deadline).await;
                Err(HandshakeError::TimedOut(timeout))
            }
            None => pending().await,
        }
    };
    or(handshake, expired).await
}

/// Handshakes, then settles where the records are encrypted.
async fn establish<S: Transport, D: Side>(
    conn: D::Connection,
    stream: S,
    #[cfg(feature = "kernel")] kernel: Option<&crate::KernelTls>,
) -> Result<TlsStream<S, D>, HandshakeError> {
    let (mut reader, mut writer) = stream.split();
    let mut engine = Engine::<D>::new(conn);
    engine.handshake(&mut reader, &mut writer).await?;
    let negotiated = Negotiated::of::<D>(&engine.conn);
    tracing::trace!(
        version = ?negotiated.version,
        suite = ?negotiated.suite.suite(),
        alpn = ?negotiated.alpn.as_deref().map(String::from_utf8_lossy),
        "TLS handshake complete"
    );

    let (read, write) = S::secure(
        engine,
        reader,
        writer,
        #[cfg(feature = "kernel")]
        kernel,
    )
    .await?;
    let mode = read.mode();
    Ok(TlsStream {
        read: TlsReadHalf(read),
        write: TlsWriteHalf(write),
        negotiated: Negotiated { mode, ..negotiated },
    })
}
