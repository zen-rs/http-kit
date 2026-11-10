//! The two ends of a connection, over rustls's unbuffered connection types.

use std::ops::DerefMut;

use rustls::{
    client::{ClientConnectionData, UnbufferedClientConnection},
    server::{ServerConnectionData, UnbufferedServerConnection},
    unbuffered::{UnbufferedConnectionCommon, UnbufferedStatus},
};

mod sealed {
    pub trait Sealed {}
}

/// Which end of the connection this is: [`Server`] or [`Client`].
///
/// rustls gives each end its own connection type; this trait is the little
/// the stream needs from either.
pub trait Side: sealed::Sealed + 'static {
    /// rustls's per-end connection data.
    type Data: 'static;
    /// rustls's unbuffered connection for this end.
    type Connection: DerefMut<Target = UnbufferedConnectionCommon<Self::Data>> + 'static;

    /// Processes the records in `incoming` until rustls needs the caller.
    #[doc(hidden)]
    fn process<'c, 'i>(
        conn: &'c mut Self::Connection,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data>;

    /// Hands the record layer over: the traffic secrets, and what rustls
    /// keeps to derive the next ones.
    #[cfg(all(target_os = "linux", feature = "kernel"))]
    #[doc(hidden)]
    fn into_kernel(
        conn: Self::Connection,
    ) -> Result<
        (
            rustls::ExtractedSecrets,
            rustls::kernel::KernelConnection<Self::Data>,
        ),
        rustls::Error,
    >;

    /// Takes a TLS 1.3 `NewSessionTicket` the peer sent after the switch.
    #[cfg(all(target_os = "linux", feature = "kernel"))]
    #[doc(hidden)]
    fn new_session_ticket(
        conn: &mut rustls::kernel::KernelConnection<Self::Data>,
        payload: &[u8],
    ) -> Result<(), rustls::Error>;
}

/// The accepting end.
#[derive(Debug, Clone, Copy)]
pub struct Server;

/// The dialling end.
#[derive(Debug, Clone, Copy)]
pub struct Client;

impl sealed::Sealed for Server {}
impl sealed::Sealed for Client {}

impl Side for Server {
    type Data = ServerConnectionData;
    type Connection = UnbufferedServerConnection;

    fn process<'c, 'i>(
        conn: &'c mut Self::Connection,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        conn.process_tls_records(incoming)
    }

    #[cfg(all(target_os = "linux", feature = "kernel"))]
    fn into_kernel(
        conn: Self::Connection,
    ) -> Result<
        (
            rustls::ExtractedSecrets,
            rustls::kernel::KernelConnection<Self::Data>,
        ),
        rustls::Error,
    > {
        conn.dangerous_into_kernel_connection()
    }

    #[cfg(all(target_os = "linux", feature = "kernel"))]
    fn new_session_ticket(
        _conn: &mut rustls::kernel::KernelConnection<Self::Data>,
        _payload: &[u8],
    ) -> Result<(), rustls::Error> {
        // Only a server issues tickets.
        Err(rustls::Error::InappropriateHandshakeMessage {
            expect_types: vec![rustls::HandshakeType::KeyUpdate],
            got_type: rustls::HandshakeType::NewSessionTicket,
        })
    }
}

impl Side for Client {
    type Data = ClientConnectionData;
    type Connection = UnbufferedClientConnection;

    fn process<'c, 'i>(
        conn: &'c mut Self::Connection,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        conn.process_tls_records(incoming)
    }

    #[cfg(all(target_os = "linux", feature = "kernel"))]
    fn into_kernel(
        conn: Self::Connection,
    ) -> Result<
        (
            rustls::ExtractedSecrets,
            rustls::kernel::KernelConnection<Self::Data>,
        ),
        rustls::Error,
    > {
        conn.dangerous_into_kernel_connection()
    }

    #[cfg(all(target_os = "linux", feature = "kernel"))]
    fn new_session_ticket(
        conn: &mut rustls::kernel::KernelConnection<Self::Data>,
        payload: &[u8],
    ) -> Result<(), rustls::Error> {
        conn.handle_new_session_ticket(payload)
    }
}
