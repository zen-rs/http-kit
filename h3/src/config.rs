//! Endpoint settings.
//!
//! Every value here is an operator setting: the defaults are a starting point
//! sized for typical traffic, not a ceiling the crate enforces. The one value
//! without a default is the field section limit, which bounds the memory a
//! peer can make a request or response head cost, so each endpoint states it.

use std::{fmt, sync::Arc, time::Duration};

use boring::{
    pkey::PKey,
    ssl::{
        NameType, SelectCertError, SslAlert, SslContextBuilder, SslMethod, SslRef, SslVerifyError,
        SslVerifyMode,
    },
    x509::{X509, X509Ref},
};

use crate::{
    Error,
    retry::{RetryConfig, TokenKey},
};

/// The congestion controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CongestionControl {
    /// NewReno.
    Reno,
    /// CUBIC (RFC 9438).
    #[default]
    Cubic,
    /// BBR from quiche's gcongestion port (`Bbr2Gcongestion`).
    Bbr2,
}

impl CongestionControl {
    fn algorithm(self) -> quiche::CongestionControlAlgorithm {
        match self {
            Self::Reno => quiche::CongestionControlAlgorithm::Reno,
            Self::Cubic => quiche::CongestionControlAlgorithm::CUBIC,
            Self::Bbr2 => quiche::CongestionControlAlgorithm::Bbr2Gcongestion,
        }
    }
}

/// QUIC transport settings, shared by servers and clients.
#[derive(Debug, Clone, PartialEq)]
pub struct TransportConfig {
    /// The congestion controller.
    pub congestion_control: CongestionControl,
    /// Whether packets are paced over the round trip rather than sent in
    /// bursts. Paced packets are held until quiche's release time.
    pub pacing: bool,
    /// How long a connection may go without receiving anything before it
    /// closes. `None` advertises no idle timeout (the peer's still applies).
    pub idle_timeout: Option<Duration>,
    /// The initial connection-level flow-control window, in bytes.
    pub initial_max_data: u64,
    /// The initial flow-control window of each bidirectional stream, in
    /// bytes, in both directions.
    pub initial_max_stream_data_bidi: u64,
    /// The initial flow-control window of each unidirectional stream, in
    /// bytes. HTTP/3's control and QPACK streams use these.
    pub initial_max_stream_data_uni: u64,
    /// The largest the connection window may grow to by auto-tuning, in bytes.
    pub max_connection_window: u64,
    /// The largest a stream window may grow to by auto-tuning, in bytes.
    pub max_stream_window: u64,
    /// How many bidirectional streams (requests) the peer may have open at
    /// once.
    pub initial_max_streams_bidi: u64,
    /// How many unidirectional streams the peer may open. HTTP/3 needs three
    /// (control, QPACK encoder and decoder).
    pub initial_max_streams_uni: u64,
    /// The largest UDP payload this endpoint accepts, in bytes.
    pub max_recv_udp_payload_size: usize,
    /// The largest UDP payload this endpoint sends, in bytes, before path MTU
    /// discovery raises it.
    pub max_send_udp_payload_size: usize,
    /// Whether to probe for a larger path MTU (RFC 8899).
    pub discover_pmtu: bool,
    /// Whether to tell the peer not to migrate the connection to a new
    /// address.
    pub disable_active_migration: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            congestion_control: CongestionControl::default(),
            pacing: true,
            idle_timeout: Some(Duration::from_secs(30)),
            initial_max_data: 10 * 1024 * 1024,
            initial_max_stream_data_bidi: 1024 * 1024,
            initial_max_stream_data_uni: 1024 * 1024,
            max_connection_window: 24 * 1024 * 1024,
            max_stream_window: 16 * 1024 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_recv_udp_payload_size: 65_527,
            max_send_udp_payload_size: 1350,
            discover_pmtu: false,
            disable_active_migration: true,
        }
    }
}

/// A certificate chain and its private key, PEM-encoded.
///
/// The same PEM a TCP listener's TLS configuration reads, so one identity
/// can serve HTTP/1.1 and HTTP/2 over TLS and HTTP/3 alike.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    cert_chain: Vec<u8>,
    private_key: Vec<u8>,
    ocsp_response: Option<Vec<u8>>,
}

impl Identity {
    /// An identity from a PEM certificate chain (leaf first, then
    /// intermediates) and a PEM private key.
    pub fn from_pem(cert_chain: impl Into<Vec<u8>>, private_key: impl Into<Vec<u8>>) -> Self {
        Self {
            cert_chain: cert_chain.into(),
            private_key: private_key.into(),
            ocsp_response: None,
        }
    }

    /// Staples `response`, a DER OCSP response for the leaf, to every
    /// handshake whose client asks for one (`status_request`, RFC 6066 §8).
    ///
    /// The server sends it as given: renewing it before it expires is the
    /// operator's work, by building a new [`ServerConfig`].
    #[must_use]
    pub fn with_ocsp_response(mut self, response: impl Into<Vec<u8>>) -> Self {
        self.ocsp_response = Some(response.into());
        self
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field(
                "cert_chain",
                &format_args!("{} bytes", self.cert_chain.len()),
            )
            .field("private_key", &format_args!("<redacted>"))
            .field("ocsp_response", &self.ocsp_response.as_ref().map(Vec::len))
            .finish()
    }
}

/// The certificates a client trusts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Roots {
    /// Whether the platform's default trust store (BoringSSL's default
    /// verify paths) is trusted.
    pub system: bool,
    /// Further trusted certificates, each PEM-encoded (one or more
    /// certificates per entry).
    pub pem: Vec<Vec<u8>>,
}

/// Why a [`Verifier`] refuses a server's certificate chain. The handshake
/// fails with the matching TLS alert, which the server sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// The certificate is malformed, or unacceptable for another reason
    /// (`bad_certificate`).
    BadCertificate,
    /// The chain does not lead to a trusted authority (`unknown_ca`).
    UnknownCa,
    /// A certificate is expired, or not yet valid (`certificate_expired`).
    Expired,
    /// A certificate was revoked (`certificate_revoked`).
    Revoked,
}

impl Rejection {
    const fn alert(self) -> SslAlert {
        match self {
            Self::BadCertificate => SslAlert::BAD_CERTIFICATE,
            Self::UnknownCa => SslAlert::UNKNOWN_CA,
            Self::Expired => SslAlert::CERTIFICATE_EXPIRED,
            Self::Revoked => SslAlert::CERTIFICATE_REVOKED,
        }
    }
}

/// What a server presented in its handshake, as a [`Verifier`] is shown it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Presented<'a> {
    /// The certificate chain as the server sent it, each certificate
    /// DER-encoded and the leaf first.
    pub chain: &'a [Vec<u8>],
    /// The server name the client connected to.
    pub server_name: &'a str,
    /// The DER OCSP response the server stapled, empty when it sent none.
    /// The client asks for one in every handshake a [`Verifier`] judges.
    pub ocsp_response: &'a [u8],
}

type VerifyFn = dyn Fn(&Presented<'_>) -> Result<(), Rejection> + Send + Sync;

/// Decides whether what a server presented is acceptable: the platform
/// verifier, a revocation set, a pinned key.
///
/// The function receives the [`Presented`] chain, server name and stapled
/// OCSP response. Its verdict decides the handshake: `Ok` lets it go on, a
/// [`Rejection`] fails it. Nothing else is checked, the name and the
/// revocation status included: matching the leaf against the server name and
/// reading the stapled response are the verifier's work.
///
/// It runs inside the handshake on the connection's thread, so it must not
/// block.
#[derive(Clone)]
pub struct Verifier(Arc<VerifyFn>);

impl Verifier {
    /// A verifier calling `verify`.
    pub fn new(
        verify: impl Fn(&Presented<'_>) -> Result<(), Rejection> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(verify))
    }

    /// The verdict on a handshake's chain, or the alert for a handshake that
    /// has none to show.
    fn check(&self, ssl: &SslRef) -> Result<(), SslVerifyError> {
        let Some(chain) = ssl.peer_cert_chain() else {
            return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
        };
        let Some(name) = ssl.servername(NameType::HOST_NAME) else {
            return Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR));
        };
        let chain = chain
            .iter()
            .map(X509Ref::to_der)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
        let presented = Presented {
            chain: &chain,
            server_name: name,
            ocsp_response: ssl.ocsp_status().unwrap_or_default(),
        };
        (self.0)(&presented).map_err(|rejection| SslVerifyError::Invalid(rejection.alert()))
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Verifier").finish_non_exhaustive()
    }
}

impl PartialEq for Verifier {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// What a client trusts a server's certificate chain on.
#[derive(Debug, Clone, PartialEq)]
pub enum Trust {
    /// BoringSSL verifies the chain against these roots, and the server name
    /// against the leaf.
    Roots(Roots),
    /// The [`Verifier`] alone decides; no root is consulted.
    Verifier(Verifier),
}

/// Settings for a server endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerConfig {
    /// The QUIC transport.
    pub transport: TransportConfig,
    /// The certificate chain and key the server presents.
    pub identity: Identity,
    /// The largest request header or trailer section accepted, in bytes as
    /// RFC 9114 §4.2.2 counts them (`SETTINGS_MAX_FIELD_SECTION_SIZE`). A
    /// larger one closes the connection with `H3_EXCESSIVE_LOAD`.
    pub max_field_section_size: u64,
    /// The QPACK dynamic table capacity offered to the peer's encoder, in
    /// bytes. `0` (the default) keeps header compression to the static table.
    pub qpack_max_table_capacity: u64,
    /// How many streams may be blocked waiting on the QPACK dynamic table.
    pub qpack_blocked_streams: u64,
    /// The most bytes one read of a request body hands up.
    pub read_size: usize,
    /// Address validation with a stateless Retry; `None` opens a connection
    /// for every Initial without one.
    ///
    /// The default retries every new connection under a key generated for
    /// this configuration: no tuning makes a flood of spoofed Initials
    /// allocate connection state, at the cost of one round trip per
    /// handshake. Servers sharing one address need one shared
    /// [`TokenKey`](crate::TokenKey).
    pub retry: Option<RetryConfig>,
}

impl ServerConfig {
    /// A server presenting `identity`, accepting field sections of up to
    /// `max_field_section_size` bytes, with every other setting at its
    /// default.
    #[must_use]
    pub fn new(identity: Identity, max_field_section_size: u64) -> Self {
        Self {
            transport: TransportConfig::default(),
            identity,
            max_field_section_size,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            read_size: 64 * 1024,
            retry: Some(RetryConfig::new(TokenKey::generate())),
        }
    }

    pub(crate) fn quiche(&self) -> Result<(quiche::Config, H3Settings), Error> {
        let mut tls = SslContextBuilder::new(SslMethod::tls())?;
        let mut chain = X509::stack_from_pem(&self.identity.cert_chain)?.into_iter();
        let leaf = chain.next().ok_or(Error::NoCertificate)?;
        tls.set_certificate(&leaf)?;
        for intermediate in chain {
            tls.add_extra_chain_cert(intermediate)?;
        }
        let key = PKey::private_key_from_pem(&self.identity.private_key)?;
        tls.set_private_key(&key)?;
        tls.check_private_key()?;
        if let Some(response) = self.identity.ocsp_response.clone() {
            tls.set_select_certificate_callback(move |mut hello| {
                hello
                    .ssl_mut()
                    .set_ocsp_status(&response)
                    .map_err(|_| SelectCertError::ERROR)
            });
        }
        let mut quic = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)?;
        self.transport.apply(&mut quic)?;
        quic.verify_peer(false);
        Ok((
            quic,
            H3Settings {
                max_field_section_size: self.max_field_section_size,
                qpack_max_table_capacity: self.qpack_max_table_capacity,
                qpack_blocked_streams: self.qpack_blocked_streams,
            },
        ))
    }
}

/// Settings for a client.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientConfig {
    /// The QUIC transport.
    pub transport: TransportConfig,
    /// What the server's chain is verified against.
    pub trust: Trust,
    /// The largest response header or trailer section accepted, in bytes as
    /// RFC 9114 §4.2.2 counts them (`SETTINGS_MAX_FIELD_SECTION_SIZE`).
    pub max_field_section_size: u64,
    /// The QPACK dynamic table capacity offered to the peer's encoder, in
    /// bytes.
    pub qpack_max_table_capacity: u64,
    /// How many streams may be blocked waiting on the QPACK dynamic table.
    pub qpack_blocked_streams: u64,
    /// The most bytes one read of a response body hands up.
    pub read_size: usize,
}

impl ClientConfig {
    /// A client trusting `roots`, accepting field sections of up to
    /// `max_field_section_size` bytes, with every other setting at its
    /// default.
    #[must_use]
    pub fn new(roots: Roots, max_field_section_size: u64) -> Self {
        Self::with_trust(Trust::Roots(roots), max_field_section_size)
    }

    /// A client whose server certificates `verifier` judges, accepting field
    /// sections of up to `max_field_section_size` bytes, with every other
    /// setting at its default.
    #[must_use]
    pub fn with_verifier(verifier: Verifier, max_field_section_size: u64) -> Self {
        Self::with_trust(Trust::Verifier(verifier), max_field_section_size)
    }

    fn with_trust(trust: Trust, max_field_section_size: u64) -> Self {
        Self {
            transport: TransportConfig::default(),
            trust,
            max_field_section_size,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            read_size: 64 * 1024,
        }
    }

    pub(crate) fn quiche(&self) -> Result<(quiche::Config, H3Settings), Error> {
        let mut tls = SslContextBuilder::new(SslMethod::tls())?;
        match &self.trust {
            Trust::Roots(roots) => {
                if roots.system {
                    tls.set_default_verify_paths()?;
                }
                for pem in &roots.pem {
                    for cert in X509::stack_from_pem(pem)? {
                        tls.cert_store_mut().add_cert(cert)?;
                    }
                }
                tls.set_verify(SslVerifyMode::PEER);
            }
            Trust::Verifier(verifier) => {
                let verifier = verifier.clone();
                tls.enable_ocsp_stapling();
                tls.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| verifier.check(ssl));
            }
        }
        let mut quic = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)?;
        self.transport.apply(&mut quic)?;
        quic.verify_peer(true);
        Ok((
            quic,
            H3Settings {
                max_field_section_size: self.max_field_section_size,
                qpack_max_table_capacity: self.qpack_max_table_capacity,
                qpack_blocked_streams: self.qpack_blocked_streams,
            },
        ))
    }
}

impl TransportConfig {
    fn apply(&self, quic: &mut quiche::Config) -> Result<(), Error> {
        quic.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        quic.set_cc_algorithm(self.congestion_control.algorithm());
        quic.enable_pacing(self.pacing);
        quic.set_max_idle_timeout(self.idle_timeout.map_or(0, |timeout| {
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
        }));
        quic.set_initial_max_data(self.initial_max_data);
        quic.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi);
        quic.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi);
        quic.set_initial_max_stream_data_uni(self.initial_max_stream_data_uni);
        quic.set_max_connection_window(self.max_connection_window);
        quic.set_max_stream_window(self.max_stream_window);
        quic.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        quic.set_initial_max_streams_uni(self.initial_max_streams_uni);
        quic.set_max_recv_udp_payload_size(self.max_recv_udp_payload_size);
        quic.set_max_send_udp_payload_size(self.max_send_udp_payload_size);
        quic.discover_pmtu(self.discover_pmtu);
        quic.set_disable_active_migration(self.disable_active_migration);
        Ok(())
    }
}

/// The HTTP/3 settings an endpoint sends, kept as values: quiche's
/// configuration is built for each connection that reaches HTTP/3.
#[derive(Debug, Clone, Copy)]
pub(crate) struct H3Settings {
    max_field_section_size: u64,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
}

impl H3Settings {
    pub(crate) fn build(self) -> quiche::h3::Config {
        let mut config =
            quiche::h3::Config::new().expect("quiche's default HTTP/3 settings are valid");
        config.set_max_field_section_size(self.max_field_section_size);
        config.set_qpack_max_table_capacity(self.qpack_max_table_capacity);
        config.set_qpack_blocked_streams(self.qpack_blocked_streams);
        config
    }
}
