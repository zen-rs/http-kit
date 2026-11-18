//! Shared test fixtures for `http-kit-h2` conformance and interop suites:
//! runtime runners (`compio` and `tokio`), a self-signed localhost CA with ALPN
//! `h2`, and real Chinese/Japanese/Korean test text.
#![allow(dead_code)]

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_lite::future::or;
use http_kit_io::Timer;
use http_kit_tls::{TlsAcceptor, TlsConnector};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    SanType,
};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

/// Real multi-byte text covering Chinese, Japanese, and Korean.
pub const CJK: [&str; 3] = [
    "你好，世界。流控与零拷贝管道传输。",
    "こんにちは、世界。ストリーム多重化とフロー制御。",
    "안녕하세요, 세계. 무복사 파이프 및 흐름 제어.",
];

pub fn cjk_payload(repeat: usize) -> Vec<u8> {
    CJK.concat().into_bytes().repeat(repeat)
}

pub fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Throwaway CA and `localhost` / `127.0.0.1` server identity configured for ALPN `h2`.
#[derive(Clone)]
pub struct TestPki {
    pub ca_pem: String,
    pub server_rustls: Arc<RustlsServerConfig>,
    pub client_rustls: Arc<RustlsClientConfig>,
}

pub fn pki() -> TestPki {
    let provider = Arc::new(ring::default_provider());

    let ca_key = KeyPair::generate().expect("generate CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "http-kit-h2 test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();
    let ca_der: CertificateDer<'static> = ca_cert.der().clone();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf params");
    leaf_params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign leaf cert");

    let mut server_cfg = RustlsServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_cert.der().clone(), ca_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let mut roots = RootCertStore::empty();
    roots.add(ca_der).expect("add CA root");
    let mut client_cfg = RustlsClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

    TestPki {
        ca_pem,
        server_rustls: Arc::new(server_cfg),
        client_rustls: Arc::new(client_cfg),
    }
}

pub fn tls_acceptor(pki: &TestPki) -> TlsAcceptor {
    let acceptor = TlsAcceptor::new(pki.server_rustls.clone());
    #[cfg(target_os = "linux")]
    if let Ok(ktls) = http_kit_tls::KernelTls::probe() {
        return acceptor.with_kernel_tls(ktls);
    }
    acceptor
}

pub fn tls_connector(pki: &TestPki) -> TlsConnector {
    let connector = TlsConnector::new(pki.client_rustls.clone());
    #[cfg(target_os = "linux")]
    if let Ok(ktls) = http_kit_tls::KernelTls::probe() {
        return connector.with_kernel_tls(ktls);
    }
    connector
}

pub async fn within<I: Timer, F: Future>(io: &I, limit: Duration, test: F) -> F::Output {
    let expired = async {
        io.sleep(limit).await;
        panic!("test did not finish within {limit:?}");
    };
    or(test, expired).await
}

pub fn on_compio<F: Future>(test: impl FnOnce(http_kit_io::compio::Compio) -> F) -> F::Output {
    compio::runtime::Runtime::new()
        .expect("compio runtime")
        .block_on(test(http_kit_io::compio::Compio::default()))
}

pub fn on_tokio<F: Future>(test: impl FnOnce(http_kit_io::tokio::Tokio) -> F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, test(http_kit_io::tokio::Tokio))
}
