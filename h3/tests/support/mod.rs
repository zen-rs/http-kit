//! What the end-to-end tests share: a certificate authority made at test
//! time, real text, and a way to run one test body on each runtime.
#![allow(dead_code)]

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509Name, X509NameBuilder, X509NameRef,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use futures_lite::future::or;
use http_kit_h3::{ClientConfig, Identity, Roots, ServerConfig};
use http_kit_io::Io;

/// Greetings in Chinese, Japanese and Korean, for bodies and fields.
pub const CJK: [&str; 3] = ["你好，世界。", "こんにちは、世界。", "안녕하세요, 세계."];

/// The field section limit both ends use.
pub const MAX_FIELD_SECTION: u64 = 16 * 1024;

pub fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn name(common_name: &str) -> X509Name {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    name.build()
}

fn builder(
    subject: &X509NameRef,
    issuer: &X509NameRef,
    key: &PKey<Private>,
) -> boring::x509::X509Builder {
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    cert.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(subject).unwrap();
    cert.set_issuer_name(issuer).unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert
}

/// A certificate authority and a server certificate it issued for
/// `localhost` and `127.0.0.1`.
pub struct Pki {
    /// The server's chain and key.
    pub identity: Identity,
    /// The authority's certificate, PEM.
    pub root: Vec<u8>,
}

pub fn pki() -> Pki {
    let ca_key = key();
    let ca_name = name("http-kit-h3 test authority");
    let mut ca = builder(&ca_name, &ca_name, &ca_key);
    ca.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(
        &KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();

    let leaf_key = key();
    let mut leaf = builder(&name("localhost"), ca.subject_name(), &leaf_key);
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip(&IpAddr::from(Ipv4Addr::LOCALHOST).to_string())
        .build(&leaf.x509v3_context(Some(&ca), None))
        .unwrap();
    leaf.append_extension(&san).unwrap();
    leaf.append_extension(
        &KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    leaf.append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf = leaf.build();

    let mut chain = leaf.to_pem().unwrap();
    chain.extend(ca.to_pem().unwrap());
    Pki {
        identity: Identity::from_pem(chain, leaf_key.private_key_to_pem_pkcs8().unwrap()),
        root: ca.to_pem().unwrap(),
    }
}

pub fn server_config(pki: &Pki) -> ServerConfig {
    ServerConfig::new(pki.identity.clone(), MAX_FIELD_SECTION)
}

pub fn client_config(pki: &Pki) -> ClientConfig {
    ClientConfig::new(
        Roots {
            system: false,
            pem: vec![pki.root.clone()],
        },
        MAX_FIELD_SECTION,
    )
}

/// Runs `test` to completion, failing it if it takes longer than `limit`.
pub async fn within<I: Io, F: Future>(io: &I, limit: Duration, test: F) -> F::Output {
    let expired = async {
        io.sleep(limit).await;
        panic!("test did not finish within {limit:?}");
    };
    or(test, expired).await
}

/// Runs a test body on a compio runtime.
pub fn on_compio<F: Future>(test: impl FnOnce(http_kit_io::compio::Compio) -> F) -> F::Output {
    compio::runtime::Runtime::new()
        .unwrap()
        .block_on(test(http_kit_io::compio::Compio))
}

/// Runs a test body on a current-thread tokio runtime.
pub fn on_tokio<F: Future>(test: impl FnOnce(http_kit_io::tokio::Tokio) -> F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test(http_kit_io::tokio::Tokio))
}
