//! Kernel TLS: which cipher suites the running kernel can take.

#[cfg(target_os = "linux")]
pub(crate) mod linux;

use std::io;

/// What the running kernel's TLS offload can take, probed once and handed to
/// [`TlsAcceptor::with_kernel_tls`](crate::TlsAcceptor::with_kernel_tls) or
/// [`TlsConnector::with_kernel_tls`](crate::TlsConnector::with_kernel_tls).
///
/// Kernel TLS is Linux's (the `tls` module, AES-GCM-128/256 and
/// ChaCha20-Poly1305 for TLS 1.2 and 1.3). Elsewhere a probe finds nothing,
/// and every connection stays in user space.
#[derive(Debug, Clone, Copy)]
pub struct KernelTls {
    #[cfg(target_os = "linux")]
    ciphers: Option<linux::Ciphers>,
}

impl KernelTls {
    /// Probes the kernel: which cipher suites it accepts keys for, tried on
    /// loopback sockets.
    ///
    /// It opens and closes a few TCP connections to itself, so it runs once
    /// at startup, not per connection.
    ///
    /// # Errors
    ///
    /// The loopback sockets could not be opened, or the kernel refused a
    /// suite for a reason other than not supporting it.
    pub fn probe() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let ciphers = linux::probe()?;
            if ciphers.is_none() {
                tracing::debug!("the kernel has no TLS offload; is the `tls` module loaded?");
            }
            Ok(Self { ciphers })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {})
        }
    }

    /// Whether the kernel takes any suite at all.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.ciphers.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Whether the kernel takes `cipher` for `version`.
    #[cfg(target_os = "linux")]
    pub(crate) fn supports(
        &self,
        version: rustls::ProtocolVersion,
        cipher: crate::record::Cipher,
    ) -> bool {
        use crate::record::Cipher;

        let Some(ciphers) = self.ciphers else {
            return false;
        };
        let suites = match version {
            rustls::ProtocolVersion::TLSv1_2 => ciphers.tls12,
            rustls::ProtocolVersion::TLSv1_3 => ciphers.tls13,
            _ => return false,
        };
        match cipher {
            Cipher::Aes128Gcm => suites.aes_128_gcm,
            Cipher::Aes256Gcm => suites.aes_256_gcm,
            Cipher::Chacha20Poly1305 => suites.chacha20_poly1305,
        }
    }
}
