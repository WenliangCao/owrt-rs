//! TLS listener support: DER certificate/key files as used by uhttpd (-C/-K).

use std::fs;
use std::io;
use std::sync::Arc;

pub fn server_config(cert_path: &str, key_path: &str) -> io::Result<Arc<rustls::ServerConfig>> {
    let cert = fs::read(cert_path)?;
    let key = fs::read(key_path)?;
    let certs = vec![rustls::pki_types::CertificateDer::from(cert)];
    let key = rustls::pki_types::PrivateKeyDer::try_from(key)
        .or_else(|_| {
            // uhttpd's px5g writes PKCS#8 or SEC1 DER; try both interpretations
            fs::read(key_path).map(|k| {
                rustls::pki_types::PrivateKeyDer::Sec1(rustls::pki_types::PrivateSec1KeyDer::from(
                    k,
                ))
            })
        })
        .map_err(|e| io::Error::other(format!("private key: {e}")))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Arc::new(config))
}
