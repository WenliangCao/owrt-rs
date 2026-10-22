//! TLS listener support: DER certificate/key files as used by uhttpd (-C/-K).

use std::fs;
use std::io;
use std::sync::Arc;

pub fn server_config(
    cert_path: &str,
    key_path: &str,
    ciphers: Option<&str>,
) -> io::Result<Arc<rustls::ServerConfig>> {
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
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(ciphers) = ciphers.filter(|s| *s != "DEFAULT") {
        let mut selected = Vec::new();
        for name in ciphers.split(':') {
            let canonical = match name {
                "ECDHE-RSA-AES128-GCM-SHA256" | "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256" => {
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                }
                "ECDHE-RSA-AES256-GCM-SHA384" | "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384" => {
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                }
                "ECDHE-ECDSA-AES128-GCM-SHA256" | "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256" => {
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                }
                "ECDHE-ECDSA-AES256-GCM-SHA384" | "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384" => {
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                }
                "ECDHE-RSA-CHACHA20-POLY1305" | "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256" => {
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                }
                "ECDHE-ECDSA-CHACHA20-POLY1305"
                | "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256" => {
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                }
                other => other,
            };
            let Some(suite) = provider
                .cipher_suites
                .iter()
                .find(|suite| format!("{:?}", suite.suite()) == canonical)
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported TLS cipher: {name}"),
                ));
            };
            selected.push(*suite);
        }
        provider.cipher_suites = selected;
    }
    let provider = Arc::new(provider);
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Arc::new(config))
}
