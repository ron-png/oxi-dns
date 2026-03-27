use crate::config::TlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tracing::info;

/// Load or generate TLS certificate and key, returning a rustls ServerConfig.
pub fn build_server_config(tls_config: &TlsConfig) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = load_or_generate_certs(tls_config)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig that trusts common CAs (for upstream DoT/DoQ).
pub fn build_client_config() -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Build a quinn::ServerConfig from our rustls ServerConfig for DoQ.
pub fn build_quic_server_config(tls_config: &TlsConfig) -> anyhow::Result<quinn::ServerConfig> {
    let rustls_config = build_server_config(tls_config)?;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?;

    let mut quic_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::new(default_quic_transport());
    quic_config.transport_config(transport);

    Ok(quic_config)
}

/// Build a quinn::ClientConfig for upstream DoQ connections.
pub fn build_quic_client_config() -> anyhow::Result<quinn::ClientConfig> {
    let client_tls = build_client_config()?;
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    Ok(client_config)
}

fn default_quic_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
    ));
    transport
}

/// Load certificates from files, or generate a self-signed certificate.
fn load_or_generate_certs(
    tls_config: &TlsConfig,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match (&tls_config.cert_path, &tls_config.key_path) {
        (Some(cert_path), Some(key_path)) => {
            info!(
                "Loading TLS cert from {} and key from {}",
                cert_path, key_path
            );
            let cert_file = std::fs::File::open(cert_path)?;
            let key_file = std::fs::File::open(key_path)?;

            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
                    .collect::<Result<Vec<_>, _>>()?;

            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))?
                .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

            Ok((certs, key))
        }
        _ => {
            info!("No TLS cert/key configured, generating self-signed certificate");
            generate_self_signed()
        }
    }
}

/// Generate a self-signed certificate for localhost / oxi-hole.
fn generate_self_signed() -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>
{
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "oxi-hole.local".to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Oxi-Hole DNS Server");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST,
        )));

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}
