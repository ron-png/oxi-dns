use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::warn;

/// Parsed upstream server specification.
#[derive(Debug, Clone)]
pub enum UpstreamSpec {
    /// Plain UDP DNS (e.g., "8.8.8.8:53" or "udp://8.8.8.8:53")
    Udp(SocketAddr),
    /// DNS-over-TLS (e.g., "tls://1.1.1.1:853" or "tls://dns.google:853")
    Tls { addr: SocketAddr, hostname: String },
    /// DNS-over-HTTPS (e.g., "https://dns.google/dns-query")
    Https { url: String },
    /// DNS-over-QUIC (e.g., "quic://dns.adguard-dns.com:853")
    Quic { addr: SocketAddr, hostname: String },
}

impl UpstreamSpec {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(rest) = s.strip_prefix("tls://") {
            let (hostname, addr) = parse_host_port(rest, 853)?;
            Ok(Self::Tls { addr, hostname })
        } else if s.starts_with("https://") {
            Ok(Self::Https { url: s.to_string() })
        } else if let Some(rest) = s.strip_prefix("quic://") {
            let (hostname, addr) = parse_host_port(rest, 853)?;
            Ok(Self::Quic { addr, hostname })
        } else if let Some(rest) = s.strip_prefix("udp://") {
            let addr: SocketAddr = rest.parse()?;
            Ok(Self::Udp(addr))
        } else {
            // Default: plain UDP
            let addr: SocketAddr = s.parse()?;
            Ok(Self::Udp(addr))
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Udp(addr) => format!("udp://{}", addr),
            Self::Tls { hostname, addr } => format!("tls://{}:{}", hostname, addr.port()),
            Self::Https { url } => url.clone(),
            Self::Quic { hostname, addr } => format!("quic://{}:{}", hostname, addr.port()),
        }
    }
}

fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(String, SocketAddr)> {
    // Try as SocketAddr first (e.g., "1.1.1.1:853")
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr));
    }

    // Try as host:port (e.g., "dns.google:853")
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            let addr = resolve_hostname(host, port)?;
            return Ok((host.to_string(), addr));
        }
    }

    // Just a hostname, use default port
    let addr = resolve_hostname(s, default_port)?;
    Ok((s.to_string(), addr))
}

fn resolve_hostname(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", host))?;
    Ok(addr)
}

/// Handles forwarding DNS queries to upstream servers with multi-protocol support.
#[derive(Clone)]
pub struct UpstreamForwarder {
    upstreams: Vec<UpstreamSpec>,
    timeout: Duration,
    tls_client_config: Arc<rustls::ClientConfig>,
    quic_client_config: quinn::ClientConfig,
}

impl UpstreamForwarder {
    pub fn new(
        upstream_strs: &[String],
        timeout_ms: u64,
        tls_client_config: Arc<rustls::ClientConfig>,
        quic_client_config: quinn::ClientConfig,
    ) -> anyhow::Result<Self> {
        let mut upstreams = Vec::new();
        for s in upstream_strs {
            match UpstreamSpec::parse(s) {
                Ok(spec) => {
                    tracing::info!("Upstream: {}", spec.label());
                    upstreams.push(spec);
                }
                Err(e) => {
                    warn!("Skipping invalid upstream '{}': {}", s, e);
                }
            }
        }
        if upstreams.is_empty() {
            anyhow::bail!("No valid upstream DNS servers configured");
        }
        Ok(Self {
            upstreams,
            timeout: Duration::from_millis(timeout_ms),
            tls_client_config,
            quic_client_config,
        })
    }

    /// Forward a DNS query to upstream servers, trying each in order.
    /// Returns (response_bytes, upstream_label).
    pub async fn forward(&self, packet: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
        for upstream in &self.upstreams {
            let result = match upstream {
                UpstreamSpec::Udp(addr) => self.forward_udp(packet, *addr).await,
                UpstreamSpec::Tls { addr, hostname } => {
                    self.forward_dot(packet, *addr, hostname).await
                }
                UpstreamSpec::Https { url } => self.forward_doh(packet, url).await,
                UpstreamSpec::Quic { addr, hostname } => {
                    self.forward_doq(packet, *addr, hostname).await
                }
            };

            match result {
                Ok(response) => return Ok((response, upstream.label())),
                Err(e) => {
                    warn!("Upstream {} failed: {}", upstream.label(), e);
                }
            }
        }
        anyhow::bail!("All upstream DNS servers failed")
    }

    /// Plain UDP forwarding.
    async fn forward_udp(&self, packet: &[u8], addr: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(packet, addr).await?;

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await??;
        Ok(buf[..len].to_vec())
    }

    /// DNS-over-TLS forwarding.
    async fn forward_dot(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let connector = tokio_rustls::TlsConnector::from(self.tls_client_config.clone());
        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())?;

        let tcp =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(addr)).await??;
        let mut tls =
            tokio::time::timeout(self.timeout, connector.connect(server_name, tcp)).await??;

        // DNS over TCP/TLS: 2-byte big-endian length prefix
        let len_bytes = (packet.len() as u16).to_be_bytes();
        tls.write_all(&len_bytes).await?;
        tls.write_all(packet).await?;
        tls.flush().await?;

        // Read response length
        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, tls.read_exact(&mut resp_len_buf)).await??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        // Read response
        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, tls.read_exact(&mut resp_buf)).await??;

        Ok(resp_buf)
    }

    /// DNS-over-HTTPS forwarding (RFC 8484).
    async fn forward_doh(&self, packet: &[u8], url: &str) -> anyhow::Result<Vec<u8>> {
        // Use reqwest for HTTPS POST with application/dns-message
        let client = reqwest::Client::builder().timeout(self.timeout).build()?;

        let response = client
            .post(url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(packet.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("DoH upstream returned status {}", response.status());
        }

        let body = response.bytes().await?;
        Ok(body.to_vec())
    }

    /// DNS-over-QUIC forwarding (RFC 9250).
    async fn forward_doq(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(self.quic_client_config.clone());

        let connection =
            tokio::time::timeout(self.timeout, endpoint.connect(addr, hostname)?).await??;

        // Open a bidirectional stream for this query
        let (mut send, mut recv) =
            tokio::time::timeout(self.timeout, connection.open_bi()).await??;

        // DoQ: 2-byte length prefix + DNS message
        let len_bytes = (packet.len() as u16).to_be_bytes();
        send.write_all(&len_bytes).await?;
        send.write_all(packet).await?;
        send.finish()?;

        // Read response: 2-byte length + message
        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut resp_len_buf)).await??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut resp_buf)).await??;

        // Clean up
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;

        Ok(resp_buf)
    }
}
