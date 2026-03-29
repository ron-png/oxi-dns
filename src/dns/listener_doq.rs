use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

fn bind_udp_reuse_port(addr: &str) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr.parse()?;
    let domain = if sock_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sock_addr.into())?;
    Ok(socket.into())
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    addr: String,
    blocklist: BlocklistManager,
    stats: Stats,
    upstream: UpstreamForwarder,
    features: FeatureManager,
    blocking_mode: Arc<RwLock<BlockingMode>>,
    quic_config: quinn::ServerConfig,
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let std_socket = bind_udp_reuse_port(&addr)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quic_config),
        std_socket,
        quinn::default_runtime().unwrap(),
    )?;
    info!("DoQ listener ready on {}", addr);

    while let Some(incoming) = endpoint.accept().await {
        let bl = blocklist.clone();
        let st = stats.clone();
        let up = upstream.clone();
        let ft = features.clone();
        let bm = blocking_mode.clone();
        let ql = query_log.clone();
        let anon = anonymize_ip.clone();
        let ipv6_enabled = ipv6_enabled.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let peer = connection.remote_address();
                    let client_ip = peer.ip().to_string();

                    loop {
                        match connection.accept_bi().await {
                            Ok((send, recv)) => {
                                let bl = bl.clone();
                                let st = st.clone();
                                let up = up.clone();
                                let ft = ft.clone();
                                let bm = bm.clone();
                                let cip = client_ip.clone();
                                let ql = ql.clone();
                                let anon = anon.clone();
                                let ipv6 = ipv6_enabled.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = handle_doq_stream(
                                        send, recv, &cip, &bl, &st, &up, &ft, &bm, &ql, &anon,
                                        &ipv6,
                                    )
                                    .await
                                    {
                                        debug!("DoQ stream error from {}: {}", cip, e);
                                    }
                                });
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                            Err(e) => {
                                debug!("DoQ connection error: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("DoQ incoming connection error: {}", e);
                }
            }
        });
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_doq_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    client_ip: &str,
    blocklist: &BlocklistManager,
    stats: &Stats,
    upstream: &UpstreamForwarder,
    features: &FeatureManager,
    blocking_mode: &Arc<RwLock<BlockingMode>>,
    query_log: &QueryLog,
    anonymize_ip: &Arc<AtomicBool>,
    ipv6_enabled: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    if msg_len == 0 || msg_len > 65535 {
        anyhow::bail!("Invalid DoQ message length: {}", msg_len);
    }

    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf).await?;

    let response = handler::process_dns_query(
        &msg_buf,
        client_ip,
        blocklist,
        upstream,
        stats,
        features,
        blocking_mode,
        query_log,
        anonymize_ip,
        ipv6_enabled,
    )
    .await?;

    let resp_len = (response.len() as u16).to_be_bytes();
    send.write_all(&resp_len).await?;
    send.write_all(&response).await?;
    send.finish()?;

    Ok(())
}
