use crate::blocklist::BlocklistManager;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::{FeatureManager, SafeSearchTarget};
use crate::stats::{QueryLogEntry, Stats};
use chrono::Utc;
use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::Ipv4Addr;
use std::time::Instant;
use tracing::debug;

/// Process a DNS query: check safe search, check blocklist, forward if allowed.
pub async fn process_dns_query(
    packet: &[u8],
    client_ip: &str,
    blocklist: &BlocklistManager,
    upstream: &UpstreamForwarder,
    stats: &Stats,
    features: &FeatureManager,
) -> anyhow::Result<Vec<u8>> {
    let start = Instant::now();
    let request = Message::from_bytes(packet)?;

    let question = match request.queries().first() {
        Some(q) => q,
        None => anyhow::bail!("No question in DNS query"),
    };

    let domain = question.name().to_string();
    let query_type = question.query_type();
    let domain_trimmed = domain.trim_end_matches('.');

    debug!(
        "Query from {}: {} {:?}",
        client_ip, domain_trimmed, query_type
    );

    // Check safe search rewriting (only for A queries)
    if query_type == RecordType::A {
        if let Some(target) = features.get_safe_search_target(domain_trimmed).await {
            let safe_ip = match &target {
                SafeSearchTarget::A(ip) => Some(*ip),
                SafeSearchTarget::Cname(cname) => {
                    // Resolve the CNAME target via upstream
                    resolve_cname_to_ip(upstream, cname).await
                }
            };

            if let Some(ip) = safe_ip {
                let response = build_safe_search_response(&request, &domain, ip);
                let response_bytes = response.to_vec()?;

                stats.record_query(QueryLogEntry {
                    timestamp: Utc::now(),
                    domain: domain_trimmed.to_string(),
                    query_type: format!("{:?}", query_type),
                    client_ip: client_ip.to_string(),
                    blocked: false,
                    response_time_ms: start.elapsed().as_millis() as u64,
                    upstream: Some("safe-search".to_string()),
                });

                debug!("Safe search rewrite: {} -> {}", domain_trimmed, ip);
                return Ok(response_bytes);
            }
        }
    }

    // Check blocklist
    if blocklist.is_blocked(domain_trimmed).await {
        let response = build_blocked_response(&request, &domain, query_type);
        let response_bytes = response.to_vec()?;

        stats.record_query(QueryLogEntry {
            timestamp: Utc::now(),
            domain: domain_trimmed.to_string(),
            query_type: format!("{:?}", query_type),
            client_ip: client_ip.to_string(),
            blocked: true,
            response_time_ms: start.elapsed().as_millis() as u64,
            upstream: None,
        });

        debug!("Blocked: {} {:?}", domain_trimmed, query_type);
        return Ok(response_bytes);
    }

    // Forward to upstream
    let (response_bytes, upstream_used) = upstream.forward(packet).await?;

    stats.record_query(QueryLogEntry {
        timestamp: Utc::now(),
        domain: domain_trimmed.to_string(),
        query_type: format!("{:?}", query_type),
        client_ip: client_ip.to_string(),
        blocked: false,
        response_time_ms: start.elapsed().as_millis() as u64,
        upstream: Some(upstream_used),
    });

    Ok(response_bytes)
}

/// Build a safe search response that returns a specific IP.
fn build_safe_search_response(request: &Message, domain: &str, ip: std::net::Ipv4Addr) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    let name = Name::from_ascii(domain).unwrap_or_default();
    let rdata = RData::A(ip.into());
    let record = Record::from_rdata(name, 60, rdata);
    response.add_answer(record);

    response
}

/// Build a response that blocks the domain by returning 0.0.0.0 / :: sinkhole.
fn build_blocked_response(request: &Message, domain: &str, query_type: RecordType) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    let name = Name::from_ascii(domain).unwrap_or_default();
    match query_type {
        RecordType::A => {
            let rdata = RData::A("0.0.0.0".parse().unwrap());
            let record = Record::from_rdata(name, 300, rdata);
            response.add_answer(record);
        }
        RecordType::AAAA => {
            let rdata = RData::AAAA("::".parse().unwrap());
            let record = Record::from_rdata(name, 300, rdata);
            response.add_answer(record);
        }
        _ => {}
    }

    response
}

/// Resolve a CNAME target to an IPv4 address by building and forwarding a DNS query.
async fn resolve_cname_to_ip(upstream: &UpstreamForwarder, cname: &str) -> Option<Ipv4Addr> {
    use hickory_proto::op::Query;

    let name = Name::from_ascii(&format!("{}.", cname)).ok()?;
    let mut request = Message::new();
    let mut header = Header::new();
    header.set_id(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(1234));
    header.set_message_type(MessageType::Query);
    header.set_op_code(OpCode::Query);
    header.set_recursion_desired(true);
    request.set_header(header);

    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::A);
    request.add_query(query);

    let packet = request.to_vec().ok()?;
    let (response_bytes, _) = upstream.forward(&packet).await.ok()?;
    let response = Message::from_bytes(&response_bytes).ok()?;

    for answer in response.answers() {
        if let RData::A(ip) = answer.data() {
            return Some(ip.0);
        }
    }
    None
}
