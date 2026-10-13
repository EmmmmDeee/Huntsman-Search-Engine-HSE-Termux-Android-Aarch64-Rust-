//! A DAG collector that reverse-resolves IP addresses to domain names over unprivileged UDP/53.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use huntsman_core::{
    Collector, Entity, EntityKind, EpistemicLevel, HuntsmanError, NetworkGovernor,
    ProvenanceEnvelope, Transport,
};

use crate::dns::{self, PtrOutcome, QueryKey};

/// Reverse-resolves `Ip` entities to `Domain` entities with a single `PTR` query over UDP/53.
///
/// The query name is the address's reverse-DNS form (`in-addr.arpa` for IPv4, `ip6.arpa` for
/// IPv6). The query is paced through the governor's per-host permit and every datagram is bound to
/// the query that provoked it (transaction id, QR bit, OPCODE, echoed question; see
/// [`crate::dns::parse_ptr`]) before any name is trusted. Each returned `PTR` name is validated
/// through [`EntityKind::new_domain`]; a name that is not a well-formed domain is dropped rather
/// than emitted. Paired with [`crate::DnsResolveCollector`], this closes the graph both ways
/// (domain -> address -> domain).
///
/// # Observation time
///
/// As with the forward resolver, the engine bans clocks in library code, so the answer's
/// observation time is supplied to [`PtrResolveCollector::new`] and stamped onto every discovered
/// entity.
pub struct PtrResolveCollector {
    resolver_host: String,
    resolver_port: u16,
    timeout: Duration,
    max_response: usize,
    edns_udp_payload: u16,
    observed_at_unix: u64,
    nonce: u64,
    counter: AtomicU64,
}

impl PtrResolveCollector {
    /// Resolver host with standard port 53, a 5s timeout, and a 4096-byte EDNS/response ceiling.
    ///
    /// `observed_at_unix` is stamped onto discovered entities (the engine bans clocks in library
    /// code, so the caller supplies it).
    #[must_use]
    pub fn new(resolver_host: impl Into<String>, observed_at_unix: u64) -> Self {
        Self {
            resolver_host: resolver_host.into(),
            resolver_port: 53,
            timeout: Duration::from_secs(5),
            max_response: 4096,
            edns_udp_payload: 4096,
            observed_at_unix,
            nonce: u64::from(std::process::id()),
            counter: AtomicU64::new(0),
        }
    }

    /// Override the resolver UDP port (the default is 53).
    #[must_use]
    pub fn with_resolver_port(mut self, port: u16) -> Self {
        self.resolver_port = port;
        self
    }

    fn emit(&self, input: &Entity, raw: &[u8], kind: EntityKind) -> Entity {
        let provenance = ProvenanceEnvelope::new(
            self.name(),
            self.observed_at_unix,
            raw,
            &kind,
            EpistemicLevel::DirectObservation,
        );
        Entity {
            provenance,
            kind,
            hop_depth: input.hop_depth.saturating_add(1),
        }
    }
}

#[async_trait]
impl Collector for PtrResolveCollector {
    fn name(&self) -> &'static str {
        "dns-ptr"
    }

    fn can_consume(&self, kind: &EntityKind) -> bool {
        matches!(kind, EntityKind::Ip(_))
    }

    async fn process(
        &self,
        input: &Entity,
        transport: Arc<dyn Transport>,
        governor: NetworkGovernor,
    ) -> Result<Vec<Entity>, HuntsmanError> {
        let EntityKind::Ip(ip) = &input.kind else {
            return Ok(Vec::new());
        };

        let reverse = dns::reverse_dns_name(*ip);
        let id = dns::transaction_id(
            self.nonce,
            self.counter.fetch_add(1, Ordering::Relaxed),
            &reverse,
            dns::TYPE_PTR,
        );
        let query = dns::encode_query(id, &reverse, dns::TYPE_PTR, self.edns_udp_payload)?;

        let _permit = governor.acquire_host_permit(&self.resolver_host).await?;
        let response = transport
            .udp_query(
                &self.resolver_host,
                self.resolver_port,
                &query,
                self.timeout,
                self.max_response,
            )
            .await?;

        let key = QueryKey {
            id,
            name: reverse,
            qtype: dns::TYPE_PTR,
        };
        match dns::parse_ptr(&key, &response)? {
            PtrOutcome::Names(names) => {
                let mut discovered = Vec::with_capacity(names.len());
                for name in names {
                    // A PTR target that is not a well-formed domain is dropped, not emitted.
                    if let Ok(kind) = EntityKind::new_domain(&name) {
                        discovered.push(self.emit(input, &response, kind));
                    }
                }
                Ok(discovered)
            }
            // The name definitively has no PTR record: a real empty result, not a failure.
            PtrOutcome::NameError => Ok(Vec::new()),
            PtrOutcome::Truncated => Err(HuntsmanError::Protocol(format!(
                "PTR answer for {ip} was truncated (TC set) and cannot be trusted over UDP"
            ))),
            PtrOutcome::ServerFailure(rcode) => Err(HuntsmanError::Protocol(format!(
                "resolver returned RCODE {rcode} for the reverse lookup of {ip}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use huntsman_core::{GovernorConfig, MockTransport, UnprivilegedPosixTransport};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    const ANSWER_OBSERVED: u64 = 2_000_000;

    fn ip_entity(ip: IpAddr) -> Entity {
        let kind = EntityKind::Ip(ip);
        let provenance = ProvenanceEnvelope::new(
            "seed",
            1_000_000,
            b"seed",
            &kind,
            EpistemicLevel::DirectObservation,
        );
        Entity {
            provenance,
            kind,
            hop_depth: 0,
        }
    }

    fn no_cooldown_governor() -> NetworkGovernor {
        NetworkGovernor::new(GovernorConfig {
            max_active_sockets: 8,
            per_host_cooldown: Duration::ZERO,
        })
    }

    /// A loopback resolver that echoes the query id and question and answers with `targets`
    /// (empty with `rcode` for NXDOMAIN etc.).
    async fn spawn_ptr_resolver(
        targets: Vec<String>,
        rcode: u8,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(s) => s,
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = match socket.local_addr() {
            Ok(a) => a.port(),
            Err(err) => panic!("local_addr failed: {err}"),
        };
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let query = &buf[..len];
            let mut pos = 12;
            while query[pos] != 0 {
                pos += 1 + usize::from(query[pos]);
            }
            let question_end = pos + 1 + 4;
            let mut msg = Vec::new();
            msg.extend_from_slice(&query[0..2]); // echo id
            let flags = (0x8180u16 & 0xFFF0) | u16::from(rcode);
            msg.extend_from_slice(&flags.to_be_bytes());
            msg.extend_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&(targets.len() as u16).to_be_bytes());
            msg.extend_from_slice(&0u16.to_be_bytes());
            msg.extend_from_slice(&0u16.to_be_bytes());
            msg.extend_from_slice(&query[12..question_end]); // echo the question
            for target in &targets {
                msg.extend_from_slice(&[0xC0, 0x0C]); // owner = question pointer
                msg.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
                msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                msg.extend_from_slice(&300u32.to_be_bytes());
                let mut rdata = Vec::new();
                for label in target.split('.') {
                    rdata.push(u8::try_from(label.len()).unwrap_or(0));
                    rdata.extend_from_slice(label.as_bytes());
                }
                rdata.push(0);
                msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                msg.extend_from_slice(&rdata);
            }
            let _ = socket.send_to(&msg, peer).await;
        });
        (port, handle)
    }

    async fn reverse_via_loopback(
        ip: IpAddr,
        targets: Vec<String>,
        rcode: u8,
    ) -> Result<Vec<Entity>, HuntsmanError> {
        let (port, handle) = spawn_ptr_resolver(targets, rcode).await;
        let transport: Arc<dyn Transport> = Arc::new(UnprivilegedPosixTransport::new());
        let collector =
            PtrResolveCollector::new("127.0.0.1", ANSWER_OBSERVED).with_resolver_port(port);
        let out = collector
            .process(&ip_entity(ip), transport, no_cooldown_governor())
            .await;
        handle.abort();
        out
    }

    #[tokio::test]
    async fn reverse_resolves_an_ip_to_a_domain_entity() {
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let out = match reverse_via_loopback(ip, vec!["host.example.com".to_owned()], 0).await {
            Ok(out) => out,
            Err(err) => panic!("reverse lookup failed: {err}"),
        };
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind.canonical_value(), "host.example.com");
        assert_eq!(out[0].hop_depth, 1);
        assert_eq!(out[0].provenance.observed_at_utc, ANSWER_OBSERVED);
        assert_eq!(out[0].provenance.source_module, "dns-ptr");
    }

    #[tokio::test]
    async fn an_ip_with_no_ptr_record_is_a_real_empty_result() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // RCODE 3 (NXDOMAIN): definitive, so an empty Vec, not an error.
        match reverse_via_loopback(ip, Vec::new(), 3).await {
            Ok(out) => assert!(out.is_empty()),
            Err(err) => panic!("NXDOMAIN must be a real empty result, got error: {err}"),
        }
    }

    #[tokio::test]
    async fn a_server_failure_is_surfaced_as_an_error() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        // RCODE 2 (SERVFAIL).
        assert!(reverse_via_loopback(ip, Vec::new(), 2).await.is_err());
    }

    #[tokio::test]
    async fn non_ip_entities_are_ignored() {
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let collector = PtrResolveCollector::new("1.1.1.1", ANSWER_OBSERVED);
        let kind = match EntityKind::new_domain("example.com") {
            Ok(kind) => kind,
            Err(err) => panic!("domain must canonicalize: {err}"),
        };
        let provenance = ProvenanceEnvelope::new(
            "seed",
            1,
            b"example.com",
            &kind,
            EpistemicLevel::DirectObservation,
        );
        let seed = Entity {
            provenance,
            kind,
            hop_depth: 0,
        };
        assert!(!collector.can_consume(&seed.kind));
        match collector
            .process(&seed, transport, no_cooldown_governor())
            .await
        {
            Ok(out) => assert!(out.is_empty()),
            Err(err) => panic!("ignored kind must not error: {err}"),
        }
    }
}
