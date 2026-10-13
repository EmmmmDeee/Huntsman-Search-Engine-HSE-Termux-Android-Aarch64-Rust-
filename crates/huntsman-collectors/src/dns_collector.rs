//! A DAG collector that resolves domains to IP addresses over unprivileged UDP/53.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use huntsman_core::{
    Collector, Entity, EntityKind, EpistemicLevel, HuntsmanError, NetworkGovernor,
    ProvenanceEnvelope, Transport,
};

use crate::dns::{self, DnsOutcome, QueryKey};

/// Resolves `Domain` entities to `Ip` entities by querying a recursive resolver over UDP/53.
///
/// A domain is resolved with two queries, `A` and `AAAA`, each paced through the governor's
/// per-host permit so a burst never hammers one resolver, and each bounded to the configured
/// EDNS UDP payload ceiling. Every datagram is bound to the query that provoked it (see
/// [`crate::dns::parse`]) before any address is trusted: a forged transaction id, an unsolicited
/// question, a set TC bit, or a server-failure RCODE never becomes a silent success.
///
/// # Observation time
///
/// The engine forbids nondeterministic clocks in library code, and [`Collector::process`] takes
/// no clock, so the time an answer is observed is supplied to [`DnsResolveCollector::new`] by the
/// caller and stamped onto every discovered entity. Discovered addresses therefore carry when the
/// DNS answer was observed, not the parent domain's observation time.
pub struct DnsResolveCollector {
    resolver_host: String,
    resolver_port: u16,
    timeout: Duration,
    max_response: usize,
    edns_udp_payload: u16,
    observed_at_unix: u64,
    nonce: u64,
    counter: AtomicU64,
}

impl DnsResolveCollector {
    /// Resolver host with standard port 53, a 5s timeout, and a 4096-byte EDNS/response ceiling.
    ///
    /// `observed_at_unix` is the observation time stamped onto discovered entities (the engine
    /// bans clocks in library code, so the caller supplies it). The transaction-id nonce is the
    /// process id; see [`crate::dns`] for the id scheme's threat model.
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

    /// Issue one query for `qtype` and validate the datagram against it, returning the typed
    /// outcome together with the raw response bytes that evidence it.
    async fn query_once(
        &self,
        domain: &str,
        qtype: u16,
        transport: &Arc<dyn Transport>,
        governor: &NetworkGovernor,
    ) -> Result<(DnsOutcome, Vec<u8>), HuntsmanError> {
        let id = dns::transaction_id(
            self.nonce,
            self.counter.fetch_add(1, Ordering::Relaxed),
            domain,
            qtype,
        );
        let query = dns::encode_query(id, domain, qtype, self.edns_udp_payload)?;
        // Per-host pacing: consecutive dispatches to this resolver are spaced by the governor's
        // cooldown, and the socket permit is held for the dialogue so the FD budget is honoured.
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
            name: domain.to_ascii_lowercase(),
            qtype,
        };
        let outcome = dns::parse(&key, &response)?;
        Ok((outcome, response))
    }

    /// Build an `Ip` entity for `record`, stamped with the answer's observation time.
    fn emit(&self, input: &Entity, raw: &[u8], ip: std::net::IpAddr) -> Entity {
        let kind = EntityKind::Ip(ip);
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
impl Collector for DnsResolveCollector {
    fn name(&self) -> &'static str {
        "dns_resolve"
    }

    fn can_consume(&self, kind: &EntityKind) -> bool {
        matches!(kind, EntityKind::Domain(_))
    }

    async fn process(
        &self,
        input: &Entity,
        transport: Arc<dyn Transport>,
        governor: NetworkGovernor,
    ) -> Result<Vec<Entity>, HuntsmanError> {
        let EntityKind::Domain(domain) = &input.kind else {
            return Ok(Vec::new());
        };

        let mut discovered: Vec<Entity> = Vec::new();
        // The first failure (a server failure, a truncated answer, or a transport/parse error) is
        // kept so an empty result is surfaced as that failure rather than as a silent success.
        let mut failure: Option<HuntsmanError> = None;
        // Whether any query returned a definitive answer (records or NXDOMAIN), so an empty-but-
        // definitive result (e.g. no A for an IPv6-only name) is a real zero, not a failure.
        let mut definitive = false;

        for qtype in [dns::TYPE_A, dns::TYPE_AAAA] {
            match self.query_once(domain, qtype, &transport, &governor).await {
                Ok((DnsOutcome::Answers(records), raw)) => {
                    definitive = true;
                    for record in records {
                        discovered.push(self.emit(input, &raw, record.ip()));
                    }
                }
                Ok((DnsOutcome::NameError, _)) => definitive = true,
                Ok((DnsOutcome::Truncated, _)) => {
                    if failure.is_none() {
                        failure = Some(HuntsmanError::Protocol(format!(
                            "DNS answer for {domain} was truncated (TC set) and cannot be trusted over UDP"
                        )));
                    }
                }
                Ok((DnsOutcome::ServerFailure(rcode), _)) => {
                    if failure.is_none() {
                        failure = Some(HuntsmanError::Protocol(format!(
                            "resolver returned RCODE {rcode} for {domain}"
                        )));
                    }
                }
                Err(err) => {
                    if failure.is_none() {
                        failure = Some(err);
                    }
                }
            }
        }

        if !discovered.is_empty() {
            return Ok(discovered);
        }
        if definitive && failure.is_none() {
            // Both queries resolved definitively to no address: a real empty result.
            return Ok(Vec::new());
        }
        Err(failure.unwrap_or_else(|| {
            HuntsmanError::Transport(format!("no DNS answer was obtained for {domain}"))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use huntsman_core::{GovernorConfig, MockTransport, UnprivilegedPosixTransport};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::net::UdpSocket;

    /// Parent observation time of a seed domain entity; distinct from the answer time below.
    const PARENT_OBSERVED: u64 = 1_000_000;
    /// The answer observation time supplied to the collector in tests.
    const ANSWER_OBSERVED: u64 = 2_000_000;

    fn domain_entity(domain: &str) -> Entity {
        let kind = match EntityKind::new_domain(domain) {
            Ok(kind) => kind,
            Err(err) => panic!("domain must canonicalize: {err}"),
        };
        let provenance = ProvenanceEnvelope::new(
            "seed",
            PARENT_OBSERVED,
            domain.as_bytes(),
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

    /// What the loopback resolver should answer, by record type and RCODE.
    #[derive(Clone)]
    struct Plan {
        a: Vec<Ipv4Addr>,
        aaaa: Vec<Ipv6Addr>,
        rcode: u8,
    }

    /// Read a query datagram's id and QTYPE and the byte range of its question (offsets 12..end).
    fn read_query(buf: &[u8]) -> (u16, u16, usize) {
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let mut pos = 12;
        while buf[pos] != 0 {
            pos += 1 + usize::from(buf[pos]);
        }
        let name_end = pos + 1;
        let qtype = u16::from_be_bytes([buf[name_end], buf[name_end + 1]]);
        (id, qtype, name_end + 4)
    }

    /// Craft a correctly-bound response (echoing the id and question) for the plan.
    fn build_response(query: &[u8], plan: &Plan) -> Vec<u8> {
        let (id, qtype, question_end) = read_query(query);
        let flags = (0x8180u16 & 0xFFF0) | u16::from(plan.rcode);
        let count = match qtype {
            dns::TYPE_A => plan.a.len(),
            dns::TYPE_AAAA => plan.aaaa.len(),
            _ => 0,
        };
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        msg.extend_from_slice(&(count as u16).to_be_bytes()); // ANCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        msg.extend_from_slice(&query[12..question_end]); // echo the question verbatim
        let push = |msg: &mut Vec<u8>, rtype: u16, rdata: &[u8]| {
            msg.extend_from_slice(&[0xC0, 0x0C]); // owner = pointer to the question name
            msg.extend_from_slice(&rtype.to_be_bytes());
            msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            msg.extend_from_slice(&300u32.to_be_bytes()); // TTL
            msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            msg.extend_from_slice(rdata);
        };
        if qtype == dns::TYPE_A {
            for ip in &plan.a {
                push(&mut msg, dns::TYPE_A, &ip.octets());
            }
        } else if qtype == dns::TYPE_AAAA {
            for ip in &plan.aaaa {
                push(&mut msg, dns::TYPE_AAAA, &ip.octets());
            }
        }
        msg
    }

    /// Bind a loopback UDP resolver that serves `requests` datagrams from `plan`, returning its
    /// port and the server task.
    async fn spawn_resolver(plan: Plan, requests: usize) -> (u16, tokio::task::JoinHandle<()>) {
        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(err) => panic!("resolver bind failed: {err}"),
        };
        let port = match socket.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("resolver local_addr failed: {err}"),
        };
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            for _ in 0..requests {
                let (len, peer) = match socket.recv_from(&mut buf).await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let response = build_response(&buf[..len], &plan);
                if socket.send_to(&response, peer).await.is_err() {
                    return;
                }
            }
        });
        (port, handle)
    }

    /// Resolve `domain` against a loopback resolver following `plan`.
    async fn resolve_via_loopback(plan: Plan, domain: &str) -> Result<Vec<Entity>, HuntsmanError> {
        let (port, handle) = spawn_resolver(plan, 2).await;
        let transport: Arc<dyn Transport> = Arc::new(UnprivilegedPosixTransport::new());
        let collector =
            DnsResolveCollector::new("127.0.0.1", ANSWER_OBSERVED).with_resolver_port(port);
        let seed = domain_entity(domain);
        let out = collector
            .process(&seed, transport, no_cooldown_governor())
            .await;
        handle.abort();
        out
    }

    #[tokio::test]
    async fn non_domain_entities_are_ignored() {
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let collector = DnsResolveCollector::new("1.1.1.1", ANSWER_OBSERVED);
        let kind = EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let provenance = ProvenanceEnvelope::new(
            "seed",
            PARENT_OBSERVED,
            b"10.0.0.1",
            &kind,
            EpistemicLevel::DirectObservation,
        );
        let seed = Entity {
            provenance,
            kind,
            hop_depth: 0,
        };
        assert!(!collector.can_consume(&seed.kind));
        let out = match collector
            .process(&seed, transport, no_cooldown_governor())
            .await
        {
            Ok(out) => out,
            Err(err) => panic!("process errored on ignored kind: {err}"),
        };
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn a_missing_resolver_route_surfaces_a_transport_error() {
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let collector = DnsResolveCollector::new("1.1.1.1", ANSWER_OBSERVED);
        let seed = domain_entity("example.com");
        assert!(collector
            .process(&seed, transport, no_cooldown_governor())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_forged_transaction_id_datagram_is_not_trusted() {
        // A fixed datagram whose transaction id (0x9999) the collector's generated ids never
        // match: both the A and AAAA query reject it, so no address is ever surfaced.
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&0x9999u16.to_be_bytes());
        datagram.extend_from_slice(&0x8180u16.to_be_bytes());
        datagram.extend_from_slice(&1u16.to_be_bytes());
        datagram.extend_from_slice(&1u16.to_be_bytes());
        datagram.extend_from_slice(&0u16.to_be_bytes());
        datagram.extend_from_slice(&0u16.to_be_bytes());
        for label in ["example", "com"] {
            datagram.push(label.len() as u8);
            datagram.extend_from_slice(label.as_bytes());
        }
        datagram.push(0);
        datagram.extend_from_slice(&dns::TYPE_A.to_be_bytes());
        datagram.extend_from_slice(&1u16.to_be_bytes());
        datagram.extend_from_slice(&[0xC0, 0x0C]);
        datagram.extend_from_slice(&dns::TYPE_A.to_be_bytes());
        datagram.extend_from_slice(&1u16.to_be_bytes());
        datagram.extend_from_slice(&300u32.to_be_bytes());
        datagram.extend_from_slice(&4u16.to_be_bytes());
        datagram.extend_from_slice(&[6, 6, 6, 6]);

        let transport = Arc::new(MockTransport::new());
        transport.register_udp("1.1.1.1", 53, datagram).await;
        let collector = DnsResolveCollector::new("1.1.1.1", ANSWER_OBSERVED);
        let seed = domain_entity("example.com");
        let result = collector
            .process(&seed, transport, no_cooldown_governor())
            .await;
        let entities = result.unwrap_or_default();
        assert!(
            !entities
                .iter()
                .any(|e| e.kind == EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6)))),
            "a forged-transaction-id datagram was trusted: {entities:?}"
        );
    }

    #[tokio::test]
    async fn resolves_a_domain_to_both_ipv4_and_ipv6() {
        let v4 = Ipv4Addr::new(93, 184, 216, 34);
        let v6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let plan = Plan {
            a: vec![v4],
            aaaa: vec![v6],
            rcode: 0,
        };
        let discovered = match resolve_via_loopback(plan, "example.com").await {
            Ok(entities) => entities,
            Err(err) => panic!("process failed: {err}"),
        };
        let addrs: Vec<IpAddr> = discovered
            .iter()
            .map(|e| match &e.kind {
                EntityKind::Ip(ip) => *ip,
                other => panic!("expected an Ip entity, got {other:?}"),
            })
            .collect();
        assert!(addrs.contains(&IpAddr::V4(v4)), "{addrs:?}");
        assert!(addrs.contains(&IpAddr::V6(v6)), "{addrs:?}");
        for entity in &discovered {
            assert_eq!(entity.hop_depth, 1);
            assert_eq!(entity.provenance.source_module, "dns_resolve");
        }
    }

    #[tokio::test]
    async fn an_ipv6_only_domain_yields_its_aaaa_addresses() {
        // Finding 5: the A query is a real empty success and the AAAA query carries the address.
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
        let plan = Plan {
            a: vec![],
            aaaa: vec![v6],
            rcode: 0,
        };
        let discovered = match resolve_via_loopback(plan, "v6only.example").await {
            Ok(entities) => entities,
            Err(err) => panic!("process failed: {err}"),
        };
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].kind, EntityKind::Ip(IpAddr::V6(v6)));
    }

    #[tokio::test]
    async fn discovered_entities_carry_the_answer_time_not_the_parent_time() {
        // Finding 4: the Ip entity's observed_at_utc is the answer time, not the seed's.
        let plan = Plan {
            a: vec![Ipv4Addr::new(1, 2, 3, 4)],
            aaaa: vec![],
            rcode: 0,
        };
        let discovered = match resolve_via_loopback(plan, "example.com").await {
            Ok(entities) => entities,
            Err(err) => panic!("process failed: {err}"),
        };
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].provenance.observed_at_utc, ANSWER_OBSERVED);
        assert_ne!(discovered[0].provenance.observed_at_utc, PARENT_OBSERVED);
    }

    #[tokio::test]
    async fn a_servfail_is_surfaced_as_an_error_not_an_empty_success() {
        // Finding 3: SERVFAIL on both queries is never a silent empty success.
        let plan = Plan {
            a: vec![],
            aaaa: vec![],
            rcode: 2,
        };
        let result = resolve_via_loopback(plan, "example.com").await;
        assert!(
            matches!(result, Err(HuntsmanError::Protocol(_))),
            "{result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_two_queries_are_paced_per_host() {
        // The collector takes a per-host permit for each of its two queries, so the second
        // dispatch to one resolver is spaced by the governor cooldown. MockTransport is instant,
        // so the elapsed virtual time is the pacing alone.
        let cooldown = Duration::from_millis(250);
        let transport = Arc::new(MockTransport::new());
        // Any datagram; it is rejected on binding, which does not affect the pacing measurement.
        transport.register_udp("1.1.1.1", 53, vec![0u8; 12]).await;
        let governor = NetworkGovernor::new(GovernorConfig {
            max_active_sockets: 8,
            per_host_cooldown: cooldown,
        });
        let collector = DnsResolveCollector::new("1.1.1.1", ANSWER_OBSERVED);
        let seed = domain_entity("example.com");

        let started = tokio::time::Instant::now();
        let _ = collector.process(&seed, transport, governor).await;
        assert!(
            started.elapsed() >= cooldown,
            "the second query was not paced: {:?}",
            started.elapsed()
        );
    }
}
