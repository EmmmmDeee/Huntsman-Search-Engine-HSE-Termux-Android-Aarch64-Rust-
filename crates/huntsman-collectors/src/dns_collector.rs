//! A DAG collector that resolves domains to IP addresses over unprivileged UDP/53.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use huntsman_core::{
    Collector, Entity, EntityKind, EpistemicLevel, HuntsmanError, NetworkGovernor,
    ProvenanceEnvelope, Transport,
};

use crate::dns;

/// Resolves `Domain` entities to `Ip` entities by querying a recursive resolver over UDP/53.
///
/// Each query takes one governor socket permit for its lifetime, holding the engine within its
/// file-descriptor budget, and bounds the response read to a fixed EDNS-sized ceiling.
pub struct DnsResolveCollector {
    resolver_host: String,
    resolver_port: u16,
    timeout: Duration,
    max_response: usize,
}

impl DnsResolveCollector {
    /// Resolver host with standard port 53, a 5s timeout, and a 4096-byte response ceiling.
    #[must_use]
    pub fn new(resolver_host: impl Into<String>) -> Self {
        Self {
            resolver_host: resolver_host.into(),
            resolver_port: 53,
            timeout: Duration::from_secs(5),
            max_response: 4096,
        }
    }
}

#[async_trait]
impl Collector for DnsResolveCollector {
    fn name(&self) -> &'static str {
        "dns-resolve"
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

        // Hold a socket permit for the dialogue so the engine stays within its FD budget.
        let _permit = governor.acquire_socket_permit().await?;
        let query = dns::encode_query(0x1a2b, domain, dns::TYPE_A)?;
        let response = transport
            .udp_query(
                &self.resolver_host,
                self.resolver_port,
                &query,
                self.timeout,
                self.max_response,
            )
            .await?;

        let records = dns::parse_answers(&response)?;
        let mut discovered = Vec::with_capacity(records.len());
        for record in records {
            let kind = EntityKind::Ip(record.ip());
            let provenance = ProvenanceEnvelope::new(
                self.name(),
                input.provenance.observed_at_utc,
                &response,
                &kind,
                EpistemicLevel::DirectObservation,
            );
            discovered.push(Entity {
                provenance,
                kind,
                hop_depth: input.hop_depth.saturating_add(1),
            });
        }
        Ok(discovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use huntsman_core::{GovernorConfig, MockTransport};
    use std::net::{IpAddr, Ipv4Addr};

    fn domain_entity(domain: &str) -> Entity {
        let kind = match EntityKind::new_domain(domain) {
            Ok(kind) => kind,
            Err(err) => panic!("domain must canonicalize: {err}"),
        };
        let provenance = ProvenanceEnvelope::new(
            "seed",
            1_710_000_000,
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

    fn response_a() -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x1a2bu16.to_be_bytes());
        msg.extend_from_slice(&0x8180u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        for label in ["example", "com"] {
            msg.push(u8::try_from(label.len()).unwrap_or(0));
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&dns::TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&dns::TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[93, 184, 216, 34]);
        msg
    }

    #[tokio::test]
    async fn resolves_a_domain_to_an_ip_entity_offline() {
        let transport = Arc::new(MockTransport::new());
        transport.register_udp("1.1.1.1", 53, response_a()).await;
        let governor = NetworkGovernor::new(GovernorConfig::default());
        let collector = DnsResolveCollector::new("1.1.1.1");
        let seed = domain_entity("example.com");

        let discovered = match collector.process(&seed, transport, governor).await {
            Ok(entities) => entities,
            Err(err) => panic!("process failed: {err}"),
        };

        assert_eq!(discovered.len(), 1);
        assert_eq!(
            discovered[0].kind,
            EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
        assert_eq!(discovered[0].hop_depth, 1);
        assert_eq!(discovered[0].provenance.source_module, "dns-resolve");
    }

    #[tokio::test]
    async fn a_missing_resolver_route_surfaces_a_transport_error() {
        let transport = Arc::new(MockTransport::new());
        let governor = NetworkGovernor::new(GovernorConfig::default());
        let collector = DnsResolveCollector::new("1.1.1.1");
        let seed = domain_entity("example.com");
        assert!(collector.process(&seed, transport, governor).await.is_err());
    }

    #[tokio::test]
    async fn non_domain_entities_are_ignored() {
        let transport = Arc::new(MockTransport::new());
        let governor = NetworkGovernor::new(GovernorConfig::default());
        let collector = DnsResolveCollector::new("1.1.1.1");
        let kind = EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let provenance = ProvenanceEnvelope::new(
            "seed",
            1_710_000_000,
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
        let out = match collector.process(&seed, transport, governor).await {
            Ok(out) => out,
            Err(err) => panic!("process errored on ignored kind: {err}"),
        };
        assert!(out.is_empty());
    }
}
