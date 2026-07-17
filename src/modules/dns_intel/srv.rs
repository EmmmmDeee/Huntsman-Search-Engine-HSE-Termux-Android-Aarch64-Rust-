//! DNS SRV service-discovery enumeration (RFC 2782) — `_service._proto.domain`
//! records name the concrete `host:port` an operator runs a service on. They
//! routinely expose internal service topology never advertised as a normal
//! subdomain, most valuably **Active Directory** domain controllers and global
//! catalog (`_ldap._tcp.dc._msdcs`, `_kerberos._tcp`, `_gc._tcp`), enterprise
//! mail/collaboration (`_autodiscover._tcp`, `_sipfederationtls._tcp`), federated
//! chat (`_xmpp-{client,server}._tcp`), calendaring (`_caldav`/`_carddav`), VoIP
//! (`_sip._*`), and volume-license activation (`_vlmcs._tcp`, a KMS host — a
//! strong Windows-enterprise fingerprint).
//!
//! Each resolved SRV target host becomes a new `Domain` entity: a fresh pivot the
//! engine re-dispatches through every `Domain`-accepting module (A/AAAA
//! resolution, brute force, permutation, CAA, port scan, TLS inspection, …). The
//! discovered service name and port ride along as evidence attributes.
//!
//! Gated to the **registrable domain** (`registrable_domain(target) == target`):
//! SRV service-discovery records are organisation-level, published at the apex
//! (the service-name prefix already carries any `dc._msdcs`-style subdomain),
//! so re-running the whole probe set against every discovered subdomain would be
//! pure wasted queries on a mobile link. Pure DNS, free, no keys — one query per
//! candidate service name, bounded-concurrency.

use hickory_resolver::proto::rr::{RData, RecordType};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleContext,
    scan::Target,
};
use crate::util::dns::shared_resolver;
use crate::util::domains::registrable_domain;

use super::{MAX_CONCURRENT_BRUTE, SRC};

/// Well-known SRV service-name prefixes (everything left of the target domain),
/// each paired with a short human label for the evidence. Curated for OSINT
/// signal: Active Directory / enterprise identity first (the highest-value
/// disclosures), then mail, collaboration, VoIP, and a few widely-deployed
/// services. Every entry is a real registered `_service._proto` name from RFC
/// 6763 / vendor deployment guides.
const SRV_SERVICES: &[(&str, &str)] = &[
    // Active Directory / Windows enterprise (highest signal)
    ("_ldap._tcp", "LDAP"),
    ("_ldap._tcp.dc._msdcs", "AD domain controller"),
    ("_ldap._tcp.gc._msdcs", "AD global catalog (LDAP)"),
    ("_kerberos._tcp", "Kerberos"),
    ("_kerberos._udp", "Kerberos"),
    ("_kerberos._tcp.dc._msdcs", "AD Kerberos DC"),
    ("_kpasswd._tcp", "Kerberos password change"),
    ("_kpasswd._udp", "Kerberos password change"),
    ("_gc._tcp", "AD global catalog"),
    ("_vlmcs._tcp", "KMS volume-license activation host"),
    // Enterprise mail / collaboration
    ("_autodiscover._tcp", "Exchange autodiscover"),
    ("_sipfederationtls._tcp", "SIP federation (Teams/Skype)"),
    ("_sipinternaltls._tcp", "SIP internal TLS (Lync)"),
    ("_sip._tls", "SIP over TLS"),
    ("_sip._tcp", "SIP"),
    ("_sip._udp", "SIP"),
    ("_sips._tcp", "SIP secure"),
    // Federated chat / calendaring / contacts
    ("_xmpp-client._tcp", "XMPP client"),
    ("_xmpp-server._tcp", "XMPP server"),
    ("_jabber._tcp", "Jabber"),
    ("_matrix._tcp", "Matrix homeserver"),
    ("_caldav._tcp", "CalDAV"),
    ("_caldavs._tcp", "CalDAV secure"),
    ("_carddav._tcp", "CardDAV"),
    ("_carddavs._tcp", "CardDAV secure"),
    // Standard mail submission / retrieval
    ("_submission._tcp", "mail submission"),
    ("_imap._tcp", "IMAP"),
    ("_imaps._tcp", "IMAP secure"),
    ("_pop3._tcp", "POP3"),
    ("_pop3s._tcp", "POP3 secure"),
    // Other widely-deployed services worth a pivot
    ("_ftp._tcp", "FTP"),
    ("_minecraft._tcp", "Minecraft server"),
    ("_ts3._udp", "TeamSpeak 3"),
    ("_stun._udp", "STUN (WebRTC)"),
    ("_turn._udp", "TURN (WebRTC)"),
];

/// One resolved SRV answer, flattened for entity construction:
/// `(target_host, port, priority, weight, service_prefix, service_label)`.
type SrvHit = (String, u16, u16, u16, &'static str, &'static str);

/// SRV service-discovery sweep for one target. No-op (returns empty) unless
/// `target` IS its own registrable domain — see the module doc for why the probe
/// set is apex-only.
pub(super) async fn srv_enumerate(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let domain = target.value.trim().trim_end_matches('.').to_lowercase();
    if domain.is_empty() || domain.contains('/') || domain.contains(' ') {
        return Ok(Vec::new());
    }
    // Only fire at the apex — SRV service-discovery is organisation-level.
    match registrable_domain(&domain) {
        Some(reg) if reg == domain => {}
        _ => return Ok(Vec::new()),
    }

    let hits = resolve_srv_concurrently(&domain, MAX_CONCURRENT_BRUTE).await;

    let entities: Vec<Entity> = hits
        .into_iter()
        .map(|(host, port, priority, weight, prefix, label)| {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.80, &ctx.scan_id);
            e.tag("srv");
            e.tag("dns-srv");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "SRV {prefix}.{domain} → {host}:{port} ({label}) — a \
                         service-discovery record naming this host",
                    ),
                )
                .with_attr("service", prefix)
                .with_attr("service_label", label)
                .with_attr("target_host", &host)
                .with_attr("port", port.to_string())
                .with_attr("priority", priority.to_string())
                .with_attr("weight", weight.to_string())
                .with_attr("parent_domain", &domain)
                .with_attr("method", "srv-service-discovery"),
            );
            e
        })
        .collect();
    Ok(entities)
}

/// Resolve every SRV candidate name for `domain` concurrently (bounded to
/// `max_concurrent` in flight), returning the flattened answers sorted for
/// deterministic output regardless of DNS completion order.
async fn resolve_srv_concurrently(domain: &str, max_concurrent: usize) -> Vec<SrvHit> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let resolver = shared_resolver();
    let sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for (prefix, label) in SRV_SERVICES {
        let name = format!("{prefix}.{domain}");
        let sem = Arc::clone(&sem);
        let (prefix, label) = (*prefix, *label);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let lookup = resolver.lookup(name.as_str(), RecordType::SRV).await.ok()?;
            let hits: Vec<SrvHit> = lookup
                .answers()
                .iter()
                .filter_map(|record| {
                    let RData::SRV(srv) = &record.data else {
                        return None;
                    };
                    let host = srv.target.to_ascii().trim_end_matches('.').to_lowercase();
                    // A well-formed "no service here" SRV answer is a single
                    // record with target "." and port 0 (RFC 2782); skip it and
                    // any empty target.
                    if host.is_empty() {
                        return None;
                    }
                    Some((host, srv.port, srv.priority, srv.weight, prefix, label))
                })
                .collect();
            if hits.is_empty() { None } else { Some(hits) }
        });
    }

    let mut out: Vec<SrvHit> = Vec::new();
    while let Some(join_result) = set.join_next().await {
        if let Ok(Some(hits)) = join_result {
            out.extend(hits);
        }
    }
    // Deterministic order: by target host, then port, then service prefix.
    out.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.4.cmp(b.4)));
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_list_is_well_formed() {
        // Every prefix is an underscore-service._proto shape and unique.
        let mut seen = std::collections::BTreeSet::new();
        for (prefix, label) in SRV_SERVICES {
            assert!(
                prefix.starts_with('_'),
                "SRV prefix must start with '_': {prefix}"
            );
            assert!(
                prefix.contains("._tcp") || prefix.contains("._udp") || prefix.contains("._tls"),
                "SRV prefix must carry a _tcp/_udp/_tls proto label: {prefix}"
            );
            assert!(!label.is_empty(), "every service needs a human label");
            assert!(seen.insert(*prefix), "duplicate SRV prefix: {prefix}");
        }
        assert!(
            SRV_SERVICES.len() >= 25,
            "expected a broad service dictionary"
        );
    }

    #[tokio::test]
    async fn skips_a_subdomain_target() {
        // SRV enumeration is apex-only; a subdomain must be a no-op.
        let target = Target::new(crate::core::scan::TargetKind::Domain, "api.example.com");
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };
        let out = srv_enumerate(&target, &ctx).await.unwrap();
        assert!(
            out.is_empty(),
            "a subdomain has no apex-level SRV probe set"
        );
    }
}
