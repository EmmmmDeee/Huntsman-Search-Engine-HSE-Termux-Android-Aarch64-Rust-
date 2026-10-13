//! `SpiderFoot` 4.0 correlation rules that apply to what Huntsman collects, ported from
//! `correlations/*.yaml` (v4.0, `b9c345d`) with their ids, matching and headlines.
//!
//! Mapping: `INTERNET_NAME` is a `Domain` entity, `IP_ADDRESS`/`IPV6_ADDRESS` an `IpAddress`,
//! `EMAILADDR` an `Email`; an event's `module` is an evidence item's provenance source, and one
//! `SpiderFoot` event per value is one evidence item. `crtsh`/`certspotter` stand for `sfp_crt`/
//! `sfp_certspotter`, `dns` for `sfp_dnsresolve`. `SpiderFoot`'s `INFO` risk is `low`.
//!
//! Not ported because Huntsman has no producing module: `host_only_from_bruteforce`
//! (`sfp_dnsbrute`), `dns_zone_transfer_possible` (`sfp_dnszonexfer`), and the 30 rules over
//! event types it does not collect.

use std::collections::BTreeSet;

use crate::entity::{Entity, EntityKind};

use super::{Correlation, RuleContext, Severity};

const CT_SOURCES: &[&str] = &["crtsh", "certspotter"];
/// `sfp_dnsresolve`'s stand-in: resolving a CT host does not make it "found elsewhere".
const RESOLVER_SOURCE: &str = "dns";

fn kind_entities<'a>(
    context: &RuleContext<'a>,
    kinds: &'a [EntityKind],
) -> impl Iterator<Item = &'a Entity> + 'a {
    context
        .entities()
        .iter()
        .filter(move |entity| kinds.contains(&entity.kind))
}

fn sources(entity: &Entity) -> BTreeSet<&str> {
    entity
        .evidence
        .iter()
        .map(|item| item.provenance.source.as_str())
        .collect()
}

fn one(
    id: &str,
    name: &str,
    severity: Severity,
    headline: String,
    entity: &Entity,
    scan_id: &str,
    now: u64,
) -> Correlation {
    Correlation::new(
        id,
        name,
        severity,
        headline,
        vec![entity.uid.clone()],
        scan_id,
        now,
    )
}

/// `dev_or_test_system` (MEDIUM): a host name containing dev, test, uat, internal or staging.
#[must_use]
pub fn dev_or_test_system(context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
    const MARKERS: [&str; 5] = ["dev", "test", "uat", "internal", "staging"];
    kind_entities(context, &[EntityKind::Domain])
        .filter(|entity| MARKERS.iter().any(|marker| entity.value.contains(marker)))
        .map(|entity| {
            one(
                "dev_or_test_system",
                "A host appearing to be a test or development system was found",
                Severity::Medium,
                format!("Development or internal system found: {}", entity.value),
                entity,
                scan_id,
                now,
            )
        })
        .collect()
}

/// `internal_host` (MEDIUM): DNS resolution produced an address in 192.168/16 or 10/8, exactly
/// the two ranges `SpiderFoot`'s rule matches.
#[must_use]
pub fn internal_host(context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
    kind_entities(context, &[EntityKind::IpAddress])
        .filter(|entity| entity.value.starts_with("192.168.") || entity.value.starts_with("10."))
        .filter(|entity| sources(entity).contains(RESOLVER_SOURCE))
        .map(|entity| {
            one(
                "internal_host",
                "A host resolving to unroutable IPs was found",
                Severity::Medium,
                format!("An internal host was found: {}", entity.value),
                entity,
                scan_id,
                now,
            )
        })
        .collect()
}

/// `host_only_from_certificatetransparency` (LOW): a host name seen in a CT index and from no
/// other source but DNS resolution.
#[must_use]
pub fn host_only_from_certificatetransparency(
    context: &RuleContext<'_>,
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    kind_entities(context, &[EntityKind::Domain])
        .filter(|entity| {
            let found = sources(entity);
            found.iter().any(|source| CT_SOURCES.contains(source))
                && found
                    .iter()
                    .all(|source| CT_SOURCES.contains(source) || *source == RESOLVER_SOURCE)
        })
        .map(|entity| {
            one(
                "host_only_from_certificatetransparency",
                "Hostname only from certificate transparency",
                Severity::Low,
                format!(
                    "Host found only in certificate transparency: {}",
                    entity.value
                ),
                entity,
                scan_id,
                now,
            )
        })
        .collect()
}

/// `SpiderFoot`'s `outlier` analysis over one bucket per value, sized by its event count: nothing
/// when the average bucket holds under `noisy_percent` (10) of all events, otherwise every bucket
/// holding at most `maximum_percent` of them.
fn outliers<'a>(entities: &[&'a Entity], maximum_percent: f64) -> Vec<&'a Entity> {
    if entities.is_empty() {
        return Vec::new();
    }
    let as_f64 = |n: usize| f64::from(u32::try_from(n).unwrap_or(u32::MAX));
    let counts: Vec<f64> = entities
        .iter()
        .map(|entity| as_f64(entity.evidence.len().max(1)))
        .collect();
    let total: f64 = counts.iter().sum();
    let average = total / as_f64(counts.len());
    if average / total * 100.0 < 10.0 {
        return Vec::new();
    }
    entities
        .iter()
        .zip(counts)
        .filter(|(_, count)| count / total * 100.0 <= maximum_percent)
        .map(|(entity, _)| *entity)
        .collect()
}

fn outlier_rule(
    context: &RuleContext<'_>,
    kinds: &[EntityKind],
    (id, name, label): (&str, &str, &str),
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let entities: Vec<&Entity> = context
        .entities()
        .iter()
        .filter(|entity| kinds.contains(&entity.kind))
        .collect();
    outliers(&entities, 10.0)
        .into_iter()
        .map(|entity| {
            one(
                id,
                name,
                Severity::Low,
                format!("Outlier {label} found: {}", entity.value),
                entity,
                scan_id,
                now,
            )
        })
        .collect()
}

/// `outlier_email` (INFO).
#[must_use]
pub fn outlier_email(context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
    outlier_rule(
        context,
        &[EntityKind::Email],
        (
            "outlier_email",
            "Outlier email address found",
            "email address",
        ),
        scan_id,
        now,
    )
}

/// `outlier_hostname` (INFO).
#[must_use]
pub fn outlier_hostname(context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
    outlier_rule(
        context,
        &[EntityKind::Domain],
        ("outlier_hostname", "Outlier hostname", "hostname"),
        scan_id,
        now,
    )
}

/// `outlier_ipaddress` (INFO).
#[must_use]
pub fn outlier_ipaddress(context: &RuleContext<'_>, scan_id: &str, now: u64) -> Vec<Correlation> {
    outlier_rule(
        context,
        &[EntityKind::IpAddress],
        ("outlier_ipaddress", "Outlier IP address", "IP address"),
        scan_id,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Evidence, EvidenceProvenance};

    fn entity(kind: EntityKind, value: &str, sources: &[&str]) -> Entity {
        let mut entity = Entity::new(kind, value, 0.9, "scan");
        for source in sources {
            entity.add_evidence(Evidence::new(EvidenceProvenance::new(*source), "seen"));
        }
        entity
    }

    fn fired(
        rule: fn(&RuleContext<'_>, &str, u64) -> Vec<Correlation>,
        entities: &[Entity],
    ) -> Vec<String> {
        let context = RuleContext::new(entities, &[]);
        rule(&context, "scan", 1)
            .into_iter()
            .map(|c| c.description)
            .collect()
    }

    #[test]
    fn dev_or_test_hosts_match_sf_markers() {
        let entities = [
            entity(EntityKind::Domain, "staging.example.com", &["crtsh"]),
            entity(EntityKind::Domain, "www.example.com", &["crtsh"]),
            entity(EntityKind::Domain, "uat-api.example.com", &["dns"]),
        ];
        assert_eq!(
            fired(dev_or_test_system, &entities),
            vec![
                "Development or internal system found: staging.example.com",
                "Development or internal system found: uat-api.example.com"
            ]
        );
    }

    #[test]
    fn internal_hosts_need_dns_resolution_and_the_sf_ranges() {
        let entities = [
            entity(EntityKind::IpAddress, "10.1.2.3", &["dns"]),
            entity(EntityKind::IpAddress, "192.168.0.9", &["cymru"]),
            entity(EntityKind::IpAddress, "172.16.0.1", &["dns"]),
            entity(EntityKind::IpAddress, "8.8.8.8", &["dns"]),
        ];
        assert_eq!(
            fired(internal_host, &entities),
            vec!["An internal host was found: 10.1.2.3"]
        );
    }

    #[test]
    fn ct_only_hosts_allow_resolution_but_nothing_else() {
        let entities = [
            entity(
                EntityKind::Domain,
                "a.example.com",
                &["crtsh", "certspotter"],
            ),
            entity(EntityKind::Domain, "b.example.com", &["certspotter", "dns"]),
            entity(EntityKind::Domain, "c.example.com", &["crtsh", "web_query"]),
            entity(EntityKind::Domain, "d.example.com", &["dns"]),
        ];
        assert_eq!(
            fired(host_only_from_certificatetransparency, &entities),
            vec![
                "Host found only in certificate transparency: a.example.com",
                "Host found only in certificate transparency: b.example.com"
            ]
        );
    }

    #[test]
    fn outliers_follow_sf_noise_guard_and_threshold() {
        // 10 buckets, one seen once among 1 + 9*3 = 28 events: 1/28 = 3.6% <= 10%, others
        // 3/28 = 10.7%. Average share 10% is not under the 10% noise guard.
        let mut entities = vec![entity(EntityKind::IpAddress, "192.0.2.1", &["dns"])];
        for i in 2..=10 {
            entities.push(entity(
                EntityKind::IpAddress,
                &format!("192.0.2.{i}"),
                &["dns", "cymru", "seed"],
            ));
        }
        assert_eq!(
            fired(outlier_ipaddress, &entities),
            vec!["Outlier IP address found: 192.0.2.1"]
        );
        // Eleven equal buckets: average share 9.1% is under the guard, so nothing is reported.
        let noisy: Vec<Entity> = (1..=11)
            .map(|i| entity(EntityKind::Email, &format!("u{i}@example.com"), &["x"]))
            .collect();
        assert!(fired(outlier_email, &noisy).is_empty());
    }
}
