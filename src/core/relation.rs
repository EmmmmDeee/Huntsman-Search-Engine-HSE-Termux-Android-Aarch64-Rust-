//! `core::relation` — typed entity-to-entity edges: the attribution-pathway
//! layer of the entity graph.
//!
//! # Determinism (architecture invariant)
//! Like the correlator, this layer is **pure open math** — no inference, no
//! fuzzy matching, no LLM. Every edge is derived from concrete, normalised
//! entity values, so the same entity set always produces the same relations.
//!
//! # Edge families
//! Post-scan **structural** builder (`derive_structural`) links entities by
//! canonical value:
//!   - `SubdomainOf`     — Domain → its closest present parent Domain
//!   - `BelongsToDomain` — Email  → the Domain of its address
//!   - `HostedOn`        — Url    → the Domain of its host
//!
//! `derive_colocation` links `CoLocatedWith` between Coordinates within
//! `CO_LOCATION_KM` (Haversine via `util::geohash`). `derive_resolution` links
//! `ResolvesTo` (Domain → IpAddress) by matching an IP entity's DNS evidence
//! against present Domain nodes. All three run in `finalise_scan`.
//!
//! `DerivedFrom` (child → the entity whose expansion surfaced it) is **lineage**
//! — recorded by the engine's `run_expansion` (not a post-scan builder) and
//! persisted alongside the above.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::entity::{Entity, EntityKind, unix_now};

/// The typed edge between two entities. Stable snake_case serde tags so the
/// (future) SPA force-graph can switch on `rel.kind` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// `from` (a Domain) is a subdomain of `to` (its closest present parent).
    SubdomainOf,
    /// `from` (an Email) belongs to `to` (the Domain of its address).
    BelongsToDomain,
    /// `from` (a Url) is hosted on `to` (the Domain of its host).
    HostedOn,
    /// `from` (a Domain) resolves to `to` (an IpAddress) — derived from DNS
    /// evidence on the IP entity (A/AAAA records).
    ResolvesTo,
    /// `from` and `to` are Coordinates within `CO_LOCATION_KM` of each other —
    /// the same locality, surfaced by independent sources.
    CoLocatedWith,
    /// `from` was discovered by pivoting on `to` during expansion (lineage).
    DerivedFrom,
}

impl RelationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubdomainOf => "subdomain_of",
            Self::BelongsToDomain => "belongs_to_domain",
            Self::HostedOn => "hosted_on",
            Self::ResolvesTo => "resolves_to",
            Self::CoLocatedWith => "co_located_with",
            Self::DerivedFrom => "derived_from",
        }
    }
}

impl std::fmt::Display for RelationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A directed, typed edge between two entities (referenced by UID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    /// Deterministic id: `hex(SHA-256("from|kind|to|scan"))`. Lets storage
    /// upsert idempotently so re-scans don't duplicate edges.
    pub id: String,
    pub from_uid: String,
    pub to_uid: String,
    pub kind: RelationKind,
    /// Edge confidence — the weaker of the two endpoints' base confidence,
    /// clamped to [0, 1]. The structural fact itself is certain; this carries
    /// the trust of the endpoints it connects.
    pub confidence: f64,
    pub scan_id: String,
    pub observed_at: u64,
}

impl Relation {
    pub fn new(
        from_uid: impl Into<String>,
        to_uid: impl Into<String>,
        kind: RelationKind,
        confidence: f64,
        scan_id: impl Into<String>,
    ) -> Self {
        let from_uid = from_uid.into();
        let to_uid = to_uid.into();
        let scan_id = scan_id.into();
        let mut h = Sha256::new();
        h.update(from_uid.as_bytes());
        h.update(b"|");
        h.update(kind.as_str().as_bytes());
        h.update(b"|");
        h.update(to_uid.as_bytes());
        h.update(b"|");
        h.update(scan_id.as_bytes());
        Self {
            id: hex::encode(h.finalize()),
            from_uid,
            to_uid,
            kind,
            confidence: confidence.clamp(0.0, 1.0),
            scan_id,
            observed_at: unix_now(),
        }
    }
}

/// Normalise a host/domain string the same way `EntityKind::Domain` does for
/// entity values: lowercase, strip a leading `www.`, strip a trailing dot.
/// Used so an Email/Url's domain matches the stored Domain entity value.
fn domain_key(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some(stripped) = s.strip_suffix('.') {
        s = stripped.to_string();
    }
    if let Some(stripped) = s.strip_prefix("www.") {
        s = stripped.to_string();
    }
    s
}

/// True if `child` is a proper subdomain of `parent` (label-aligned suffix).
fn is_subdomain_of(child: &str, parent: &str) -> bool {
    child.len() > parent.len()
        && child.ends_with(parent)
        && child.as_bytes()[child.len() - parent.len() - 1] == b'.'
}

/// Derive the deterministic structural relations for a scan's entity set.
///
/// Pure: depends only on the entities passed in. Edges only ever connect
/// entities that are both present in the set (so every endpoint UID resolves).
pub fn derive_structural(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashMap;

    // Index Domain entities by their (already-normalised) value.
    let domain_by_value: HashMap<&str, &Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| (e.value.as_str(), e))
        .collect();

    let mut relations = Vec::new();
    let conf = |a: &Entity, b: &Entity| a.confidence.min(b.confidence);

    for e in entities {
        match e.kind {
            EntityKind::Domain => {
                // Link to the closest (longest) present parent domain.
                if let Some(&parent) = domain_by_value
                    .values()
                    .filter(|p| is_subdomain_of(&e.value, &p.value))
                    .max_by_key(|p| p.value.len())
                {
                    relations.push(Relation::new(
                        e.uid.as_str(),
                        parent.uid.as_str(),
                        RelationKind::SubdomainOf,
                        conf(e, parent),
                        scan_id,
                    ));
                }
            }
            EntityKind::Email => {
                if let Some((_, dom)) = e.value.split_once('@')
                    && let Some(&d) = domain_by_value.get(domain_key(dom).as_str())
                {
                    relations.push(Relation::new(
                        e.uid.as_str(),
                        d.uid.as_str(),
                        RelationKind::BelongsToDomain,
                        conf(e, d),
                        scan_id,
                    ));
                }
            }
            EntityKind::Url => {
                if let Some(host) = url::Url::parse(&e.value)
                    .ok()
                    .and_then(|u| u.host_str().map(domain_key))
                    && let Some(&d) = domain_by_value.get(host.as_str())
                {
                    relations.push(Relation::new(
                        e.uid.as_str(),
                        d.uid.as_str(),
                        RelationKind::HostedOn,
                        conf(e, d),
                        scan_id,
                    ));
                }
            }
            _ => {}
        }
    }

    relations
}

/// Distance (km) under which two Coordinates entities are treated as the same
/// locality and linked with a `CoLocatedWith` edge. ~1 km bridges the scatter
/// between independent geocoders pointing at one place while staying tight
/// enough to be meaningful.
pub const CO_LOCATION_KM: f64 = 1.0;

/// Derive `CoLocatedWith` edges between Coordinates entities within
/// `CO_LOCATION_KM` of each other. Pure + deterministic: reuses
/// `util::geohash` for parsing and Haversine distance, emits one canonically-
/// directed edge per close pair (smaller UID → larger), so re-scans upsert
/// idempotently. O(k²) over the (typically few) Coordinates entities only.
pub fn derive_colocation(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let coords: Vec<(&Entity, f64, f64)> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .filter_map(|e| crate::util::geohash::parse_coords(&e.value).map(|(la, lo)| (e, la, lo)))
        .collect();

    let mut relations = Vec::new();
    for i in 0..coords.len() {
        for j in (i + 1)..coords.len() {
            let (a, la1, lo1) = coords[i];
            let (b, la2, lo2) = coords[j];
            if crate::util::geohash::haversine_km(la1, lo1, la2, lo2) <= CO_LOCATION_KM {
                // Canonical direction so the pair yields exactly one
                // deterministic edge regardless of iteration order.
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                relations.push(Relation::new(
                    from.uid.as_str(),
                    to.uid.as_str(),
                    RelationKind::CoLocatedWith,
                    a.confidence.min(b.confidence),
                    scan_id,
                ));
            }
        }
    }
    relations
}

/// Derive `ResolvesTo` edges (Domain → IpAddress) from DNS evidence.
///
/// Robust by design: rather than coupling to a specific module's attribute
/// key, it scans each IpAddress entity's evidence — both attribute *values*
/// (e.g. `dns_intel`'s `domain` attr) and summary tokens (the shared
/// "`<TYPE> record for <domain>`" convention used by `dns_intel` and
/// `doh_resolver`) — and links any token that normalises to a present Domain
/// entity. Only IpAddress entities are scanned and only exact matches against
/// real Domain nodes fire, so non-domain tokens (record types, TTLs) can't
/// produce false edges. Deterministic; one edge per (domain, ip) pair.
pub fn derive_resolution(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    let domain_by_value: HashMap<&str, &Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| (e.value.as_str(), e))
        .collect();
    if domain_by_value.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for ip in entities.iter().filter(|e| e.kind == EntityKind::IpAddress) {
        for ev in &ip.evidence {
            let candidates = ev
                .attributes
                .values()
                .map(String::as_str)
                .chain(ev.summary.split_whitespace());
            for token in candidates {
                let norm = crate::core::entity::normalise(&EntityKind::Domain, token);
                if let Some(dom) = domain_by_value.get(norm.as_str())
                    && seen.insert((dom.uid.clone(), ip.uid.clone()))
                {
                    out.push(Relation::new(
                        dom.uid.as_str(),
                        ip.uid.as_str(),
                        RelationKind::ResolvesTo,
                        ip.confidence.min(dom.confidence),
                        scan_id,
                    ));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
        Entity::new(kind, value, conf, "rel-scan")
    }

    #[test]
    fn relation_id_is_deterministic_and_idempotent() {
        let a = Relation::new("uidA", "uidB", RelationKind::SubdomainOf, 0.8, "s1");
        let b = Relation::new("uidA", "uidB", RelationKind::SubdomainOf, 0.8, "s1");
        assert_eq!(a.id, b.id, "same edge → same id (idempotent upsert)");
        assert_eq!(a.id.len(), 64);
    }

    #[test]
    fn relation_id_differs_by_kind_and_direction() {
        let sub = Relation::new("a", "b", RelationKind::SubdomainOf, 1.0, "s");
        let host = Relation::new("a", "b", RelationKind::HostedOn, 1.0, "s");
        let rev = Relation::new("b", "a", RelationKind::SubdomainOf, 1.0, "s");
        assert_ne!(sub.id, host.id);
        assert_ne!(sub.id, rev.id);
    }

    #[test]
    fn confidence_is_clamped() {
        let r = Relation::new("a", "b", RelationKind::HostedOn, 1.5, "s");
        assert!((r.confidence - 1.0).abs() < 1e-9);
    }

    #[test]
    fn subdomain_edge_links_to_closest_present_parent() {
        // a.b.example.com, b.example.com, example.com all present →
        // a.b.example.com should link to b.example.com (closest), not example.com.
        let entities = vec![
            ent(EntityKind::Domain, "a.b.example.com", 0.9),
            ent(EntityKind::Domain, "b.example.com", 0.8),
            ent(EntityKind::Domain, "example.com", 0.7),
        ];
        let rels = derive_structural(&entities, "s");
        let subs: Vec<_> = rels
            .iter()
            .filter(|r| r.kind == RelationKind::SubdomainOf)
            .collect();
        // a.b.example.com → b.example.com ; b.example.com → example.com
        assert_eq!(subs.len(), 2, "got: {subs:?}");
        let a = &entities[0];
        let b = &entities[1];
        let apex = &entities[2];
        assert!(
            subs.iter()
                .any(|r| r.from_uid == a.uid && r.to_uid == b.uid),
            "a.b.example.com should link to closest parent b.example.com"
        );
        assert!(
            subs.iter()
                .any(|r| r.from_uid == b.uid && r.to_uid == apex.uid)
        );
        // It must NOT also link the deepest straight to the apex.
        assert!(
            !subs
                .iter()
                .any(|r| r.from_uid == a.uid && r.to_uid == apex.uid),
            "should link to closest parent only, not skip-level to apex"
        );
    }

    #[test]
    fn email_links_to_present_domain_only() {
        let entities = vec![
            ent(EntityKind::Email, "alice@example.com", 0.8),
            ent(EntityKind::Domain, "example.com", 0.9),
            ent(EntityKind::Email, "bob@absent.com", 0.8), // domain not in set
        ];
        let rels = derive_structural(&entities, "s");
        let belongs: Vec<_> = rels
            .iter()
            .filter(|r| r.kind == RelationKind::BelongsToDomain)
            .collect();
        assert_eq!(
            belongs.len(),
            1,
            "only the email whose domain is present links"
        );
        assert_eq!(belongs[0].from_uid, entities[0].uid);
        assert_eq!(belongs[0].to_uid, entities[1].uid);
        // Edge confidence is the weaker endpoint (0.8).
        assert!((belongs[0].confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn url_links_to_domain_stripping_www() {
        let entities = vec![
            ent(EntityKind::Url, "https://www.example.com/path", 0.6),
            ent(EntityKind::Domain, "example.com", 0.9),
        ];
        let rels = derive_structural(&entities, "s");
        let hosted: Vec<_> = rels
            .iter()
            .filter(|r| r.kind == RelationKind::HostedOn)
            .collect();
        assert_eq!(hosted.len(), 1);
        assert_eq!(hosted[0].from_uid, entities[0].uid);
        assert_eq!(hosted[0].to_uid, entities[1].uid);
    }

    #[test]
    fn no_edges_without_matching_endpoints() {
        // No Domain entities at all → no structural edges.
        let entities = vec![
            ent(EntityKind::Email, "a@x.com", 0.8),
            ent(EntityKind::Url, "https://y.com/", 0.7),
        ];
        let rels = derive_structural(&entities, "s");
        assert!(rels.is_empty());
    }

    #[test]
    fn is_subdomain_of_label_aligned() {
        assert!(is_subdomain_of("a.example.com", "example.com"));
        assert!(!is_subdomain_of("notexample.com", "example.com")); // not label-aligned
        assert!(!is_subdomain_of("example.com", "example.com")); // not proper
    }

    #[test]
    fn colocation_links_nearby_coordinates() {
        // ~0.24 km apart (Brisbane CBD) → linked.
        let a = ent(EntityKind::Coordinates, "-27.470000,153.020000", 0.9);
        let b = ent(EntityKind::Coordinates, "-27.472000,153.021000", 0.7);
        let rels = derive_colocation(&[a.clone(), b.clone()], "s");
        assert_eq!(rels.len(), 1, "nearby coords should yield one edge");
        assert_eq!(rels[0].kind, RelationKind::CoLocatedWith);
        // Canonical direction: smaller uid → larger.
        let (lo, hi) = if a.uid <= b.uid { (&a, &b) } else { (&b, &a) };
        assert_eq!(rels[0].from_uid, lo.uid);
        assert_eq!(rels[0].to_uid, hi.uid);
        // Edge confidence is the weaker endpoint.
        assert!((rels[0].confidence - 0.7).abs() < 1e-9);
    }

    #[test]
    fn colocation_skips_distant_coordinates() {
        // Brisbane vs Sydney (~730 km) → no edge.
        let a = ent(EntityKind::Coordinates, "-27.470000,153.020000", 0.9);
        let b = ent(EntityKind::Coordinates, "-33.870000,151.210000", 0.9);
        assert!(derive_colocation(&[a, b], "s").is_empty());
    }

    #[test]
    fn colocation_ignores_non_coordinates() {
        let a = ent(EntityKind::Email, "a@x.com", 0.9);
        let b = ent(EntityKind::Domain, "x.com", 0.9);
        assert!(derive_colocation(&[a, b], "s").is_empty());
    }

    #[test]
    fn colocation_one_edge_per_pair() {
        let a = ent(EntityKind::Coordinates, "-27.470000,153.020000", 0.9);
        let b = ent(EntityKind::Coordinates, "-27.470500,153.020500", 0.8);
        assert_eq!(
            derive_colocation(&[a, b], "s").len(),
            1,
            "one edge per pair, not two reversed"
        );
    }

    // ── derive_resolution (Domain → Ip via DNS evidence) ───────────────────

    #[test]
    fn resolution_links_domain_to_ip_dns_intel_shape() {
        use crate::core::entity::Evidence;
        // Realistic dns_intel A-record fixture: IpAddress entity carrying a
        // `domain` attribute + the "<TYPE> record for <domain>" summary.
        let mut ip = Entity::new(EntityKind::IpAddress, "93.184.216.34", 0.95, "rel-scan");
        ip.add_evidence(
            Evidence::new("dns_intel", "A record for example.com")
                .with_attr("record_type", "A")
                .with_attr("domain", "example.com")
                .with_attr("ttl_secs", "3600")
                .with_attr("ip_version", "ipv4"),
        );
        let dom = ent(EntityKind::Domain, "example.com", 0.9);
        let rels = derive_resolution(&[ip.clone(), dom.clone()], "s");
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].kind, RelationKind::ResolvesTo);
        assert_eq!(rels[0].from_uid, dom.uid, "edge points domain -> ip");
        assert_eq!(rels[0].to_uid, ip.uid);
        assert!((rels[0].confidence - 0.9).abs() < 1e-9); // weaker endpoint
    }

    #[test]
    fn resolution_links_via_summary_only_doh_shape() {
        use crate::core::entity::Evidence;
        // Realistic doh_resolver fixture: domain only in the summary, the sole
        // attribute is record_type. The summary-token path must still link it.
        let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "rel-scan");
        ip.add_evidence(
            Evidence::new("doh_resolver", "A record for example.com").with_attr("record_type", "A"),
        );
        let dom = ent(EntityKind::Domain, "example.com", 0.9);
        let rels = derive_resolution(&[ip, dom], "s");
        assert_eq!(rels.len(), 1, "summary-only domain must still link");
        assert_eq!(rels[0].kind, RelationKind::ResolvesTo);
    }

    #[test]
    fn resolution_no_edge_without_matching_domain_entity() {
        use crate::core::entity::Evidence;
        let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "rel-scan");
        ip.add_evidence(
            Evidence::new("dns_intel", "A record for absent.com").with_attr("domain", "absent.com"),
        );
        // Only an unrelated domain is present.
        let other = ent(EntityKind::Domain, "example.com", 0.9);
        assert!(derive_resolution(&[ip, other], "s").is_empty());
    }

    #[test]
    fn resolution_dedups_repeated_domain_mentions() {
        use crate::core::entity::Evidence;
        let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "rel-scan");
        // Domain appears in both an attr and the summary, across two records.
        ip.add_evidence(
            Evidence::new("dns_intel", "A record for example.com")
                .with_attr("domain", "example.com"),
        );
        ip.add_evidence(
            Evidence::new("dns_intel", "AAAA record for example.com")
                .with_attr("domain", "example.com"),
        );
        let dom = ent(EntityKind::Domain, "example.com", 0.9);
        assert_eq!(
            derive_resolution(&[ip, dom], "s").len(),
            1,
            "one edge per (domain, ip) pair"
        );
    }
}
