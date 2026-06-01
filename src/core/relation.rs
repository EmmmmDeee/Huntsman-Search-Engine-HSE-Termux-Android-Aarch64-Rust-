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
//!
//! `derive_identity_equivalence` links `SameAs` (entity resolution): present
//! Email entities whose **provable canonical mailbox** matches (dot/plus/alias
//! variants) are tied into one equivalence class. Unlike the post-scan
//! structural builders, the engine runs it **live during ingestion** (every
//! round) so the unified identity view updates continuously; it is
//! non-destructive (both surface forms are retained) and reversible (the class
//! is the connected component over the edges).

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
    /// `from` (a Domain) is registered by `to` (an Organisation or Email) —
    /// derived from WHOIS registrant evidence on the Domain entity.
    RegisteredBy,
    /// `from` and `to` are Coordinates within `CO_LOCATION_KM` of each other —
    /// the same locality, surfaced by independent sources.
    CoLocatedWith,
    /// `from` was discovered by pivoting on `to` during expansion (lineage).
    DerivedFrom,
    /// `from` and `to` are the **same real-world identifier** under a
    /// deterministic, provider-documented canonicalisation (e.g. an email's
    /// dot/plus/alias variants). The entity-resolution edge: a non-destructive,
    /// reversible assertion that two distinct surface forms denote one identity.
    /// Both nodes are retained with their own provenance; the resolved identity
    /// is the connected component over these edges, and dropping an edge splits
    /// the class back out (provenance-controlled rollback).
    SameAs,
}

impl RelationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubdomainOf => "subdomain_of",
            Self::BelongsToDomain => "belongs_to_domain",
            Self::HostedOn => "hosted_on",
            Self::ResolvesTo => "resolves_to",
            Self::RegisteredBy => "registered_by",
            Self::CoLocatedWith => "co_located_with",
            Self::DerivedFrom => "derived_from",
            Self::SameAs => "same_as",
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

/// Derive the structural relations for a scan's entity set.
///
/// Deterministic in the edges it produces (set + ids) — it depends only on the
/// entities passed in, and only connects entities both present in the set (so
/// every endpoint UID resolves). (Each `Relation` carries a wall-clock
/// `observed_at`, so the values aren't bit-identical across calls, but the edge
/// set and their deterministic ids are.)
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
                // Walk up one label at a time; the first present ancestor is
                // the closest parent. O(labels) hash lookups instead of an
                // O(N) scan over every domain — meaningful on subdomain-heavy
                // scans (crt.sh-style expansions) on low-power devices.
                // Stripping at '.' keeps matches label-aligned, so
                // `notexample.com` never matches `example.com`.
                let mut rest = e.value.as_str();
                while let Some(dot) = rest.find('.') {
                    rest = &rest[dot + 1..];
                    if let Some(&parent) = domain_by_value.get(rest) {
                        relations.push(Relation::new(
                            e.uid.as_str(),
                            parent.uid.as_str(),
                            RelationKind::SubdomainOf,
                            conf(e, parent),
                            scan_id,
                        ));
                        break;
                    }
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
/// `CO_LOCATION_KM` of each other. The edge set + ids are deterministic
/// (`observed_at` aside): reuses `util::geohash` for parsing and Haversine
/// distance, emits one canonically-directed edge per close pair (smaller UID →
/// larger), so re-scans upsert idempotently. O(k²) over the (typically few)
/// Coordinates entities only.
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
                // Strip surrounding punctuation that summary tokenisation can
                // leave attached (e.g. "example.com," or "(example.com)"), but
                // keep '-' / '_' which are valid in domain labels.
                let cleaned =
                    token.trim_matches(|c: char| c.is_ascii_punctuation() && c != '-' && c != '_');
                let norm = crate::core::entity::normalise(&EntityKind::Domain, cleaned);
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

/// Derive `RegisteredBy` edges (Domain → Organisation / Email) from WHOIS
/// registrant evidence.
///
/// Robust by design, mirroring `derive_resolution`: it matches a Domain
/// entity's evidence attribute *values* (e.g. `whois`'s `registrant_org` /
/// `registrant_email` attrs) against present Organisation and Email entities,
/// rather than coupling to attribute keys. `whois` emits the registrant org
/// and contact emails as their own entities, so both endpoints are present.
/// `registrar`-keyed attributes are skipped, so a registrar that happens to be
/// a present Organisation entity isn't mistaken for the registrant. Org names
/// are matched as whole trimmed values (not tokenised) since they contain
/// spaces. One edge per (domain, registrant).
pub fn derive_registration(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    let org_by_value: HashMap<&str, &Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| (e.value.as_str(), e))
        .collect();
    let email_by_value: HashMap<&str, &Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| (e.value.as_str(), e))
        .collect();
    if org_by_value.is_empty() && email_by_value.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    let mut link = |dom: &Entity, who: &Entity, out: &mut Vec<Relation>| {
        if seen.insert((dom.uid.clone(), who.uid.clone())) {
            out.push(Relation::new(
                dom.uid.as_str(),
                who.uid.as_str(),
                RelationKind::RegisteredBy,
                dom.confidence.min(who.confidence),
                scan_id,
            ));
        }
    };

    for dom in entities.iter().filter(|e| e.kind == EntityKind::Domain) {
        for ev in &dom.evidence {
            for (k, v) in &ev.attributes {
                // Skip registrar fields: the registrar is not the registrant,
                // and in a multi-domain / company scan it can itself be a
                // present Organisation entity. ("registrant" does not contain
                // "registrar", so registrant_* keys are kept.)
                if k.contains("registrar") {
                    continue;
                }
                // Organisation: whole trimmed value (org names contain spaces).
                if let Some(&org) = org_by_value.get(v.trim()) {
                    link(dom, org, &mut out);
                    continue;
                }
                // Email: normalise the same way the Email entity value was.
                let email_key = crate::core::entity::normalise(&EntityKind::Email, v);
                if let Some(&em) = email_by_value.get(email_key.as_str()) {
                    link(dom, em, &mut out);
                }
            }
        }
    }
    out
}

/// Canonicalise an email address to the mailbox it provably routes to, or
/// `None` if the value isn't a single well-formed address.
///
/// High-precision and provider-aware by design — it only collapses
/// transformations the provider **documents** as address-equivalent, so it
/// never fuses two genuinely distinct mailboxes (the cardinal sin of entity
/// resolution):
///
/// - **Gmail / Googlemail**: dots in the local part are ignored and the two
///   domains are aliases, so `John.Smith@googlemail.com` ≡ `johnsmith@gmail.com`.
/// - **Sub-addressing (`+tag`)**: for providers that document plus-addressing
///   (Gmail, Outlook/Hotmail/Live, iCloud, Proton, Fastmail), everything from
///   the first `+` in the local part is a delivery tag and is dropped.
/// - **Everything else**: returned lowercased but otherwise untouched, so a
///   provider that treats dots or `+` as significant is never over-merged.
fn canonical_mailbox(email: &str) -> Option<(String, String)> {
    let e = email.trim().to_ascii_lowercase();
    let (local, domain) = e.split_once('@')?;
    // Reject multi-`@` / empty halves: not a single well-formed address.
    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        return None;
    }
    // googlemail.com is a documented alias of gmail.com.
    let domain = if domain == "googlemail.com" {
        "gmail.com"
    } else {
        domain
    };
    let is_gmail = domain == "gmail.com";

    // Providers that route `user+tag@domain` to `user@domain`. Conservative:
    // only providers whose sub-addressing is documented are listed, so a `+`
    // that is significant elsewhere is preserved.
    const PLUS_PROVIDERS: &[&str] = &[
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "icloud.com",
        "me.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "fastmail.com",
    ];

    let base = match (PLUS_PROVIDERS.contains(&domain), local.split_once('+')) {
        (true, Some((base, _tag))) => base,
        _ => local,
    };
    let mut local = base.to_string();
    // Gmail ignores dots in the local part.
    if is_gmail {
        local.retain(|c| c != '.');
    }
    // A local part that is empty after canonicalisation (e.g. "+tag@gmail.com"
    // or ".@gmail.com") isn't a routable mailbox — don't resolve on it.
    if local.is_empty() {
        return None;
    }
    Some((local, domain.to_string()))
}

/// Derive `SameAs` identity-equivalence edges among the scan's Email entities.
///
/// Pure and deterministic — it honours this layer's "open math, no fuzzy
/// matching" invariant: it groups present Email entities by their provable
/// canonical mailbox ([`canonical_mailbox`]) and links every distinct surface
/// form in a group to the group's representative (the lexicographically
/// smallest UID) with a `SameAs` edge. A group with fewer than two **distinct**
/// entities yields nothing, so only genuine cross-form duplicates produce
/// edges. The star topology (member → representative) is O(k) per group and
/// connects the whole equivalence class through the representative; one edge
/// per (member, representative) pair, canonically directed, so re-scans upsert
/// idempotently on the deterministic edge id.
///
/// Non-destructive and reversible: both surface-form nodes are retained with
/// their own provenance; the resolved identity is the connected component over
/// these edges, and dropping an edge "splits" the class back out.
pub fn derive_identity_equivalence(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::BTreeMap;

    // canonical mailbox -> the present Email entities resolving to it.
    // BTreeMap keeps group iteration deterministic across runs.
    let mut groups: BTreeMap<(String, String), Vec<&Entity>> = BTreeMap::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Email) {
        if let Some(key) = canonical_mailbox(&e.value) {
            groups.entry(key).or_default().push(e);
        }
    }

    let mut out = Vec::new();
    for (_canonical, mut members) in groups {
        // Distinct UIDs only: two evidence copies of one entity value share a
        // UID (they're already the same node), which is not a resolution.
        members.sort_by(|a, b| a.uid.cmp(&b.uid));
        members.dedup_by(|a, b| a.uid == b.uid);
        if members.len() < 2 {
            continue;
        }
        let rep = members[0]; // smallest UID = deterministic representative
        for m in &members[1..] {
            out.push(Relation::new(
                m.uid.as_str(),
                rep.uid.as_str(),
                RelationKind::SameAs,
                m.confidence.min(rep.confidence),
                scan_id,
            ));
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
    fn subdomain_edges_are_label_aligned() {
        // "notexample.com" must NOT be treated as a subdomain of "example.com"
        // (the label-strip walks dot boundaries, so it never matches mid-label).
        let entities = vec![
            ent(EntityKind::Domain, "notexample.com", 0.9),
            ent(EntityKind::Domain, "example.com", 0.8),
        ];
        let subs: Vec<_> = derive_structural(&entities, "s")
            .into_iter()
            .filter(|r| r.kind == RelationKind::SubdomainOf)
            .collect();
        assert!(
            subs.is_empty(),
            "notexample.com is not a subdomain of example.com, got: {subs:?}"
        );
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

    #[test]
    fn resolution_trims_punctuation_from_summary_tokens() {
        use crate::core::entity::Evidence;
        let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "rel-scan");
        // Domain appears wrapped in punctuation in the summary token.
        ip.add_evidence(Evidence::new("doh_resolver", "A record for (example.com),"));
        let dom = ent(EntityKind::Domain, "example.com", 0.9);
        let rels = derive_resolution(&[ip, dom], "s");
        assert_eq!(
            rels.len(),
            1,
            "punctuation-wrapped domain token must still link"
        );
        assert_eq!(rels[0].kind, RelationKind::ResolvesTo);
    }

    // ── derive_registration (Domain → registrant via WHOIS evidence) ───────

    #[test]
    fn registration_links_domain_to_registrant_org_and_email() {
        use crate::core::entity::Evidence;
        // Realistic whois fixture: the Domain carries registrant_org +
        // registrant_email attrs (and a registrar that is NOT a registrant),
        // and whois also emits the Organisation + Email entities.
        let mut dom = Entity::new(EntityKind::Domain, "example.com", 0.92, "rel-scan");
        dom.add_evidence(
            Evidence::new("whois", "WHOIS for example.com")
                .with_attr("registrar", "MarkMonitor Inc.")
                .with_attr("registrant_org", "Example Org LLC")
                .with_attr("registrant_email", "admin@example.com"),
        );
        let org = ent(EntityKind::Organisation, "Example Org LLC", 0.72);
        let email = ent(EntityKind::Email, "admin@example.com", 0.78);
        // The registrar is ALSO present as an Organisation entity (as happens
        // in multi-domain scans) — it must NOT be linked as the registrant.
        let registrar = ent(EntityKind::Organisation, "MarkMonitor Inc.", 0.70);
        let rels = derive_registration(
            &[dom.clone(), org.clone(), email.clone(), registrar.clone()],
            "s",
        );
        assert_eq!(
            rels.len(),
            2,
            "registrant org + registrant email; NOT registrar"
        );
        assert!(rels.iter().all(|r| r.kind == RelationKind::RegisteredBy));
        assert!(
            rels.iter().all(|r| r.from_uid == dom.uid),
            "domain -> registrant"
        );
        let targets: Vec<&str> = rels.iter().map(|r| r.to_uid.as_str()).collect();
        assert!(targets.contains(&org.uid.as_str()));
        assert!(targets.contains(&email.uid.as_str()));
        assert!(
            !targets.contains(&registrar.uid.as_str()),
            "registrar must be excluded from registered_by"
        );
    }

    #[test]
    fn registration_no_edge_when_registrant_not_an_entity() {
        use crate::core::entity::Evidence;
        let mut dom = Entity::new(EntityKind::Domain, "example.com", 0.92, "rel-scan");
        dom.add_evidence(
            Evidence::new("whois", "WHOIS for example.com")
                .with_attr("registrant_org", "Nonexistent Org"),
        );
        // No Organisation/Email entity matches → no edge.
        assert!(derive_registration(&[dom], "s").is_empty());
    }

    #[test]
    fn registration_dedups_repeated_registrant() {
        use crate::core::entity::Evidence;
        let mut dom = Entity::new(EntityKind::Domain, "example.com", 0.9, "rel-scan");
        dom.add_evidence(
            Evidence::new("whois", "WHOIS for example.com")
                .with_attr("registrant_org", "Acme Inc")
                .with_attr("admin_org", "Acme Inc"),
        );
        let org = ent(EntityKind::Organisation, "Acme Inc", 0.72);
        assert_eq!(
            derive_registration(&[dom, org], "s").len(),
            1,
            "one edge per (domain, registrant)"
        );
    }

    // ── canonical_mailbox + derive_identity_equivalence (entity resolution) ─

    #[test]
    fn canonical_mailbox_gmail_ignores_dots_plus_and_alias() {
        let canon = ("johnsmith".to_string(), "gmail.com".to_string());
        assert_eq!(
            canonical_mailbox("john.smith@gmail.com"),
            Some(canon.clone())
        );
        assert_eq!(
            canonical_mailbox("johnsmith@gmail.com"),
            Some(canon.clone())
        );
        assert_eq!(
            canonical_mailbox("j.o.h.n.smith+newsletter@gmail.com"),
            Some(canon.clone())
        );
        // googlemail.com is an alias of gmail.com.
        assert_eq!(canonical_mailbox("John.Smith@googlemail.com"), Some(canon));
    }

    #[test]
    fn canonical_mailbox_preserves_dots_for_non_gmail() {
        // Dots are gmail-specific: a non-gmail provider may route john.smith and
        // johnsmith to different mailboxes, so they must NOT collapse.
        assert_eq!(
            canonical_mailbox("john.smith@outlook.com"),
            Some(("john.smith".to_string(), "outlook.com".to_string()))
        );
        assert_ne!(
            canonical_mailbox("john.smith@outlook.com"),
            canonical_mailbox("johnsmith@outlook.com")
        );
    }

    #[test]
    fn canonical_mailbox_strips_plus_for_known_providers_only() {
        // Known plus-addressing provider → tag stripped.
        assert_eq!(
            canonical_mailbox("user+promos@icloud.com"),
            Some(("user".to_string(), "icloud.com".to_string()))
        );
        // Unknown provider → '+' may be significant, so it is preserved.
        assert_eq!(
            canonical_mailbox("user+promos@example.com"),
            Some(("user+promos".to_string(), "example.com".to_string()))
        );
    }

    #[test]
    fn canonical_mailbox_rejects_malformed() {
        assert_eq!(canonical_mailbox("not-an-email"), None);
        assert_eq!(canonical_mailbox("@gmail.com"), None);
        assert_eq!(canonical_mailbox("user@"), None);
        assert_eq!(canonical_mailbox("a@b@gmail.com"), None);
        assert_eq!(canonical_mailbox("user@localhost"), None); // no dot in domain
        assert_eq!(canonical_mailbox("+tag@gmail.com"), None); // empty after canon
    }

    #[test]
    fn identity_equivalence_links_gmail_dot_variants() {
        let a = ent(EntityKind::Email, "john.smith@gmail.com", 0.9);
        let b = ent(EntityKind::Email, "johnsmith@gmail.com", 0.7);
        let rels = derive_identity_equivalence(&[a.clone(), b.clone()], "s");
        assert_eq!(rels.len(), 1, "two surface forms of one mailbox → one edge");
        assert_eq!(rels[0].kind, RelationKind::SameAs);
        // Canonical direction: member (larger uid) → representative (smaller uid).
        let (rep, member) = if a.uid <= b.uid { (&a, &b) } else { (&b, &a) };
        assert_eq!(rels[0].from_uid, member.uid);
        assert_eq!(rels[0].to_uid, rep.uid);
        // Edge confidence is the weaker endpoint.
        assert!((rels[0].confidence - 0.7).abs() < 1e-9);
    }

    #[test]
    fn identity_equivalence_never_merges_distinct_mailboxes() {
        // Different gmail mailboxes, and dot-variant non-gmail addresses, must
        // never be fused — a false merge is the cardinal entity-resolution sin.
        let entities = vec![
            ent(EntityKind::Email, "johnsmith@gmail.com", 0.9),
            ent(EntityKind::Email, "janedoe@gmail.com", 0.9),
            ent(EntityKind::Email, "john.smith@outlook.com", 0.9),
            ent(EntityKind::Email, "johnsmith@outlook.com", 0.9),
        ];
        assert!(
            derive_identity_equivalence(&entities, "s").is_empty(),
            "distinct mailboxes (and dot-variant non-gmail) must not resolve"
        );
    }

    #[test]
    fn identity_equivalence_star_topology_for_three_variants() {
        // Three surface forms of one gmail mailbox → 2 edges (each non-rep → rep),
        // not 3 (a full clique): the star connects the class in O(k).
        let entities = vec![
            ent(EntityKind::Email, "john.smith@gmail.com", 0.9),
            ent(EntityKind::Email, "johnsmith@gmail.com", 0.9),
            ent(EntityKind::Email, "j.ohnsmith+work@googlemail.com", 0.9),
        ];
        let rels = derive_identity_equivalence(&entities, "s");
        assert_eq!(rels.len(), 2, "star topology: k-1 edges for k=3 variants");
        assert!(rels.iter().all(|r| r.kind == RelationKind::SameAs));
        // Every edge points at the same representative (smallest UID present).
        let rep_uid = entities.iter().map(|e| &e.uid).min().unwrap();
        assert!(rels.iter().all(|r| &r.to_uid == rep_uid));
    }

    #[test]
    fn identity_equivalence_ignores_non_email_entities() {
        let entities = vec![
            ent(EntityKind::Username, "johnsmith", 0.9),
            ent(EntityKind::Domain, "gmail.com", 0.9),
            ent(EntityKind::Email, "solo@gmail.com", 0.9), // single → no edge
        ];
        assert!(derive_identity_equivalence(&entities, "s").is_empty());
    }
}
