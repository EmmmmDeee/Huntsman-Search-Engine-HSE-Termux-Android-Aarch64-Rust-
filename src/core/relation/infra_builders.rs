//! Infrastructure-graph relation builders: subdomain/hosting ownership,
//! geo co-location, DNS resolution, WHOIS registration, name-permutation
//! lineage, and shared-operator co-ownership. The identity-graph builders
//! live in the sibling [`super::identity_builders`]; [`super::builders`]
//! orchestrates both into the single deterministic `derive_all` chain.

use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::types::{Relation, RelationKind, domain_key};

use super::identity_builders::persons_by_name;

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

/// Derive `RegisteredBy` edges (Domain → Organisation / Email / Person) from
/// WHOIS registrant evidence.
///
/// Robust by design, mirroring `derive_resolution`: it matches a Domain
/// entity's evidence attribute *values* (e.g. `whois`'s `registrant_org` /
/// `registrant_email` / `registrant_name` attrs) against present Organisation,
/// Email and Person entities, rather than coupling to attribute keys. `whois`
/// emits the registrant org, contact emails and registrant/admin/tech names as
/// their own entities and folds the name values into the domain evidence, so
/// every endpoint is present. `registrar`-keyed attributes are skipped, so a
/// registrar that happens to be a present Organisation entity isn't mistaken
/// for the registrant. Org/Person names are matched as whole trimmed values
/// (not tokenised) since they contain spaces. One edge per (domain, registrant).
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
    // Registrant/admin/tech NAMES (folded into the domain evidence by `whois`)
    // resolve to a present Person via this deterministic index, so the human who
    // registered the domain is linked to it — not just the org/email contacts.
    let persons = persons_by_name(entities);
    if org_by_value.is_empty() && email_by_value.is_empty() && persons.is_empty() {
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
                // Registrant/admin/tech name → the human registrant Person.
                // Checked BEFORE org/email so a name value can't be mis-matched
                // as an org. `*_name` selects exactly registrant_name/admin_name/
                // tech_name (name_servers ends with "servers", registrar_* is
                // already skipped).
                if k.ends_with("_name") {
                    if let Some(&p) = persons.get(v.trim().to_lowercase().as_str()) {
                        link(dom, p, &mut out);
                    }
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

/// Derive `DerivedFrom` edges from each name-derived Username/Email back to the
/// subject Person it was permuted from.
///
/// `name_intel` produces speculative usernames/emails from a Person seed in a
/// single module call, so the engine's expansion lineage never links them — the
/// provenance survives only as each handle's `source_name` evidence attribute.
/// Without an edge the dossier is the subject Person plus a pile of orphan
/// handles; this turns the recorded provenance into a graph edge so every derived
/// handle points back at the individual it came from (a graph/report export then
/// shows the Person as the hub — the "individualised result" the engine is for).
///
/// Only `name-derived`-tagged entities are considered, matched case-insensitively
/// by their `source_name` against present Person entities, so no unrelated entity
/// can spuriously attach. The edge carries the handle's own (speculative)
/// confidence, so a guessed handle's lineage never inflates its weight.
/// Deterministic: one edge per matching handle, emitted in entity order.
pub fn derive_name_lineage(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    // Person values are NOT case-folded at normalisation ("Jane Smith" and
    // "jane smith" are distinct entities), but this lookup folds them — so two
    // Persons can collide on one key. Use the shared deterministic index (highest
    // confidence wins, ties broken by smaller uid) so the chosen parent never
    // depends on the caller's (HashMap-randomised) entity order — the same
    // collision rule the other name-keyed builders bind to, kept in one place so
    // it can never drift between them.
    let persons = persons_by_name(entities);
    if persons.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for e in entities.iter().filter(|e| e.has_tag("name-derived")) {
        let Some(src) = e
            .evidence
            .iter()
            .find_map(|ev| ev.attributes.get("source_name"))
        else {
            continue;
        };
        if let Some(person) = persons.get(src.trim().to_lowercase().as_str())
            && person.uid != e.uid
        {
            out.push(Relation::new(
                e.uid.as_str(),
                person.uid.as_str(),
                RelationKind::DerivedFrom,
                e.confidence,
                scan_id,
            ));
        }
    }
    out
}

/// Upper bound on distinct registrable domains sharing a single dedicated IP for
/// `derive_co_ownership` to emit a `SameOperator` edge — mirrors the AU-062
/// correlator cap (`MAX_CO_HOSTED_REGISTRABLE`). Both must stay in sync: the
/// correlator fires when ≤N sites share an IP; the builder emits the structural
/// edge for the same membership set.
const MAX_CO_HOSTED_REGISTRABLE: usize = 5;

/// Derive `SameOperator` edges between domain/site entities that share an operator
/// — inferred from three complementary evidence classes, each with appropriate
/// false-positive guards. Runs AFTER the other builders so it can read the
/// `RegisteredBy` and `ResolvesTo` edges they produced (passed as `relations`).
///
/// **Source A — Shared WHOIS registrant** (`RegisteredBy` edges, grouped by
/// registrant uid): ≥2 domains sharing one genuine registrant are very likely
/// co-owned. Privacy-proxy / redaction registrants (see
/// [`crate::util::domains::is_proxy_registrant`]) are excluded — a shared proxy
/// spans millions of unrelated domains and would cause mass false positives.
/// Mirrors the AU-061 correlator gate.
///
/// **Source B — Shared dedicated IP** (`ResolvesTo` edges, grouped by IP uid):
/// ≥2 DISTINCT registrable domains on one non-CDN, non-anycast IP with ≤
/// [`MAX_CO_HOSTED_REGISTRABLE`] members are probably co-hosted by the same
/// operator. Mirrors the three AU-062 guards: CDN/non-routable exclusion, eTLD+1
/// dedup, fan-out cap.
///
/// **Source C — Shared web-analytics ID** (`TrackingId` entity evidence): a
/// `TrackingId` entity whose `source_domain` attributes name ≥2 present Domain
/// entities. A shared GA/GTM/pixel ID is an intentional operator-level
/// configuration tag. Mirrors the AU-044 gate.
///
/// Edge direction: canonical `min_uid → max_uid` (same as `CoLocatedWith`) so
/// re-scans upsert idempotently and there is exactly one edge per pair.
/// Confidence = `min(a.confidence, b.confidence)`, consistent with every other
/// builder. Deduped: the same pair can qualify under multiple sources; only one
/// edge is emitted.
pub fn derive_co_ownership(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    if entities.is_empty() {
        return Vec::new();
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let mut out: Vec<Relation> = Vec::new();
    // Global dedup so the same pair emitted by A, B, or C produces one edge.
    let mut emitted: HashSet<(String, String)> = HashSet::new();

    let mut push_pair = |a_uid: &str, b_uid: &str, out: &mut Vec<Relation>| {
        let (from, to) = if a_uid <= b_uid {
            (a_uid, b_uid)
        } else {
            (b_uid, a_uid)
        };
        let key = (from.to_string(), to.to_string());
        if emitted.contains(&key) {
            return;
        }
        emitted.insert(key);
        let conf = by_uid
            .get(from)
            .map_or(0.5, |e| e.confidence)
            .min(by_uid.get(to).map_or(0.5, |e| e.confidence));
        out.push(Relation::new(
            from,
            to,
            RelationKind::SameOperator,
            conf,
            scan_id,
        ));
    };

    // ── Source A: shared registrant ──────────────────────────────────────────
    {
        let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
        for r in relations
            .iter()
            .filter(|r| r.kind == RelationKind::RegisteredBy)
        {
            let (Some(dom), Some(reg)) = (
                by_uid.get(r.from_uid.as_str()),
                by_uid.get(r.to_uid.as_str()),
            ) else {
                continue;
            };
            if dom.kind != EntityKind::Domain
                || !matches!(reg.kind, EntityKind::Organisation | EntityKind::Email)
            {
                continue;
            }
            if crate::util::domains::is_proxy_registrant(&reg.value, reg.kind == EntityKind::Email)
            {
                continue;
            }
            let members = groups.entry(r.to_uid.as_str()).or_default();
            if !members.contains(&r.from_uid.as_str()) {
                members.push(r.from_uid.as_str());
            }
        }
        for (_, mut domains) in groups {
            if domains.len() < 2 || domains.len() > 20 {
                continue;
            }
            domains.sort_unstable();
            for i in 0..domains.len() {
                for j in (i + 1)..domains.len() {
                    push_pair(domains[i], domains[j], &mut out);
                }
            }
        }
    }

    // ── Source B: shared dedicated IP ────────────────────────────────────────
    {
        let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
        for r in relations
            .iter()
            .filter(|r| r.kind == RelationKind::ResolvesTo)
        {
            let (Some(dom), Some(ip)) = (
                by_uid.get(r.from_uid.as_str()),
                by_uid.get(r.to_uid.as_str()),
            ) else {
                continue;
            };
            if dom.kind != EntityKind::Domain || ip.kind != EntityKind::IpAddress {
                continue;
            }
            if crate::core::validation::is_cdn_edge_ip(&ip.value)
                || crate::core::validation::is_non_routable_ip(&ip.value)
            {
                continue;
            }
            let members = groups.entry(r.to_uid.as_str()).or_default();
            if !members.contains(&r.from_uid.as_str()) {
                members.push(r.from_uid.as_str());
            }
        }
        for (_, mut domains) in groups {
            if domains.len() < 2 {
                continue;
            }
            domains.sort_unstable();
            let mut registrables: Vec<String> = domains
                .iter()
                .filter_map(|u| by_uid.get(u))
                .filter_map(|e| crate::util::domains::registrable_domain(&e.value))
                .collect();
            registrables.sort_unstable();
            registrables.dedup();
            if registrables.len() < 2 || registrables.len() > MAX_CO_HOSTED_REGISTRABLE {
                continue;
            }
            for i in 0..domains.len() {
                for j in (i + 1)..domains.len() {
                    push_pair(domains[i], domains[j], &mut out);
                }
            }
        }
    }

    // ── Source C: shared web-analytics ID ────────────────────────────────────
    {
        let domain_by_value: HashMap<&str, &Entity> = entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .map(|e| (e.value.as_str(), e))
            .collect();
        for tid in entities.iter().filter(|e| e.kind == EntityKind::TrackingId) {
            let mut sources: Vec<&str> = tid
                .evidence
                .iter()
                .filter_map(|ev| ev.attributes.get("source_domain").map(String::as_str))
                .collect();
            sources.sort_unstable();
            sources.dedup();
            let matching: Vec<&str> = sources
                .iter()
                .filter_map(|s| domain_by_value.get(s).map(|e| e.uid.as_str()))
                .collect();
            if matching.len() < 2 {
                continue;
            }
            for i in 0..matching.len() {
                for j in (i + 1)..matching.len() {
                    push_pair(matching[i], matching[j], &mut out);
                }
            }
        }
    }

    out
}
