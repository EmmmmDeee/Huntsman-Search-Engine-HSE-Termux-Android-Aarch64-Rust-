use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::types::{Relation, RelationKind, domain_key};

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
    use std::collections::HashMap;

    // Person values are NOT case-folded at normalisation ("Jane Smith" and
    // "jane smith" are distinct entities), but this lookup folds them — so two
    // Persons can collide on one key. A plain last-write-wins collect made the
    // edge target depend on the caller's (HashMap-randomised) entity order,
    // breaking this module's determinism invariant. Resolve collisions with a
    // stable rule instead: highest confidence wins, ties broken by smaller uid.
    let mut persons: HashMap<String, &Entity> = HashMap::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Person) {
        persons
            .entry(e.value.trim().to_lowercase())
            .and_modify(|cur| {
                let better = e.confidence > cur.confidence
                    || (e.confidence == cur.confidence && e.uid < cur.uid);
                if better {
                    *cur = e;
                }
            })
            .or_insert(e);
    }
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

// ── Identity relations ───────────────────────────────────────────────────────
//
// The builders above reconstruct the *infrastructure* graph (subdomains, hosting,
// DNS, WHOIS). For a person-centric scan that is mostly empty — the high-value
// edges bind the SUBJECT to their identifiers, accounts, places and associates.
// Without them a 500-entity person scan persists zero relations (nodes, no edges)
// and the dossier/force-graph shows an unconnected pile. These builders add that
// identity layer, holding to the same rigor as the infra builders: deterministic
// (stable, deduped, canonically-directed), evidence- or structure-grounded so no
// false edge fires, and confidence carried from the endpoints — *damped* for the
// two candidate signals (fingerprint ownership, surname kinship) so a lead never
// masquerades as a certainty.

/// Confidence damp for a fingerprint-based [`RelationKind::IdentifiedBy`] edge:
/// the endpoints are real, but binding a handle to the subject purely by an
/// identity-fingerprint overlap is a lead, not a structural certainty.
const IDENTITY_CANDIDATE_DAMP: f64 = 0.6;

/// Confidence damp for a surname-based [`RelationKind::AssociatedWith`] kinship
/// edge — a candidate association (people can share a surname by coincidence),
/// surfaced for the operator to confirm.
const KINSHIP_DAMP: f64 = 0.5;

/// Score damp for an inferred co-residence edge. Two distinct people NAMED at the
/// SAME specific street address (a register's separate owner records, a household
/// roll) are linked even when they share no surname — the household tie the surname
/// kinship structurally can't see. Evidence-grounded (both names are on a record at
/// that address), so it outranks a bare surname guess ([`KINSHIP_DAMP`]); damped
/// below a DECLARED relationship because "same address" can occasionally be a shared
/// building rather than one household.
const CO_RESIDENCE_DAMP: f64 = 0.8;

/// Tags that mark an `Address` as too COARSE to be a dwelling — a postcode / suburb
/// centroid, not a specific home. Two people sharing a postcode are not
/// co-residents, so these places never link a household.
const COARSE_ADDRESS_TAGS: &[&str] = &["coarse", "postcode-only", "candidate-suburb"];

/// Max residents paired per place — a household is small; this bounds the O(k²)
/// pairing on a pathological owner list (Determinism + low-RAM Termux).
const CO_RESIDENCE_MAX_PER_PLACE: usize = 8;

/// Score damp for a CO-MENTION association — two distinct Persons NAMED IN THE SAME
/// SOURCE document (one result page, record, or article). The document-level analog
/// of co-residence: where co-residence links people a shared ADDRESS names together,
/// this links people a shared SOURCE names together — relatives and associates a
/// single page lists side by side (an obituary, a family notice, co-owners on a
/// title) that neither a surname nor an address would connect. A shared source is
/// real but more circumstantial than a shared dwelling, so it is damped below
/// co-residence ([`CO_RESIDENCE_DAMP`]) and a declared link; a same-surname
/// co-mentioned pair keeps its stronger kinship edge on the same pair, so the two
/// angles corroborate rather than double-count.
const CO_MENTION_DAMP: f64 = 0.45;

/// A source naming MORE than this many distinct Persons is a directory / news
/// round-up / list page, not a relationship document — co-mention would mint O(n²)
/// spurious edges from it, so such a source is skipped entirely. A source naming a
/// handful (2–5) is exactly the obituary / family-notice document this exists to mine.
const CO_MENTION_MAX_PERSONS_PER_SOURCE: usize = 5;

/// Evidence attribute keys that identify the SOURCE document a finding came from —
/// the join key for co-mention. `url` is canonical (search results, scraped pages);
/// `source_url` / `page` are module variants.
const CO_MENTION_SOURCE_ATTRS: &[&str] = &["url", "source_url", "page"];

/// Distinctive owner / infrastructure SELECTOR attributes the modules actually emit
/// and that genuinely individuate an affiliation — a registrant identity, a crypto
/// fingerprint, an email's gravatar. Deliberately EXCLUDES generic fields shared by
/// the masses (registrar, country, provider, ASN), which would mint false ties. This
/// curated allowlist is the precision floor for [`derive_shared_selector`]; every
/// entry is a real key emitted somewhere in the module layer (no speculative
/// selectors), keeping the pivot grounded in data the engine actually produces.
const AFFILIATION_SELECTOR_ATTRS: &[&str] = &[
    "registrant_email",
    "registrant_org",
    "admin_org",
    "cert_serial",
    "key_fingerprint",
    "gravatar_hash",
];

/// Score damp for a shared-selector affiliation edge. An individuating selector is a
/// strong tie but still circumstantial (a registrant can be a shared agent), so it is
/// damped like co-mention — a lead for the analyst to confirm, not an assertion.
const AFFILIATION_DAMP: f64 = 0.45;

/// A selector value shared by MORE than this many distinct entities is not
/// individuating — a privacy-proxy registrant, a default TLS fingerprint, a shared
/// host — so it links nothing. A genuine owner selector is shared by a few affiliates.
const AFFILIATION_CROWD_CAP: usize = 6;

/// Evidence attribute keys whose value names a real person — the owner /
/// registrant / account holder a module recorded alongside an identifier or a
/// place. Matched case-insensitively against present Person entities, so an
/// owner-named address (`qld_unclaimed`'s `owner`) or a profile's `full_name`
/// becomes a graph edge rather than a buried attribute.
const PERSON_NAME_ATTRS: &[&str] = &[
    "owner",
    "full_name",
    "name",
    "person",
    "account_name",
    "source_name",
    "registrant_name",
    "holder",
    "resident",
    "contact_name",
    "display_name",
];

/// The normalised identity fingerprint of an Email/Username, for detecting a
/// shared persona across platforms. Emails key on the local-part (handled by
/// [`crate::core::scan::identity_norm`], which splits on `@`); usernames on the
/// whole value. `None` for a handle too short or all-digits to be a reliable
/// persona key, so generic noise can't fan out into a false alias clique.
fn persona_key(e: &Entity) -> Option<String> {
    if !matches!(e.kind, EntityKind::Email | EntityKind::Username) {
        return None;
    }
    let key = crate::core::scan::identity_norm(&e.value);
    // 4 = IDENTITY_OVERLAP_MIN: shorter handles alias too readily.
    (key.len() >= 4 && !key.bytes().all(|b| b.is_ascii_digit())).then_some(key)
}

/// The folded last whitespace token of a Person value — a family key. `None` when
/// it's < 4 chars (initials / very short surnames alias too readily).
fn surname_key(value: &str) -> Option<String> {
    let last = value.split_whitespace().next_back()?;
    let key = crate::core::scan::identity_norm(last);
    (key.len() >= 4).then_some(key)
}

/// Index present Person entities by their folded full name, resolving collisions
/// deterministically (higher confidence, then smaller uid) so the chosen target
/// never depends on the caller's entity order — the determinism invariant the
/// whole module holds to.
fn persons_by_name(entities: &[Entity]) -> std::collections::HashMap<String, &Entity> {
    let mut persons = std::collections::HashMap::new();
    for p in entities.iter().filter(|e| e.kind == EntityKind::Person) {
        persons
            .entry(p.value.trim().to_lowercase())
            .and_modify(|cur: &mut &Entity| {
                if p.confidence > cur.confidence
                    || (p.confidence == cur.confidence && p.uid < cur.uid)
                {
                    *cur = p;
                }
            })
            .or_insert(p);
    }
    persons
}

/// The subject Person(s): those carrying the engine's seed-anchor tag (`subject`
/// or `seed`). The fingerprint/`exact-name-match` paths bind only to these, so an
/// incidental Person never accretes the subject's handles or places.
fn subject_persons(entities: &[Entity]) -> Vec<&Entity> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && (e.has_tag("subject") || e.has_tag("seed")))
        .collect()
}

/// Stable output order (by endpoints) so a builder whose internal grouping uses a
/// `HashMap` still returns a deterministic `Vec` — matching the module contract.
fn sort_edges(edges: &mut [Relation]) {
    edges.sort_by(|a, b| {
        (a.from_uid.as_str(), a.to_uid.as_str()).cmp(&(b.from_uid.as_str(), b.to_uid.as_str()))
    });
}

/// Derive `AliasOf` edges between Email/Username entities that share one
/// normalised persona key — the cross-platform "same handle" pivot
/// (`jsmith@gmail.com` ↔ `jsmith@outlook.com` ↔ username `jsmith`). Purely
/// structural (exact normalised-handle match), so precision is high; generic /
/// numeric handles are excluded by [`persona_key`]. Symmetric edges are emitted
/// once in canonical direction (smaller UID → larger) and deduped, then sorted —
/// deterministic regardless of entity order.
pub fn derive_handles(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    let mut by_key: HashMap<String, Vec<&Entity>> = HashMap::new();
    for e in entities {
        if let Some(k) = persona_key(e) {
            by_key.entry(k).or_default().push(e);
        }
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for group in by_key.values() {
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let (a, b) = (group[i], group[j]);
                // Same entity, or two spellings that normalise identically — not
                // an alias between *distinct* identifiers.
                if a.uid == b.uid || a.value == b.value {
                    continue;
                }
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                if seen.insert((from.uid.clone(), to.uid.clone())) {
                    out.push(Relation::new(
                        from.uid.as_str(),
                        to.uid.as_str(),
                        RelationKind::AliasOf,
                        from.confidence.min(to.confidence),
                        scan_id,
                    ));
                }
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Derive `IdentifiedBy` edges (Person → Email/Username/Phone) binding the subject
/// to their identifiers. Two grounded paths, evidence preferred:
///   * **evidence** — the identifier's evidence carries an owner/name attribute
///     ([`PERSON_NAME_ATTRS`]) matching a present Person (any Person; the module
///     itself attributed it). High confidence (min of endpoints).
///   * **fingerprint** — an Email-local/Username whose identity fingerprint
///     overlaps the *subject*'s name ([`crate::core::scan::identity_overlaps`],
///     the same primitive the engine uses to gate wrong-identity pivots). A
///     candidate, so damped by [`IDENTITY_CANDIDATE_DAMP`]; bound only to the
///     subject so it can't mis-attach to an incidental Person. Phones have no
///     fingerprint, so they link by evidence only.
///
/// Deduped per (person, identifier); deterministic output order.
pub fn derive_identity_ownership(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashSet;

    let person_by_name = persons_by_name(entities);
    if person_by_name.is_empty() {
        return Vec::new();
    }
    let subjects = subject_persons(entities);

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for h in entities.iter().filter(|e| {
        matches!(
            e.kind,
            EntityKind::Email | EntityKind::Username | EntityKind::Phone
        )
    }) {
        // Evidence-grounded ownership (any attributed Person).
        let mut linked = false;
        for ev in &h.evidence {
            for (k, v) in &ev.attributes {
                if !PERSON_NAME_ATTRS.iter().any(|a| k.eq_ignore_ascii_case(a)) {
                    continue;
                }
                if let Some(&p) = person_by_name.get(v.trim().to_lowercase().as_str())
                    && p.uid != h.uid
                    && seen.insert((p.uid.clone(), h.uid.clone()))
                {
                    out.push(Relation::new(
                        p.uid.as_str(),
                        h.uid.as_str(),
                        RelationKind::IdentifiedBy,
                        p.confidence.min(h.confidence),
                        scan_id,
                    ));
                    linked = true;
                }
            }
        }
        if linked || !matches!(h.kind, EntityKind::Email | EntityKind::Username) {
            continue;
        }
        // Fingerprint-grounded ownership, subject-only and damped.
        for s in &subjects {
            if s.uid != h.uid
                && crate::core::scan::identity_overlaps(&s.value, &h.value)
                && seen.insert((s.uid.clone(), h.uid.clone()))
            {
                out.push(Relation::new(
                    s.uid.as_str(),
                    h.uid.as_str(),
                    RelationKind::IdentifiedBy,
                    s.confidence.min(h.confidence) * IDENTITY_CANDIDATE_DAMP,
                    scan_id,
                ));
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Derive `LocatedAt` edges (Person → Address/Coordinates). Evidence-grounded: a
/// place whose evidence carries an owner/resident attribute ([`PERSON_NAME_ATTRS`])
/// matching a present Person (`qld_unclaimed`'s `owner = ERIK DIEGMANN`). Failing
/// that, a place the scan already flagged as the subject's via the geo
/// correlator's `exact-name-match` tag binds to the subject(s) — reusing that
/// vetted decision rather than re-deriving it. Deduped per (person, place);
/// deterministic output order.
pub fn derive_residency(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashSet;

    let person_by_name = persons_by_name(entities);
    if person_by_name.is_empty() {
        return Vec::new();
    }
    let subjects = subject_persons(entities);

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for place in entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Address | EntityKind::Coordinates))
    {
        let mut linked = false;
        for ev in &place.evidence {
            for (k, v) in &ev.attributes {
                if !PERSON_NAME_ATTRS.iter().any(|a| k.eq_ignore_ascii_case(a)) {
                    continue;
                }
                if let Some(&p) = person_by_name.get(v.trim().to_lowercase().as_str())
                    && seen.insert((p.uid.clone(), place.uid.clone()))
                {
                    out.push(Relation::new(
                        p.uid.as_str(),
                        place.uid.as_str(),
                        RelationKind::LocatedAt,
                        p.confidence.min(place.confidence),
                        scan_id,
                    ));
                    linked = true;
                }
            }
        }
        if linked || !place.has_tag("exact-name-match") {
            continue;
        }
        for s in &subjects {
            if seen.insert((s.uid.clone(), place.uid.clone())) {
                out.push(Relation::new(
                    s.uid.as_str(),
                    place.uid.as_str(),
                    RelationKind::LocatedAt,
                    s.confidence.min(place.confidence),
                    scan_id,
                ));
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Derive `AssociatedWith` kinship-candidate edges between Person entities that
/// share a surname ([`surname_key`]) but are distinct people. People surface in a
/// scan because they're relevant to the subject, so a shared surname is a strong
/// associate lead — but coincidental, so the edge is damped by [`KINSHIP_DAMP`]
/// and clearly typed as a candidate. Symmetric, canonically directed, deduped,
/// deterministic.
pub fn derive_kinship(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    let mut by_surname: HashMap<String, Vec<&Entity>> = HashMap::new();
    for p in entities.iter().filter(|e| e.kind == EntityKind::Person) {
        if let Some(k) = surname_key(&p.value) {
            by_surname.entry(k).or_default().push(p);
        }
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for group in by_surname.values() {
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let (a, b) = (group[i], group[j]);
                // Distinct people only — not the same Person surfaced twice, and
                // not two spellings of one full name.
                if a.uid == b.uid
                    || crate::core::scan::identity_norm(&a.value)
                        == crate::core::scan::identity_norm(&b.value)
                {
                    continue;
                }
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                if seen.insert((from.uid.clone(), to.uid.clone())) {
                    out.push(Relation::new(
                        from.uid.as_str(),
                        to.uid.as_str(),
                        RelationKind::AssociatedWith,
                        from.confidence.min(to.confidence) * KINSHIP_DAMP,
                        scan_id,
                    ));
                }
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Evidence attribute keys whose value names another person this entity is
/// explicitly related/associated to — a people-search relative (`related_to`), a
/// joint register owner (`co_owner` / `joint_owner`), etc. A DECLARED link, so
/// the resulting edge is evidence-grounded (full endpoint trust), unlike the
/// surname kinship heuristic.
const ASSOCIATION_ATTRS: &[&str] = &[
    "related_to",
    "relative_of",
    "associate_of",
    "associated_with",
    "related_person",
    "relation_to",
    "co_owner",
    "joint_owner",
];

/// Derive `AssociatedWith` edges from a DECLARED relationship: a Person whose
/// evidence names another present Person via an association attribute
/// ([`ASSOCIATION_ATTRS`]) — a SeekNow relative carrying `related_to = <subject>`,
/// or a joint unclaimed-money record's `co_owner`. Evidence-grounded, so it
/// carries full endpoint trust (a declared link, not a surname guess) — the
/// high-precision complement to [`derive_kinship`]. The two can emit the same
/// `(from, kind, to)` edge; that is deliberate (one upserts over the other by id)
/// and is how a surname guess gets *upgraded* to a declared certainty when both
/// fire. Symmetric, canonically directed, deduped, deterministic.
pub fn derive_declared_associations(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashSet;

    let person_by_name = persons_by_name(entities);
    if person_by_name.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Person) {
        for ev in &e.evidence {
            for (k, v) in &ev.attributes {
                if !ASSOCIATION_ATTRS.iter().any(|a| k.eq_ignore_ascii_case(a)) {
                    continue;
                }
                if let Some(&other) = person_by_name.get(v.trim().to_lowercase().as_str())
                    && other.uid != e.uid
                {
                    let (from, to) = if e.uid <= other.uid {
                        (e, other)
                    } else {
                        (other, e)
                    };
                    if seen.insert((from.uid.clone(), to.uid.clone())) {
                        out.push(Relation::new(
                            from.uid.as_str(),
                            to.uid.as_str(),
                            RelationKind::AssociatedWith,
                            e.confidence.min(other.confidence),
                            scan_id,
                        ));
                    }
                }
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Distinct Persons explicitly NAMED at a place via [`PERSON_NAME_ATTRS`] evidence,
/// in stable (evidence, attribute) order, de-duplicated by uid. The shared
/// person-at-place resolution behind both residency and co-residence.
fn residents_of<'a>(
    place: &Entity,
    person_by_name: &std::collections::HashMap<String, &'a Entity>,
) -> Vec<&'a Entity> {
    use std::collections::HashSet;

    let mut found: Vec<&Entity> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for ev in &place.evidence {
        for (k, v) in &ev.attributes {
            if !PERSON_NAME_ATTRS.iter().any(|a| k.eq_ignore_ascii_case(a)) {
                continue;
            }
            if let Some(&p) = person_by_name.get(v.trim().to_lowercase().as_str())
                && seen.insert(p.uid.as_str())
            {
                found.push(p);
            }
        }
    }
    found
}

/// Derive `AssociatedWith` co-residence edges between distinct Persons NAMED at the
/// SAME specific `Address` — household members (separate owner records, co-residents
/// on a register / roll) the surname kinship can't link because they need share no
/// name. This is the free, offline angle for DIFFERENT-surname family: a partner, an
/// in-law, a married child, a flatmate — exactly the relatives a same-surname scan
/// structurally misses.
///
/// Precision-gated to a real dwelling: a COARSE postcode/suburb centroid
/// ([`COARSE_ADDRESS_TAGS`]) never links a household (thousands share a postcode),
/// and both people must be evidence-named at the place — so the edge outranks a bare
/// surname guess ([`KINSHIP_DAMP`]) yet is damped below a DECLARED relationship
/// ([`CO_RESIDENCE_DAMP`], since one address can occasionally be a shared building).
/// Bounded per place ([`CO_RESIDENCE_MAX_PER_PLACE`]), symmetric, canonically
/// directed, deduped, deterministic. A co-resident who ALSO shares the surname gets
/// this edge AND the kinship one (same `(from, to)`, this the stronger) — two
/// independent angles agreeing.
pub fn derive_co_residence(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashSet;

    let person_by_name = persons_by_name(entities);
    if person_by_name.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for place in entities.iter().filter(|e| {
        e.kind == EntityKind::Address && !COARSE_ADDRESS_TAGS.iter().any(|t| e.has_tag(t))
    }) {
        let mut residents = residents_of(place, &person_by_name);
        if residents.len() < 2 {
            continue;
        }
        residents.truncate(CO_RESIDENCE_MAX_PER_PLACE);
        for i in 0..residents.len() {
            for j in (i + 1)..residents.len() {
                let (a, b) = (residents[i], residents[j]);
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                if seen.insert((from.uid.clone(), to.uid.clone())) {
                    out.push(Relation::new(
                        from.uid.as_str(),
                        to.uid.as_str(),
                        RelationKind::AssociatedWith,
                        from.confidence.min(to.confidence) * CO_RESIDENCE_DAMP,
                        scan_id,
                    ));
                }
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Universal shared-selector affiliation engine — the general "pivot on a shared
/// selector" OSINT primitive that powers BOTH co-mention and infrastructure
/// affiliation. Links distinct entities (of `kind`, or any kind if `None`) whose
/// evidence carries the SAME value for one of the DISTINCTIVE `attrs` selectors.
///
/// A value shared by MORE than `crowd_cap` distinct entities is not individuating —
/// a privacy-proxy registrant, a default fingerprint, a directory page shared by a
/// crowd — so it mints NO edges (it would otherwise produce O(n²) noise). A value
/// shared by a handful is the genuine tie this exists to surface. Emits one
/// `damp`-scaled, canonically-directed `AssociatedWith` edge per affiliated pair;
/// symmetric, deduped, bounded, and deterministic (sorted values and members). The
/// abstraction is deliberate: a future selector pivot is a one-line config, not a new
/// loop.
fn link_by_shared_attribute(
    entities: &[Entity],
    scan_id: &str,
    attrs: &[&str],
    kind: Option<EntityKind>,
    damp: f64,
    crowd_cap: usize,
) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    // selector value -> the distinct entities whose evidence carries it.
    let mut by_value: HashMap<String, Vec<&Entity>> = HashMap::new();
    for e in entities
        .iter()
        .filter(|e| kind.as_ref().is_none_or(|k| k == &e.kind))
    {
        let mut seen_vals: HashSet<String> = HashSet::new();
        for ev in &e.evidence {
            for (key, val) in &ev.attributes {
                if !attrs.iter().any(|a| key.eq_ignore_ascii_case(a)) {
                    continue;
                }
                let v = val.trim().to_lowercase();
                if !v.is_empty() && seen_vals.insert(v.clone()) {
                    by_value.entry(v).or_default().push(e);
                }
            }
        }
    }
    if by_value.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    // Deterministic value order so the emitted edge set never depends on map order.
    let mut groups: Vec<(&String, &Vec<&Entity>)> = by_value.iter().collect();
    groups.sort_by(|a, b| a.0.cmp(b.0));
    for (_value, members) in groups {
        // A handful share an individuating selector; a crowd shares a generic one.
        if members.len() < 2 || members.len() > crowd_cap {
            continue;
        }
        let mut g = members.clone();
        g.sort_by(|a, b| a.uid.cmp(&b.uid));
        for i in 0..g.len() {
            for j in (i + 1)..g.len() {
                let (a, b) = (g[i], g[j]);
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                if from.uid != to.uid && seen.insert((from.uid.clone(), to.uid.clone())) {
                    out.push(Relation::new(
                        from.uid.as_str(),
                        to.uid.as_str(),
                        RelationKind::AssociatedWith,
                        from.confidence.min(to.confidence) * damp,
                        scan_id,
                    ));
                }
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Derive `AssociatedWith` CO-MENTION edges between distinct Persons NAMED IN THE
/// SAME SOURCE document — the document-level complement of [`derive_co_residence`].
///
/// Reverse-engineered from how real relatives are actually linked: a single public
/// source (an obituary, a family notice, a property title, one search result) names
/// both, but the engine extracts each as a SEPARATE Person and discards the "same
/// source" tie. This recovers it via the universal [`link_by_shared_attribute`]
/// engine over the source selectors — the free, offline angle for relatives and
/// associates a shared surname or address can't reach. Precision-gated
/// ([`CO_MENTION_MAX_PERSONS_PER_SOURCE`]: a crowded source is a directory, skipped)
/// and damped ([`CO_MENTION_DAMP`]) below co-residence and a declared link, so a
/// same-surname co-mentioned pair keeps its stronger kinship edge.
pub fn derive_co_mention(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    link_by_shared_attribute(
        entities,
        scan_id,
        CO_MENTION_SOURCE_ATTRS,
        Some(EntityKind::Person),
        CO_MENTION_DAMP,
        CO_MENTION_MAX_PERSONS_PER_SOURCE,
    )
}

/// Derive `AssociatedWith` AFFILIATION edges between entities that share a DISTINCTIVE
/// owner / infrastructure SELECTOR — the universal reverse-WHOIS / fingerprint pivot,
/// domain-agnostic and forward-operating on any scan.
///
/// Real-world archetype it generalises: a corporate seed and its hidden subsidiary are
/// linked because their domains share a registrant; two servers are one operator's
/// because they share a TLS certificate or SSH key; two profiles are one person's
/// because they share a gravatar. The engine extracts each as a separate entity but
/// the SHARED SELECTOR — already in their evidence ([`AFFILIATION_SELECTOR_ATTRS`]) —
/// is the tie. This materialises it as a direct affiliation edge via
/// [`link_by_shared_attribute`], so a single seed reaches the affiliate it was never
/// explicitly named with.
///
/// Precision is the curated, individuating selector set (registrant identity, crypto
/// fingerprint, gravatar — never a generic registrar / country / provider) plus the
/// [`AFFILIATION_CROWD_CAP`]: a value shared by a crowd is a privacy proxy or a default
/// fingerprint, not an owner, and is skipped. Damped ([`AFFILIATION_DAMP`]), symmetric,
/// deduped, bounded, deterministic. Any kind qualifies (domains, hosts, orgs, emails),
/// so it improves every scan that surfaces these selectors, regardless of subject.
pub fn derive_shared_selector(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    link_by_shared_attribute(
        entities,
        scan_id,
        AFFILIATION_SELECTOR_ATTRS,
        None,
        AFFILIATION_DAMP,
        AFFILIATION_CROWD_CAP,
    )
}

/// Derive every deterministic, evidence-grounded relation the engine knows how
/// to reconstruct from a persisted entity set alone — the infrastructure layer
/// (structural ownership, geo co-location, DNS resolution, WHOIS registration,
/// name lineage) and the identity layer (handle aliases, identifier ownership,
/// residency, kinship, co-residence) — in a single stable order. This is the
/// lineage-free
/// counterpart to the live scan's relation pass: the import paths (CLI `hse
/// import` and the web `scan_import` upload) have no in-flight expansion edges,
/// but every edge derivable from the entities + their evidence still applies, so
/// an imported dossier gets the same graph a live scan would. One definition so
/// the live and import paths can't drift on which relations a finished scan
/// carries.
pub fn derive_all(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let mut out = derive_structural(entities, scan_id);
    out.extend(derive_colocation(entities, scan_id));
    out.extend(derive_resolution(entities, scan_id));
    out.extend(derive_registration(entities, scan_id));
    out.extend(derive_name_lineage(entities, scan_id));
    out.extend(derive_handles(entities, scan_id));
    out.extend(derive_identity_ownership(entities, scan_id));
    out.extend(derive_residency(entities, scan_id));
    out.extend(derive_kinship(entities, scan_id));
    // Co-residence after kinship: an evidence-grounded household edge (×0.8)
    // outranks a surname guess (×0.5) on the same pair, and links the
    // DIFFERENT-surname household members kinship can't reach.
    out.extend(derive_co_residence(entities, scan_id));
    // Co-mention after co-residence: the document-level association analog — people a
    // single SOURCE names together (an obituary, a family notice, one result page).
    // Damped below co-residence; a same-surname co-mentioned pair keeps its stronger
    // kinship edge, so independent angles corroborate rather than double-count.
    out.extend(derive_co_mention(entities, scan_id));
    // Shared-selector affiliation: entities sharing a DISTINCTIVE owner / infra
    // selector (registrant, TLS/SSH fingerprint, gravatar) — the universal
    // reverse-WHOIS / fingerprint pivot, domain-agnostic across every scan.
    out.extend(derive_shared_selector(entities, scan_id));
    // Declared associations LAST so a `(from, kind, to)` edge a surname guess or a
    // co-residence inference already emitted is re-emitted here at full (declared)
    // confidence — the later, higher-trust edge wins on idempotent upsert.
    out.extend(derive_declared_associations(entities, scan_id));
    out
}
