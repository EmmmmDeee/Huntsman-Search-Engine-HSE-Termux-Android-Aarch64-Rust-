//! Identity relation builders: the person-centric graph layer.
//!
//! The infra builders (`super::infra`) reconstruct the *infrastructure* graph
//! (subdomains, hosting, DNS, WHOIS). For a person-centric scan that is mostly
//! empty — the high-value edges bind the SUBJECT to their identifiers,
//! accounts, places and associates. Without them a 500-entity person scan
//! persists zero relations (nodes, no edges) and the dossier/force-graph shows
//! an unconnected pile. These builders add that identity layer, holding to the
//! same rigor as the infra builders: deterministic (stable, deduped,
//! canonically-directed), evidence- or structure-grounded so no false edge
//! fires, and confidence carried from the endpoints — *damped* for the two
//! candidate signals (fingerprint ownership, surname kinship) so a lead never
//! masquerades as a certainty.

use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::types::{Relation, RelationKind};

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
const COARSE_ADDRESS_TAGS: &[&str] = &[
    crate::core::tags::COARSE,
    "postcode-only",
    "candidate-suburb",
];

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

/// The subject Person(s): those carrying the engine's seed-anchor tag (`subject`
/// or `seed`). The fingerprint/`exact-name-match` paths bind only to these, so an
/// incidental Person never accretes the subject's handles or places.
fn subject_persons(entities: &[Entity]) -> Vec<&Entity> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && (e.has_tag("subject") || e.has_tag("seed")))
        .collect()
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
    super::sort_edges(&mut out);
    out
}

/// Derive `SharesSecretWith` edges between Email/Username entities proven to
/// share ONE reused, individuating secret — the graph-native counterpart of
/// the correlator's "controller behind reused secrets" findings (AU-047
/// reused-secret identity, AU-048 shared key, AU-106 shared device), so
/// `identity_paths`/the dossier's CONNECTIONS section can walk this tie as a
/// real edge instead of only reading it off a standalone correlation.
///
/// Delegates to the correlator's own [`crate::core::correlator::Secret`]
/// classification and [`crate::core::correlator::canonical_handle`]
/// handle-folding (Rule 4: one classifier/one folder, so the graph edge and
/// the correlation can never disagree on which secrets qualify or which
/// handles are the same account). Emits a full pairwise clique over every
/// identity entity a qualifying secret's evidence names (not just a chain
/// through one arbitrarily-chosen hub), so `identity_paths`' BFS finds the
/// direct edge between ANY two accounts a shared secret ties together.
pub fn derive_reused_secret_link(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use crate::core::correlator::{Secret, canonical_handle};
    use std::collections::BTreeSet;

    let secrets: Vec<&Entity> = entities
        .iter()
        .filter(|e| Secret::classify(e).is_some())
        .collect();
    if secrets.is_empty() {
        return Vec::new();
    }
    let identities: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Email | EntityKind::Username))
        .collect();
    if identities.len() < 2 {
        return Vec::new();
    }

    let groups = secrets.iter().filter_map(|secret| {
        // The distinct accounts this exact secret's evidence names — mirrors
        // AU-047's own join-key read exactly (an email and/or a username per
        // breach record).
        let emails: BTreeSet<String> = secret
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("email"))
            .map(|v| v.trim().to_lowercase())
            .filter(|v| v.contains('@'))
            .collect();
        let usernames: BTreeSet<String> = secret
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("username"))
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        // Fold to distinct CONTROLLER HANDLES — the same admission gate AU-047
        // uses (≥2 distinct handles, not just ≥2 raw email/username strings, so
        // an email and its matching username from one record can't self-fire).
        let handles: BTreeSet<String> = emails
            .iter()
            .map(|e| e.split('@').next().unwrap_or(e))
            .chain(usernames.iter().map(String::as_str))
            .map(canonical_handle)
            .filter(|h| !h.is_empty())
            .collect();
        if handles.len() < 2 {
            return None;
        }
        let members: Vec<&Entity> = identities
            .iter()
            .copied()
            .filter(|id| {
                let value_lc = id.value.trim().to_lowercase();
                match id.kind {
                    EntityKind::Email => emails.contains(&value_lc),
                    EntityKind::Username => usernames.contains(&value_lc),
                    _ => false,
                }
            })
            .collect();
        (members.len() >= 2).then_some(members)
    });

    super::emit_pairwise(groups, RelationKind::SharesSecretWith, scan_id, |a, b| {
        a.confidence.min(b.confidence)
    })
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

    let person_by_name = super::persons_by_name(entities);
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
    super::sort_edges(&mut out);
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

    let person_by_name = super::persons_by_name(entities);
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
    super::sort_edges(&mut out);
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
    for (surname, group) in &by_surname {
        // A COMMON surname (Smith, Jones, Nguyen, Wang…) is shared by countless
        // unrelated strangers; pairing everyone who happens to carry one would
        // manufacture O(n²) false "associate" edges from a single popular name.
        // Only a DISTINCTIVE surname is itself evidence of likely kinship — mirror
        // the commonness discount the leads/engine paths already apply. (A genuine
        // relative of a common-surname subject still surfaces through the
        // evidence-grounded co-residence / declared-association passes.)
        if crate::util::surnames::is_common(surname) {
            continue;
        }
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
    super::sort_edges(&mut out);
    out
}

/// Confidence damp for a geo-corroborated common-surname family lead — a shared
/// surname AND a shared AU town is meaningful corroboration, but a populous
/// postcode can still hold unrelated namesakes, so it stays a damped candidate
/// lead (just below the distinctive-surname [`KINSHIP_DAMP`]).
const REGIONAL_KINSHIP_DAMP: f64 = 0.45;

/// Derive `AssociatedWith` kinship-candidate edges between same-surname Person
/// entities that [`derive_kinship`] deliberately drops — those sharing a **COMMON**
/// surname — when a shared **Australian town** (identical postcode,
/// [`crate::core::geo_family::au_postcode`]) corroborates the link.
///
/// `derive_kinship` skips common surnames (Smith, Nguyen, Wang…) because pairing
/// every stranger who carries one would manufacture O(n²) false edges — but that
/// silently drops the genuine families of the *majority* of Australians, whose
/// surnames are common. A shared specific postcode is the corroboration that makes
/// the link safe: two `Smith`s in the same town are a real associate lead, where
/// two `Smith`s in different states are not. This is the geo-gated complement that
/// recovers those families without reintroducing the false-positive flood.
///
/// **Strictly additive / disjoint**: it fires *only* for common surnames (exactly
/// the set `derive_kinship` skips) and only on a shared postcode, so it never
/// touches an edge `derive_kinship` emitted. Distinct people only (different UID
/// and folded name); symmetric, canonically directed, deduped, deterministic.
pub fn derive_regional_kinship(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    // Index common-surname Persons that carry an AU postcode, keyed by
    // (surname, postcode) — i.e. same family name AND same town.
    let mut by_town: HashMap<(String, String), Vec<&Entity>> = HashMap::new();
    for p in entities.iter().filter(|e| e.kind == EntityKind::Person) {
        let Some(surname) = surname_key(&p.value) else {
            continue;
        };
        if !crate::util::surnames::is_common(&surname) {
            continue; // distinctive surnames are derive_kinship's job (disjoint)
        }
        let Some(postcode) = crate::core::geo_family::au_postcode(p) else {
            continue; // no AU town anchor → no geo corroboration → skip
        };
        by_town.entry((surname, postcode)).or_default().push(p);
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for group in by_town.values() {
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let (a, b) = (group[i], group[j]);
                if a.uid == b.uid
                    || crate::core::scan::identity_norm(&a.value)
                        == crate::core::scan::identity_norm(&b.value)
                {
                    continue; // same person / two spellings of one name
                }
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                if seen.insert((from.uid.clone(), to.uid.clone())) {
                    out.push(Relation::new(
                        from.uid.as_str(),
                        to.uid.as_str(),
                        RelationKind::AssociatedWith,
                        from.confidence.min(to.confidence) * REGIONAL_KINSHIP_DAMP,
                        scan_id,
                    ));
                }
            }
        }
    }
    super::sort_edges(&mut out);
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

    let person_by_name = super::persons_by_name(entities);
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
    super::sort_edges(&mut out);
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
    let person_by_name = super::persons_by_name(entities);
    if person_by_name.is_empty() {
        return Vec::new();
    }
    // Each specific dwelling's named residents (≥2, capped to a household) is a
    // co-residence group; `emit_pairwise` links the household.
    let groups = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Address && !COARSE_ADDRESS_TAGS.iter().any(|t| e.has_tag(t))
        })
        .filter_map(|place| {
            let mut residents = residents_of(place, &person_by_name);
            (residents.len() >= 2).then(|| {
                residents.truncate(CO_RESIDENCE_MAX_PER_PLACE);
                residents
            })
        });
    super::emit_pairwise(groups, RelationKind::AssociatedWith, scan_id, |a, b| {
        a.confidence.min(b.confidence) * CO_RESIDENCE_DAMP
    })
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
    // Keep only individuating groups (a handful share a real selector; a crowd shares a
    // generic one); `emit_pairwise` handles direction, dedup, and deterministic order.
    let groups = by_value
        .into_values()
        .filter(|members| (2..=crowd_cap).contains(&members.len()));
    super::emit_pairwise(groups, RelationKind::AssociatedWith, scan_id, |a, b| {
        a.confidence.min(b.confidence) * damp
    })
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
