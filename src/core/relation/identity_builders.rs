//! Identity-graph relation builders: the person-centric edges (handle
//! aliases, identifier ownership, residency, kinship, co-residence,
//! co-mention, shared-selector affiliation, canonical identities, and
//! co-reference promotion) that bind a scan's SUBJECT to their
//! identifiers, accounts, places, and associates. The infrastructure-graph
//! builders (subdomains, hosting, DNS, WHOIS) live in the sibling
//! [`super::infra_builders`]; [`super::builders`] orchestrates both into the
//! single deterministic `derive_all` chain.
//!
//! For a person-centric scan the infrastructure graph is mostly empty — the
//! high-value edges here bind the SUBJECT to their identifiers, accounts,
//! places and associates. Without them a 500-entity person scan persists zero
//! relations (nodes, no edges) and the dossier/force-graph shows an
//! unconnected pile. These builders hold to the same rigor as the infra
//! builders: deterministic (stable, deduped, canonically-directed),
//! evidence- or structure-grounded so no false edge fires, and confidence
//! carried from the endpoints — *damped* for the two candidate signals
//! (fingerprint ownership, surname kinship) so a lead never masquerades as a
//! certainty.

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

/// Role / functional mailbox handles — a mailbox named by its FUNCTION, not a
/// person (`admin@`, `info@`, `support@`…). The same word recurs across countless
/// unrelated organisations, so keying a shared-persona alias on it fabricates an
/// identity clique. Entries must be lowercase ASCII alphanumerics to match
/// [`crate::core::scan::identity_norm`] output (so `no-reply` folds to `noreply`);
/// kept alphabetical for readability. Matched by a linear scan (tiny, fixed set),
/// so there is no sortedness invariant to maintain.
const ROLE_HANDLES: &[&str] = &[
    "abuse",
    "admin",
    "billing",
    "contact",
    "hello",
    "help",
    "hostmaster",
    "info",
    "mail",
    "marketing",
    "noreply",
    "office",
    "postmaster",
    "sales",
    "security",
    "support",
    "team",
    "webmaster",
];

/// A reliable persona key for a raw handle or email local-part: the
/// [`crate::core::scan::identity_norm`] fold, but only when it is long enough
/// (≥ 4 = `IDENTITY_OVERLAP_MIN`), not all-digits, and not a role/functional word
/// — the classes that alias too readily and fabricate cliques. `None` otherwise.
fn handle_key(raw: &str) -> Option<String> {
    let key = crate::core::scan::identity_norm(raw);
    if key.len() < 4
        || key.bytes().all(|b| b.is_ascii_digit())
        || ROLE_HANDLES.iter().any(|&r| r == key)
    {
        return None;
    }
    Some(key)
}

/// The persona key an Email/Username aliases on, made **kind-aware for precision**:
///
/// * **Email** → the FULL canonical mailbox
///   ([`crate::core::resolve::canonical_email`]: Gmail dot / `+tag` folding, the
///   domain KEPT). Two emails therefore alias only when they are the *same
///   mailbox* — `john@gmail.com` and `john@acme-corp.com` no longer share a key.
///   A bare local-part is unique only *within* a domain, so the old
///   `identity_norm` local-part key fused every unrelated org's `john@` / `admin@`
///   mailbox into one fabricated identity (the hazard the coref layer was already
///   hardened against, but this builder never received).
/// * **Username** → the [`handle_key`] fold of the whole value (role / short /
///   numeric handles excluded).
///
/// The local-part still bridges an Email to a *Username* that shares the handle —
/// but that cross-KIND link is derived separately in [`derive_handles`], and
/// never email-to-email. `None` for any other kind, or a mailbox that fails to
/// canonicalise.
fn persona_key(e: &Entity) -> Option<String> {
    match e.kind {
        EntityKind::Email => crate::core::resolve::canonical_email(&e.value),
        EntityKind::Username => handle_key(&e.value),
        _ => None,
    }
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
pub(super) fn persons_by_name(entities: &[Entity]) -> std::collections::HashMap<String, &Entity> {
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

/// Derive `AliasOf` edges between Email/Username entities of one persona, in two
/// precision-separated passes:
///
/// 1. **Same key** — entities sharing a [`persona_key`] alias. For Emails the key
///    is the FULL canonical mailbox, so this links only *same-mailbox* spellings
///    (`jo.hn@gmail.com` ↔ `john@googlemail.com`), never two different domains'
///    `john@`. For Usernames it links the same handle across platforms.
/// 2. **Cross-kind handle bridge** — an Email aliases a *Username* when the
///    email's local-part [`handle_key`] equals the username's. This is the ONLY
///    place a local-part drives an alias, and it never links email-to-email, so a
///    common first name (`john@`) or role account (`admin@`) can no longer fuse
///    unrelated mailboxes into a fabricated identity. Two mailboxes that share a
///    genuine personal handle still cluster — transitively, via the username they
///    both bridge to (a star, which the identity-cluster union-find resolves to
///    the same component a direct clique would).
///
/// Purely structural (exact canonical/handle match), so precision is high; short /
/// numeric / role handles are excluded by [`handle_key`]. Symmetric edges are
/// emitted once in canonical direction (smaller UID → larger) and deduped, then
/// sorted — deterministic regardless of entity order.
pub fn derive_handles(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<Relation> = Vec::new();

    // Emit one canonical, deduped AliasOf edge between two distinct identifiers.
    let link =
        |a: &Entity, b: &Entity, out: &mut Vec<Relation>, seen: &mut HashSet<(String, String)>| {
            // Same entity, or two spellings that normalise identically — not an alias
            // between *distinct* identifiers.
            if a.uid == b.uid || a.value == b.value {
                return;
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
        };

    // Pass 1: entities sharing a persona key (same mailbox / same username).
    let mut by_key: HashMap<String, Vec<&Entity>> = HashMap::new();
    for e in entities {
        if let Some(k) = persona_key(e) {
            by_key.entry(k).or_default().push(e);
        }
    }
    for group in by_key.values() {
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                link(group[i], group[j], &mut out, &mut seen);
            }
        }
    }

    // Pass 2: cross-kind handle bridge (Email local-part ↔ Username handle).
    let mut users_by_handle: HashMap<String, Vec<&Entity>> = HashMap::new();
    for u in entities.iter().filter(|e| e.kind == EntityKind::Username) {
        if let Some(k) = handle_key(&u.value) {
            users_by_handle.entry(k).or_default().push(u);
        }
    }
    if !users_by_handle.is_empty() {
        for email in entities.iter().filter(|e| e.kind == EntityKind::Email) {
            let Some(local_part) = email.value.split('@').next() else {
                continue;
            };
            let Some(k) = handle_key(local_part) else {
                continue;
            };
            if let Some(users) = users_by_handle.get(&k) {
                for u in users {
                    link(email, u, &mut out, &mut seen);
                }
            }
        }
    }

    sort_edges(&mut out);
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
/// classification and [`crate::core::entity::canonical_handle`]
/// handle-folding (Rule 4: one classifier/one folder, so the graph edge and
/// the correlation can never disagree on which secrets qualify or which
/// handles are the same account). Emits a full pairwise clique over every
/// identity entity a qualifying secret's evidence names (not just a chain
/// through one arbitrarily-chosen hub), so `identity_paths`' BFS finds the
/// direct edge between ANY two accounts a shared secret ties together.
pub fn derive_reused_secret_link(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use crate::core::correlator::Secret;
    use crate::core::entity::canonical_handle;
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

    emit_pairwise(groups, RelationKind::SharesSecretWith, scan_id, |a, b| {
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
        // Reuse the shared person-at-place resolver (same evidence order, filter,
        // lookup and per-place uid dedup); the global `seen` still handles
        // cross-place dedup and the exact-name fallback below.
        for p in residents_of(place, &person_by_name) {
            if seen.insert((p.uid.clone(), place.uid.clone())) {
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
    sort_edges(&mut out);
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
    let person_by_name = persons_by_name(entities);
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
    emit_pairwise(groups, RelationKind::AssociatedWith, scan_id, |a, b| {
        a.confidence.min(b.confidence) * CO_RESIDENCE_DAMP
    })
}

/// Emit one canonically-directed (`smaller-uid → larger`), deduplicated `kind` edge
/// per distinct pair within each group, the confidence from `conf(from, to)`. The
/// shared "clique → symmetric pairwise edges" core every group-based builder needs
/// (co-residence, co-mention, shared-selector, canonical identities): each assembles
/// the entity groups it judges related — already filtered / capped to its own rules —
/// and this performs the pairing, canonical direction, cross-group dedup, and
/// deterministic final ordering ONCE, instead of every builder re-implementing the
/// same nested loop. Members are sorted by UID, so the edge set is independent of how
/// a caller ordered each group.
fn emit_pairwise<'a>(
    groups: impl IntoIterator<Item = Vec<&'a Entity>>,
    kind: RelationKind,
    scan_id: &str,
    conf: impl Fn(&Entity, &Entity) -> f64,
) -> Vec<Relation> {
    use std::collections::HashSet;

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for mut members in groups {
        members.sort_by(|a, b| a.uid.cmp(&b.uid));
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                let (a, b) = (members[i], members[j]);
                let (from, to) = if a.uid <= b.uid { (a, b) } else { (b, a) };
                if from.uid != to.uid && seen.insert((from.uid.clone(), to.uid.clone())) {
                    out.push(Relation::new(
                        from.uid.as_str(),
                        to.uid.as_str(),
                        kind,
                        conf(from, to),
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
    // Keep only individuating groups (a handful share a real selector; a crowd shares a
    // generic one); `emit_pairwise` handles direction, dedup, and deterministic order.
    let groups = by_value
        .into_values()
        .filter(|members| (2..=crowd_cap).contains(&members.len()));
    emit_pairwise(groups, RelationKind::AssociatedWith, scan_id, |a, b| {
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

/// Derive `SameAs` edges between distinct entities the canonical resolver proves are
/// the SAME real-world identity wearing two contexts — the reflexive self-pairing
/// pivot ([`crate::core::resolve`]).
///
/// The resolver folds provider-specific representations to one canonical form (Gmail
/// dot / `+tag` blindness, phone digit-only, order-insensitive names), so two entities
/// the engine extracted SEPARATELY — `j.ohn+work@gmail.com` and `john@gmail.com`, a
/// phone in national and E.164 form, "Jane Citizen" and "Citizen, Jane" — are revealed
/// as one identity in two contexts. This wires that previously analysis-only signal
/// into the graph: a single seed and every contextual variant of it collapse to one
/// connected node for traversal, so the variant is a valid state-mutating self-pairing,
/// not a new stranger. Strong by construction (the resolver only groups EXACT canonical
/// collisions, never fuzzy guesses), so it carries full endpoint trust rather than a
/// damp. Symmetric, canonically directed (smaller-uid → larger), deduped, deterministic.
pub fn derive_canonical_identities(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashMap;

    let groups = crate::core::resolve::suggest_merges(entities);
    if groups.is_empty() {
        return Vec::new();
    }
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    // Resolve each canonical group's member UIDs back to entities; `emit_pairwise`
    // links every distinct variant pair as the same node.
    let entity_groups = groups.iter().map(|group| {
        group
            .members
            .iter()
            .filter_map(|uid| by_uid.get(uid.as_str()).copied())
            .collect::<Vec<&Entity>>()
    });
    emit_pairwise(entity_groups, RelationKind::SameAs, scan_id, |a, b| {
        a.confidence.min(b.confidence)
    })
}

/// Minimum [`crate::core::coref::resolve_coreferences`] score for a co-reference
/// hypothesis to be **promoted into a graph edge**. Far above the read-only view's
/// emission floor: a reported hypothesis is a lead for an analyst to weigh, but a
/// graph edge is consumed by clustering, network synthesis and the autonomous
/// prioritiser, so only a *strong* same-individual match (an exact-handle match,
/// or several independent corroborating signals) earns one.
const COREF_PROMOTE_MIN_SCORE: f64 = 0.80;

/// Promote strong cross-identifier **co-reference** hypotheses
/// ([`crate::core::coref::resolve_coreferences`]) into typed identity relations,
/// so the same-individual links the scorer finds become first-class graph edges
/// the clustering, network and autonomous layers all consume — not just a
/// read-only view. Each promoted pair maps to the edge that fits its kinds:
///   * **Person ↔ identifier** → [`IdentifiedBy`](RelationKind::IdentifiedBy)
///     (Person → Email/Username/Phone) — the person owns the selector;
///   * **Person ↔ Person** → [`SameAs`](RelationKind::SameAs) — two name records
///     of one individual;
///   * **identifier ↔ identifier** → [`AliasOf`](RelationKind::AliasOf) — two
///     selectors of one persona.
///
/// **Strictly additive**: an edge already present in `existing` (same
/// `from|kind|to`) is never re-emitted, so this pass can only *add* links and can
/// never lower the confidence of an edge a higher-trust builder (handles /
/// identity-ownership / canonical-identities) already produced. Confidence is the
/// match score damped by the weaker endpoint's trust (`score × min(conf)`), so an
/// inferred co-reference edge never outranks a structural one. Deterministic
/// (sorted); deduped per `(from, kind, to)`.
pub fn derive_coreferences(
    entities: &[Entity],
    existing: &[Relation],
    scan_id: &str,
) -> Vec<Relation> {
    use std::collections::HashSet;

    // Index the edges already built this finalise so we only ever ADD, never
    // restate (and so never churn a stronger builder's confidence on upsert).
    let prior: HashSet<(&str, &str, &str)> = existing
        .iter()
        .map(|r| (r.from_uid.as_str(), r.kind.as_str(), r.to_uid.as_str()))
        .collect();
    // UID → confidence, to damp each promoted edge by its weaker endpoint.
    let conf_of: std::collections::HashMap<&str, f64> = entities
        .iter()
        .map(|e| (e.uid.as_str(), e.confidence))
        .collect();
    let kind_of: std::collections::HashMap<&str, EntityKind> = entities
        .iter()
        .map(|e| (e.uid.as_str(), e.kind.clone()))
        .collect();

    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut out = Vec::new();
    for c in crate::core::coref::resolve_coreferences(entities, COREF_PROMOTE_MIN_SCORE, 512) {
        let (Some(ka), Some(kb)) = (kind_of.get(c.uid_a.as_str()), kind_of.get(c.uid_b.as_str()))
        else {
            continue;
        };
        let a_person = *ka == EntityKind::Person;
        let b_person = *kb == EntityKind::Person;
        // Choose the typed edge and its canonical direction for the pair's kinds.
        let (from, to, kind) = match (a_person, b_person) {
            // Person → identifier (the person owns the selector).
            (true, false) => (&c.uid_a, &c.uid_b, RelationKind::IdentifiedBy),
            (false, true) => (&c.uid_b, &c.uid_a, RelationKind::IdentifiedBy),
            // Two persons: one individual, two name records. Smaller-UID → larger.
            (true, true) => (&c.uid_a, &c.uid_b, RelationKind::SameAs),
            // Two identifiers: aliases of one persona. Smaller-UID → larger.
            (false, false) => (&c.uid_a, &c.uid_b, RelationKind::AliasOf),
        };
        if prior.contains(&(from.as_str(), kind.as_str(), to.as_str())) {
            continue; // a higher-trust builder already emitted this exact edge
        }
        if !seen.insert((from.clone(), kind.as_str().to_string(), to.clone())) {
            continue;
        }
        let min_conf = conf_of
            .get(from.as_str())
            .copied()
            .unwrap_or(0.0)
            .min(conf_of.get(to.as_str()).copied().unwrap_or(0.0));
        out.push(Relation::new(
            from.as_str(),
            to.as_str(),
            kind,
            c.score * min_conf,
            scan_id,
        ));
    }
    sort_edges(&mut out);
    out
}
