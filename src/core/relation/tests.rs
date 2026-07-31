use super::*;

#[test]
fn relation_kind_as_str_matches_serde() {
    // No-silent-drift: the type owns its canonical string and
    // this pins it to the serde wire form so the two can't split. as_str is the
    // stored `relations.kind` column AND the API/SPA edge label; the serde derive
    // is what crosses the wire — a rename touching only one would silently fork
    // the DB form from the JSON form.
    //
    // `EVERY` is walked by an arm-less `match` (no `_`): adding a RelationKind
    // variant fails to compile here until it is listed — the compile-forced guard
    // the previous HARDCODED array lacked, which silently omitted `SharesSecretWith`
    // (14 of 15 variants), leaving its tag unpinned. The loop proves, for every
    // variant, that as_str == the serde tag == Display, and that the tag
    // deserialises back to the same variant (the DB/API read path).
    const EVERY: &[RelationKind] = &[
        RelationKind::SubdomainOf,
        RelationKind::BelongsToDomain,
        RelationKind::HostedOn,
        RelationKind::ResolvesTo,
        RelationKind::RegisteredBy,
        RelationKind::CoLocatedWith,
        RelationKind::DerivedFrom,
        RelationKind::IdentifiedBy,
        RelationKind::AliasOf,
        RelationKind::LocatedAt,
        RelationKind::AssociatedWith,
        RelationKind::SameAs,
        RelationKind::SameOperator,
        RelationKind::SameIdentity,
        RelationKind::SharesSecretWith,
    ];
    for &k in EVERY {
        // Compile-time tripwire: NO `_` arm.
        match k {
            RelationKind::SubdomainOf
            | RelationKind::BelongsToDomain
            | RelationKind::HostedOn
            | RelationKind::ResolvesTo
            | RelationKind::RegisteredBy
            | RelationKind::CoLocatedWith
            | RelationKind::DerivedFrom
            | RelationKind::IdentifiedBy
            | RelationKind::AliasOf
            | RelationKind::LocatedAt
            | RelationKind::AssociatedWith
            | RelationKind::SameAs
            | RelationKind::SameOperator
            | RelationKind::SameIdentity
            | RelationKind::SharesSecretWith => {}
        }
        let json = serde_json::to_string(&k).expect("should succeed");
        let tag = json.trim_matches('"');
        assert_eq!(tag, k.as_str(), "as_str vs serde: {k:?}");
        assert_eq!(k.to_string(), k.as_str(), "Display vs as_str: {k:?}");
        let back: RelationKind = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(back, k, "serde round-trip: {k:?}");
    }
    assert_eq!(EVERY.len(), 15, "one entry per RelationKind variant");
}
use crate::core::entity::{Entity, EntityKind};

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "rel-scan")
}

#[test]
fn name_lineage_links_derived_handles_to_the_subject_person() {
    use crate::core::entity::Evidence;
    let person = ent(EntityKind::Person, "Jane Smith", 0.6);

    // Two name-derived handles carrying the subject as `source_name`.
    let mut uname = ent(EntityKind::Username, "jsmith", 0.38);
    uname.tag("name-derived");
    uname.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "Jane Smith"),
    );
    let mut email = ent(EntityKind::Email, "jane.smith@gmail.com", 0.30);
    email.tag("name-derived");
    email.add_evidence(
        Evidence::new("name_intel", "permuted").with_attr("source_name", "jane smith"), // case-insensitive
    );

    // An unrelated handle: not name-derived → must NOT link.
    let other = ent(EntityKind::Username, "unrelated", 0.5);

    let ents = vec![person.clone(), uname.clone(), email.clone(), other];
    let rels = derive_name_lineage(&ents, "s");

    assert_eq!(
        rels.len(),
        2,
        "both name-derived handles link, the orphan does not"
    );
    for r in &rels {
        assert_eq!(r.kind, RelationKind::DerivedFrom);
        assert_eq!(r.to_uid, person.uid, "edge points at the subject Person");
    }
    assert!(rels.iter().any(|r| r.from_uid == uname.uid));
    assert!(rels.iter().any(|r| r.from_uid == email.uid));

    // No Person present → no edges (and no panic).
    assert!(derive_name_lineage(&[uname, email], "s").is_empty());
}

#[test]
fn co_residence_links_different_surname_household_at_a_specific_address() {
    use crate::core::entity::Evidence;

    // Two separate register records at ONE specific address name two
    // DIFFERENT-surname people — the household the surname kinship can't link.
    let mut addr = ent(
        EntityKind::Address,
        "12 Rose Street, Brisbane QLD 4000",
        0.6,
    );
    addr.add_evidence(Evidence::new("qld_unclaimed", "rec1").with_attr("owner", "Jane Citizen"));
    addr.add_evidence(Evidence::new("qld_unclaimed", "rec2").with_attr("owner", "Mark Roe"));
    let jane = ent(EntityKind::Person, "Jane Citizen", 0.7);
    let mark = ent(EntityKind::Person, "Mark Roe", 0.6);

    let ents = vec![addr, jane.clone(), mark.clone()];
    let edges = derive_co_residence(&ents, "s");
    assert_eq!(
        edges.len(),
        1,
        "one household edge between the two co-residents"
    );
    let e = &edges[0];
    assert_eq!(e.kind, RelationKind::AssociatedWith);
    assert!(
        (e.from_uid == jane.uid && e.to_uid == mark.uid)
            || (e.from_uid == mark.uid && e.to_uid == jane.uid),
        "links the two co-residents"
    );
    // Evidence-grounded co-residence sits between a surname guess (×0.5) and a
    // declared link (×1.0); the surname kinship can't see it (different surnames).
    let min_conf = 0.6; // min(jane 0.7, mark 0.6)
    assert!(
        e.confidence > min_conf * 0.5 && e.confidence < min_conf,
        "confidence {} is evidence-grounded but damped",
        e.confidence
    );
    assert!(derive_kinship(&ents, "s").is_empty());

    // A COARSE postcode/suburb is never a household, even with two named owners.
    let mut coarse = ent(EntityKind::Address, "QLD 4000, Australia", 0.4);
    coarse.tag("postcode-only");
    coarse.add_evidence(Evidence::new("qld_unclaimed", "a").with_attr("owner", "Jane Citizen"));
    coarse.add_evidence(Evidence::new("qld_unclaimed", "b").with_attr("owner", "Mark Roe"));
    assert!(
        derive_co_residence(&[coarse, jane.clone(), mark.clone()], "s").is_empty(),
        "a postcode centroid is not a dwelling"
    );

    // A single resident is no household, and a same-surname co-resident gets BOTH
    // this edge and the kinship one (two angles agreeing on the same pair).
    let solo = {
        let mut a = ent(EntityKind::Address, "9 Lone Way, Cairns QLD 4870", 0.6);
        a.add_evidence(Evidence::new("qld_unclaimed", "r").with_attr("owner", "Jane Citizen"));
        a
    };
    assert!(
        derive_co_residence(&[solo, jane], "s").is_empty(),
        "one name is not a household"
    );
}

/// A Person carrying a `url` source attribute, the join key for co-mention.
fn person_in_source(name: &str, conf: f64, url: &str) -> Entity {
    use crate::core::entity::Evidence;
    let mut e = ent(EntityKind::Person, name, conf);
    e.add_evidence(Evidence::new("search_engines", "result").with_attr("url", url));
    e
}

#[test]
fn co_mention_links_two_people_named_in_the_same_source() {
    // The reverse-engineered Kyle/Erik case: a single source names both, and the
    // engine extracted each separately — co-mention recovers the shared-source tie.
    let kyle = person_in_source("Kyle Diegmann", 0.6, "https://example.com/obituary");
    let erik = person_in_source("Erik Diegmann", 0.5, "https://example.com/obituary");
    let edges = derive_co_mention(&[kyle.clone(), erik.clone()], "s");
    assert_eq!(edges.len(), 1, "one co-mention edge between the two");
    let e = &edges[0];
    assert_eq!(e.kind, RelationKind::AssociatedWith);
    let mut got = [e.from_uid.clone(), e.to_uid.clone()];
    got.sort();
    let mut want = [kyle.uid.clone(), erik.uid.clone()];
    want.sort();
    assert_eq!(got, want, "endpoints are the two co-mentioned persons");
    // Damped: min(0.6, 0.5) × CO_MENTION_DAMP (0.45).
    assert!((e.confidence - 0.5 * 0.45).abs() < 1e-9);
}

#[test]
fn co_mention_ignores_people_in_different_sources() {
    let kyle = person_in_source("Kyle Diegmann", 0.6, "https://a.example/x");
    let erik = person_in_source("Erik Diegmann", 0.5, "https://b.example/y");
    assert!(
        derive_co_mention(&[kyle, erik], "s").is_empty(),
        "no shared source ⇒ no co-mention"
    );
}

#[test]
fn co_mention_skips_crowded_list_sources() {
    // Six people (one more than the cap of 5) ⇒ a directory / round-up, not a
    // relationship document.
    let url = "https://example.com/directory";
    let ents: Vec<Entity> = (0..6)
        .map(|i| person_in_source(&format!("Person Number{i:02}"), 0.6, url))
        .collect();
    assert!(
        derive_co_mention(&ents, "s").is_empty(),
        "a crowded source mints no edges"
    );
}

#[test]
fn co_mention_pairs_a_small_group_deterministically() {
    let url = "https://example.com/family-notice";
    let ents = vec![
        person_in_source("Aaron Diegmann", 0.6, url),
        person_in_source("Beth Diegmann", 0.6, url),
        person_in_source("Carl Diegmann", 0.6, url),
    ];
    let e1 = derive_co_mention(&ents, "s");
    assert_eq!(e1.len(), 3, "three people in one source → C(3,2) = 3 edges");
    // Deterministic under input reordering.
    let mut shuffled = ents.clone();
    shuffled.reverse();
    let e2 = derive_co_mention(&shuffled, "s");
    let ids1: Vec<&str> = e1.iter().map(|r| r.id.as_str()).collect();
    let ids2: Vec<&str> = e2.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids1, ids2, "edge set is independent of input order");
}

/// An entity carrying one distinctive selector attribute, the join key for affiliation.
fn entity_with_attr(
    kind: EntityKind,
    value: &str,
    conf: f64,
    attr: &str,
    attr_val: &str,
) -> Entity {
    use crate::core::entity::Evidence;
    let mut e = ent(kind, value, conf);
    e.add_evidence(Evidence::new("whois", "rec").with_attr(attr, attr_val));
    e
}

#[test]
fn shared_selector_links_domains_by_shared_registrant() {
    // The synthetic corporate → hidden-subsidiary archetype: two domains the engine
    // found separately, tied by one registrant email already sitting in their evidence.
    let a = entity_with_attr(
        EntityKind::Domain,
        "company-a.com",
        0.7,
        "registrant_email",
        "admin@holdco.com",
    );
    let b = entity_with_attr(
        EntityKind::Domain,
        "company-b.com",
        0.6,
        "registrant_email",
        "admin@holdco.com",
    );
    let edges = derive_shared_selector(&[a, b], "s");
    assert_eq!(edges.len(), 1, "shared registrant ⇒ one affiliation edge");
    assert_eq!(edges[0].kind, RelationKind::AssociatedWith);
    // Damped: min(0.7, 0.6) × AFFILIATION_DAMP (0.45).
    assert!((edges[0].confidence - 0.6 * 0.45).abs() < 1e-9);
}

#[test]
fn shared_selector_links_any_kind_by_fingerprint() {
    // A shared TLS cert serial ⇒ same operator, regardless of entity kind — the
    // capability is domain-agnostic, not bound to one subject type.
    let h1 = entity_with_attr(
        EntityKind::Domain,
        "h1.example",
        0.6,
        "cert_serial",
        "0af3:21:bc",
    );
    let h2 = entity_with_attr(
        EntityKind::IpAddress,
        "203.0.113.9",
        0.6,
        "cert_serial",
        "0af3:21:bc",
    );
    assert_eq!(derive_shared_selector(&[h1, h2], "s").len(), 1);
}

#[test]
fn shared_selector_ignores_generic_non_allowlisted_attributes() {
    // A shared REGISTRAR (GoDaddy) is not individuating and is not in the curated
    // selector set — so it links nothing. This is the anti-overfitting guard.
    let a = entity_with_attr(EntityKind::Domain, "x.com", 0.7, "registrar", "GoDaddy");
    let b = entity_with_attr(EntityKind::Domain, "y.com", 0.6, "registrar", "GoDaddy");
    assert!(
        derive_shared_selector(&[a, b], "s").is_empty(),
        "a shared registrar is not affiliation"
    );
}

#[test]
fn shared_selector_skips_crowded_privacy_proxy_values() {
    // A registrant org shared by a crowd (a privacy proxy) is not an owner.
    let org = "Privacy Protect LLC";
    let ents: Vec<Entity> = (0..7)
        .map(|i| {
            entity_with_attr(
                EntityKind::Domain,
                &format!("d{i:02}.example"),
                0.6,
                "registrant_org",
                org,
            )
        })
        .collect();
    assert!(
        derive_shared_selector(&ents, "s").is_empty(),
        "a crowd-shared registrant proxy mints no edges"
    );
}

#[test]
fn shared_selector_no_edge_for_distinct_values() {
    let a = entity_with_attr(
        EntityKind::Domain,
        "a.com",
        0.7,
        "registrant_email",
        "a@a.com",
    );
    let b = entity_with_attr(
        EntityKind::Domain,
        "b.com",
        0.6,
        "registrant_email",
        "b@b.com",
    );
    assert!(derive_shared_selector(&[a, b], "s").is_empty());
}

#[test]
fn canonical_identities_links_gmail_variants_as_same() {
    // Reflexive self-pairing: the engine extracted two contextual forms of ONE
    // address; the canonical resolver proves they are the same identity.
    let a = ent(EntityKind::Email, "j.ohn+work@gmail.com", 0.6);
    let b = ent(EntityKind::Email, "john@gmail.com", 0.5);
    let edges = derive_canonical_identities(&[a.clone(), b.clone()], "s");
    assert_eq!(edges.len(), 1, "two Gmail variants are one identity");
    assert_eq!(edges[0].kind, RelationKind::SameAs);
    let mut got = [edges[0].from_uid.clone(), edges[0].to_uid.clone()];
    got.sort();
    let mut want = [a.uid.clone(), b.uid.clone()];
    want.sort();
    assert_eq!(got, want, "the edge joins the two variants");
    // Strong by construction — full endpoint trust, no damp: min(0.6, 0.5).
    assert!((edges[0].confidence - 0.5).abs() < 1e-9);
}

#[test]
fn canonical_identities_links_reordered_person_names() {
    let a = ent(EntityKind::Person, "Jane Citizen", 0.6);
    let b = ent(EntityKind::Person, "Citizen, Jane", 0.6);
    let edges = derive_canonical_identities(&[a, b], "s");
    assert_eq!(edges.len(), 1, "a name and its reordering are one person");
    assert_eq!(edges[0].kind, RelationKind::SameAs);
}

#[test]
fn canonical_identities_ignores_genuinely_distinct_entities() {
    let a = ent(EntityKind::Email, "alice@gmail.com", 0.6);
    let b = ent(EntityKind::Email, "bob@gmail.com", 0.6);
    assert!(
        derive_canonical_identities(&[a, b], "s").is_empty(),
        "distinct addresses are not the same identity"
    );
}

#[test]
fn derive_all_aggregates_every_structural_derivation() {
    use crate::core::entity::Evidence;
    // A mixed set exercising two independent derivations: a subdomain edge
    // (structural) and a name-lineage edge. `derive_all` must surface both,
    // and exactly the union of the individual passes — so the import paths
    // and the live scan can't diverge on which edges a finished scan carries.
    let parent = ent(EntityKind::Domain, "acme.com", 0.7);
    let sub = ent(EntityKind::Domain, "mail.acme.com", 0.6);
    let person = ent(EntityKind::Person, "Jane Smith", 0.6);
    let mut handle = ent(EntityKind::Username, "jsmith", 0.38);
    handle.tag("name-derived");
    handle.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "Jane Smith"),
    );

    let ents = vec![parent, sub, person, handle];
    let all = derive_all(&ents, "s");
    // Rebuild the expected count exactly as derive_all does internally:
    // base passes first, co-ownership over those, then profile links, then identity passes.
    let mut base = derive_structural(&ents, "s");
    base.extend(derive_colocation(&ents, "s"));
    base.extend(derive_resolution(&ents, "s"));
    base.extend(derive_registration(&ents, "s"));
    base.extend(derive_name_lineage(&ents, "s"));
    let expected = base.len()
        + derive_co_ownership(&ents, &base, "s").len()
        + derive_profile_links(&ents, "s").len()
        + derive_handles(&ents, "s").len()
        + derive_identity_ownership(&ents, "s").len()
        + derive_residency(&ents, "s").len()
        + derive_kinship(&ents, "s").len()
        + derive_regional_kinship(&ents, "s").len()
        + derive_co_residence(&ents, "s").len()
        + derive_co_mention(&ents, "s").len()
        + derive_shared_selector(&ents, "s").len()
        + derive_canonical_identities(&ents, "s").len()
        + derive_declared_associations(&ents, "s").len();
    assert_eq!(all.len(), expected, "derive_all is the union of every pass");
    assert!(all.iter().any(|r| r.kind == RelationKind::SubdomainOf));
    assert!(all.iter().any(|r| r.kind == RelationKind::DerivedFrom));
    // The handle's `source_name` evidence names the subject, so the identity
    // layer also binds it (Person → handle) — the union must include that pass.
    assert!(all.iter().any(|r| r.kind == RelationKind::IdentifiedBy));

    // No entities → no edges, no panic.
    assert!(derive_all(&[], "s").is_empty());
}

#[test]
fn derive_reused_secret_link_ties_two_accounts_sharing_a_salted_hash() {
    use crate::core::entity::Evidence;
    // The graph-native counterpart of AU-047: a salted hash carried against two
    // distinct emails must produce a walkable SharesSecretWith edge between
    // them, mirroring the correlator's own fixture exactly (delegates to the
    // same `Secret::classify`).
    let mut cred = Entity::new(
        EntityKind::Credential,
        "$2a$10$id3HAw6TcOjKvPH/RK7MS.abcdef",
        0.6,
        "s",
    );
    cred.add_evidence(
        Evidence::new("import:dossier", "breach entry").with_attr("email", "burner1@proton.me"),
    );
    cred.add_evidence(
        Evidence::new("import:dossier", "breach entry").with_attr("email", "real.name@gmail.com"),
    );
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "s");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "s");

    let rels = derive_reused_secret_link(&[cred, a.clone(), b.clone()], "s");
    assert_eq!(
        rels.len(),
        1,
        "a shared salted hash must tie the two accounts"
    );
    assert_eq!(rels[0].kind, RelationKind::SharesSecretWith);
    let (lo, hi) = if a.uid <= b.uid {
        (&a.uid, &b.uid)
    } else {
        (&b.uid, &a.uid)
    };
    assert_eq!(&rels[0].from_uid, lo);
    assert_eq!(&rels[0].to_uid, hi);
}

#[test]
fn derive_reused_secret_link_precision_gate_matches_au047_exactly() {
    use crate::core::entity::Evidence;
    // An UNSALTED digest must NOT link — it could be a common password shared
    // by unrelated people. Same `Secret::classify` admission gate AU-047
    // fires on, so the two must never disagree.
    let mut cred = Entity::new(
        EntityKind::Credential,
        "00346d91dd87c74089f3bfa88e13de8101000000dcb6",
        0.6,
        "s",
    );
    cred.add_evidence(
        Evidence::new("import:dossier", "breach entry").with_attr("email", "burner1@proton.me"),
    );
    cred.add_evidence(
        Evidence::new("import:dossier", "breach entry").with_attr("email", "real.name@gmail.com"),
    );
    let a = Entity::new(EntityKind::Email, "burner1@proton.me", 0.6, "s");
    let b = Entity::new(EntityKind::Email, "real.name@gmail.com", 0.6, "s");
    assert!(
        derive_reused_secret_link(&[cred, a, b], "s").is_empty(),
        "an unsalted digest must not manufacture a shared-secret edge"
    );
}

#[test]
fn derive_reused_secret_link_emits_the_full_pairwise_clique() {
    use crate::core::entity::Evidence;
    // Three accounts sharing ONE secret must produce a full 3-clique (every
    // pair directly linked), so identity_paths' BFS finds the direct edge
    // between ANY two of them, not just a chain through one hub.
    let mut cred = Entity::new(EntityKind::ApiKey, "sk-live-abcdef0123456789", 0.6, "s");
    for em in ["a@x.com", "b@x.com", "c@x.com"] {
        cred.add_evidence(Evidence::new("import:dossier", "breach entry").with_attr("email", em));
    }
    let a = Entity::new(EntityKind::Email, "a@x.com", 0.6, "s");
    let b = Entity::new(EntityKind::Email, "b@x.com", 0.6, "s");
    let c = Entity::new(EntityKind::Email, "c@x.com", 0.6, "s");

    let rels = derive_reused_secret_link(&[cred, a, b, c], "s");
    assert_eq!(
        rels.len(),
        3,
        "3 accounts must yield a full 3-clique (3 pairs)"
    );
    assert!(
        rels.iter()
            .all(|r| r.kind == RelationKind::SharesSecretWith)
    );
}

#[test]
fn derive_all_within_budget_stops_starting_new_passes_past_the_deadline() {
    use std::time::{Duration, Instant};
    // Same mixed set as the aggregation test: a subdomain edge (structural,
    // FIRST pass) plus identity edges from later passes. The budget must cut
    // the chain AFTER a completed pass, never mid-pass, so the result is always
    // a coherent prefix of the full edge set.
    let parent = ent(EntityKind::Domain, "acme.com", 0.7);
    let sub = ent(EntityKind::Domain, "mail.acme.com", 0.6);
    let person = ent(EntityKind::Person, "Jane Smith", 0.6);
    let mut handle = ent(EntityKind::Username, "jsmith", 0.38);
    handle.tag("name-derived");
    handle.add_evidence(
        crate::core::entity::Evidence::new("name_intel", "derived")
            .with_attr("source_name", "Jane Smith"),
    );
    let ents = vec![parent, sub, person, handle];

    // `None` is exactly `derive_all` — the wrapper adds no edges and drops none.
    assert_eq!(
        derive_all_within(&ents, "s", None).len(),
        derive_all(&ents, "s").len(),
        "unbudgeted derive_all_within is identical to derive_all"
    );

    // A far-future deadline never trips: full union, same as `None`.
    let future = Some(Instant::now() + Duration::from_secs(3600));
    assert_eq!(
        derive_all_within(&ents, "s", future).len(),
        derive_all(&ents, "s").len(),
        "a deadline that can't be reached runs the whole chain"
    );

    // A deadline of `now` is already spent by the time the first pass finishes,
    // so derivation returns exactly the FIRST pass (structural) and skips the
    // rest — the structural subdomain edge survives, the later identity edges
    // do not. This is the SIGKILL-avoidance guarantee: a pathological graph
    // still finalises a coherent partial relation set instead of nothing.
    let now = Some(Instant::now());
    let partial = derive_all_within(&ents, "s", now);
    let structural = derive_structural(&ents, "s");
    assert_eq!(
        partial.len(),
        structural.len(),
        "a spent budget returns exactly the first (structural) pass"
    );
    assert!(
        partial.iter().any(|r| r.kind == RelationKind::SubdomainOf),
        "the structural subdomain edge is in the partial set"
    );
    assert!(
        !partial.iter().any(|r| r.kind == RelationKind::IdentifiedBy),
        "a later-pass identity edge is dropped once the budget is spent"
    );
    // The budget can only ever SHRINK the result, never grow it.
    assert!(partial.len() <= derive_all(&ents, "s").len());

    // The shipped budget is a positive, finite duration (sanity on the const).
    assert!(DERIVE_BUDGET >= Duration::from_secs(1));
}

#[test]
fn person_scan_entities_anchor_a_relation_graph() {
    // Regression guard for the live-bundle "relations: 0" symptom. The diagnosis
    // was that the empty graph reflected an infrastructure-dominated, name-attr-poor
    // entity set — NOT a broken builder. This locks that distinction: realistic
    // person-scan shapes MUST anchor a graph (so a refactor that silently zeroes the
    // derivers is caught), while genuinely unlinkable orphans MUST NOT fabricate
    // identity edges (so the graph never invents a relationship from nothing).
    use crate::core::entity::Evidence;
    let subj_uid_in = |edges: &[Relation], uid: &str, k: RelationKind| {
        edges
            .iter()
            .any(|r| r.kind == k && (r.from_uid == uid || r.to_uid == uid))
    };

    // A — FullName-seeded scan: the subject Person (tagged as name_intel tags it)
    // plus two name-derived identifiers carrying `source_name`. The subject must be
    // bound to BOTH identifiers (IdentifiedBy), so the dossier is a graph, not a
    // pile of orphan handles.
    let mut subj = ent(EntityKind::Person, "Haigen Bamford", 0.55);
    subj.tag("seed");
    subj.tag("subject");
    let mut handle = ent(EntityKind::Username, "haigenb", 0.4);
    handle.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "Haigen Bamford"),
    );
    let mut mail = ent(EntityKind::Email, "haigenb@gmail.com", 0.45);
    mail.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "Haigen Bamford"),
    );
    let a = derive_all(&[subj.clone(), handle.clone(), mail.clone()], "s");
    assert!(
        subj_uid_in(&a, &subj.uid, RelationKind::IdentifiedBy),
        "a tagged subject with name-attributed identifiers must anchor IdentifiedBy edges"
    );
    assert!(
        a.iter()
            .filter(|r| r.kind == RelationKind::IdentifiedBy)
            .count()
            >= 2,
        "the subject must bind to both of its identifiers"
    );

    // B — Email-seeded scan: no subject Person, but the subject email's breach
    // record names a present Person (`name` attr). The evidence-grounded ownership
    // path must still resolve the email to that identity — the core deliverable of
    // an email OSINT scan ("whose address is this?").
    let mut semail = ent(EntityKind::Email, "haigen@example.com", 0.9);
    semail.tag("seed");
    semail.tag("subject");
    semail.add_evidence(Evidence::new("hibp", "breach").with_attr("name", "Haigen Bamford"));
    let person = ent(EntityKind::Person, "Haigen Bamford", 0.5);
    let b = derive_all(&[semail.clone(), person], "s");
    assert!(
        subj_uid_in(&b, &semail.uid, RelationKind::IdentifiedBy),
        "an email whose breach record names a present Person must resolve to that identity"
    );

    // C — Orphan identifiers with NO person-name evidence and no subject Person:
    // the graph must NOT invent an IdentifiedBy edge from nothing (precision).
    let e1 = ent(EntityKind::Email, "randomx@gmail.com", 0.6);
    let p1 = ent(EntityKind::Phone, "+61400111222", 0.5);
    let c = derive_all(&[e1, p1], "s");
    assert!(
        !c.iter().any(|r| r.kind == RelationKind::IdentifiedBy),
        "orphan identifiers with no name signal must not fabricate identity edges"
    );
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
fn url_host_matches_domain_exactly_like_entity_normalisation() {
    // domain_key must be the SAME normalisation Domain entities get —
    // including the fixed-point `www.` strip. A hand-rolled single strip
    // left `www.www.example.com` unmatched against `example.com`.
    let entities = vec![
        ent(EntityKind::Url, "https://www.www.example.com/x", 0.6),
        ent(EntityKind::Domain, "example.com", 0.9),
    ];
    let hosted: Vec<_> = derive_structural(&entities, "s")
        .into_iter()
        .filter(|r| r.kind == RelationKind::HostedOn)
        .collect();
    assert_eq!(hosted.len(), 1, "stacked www. labels must still match");
}

#[test]
fn name_lineage_collision_is_deterministic_under_entity_order() {
    use crate::core::entity::Evidence;
    // Person values are not case-folded at normalisation, so two distinct
    // Person entities can share one folded lookup key. The edge target must
    // not depend on input order: highest confidence wins, ties by uid.
    let strong = ent(EntityKind::Person, "Jane Smith", 0.8);
    let weak = ent(EntityKind::Person, "jane smith", 0.4);
    let mut handle = ent(EntityKind::Username, "jsmith", 0.38);
    handle.tag("name-derived");
    handle.add_evidence(
        Evidence::new("name_intel", "derived").with_attr("source_name", "JANE SMITH"),
    );

    let fwd = vec![strong.clone(), weak.clone(), handle.clone()];
    let rev = vec![weak.clone(), strong.clone(), handle.clone()];
    let r1 = derive_name_lineage(&fwd, "s");
    let r2 = derive_name_lineage(&rev, "s");
    assert_eq!(r1.len(), 1);
    assert_eq!(r2.len(), 1);
    assert_eq!(
        r1[0].to_uid, strong.uid,
        "the higher-confidence Person must win the collision"
    );
    assert_eq!(
        r1[0].to_uid, r2[0].to_uid,
        "edge target must be identical regardless of entity order"
    );
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
        Evidence::new("dns_intel", "A record for example.com").with_attr("domain", "example.com"),
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

#[test]
fn registration_links_domain_to_registrant_person() {
    use crate::core::entity::Evidence;
    // whois folds the registrant NAME into the domain evidence and emits the
    // registrant as a Person entity — the human registrant must be linked to the
    // domain (RegisteredBy), not left an orphan. No org/email here, so this also
    // covers the early-return guard now admitting a Person-only registrant.
    let mut dom = Entity::new(EntityKind::Domain, "example.com", 0.92, "rel-scan");
    dom.add_evidence(
        Evidence::new("whois", "WHOIS for example.com")
            .with_attr("registrant_name", "Jordan Avery")
            .with_attr("registrar", "MarkMonitor Inc."),
    );
    let person = ent(EntityKind::Person, "Jordan Avery", 0.72);
    let rels = derive_registration(&[dom.clone(), person.clone()], "s");
    assert_eq!(rels.len(), 1, "domain -> registrant person");
    assert_eq!(rels[0].kind, RelationKind::RegisteredBy);
    assert_eq!(rels[0].from_uid, dom.uid, "edge originates at the domain");
    assert_eq!(
        rels[0].to_uid, person.uid,
        "edge targets the registrant person"
    );
}

// ── Identity relations ───────────────────────────────────────────────────────

#[test]
fn handles_alias_shared_persona_across_platforms() {
    // One persona ("jsmith") across two mailboxes and a username → a 3-clique of
    // AliasOf edges. A different persona and a numeric handle stay unlinked.
    let g1 = ent(EntityKind::Email, "jsmith@gmail.com", 0.7);
    let o1 = ent(EntityKind::Email, "jsmith@outlook.com", 0.6);
    let u1 = ent(EntityKind::Username, "jsmith", 0.5);
    let other = ent(EntityKind::Email, "bobjones@gmail.com", 0.8);
    let numeric = ent(EntityKind::Username, "12345", 0.9); // excluded by persona_key

    let rels = derive_handles(&[g1.clone(), o1.clone(), u1.clone(), other, numeric], "s");
    assert_eq!(rels.len(), 3, "C(3,2) alias edges for the one persona");
    for r in &rels {
        assert_eq!(r.kind, RelationKind::AliasOf);
        assert!(
            r.from_uid <= r.to_uid,
            "canonical direction (smaller uid first)"
        );
    }
    // Idempotent + deterministic: re-deriving yields the same id set & order.
    let again = derive_handles(&[g1, o1, u1], "s");
    let ids: Vec<&str> = rels.iter().map(|r| r.id.as_str()).collect();
    let ids2: Vec<&str> = again.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ids2);
}

#[test]
fn identity_ownership_evidence_then_fingerprint() {
    use crate::core::entity::Evidence;
    // Subject Person (seed-anchor tagged) + an evidence-named mailbox + a
    // fingerprint-only handle + an unrelated handle that must NOT bind.
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.9);
    subject.tag("subject");

    // Evidence path: owner attribute names the subject → full-confidence edge.
    let mut owned = ent(EntityKind::Email, "k.d@acme.com", 0.6);
    owned.add_evidence(Evidence::new("breach", "dump").with_attr("owner", "Kyle Diegmann"));

    // Fingerprint path: identity overlap with the subject, no evidence → damped.
    let fp = ent(EntityKind::Username, "kdiegmann", 0.5);

    // Unrelated handle: no evidence, no fingerprint overlap → no edge.
    let unrelated = ent(EntityKind::Username, "zztopfan", 0.5);

    let rels = derive_identity_ownership(
        &[subject.clone(), owned.clone(), fp.clone(), unrelated],
        "s",
    );
    assert_eq!(
        rels.len(),
        2,
        "the named mailbox and the fingerprinted handle"
    );
    for r in &rels {
        assert_eq!(r.kind, RelationKind::IdentifiedBy);
        assert_eq!(
            r.from_uid, subject.uid,
            "Person is the `from` (owner) endpoint"
        );
    }
    let owned_edge = rels
        .iter()
        .find(|r| r.to_uid == owned.uid)
        .expect("should succeed");
    let fp_edge = rels
        .iter()
        .find(|r| r.to_uid == fp.uid)
        .expect("should succeed");
    // Evidence edge carries full endpoint trust; fingerprint edge is damped.
    assert!((owned_edge.confidence - 0.6_f64.min(0.9)).abs() < 1e-9);
    assert!(
        fp_edge.confidence < 0.5_f64.min(0.9),
        "fingerprint ownership is a damped candidate"
    );
}

#[test]
fn identity_ownership_fingerprint_only_binds_the_subject() {
    // A NON-subject Person must not accrete a handle by fingerprint alone — only
    // the seed-anchored subject does, so an incidental namesake stays unlinked.
    let nonsubject = ent(EntityKind::Person, "Kyle Diegmann", 0.9); // no `subject` tag
    let handle = ent(EntityKind::Username, "kdiegmann", 0.5);
    assert!(
        derive_identity_ownership(&[nonsubject, handle], "s").is_empty(),
        "fingerprint ownership requires the subject tag"
    );
}

#[test]
fn coreference_promotion_emits_typed_identity_edges() {
    // A username, a matching email, and the person's name — all canonicalising to
    // "johnsmith". Co-reference promotion must wire them with the edge that fits
    // each pair's kinds: AliasOf (identifier↔identifier), IdentifiedBy (person→id).
    let user = ent(EntityKind::Username, "johnsmith", 0.8);
    let email = ent(EntityKind::Email, "johnsmith@gmail.com", 0.8);
    let person = ent(EntityKind::Person, "John Smith", 0.8);

    let rels = derive_coreferences(&[user.clone(), email.clone(), person.clone()], &[], "s");
    assert!(
        !rels.is_empty(),
        "strong co-references must promote to edges"
    );

    // Username↔Email → AliasOf, canonical direction.
    let alias = rels
        .iter()
        .find(|r| r.kind == RelationKind::AliasOf)
        .expect("the two identifiers alias one persona");
    assert!(alias.from_uid <= alias.to_uid, "canonical direction");

    // Person↔identifier → IdentifiedBy, Person is always the `from` endpoint.
    for r in rels.iter().filter(|r| r.kind == RelationKind::IdentifiedBy) {
        assert_eq!(r.from_uid, person.uid, "Person owns the selector");
    }
    // Confidence is the match score damped by the weaker endpoint (never > min conf).
    for r in &rels {
        assert!(r.confidence <= 0.8 + 1e-9, "damped by endpoint trust");
        assert!(r.confidence > 0.0);
    }
}

#[test]
fn coreference_promotion_is_strictly_additive() {
    // An edge already present in `existing` for the same (from, kind, to) must NOT
    // be re-emitted — the pass can only ADD links, never restate a higher-trust
    // builder's edge (which would churn its confidence on upsert).
    let user = ent(EntityKind::Username, "johnsmith", 0.8);
    let email = ent(EntityKind::Email, "johnsmith@gmail.com", 0.8);
    let ents = vec![user.clone(), email.clone()];

    // First, what the pass would emit unconstrained.
    let fresh = derive_coreferences(&ents, &[], "s");
    let alias = fresh
        .iter()
        .find(|r| r.kind == RelationKind::AliasOf)
        .expect("an alias edge");

    // Now pre-seed that exact edge as "already built" — the pass must skip it.
    let prior = vec![Relation::new(
        alias.from_uid.as_str(),
        alias.to_uid.as_str(),
        RelationKind::AliasOf,
        0.95, // a stronger builder's confidence — must be preserved (not restated)
        "s",
    )];
    let after = derive_coreferences(&ents, &prior, "s");
    assert!(
        !after
            .iter()
            .any(|r| r.from_uid == alias.from_uid && r.kind == RelationKind::AliasOf),
        "a pre-existing edge is never re-emitted"
    );
}

#[test]
fn coreference_promotion_ignores_weak_hypotheses() {
    // Two unrelated people sharing only a first name never reach the high
    // promotion threshold, so no spurious identity edge is created.
    let a = ent(EntityKind::Person, "John Smith", 0.8);
    let b = ent(EntityKind::Person, "John Citizen", 0.8);
    assert!(
        derive_coreferences(&[a, b], &[], "s").is_empty(),
        "namesakes must not be fused into one identity"
    );
}

#[test]
fn residency_links_person_to_place_by_owner_and_tag() {
    use crate::core::entity::Evidence;
    // Owner-named address (qld_unclaimed style) → LocatedAt to that Person.
    let person = ent(EntityKind::Person, "Erik Diegmann", 0.5);
    let mut addr = ent(EntityKind::Address, "QLD 4552, Australia", 0.5);
    addr.add_evidence(
        Evidence::new("qld_unclaimed", "unclaimed money").with_attr("owner", "Erik Diegmann"),
    );

    // A coordinate the scan already flagged as the subject's by name → subject.
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    subject.tag("subject");
    let mut coord = ent(EntityKind::Coordinates, "-26.65,152.95", 0.4);
    coord.tag("exact-name-match");

    let rels = derive_residency(
        &[person.clone(), addr.clone(), subject.clone(), coord.clone()],
        "s",
    );
    assert_eq!(rels.len(), 2);
    assert!(rels.iter().all(|r| r.kind == RelationKind::LocatedAt));
    assert!(
        rels.iter()
            .any(|r| r.from_uid == person.uid && r.to_uid == addr.uid),
        "owner attribute binds the named person to the address"
    );
    assert!(
        rels.iter()
            .any(|r| r.from_uid == subject.uid && r.to_uid == coord.uid),
        "exact-name-match place binds to the subject"
    );
}

#[test]
fn kinship_links_same_surname_distinct_people() {
    let kyle = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    let erik = ent(EntityKind::Person, "Erik Diegmann", 0.5);
    let stranger = ent(EntityKind::Person, "Jane Smith", 0.6); // different surname

    let rels = derive_kinship(&[kyle.clone(), erik.clone(), stranger], "s");
    assert_eq!(rels.len(), 1, "one kinship candidate (Kyle ↔ Erik)");
    let r = &rels[0];
    assert_eq!(r.kind, RelationKind::AssociatedWith);
    assert!(r.from_uid <= r.to_uid, "canonical direction");
    // Damped: a surname match is a candidate, not endpoint-strength certainty.
    assert!(
        r.confidence < 0.8_f64.min(0.5),
        "kinship confidence is damped below the endpoints"
    );
}

#[test]
fn kinship_skips_common_surnames() {
    // A COMMON surname is shared by unrelated strangers — two "Smith"s on a scan
    // are not evidence of kinship and must not be linked (the O(n²) false-associate
    // blow-up). A distinctive surname still links (see kinship_links_… above).
    let a = ent(EntityKind::Person, "Alice Smith", 0.7);
    let b = ent(EntityKind::Person, "Bob Smith", 0.7);
    assert!(
        derive_kinship(&[a, b], "s").is_empty(),
        "a common surname (Smith) is not a kinship signal"
    );
    // Sanity: an uncommon surname at the same confidences DOES link, so the empty
    // result above is the commonness gate, not some other guard.
    let c = ent(EntityKind::Person, "Alice Diegmann", 0.7);
    let d = ent(EntityKind::Person, "Bob Diegmann", 0.7);
    assert_eq!(derive_kinship(&[c, d], "s").len(), 1);
}

#[test]
fn kinship_skips_one_person_two_spellings() {
    // The SAME person under two spellings (different uids, identical folded name)
    // is not their own kin — the normalised-name guard drops the pair.
    let a = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    let b = ent(EntityKind::Person, "kyle diegmann", 0.7); // distinct entity, same identity
    assert!(
        derive_kinship(&[a, b], "s").is_empty(),
        "two spellings of one person are not a kinship pair"
    );
}

#[test]
fn kinship_excludes_short_surnames() {
    // Two-letter surnames alias far too readily (Ng, Le, Xu) — excluded.
    let a = ent(EntityKind::Person, "Bob Ng", 0.6);
    let b = ent(EntityKind::Person, "Al Ng", 0.6);
    assert!(derive_kinship(&[a, b], "s").is_empty());
}

#[test]
fn declared_associations_link_related_and_co_owners() {
    use crate::core::entity::Evidence;
    // A SeekNow relative (related_to) and a qld joint record (co_owner) each
    // declare a relationship to a present Person — bound at FULL trust (declared,
    // not the surname guess), so the edge confidence is the endpoint minimum.
    let subject = ent(EntityKind::Person, "Kyle Diegmann", 0.8);
    let mut rel = ent(EntityKind::Person, "Erik Diegmann", 0.55);
    rel.add_evidence(
        Evidence::new("see_know", "relative").with_attr("related_to", "Kyle Diegmann"),
    );
    let mut curt = ent(EntityKind::Person, "Curt Diegmann", 0.35);
    curt.add_evidence(
        Evidence::new("qld_unclaimed", "owner").with_attr("co_owner", "Hayley Diegmann"),
    );
    let hayley = ent(EntityKind::Person, "Hayley Diegmann", 0.35);

    let rels = derive_declared_associations(
        &[subject.clone(), rel.clone(), curt.clone(), hayley.clone()],
        "s",
    );
    assert_eq!(rels.len(), 2, "related_to + co_owner");
    assert!(rels.iter().all(|r| r.kind == RelationKind::AssociatedWith));
    let connects = |a: &Entity, b: &Entity| {
        let (lo, hi) = if a.uid <= b.uid {
            (&a.uid, &b.uid)
        } else {
            (&b.uid, &a.uid)
        };
        rels.iter().find(|r| &r.from_uid == lo && &r.to_uid == hi)
    };
    let ke = connects(&subject, &rel).expect("related_to binds relative → subject");
    assert!(
        (ke.confidence - 0.55_f64).abs() < 1e-9,
        "declared edge carries full endpoint trust, not a damped guess"
    );
    assert!(
        connects(&curt, &hayley).is_some(),
        "co_owner binds joint owners"
    );
}

#[test]
fn diegmann_family_connects_from_any_seed_angle() {
    // Ground truth: Kyle, Erik, Curt and Hayley Diegmann are connected. A scan
    // seeded on ANY of them surfaces the others (qld_unclaimed surname-broadened
    // search emits each owner as a Person, name_intel anchors the subject), and
    // the relation layer must connect all four regardless of which is the seed —
    // the free, angle-independent family guarantee, proven via graph reachability.
    let family = [
        "Kyle Diegmann",
        "Erik Diegmann",
        "Curt Diegmann",
        "Hayley Diegmann",
    ];
    for &seed in &family {
        // The entity set this seed produces: the subject (exact-name-match) plus
        // the rest as surname family-candidates, exactly as qld_unclaimed emits.
        let ents: Vec<Entity> = family
            .iter()
            .map(|&name| {
                let mut p = ent(
                    EntityKind::Person,
                    name,
                    if name == seed { 0.6 } else { 0.35 },
                );
                p.tag(if name == seed {
                    "exact-name-match"
                } else {
                    "family-candidate"
                });
                p
            })
            .collect();

        let rels = derive_all(&ents, "s");
        // Build an undirected graph over the association edges and BFS from seed.
        let mut adj: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
        for r in rels
            .iter()
            .filter(|r| r.kind == RelationKind::AssociatedWith)
        {
            adj.entry(&r.from_uid).or_default().push(&r.to_uid);
            adj.entry(&r.to_uid).or_default().push(&r.from_uid);
        }
        let subject = ents
            .iter()
            .find(|e| e.value == seed)
            .expect("should succeed");
        let mut reached = std::collections::HashSet::new();
        let mut stack = vec![subject.uid.as_str()];
        while let Some(u) = stack.pop() {
            if reached.insert(u)
                && let Some(neighbours) = adj.get(u)
            {
                stack.extend(neighbours.iter().copied());
            }
        }
        for e in &ents {
            assert!(
                reached.contains(e.uid.as_str()),
                "seeding on '{seed}': '{}' must be connected to the family graph",
                e.value
            );
        }
    }
}

// ── derive_co_ownership (SameOperator structural edges) ─────────────────────

fn reg_edge(dom: &Entity, who: &Entity) -> crate::core::relation::Relation {
    Relation::new(
        dom.uid.as_str(),
        who.uid.as_str(),
        RelationKind::RegisteredBy,
        dom.confidence.min(who.confidence),
        "s",
    )
}

fn resolves_edge(dom: &Entity, ip: &Entity) -> Relation {
    Relation::new(
        dom.uid.as_str(),
        ip.uid.as_str(),
        RelationKind::ResolvesTo,
        dom.confidence.min(ip.confidence),
        "s",
    )
}

#[test]
fn co_ownership_shared_registrant_links_two_domains() {
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let registrant = ent(EntityKind::Organisation, "Haigen Enterprises Pty Ltd", 0.9);
    let relations = vec![reg_edge(&dom_a, &registrant), reg_edge(&dom_b, &registrant)];
    let rels = derive_co_ownership(&[dom_a.clone(), dom_b.clone(), registrant], &relations, "s");
    assert_eq!(rels.len(), 1, "one SameOperator edge for the pair");
    assert_eq!(rels[0].kind, RelationKind::SameOperator);
    // Canonical direction: smaller uid → larger uid.
    let (exp_from, exp_to) = if dom_a.uid <= dom_b.uid {
        (&dom_a.uid, &dom_b.uid)
    } else {
        (&dom_b.uid, &dom_a.uid)
    };
    assert_eq!(&rels[0].from_uid, exp_from);
    assert_eq!(&rels[0].to_uid, exp_to);
    assert!((rels[0].confidence - 0.8).abs() < 1e-9);
}

#[test]
fn co_ownership_proxy_registrant_excluded() {
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    // "Domains By Proxy" contains "domains by proxy" — a known proxy marker.
    let proxy = ent(EntityKind::Organisation, "Domains By Proxy, LLC", 0.9);
    let relations = vec![reg_edge(&dom_a, &proxy), reg_edge(&dom_b, &proxy)];
    let rels = derive_co_ownership(&[dom_a, dom_b, proxy], &relations, "s");
    assert!(rels.is_empty(), "privacy-proxy registrant must be excluded");
}

#[test]
fn co_ownership_shared_dedicated_ip_links_two_distinct_sites() {
    // 45.33.32.156 — Linode/Akamai static IP; not in CDN prefix table, routable.
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let ip = ent(EntityKind::IpAddress, "45.33.32.156", 0.9);
    let relations = vec![resolves_edge(&dom_a, &ip), resolves_edge(&dom_b, &ip)];
    let rels = derive_co_ownership(&[dom_a.clone(), dom_b.clone(), ip], &relations, "s");
    assert_eq!(rels.len(), 1, "one SameOperator edge for co-hosted pair");
    assert_eq!(rels[0].kind, RelationKind::SameOperator);
}

#[test]
fn co_ownership_cdn_ip_excluded() {
    // 104.16.5.5 — Cloudflare CDN prefix (is_cdn_edge_ip returns true).
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let cdn_ip = ent(EntityKind::IpAddress, "104.16.5.5", 0.9);
    let relations = vec![
        resolves_edge(&dom_a, &cdn_ip),
        resolves_edge(&dom_b, &cdn_ip),
    ];
    let rels = derive_co_ownership(&[dom_a, dom_b, cdn_ip], &relations, "s");
    assert!(rels.is_empty(), "CDN/anycast IP must be excluded");
}

#[test]
fn co_ownership_single_site_subdomains_not_co_owned() {
    // www.example.com and api.example.com on the same IP collapse to one
    // registrable domain (example.com) — must NOT fire.
    let dom_a = ent(EntityKind::Domain, "www.example.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "api.example.com", 0.8);
    let ip = ent(EntityKind::IpAddress, "45.33.32.156", 0.9);
    let relations = vec![resolves_edge(&dom_a, &ip), resolves_edge(&dom_b, &ip)];
    let rels = derive_co_ownership(&[dom_a, dom_b, ip], &relations, "s");
    assert!(
        rels.is_empty(),
        "subdomains of the same registrable domain must not fire as co-ownership"
    );
}

#[test]
fn co_ownership_shared_tracking_id_links_carrying_domains() {
    use crate::core::entity::Evidence;
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let mut tid = ent(EntityKind::TrackingId, "UA-12345678-1", 0.85);
    // Both domains carried the same Google Analytics ID.
    tid.add_evidence(
        Evidence::new("web_crawler", "GA tag on alpha-site.com")
            .with_attr("source_domain", "alpha-site.com"),
    );
    tid.add_evidence(
        Evidence::new("web_crawler", "GA tag on beta-site.org")
            .with_attr("source_domain", "beta-site.org"),
    );
    let rels = derive_co_ownership(&[dom_a.clone(), dom_b.clone(), tid], &[], "s");
    assert_eq!(
        rels.len(),
        1,
        "shared analytics ID links the carrying domains"
    );
    assert_eq!(rels[0].kind, RelationKind::SameOperator);
    let (exp_from, exp_to) = if dom_a.uid <= dom_b.uid {
        (&dom_a.uid, &dom_b.uid)
    } else {
        (&dom_b.uid, &dom_a.uid)
    };
    assert_eq!(&rels[0].from_uid, exp_from);
    assert_eq!(&rels[0].to_uid, exp_to);
}

#[test]
fn co_ownership_same_pair_from_two_sources_emits_one_edge() {
    use crate::core::entity::Evidence;
    // Domains share BOTH a registrant AND a tracking ID — only one SameOperator
    // edge should be produced (the global dedup guard).
    let dom_a = ent(EntityKind::Domain, "alpha-site.com", 0.8);
    let dom_b = ent(EntityKind::Domain, "beta-site.org", 0.8);
    let registrant = ent(EntityKind::Organisation, "Haigen Enterprises Pty Ltd", 0.9);
    let mut tid = ent(EntityKind::TrackingId, "GTM-ABC123", 0.85);
    tid.add_evidence(
        Evidence::new("web_crawler", "GTM on alpha-site.com")
            .with_attr("source_domain", "alpha-site.com"),
    );
    tid.add_evidence(
        Evidence::new("web_crawler", "GTM on beta-site.org")
            .with_attr("source_domain", "beta-site.org"),
    );
    let relations = vec![reg_edge(&dom_a, &registrant), reg_edge(&dom_b, &registrant)];
    let rels = derive_co_ownership(&[dom_a, dom_b, registrant, tid], &relations, "s");
    assert_eq!(
        rels.len(),
        1,
        "same pair from registrant + tracking ID must deduplicate to one edge"
    );
}

// ── derive_profile_links (SameIdentity structural edges) ────────────────────

#[test]
fn profile_links_github_matches_username() {
    let uname = ent(EntityKind::Username, "rhino-ryno23", 0.9);
    let url = ent(EntityKind::Url, "https://github.com/rhino-ryno23", 0.80);
    let rels = derive_profile_links(&[uname.clone(), url.clone()], "s");
    assert_eq!(rels.len(), 1, "one SameIdentity edge");
    assert_eq!(rels[0].kind, RelationKind::SameIdentity);
    assert_eq!(rels[0].from_uid, uname.uid, "directed Username → Url");
    assert_eq!(rels[0].to_uid, url.uid);
    assert!(
        (rels[0].confidence - 0.80).abs() < 1e-9,
        "min(0.9, 0.8)=0.8"
    );
}

#[test]
fn profile_links_direction_is_username_to_url() {
    let uname = ent(EntityKind::Username, "haigenbamford", 0.85);
    let url = ent(EntityKind::Url, "https://twitter.com/haigenbamford", 0.75);
    let rels = derive_profile_links(&[uname.clone(), url.clone()], "s");
    assert_eq!(rels.len(), 1);
    assert_eq!(rels[0].from_uid, uname.uid);
    assert_eq!(rels[0].to_uid, url.uid);
}

#[test]
fn profile_links_case_insensitive_match() {
    // Username stored as mixed case; URL always lowercased by platform.
    let uname = ent(EntityKind::Username, "Rhino-Ryno23", 0.9);
    let url = ent(EntityKind::Url, "https://github.com/rhino-ryno23", 0.80);
    let rels = derive_profile_links(&[uname.clone(), url.clone()], "s");
    assert_eq!(rels.len(), 1, "case-insensitive match must fire");
    assert_eq!(rels[0].from_uid, uname.uid);
}

#[test]
fn profile_links_tiktok_at_prefix_stripped() {
    let uname = ent(EntityKind::Username, "dancequeen", 0.85);
    let url = ent(EntityKind::Url, "https://www.tiktok.com/@dancequeen", 0.80);
    let rels = derive_profile_links(&[uname.clone(), url.clone()], "s");
    assert_eq!(rels.len(), 1, "@ prefix stripped correctly");
    assert_eq!(rels[0].from_uid, uname.uid);
}

#[test]
fn profile_links_reddit_user_prefix_skipped() {
    // Reddit URL: /user/{username}/about.json — segment index 1.
    let uname = ent(EntityKind::Username, "rhino-ryno23", 0.88);
    let url = ent(
        EntityKind::Url,
        "https://www.reddit.com/user/rhino-ryno23/about.json",
        0.75,
    );
    let rels = derive_profile_links(&[uname.clone(), url.clone()], "s");
    assert_eq!(
        rels.len(),
        1,
        "user/ prefix skipped, about.json segment ignored"
    );
}

#[test]
fn profile_links_bluesky_suffix_stripped() {
    let uname = ent(EntityKind::Username, "haigen", 0.85);
    let url = ent(
        EntityKind::Url,
        "https://bsky.app/profile/haigen.bsky.social",
        0.80,
    );
    let rels = derive_profile_links(&[uname.clone(), url.clone()], "s");
    assert_eq!(rels.len(), 1, ".bsky.social suffix stripped");
    assert_eq!(rels[0].from_uid, uname.uid);
}

#[test]
fn profile_links_hackernews_query_param() {
    let uname = ent(EntityKind::Username, "pg", 0.90);
    let url = ent(
        EntityKind::Url,
        "https://news.ycombinator.com/user?id=pg",
        0.85,
    );
    let rels = derive_profile_links(&[uname.clone(), url.clone()], "s");
    assert_eq!(rels.len(), 1, "?id= query param extracted");
    assert_eq!(rels[0].from_uid, uname.uid);
}

#[test]
fn profile_links_unknown_host_no_edge() {
    let uname = ent(EntityKind::Username, "rhino-ryno23", 0.9);
    let url = ent(
        EntityKind::Url,
        "https://unknownplatform.example.com/rhino-ryno23",
        0.80,
    );
    let rels = derive_profile_links(&[uname, url], "s");
    assert!(rels.is_empty(), "unknown host must produce no edge");
}

#[test]
fn profile_links_no_matching_username_entity_no_edge() {
    // URL matches a known platform but no Username entity with that handle exists.
    let other_uname = ent(EntityKind::Username, "someone_else", 0.9);
    let url = ent(EntityKind::Url, "https://github.com/rhino-ryno23", 0.80);
    let rels = derive_profile_links(&[other_uname, url], "s");
    assert!(
        rels.is_empty(),
        "non-matching username must produce no edge"
    );
}

#[test]
fn profile_links_no_username_entities_returns_empty() {
    // No Username entity at all → early return, no panic.
    let url = ent(EntityKind::Url, "https://github.com/rhino-ryno23", 0.80);
    assert!(derive_profile_links(&[url], "s").is_empty());
    assert!(derive_profile_links(&[], "s").is_empty());
}

#[test]
fn profile_links_multiple_platforms_same_username() {
    // Same username confirmed on three platforms → three SameIdentity edges.
    let uname = ent(EntityKind::Username, "hacker", 0.90);
    let gh = ent(EntityKind::Url, "https://github.com/hacker", 0.80);
    let tw = ent(EntityKind::Url, "https://twitter.com/hacker", 0.75);
    let gl = ent(EntityKind::Url, "https://gitlab.com/hacker", 0.70);
    let rels = derive_profile_links(&[uname.clone(), gh, tw, gl], "s");
    assert_eq!(rels.len(), 3, "one edge per confirmed platform profile");
    assert!(rels.iter().all(|r| r.kind == RelationKind::SameIdentity));
    assert!(rels.iter().all(|r| r.from_uid == uname.uid));
}

#[test]
fn regional_kinship_links_common_surname_family_sharing_a_town() {
    use crate::core::entity::Evidence;
    // Two COMMON-surname people (Smith) in the SAME AU town (postcode 4557) — the
    // family derive_kinship drops on the commonness discount. The shared postcode
    // is the corroboration that recovers the link.
    let mut a = ent(EntityKind::Person, "John Smith", 0.6);
    a.add_evidence(Evidence::new("au_people", "directory").with_attr("postcode", "4557"));
    let mut b = ent(EntityKind::Person, "Jane Smith", 0.6);
    b.add_evidence(Evidence::new("au_people", "directory").with_attr("postcode", "4557"));

    let rels = derive_regional_kinship(&[a.clone(), b.clone()], "s");
    assert_eq!(
        rels.len(),
        1,
        "same town + same common surname → one family lead"
    );
    assert_eq!(rels[0].kind, RelationKind::AssociatedWith);
    assert!(rels[0].from_uid <= rels[0].to_uid, "canonical direction");
    // Damped candidate lead (a populous postcode can hold namesakes).
    assert!(rels[0].confidence < 0.6 * 0.5, "geo-gated lead is damped");
    assert!(rels[0].confidence > 0.0);
}

#[test]
fn regional_kinship_requires_the_same_town() {
    use crate::core::entity::Evidence;
    // Same common surname but DIFFERENT towns → not a family lead.
    let mut a = ent(EntityKind::Person, "John Smith", 0.6);
    a.add_evidence(Evidence::new("au_people", "d").with_attr("postcode", "4557"));
    let mut b = ent(EntityKind::Person, "Jane Smith", 0.6);
    b.add_evidence(Evidence::new("au_people", "d").with_attr("postcode", "2000"));
    assert!(
        derive_regional_kinship(&[a, b], "s").is_empty(),
        "different towns must not link strangers"
    );
}

#[test]
fn regional_kinship_is_disjoint_from_distinctive_surname_kinship() {
    use crate::core::entity::Evidence;
    // A DISTINCTIVE surname is derive_kinship's domain; the regional pass must stay
    // out of it (disjoint) even when a town is shared — no double / churned edge.
    let mut a = ent(EntityKind::Person, "Erik Diegmann", 0.6);
    a.add_evidence(Evidence::new("qld_unclaimed", "r").with_attr("postcode", "4552"));
    let mut b = ent(EntityKind::Person, "Curt Diegmann", 0.6);
    b.add_evidence(Evidence::new("qld_unclaimed", "r").with_attr("postcode", "4552"));
    assert!(
        derive_regional_kinship(&[a, b], "s").is_empty(),
        "distinctive surnames belong to derive_kinship, not the regional pass"
    );
}

#[test]
fn regional_kinship_needs_a_postcode_anchor() {
    // Same common surname, no postcode evidence → no geo corroboration → no edge.
    let a = ent(EntityKind::Person, "John Smith", 0.6);
    let b = ent(EntityKind::Person, "Jane Smith", 0.6);
    assert!(
        derive_regional_kinship(&[a, b], "s").is_empty(),
        "without a shared town the common-surname pair stays unlinked"
    );
}

#[test]
fn collapse_to_max_confidence_keeps_the_strongest_of_duplicate_edges() {
    use super::builders::collapse_to_max_confidence;
    // Same (from, kind, to, scan) → same Relation id (the id EXCLUDES confidence),
    // so the builders' weakest-first emission (surname kinship 0.5 before a declared
    // 0.9 on one pair) must collapse to the STRONGEST edge. Otherwise persistence's
    // ON CONFLICT(id) DO NOTHING keeps the weakest and flips downstream confidence
    // gating — the exact inverse of the "higher-trust wins" intent.
    let weak = Relation::new("a", "b", RelationKind::AssociatedWith, 0.5, "s1");
    let strong = Relation::new("a", "b", RelationKind::AssociatedWith, 0.9, "s1");
    assert_eq!(weak.id, strong.id, "confidence is not part of the id");
    let other = Relation::new("a", "c", RelationKind::AssociatedWith, 0.6, "s1");

    let collapsed = collapse_to_max_confidence(vec![weak, strong, other]);
    assert_eq!(
        collapsed.len(),
        2,
        "the a→b duplicate collapses to one edge"
    );
    let ab = collapsed
        .iter()
        .find(|r| r.to_uid == "b")
        .expect("a→b kept");
    assert!(
        (ab.confidence - 0.9).abs() < 1e-9,
        "the strongest (0.9) edge survives, got {}",
        ab.confidence
    );
    // Deterministic first-occurrence order; the distinct a→c edge is untouched.
    assert_eq!(collapsed[0].to_uid, "b");
    assert_eq!(collapsed[1].to_uid, "c");
}

// ── provenance_chain (derivation trail) ─────────────────────────────────

#[test]
fn provenance_chain_walks_derivedfrom_back_to_the_root() {
    // root ← child ← grand: each DerivedFrom points child → parent.
    let rels = vec![
        Relation::new("child", "root", RelationKind::DerivedFrom, 0.9, "s"),
        Relation::new("grand", "child", RelationKind::DerivedFrom, 0.9, "s"),
    ];
    // From the deepest node the trail walks back to the seed root.
    assert_eq!(
        provenance_chain("grand", &rels),
        vec!["grand", "child", "root"]
    );
    // A root (no parent edge) is its own single-element chain.
    assert_eq!(provenance_chain("root", &rels), vec!["root"]);
    // A non-DerivedFrom edge is ignored by the walk.
    let noise = vec![Relation::new(
        "grand",
        "x",
        RelationKind::HostedOn,
        0.9,
        "s",
    )];
    assert_eq!(provenance_chain("grand", &noise), vec!["grand"]);
}

#[test]
fn provenance_chain_is_cycle_safe() {
    // A pathological a↔b DerivedFrom cycle must terminate, not loop forever.
    let rels = vec![
        Relation::new("a", "b", RelationKind::DerivedFrom, 0.5, "s"),
        Relation::new("b", "a", RelationKind::DerivedFrom, 0.5, "s"),
    ];
    // a → b → (a already seen → stop).
    assert_eq!(provenance_chain("a", &rels), vec!["a", "b"]);
}
