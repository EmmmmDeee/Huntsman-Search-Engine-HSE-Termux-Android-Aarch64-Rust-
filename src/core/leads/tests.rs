use super::*;
use crate::core::entity::EntityKind;
use crate::core::relation::RelationKind;

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "leads-scan")
}

fn rel(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
    Relation::new(from.uid.as_str(), to.uid.as_str(), kind, conf, "leads-scan")
}

/// The headline case: an untapped relative (below the expansion floor, so the
/// engine never pivoted it) outranks an already-strong owned identifier, and its
/// reason names both the relationship and that it is uninvestigated.
#[test]
fn recommend_ranks_untapped_relatives() {
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.85);
    subject.tag("subject");
    let mut erik = ent(EntityKind::Person, "Erik Diegmann", 0.35); // sub-floor → untapped
    erik.tag("family-candidate");
    let email = ent(EntityKind::Email, "kyle@example.com", 0.8); // above floor, owned
    let addr = ent(EntityKind::Address, "QLD 4552, Australia", 0.5); // not pivotable

    let relations = vec![
        rel(&subject, &erik, RelationKind::AssociatedWith, 0.5),
        rel(&subject, &email, RelationKind::IdentifiedBy, 0.8),
        rel(&subject, &addr, RelationKind::LocatedAt, 0.5),
    ];
    let entities = vec![subject, erik.clone(), email.clone(), addr];

    let leads = recommend(&entities, &relations, 0.50);
    // Two pivotable leads (person, email); the address is not pivotable.
    assert_eq!(leads.len(), 2, "address is not an actionable lead");
    let erik_lead = leads.iter().find(|l| l.value == "Erik Diegmann").unwrap();
    let email_lead = leads
        .iter()
        .find(|l| l.value == "kyle@example.com")
        .unwrap();
    assert_eq!(erik_lead.target_kind, "full_name");
    assert_eq!(email_lead.target_kind, "email");
    assert_eq!(erik_lead.action, "scan");
    assert!(
        erik_lead.reason.contains("relative") && erik_lead.reason.contains("not yet investigated"),
        "reason: {}",
        erik_lead.reason
    );
    // The untapped relative is boosted above the strong-but-tapped identifier.
    assert!(
        leads[0].value == "Erik Diegmann",
        "an untapped relative is the top next step, got {:?}",
        leads.iter().map(|l| &l.value).collect::<Vec<_>>()
    );
}

/// A geo-corroborated relative — shared surname AND the subject's own confirmed
/// area, two independent free signals ([`crate::core::geo_family`]) — is the single
/// most reliable free pivot, so it is the TOP lead even though geo-corroboration
/// lifted its confidence above the expansion floor. Its reason names the geo
/// confirmation, and it stays flagged untapped (the engine held it below the floor
/// through expansion and never auto-pivoted it). Without this, the binary
/// "untapped ⇒ boost" ranked a *confirmed* relative below an unconfirmed guess.
#[test]
fn recommend_ranks_geo_corroborated_family_top() {
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.85);
    subject.tag("subject");

    // Geo-confirmed relative, promoted to PROBABLE (c_eff 0.56 > the 0.50 floor).
    let mut confirmed = ent(EntityKind::Person, "Erik Diegmann", 0.56);
    confirmed.tag("family-candidate");
    confirmed.tag("geo-corroborated");

    // Unconfirmed same-surname candidate, still below the floor.
    let mut guess = ent(EntityKind::Person, "Curt Diegmann", 0.32);
    guess.tag("family-candidate");

    let relations = vec![
        rel(&subject, &confirmed, RelationKind::AssociatedWith, 0.6),
        rel(&subject, &guess, RelationKind::AssociatedWith, 0.5),
    ];
    let entities = vec![subject, confirmed.clone(), guess.clone()];

    let leads = recommend(&entities, &relations, 0.50);
    assert_eq!(
        leads[0].value,
        "Erik Diegmann",
        "the geo-corroborated relative is the top lead, got {:?}",
        leads.iter().map(|l| &l.value).collect::<Vec<_>>()
    );
    let top = &leads[0];
    assert!(
        top.reason.contains("relative")
            && top.reason.contains("confirmed in the subject's area")
            && top.reason.contains("not yet investigated"),
        "reason: {}",
        top.reason
    );
    // Both are relatives, but the confirmed one scores strictly higher than the
    // unconfirmed guess — reliability is what separates them.
    let guess_lead = leads.iter().find(|l| l.value == "Curt Diegmann").unwrap();
    assert!(
        top.score > guess_lead.score,
        "confirmed ({}) must outrank unconfirmed ({})",
        top.score,
        guess_lead.score
    );
    // The UI badges this: corroborated vs a bare guess.
    assert!(
        top.confirmed,
        "the geo-corroborated relative is flagged confirmed"
    );
    assert!(
        !guess_lead.confirmed,
        "an unconfirmed candidate is not flagged confirmed"
    );
}

/// The precision complement: a geo-discordant namesake (shared surname, a region
/// away) is demoted below an otherwise-identical in-region candidate, its reason
/// names the namesake doubt, and it is flagged `discordant` (not `confirmed`) for
/// the UI — so interstate look-alikes never crowd out the genuine local family.
#[test]
fn recommend_demotes_geo_discordant_namesakes() {
    let mut subject = ent(EntityKind::Person, "Kyle Diegmann", 0.85);
    subject.tag("subject");

    // Two same-surname candidates, identical but for location: one local, one a
    // region away and flagged a likely namesake by the finalize pass.
    let mut local = ent(EntityKind::Person, "Aaron Diegmann", 0.32);
    local.tag("family-candidate");
    let mut namesake = ent(EntityKind::Person, "Zane Diegmann", 0.32);
    namesake.tag("family-candidate");
    namesake.tag("geo-discordant");

    let relations = vec![
        rel(&subject, &local, RelationKind::AssociatedWith, 0.5),
        rel(&subject, &namesake, RelationKind::AssociatedWith, 0.5),
    ];
    let entities = vec![subject, local.clone(), namesake.clone()];

    let leads = recommend(&entities, &relations, 0.50);
    let local_lead = leads.iter().find(|l| l.value == "Aaron Diegmann").unwrap();
    let namesake_lead = leads.iter().find(|l| l.value == "Zane Diegmann").unwrap();
    assert!(
        local_lead.score > namesake_lead.score,
        "the local candidate ({}) outranks the namesake ({})",
        local_lead.score,
        namesake_lead.score
    );
    assert!(namesake_lead.discordant && !namesake_lead.confirmed);
    assert!(!local_lead.discordant);
    assert!(
        namesake_lead.reason.contains("possible namesake"),
        "reason: {}",
        namesake_lead.reason
    );
    // The local candidate is the top lead overall.
    assert_eq!(leads[0].value, "Aaron Diegmann");
}

/// Reliability lifts a lead, but only for a *new* person/persona — never for a
/// value the subject already owns. A geo-corroborated relative beats a same-tier
/// plain relative, and a VERIFIED owned identifier still trails an untapped
/// relative (owning your own email is confirmation, not a next step).
#[test]
fn confirmation_boost_rewards_new_people_not_owned_identifiers() {
    // geo-corroborated > plain, at equal confidence/edge — confirmation decides.
    let geo = confirmation_boost("people", "PROBABLE", &["geo-corroborated".into()]);
    let plain = confirmation_boost("people", "PROBABLE", &[]);
    assert!(
        geo > plain,
        "geo-corroboration is the strongest confirmation"
    );
    // A reliable *new* person earns a bonus; an owned identifier never does.
    assert!(confirmation_boost("people", "VERIFIED", &[]) > 0.0);
    assert_eq!(confirmation_boost("identifiers", "VERIFIED", &[]), 0.0);
    assert_eq!(confirmation_boost("locations", "VERIFIED", &[]), 0.0);
    // A bare candidate (no second signal) earns nothing.
    assert_eq!(confirmation_boost("people", "CANDIDATE", &[]), 0.0);
}

/// Aliases and infrastructure are pivotable too, but a non-pivotable kind (or no
/// connections at all) yields nothing — no speculative noise.
#[test]
fn recommend_covers_pivotable_kinds_only() {
    let mut subject = ent(EntityKind::Username, "kdiegmann", 0.7);
    subject.tag("subject");
    let alias = ent(EntityKind::Email, "kd@example.com", 0.6);
    let dom = ent(EntityKind::Domain, "example.com", 0.6);
    let relations = vec![
        rel(&subject, &alias, RelationKind::AliasOf, 0.6),
        rel(&alias, &dom, RelationKind::BelongsToDomain, 0.6),
    ];
    let leads = recommend(&[subject, alias, dom], &relations, 0.50);
    let kinds: std::collections::BTreeSet<&str> = leads.iter().map(|l| l.kind.as_str()).collect();
    assert!(kinds.contains("email"), "alias email is a lead");

    // No connections → no leads (and no panic on an empty graph).
    let lone = ent(EntityKind::Person, "Nobody Connected", 0.9);
    assert!(recommend(std::slice::from_ref(&lone), &[], 0.50).is_empty());
    assert!(recommend(&[], &[], 0.50).is_empty());
}

/// Leads are a bounded, ranked shortlist (deterministic), never an unbounded
/// second entity dump, even on a large family.
#[test]
fn recommend_is_bounded_and_ranked() {
    let mut subject = ent(EntityKind::Person, "Hub Person", 0.9);
    subject.tag("subject");
    let mut entities = vec![subject.clone()];
    let mut relations = Vec::new();
    for i in 0..60 {
        // Distinct surnames so kinship doesn't cross-link them; each is a direct
        // declared associate of the subject.
        let p = ent(EntityKind::Person, &format!("Person Number{i:02}"), 0.3);
        relations.push(rel(&subject, &p, RelationKind::AssociatedWith, 0.4));
        entities.push(p);
    }
    let leads = recommend(&entities, &relations, 0.50);
    assert!(leads.len() <= LEAD_CAP, "leads are capped at {LEAD_CAP}");
    // Sorted by score descending.
    for w in leads.windows(2) {
        assert!(w[0].score >= w[1].score, "leads are ranked by score");
    }
    // Deterministic: a second run yields the identical ordered value list.
    let again = recommend(&entities, &relations, 0.50);
    let v1: Vec<&str> = leads.iter().map(|l| l.value.as_str()).collect();
    let v2: Vec<&str> = again.iter().map(|l| l.value.as_str()).collect();
    assert_eq!(v1, v2);
}
