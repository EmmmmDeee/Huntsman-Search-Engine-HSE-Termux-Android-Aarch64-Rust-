//! Fixtures are transcriptions of logs read live from `plc.directory` in July
//! 2026, kept in their wire form so the wire types are exercised alongside the
//! rules. The judgements under test are the ones that could put a wrong name,
//! a stranger's domain, or a hosting provider's server into a dossier.

use std::collections::BTreeMap;

use super::history::{History, Spell};
use super::transform::{history_to_entities, web_did_entities};
use super::types::AuditEntry;
use super::{
    DID_KIND, MAX_HANDLES, MAX_PDS, MAX_ROTATION_KEYS, PlcDirectory, ROTATION_KEY_KIND,
    SHARED_ROTATION_KEYS,
};
use crate::core::{
    confidence,
    entity::{Entity, EntityKind},
    module::{Module, ModuleCategory, ModuleCost},
    scan::{Target, TargetKind},
};

const DID: &str = "did:plc:44ybard66vv44zksje25o7dz";

fn log(raw: &str) -> Vec<AuditEntry> {
    serde_json::from_str(raw).expect("fixture parses")
}

/// `bnewbold.net`, read live: a legacy `create` on Bluesky's monolith, a rename
/// onto a staff handle after the shard migration, then a rename onto a personal
/// domain hosted on the subject's own server. Three handles and three hosts,
/// none of which the profile API reports.
fn bnewbold() -> Vec<AuditEntry> {
    log(r#"[
      {
        "createdAt": "2023-04-12T04:53:57.057Z",
        "nullified": false,
        "operation": {
          "type": "create",
          "handle": "bnewbold.bsky.social",
          "service": "https://bsky.social",
          "signingKey": "did:key:zQ3shdKF2sB1MRVAgtaJ6XmT4qNvJnXShgTLmXjR4XiMkNaEk"
        }
      },
      {
        "createdAt": "2024-02-01T18:02:11.001Z",
        "nullified": false,
        "operation": {
          "type": "plc_operation",
          "alsoKnownAs": ["at://bnewbold.bsky.team"],
          "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer",
            "endpoint": "https://morel.us-east.host.bsky.network"}},
          "rotationKeys": [
            "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg",
            "did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK"
          ]
        }
      },
      {
        "createdAt": "2025-06-06T21:14:03.412Z",
        "nullified": false,
        "operation": {
          "type": "plc_operation",
          "alsoKnownAs": ["at://bnewbold.net"],
          "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer",
            "endpoint": "https://pds.robocracy.org"}},
          "rotationKeys": [
            "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg",
            "did:key:zQ3shWpaAqZWEUCHNqNGkyxLPYRxCTgQkjnRBcDBH1mWaXPCT"
          ]
        }
      }
    ]"#)
}

fn entities(raw: &[AuditEntry]) -> Vec<Entity> {
    history_to_entities(DID, &super::history::fold(raw), "scan-1")
}

fn find<'a>(ents: &'a [Entity], kind: &EntityKind, value: &str) -> &'a Entity {
    ents.iter()
        .find(|e| &e.kind == kind && e.value == value)
        .unwrap_or_else(|| panic!("no {kind:?} entity {value:?} in {:?}", values(ents)))
}

fn values(ents: &[Entity]) -> Vec<(String, &str)> {
    ents.iter()
        .map(|e| (format!("{:?}", e.kind), e.value.as_str()))
        .collect()
}

fn did_attrs(ents: &[Entity]) -> BTreeMap<String, String> {
    let did = find(ents, &EntityKind::Other(DID_KIND.into()), DID);
    did.evidence[0].attributes.clone()
}

fn conf_eq(e: &Entity, expected: f64) {
    assert!(
        (e.confidence - expected).abs() < f64::EPSILON,
        "{:?} {:?} is {} not {expected}",
        e.kind,
        e.value,
        e.confidence
    );
}

#[test]
fn module_metadata() {
    let m = PlcDirectory;
    assert_eq!(m.name(), "plc_directory");
    assert!(!m.description().is_empty());
    // Keyless: the directory exists to be read without registration.
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::Social);
    // Immediately behind `bluesky_user` (104), which answers the cheaper
    // present-tense question first.
    assert_eq!(m.priority(), 103);
    assert!(m.max_timeout_ms() >= 8_000, "two sequential requests");
    assert!(m.produces().contains(&EntityKind::Username));
    assert!(m.produces().contains(&EntityKind::Domain));
    // The hosting servers and domain handles it recovers are network
    // infrastructure, which the Social default does not claim.
    assert!(m.attack_techniques().contains(&"T1590.002"));
}

#[test]
fn only_usernames_are_accepted() {
    let m = PlcDirectory;
    assert!(m.accepts(&Target::new(TargetKind::Username, "bnewbold.net")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "bnewbold.net")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Bryan Newbold")));
}

#[test]
fn every_handle_the_account_ever_used_is_recovered() {
    let ents = entities(&bnewbold());

    let usernames: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    // `bnewbold.bsky.social` and `bnewbold.bsky.team` collapse to one username,
    // which is the entire point of collapsing them: it deduplicates with the
    // same name found by every other social module.
    assert_eq!(usernames, vec!["bnewbold.net", "bnewbold"]);

    // The handle in force now is graded as `bluesky_user` grades it, so the two
    // sources corroborate one entity instead of contradicting each other.
    let current = find(&ents, &EntityKind::Username, "bnewbold.net");
    conf_eq(current, confidence::HIGH_PLUSPLUS_PLUS);
    assert!(!current.has_tag("former-handle"));

    let former = find(&ents, &EntityKind::Username, "bnewbold");
    conf_eq(former, confidence::MEDIUM_PLUS);
    assert!(former.has_tag("former-handle"));
    assert!(former.has_tag("historical"));
    assert!(
        former.confidence > confidence::MEDIUM,
        "a recovered former handle must clear the expansion floor or the walk is decorative"
    );
}

#[test]
fn a_released_handle_carries_the_window_it_was_held_in() {
    let ents = entities(&bnewbold());
    let attrs = &find(&ents, &EntityKind::Username, "bnewbold").evidence[0].attributes;

    assert_eq!(
        attrs.get("handle_state").map(String::as_str),
        Some("former")
    );
    assert_eq!(
        attrs.get("first_seen").map(String::as_str),
        Some("2023-04-12")
    );
    // The subject is not claimed to hold it now, and a stranger holding it later
    // is a separate finding — stated on the entity, not left in the source.
    let caveat = attrs
        .get("coverage")
        .expect("former handles carry the caveat");
    assert!(caveat.contains("NO LONGER"));
}

#[test]
fn a_platform_issued_handle_never_becomes_a_domain() {
    let ents = entities(&bnewbold());
    let domains: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();

    // Emitting either would attribute Bluesky's domain to an individual.
    assert!(!domains.contains(&"bnewbold.bsky.social"));
    assert!(!domains.contains(&"bnewbold.bsky.team"));

    // The personal domain is the opposite case: AT Protocol verifies it by DNS
    // TXT or `/.well-known`, so control was demonstrated while it was in force.
    let d = find(&ents, &EntityKind::Domain, "bnewbold.net");
    conf_eq(d, confidence::HIGH_PLUSPLUS);
    assert!(d.has_tag("verified-control"));
    assert!(d.evidence[0].attributes.contains_key("attribution"));
    assert!(
        d.evidence[0]
            .attributes
            .get("coverage")
            .is_some_and(|c| c.contains("does NOT prove")),
        "control is not registration"
    );
}

#[test]
fn a_domain_handle_is_graded_by_how_likely_it_is_to_be_the_subjects() {
    // A handle an operator issued out of its own domain, since dropped, against
    // a registrable domain in force now.
    let ents = entities(&log(r#"[
      {"createdAt": "2023-01-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://alice.pds.example.org"]}},
      {"createdAt": "2024-01-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://alice.dev"]}}
    ]"#));

    // Real, worth recording, and the last thing that should pull a stranger's
    // infrastructure into the graph on its own authority.
    let former = find(&ents, &EntityKind::Domain, "alice.pds.example.org");
    conf_eq(former, confidence::LOW_MEDIUM);
    assert!(
        former.confidence < confidence::MEDIUM,
        "a former subdomain handle must sit below the expansion floor"
    );
    // A registrable domain the subject had to obtain, and still holds.
    conf_eq(
        find(&ents, &EntityKind::Domain, "alice.dev"),
        confidence::HIGH_PLUSPLUS,
    );

    // One weak axis each: a dropped apex, and a subdomain in force. Both land
    // in the middle, above the floor and below a current registrable domain.
    let mixed = entities(&log(r#"[
      {"createdAt": "2023-01-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://old.example"]}},
      {"createdAt": "2024-01-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://alice.pds.example.org"]}}
    ]"#));
    conf_eq(
        find(&mixed, &EntityKind::Domain, "old.example"),
        confidence::MEDIUM_PLUS,
    );
    conf_eq(
        find(&mixed, &EntityKind::Domain, "alice.pds.example.org"),
        confidence::MEDIUM_PLUS,
    );
}

#[test]
fn a_self_hosted_server_is_emitted_and_blueskys_is_withheld() {
    let ents = entities(&bnewbold());
    let domains: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();

    // One company's shared infrastructure is not the subject's.
    assert!(!domains.contains(&"bsky.social"));
    assert!(!domains.contains(&"morel.us-east.host.bsky.network"));

    let pds = find(&ents, &EntityKind::Domain, "pds.robocracy.org");
    conf_eq(pds, confidence::MEDIUM_PLUS);
    assert!(pds.has_tag("atproto-pds"));
    assert!(pds.has_tag("infrastructure"));
    assert_eq!(
        pds.evidence[0]
            .attributes
            .get("pds_state")
            .map(String::as_str),
        Some("current")
    );

    // Withheld is not the same as unrecorded: the migrations still date the
    // account, and the count says how many domains the walk actually produced.
    let attrs = did_attrs(&ents);
    let noted = attrs
        .get("pds_bluesky_operated")
        .expect("recorded on the DID");
    assert!(noted.contains("bsky.social"));
    assert!(noted.contains("morel.us-east.host.bsky.network"));
    assert_eq!(attrs.get("pds_emitted").map(String::as_str), Some("1"));
    assert_eq!(attrs.get("pds_observed").map(String::as_str), Some("3"));
}

#[test]
fn provider_rotation_keys_are_withheld_and_counted() {
    let ents = entities(&bnewbold());
    let keys: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Other(ROTATION_KEY_KIND.into()))
        .map(|e| e.value.as_str())
        .collect();

    // Verified live: these two are Bluesky's operator keys, shared by every
    // hosted account. Emitting one as a correlator would assert a link between
    // the subject and tens of millions of strangers.
    for shared in SHARED_ROTATION_KEYS {
        assert!(!keys.contains(shared), "emitted a provider key: {shared}");
    }
    assert_eq!(
        keys,
        vec!["did:key:zQ3shWpaAqZWEUCHNqNGkyxLPYRxCTgQkjnRBcDBH1mWaXPCT"]
    );

    let attrs = did_attrs(&ents);
    assert_eq!(
        attrs.get("rotation_keys_emitted").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        attrs.get("rotation_keys_withheld").map(String::as_str),
        Some("2")
    );
    assert!(attrs.contains_key("rotation_keys_withheld_note"));

    // The list of known provider keys is incomplete by construction, so the one
    // that survives it still says what it does and does not prove.
    let emitted = &ents
        .iter()
        .find(|e| e.kind == EntityKind::Other(ROTATION_KEY_KIND.into()))
        .expect("one key survives the filter")
        .evidence[0];
    assert!(
        emitted
            .attributes
            .get("coverage")
            .is_some_and(|c| c.contains("KEY HOLDER"))
    );
}

#[test]
fn the_creation_date_is_the_first_effective_operation() {
    let attrs = did_attrs(&entities(&bnewbold()));
    assert_eq!(
        attrs.get("account_created").map(String::as_str),
        Some("2023-04-12")
    );
    assert_eq!(attrs.get("plc_operations").map(String::as_str), Some("3"));
    assert_eq!(attrs.get("handles_observed").map(String::as_str), Some("3"));
    assert_eq!(
        attrs.get("current_handle").map(String::as_str),
        Some("bnewbold.net")
    );
    assert_eq!(
        attrs.get("current_pds").map(String::as_str),
        Some("pds.robocracy.org")
    );
}

#[test]
fn a_deleted_account_still_yields_its_history() {
    // The log outlives the account: the tombstone erases nothing before it.
    let ents = entities(&log(r#"[
      {"createdAt": "2022-11-17T00:35:16.391Z", "nullified": false, "operation": {
        "type": "create", "handle": "ghost.bsky.social", "service": "https://bsky.social"}},
      {"createdAt": "2024-08-02T09:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_tombstone"}}
    ]"#));

    let did = find(&ents, &EntityKind::Other(DID_KIND.into()), DID);
    assert!(did.has_tag("deleted-account"));
    let attrs = &did.evidence[0].attributes;
    assert_eq!(
        attrs.get("tombstoned").map(String::as_str),
        Some("2024-08-02")
    );
    assert!(
        attrs
            .get("tombstoned_note")
            .is_some_and(|n| n.contains("append-only"))
    );
    // The handle the deleted account went by survives, which is the whole point.
    find(&ents, &EntityKind::Username, "ghost");
}

#[test]
fn a_nullified_operation_contributes_nothing_but_is_reported() {
    // The classic takeover shape: an attacker rewrites the handle and hosting
    // server, and the rightful key holders revert it inside the recovery window.
    let ents = entities(&log(r#"[
      {"createdAt": "2023-05-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "create", "handle": "victim.bsky.social", "service": "https://bsky.social"}},
      {"createdAt": "2024-03-09T11:22:33.000Z", "nullified": true, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://attacker-owned.example"],
        "services": {"atproto_pds": {"endpoint": "https://evil.example"}},
        "rotationKeys": ["did:key:zQ3shATTACKERKEYzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]}},
      {"createdAt": "2024-03-09T12:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://victim.bsky.social"],
        "services": {"atproto_pds": {"endpoint": "https://bsky.social"}}}}
    ]"#));

    // Folding the reverted state in would attribute to the subject a name and a
    // server that were never legitimately theirs.
    let vals: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
    assert!(!vals.contains(&"attacker-owned.example"));
    assert!(!vals.contains(&"evil.example"));
    assert!(!vals.iter().any(|v| v.contains("ATTACKERKEY")));

    // But the reversal itself is a finding, not something to swallow.
    let did = find(&ents, &EntityKind::Other(DID_KIND.into()), DID);
    assert!(did.has_tag("plc-recovery"));
    let attrs = &did.evidence[0].attributes;
    assert_eq!(
        attrs.get("nullified_operations").map(String::as_str),
        Some("1")
    );
    assert!(
        attrs
            .get("nullified_note")
            .is_some_and(|n| n.contains("unauthorised"))
    );
    // Nullified entries still count as operations on record.
    assert_eq!(attrs.get("plc_operations").map(String::as_str), Some("3"));
}

#[test]
fn a_casing_change_is_not_reported_as_a_rename() {
    // Handles are case-insensitive in AT Protocol; a re-cased handle is the same
    // name, and reporting it as a former one would invent an alias.
    let ents = entities(&log(r#"[
      {"createdAt": "2023-01-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "create", "handle": "Alice.BSKY.social", "service": "https://bsky.social"}},
      {"createdAt": "2024-01-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://alice.bsky.social"]}}
    ]"#));

    let usernames: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(usernames, vec!["alice"]);
    conf_eq(
        find(&ents, &EntityKind::Username, "alice"),
        confidence::HIGH_PLUSPLUS_PLUS,
    );
}

#[test]
fn a_reclaimed_handle_reports_the_window_its_use_spans() {
    // Observed live on `retr0.id`: dropped for a proxy handle, then reclaimed.
    // The window is first- and last-*observed*, and the gap inside it is the
    // log's, not an assertion of continuous use.
    let ents = entities(&log(r#"[
      {"createdAt": "2023-06-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "create", "handle": "retr0.id", "service": "https://bsky.social"}},
      {"createdAt": "2024-02-14T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://retr0-id.translate.goog"]}},
      {"createdAt": "2025-09-30T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://retr0.id"]}}
    ]"#));

    let d = find(&ents, &EntityKind::Domain, "retr0.id");
    let attrs = &d.evidence[0].attributes;
    assert_eq!(
        attrs.get("first_seen").map(String::as_str),
        Some("2023-06-01")
    );
    assert_eq!(
        attrs.get("last_seen").map(String::as_str),
        Some("2025-09-30")
    );
    assert_eq!(
        attrs.get("handle_state").map(String::as_str),
        Some("current")
    );

    // The Google Translate proxy satisfies handle verification for a domain
    // Google owns — a known loophole, never the subject's infrastructure.
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "retr0-id.translate.goog")
    );
    find(&ents, &EntityKind::Username, "retr0-id");
}

#[test]
fn an_operation_that_declares_nothing_invents_nothing() {
    let ents = entities(&log(r#"[
      {"createdAt": "2023-01-01T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": [], "rotationKeys": []}},
      {"createdAt": "2023-01-02T00:00:00.000Z", "nullified": false},
      {"createdAt": "2023-01-03T00:00:00.000Z", "nullified": false, "operation": {
        "type": "plc_operation", "alsoKnownAs": ["at://"],
        "services": {"atproto_pds": {"endpoint": "   "}}}}
    ]"#));

    // Only the DID itself, which the log does establish.
    assert_eq!(values(&ents).len(), 1, "{:?}", values(&ents));
    let attrs = did_attrs(&ents);
    assert_eq!(attrs.get("handles_observed").map(String::as_str), Some("0"));
    assert_eq!(attrs.get("pds_observed").map(String::as_str), Some("0"));
    assert!(!attrs.contains_key("current_handle"));
    assert!(!attrs.contains_key("current_pds"));
}

#[test]
fn an_entry_without_a_timestamp_does_not_get_an_invented_date() {
    let ents = entities(&log(r#"[
      {"nullified": false, "operation": {
        "type": "create", "handle": "nodate.bsky.social", "service": "https://bsky.social"}}
    ]"#));

    let attrs = did_attrs(&ents);
    assert!(!attrs.contains_key("account_created"));
    let u = find(&ents, &EntityKind::Username, "nodate");
    assert!(!u.evidence[0].attributes.contains_key("first_seen"));
    assert!(!u.evidence[0].attributes.contains_key("last_seen"));
}

#[test]
fn a_web_did_yields_its_anchor_domain_and_admits_it_has_no_log() {
    let ents = web_did_entities("did:web:example.com", "example.com", "scan-1");

    let d = find(&ents, &EntityKind::Domain, "example.com");
    conf_eq(d, confidence::HIGH_PLUSPLUS);
    assert!(d.has_tag("did-web"));
    assert!(
        d.evidence[0]
            .attributes
            .get("coverage")
            .is_some_and(|c| c.contains("NO PLC audit log")),
        "absence of history must not read as absence of a history"
    );

    let id = find(
        &ents,
        &EntityKind::Other(DID_KIND.into()),
        "did:web:example.com",
    );
    assert_eq!(
        id.evidence[0]
            .attributes
            .get("did_method")
            .map(String::as_str),
        Some("web")
    );
}

#[test]
fn every_cap_reports_what_it_dropped() {
    // Pathological, but a cap that fires silently turns a partial enumeration
    // into what reads as a complete one.
    let h = History {
        ops: 99,
        handles: (0..MAX_HANDLES + 10)
            .map(|i| Spell {
                value: format!("user{i}.bsky.social"),
                first_seen: "2023-01-01".into(),
                last_seen: "2024-01-01".into(),
            })
            .collect(),
        current_handles: vec!["user0.bsky.social".into()],
        pds: (0..MAX_PDS + 5)
            .map(|i| Spell {
                value: format!("pds{i}.example.org"),
                first_seen: String::new(),
                last_seen: String::new(),
            })
            .collect(),
        current_pds: Some("pds0.example.org".into()),
        rotation_keys: (0..MAX_ROTATION_KEYS + 2)
            .map(|i| format!("did:key:zQ3sh{i}"))
            .collect(),
        ..History::default()
    };

    let ents = history_to_entities(DID, &h, "scan-1");
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Username)
            .count(),
        MAX_HANDLES
    );
    assert_eq!(
        ents.iter().filter(|e| e.kind == EntityKind::Domain).count(),
        MAX_PDS
    );
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Other(ROTATION_KEY_KIND.into()))
            .count(),
        MAX_ROTATION_KEYS
    );

    let attrs = did_attrs(&ents);
    for key in [
        "handles_truncated",
        "pds_truncated",
        "rotation_keys_truncated",
    ] {
        assert!(
            attrs.get(key).is_some_and(|v| v.contains("NOT")),
            "{key} must say what was left out"
        );
    }
    // And the true totals stay legible next to the truncation notes.
    let handles_total = (MAX_HANDLES + 10).to_string();
    let pds_total = (MAX_PDS + 5).to_string();
    assert_eq!(attrs.get("handles_observed"), Some(&handles_total));
    assert_eq!(attrs.get("pds_observed"), Some(&pds_total));
}

#[test]
fn the_did_entity_is_emitted_last_so_it_can_report_the_walk() {
    let ents = entities(&bnewbold());
    let last = ents.last().expect("non-empty");
    assert_eq!(last.kind, EntityKind::Other(DID_KIND.into()));
    assert_eq!(last.value, DID);
    conf_eq(last, confidence::VERY_HIGH_PLUSPLUS);
    // Same discriminant string `bluesky_user` emits, so the two modules
    // corroborate one entity under noisy-OR rather than producing two spellings
    // of the same identifier that never meet.
    assert_eq!(DID_KIND, "bluesky-did");
    assert!(last.has_tag("did"));
    assert!(last.has_tag("account-age"));
}
