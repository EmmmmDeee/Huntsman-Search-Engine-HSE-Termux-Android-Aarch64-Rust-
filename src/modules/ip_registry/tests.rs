use crate::core::entity::{Entity, EntityKind};
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

use super::types::{AutnumResp, RdapResp};
use super::{IpRegistry, build_autnum_entities, build_rdap_entities, rdap_lookup_asn};

fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

#[test]
fn accepts_ip_and_asn() {
    let m = IpRegistry;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(m.accepts(&Target::new(TargetKind::Asn, "AS15169")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}

#[test]
fn priority_and_timeout() {
    let m = IpRegistry;
    assert_eq!(m.priority(), 23);
    assert_eq!(m.max_timeout_ms(), 8_000);
}

#[test]
fn parse_arin_rdap_response() {
    let raw = r#"{
      "handle":"NET-8-8-8-0-1",
      "name":"LVLT-GOGL-8-8-8",
      "country":"US",
      "startAddress":"8.8.8.0",
      "endAddress":"8.8.8.255",
      "ipVersion":"v4",
      "parentHandle":"NET-8-0-0-0-0",
      "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
      "events":[
        {"eventAction":"last changed","eventDate":"2014-03-14T16:52:05-04:00"},
        {"eventAction":"registration","eventDate":"2014-03-14T16:52:05-04:00"}
      ]
    }"#;
    let r: RdapResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(r.handle.as_deref(), Some("NET-8-8-8-0-1"));
    assert_eq!(r.country.as_deref(), Some("US"));
    assert_eq!(r.cidr0_cidrs.len(), 1);
    assert_eq!(r.events.len(), 2);
}

// ── build_rdap_entities (pure) ──────────────────────────────────────

fn rdap(json: &str) -> RdapResp {
    serde_json::from_str(json).expect("valid RdapResp fixture")
}

#[test]
fn rdap_full_record_maps_cidr_country_and_events() {
    let body = rdap(
        r#"{
          "handle":"NET-8-8-8-0-1", "name":"LVLT-GOGL-8-8-8", "country":"us",
          "ipVersion":"v4", "parentHandle":"NET-8-0-0-0-0",
          "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
          "events":[{"eventAction":"last changed","eventDate":"2014-03-14"}]
        }"#,
    );
    let ents = build_rdap_entities(&body, "8.8.8.0", "s");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert_eq!(e.kind, EntityKind::IpAddress);
    assert!(e.has_tag("rdap"));
    assert!(e.has_tag("country:US"), "country tag is uppercased");

    let ev = &e.evidence[0];
    let attr = |k: &str| ev.attributes.get(k).map(String::as_str);
    assert_eq!(attr("handle"), Some("NET-8-8-8-0-1"));
    assert_eq!(attr("prefix"), Some("8.8.8.0/24"));
    assert_eq!(attr("ip_version"), Some("v4"));
    assert_eq!(attr("parent_handle"), Some("NET-8-0-0-0-0"));
    // The space in the action becomes an underscore in the key.
    assert_eq!(attr("event:last_changed"), Some("2014-03-14"));
}

#[test]
fn rdap_prefix_falls_back_to_address_range() {
    let body = rdap(r#"{ "startAddress":"8.8.8.0", "endAddress":"8.8.8.255" }"#);
    let ev = &build_rdap_entities(&body, "8.8.8.0", "s")[0].evidence[0];
    assert_eq!(
        ev.attributes.get("prefix").map(String::as_str),
        Some("8.8.8.0 – 8.8.8.255")
    );
}

#[test]
fn rdap_blank_country_adds_no_tag_or_attr() {
    let body = rdap(r#"{ "country":"" }"#);
    let e = &build_rdap_entities(&body, "1.2.3.4", "s")[0];
    assert!(!e.tags.iter().any(|t| t.starts_with("country:")));
    assert!(!e.evidence[0].attributes.contains_key("country"));
}

#[test]
fn rdap_no_contacts_yields_only_the_ip_entity() {
    // A record with no `entities` array must still produce exactly the one
    // IpAddress entity — the nested-contact mining is purely additive.
    let body = rdap(r#"{ "handle":"NET-1", "country":"US" }"#);
    let ents = build_rdap_entities(&body, "1.2.3.4", "s");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::IpAddress);
}

// A trimmed ARIN-shaped record: a registrant (org kind) that itself nests an
// abuse contact and a technical/administrative contact — the real RDAP shape.
// Deliberately NOT google.com: that domain is in `INFRA_PROVIDER_ROOTS` by design (see
// `rdap_suppresses_infra_mail_domain_abuse_email`), which would suppress every
// contact regardless of local-part and defeat the point of this fixture —
// exercising the nested-entity walk itself.
const RDAP_WITH_CONTACTS: &str = r#"{
  "handle":"NET-8-8-8-0-2", "name":"ACME", "country":"US", "ipVersion":"v4",
  "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
  "entities":[{
    "handle":"ACME", "roles":["registrant"],
    "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Acme Hosting LLC"],["kind",{},"text","org"]]],
    "entities":[
      {"handle":"ABUSE5250-ARIN","roles":["abuse"],
       "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["kind",{},"text","group"],["email",{},"text","netops-desk@acmehosting.example"]]]},
      {"handle":"ZG39-ARIN","roles":["technical","administrative"],
       "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Acme Hosting LLC"],["kind",{},"text","group"],["email",{},"text","arin-contact@acmehosting.example"]]]}
    ]
  }]
}"#;

#[test]
fn rdap_mines_registrant_org_and_nested_abuse_email() {
    let ents = build_rdap_entities(&rdap(RDAP_WITH_CONTACTS), "8.8.8.8", "s");
    // IpAddress + registrant Organisation + abuse Email.
    assert_eq!(ents.len(), 3);

    let org = of_kind(&ents, EntityKind::Organisation).expect("registrant org");
    assert_eq!(org.value, "Acme Hosting LLC");
    assert!(org.has_tag("ip-registrant") && org.has_tag("rdap"));
    assert_eq!(
        org.evidence[0].attributes.get("ip").map(String::as_str),
        Some("8.8.8.8")
    );

    // The abuse contact is nested one level under the registrant — the walk
    // must recurse to reach it.
    let email = of_kind(&ents, EntityKind::Email).expect("abuse email");
    assert_eq!(email.value, "netops-desk@acmehosting.example");
    assert!(email.has_tag("role:abuse") && email.has_tag("rdap-contact"));
    assert_eq!(
        email.evidence[0]
            .attributes
            .get("contact_role")
            .map(String::as_str),
        Some("abuse")
    );

    // Technical/administrative contact emails are deliberately NOT surfaced —
    // only the abuse role, which is never GDPR-redacted for IP allocations.
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "arin-contact@acmehosting.example"),
        "only the abuse-role email is emitted"
    );
}

#[test]
fn rdap_suppresses_role_local_part_abuse_email() {
    // A registrar/provider abuse desk (`abuse@`) is infrastructure contact,
    // not the subject's own mail — the same false-positive class
    // `whois`/`dns_intel` already gate on via `is_infrastructure_email`.
    // Regression test for the audit finding (role-mailbox-as-pii) that RDAP
    // abuse contacts previously bypassed that gate entirely.
    let body = rdap(
        r#"{ "handle":"NET-8-8-8-0-2", "entities":[{
            "handle":"ABUSE5250-ARIN","roles":["abuse"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["kind",{},"text","group"],["email",{},"text","abuse@acmehosting.example"]]]
        }] }"#,
    );
    let ents = build_rdap_entities(&body, "8.8.8.8", "s");
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Email),
        "a role-local-part abuse contact must not surface as an Email entity"
    );
}

#[test]
fn rdap_suppresses_infra_mail_domain_abuse_email() {
    // google.com is in `INFRA_PROVIDER_ROOTS` by design — its abuse desk is provider
    // infrastructure regardless of local-part. A non-role local-part
    // (`network-ops`, not `abuse`) confirms the domain match alone is
    // sufficient to gate it.
    let body = rdap(
        r#"{ "handle":"NET-8-8-8-0-2", "entities":[{
            "handle":"ABUSE5250-ARIN","roles":["abuse"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["kind",{},"text","group"],["email",{},"text","network-ops@google.com"]]]
        }] }"#,
    );
    let ents = build_rdap_entities(&body, "8.8.8.8", "s");
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Email),
        "a contact on an INFRA_PROVIDER_ROOTS-listed domain must not surface as an Email entity, \
         regardless of local-part"
    );
}

#[test]
fn rdap_individual_registrant_is_not_emitted_as_org() {
    // A natural-person registrant (vCard kind=individual) must never surface as
    // an Organisation, even though IP blocks are normally operator-held.
    let body = rdap(
        r#"{ "handle":"NET-X", "entities":[{
            "roles":["registrant"],
            "vcardArray":["vcard",[["fn",{},"text","Jane Q Public"],["kind",{},"text","individual"]]]
        }] }"#,
    );
    let ents = build_rdap_entities(&body, "1.2.3.4", "s");
    assert!(
        of_kind(&ents, EntityKind::Organisation).is_none(),
        "individual-kind registrant is not an Organisation"
    );
    assert_eq!(ents.len(), 1, "only the IpAddress entity remains");
}

#[test]
fn rdap_abuse_contact_with_non_email_vcard_yields_no_email() {
    // An abuse contact whose vCard email field is malformed is dropped.
    let body = rdap(
        r#"{ "entities":[{
            "roles":["abuse"],
            "vcardArray":["vcard",[["email",{},"text","not-an-email"]]]
        }] }"#,
    );
    let ents = build_rdap_entities(&body, "1.2.3.4", "s");
    assert!(of_kind(&ents, EntityKind::Email).is_none());
}

// ── build_autnum_entities (pure) — fixtures captured from the live RIRs on
//    2026-09-15 via https://rdap.arin.net/registry/autnum/{n}, trimmed to the
//    fields this module reads (structure and values verbatim) ────────────────

/// ARIN's own answer for AS15169 (Google): one `org`-kind registrant with the
/// abuse and technical desks nested beneath it.
const ARIN_AS15169: &str = r#"{"objectClassName":"autnum","handle":"AS15169","name":"GOOGLE","startAutnum":15169,"endAutnum":15169,"status":["active"],"port43":"whois.arin.net","events":[{"eventAction":"last changed","eventDate":"2012-02-24T09:44:34-05:00"},{"eventAction":"registration","eventDate":"2000-03-30T00:00:00-05:00"}],"entities":[{"handle":"GOGL","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"],["kind",{},"text","org"]]],"entities":[{"handle":"ABUSE5250-ARIN","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["org",{},"text","Google Inc."],["kind",{},"text","group"],["email",{},"text","network-abuse@google.com"]]]},{"handle":"ZG39-ARIN","roles":["administrative","technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"],["org",{},"text","Google LLC"],["kind",{},"text","group"],["email",{},"text","arin-contact@google.com"]]]}]},{"handle":"ZG39-ARIN","roles":["technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"],["org",{},"text","Google LLC"],["kind",{},"text","group"],["email",{},"text","arin-contact@google.com"]]]}]}"#;

/// RIPE's answer for AS3320 (Deutsche Telekom), reached through ARIN's
/// redirect: several `registrant`-role entities — the organisation plus the
/// maintainer / routing-registry handles marked `kind: individual`.
const RIPE_AS3320: &str = r#"{"objectClassName":"autnum","handle":"AS3320","name":"DTAG","startAutnum":3320,"endAutnum":3320,"status":["active"],"port43":"whois.ripe.net","events":[{"eventAction":"registration","eventDate":"1970-01-01T00:00:00Z"},{"eventAction":"last changed","eventDate":"2020-12-11T15:33:02Z"}],"entities":[{"handle":"DTAG-RR","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","DTAG-RR"],["kind",{},"text","individual"]]]},{"handle":"ORG-DTA2-RIPE","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Deutsche Telekom AG"],["kind",{},"text","org"]]]},{"handle":"RIPE-NCC-END-MNT","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE-NCC-END-MNT"],["kind",{},"text","individual"],["org",{},"text","ORG-NCC1-RIPE"]]]},{"handle":"SB15220-RIPE","roles":["administrative","technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Sebastian Becker"],["kind",{},"text","individual"]]]},{"handle":"DTAG3-RIPE","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Deutsche Telekom LIR Abuse Contact"],["kind",{},"text","group"],["email",{"type":"abuse"},"text","abuse@telekom.de"]]],"entities":[{"handle":"DTAG-NIC","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","DTAG-NIC"],["kind",{},"text","individual"]]]},{"handle":"DTAG1-RIPE","roles":["administrative","technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","DTAG Internet Routing Registry"],["kind",{},"text","group"]]]}]}]}"#;

fn autnum(json: &str) -> AutnumResp {
    serde_json::from_str(json).expect("valid autnum fixture")
}

#[test]
fn arin_autnum_yields_the_registered_asn_and_its_operator() {
    let ents = build_autnum_entities(&autnum(ARIN_AS15169), 15169, "s");
    let asn = of_kind(&ents, EntityKind::Asn).expect("the ASN registry entity");
    assert_eq!(asn.value, "AS15169");
    assert!(asn.has_tag("registered") && asn.has_tag("rdap"));
    let ev = &asn.evidence[0];
    assert_eq!(
        ev.attributes.get("handle").map(String::as_str),
        Some("AS15169")
    );
    assert_eq!(
        ev.attributes.get("name").map(String::as_str),
        Some("GOOGLE")
    );
    assert_eq!(
        ev.attributes.get("status").map(String::as_str),
        Some("active")
    );
    assert_eq!(
        ev.attributes.get("registry").map(String::as_str),
        Some("whois.arin.net")
    );
    assert_eq!(
        ev.attributes.get("event:registration").map(String::as_str),
        Some("2000-03-30T00:00:00-05:00")
    );
    assert!(
        !ev.attributes.contains_key("range"),
        "a single-number autnum has no range"
    );

    let org = of_kind(&ents, EntityKind::Organisation).expect("the operator organisation");
    assert_eq!(org.value, "Google LLC");
    assert!(org.has_tag("asn-operator") && org.has_tag("rdap"));
    assert_eq!(org.evidence[0].source, "ip_registry");
    // Nothing this module no longer has a source for is fabricated.
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Url),
        "RDAP carries no website"
    );
}

#[test]
fn ripe_autnum_picks_the_org_kind_registrant_never_a_maintainer_handle() {
    let ents = build_autnum_entities(&autnum(RIPE_AS3320), 3320, "s");
    let asn = of_kind(&ents, EntityKind::Asn).expect("the ASN registry entity");
    assert_eq!(asn.value, "AS3320");
    assert_eq!(
        asn.evidence[0]
            .attributes
            .get("registry")
            .map(String::as_str),
        Some("whois.ripe.net"),
        "the RIR that answered after ARIN's redirect is named"
    );
    let orgs: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(
        orgs,
        vec!["Deutsche Telekom AG"],
        "DTAG-RR / RIPE-NCC-END-MNT are individual-kind maintainer handles, not organisations"
    );
    // `abuse@telekom.de` is a role local-part — infrastructure contact, gated
    // out exactly as the allocation path gates its abuse desk.
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::Email),
        "no Email may be minted from a role mailbox: {ents:?}"
    );
}

#[test]
fn autnum_contacts_are_role_tagged_deduplicated_and_gated() {
    // SYNTHETIC contact tree in the RIR's shape (the authentic fixtures' only
    // contact mailboxes are role local-parts, which the gate drops): a named
    // person on a non-provider domain is emitted with the role they hold, a
    // mailbox listed under two roles is emitted once, and the role/provider gate
    // still holds — `network-abuse@` carries the system-role segment `abuse`
    // and `hostmaster@` is a role local-part, so neither is minted.
    let raw = r#"{"objectClassName":"autnum","handle":"AS64500","name":"EXAMPLE-NET","startAutnum":64500,"endAutnum":64501,"status":["active"],"port43":"whois.example.net",
      "entities":[
        {"handle":"EX-ORG","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Networks Pty Ltd"],["kind",{},"text","org"]]],
         "entities":[
           {"handle":"EX-ABUSE","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Network Abuse Desk"],["kind",{},"text","group"],["email",{},"text","network-abuse@example-networks.net"]]]},
           {"handle":"EX-ABUSE-P","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","J. Citizen"],["kind",{},"text","individual"],["email",{},"text","J.Citizen@example-networks.net"]]]},
           {"handle":"EX-OPS","roles":["administrative","technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Ops"],["kind",{},"text","group"],["email",{},"text","Ops-Team@example-networks.net"]]]},
           {"handle":"EX-HM","roles":["technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Hostmaster"],["kind",{},"text","group"],["email",{},"text","hostmaster@example-networks.net"]]]}
         ]}
      ]}"#;
    let ents = build_autnum_entities(&autnum(raw), 64500, "s");
    let asn = of_kind(&ents, EntityKind::Asn).expect("asn");
    assert_eq!(
        asn.evidence[0].attributes.get("range").map(String::as_str),
        Some("AS64500-AS64501"),
        "a block of numbers is recorded as its range"
    );
    let mut emails: Vec<(String, Vec<String>)> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| {
            let mut roles: Vec<String> = e
                .tags
                .iter()
                .filter(|t| t.starts_with("role:"))
                .cloned()
                .collect();
            roles.sort();
            (e.value.clone(), roles)
        })
        .collect();
    emails.sort();
    assert_eq!(
        emails,
        vec![
            (
                "j.citizen@example-networks.net".to_string(),
                vec!["role:abuse".to_string()]
            ),
            (
                "ops-team@example-networks.net".to_string(),
                vec!["role:admin".to_string()]
            ),
        ],
        "the named abuse contact carries its role; the ops mailbox is emitted once (admin, its \
         first role) and lowercased; network-abuse@ and hostmaster@ are gated out"
    );
    assert!(emails.iter().all(|(_, roles)| roles.len() == 1));
    let org = of_kind(&ents, EntityKind::Organisation).expect("operator");
    assert_eq!(org.value, "Example Networks Pty Ltd");
}

#[test]
fn autnum_with_no_contacts_yields_only_the_asn_entity() {
    let ents = build_autnum_entities(
        &autnum(
            r#"{"objectClassName":"autnum","handle":"AS64496","startAutnum":64496,"endAutnum":64496}"#,
        ),
        64496,
        "s",
    );
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Asn);
    assert!(!ents[0].evidence[0].attributes.contains_key("status"));
}

/// The transport half against a loopback RDAP: a genuine record parses, a 404
/// is the clean "no such autnum", and any other failure is the module's error.
#[tokio::test]
async fn rdap_lookup_asn_parses_a_record_and_classifies_404_and_failures() {
    use crate::util::http::test_server::{Canned, serve};
    let client = reqwest::Client::new();
    let base = serve(vec![
        Canned::json(200, ARIN_AS15169),
        Canned::json(404, r#"{"errorCode":404,"title":"Not Found"}"#),
        Canned::text(503, "Service Unavailable"),
    ])
    .await;
    let r = rdap_lookup_asn(&client, &base, 15169, "s")
        .await
        .expect("a genuine autnum record");
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Asn && e.value == "AS15169")
    );
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.value == "Google LLC")
    );

    let r = rdap_lookup_asn(&client, &base, 64496, "s")
        .await
        .expect("RDAP's 404 is the clean negative");
    assert!(r.is_empty());

    let err = rdap_lookup_asn(&client, &base, 15169, "s")
        .await
        .expect_err("an outage is the module's error, not an empty registry");
    assert!(err.to_string().contains("503"), "{err}");
}
