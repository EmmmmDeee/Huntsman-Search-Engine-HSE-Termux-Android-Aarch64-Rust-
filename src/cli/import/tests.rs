//! Unit tests for the import parsers and persistence.
//!
//! Split out of the module file; reaches private parsers/helpers via
//! `use super::*` (each parser is re-exported into the parent's scope).

use super::{deduplicate_by_uid, entities_from_upload, looks_like_dossier, parse_dossier};

/// The upload dispatcher parses UNTRUSTED text from the web endpoint, so it
/// must never panic — not on truncation, not on a multibyte codepoint landing
/// next to a structural marker (`@`, `->`, `•`, `:`, a section header), not on
/// malformed JSON/HTML. This pins that contract: every hostile input returns
/// Ok/Err, never unwinds. (Panic = abort is off, but a 500 from a paste is
/// still a defect.)
#[tokio::test]
async fn upload_dispatcher_never_panics_on_adversarial_input() {
    let bomb = "é".repeat(4000); // multibyte filler
    let cases: Vec<String> = vec![
            String::new(),
            " \t\n ".into(),
            "@".into(),
            "->".into(),
            "\u{2022}".into(),                                   // lone bullet
            "Entry #".into(),                                    // truncated header
            "Entry #\u{2022}:é".into(),                          // bullet+multibyte at header
            format!("Entry #1:\n   \u{2022} email: {bomb}@"),    // dangling local@
            format!("EMAILS:\n  -> {bomb}@{bomb}"),              // huge no-TLD email
            "USERNAMES:\n->".into(),                             // empty list item
            "\u{2022} : value".into(),                           // empty key
            "URL: \nUsername: \nPassword: ".into(),              // empty TXT fields
            "=== INFECTED MACHINES".into(),                      // section marker, no body
            "=== OSINT ENRICHMENT\nIP: \nlat: zzz\nlon: ".into(),// bad geo numbers
            "{".into(),                                          // truncated JSON
            "{}".into(),
            r#"{"searchResults":{"MULTI_SERVICE_RESULTS":{"breach":{"data":{"results":[null,1,"x"]}}}}}"#.into(),
            r#"{"stealerData":{"victims":[{"device_ips":[1,null,"1.2.3.4"]}]}}"#.into(),
            "<html>".into(),
            format!("<html>{bomb}@{bomb}.com http://{bomb}</html>"),
            // Section markers butted against multibyte text.
            format!("PASSWORDS:é\n-> é{bomb}"),
            "Entry #1:\n   \u{2022} name: é\n   \u{2022} hash: $2a$".into(),
        ];
    for (i, input) in cases.iter().enumerate() {
        // The await completing at all is the assertion — a panic would unwind
        // through here and fail the test.
        let r = entities_from_upload(input, "fuzz").await;
        // Whatever the outcome, entities (if any) must be well-formed.
        if let Ok((ents, _)) = r {
            for e in &ents {
                assert!(
                    !e.value.is_empty(),
                    "case {i}: produced an empty-value entity"
                );
            }
        }
    }
}

#[tokio::test]
async fn upload_dispatcher_routes_every_format_to_its_parser() {
    use crate::core::entity::EntityKind;
    let has = |ents: &[crate::core::entity::Entity], k: EntityKind, v: &str| {
        ents.iter().any(|e| e.kind == k && e.value == v)
    };

    // HTML export → regex extraction of domains/emails/IPs.
    let (html, label) = entities_from_upload(
        "<html><body>contact me at jo@acme-corp.com on acme-corp.com</body></html>",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "oathnet-html");
    assert!(has(&html, EntityKind::Email, "jo@acme-corp.com"));

    // Dossier compilation → per-entry correlation.
    let (dos, label) = entities_from_upload(
        "Entry #1:\n   \u{2022} email: isaacfrost@gmail.com\n   \u{2022} name: Isaac Frost\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "dossier");
    assert!(has(&dos, EntityKind::Email, "isaacfrost@gmail.com"));
    assert!(has(&dos, EntityKind::Person, "Isaac Frost"));

    // OathNet stealer-log TXT → the catch-all text branch.
    let (txt, label) = entities_from_upload(
        "URL: https://admin.target.io/login\nUsername: victim\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "oathnet-txt");
    assert!(txt.iter().any(|e| e.kind == EntityKind::Url));

    // JSON API export → parsed (and the label proves the branch).
    let (_json, label) =
        entities_from_upload(r#"{"exportInfo":{"query":"x"},"searchResults":{}}"#, "s")
            .await
            .unwrap();
    assert_eq!(label, "oathnet-json");

    // Malformed JSON is a clean error, not a panic.
    assert!(entities_from_upload("{ not valid json", "s").await.is_err());
}
use crate::core::entity::{Entity, EntityKind};

// The exact shape of the user-provided "Isaac Frost.txt" dossier upload.
const DOSSIER: &str = "http://www.linkedin.com/in/isaac-frost-42474a122
    Entry #82:
       \u{2022} username: zacfrost512
       \u{2022} email: zacfrost512@gmail.com
       \u{2022} name: Isaac Frost
       \u{2022} _domain: gmail.com
       \u{2022} ip: 8.8.8.8
       \u{2022} phone: +61412345678
       \u{2022} id: 9540629
       \u{2022} created: 2016-02-19 15:57:12
       \u{2022} language: en
    Entry #85:
       \u{2022} username: IsaacFrost6
       \u{2022} email: frostisms@gmail.com
       \u{2022} name: Isaac Frost
       \u{2022} domain: derbyrock.com
       \u{2022} ip: 203.0.113.45
       \u{2022} birthdate: 2002-11-17
       \u{2022} country: GB
       \u{2022} gender: M
       \u{2022} hash: $2a$10$id3HAw6TcOjKvPH/RK7MS.
USERNAMES:
  -> isaac frost
  -> a_frost_life
  -> isaac@derbyrock.com
EMAILS:
  -> betocastillo097@gmail.com
  -> @gmail
PASSWORDS:
  -> 00346D91DD87C74089F3BFA88E13DE8101000000DCB6
";

#[test]
fn dossier_is_detected_and_oathnet_txt_is_not() {
    assert!(looks_like_dossier(DOSSIER));
    assert!(!looks_like_dossier(
        "URL: https://x.com/login\nUsername: bob\nPassword: hunter2\n"
    ));
}

#[test]
fn dossier_parse_yields_correlated_individualised_entities() {
    let (mut ents, stats) = parse_dossier(DOSSIER, "sid");
    deduplicate_by_uid(&mut ents);
    let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

    // Entry-derived identity, fully parsed (not fragments).
    assert!(has(EntityKind::Email, "zacfrost512@gmail.com"));
    assert!(has(EntityKind::Username, "zacfrost512"));
    assert!(has(EntityKind::Person, "Isaac Frost"));
    assert!(has(
        EntityKind::Url,
        "http://www.linkedin.com/in/isaac-frost-42474a122"
    ));
    // Password hash is a Credential, never a Password.
    assert!(has(EntityKind::Credential, "$2a$10$id3HAw6TcOjKvPH/RK7MS."));
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Password));

    // Section lists folded in; an email appears in the USERNAMES list too.
    assert!(has(EntityKind::Email, "betocastillo097@gmail.com"));
    assert!(has(EntityKind::Email, "isaac@derbyrock.com"));
    assert!(has(EntityKind::Username, "a_frost_life"));

    // The `@gmail` fragment is rejected, never surfaced.
    assert!(!ents.iter().any(|e| e.value == "@gmail"));
    // The freemail `_domain` is NOT emitted as a bare Domain entity.
    assert!(!has(EntityKind::Domain, "gmail.com"));

    // `ip`/`phone`/`domain` entry fields are first-class pivotable seeds — the
    // text path now matches the JSON importer's coverage. Each is validated:
    // a routable IP, a corporate domain and an E.164 phone are kept…
    assert!(has(EntityKind::IpAddress, "8.8.8.8"));
    assert!(has(EntityKind::Phone, "+61412345678"));
    assert!(has(EntityKind::Domain, "derbyrock.com"));
    // …while a documentation-range IP (RFC 5737) is rejected as bogus, never
    // becoming a high-confidence false seed.
    assert!(!has(EntityKind::IpAddress, "203.0.113.45"));

    // Individualised: the per-entry evidence carries the FULL record, so
    // birthdate/country/gender are verifiable on the finding, not lost.
    let frost = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "frostisms@gmail.com")
        .expect("entry #85 email");
    let attrs = &frost.evidence[0].attributes;
    assert_eq!(
        attrs.get("birthdate").map(String::as_str),
        Some("2002-11-17")
    );
    assert_eq!(attrs.get("country").map(String::as_str), Some("GB"));
    assert_eq!(attrs.get("gender").map(String::as_str), Some("M"));
    assert_eq!(attrs.get("name").map(String::as_str), Some("Isaac Frost"));
    // The hash is NOT echoed into a benign attribute.
    assert!(!attrs.contains_key("hash"));

    // The PASSWORDS: section's `-> <hex hash>` becomes a Credential too — a
    // major part of the real file, distinct from the per-entry `hash:` field.
    assert!(
        has(
            EntityKind::Credential,
            "00346D91DD87C74089F3BFA88E13DE8101000000DCB6"
        ),
        "a PASSWORDS-section hex hash must be parsed as a Credential"
    );

    // Two distinct credentials: the entry's bcrypt hash + the PASSWORDS hex.
    assert!(stats.persons >= 1 && stats.credentials >= 2 && stats.emails >= 3);
}

#[test]
fn finalize_drops_bogus_ips_keeps_real_and_private_and_dedups() {
    let sid = "import-test";
    let mut v = vec![
        Entity::new(EntityKind::IpAddress, "192.0.2.1", 0.6, sid), // doc -> drop
        Entity::new(EntityKind::IpAddress, "203.0.113.9", 0.6, sid), // doc -> drop
        Entity::new(EntityKind::IpAddress, "240.0.0.1", 0.6, sid), // reserved -> drop
        Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.6, sid),   // real -> keep
        Entity::new(EntityKind::IpAddress, "192.168.1.5", 0.6, sid), // private -> keep
        Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.6, sid),   // dup -> deduped
        Entity::new(EntityKind::Email, "x@b.com", 0.6, sid),       // non-IP untouched
    ];
    deduplicate_by_uid(&mut v);
    let vals: Vec<&str> = v.iter().map(|e| e.value.as_str()).collect();

    for bogus in ["192.0.2.1", "203.0.113.9", "240.0.0.1"] {
        assert!(
            !vals.contains(&bogus),
            "bogus {bogus} must be dropped: {vals:?}"
        );
    }
    assert_eq!(
        vals.iter().filter(|x| **x == "8.8.8.8").count(),
        1,
        "real IP kept exactly once (deduped)"
    );
    assert!(vals.contains(&"192.168.1.5"), "private IP kept");
    assert!(vals.contains(&"x@b.com"), "non-IP entity untouched");
}

#[test]
fn finalize_drops_ip_literals_mis_classified_as_domains() {
    let sid = "import-test";
    let mut v = vec![
        Entity::new(EntityKind::Domain, "8.8.8.8", 0.45, sid), // IP-as-domain -> drop
        Entity::new(EntityKind::Domain, "192.0.2.1", 0.45, sid), // doc-IP-as-domain -> drop
        Entity::new(EntityKind::Domain, "evil.com", 0.50, sid), // real domain -> keep
        Entity::new(EntityKind::Domain, "sub.evil.com", 0.45, sid), // real subdomain -> keep
    ];
    deduplicate_by_uid(&mut v);
    let vals: Vec<&str> = v.iter().map(|e| e.value.as_str()).collect();
    assert!(
        !vals.contains(&"8.8.8.8"),
        "IP literal must not be a domain: {vals:?}"
    );
    assert!(
        !vals.contains(&"192.0.2.1"),
        "doc-IP literal must not be a domain"
    );
    assert!(vals.contains(&"evil.com"), "real domain kept");
    assert!(vals.contains(&"sub.evil.com"), "real subdomain kept");
}

#[test]
fn import_txt_survives_misordered_section_markers() {
    // Regression: a crafted TXT export with the OSINT ENRICHMENT marker
    // BEFORE the INFECTED MACHINES marker used to panic
    // (`&body[vs..victim_end]` with start > end), aborting `hse import` —
    // the CLI path has no catch_unwind. The end marker is now sought after
    // the start, so the slice is always well-formed.
    // Tested against the pure parser (the panic was in parsing, not
    // persistence) so the test stays hermetic — it never touches the default
    // store that `cmd_import_txt` now writes to.
    let body = "=== OSINT ENRICHMENT ===\nstuff\n=== INFECTED MACHINES ===\nIPs: 8.8.8.8\n";
    let (ents, _) = super::parse_oathnet_txt(body, "sid");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::IpAddress && e.value == "8.8.8.8"),
        "misordered section markers must parse, not panic"
    );
}

#[test]
fn import_txt_parses_victim_section_in_normal_order() {
    // Happy path unaffected: INFECTED before OSINT still parses cleanly.
    let body = "=== INFECTED MACHINES ===\nIPs: 8.8.8.8\n=== OSINT ENRICHMENT ===\nMore: x\n";
    let (ents, _) = super::parse_oathnet_txt(body, "sid");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::IpAddress && e.value == "8.8.8.8")
    );
}

#[test]
fn reused_hash_across_entries_is_preserved_for_cross_account_linking() {
    use crate::core::entity::EntityKind;
    // The unmasking signal: two DIFFERENT accounts sharing one salted hash. The
    // parser must not value-dedup the credential away; after dedup-merge the one
    // credential entity must carry BOTH entries' emails in its evidence, so the
    // correlator (AU-047) can link the compartmentalised identities.
    let dossier = "Entry #1:\n   \u{2022} email: a@proton.me\n   \u{2022} hash: $2a$10$SAMEHASHvalueAAAAAAAAAAAAAA\nEntry #2:\n   \u{2022} email: b@gmail.com\n   \u{2022} hash: $2a$10$SAMEHASHvalueAAAAAAAAAAAAAA\n";
    let (mut ents, _) = super::parse_dossier(dossier, "sid");
    super::deduplicate_by_uid(&mut ents);

    let cred = ents
        .iter()
        .find(|e| e.kind == EntityKind::Credential)
        .expect("a credential entity");
    let emails: std::collections::BTreeSet<&str> = cred
        .evidence
        .iter()
        .filter_map(|ev| ev.attributes.get("email").map(String::as_str))
        .collect();
    assert!(
        emails.contains("a@proton.me") && emails.contains("b@gmail.com"),
        "the reused-hash credential must retain BOTH accounts' emails, got {emails:?}"
    );
}
