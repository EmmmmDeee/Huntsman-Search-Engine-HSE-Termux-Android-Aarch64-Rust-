//! Unit tests for the import parsers and persistence.
//!
//! Split out of the module file; reaches private parsers/helpers via
//! `use super::*` (each parser is re-exported into the parent's scope).

use super::{
    deduplicate_by_uid, entities_from_upload, looks_like_dossier, parse_dossier, parse_oathnet_html,
};

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

    // DeHashed CSV export → the breach-table branch.
    let (csvents, label) = entities_from_upload(
        "id,email,username,name,database_name,password,phone\n\
         1,jordanavery@gmail.com,javery,Jordan Avery,ExampleBreach,Hunter2pass,+61412345678\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "dehashed-csv");
    assert!(has(&csvents, EntityKind::Email, "jordanavery@gmail.com"));
    assert!(has(&csvents, EntityKind::Person, "Jordan Avery"));

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

use super::csv::{looks_like_dehashed_csv, parse_dehashed_csv};

#[test]
fn dehashed_csv_is_detected_strictly() {
    assert!(looks_like_dehashed_csv(
        "id,email,username,database_name,password\n1,a@b.com,x,Breach,pw\n"
    ));
    assert!(looks_like_dehashed_csv(
        "email,hashed_password.1\nx@y.com,abc\n"
    ));
    // An arbitrary CSV without the DeHashed hallmark is not swallowed.
    assert!(!looks_like_dehashed_csv("name,age\nBob,42\n"));
    // Nor are the other import formats.
    assert!(!looks_like_dehashed_csv(DOSSIER));
}

#[test]
fn dehashed_csv_parses_quoted_fields_and_every_kind() {
    // Synthetic placeholders only (no real PII). The address carries an internal
    // comma, so it must be quoted — exercising the RFC-4180 field reader.
    let csv = "id,email,username,hashed_password.1,name,database_name,url,password,address,phone\n\
        1,jordanavery@gmail.com,javery,$2a$10$abcdefghijklmnopqrs,Jordan Avery,ExampleBreach2019,\
https://site.example/u,Sup3rSecret!,\"12 Smith St, Carlton VIC 3053\",+61412345678\n";
    let (ents, stats) = parse_dehashed_csv(csv, "s");
    let has = |k: EntityKind, pred: &dyn Fn(&str) -> bool| {
        ents.iter().any(|e| e.kind == k && pred(&e.value))
    };
    assert!(has(EntityKind::Email, &|v| v == "jordanavery@gmail.com"));
    assert!(has(EntityKind::Username, &|v| v == "javery"));
    assert!(has(EntityKind::Person, &|v| v == "Jordan Avery"));
    assert!(has(EntityKind::Credential, &|v| v == "Sup3rSecret!")); // plaintext
    assert!(has(EntityKind::Credential, &|v| v.starts_with("$2a$"))); // hash
    // The quoted address (internal comma) parsed as ONE field.
    assert!(has(EntityKind::Address, &|v| v
        .to_ascii_lowercase()
        .contains("carlton")));
    assert!(ents.iter().any(|e| e.kind == EntityKind::Phone));
    assert!(ents.iter().any(|e| e.kind == EntityKind::Url));
    // Every breach entity carries its source database in evidence.
    let em = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("email");
    assert!(em.evidence.iter().any(|ev| {
        ev.attributes
            .get("database_name")
            .is_some_and(|v| v == "ExampleBreach2019")
    }));
    assert_eq!(stats.breach_records, 1);
}

#[test]
fn dossier_parse_strips_leading_utf8_bom() {
    // An exporter that writes "UTF-8 with BOM" (Excel / Notepad default) prefixes
    // the file with U+FEFF, which `str::trim` does NOT strip — so the first section
    // header `EMAILS:` became `\u{feff}EMAILS:`, matched no section, and the whole
    // first section was silently dropped.
    let bom_dossier = "\u{feff}EMAILS:\n  -> betocastillo097@gmail.com\n";
    let (ents, _) = parse_dossier(bom_dossier, "sid");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "betocastillo097@gmail.com"),
        "the first section must parse despite a leading BOM: {:?}",
        ents.iter().map(|e| (&e.kind, &e.value)).collect::<Vec<_>>()
    );
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
fn import_txt_keeps_ipv6_victim_addresses() {
    // The old `contains('.')` gate dropped every IPv6 victim IP. A mixed IPs line
    // must keep both families and skip only the unspecified/`0.x` "no address" junk.
    let body = "=== INFECTED MACHINES ===\nIPs: 10.0.0.5, 2001:db8::1, 0.0.0.0, ::, 203.0.113.9\n";
    let (ents, _) = super::parse_oathnet_txt(body, "sid");
    let ips: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        ips.contains(&"2001:db8::1"),
        "IPv6 victim IP must be kept: {ips:?}"
    );
    assert!(
        ips.contains(&"10.0.0.5"),
        "IPv4 victim IP still kept: {ips:?}"
    );
    assert!(!ips.contains(&"0.0.0.0"), "0.x junk skipped: {ips:?}");
    assert!(!ips.contains(&"::"), "unspecified IPv6 skipped: {ips:?}");
}

#[test]
fn dossier_plaintext_password_and_session_token_become_linkable_credentials() {
    use crate::core::entity::EntityKind;
    // Stealer-log fields — a reused plaintext `password` and a `session` token —
    // must surface as Credential entities tagged for AU-047, carrying each
    // entry's email so the reused-secret link can fire. Like the hash path,
    // reuse across entries must survive the uid-merge (both emails on one
    // credential), not be value-deduped away.
    let dossier = "Entry #1:\n   \u{2022} email: a@corp.io\n   \
                   \u{2022} password: Tr0ub4dor&3xK9!q\n   \
                   \u{2022} session: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15\n\
                   Entry #2:\n   \u{2022} email: b@other.io\n   \
                   \u{2022} password: Tr0ub4dor&3xK9!q\n";
    let (mut ents, stats) = super::parse_dossier(dossier, "sid");
    super::deduplicate_by_uid(&mut ents);

    // The reused password is one merged Credential tagged plaintext-credential
    // carrying BOTH accounts' emails (so AU-047 links them).
    let pw = ents
        .iter()
        .find(|e| e.kind == EntityKind::Credential && e.value == "Tr0ub4dor&3xK9!q")
        .expect("plaintext password credential");
    assert!(pw.has_tag("plaintext-credential"));
    let emails: std::collections::BTreeSet<&str> = pw
        .evidence
        .iter()
        .filter_map(|ev| ev.attributes.get("email").map(String::as_str))
        .collect();
    assert!(
        emails.contains("a@corp.io") && emails.contains("b@other.io"),
        "reused password must retain both accounts' emails, got {emails:?}"
    );

    // The session token surfaces tagged session-token.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Credential && e.has_tag("session-token")),
        "session token must surface as a session-token credential"
    );
    assert!(stats.credentials >= 2);

    // End-to-end: the correlator links the two accounts on the reused password.
    let hits = crate::core::correlator::correlate_entities(&ents, "sid");
    assert!(
        hits.iter().any(|c| c.rule_id == "AU-047"),
        "reused plaintext password across two entries must fire AU-047"
    );
}

#[test]
fn dossier_entry_address_field_becomes_a_first_class_entity() {
    use crate::core::entity::EntityKind;
    // Regression: `address` was missing from the entry field whitelist, so the
    // `address:` line was never accumulated and `emit_dossier_entry`'s Address
    // block (the household / co-location pivot, AU-049) was dead code — every
    // dossier address was silently dropped during parsing.
    let dossier = "Entry #1:\n   \u{2022} email: a@corp.io\n   \
                   \u{2022} address: 12 Mary Street, Brisbane QLD 4000\n";
    let (mut ents, stats) = super::parse_dossier(dossier, "sid");
    super::deduplicate_by_uid(&mut ents);

    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("a specific residence address must be emitted");
    assert_eq!(addr.value, "12 Mary Street, Brisbane QLD 4000");
    assert!(addr.has_tag("breach") && addr.has_tag("dossier"));
    assert_eq!(stats.addresses, 1);

    // The full record still travels as evidence on the email (correlation intact).
    let email = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "a@corp.io")
        .expect("entry email");
    assert_eq!(
        email.evidence[0]
            .attributes
            .get("address")
            .map(String::as_str),
        Some("12 Mary Street, Brisbane QLD 4000"),
    );

    // A bare, non-specific locality ("USA") names a region thousands share and
    // must NOT fabricate a residence entity.
    let vague = "Entry #2:\n   \u{2022} email: b@corp.io\n   \u{2022} address: USA\n";
    let (ents2, stats2) = super::parse_dossier(vague, "sid");
    assert!(!ents2.iter().any(|e| e.kind == EntityKind::Address));
    assert_eq!(stats2.addresses, 0);
}

#[test]
fn reused_hash_across_entries_is_preserved_for_cross_account_linking() {
    use crate::core::entity::EntityKind;
    // The account-linking signal: two DIFFERENT accounts sharing one salted hash. The
    // parser must not value-dedup the credential away; after dedup-merge the one
    // credential entity must carry BOTH entries' emails in its evidence, so the
    // correlator (AU-047) can link the separate accounts.
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

// ── parse_oathnet_html ────────────────────────────────────────────────────────

#[test]
fn parse_oathnet_html_extracts_domains_ips_and_emails() {
    use crate::core::entity::EntityKind;
    let body = "<html><body>\
        Host: example.com and sub.dept.example.com<br>\
        IP: 203.0.113.7<br>\
        Contact: Alice@Example.com\
        </body></html>";
    let es = parse_oathnet_html(body, "sid");
    let has = |k: EntityKind, v: &str| es.iter().any(|e| e.kind == k && e.value == v);
    assert!(has(EntityKind::Domain, "example.com"));
    assert!(has(EntityKind::Domain, "sub.dept.example.com"));
    assert!(has(EntityKind::IpAddress, "203.0.113.7"));
    // Emails are lower-cased.
    assert!(has(EntityKind::Email, "alice@example.com"));
    // Every imported entity carries the `import` tag.
    assert!(es.iter().all(|e| e.has_tag("import")));
}

#[test]
fn parse_oathnet_html_flags_subdomains_with_lower_confidence() {
    use crate::core::entity::EntityKind;
    let es = parse_oathnet_html("a.b.example.com plain.com", "sid");
    let sub = es
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "a.b.example.com")
        .expect("subdomain present");
    let apex = es
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "plain.com")
        .expect("apex present");
    assert!(sub.has_tag("subdomain"));
    assert!(!apex.has_tag("subdomain"));
    // Subdomains are scored below apex domains (0.45 < 0.50).
    assert!(sub.confidence < apex.confidence);
}

#[test]
fn parse_oathnet_html_skips_bogus_ips_and_dedups() {
    use crate::core::entity::EntityKind;
    // 0./127./255.-prefixed IPs are dropped; a repeated domain appears once.
    let es = parse_oathnet_html(
        "127.0.0.1 0.0.0.0 255.255.255.255 example.com example.com",
        "sid",
    );
    assert!(
        !es.iter().any(|e| e.kind == EntityKind::IpAddress),
        "loopback/unspecified/broadcast IPs must be skipped"
    );
    assert_eq!(
        es.iter()
            .filter(|e| e.kind == EntityKind::Domain && e.value == "example.com")
            .count(),
        1,
        "a repeated domain must be de-duplicated"
    );
}

#[test]
fn parse_oathnet_html_empty_body_yields_nothing() {
    assert!(parse_oathnet_html("", "sid").is_empty());
}

// ── Property tests (proptest) — no-panic contract for untrusted import ────────
//
// These parsers consume untrusted bytes supplied by the operator or uploaded via
// the web endpoint; the CLI import path has no `catch_unwind`, so a panic kills
// the process. The properties below pin the no-panic contract over thousands of
// arbitrary Unicode strings (incl. multibyte sequences landing next to structural
// bytes: `•`, `->`, `@`, `:`, section markers, truncated entry blocks) — the
// class the hand-coded adversarial table in
// `upload_dispatcher_never_panics_on_adversarial_input` can never exhaust.
mod prop {
    use proptest::prelude::*;

    use super::super::{parse_dossier, parse_oathnet_html, parse_oathnet_txt};

    proptest! {
        /// `parse_dossier` must never panic on any input string and must only
        /// emit non-empty entity values.
        #[test]
        fn parse_dossier_never_panics(s in ".{0,512}") {
            let (ents, _) = parse_dossier(&s, "s");
            for e in &ents {
                prop_assert!(!e.value.is_empty(), "empty value in entity: {e:?}");
            }
        }

        /// `parse_oathnet_txt` must never panic on any input string and must only
        /// emit non-empty entity values.
        #[test]
        fn parse_oathnet_txt_never_panics(s in ".{0,512}") {
            let (ents, _) = parse_oathnet_txt(&s, "s");
            for e in &ents {
                prop_assert!(!e.value.is_empty(), "empty value in entity: {e:?}");
            }
        }

        /// `parse_oathnet_html` must never panic on any input string and must
        /// only emit non-empty entity values.
        #[test]
        fn parse_oathnet_html_never_panics(s in ".{0,512}") {
            let ents = parse_oathnet_html(&s, "s");
            for e in &ents {
                prop_assert!(!e.value.is_empty(), "empty value in entity: {e:?}");
            }
        }
    }
}
