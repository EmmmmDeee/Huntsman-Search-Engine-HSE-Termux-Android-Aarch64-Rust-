//! Unit tests for the import parsers and persistence.
//!
//! Split out of the module file; reaches private parsers/helpers via
//! `use super::*` (each parser is re-exported into the parent's scope).

use super::{
    ImportFormat, deduplicate_by_uid, detect_import_format, entities_from_upload,
    looks_like_dossier, parse_dossier, parse_oathnet_html,
};

#[test]
fn detect_import_format_is_content_based_not_extension_gated() {
    // The bug: the CLI only recognised a dossier/combined/stealer/OathNet-report
    // text export under a `.txt` extension, so the SAME content saved under any
    // other name (or none) was mis-routed to the JSON parser and rejected. The
    // detector now keys on CONTENT, so the format is identical regardless of the
    // filename — and the CLI and web upload share this one decision.
    let dossier = "Entry #1:\n   \u{2022} email: a@b.com\n";
    for path in ["dump.dat", "dump.txt", "breach", "x.json", ""] {
        assert_eq!(
            detect_import_format(path, dossier),
            ImportFormat::Dossier,
            "dossier content must be detected regardless of the filename ({path:?})"
        );
    }
    // A JSON object wins before the text heuristics (so a `{`-body is never
    // mis-keyed), by content alone — no `.json` extension required.
    assert_eq!(
        detect_import_format("export", "{\"exportInfo\":{}}"),
        ImportFormat::OathnetJson
    );
    // HTML by content even without the `.html` extension.
    assert_eq!(
        detect_import_format("page", "<!doctype html><html></html>"),
        ImportFormat::OathnetHtml
    );
    // CSV by the `.csv` hint even when the content is ambiguous.
    assert_eq!(
        detect_import_format("table.csv", "a,b,c\n1,2,3"),
        ImportFormat::DehashedCsv
    );
    // Unrecognised plain text falls to the OathNet-TXT catch-all (graceful — the
    // same final `else` the web upload uses), never a hard error.
    assert_eq!(
        detect_import_format("notes.dat", "just some unstructured prose"),
        ImportFormat::OathnetTxt
    );
}

#[test]
fn detect_import_format_ignores_a_leading_utf8_bom() {
    // Regression: a UTF-8 BOM (U+FEFF) is not whitespace, so `trim_start` left it in
    // place and a BOM-prefixed export (common from Excel / Windows exporters) was
    // misrouted to the wrong parser and silently dropped every entity. It must now
    // detect by its real first token.
    assert_eq!(
        detect_import_format("", "\u{feff}{\"exportInfo\":{}}"),
        ImportFormat::OathnetJson
    );
    assert_eq!(
        detect_import_format("", "\u{feff}<!doctype html><html></html>"),
        ImportFormat::OathnetHtml
    );
    assert_eq!(
        detect_import_format("table.csv", "\u{feff}a,b,c\n1,2,3"),
        ImportFormat::DehashedCsv
    );
}

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
            // Truncated Stealerlogs block: a victim with a dangling Password key,
            // and a `[N]` marker with a multibyte value where a domain belongs.
            format!("Module: Stealerlogs\nVictims:\n  [1]\n    Credentials:\n      [1]\n        Password:\n    Domains:\n      [1]\n        é{bomb}"),
            // Truncated OathNet report: a header, an entry with a dangling field
            // and a multibyte name butted against the OSINT marker.
            format!("=== DATABASE LOGS ===\nEntry 1:\nemail:\nfull name: é{bomb}\n=== OSINT ENRICHMENT\nIP: \nlat: x"),
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

    // Combined Search aggregator export → the breach-aggregator branch.
    let (comb, label) = entities_from_upload(COMBINED, "s").await.unwrap();
    assert_eq!(label, "combined-search");
    assert!(has(&comb, EntityKind::Email, "jordanavery@gmail.com"));
    assert!(has(&comb, EntityKind::Person, "Jordan Avery"));

    // HSE's own CSV export → round-trip branch (not the DeHashed table).
    let hse = "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags\n\
        person,Jordan Avery,Jordan Avery,0.850,1.000,3,VERIFIED,1,name_intel,,[name_intel] x,au\n";
    let (hents, label) = entities_from_upload(hse, "s").await.unwrap();
    assert_eq!(label, "hse-csv");
    assert!(has(&hents, EntityKind::Person, "Jordan Avery"));

    // JSON API export → parsed (and the label proves the branch).
    let (_json, label) =
        entities_from_upload(r#"{"exportInfo":{"query":"x"},"searchResults":{}}"#, "s")
            .await
            .unwrap();
    assert_eq!(label, "oathnet-json");

    // Malformed JSON is a clean error, not a panic.
    assert!(entities_from_upload("{ not valid json", "s").await.is_err());
}

#[tokio::test]
async fn oathnet_json_stealer_victim_emits_every_distinct_field_uncapped() {
    use crate::core::entity::EntityKind;
    // A single stealer victim record carrying MORE than the old, arbitrary
    // per-field caps (device_ips: 10, device_emails: 20, hwids: 5,
    // discord_ids: 5, device_users: 5) — every one of these array fields is
    // whatever the upstream OathNet API returned, with no dedup/validation
    // reason to cap any of them (unlike e.g. push_crypto's checksum gate).
    let device_ips: Vec<String> = (0..15).map(|i| format!("10.0.0.{i}")).collect();
    let device_emails: Vec<String> = (0..25).map(|i| format!("user{i}@victim-host.io")).collect();
    let hwids: Vec<String> = (0..8).map(|i| format!("HWID-{i}")).collect();
    let discord_ids: Vec<String> = (0..8).map(|i| format!("discord#{i}")).collect();
    let device_users: Vec<String> = (0..8).map(|i| format!("winuser{i}")).collect();
    let body = serde_json::json!({
        "stealerData": {
            "victims": [{
                "device_ips": device_ips,
                "device_emails": device_emails,
                "hwids": hwids,
                "discord_ids": discord_ids,
                "device_users": device_users,
            }]
        }
    })
    .to_string();
    let (ents, label) = entities_from_upload(&body, "s").await.unwrap();
    assert_eq!(label, "oathnet-json");
    let count = |k: EntityKind, tag: &str| {
        ents.iter()
            .filter(|e| e.kind == k && e.has_tag(tag))
            .count()
    };
    assert_eq!(
        count(EntityKind::IpAddress, "stealer-victim"),
        15,
        "every distinct device IP must be emitted, not capped at the old 10"
    );
    assert_eq!(
        count(EntityKind::Email, "stealer-victim"),
        25,
        "every distinct device email must be emitted, not capped at the old 20"
    );
    assert_eq!(
        count(EntityKind::DeviceId, "hwid"),
        8,
        "every distinct HWID must be emitted, not capped at the old 5"
    );
    assert_eq!(
        count(EntityKind::Username, "discord-id"),
        8,
        "every distinct Discord ID must be emitted, not capped at the old 5"
    );
    assert_eq!(
        count(EntityKind::Username, "device-user"),
        8,
        "every distinct device user must be emitted, not capped at the old 5"
    );
}

#[tokio::test]
async fn import_extracts_wifi_bssid_as_geolocation_seed() {
    use crate::core::entity::EntityKind;
    // A stealer-log-shaped body carrying the victim's router BSSID.
    let (ents, label) = entities_from_upload(
        "URL: https://x.com/login\nUsername: victim\nRouter BSSID: A4:B1:C2:00:11:22\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "oathnet-txt");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::MacAddress
            && e.value == "a4:b1:c2:00:11:22"
            && e.has_tag("bssid")),
        "the BSSID must become a MacAddress geolocation seed"
    );
}

#[tokio::test]
async fn import_extracts_every_distinct_mac_address_uncapped() {
    use crate::core::entity::EntityKind;
    // 60 distinct BSSIDs — more than the old, arbitrary 50-per-import cap this
    // guards against reintroducing. `push_macs` must emit every one:
    // `crate::util::extract::macs` already dedupes, so the cap protected
    // nothing real.
    let mut body = String::from("URL: https://x.com/login\nUsername: victim\n");
    for i in 0..60u32 {
        body.push_str(&format!("Router BSSID: A4:B1:C2:00:11:{i:02X}\n"));
    }
    let (ents, _label) = entities_from_upload(&body, "s").await.unwrap();
    let mac_count = ents
        .iter()
        .filter(|e| e.kind == EntityKind::MacAddress)
        .count();
    assert_eq!(
        mac_count, 60,
        "every distinct BSSID must be emitted, not capped at the old arbitrary 50"
    );
}

#[tokio::test]
async fn import_extracts_crypto_wallet_as_chain_seed() {
    use crate::core::entity::EntityKind;
    // The genesis Bitcoin address — checksum-valid, so it survives validation.
    let (ents, label) = entities_from_upload(
        "URL: https://x.com\nWallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "oathnet-txt");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::CryptoAddress
            && e.value
                .eq_ignore_ascii_case("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            && e.has_tag("crypto-address")),
        "the wallet must become a CryptoAddress chain seed"
    );
}

#[tokio::test]
async fn import_extracts_leaked_api_key_from_body() {
    use crate::core::entity::EntityKind;
    // An AWS access-key ID sitting loose in the log (not a `service: key` line).
    let (ents, label) = entities_from_upload(
        "URL: https://x.com\nleftover config had AKIAZ3XK7P2QWERT5YBN in it\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "oathnet-txt");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::ApiKey && e.has_tag("api-key") && e.has_tag("stealer")),
        "the loose AWS key must be recovered as an ApiKey finding"
    );
}

#[tokio::test]
async fn dehashed_csv_also_mines_wallets_from_any_field() {
    use crate::core::entity::EntityKind;
    // The breach "password" field is itself a wallet — the table scan recovers it.
    let (ents, label) = entities_from_upload(
        "id,email,username,database_name,password\n\
         1,a@b.com,x,Breach,1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "dehashed-csv");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::CryptoAddress && e.has_tag("dehashed")),
        "the DeHashed table scan must recover a wallet from any field"
    );
}

#[tokio::test]
async fn import_extracts_iban_as_financial_finding() {
    use crate::core::entity::EntityKind;
    let (ents, label) = entities_from_upload(
        "URL: https://x.com\nBank account: GB82WEST12345698765432\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "oathnet-txt");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Other("iban".into())
                && e.value == "GB82WEST12345698765432"
                && e.has_tag("financial")),
        "a checksum-valid IBAN must become a financial finding"
    );
}

#[tokio::test]
async fn import_extracts_labeled_ssid_for_wigle_geolocation() {
    use crate::core::entity::EntityKind;
    let (ents, label) = entities_from_upload(
        "URL: https://x.com\nUsername: victim\nSSID: Smith Home 5G\n",
        "s",
    )
    .await
    .unwrap();
    assert_eq!(label, "oathnet-txt");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Ssid
            && e.value == "Smith Home 5G"
            && e.has_tag("wifi-network")),
        "a labelled SSID must become an Ssid entity (a WiGLE geolocation seed)"
    );
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

use super::combined::{looks_like_combined_search, parse_combined_search};
use super::csv::{looks_like_dehashed_csv, looks_like_hse_csv, parse_dehashed_csv, parse_hse_csv};
use super::oathnet_report::{looks_like_oathnet_report, parse_oathnet_report};
use super::stealer::{looks_like_stealerlogs, parse_stealerlogs};

// A synthetic HSE entity CSV export (the exact column order HSE writes).
const HSE_CSV: &str = "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags\n\
person,Jordan Avery,Jordan Avery,0.850,1.000,3,VERIFIED,1782117614,au_people|name_intel,,\"[name_intel] Name found || [au_people] Residential match, Carlton\",au|verified\n\
email,jordanavery@gmail.com,jordanavery@gmail.com,0.720,0.800,2,PROBABLE,1782117614,dehashed,,[dehashed] Breach record,breach\n\
other:au-postcode,2000,2000,0.900,0.900,1,VERIFIED,1782117614,au_geo,,[au_geo] ASGS postcode,au\n";

#[test]
fn hse_csv_is_detected_and_distinct_from_dehashed() {
    assert!(looks_like_hse_csv(HSE_CSV));
    assert!(!looks_like_dehashed_csv(HSE_CSV)); // no email/db columns in HSE's header
    assert!(!looks_like_hse_csv(
        "id,email,username,database_name\n1,a@b.com,x,Y\n"
    ));
}

#[test]
fn hse_csv_round_trips_kind_value_confidence_tags_and_evidence() {
    let (ents, _stats) = parse_hse_csv(HSE_CSV, "s");
    // Person row: kind, value, confidence, tags (original + provenance), and the
    // two-source evidence trail are all restored.
    let p = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person && e.value == "Jordan Avery")
        .expect("person row");
    assert!((p.confidence - 0.85).abs() < 0.01);
    assert!(p.has_tag("au") && p.has_tag("verified") && p.has_tag("hse-csv"));
    let srcs: Vec<&str> = p.evidence.iter().map(|ev| ev.source.as_str()).collect();
    assert!(srcs.contains(&"name_intel") && srcs.contains(&"au_people"));
    // The quoted summary with an internal comma survived the RFC-4180 reader.
    assert!(p.evidence.iter().any(|ev| ev.summary.contains("Carlton")));
    // The Other("au-postcode") kind round-trips.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Other("au-postcode".into()) && e.value == "2000")
    );
    assert!(ents.iter().any(|e| e.kind == EntityKind::Email));
}

// Synthetic Combined Search export (no real PII): a module-metadata block plus
// two result records, exercising inline header values AND next-line values.
const COMBINED: &str = "Module: Combined Search
Query: javery
Search Type: Username
Results: 2

  [1]
    Key:
      snusbase
    Source Type:
      snusbase
    Status:
      results
    Count:
      2
    Results:
      [1]
        Username:
          javery
        Email:
          jordanavery@gmail.com
        Name:
          Jordan Avery
        Password:
          Hunter2pass
        Source:
          2089_EXAMPLE_BREACH_122025
      [2]
        Email:
          jordan2@example.com
        Hash:
          e1436d06a8b5f6decbf31371d9da13fc
        Lastip:
          24.32.96.70
        Source:
          2042_EXAMPLE_TECH_012024
";

#[test]
fn combined_search_is_detected() {
    assert!(looks_like_combined_search(COMBINED));
    assert!(!looks_like_combined_search(
        "URL: https://x.com/login\nUsername: bob\n"
    ));
}

#[test]
fn combined_search_parses_records_and_skips_metadata() {
    let (ents, stats) = parse_combined_search(COMBINED, "s");
    let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);
    // Record 1.
    assert!(has(EntityKind::Email, "jordanavery@gmail.com"));
    assert!(has(EntityKind::Username, "javery"));
    assert!(has(EntityKind::Person, "Jordan Avery"));
    assert!(has(EntityKind::Credential, "Hunter2pass"));
    // Record 2: a hash credential and a last-login IP.
    assert!(has(EntityKind::Email, "jordan2@example.com"));
    assert!(has(
        EntityKind::Credential,
        "e1436d06a8b5f6decbf31371d9da13fc"
    ));
    assert!(has(EntityKind::IpAddress, "24.32.96.70"));
    // Two result records; the module-metadata block emitted nothing.
    assert_eq!(stats.breach_records, 2);
    // The source database rides on the evidence.
    let em = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "jordanavery@gmail.com")
        .unwrap();
    assert!(em.evidence.iter().any(|ev| {
        ev.attributes
            .get("source")
            .is_some_and(|v| v.contains("EXAMPLE_BREACH"))
    }));
}

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
https://site.example/u,Sup3rSecret!,\"12 Smith St, Carlton VIC 3053\",0412 345 678\n";
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
    // The AU local phone is recovered and canonicalised to E.164.
    assert!(has(EntityKind::Phone, &|v| v == "+61412345678"));
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

// A SeekNow `CONTACT SUMMARY (KEY DATA)` block (synthetic; AU + US mix). The
// `NAMES:`/`PHONE NUMBERS:`/`ADDRESSES:`/`IP ADDRESSES:` aggregate lists were
// previously dropped — only EMAILS/USERNAMES/PASSWORDS were recognised.
const SEEKNOW: &str =
    "================================================================================
                           SEARCH RESULTS EXPORT
================================================================================
Query: Jordan Avery

********************    CONTACT SUMMARY (KEY DATA)    ********************

  [EMAILS: 1 | NAMES: 2 | PHONE NUMBERS: 2 | ADDRESSES: 3 | IP ADDRESSES: 1]

  EMAILS:
    -> jordanavery@gmail.com

  NAMES:
    -> Full Name: Jordan Avery
    -> Company Name: Acme Corp Pty Ltd

  PHONE NUMBERS:
    -> 0412 345 678
    -> (214) 473-9696

  ADDRESSES:
    -> address: 12 Smith Street, Carlton, VIC, 3053, Australia
    -> city: Carlton
    -> state: VIC

  IP ADDRESSES:
    -> 24.32.96.70

Entry #1:
   \u{2022} email: jordanavery@gmail.com
   \u{2022} name: Jordan Avery
";

#[test]
fn dossier_captures_seeknow_contact_summary_sections() {
    assert!(looks_like_dossier(SEEKNOW));
    let (mut ents, stats) = parse_dossier(SEEKNOW, "s");
    deduplicate_by_uid(&mut ents);
    let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

    // NAMES: full name → Person, company name → Organisation (employer pivot).
    assert!(has(EntityKind::Person, "Jordan Avery"));
    assert!(has(EntityKind::Organisation, "Acme Corp Pty Ltd"));
    assert!(stats.organisations >= 1);

    // PHONE NUMBERS: the AU local number is canonicalised to E.164; the bare US
    // number (no recoverable country code) is correctly dropped.
    assert!(has(EntityKind::Phone, "+61412345678"));
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Phone && e.value.contains("214")),
        "a bare foreign-national number must not be emitted as a phone"
    );

    // ADDRESSES: the full `address:` line is a residence; the lone `city:`/
    // `state:` fragments are too coarse and must be skipped.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Address && e.value.contains("Carlton")),
        "the full address line must become an Address"
    );
    assert!(
        !has(EntityKind::Address, "Carlton"),
        "a bare city fragment must not become an Address"
    );

    // IP ADDRESSES: a real public IP becomes a pivotable IpAddress.
    assert!(has(EntityKind::IpAddress, "24.32.96.70"));
}

#[tokio::test]
async fn upload_dispatcher_routes_seeknow_summary_to_dossier() {
    let (ents, label) = entities_from_upload(SEEKNOW, "s").await.unwrap();
    assert_eq!(label, "dossier");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Phone && e.value == "+61412345678")
    );
}

#[test]
fn dossier_list_address_carries_provenance_and_geocodes() {
    use crate::core::engine::enrich_offline_geo;
    // A CONTACT SUMMARY whose ADDRESSES section names a major AU city.
    let body = "Entry #1:\n   \u{2022} email: a@example.com\n\
                ADDRESSES:\n  -> address: 10 George Street, Sydney NSW 2000\n";
    let (mut ents, _stats) = parse_dossier(body, "s");
    deduplicate_by_uid(&mut ents);

    // The list-section address now carries an `import:dossier` corroborating
    // source (previously it had none, leaving it source-less and un-geocodable).
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("address");
    assert!(
        !addr.corroborating_sources().is_empty(),
        "a list-section address must carry provenance"
    );

    // With provenance, the shared offline geocode derives a Sydney coordinate.
    enrich_offline_geo(&mut ents, "s");
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Coordinates
            && e.has_tag("addr-derived")
            && e.value.starts_with("-33.8688")),
        "the Sydney address must geocode once it carries a source"
    );
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

// ── Stealerlogs victim-export parser ──────────────────────────────────────────

// Synthetic Stealerlogs export (no real PII): two victims sharing one reused
// password, a corporate domain, a freemail domain and an infrastructure IP.
const STEALER: &str = "Module: Stealerlogs
Query: javery
Search Type: Auto Detect
Results: 0

Success:
  true
Query:
  javery
Victims:
  [1]
    Log Id:
      ea0621568ccd7fee2bd78e16f637727612aca78d4b3d1f6bf8175cf2ca8de831
    Credentials:
      [1]
        Username:
          jordanavery@gmail.com
        Password:
          Hunter2pass
        Pwned At:
          2026-05-20T21:00:00Z
      [2]
        Username:
          javery
        Password:
          Hunter2pass
        Pwned At:
          2026-05-20T21:00:00Z
    Domains:
      [1]
        acme-corp.com
      [2]
        79.98.132.222
      [3]
        gmail.com
    Newest:
      2026-05-20T21:00:00Z
    Oldest:
      2026-05-19T10:00:00Z
    Credential Count:
      2
    Domain Count:
      3
  [2]
    Log Id:
      8c815a3dd9c0954797f060577d8fb72690ac7d8cb142eab4c87856062ab8f067
    Credentials:
      [1]
        Username:
          bob
        Password:
          Hunter2pass
        Pwned At:
          2026-05-20T21:00:00Z
    Domains:
      [1]
        derbyrock.com
    Credential Count:
      1
    Domain Count:
      1
";

#[test]
fn stealerlogs_is_detected_and_others_are_not() {
    assert!(looks_like_stealerlogs(STEALER));
    // A renamed banner still parses via the structural fingerprint.
    assert!(looks_like_stealerlogs(
        "Victims:\n  [1]\n    Log Id:\n      abc\n    Credentials:\n"
    ));
    // The other formats are not swallowed.
    assert!(!looks_like_stealerlogs(DOSSIER));
    assert!(!looks_like_stealerlogs(COMBINED));
    assert!(!looks_like_stealerlogs(
        "URL: https://x.com/login\nUsername: bob\n"
    ));
    // And the stealer export is NOT mistaken for the aggregator/dossier formats.
    assert!(!looks_like_combined_search(STEALER));
    assert!(!looks_like_dossier(STEALER));
}

#[test]
fn stealerlogs_parses_victims_creds_and_domains() {
    let (mut ents, stats) = parse_stealerlogs(STEALER, "s");
    deduplicate_by_uid(&mut ents);
    let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

    // Two victims, each one stealer doc.
    assert_eq!(stats.victim_records, 2);
    assert_eq!(stats.stealer_docs, 2);

    // Credential username shapes: an email username and two plain usernames.
    assert!(has(EntityKind::Email, "jordanavery@gmail.com"));
    assert!(has(EntityKind::Username, "javery"));
    assert!(has(EntityKind::Username, "bob"));

    // The reused plaintext password is present and — crucially — NOT collapsed
    // away: it appears under three credential lines across two victims, so after
    // the uid-merge the single Credential entity must carry evidence from every
    // victim it implicates (the AU-047 reuse signal).
    let cred = ents
        .iter()
        .find(|e| e.kind == EntityKind::Credential && e.value == "Hunter2pass")
        .expect("the reused password must survive as a Credential");
    assert!(
        cred.evidence.len() >= 2,
        "a password reused across victims must retain every victim's evidence, got {}",
        cred.evidence.len()
    );

    // Domains: the corporate domain and the infrastructure IP are kept as pivots;
    // the freemail domain is gated out (expanding gmail.com maps a platform).
    assert!(has(EntityKind::Domain, "acme-corp.com"));
    assert!(has(EntityKind::Domain, "derbyrock.com"));
    assert!(has(EntityKind::IpAddress, "79.98.132.222"));
    assert!(
        !has(EntityKind::Domain, "gmail.com"),
        "a freemail domain must not become a pivot seed"
    );

    // The infected-machine log id becomes a DeviceId pivot.
    assert!(ents.iter().any(|e| e.kind == EntityKind::DeviceId
        && e.value == "ea0621568ccd7fee2bd78e16f637727612aca78d4b3d1f6bf8175cf2ca8de831"
        && e.has_tag("log-id")));

    // Every emitted entity is tagged as stealer-victim import data.
    assert!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Username)
            .all(|e| e.has_tag("stealer-victim"))
    );
}

#[test]
fn stealerlogs_credential_pwned_at_survives_onto_its_own_entities() {
    // Regression: `Cred::pwned_at` was parsed from the real `Pwned At:` field
    // (documented in `stealer.rs`'s own module header as part of the format)
    // but then silently dropped — never read again anywhere in the codebase,
    // never surfaced as evidence, violating the full-fidelity evidentiary
    // policy (`Evidence`'s own doc: "the FULL source record, preserved
    // verbatim... nothing redacted or omitted"). This pins that the second
    // victim's single, unambiguous credential ("bob") carries its own
    // `pwned_at` evidence attribute with the exact real capture instant.
    let (ents, _stats) = parse_stealerlogs(STEALER, "s");
    let bob = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "bob")
        .expect("the bob credential must become a Username entity");
    let pwned_at = bob
        .evidence
        .iter()
        .find_map(|ev| ev.attributes.get("pwned_at"));
    assert_eq!(
        pwned_at.map(String::as_str),
        Some("2026-05-20T21:00:00Z"),
        "the credential's own Pwned At date must ride on its entity's evidence, not be dropped"
    );
}

#[tokio::test]
async fn upload_dispatcher_routes_stealerlogs() {
    let (ents, label) = entities_from_upload(STEALER, "s").await.unwrap();
    assert_eq!(label, "stealerlogs");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Credential && e.value == "Hunter2pass")
    );
}

// ── OathNet SEARCH REPORT parser ──────────────────────────────────────────────

// Synthetic OathNet SEARCH REPORT (no real PII): one fully-populated AU breach
// entry, one noise entry whose name is a doubled query token, and an OSINT IP
// enrichment block.
const OATHNET_REPORT: &str = "============================================================
OATHNET SEARCH REPORT
Generated via oathnet.org
Report Date: 2026-06-24T07:03:47.997Z
Search Query: \"javery\"
============================================================

=== SEARCH RESULTS ===
Query: javery
Count: 2

=== DATABASE LOGS ===

[Breach Logs] (2 entries)

Entry 1:
country: AU
dbname: examplebreach.com
email: jordanavery@gmail.com
email domain: gmail.com
first name: Jordan
full name: Jordan Avery
id: b8ed0df81e91044e7ba2
last name: Avery
password hash: 2e4cc0d58868c0ea4c89b799bc8fd41a087009e067a171d823368cb517d6b3be
phone number: 0412345678
service: breach
username: javery
address street: 12 Smith Street
city: Carlton
state: VIC
postal code: 3053

Entry 2:
full name: Rhino Rhino
dbname: noise.com
service: breach

=== OSINT ENRICHMENT DATA ===

--- IP INFORMATION ---

IP: 1.128.0.50
status: success
country: Australia
regionName: Victoria
city: Melbourne
lat: -37.8136
lon: 144.9631
isp: Telstra
query: 1.128.0.50
";

#[test]
fn oathnet_report_is_detected_and_others_are_not() {
    assert!(looks_like_oathnet_report(OATHNET_REPORT));
    assert!(looks_like_oathnet_report(
        "=== DATABASE LOGS ===\nEntry 1:\nemail: a@b.com\n"
    ));
    // Not confused with the dossier (`Entry #N`) or the stealer-log TXT.
    assert!(!looks_like_oathnet_report(DOSSIER));
    assert!(!looks_like_oathnet_report(
        "URL: https://x.com/login\nUsername: bob\n"
    ));
    // And the report is not mistaken for the dossier/combined shapes.
    assert!(!looks_like_dossier(OATHNET_REPORT));
    assert!(!looks_like_combined_search(OATHNET_REPORT));
}

#[test]
fn oathnet_report_parses_entries_and_osint_geolocation() {
    let (mut ents, stats) = parse_oathnet_report(OATHNET_REPORT, "s");
    deduplicate_by_uid(&mut ents);
    let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

    // Entry 1's correlated identity cluster.
    assert!(has(EntityKind::Email, "jordanavery@gmail.com"));
    assert!(has(EntityKind::Username, "javery"));
    assert!(has(EntityKind::Person, "Jordan Avery"));
    // AU local phone canonicalised to E.164.
    assert!(has(EntityKind::Phone, "+61412345678"));
    // The hash credential.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Credential
        && e.value.len() == 64
        && e.has_tag("password-hash")));
    // Residential address (real street number present).
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Address
                && e.value.to_ascii_lowercase().contains("carlton"))
    );

    // The doubled-token noise name ("Rhino Rhino") is NOT promoted to a Person.
    assert!(
        !has(EntityKind::Person, "Rhino Rhino"),
        "a query-echo name must not become a Person"
    );

    // The OSINT enrichment block geolocates the IP to coordinates + a place.
    // (The Coordinates kind canonicalises to 6 decimal places, so match by prefix
    // rather than the raw 4-place emit string.)
    assert!(
        ents.iter().any(|e| e.kind == EntityKind::Coordinates
            && e.value.starts_with("-37.8136")
            && e.value.contains("144.9631")),
        "the OSINT IP must geolocate to coordinates"
    );
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Address && e.value.contains("Melbourne"))
    );

    // Only the real entry counts as a breach record (the noise block emits a
    // Person-free record but still carries an identity-less... actually it has a
    // name field, so it is a record); assert at least the populated one parsed.
    assert!(stats.breach_records >= 1);
    // The source database rides on the email's evidence.
    let em = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("email");
    assert!(em.evidence.iter().any(|ev| {
        ev.attributes
            .get("source")
            .is_some_and(|v| v == "examplebreach.com")
    }));
}

#[tokio::test]
async fn upload_dispatcher_routes_oathnet_report() {
    let (ents, label) = entities_from_upload(OATHNET_REPORT, "s").await.unwrap();
    assert_eq!(label, "oathnet-report");
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Jordan Avery")
    );
    // The shared OSINT helper ran on the report path too.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Coordinates));
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

    use super::super::{
        parse_dossier, parse_oathnet_html, parse_oathnet_report, parse_oathnet_txt,
        parse_stealerlogs,
    };

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

        /// `parse_stealerlogs` must never panic on any input string — its nested
        /// `[N]` / indentation grammar consumes untrusted bytes — and must only
        /// emit non-empty entity values.
        #[test]
        fn parse_stealerlogs_never_panics(s in ".{0,512}") {
            let (ents, _) = parse_stealerlogs(&s, "s");
            for e in &ents {
                prop_assert!(!e.value.is_empty(), "empty value in entity: {e:?}");
            }
        }

        /// `parse_oathnet_report` must never panic on any input string and must
        /// only emit non-empty entity values.
        #[test]
        fn parse_oathnet_report_never_panics(s in ".{0,512}") {
            let (ents, _) = parse_oathnet_report(&s, "s");
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
