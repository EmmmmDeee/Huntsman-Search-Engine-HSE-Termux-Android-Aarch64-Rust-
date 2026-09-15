use super::parse::{
    PropertyRecord, extract_postcode, extract_state, name_matches, parse_nsw_response,
    parse_qld_response, parse_vic_response, record_to_entities, state_capital_coords, strip_html,
};
use super::{AuProperty, LegOutcome, LegTally, landed_off_host, leg_failure, run_leg};
use crate::core::entity::{Entity, EntityKind};
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

// pull private helpers into scope via the module path
use super::parse::{split_name, surname};

#[test]
fn split_name_splits_correctly() {
    assert_eq!(split_name("Haigen Bamford"), ("Haigen", "Bamford"));
    assert_eq!(split_name("Mary Ann Jones"), ("Mary", "Ann Jones"));
    assert_eq!(split_name("Cher"), ("Cher", ""));
    assert_eq!(split_name("  Anna  Smith  "), ("Anna", "Smith"));
}

#[test]
fn surname_returns_last_token() {
    assert_eq!(surname("Haigen Bamford"), "Bamford");
    assert_eq!(surname("Mary Ann Jones"), "Jones");
    assert_eq!(surname("Cher"), "Cher");
}

#[test]
fn strip_html_separates_tag_content() {
    let html = "<div>123</div><span>NSW</span>";
    let text = strip_html(html);
    assert!(
        !text.contains("123NSW"),
        "tags must inject word break: {text}"
    );
    assert!(text.contains("123"), "content must survive");
    assert!(text.contains("NSW"), "content must survive");
}

// Table-driven: (text, full_name, should_match)
#[test]
fn name_matches_detects_token_presence() {
    let cases: &[(&str, &str, bool)] = &[
        (
            "BAMFORD HAIGEN JOHN 25 SMITH ST SYDNEY NSW 2000",
            "Haigen Bamford",
            true,
        ),
        (
            "SMITH JOHN 10 MAIN ST PERTH WA 6000",
            "Haigen Bamford",
            false,
        ),
        ("bamford haigen 5 elm ave nsw", "Haigen Bamford", true),
        ("BAMFORD 12 OAK ST NSW", "Haigen Bamford", false), // missing given name
    ];
    for (text, name, expected) in cases {
        assert_eq!(
            name_matches(text, name),
            *expected,
            "name_matches({text:?}, {name:?}) should be {expected}"
        );
    }
}

#[test]
fn name_matches_requires_whole_word_not_substring() {
    // "le" is a SUBSTRING of "alexander" but not a whole word. The old substring
    // gate returned true here, which — now that a match stamps `owner` +
    // `exact-name-match` — would fabricate a subject↔property link for an
    // AU-common short surname. Whole-word matching must reject it.
    assert!(
        !name_matches("Alexander Smith 5 Oak St NSW 2000", "Le Smith"),
        "a short surname appearing only as a substring must NOT match"
    );
    assert!(name_matches("Le Smith 5 Oak St NSW 2000", "Le Smith"));
}

#[test]
fn record_to_entities_stamps_owner_and_exact_name_match() {
    // The name-matched owner must be stamped as an `owner` attr and both entities
    // tagged `exact-name-match`, so the relation layer links the subject Person
    // to their registered property instead of leaving it a graph orphan.
    let rec = PropertyRecord {
        owner_name: "Jordan Avery".into(),
        suburb: "Sydney".into(),
        state: "NSW",
        postcode: Some("2000".into()),
    };
    let ents = record_to_entities(&rec, "s");
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("must emit Address");
    assert_eq!(
        addr.evidence[0].attributes.get("owner").map(String::as_str),
        Some("Jordan Avery"),
        "owner attr must carry the matched name so derive_residency can bind it"
    );
    assert!(
        ents.iter().all(|e| e.has_tag("exact-name-match")),
        "both the Address and Coordinates must be tagged exact-name-match"
    );
}

#[test]
fn untabulated_suburb_geocodes_via_postcode_not_state_capital() {
    // A far-north-QLD property whose suburb is NOT in the offline city table.
    // Old behaviour: fall straight to the Brisbane state-capital centroid, yet
    // stamp it MEDIUM_PLUS + exact-name-match + derived_from:suburb_centroid — a
    // Cairns-region owner pinned to Brisbane, indistinguishable from a real fix,
    // with the parsed postcode ignored. The fix geocodes via the postcode.
    assert!(
        crate::util::city_coords::city_coords("babinda").is_none(),
        "test premise: the suburb must not be in the offline city table",
    );
    let rec = PropertyRecord {
        owner_name: "Jordan Avery".into(),
        suburb: "Babinda".into(),
        state: "QLD",
        postcode: Some("4861".into()), // far-north QLD (postcode region "48")
    };
    let ents = record_to_entities(&rec, "s");
    let coord = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("must emit a Coordinates entity");
    let derived = coord.evidence[0]
        .attributes
        .get("derived_from")
        .map(String::as_str);
    assert!(
        matches!(derived, Some("postcode_centroid" | "postcode_region")),
        "an untabulated suburb with a postcode must geocode via the postcode, got {derived:?}",
    );
    assert_ne!(
        coord.value, "-27.469800,153.025100",
        "must NOT be the Brisbane state-capital pin (canonical 6dp)",
    );
    assert!(
        !coord.has_tag("exact-name-match"),
        "a region-grain fix must not claim to be a name-matched suburb centroid",
    );
    assert!(coord.has_tag("coarse"));
    assert!(
        coord.confidence < crate::core::confidence::MEDIUM_PLUS,
        "region grain must rank below a real suburb centroid",
    );
}

#[test]
fn capital_fallback_without_postcode_is_low_confidence_and_coarse() {
    // Suburb miss AND no postcode -> the state capital is the only fallback, but
    // it must be graded honestly (LOW, coarse, truthful derived_from), never
    // passed off as a name-matched suburb centroid.
    assert!(crate::util::city_coords::city_coords("babinda").is_none());
    let rec = PropertyRecord {
        owner_name: "Jordan Avery".into(),
        suburb: "Babinda".into(),
        state: "QLD",
        postcode: None,
    };
    let ents = record_to_entities(&rec, "s");
    let coord = ents
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
        .expect("must emit a Coordinates entity");
    assert_eq!(
        coord.value, "-27.469800,153.025100",
        "Brisbane capital, canonical 6dp",
    );
    assert!(!coord.has_tag("exact-name-match"));
    assert!(coord.has_tag("coarse"));
    assert_eq!(
        coord.evidence[0]
            .attributes
            .get("derived_from")
            .map(String::as_str),
        Some("state_capital_fallback"),
    );
    assert!(coord.confidence <= crate::core::confidence::LOW);
}

#[test]
fn extract_postcode_finds_valid_au_postcode() {
    assert_eq!(extract_postcode("Sydney NSW 2000"), Some("2000".into()));
    assert_eq!(extract_postcode("Melbourne VIC 3000"), Some("3000".into()));
    assert_eq!(extract_postcode("no postcode here"), None);
    // 1000 is a valid NSW postcode (Australian National University area).
    assert_eq!(extract_postcode("Canberra NSW 1000"), Some("1000".into()));
    // 0100 is not a valid AU postcode (truly unassigned).
    assert_eq!(extract_postcode("invalid 0100 postcode"), None);
    // 5-digit run must not match.
    assert_eq!(extract_postcode("12345 invalid"), None);
}

#[test]
fn extract_state_returns_canonical_code() {
    assert_eq!(extract_state("Sydney NSW 2000"), Some("NSW"));
    assert_eq!(extract_state("Melbourne Victoria"), Some("VIC"));
    assert_eq!(extract_state("Perth WA"), Some("WA"));
    assert_eq!(extract_state("no state here"), None);
}

#[test]
fn parse_nsw_response_extracts_matching_record() {
    let html = "<tr><td>BAMFORD HAIGEN</td><td>SURRY HILLS</td><td>NSW</td><td>2010</td></tr>";
    let recs = parse_nsw_response(html, "Haigen Bamford");
    assert!(
        !recs.is_empty(),
        "must extract a record when name matches: {html}"
    );
    let rec = &recs[0];
    assert_eq!(rec.state, "NSW");
    assert_eq!(rec.postcode.as_deref(), Some("2010"));
}

#[test]
fn parse_nsw_response_ignores_non_matching_rows() {
    let html = "<tr><td>SMITH JOHN</td><td>SYDNEY</td><td>NSW</td><td>2000</td></tr>";
    let recs = parse_nsw_response(html, "Haigen Bamford");
    assert!(recs.is_empty(), "non-matching rows must be ignored");
}

#[test]
fn parse_vic_response_extracts_vic_record() {
    // Mirror of the NSW test: a VIC line yields a VIC-stated record.
    let html = "<tr><td>BAMFORD HAIGEN</td><td>FITZROY</td><td>VIC</td><td>3065</td></tr>";
    let recs = parse_vic_response(html, "Haigen Bamford");
    assert!(!recs.is_empty(), "must extract a record when name matches");
    assert_eq!(recs[0].state, "VIC");
    assert_eq!(recs[0].postcode.as_deref(), Some("3065"));
}

#[test]
fn parse_vic_response_default_state_needs_no_state_token_yields_nothing() {
    // The VIC default only labels the record's state; the suburb extractor still
    // requires the state token in the line, so a token-less line is dropped.
    let html = "<tr><td>BAMFORD HAIGEN</td><td>FITZROY</td><td>3065</td></tr>";
    assert!(parse_vic_response(html, "Haigen Bamford").is_empty());
}

#[test]
fn parse_vic_response_ignores_non_matching_rows() {
    let html = "<tr><td>SMITH JOHN</td><td>FITZROY</td><td>VIC</td><td>3065</td></tr>";
    let recs = parse_vic_response(html, "Haigen Bamford");
    assert!(recs.is_empty(), "non-matching rows must be ignored");
}

#[test]
fn parse_qld_response_extracts_qld_record() {
    let html = "<tr><td>BAMFORD HAIGEN</td><td>TOOWONG</td><td>QLD</td><td>4066</td></tr>";
    let recs = parse_qld_response(html, "Haigen Bamford");
    assert!(!recs.is_empty(), "must extract a record when name matches");
    assert_eq!(recs[0].state, "QLD");
    assert_eq!(recs[0].postcode.as_deref(), Some("4066"));
}

#[test]
fn parse_qld_response_explicit_state_overrides_default() {
    // An explicit NSW token in a QLD-portal line wins over the QLD default.
    let html = "<tr><td>BAMFORD HAIGEN</td><td>SURRY HILLS</td><td>NSW</td><td>2010</td></tr>";
    let recs = parse_qld_response(html, "Haigen Bamford");
    assert!(!recs.is_empty());
    assert_eq!(recs[0].state, "NSW");
}

#[test]
fn state_capital_coords_covers_eight_states_and_rejects_others() {
    for (code, lat, lon) in [
        ("NSW", -33.8688, 151.2093),
        ("VIC", -37.8136, 144.9631),
        ("QLD", -27.4698, 153.0251),
        ("SA", -34.9285, 138.6007),
        ("WA", -31.9505, 115.8605),
        ("TAS", -42.8821, 147.3272),
        ("ACT", -35.2809, 149.1300),
        ("NT", -12.4634, 130.8456),
    ] {
        let (got_lat, got_lon) = state_capital_coords(code).expect("should succeed");
        assert!((got_lat - lat).abs() < 1e-9, "{code} lat");
        assert!((got_lon - lon).abs() < 1e-9, "{code} lon");
    }
    assert!(state_capital_coords("XYZ").is_none());
    assert!(state_capital_coords("").is_none());
}

#[test]
fn record_to_entities_emits_address_and_coordinates() {
    let rec = PropertyRecord {
        owner_name: "Haigen Bamford".into(),
        suburb: "Sydney".into(),
        state: "NSW",
        postcode: Some("2000".into()),
    };
    let ents = record_to_entities(&rec, "s");
    let kinds: Vec<_> = ents.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Address), "must emit Address");
    // Coordinates should follow from the suburb centroid.
    // (Sydney is in the city_coords table or state-capital fallback.)
    for e in &ents {
        assert!(e.has_tag("country:AU"), "must carry country:AU");
        assert!(e.has_tag("au-state:NSW"), "must carry au-state:NSW");
    }
}

#[test]
fn record_to_entities_address_includes_postcode_when_present() {
    let rec = PropertyRecord {
        owner_name: "Haigen Bamford".into(),
        suburb: "Fitzroy".into(),
        state: "VIC",
        postcode: Some("3065".into()),
    };
    let ents = record_to_entities(&rec, "s");
    let addr = ents
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("should succeed");
    assert!(
        addr.value.contains("3065"),
        "address must include postcode: {}",
        addr.value
    );
}

#[test]
fn dedup_entities_removes_exact_duplicates() {
    let mut ents = vec![
        Entity::new(EntityKind::Address, "Sydney, NSW", 0.74, "s"),
        Entity::new(EntityKind::Address, "Sydney, NSW", 0.62, "s"),
        Entity::new(EntityKind::Address, "Melbourne, VIC", 0.74, "s"),
    ];
    crate::core::entity::dedup_merge_entities(&mut ents);
    assert_eq!(
        ents.len(),
        2,
        "duplicate (kind, value) must be deduplicated"
    );
}

#[test]
fn module_metadata_is_valid() {
    let m = AuProperty;
    assert_eq!(m.name(), "au_property");
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@example.com")));
    assert!(m.attack_techniques().contains(&"T1591.001"));
    assert!(m.attack_techniques().contains(&"T1589.003"));
    assert!(
        !m.attack_techniques().contains(&"T1591.002"),
        "no co-owner/trust/company extraction exists — owner_name is always just the queried full_name"
    );
    assert!(m.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
}

/// Adversarial-input coverage (PROBLEM_TREE T2.7): `au_property` was one of
/// the two modules (alongside `au_electoral`) still missing the never-panics
/// proptest already applied to `au_people`'s HTML parsers. `text` is the
/// untrusted, scraped portal response; `full_name` is held to the project's
/// synthetic placeholder since it originates from the operator's own typed
/// scan target, not third-party bytes.
mod prop {
    use proptest::prelude::*;

    use super::{parse_nsw_response, parse_qld_response, parse_vic_response};

    proptest! {
        #[test]
        fn parse_nsw_response_never_panics(s in ".{0,256}") {
            let _ = parse_nsw_response(&s, "Jordan Avery");
        }

        #[test]
        fn parse_vic_response_never_panics(s in ".{0,256}") {
            let _ = parse_vic_response(&s, "Jordan Avery");
        }

        #[test]
        fn parse_qld_response_never_panics(s in ".{0,256}") {
            let _ = parse_qld_response(&s, "Jordan Avery");
        }
    }
}

// ── `leg_failure` — what the operator is actually told when nothing came back.
// The 2026-07-14 live finding (NSW/VIC/QLD all 404) is only ONE of the two ways
// a run ends empty; the other is that nothing was reachable at all, which on a
// Termux handset is routine. Conflating them was the fault this replaced. ──

/// Every leg answered with an error status — the real, confirmed 2026-07-14
/// state. Only here is the "retired/migrated legacy URLs" inference earned,
/// because statuses were genuinely observed.
#[test]
fn leg_failure_reports_dead_endpoints_when_statuses_were_observed() {
    let msg = leg_failure(LegTally {
        ok: 0,
        http_error: 3,
        migrated: 0,
        unreachable: 0,
    })
    .expect("three error statuses and no success is a hard failure");
    assert!(msg.contains("non-success HTTP status"), "{msg}");
    assert!(msg.contains("retired/migrated"), "{msg}");
    assert!(
        !msg.contains("DNS, connect, TLS, or timeout"),
        "must not claim unreachability that was not observed: {msg}"
    );
}

/// Nothing answered at all. The old code reported this as "returned a
/// non-success HTTP status" — asserting an observation it never made, and
/// pointing the operator at this module instead of at their connectivity.
#[test]
fn leg_failure_does_not_claim_a_status_it_never_saw() {
    let msg = leg_failure(LegTally {
        ok: 0,
        http_error: 0,
        migrated: 0,
        unreachable: 3,
    })
    .expect("three unreachable legs and no success is a hard failure");
    // Assert on the transport vocabulary rather than one phrasing: the
    // unreachable-only message reads "none of the N … could be reached" while
    // the mixed one reads "could not be reached at all", so a single literal
    // would pin prose rather than meaning.
    assert!(msg.contains("DNS, connect, TLS, or timeout"), "{msg}");
    assert!(msg.contains("connectivity failure on this device"), "{msg}");
    assert!(
        !msg.contains("non-success HTTP status"),
        "regression: a transport failure must never be reported as an HTTP status: {msg}"
    );
    assert!(
        !msg.contains("retired/migrated"),
        "an unreached endpoint is no evidence at all about the URL: {msg}"
    );
}

/// Mixed causes are reported as mixed rather than rounded to whichever is
/// convenient.
#[test]
fn leg_failure_reports_mixed_causes_honestly() {
    let msg = leg_failure(LegTally {
        ok: 0,
        http_error: 1,
        migrated: 0,
        unreachable: 2,
    })
    .expect("no success is a hard failure");
    assert!(msg.contains('1') && msg.contains('2'), "{msg}");
    assert!(msg.contains("non-success HTTP status"), "{msg}");
    assert!(msg.contains("DNS, connect, TLS, or timeout"), "{msg}");
}

/// A leg answering 2xx means the registers WERE consulted, so an empty result
/// is a real "no records for this name" — never an error, whatever the other
/// legs did.
#[test]
fn leg_failure_is_none_once_any_leg_answered() {
    for tally in [
        LegTally {
            ok: 1,
            http_error: 0,
            migrated: 0,
            unreachable: 0,
        },
        LegTally {
            ok: 1,
            http_error: 1,
            migrated: 0,
            unreachable: 1,
        },
    ] {
        assert!(
            leg_failure(tally).is_none(),
            "a 2xx answer makes an empty result honest, not a failure: {tally:?}"
        );
    }
}

/// No leg ran, so there is nothing to report on — must not fabricate a failure.
#[test]
fn leg_failure_is_none_when_no_leg_was_attempted() {
    assert!(leg_failure(LegTally::default()).is_none());
}

/// The tally saturates rather than wrapping, so a future fan-out over many
/// legs cannot roll a u8 back to zero and turn a total outage into "no legs
/// attempted" (which `leg_failure` reports as success).
#[test]
fn leg_tally_saturates() {
    let mut t = LegTally::default();
    for _ in 0..300 {
        t.record(LegOutcome::Unreachable);
    }
    assert_eq!(t.unreachable, u8::MAX);
    assert!(
        leg_failure(t).is_some(),
        "a saturated tally is still a failure"
    );
}

// ── Backlog #3 / #4: a redirect off the portal is not the register answering;
//    a body that cannot be read to the end is not an empty register page ─────

#[test]
fn a_leg_that_landed_on_another_host_is_a_dead_endpoint_in_the_verdict() {
    // NSW's legacy domain 308-redirects wholesale to the SDT Explorer SPA on
    // portal.spatial.nsw.gov.au; that page parses to nothing for anyone, which
    // used to read as "register consulted, no records for this name".
    let msg = leg_failure(LegTally {
        ok: 0,
        http_error: 2,
        migrated: 1,
        unreachable: 0,
    })
    .expect("two error statuses plus a migrated leg and no success is a hard failure");
    assert!(msg.contains("all 3 property-register endpoints"), "{msg}");
    assert!(msg.contains("redirected away to another host"), "{msg}");
    assert!(msg.contains("retired/migrated"), "{msg}");

    // A migrated leg alone is still a failure, never a consulted register.
    assert!(
        leg_failure(LegTally {
            ok: 0,
            http_error: 0,
            migrated: 1,
            unreachable: 0,
        })
        .is_some(),
        "a redirect to some other site is not an answer from the register"
    );
    // Mixed with unreachable legs, both causes are named.
    let mixed = leg_failure(LegTally {
        ok: 0,
        http_error: 0,
        migrated: 1,
        unreachable: 2,
    })
    .expect("mixed causes are a hard failure");
    assert!(
        mixed.contains("1 returned a non-success HTTP status or redirected away"),
        "{mixed}"
    );
    assert!(mixed.contains("2 could not be reached"), "{mixed}");
}

#[test]
fn landed_off_host_compares_hosts_only() {
    let landed = |u: &str| url::Url::parse(u).expect("url");
    assert!(landed_off_host(
        "https://maps.six.nsw.gov.au/services/public/Property_Name_Address?surname=x",
        &landed("https://portal.spatial.nsw.gov.au/explorer/index.html"),
    ));
    // Same host: scheme, path and query changes are the portal's own business.
    assert!(!landed_off_host(
        "http://mapshare.vic.gov.au/mapsharevic/ows?service=WFS",
        &landed("https://mapshare.vic.gov.au/mapsharevic/ows/?service=WFS"),
    ));
    assert!(!landed_off_host(
        "https://WWW.qld.gov.au/x",
        &landed("https://www.qld.gov.au/x/"),
    ));
    // Unparseable request URL: never invent a migration.
    assert!(!landed_off_host(
        "not a url",
        &landed("https://example.com/")
    ));
}

/// The transport half, against loopback listeners with a plain client: a
/// cross-host redirect lands as `Migrated`, a body cut short mid-transfer as
/// `Unreachable`, and a genuine 2xx read to the end as `Ok`.
#[tokio::test]
async fn run_leg_classifies_a_cross_host_redirect_and_a_cut_body_honestly() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = crate::core::module::ModuleContext {
        scan_id: "s".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let parse = parse_nsw_response as fn(&str, &str) -> Vec<super::parse::PropertyRecord>;

    // The "SPA" host: answers 200 with a shell page. Reached as `localhost`, a
    // different host string from the `127.0.0.1` the leg is asked for.
    let spa =
        crate::util::http::test_server::serve(vec![crate::util::http::test_server::Canned::text(
            200,
            "<html><body><div id=app></div></body></html>",
        )])
        .await;
    let spa_port = spa.rsplit(':').next().expect("port");
    // The "legacy portal": redirects wholesale to the SPA on another host.
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let legacy_addr = legacy.local_addr().expect("addr");
    let redirect_to = format!("http://localhost:{spa_port}/explorer/index.html");
    tokio::spawn(async move {
        let Ok((mut sock, _)) = legacy.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
        let _ = sock.read(&mut buf).await;
        let head = format!(
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: {redirect_to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.shutdown().await;
    });
    let mut out = Vec::new();
    let outcome = run_leg(
        &ctx,
        &format!("http://{legacy_addr}/services/public/Property_Name_Address?surname=Moreau"),
        "application/json,text/html",
        "Fletcher Moreau",
        parse,
        &mut out,
    )
    .await;
    assert_eq!(
        outcome,
        LegOutcome::Migrated,
        "a 2xx from another host is not the register answering"
    );
    assert!(out.is_empty());

    // A body cut short: Content-Length promises more than arrives.
    let cut = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let cut_addr = cut.local_addr().expect("addr");
    tokio::spawn(async move {
        let Ok((mut sock, _)) = cut.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 500000\r\nConnection: close\r\n\r\n<html>Fletcher Moreau, Sydney NSW 2000")
            .await;
        let _ = sock.shutdown().await;
    });
    let outcome = run_leg(
        &ctx,
        &format!("http://{cut_addr}/services/public/Property_Name_Address?surname=Moreau"),
        "application/json,text/html",
        "Fletcher Moreau",
        parse,
        &mut out,
    )
    .await;
    assert_eq!(
        outcome,
        LegOutcome::Unreachable,
        "a body that could not be read to the end is a transport failure, not an empty page"
    );
    assert!(
        out.is_empty(),
        "nothing parsed from a partial body may be kept"
    );

    // A genuine answer, read whole.
    let whole =
        crate::util::http::test_server::serve(vec![crate::util::http::test_server::Canned::text(
            200,
            "<html><body><tr><td>Fletcher Moreau</td><td>Sydney NSW 2000</td></tr></body></html>",
        )])
        .await;
    let outcome = run_leg(
        &ctx,
        &format!("{whole}/services/public/Property_Name_Address?surname=Moreau"),
        "application/json,text/html",
        "Fletcher Moreau",
        parse,
        &mut out,
    )
    .await;
    assert_eq!(outcome, LegOutcome::Ok);
}
