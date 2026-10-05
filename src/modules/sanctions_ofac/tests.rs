use super::*;

use super::crypto::SanctionedAddress;
use super::entity::{ADDRESS_HIT_CONFIDENCE, HIT_CONFIDENCE};
use super::parse::SdnKind;

#[test]
fn accepts_names_organisations_and_crypto_addresses() {
    let m = SanctionsOfac;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Abu Abbas")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Banco Nacional de Cuba")));
    // A wallet is screenable because OFAC designates addresses inline in the
    // remarks this module already downloads.
    assert!(m.accepts(&Target::new(
        TargetKind::CryptoAddress,
        "1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(SanctionsOfac.name(), "sanctions_ofac");
    assert_eq!(SanctionsOfac.priority(), 111);
    assert_eq!(SanctionsOfac.cost(), ModuleCost::Free);
}

#[test]
fn produces_person_organisation_and_crypto_address() {
    let kinds = SanctionsOfac.produces();
    assert!(kinds.contains(&EntityKind::Person));
    assert!(kinds.contains(&EntityKind::Organisation));
    assert!(kinds.contains(&EntityKind::CryptoAddress));
    assert_eq!(kinds.len(), 3);
}

fn individual_record() -> SdnRecord {
    SdnRecord {
        list: super::parse::OfacList::Sdn,
        ent_num: 2674,
        name: "ABBAS, Abu".to_string(),
        kind: SdnKind::Individual,
        program: "SDGT".to_string(),
        title: "Director of PALESTINE LIBERATION FRONT".to_string(),
        remarks: "DOB 10 Dec 1948; Director of PALESTINE LIBERATION FRONT.".to_string(),
    }
}

fn organisation_record() -> SdnRecord {
    SdnRecord {
        list: super::parse::OfacList::Sdn,
        ent_num: 36,
        name: "AEROCARIBBEAN AIRLINES".to_string(),
        kind: SdnKind::Organisation,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

fn vessel_record() -> SdnRecord {
    SdnRecord {
        list: super::parse::OfacList::Sdn,
        ent_num: 4238,
        name: "MAR AZUL".to_string(),
        kind: SdnKind::Vessel,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

/// An individual whose entry designates one Bitcoin wallet — the shape that
/// makes the name path a pivot into `chain_intel`.
fn wallet_record() -> SdnRecord {
    SdnRecord {
        list: super::parse::OfacList::Sdn,
        ent_num: 31234,
        name: "IVANOV, Ivan".to_string(),
        kind: SdnKind::Individual,
        program: "CYBER2".to_string(),
        title: String::new(),
        remarks: "DOB 01 Jan 1980; Digital Currency Address - XBT \
                  1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2."
            .to_string(),
    }
}

#[test]
fn individual_hit_emits_person_with_reordered_name_and_caution() {
    let e = build_subject(&individual_record(), "s", Provenance::Name)
        .expect("individual should emit an entity");
    assert_eq!(e.kind, EntityKind::Person);
    assert_eq!(e.value, "Abu Abbas");
    assert!((e.confidence - HIT_CONFIDENCE).abs() < 1e-9);
    assert!(e.has_tag("sanctions") && e.has_tag("ofac") && e.has_tag("regulatory-action"));
    assert!(e.has_tag("needs-identity-verification"));
    let attrs = &e.evidence[0].attributes;
    assert!(attrs.contains_key("caution"));
    assert_eq!(attrs.get("program").map(String::as_str), Some("SDGT"));
    assert_eq!(
        attrs.get("title").map(String::as_str),
        Some("Director of PALESTINE LIBERATION FRONT")
    );
    assert!(
        attrs
            .get("remarks")
            .is_some_and(|r| r.contains("DOB 10 Dec 1948"))
    );
}

#[test]
fn hit_with_blank_title_omits_title_attribute() {
    let e = build_subject(&organisation_record(), "s", Provenance::Name)
        .expect("organisation should emit an entity");
    // organisation_record() has an empty title (the -0- placeholder normalises
    // to "") — the attribute must be absent, not present-and-empty.
    assert!(!e.evidence[0].attributes.contains_key("title"));
}

#[test]
fn organisation_hit_emits_organisation_without_reordering() {
    let e = build_subject(&organisation_record(), "s", Provenance::Name)
        .expect("organisation should emit an entity");
    assert_eq!(e.kind, EntityKind::Organisation);
    assert_eq!(e.value, "AEROCARIBBEAN AIRLINES");
    assert!(e.has_tag("sanctions") && e.has_tag("needs-identity-verification"));
    // No remarks on this record → the attribute is simply absent, not empty-string.
    assert!(!e.evidence[0].attributes.contains_key("remarks"));
}

#[test]
fn vessel_and_aircraft_rows_emit_no_subject() {
    assert!(build_subject(&vessel_record(), "s", Provenance::Name).is_none());
    let mut aircraft = vessel_record();
    aircraft.kind = SdnKind::Aircraft;
    assert!(build_subject(&aircraft, "s", Provenance::Address).is_none());
}

#[test]
fn address_provenance_grades_higher_and_drops_the_identity_hedge() {
    let name_hit = build_subject(&individual_record(), "s", Provenance::Name)
        .expect("individual should emit an entity");
    let addr_hit = build_subject(&individual_record(), "s", Provenance::Address)
        .expect("individual should emit an entity");

    assert!(
        addr_hit.confidence > name_hit.confidence,
        "an exact identifier match must outrank a fuzzy name match"
    );
    assert!((addr_hit.confidence - ADDRESS_HIT_CONFIDENCE).abs() < 1e-9);

    // The hedge exists because NAME matching is fuzzy; it must not survive onto
    // a finding reached by an exact identifier.
    assert!(!addr_hit.has_tag("needs-identity-verification"));
    let attrs = &addr_hit.evidence[0].attributes;
    assert!(!attrs.contains_key("caution"));
    assert!(attrs.contains_key("match_basis"));
    // Everything that is still true regardless of how the row was reached.
    assert!(addr_hit.has_tag("sanctions") && addr_hit.has_tag("ofac"));
    assert_eq!(attrs.get("program").map(String::as_str), Some("SDGT"));
}

#[test]
fn wallet_entity_records_ofacs_symbol_and_hses_inferred_chain_separately() {
    let sa = SanctionedAddress {
        symbol: "XBT".to_string(),
        address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    };
    let e = build_wallet(&wallet_record(), &sa, "s", Provenance::Address);

    assert_eq!(e.kind, EntityKind::CryptoAddress);
    assert_eq!(e.value, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    assert!(e.has_tag("sanctioned-wallet") && e.has_tag("crypto-address"));
    // HSE's shape-based inference, which `chain_intel` keys off…
    assert!(
        e.has_tag("chain:btc"),
        "a valid base58check BTC address must carry the pivot tag: {:?}",
        e.tags
    );
    // …kept distinct from Treasury's own statement of what it designated.
    let attrs = &e.evidence[0].attributes;
    assert_eq!(
        attrs.get("designated_currency").map(String::as_str),
        Some("XBT")
    );
    assert_eq!(
        attrs.get("designated_entity").map(String::as_str),
        Some("Ivan Ivanov"),
        "the wallet must name whose entry designated it, humanised like the subject"
    );
}

#[test]
fn a_wallet_reached_by_a_name_match_inherits_the_name_matchs_weakness() {
    let sa = SanctionedAddress {
        symbol: "XBT".to_string(),
        address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    };
    let pivot = build_wallet(&wallet_record(), &sa, "s", Provenance::Name);
    let direct = build_wallet(&wallet_record(), &sa, "s", Provenance::Address);

    // OFAC certainly designated this wallet either way — but reached via a
    // fuzzy name, its link to the operator's SUBJECT is only as strong as that
    // name match, so it must not be graded as if the operator had pasted it.
    assert!((pivot.confidence - HIT_CONFIDENCE).abs() < 1e-9);
    assert!(pivot.confidence < direct.confidence);
    assert!(pivot.has_tag("needs-identity-verification"));
    assert!(pivot.evidence[0].attributes.contains_key("caution"));
    // Both still assert the designation itself, which is not in doubt.
    assert!(pivot.has_tag("sanctioned-wallet") && direct.has_tag("sanctioned-wallet"));
}

#[test]
fn an_unrecognisable_address_shape_still_emits_the_designation() {
    // A symbol HSE has no classifier for (TRX, USDT, DASH, …) must not cause
    // the sanctions finding to be dropped — the designation is OFAC's, not
    // ours, and only the `chain:` pivot tag depends on our recognising it.
    let sa = SanctionedAddress {
        symbol: "TRX".to_string(),
        address: "TZ4UXDV5ZhNW7fb2AMSbgfAEZ7hWsnYS2g".to_string(),
    };
    let e = build_wallet(&wallet_record(), &sa, "s", Provenance::Address);
    assert_eq!(e.value, "TZ4UXDV5ZhNW7fb2AMSbgfAEZ7hWsnYS2g");
    assert!(e.has_tag("sanctioned-wallet"));
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("designated_currency")
            .map(String::as_str),
        Some("TRX")
    );
    assert!(
        !e.tags.iter().any(|t| t.starts_with("chain:")),
        "no chain tag may be invented for a shape HSE cannot classify: {:?}",
        e.tags
    );
}

/// A failed OFAC download with NO usable cached list must be an error, never an
/// empty screening set.
///
/// This is the module's worst possible failure: the caller iterates the returned
/// records to find hits, so an empty set produces zero hits — byte-identical to
/// the answer for a subject who is genuinely not designated. A transport failure
/// would therefore render as an affirmative sanctions clearance for a name that
/// was never actually checked, and that output is used in engagement reporting.
///
/// The stale-list path is deliberately NOT an error: OFAC publishes irregularly,
/// so screening against a previously-downloaded set still answers the question.
#[test]
fn failed_download_without_a_cached_list_is_an_error_not_a_clean_screen() {
    use super::list::degrade_on_fetch_failure;

    let rec = |name: &str| super::parse::SdnRecord {
        list: super::parse::OfacList::Sdn,
        ent_num: 1,
        name: name.to_string(),
        kind: SdnKind::Individual,
        program: "SDN".to_string(),
        title: String::new(),
        remarks: String::new(),
    };

    // Cold cache: nothing has ever loaded. Screening is impossible, not clean.
    let err = degrade_on_fetch_failure(None)
        .expect_err("a cold-cache download failure must NOT yield an empty screening set");
    let msg = err.to_string();
    assert!(
        msg.contains("sanctions_ofac"),
        "error must name the module so it reaches the operator: {msg}"
    );

    // An empty cached list screens exactly as blindly as no list at all, so it
    // must be treated the same way rather than passed off as a real set.
    degrade_on_fetch_failure(Some(Vec::new()))
        .expect_err("an EMPTY cached list is not a usable screening set");

    // A stale but populated list IS a sound degradation — preserved, not broken.
    let stale = vec![rec("ABBAS, Abu"), rec("Banco Nacional de Cuba")];
    let got = degrade_on_fetch_failure(Some(stale.clone()))
        .expect("a populated cached list must still screen");
    assert_eq!(
        got.len(),
        stale.len(),
        "the stale list must be returned intact, not truncated or emptied"
    );
    assert_eq!(got[0].name, "ABBAS, Abu");
}

/// Every route that can hand the caller a record set must agree on what counts as
/// screenable, because each one of them is a way to produce a false clean screen.
///
/// The first version of this fix guarded only the transport-failure route and left
/// two others returning `Ok(vec![])`: the cache fast path (an empty cached set was
/// served straight back as a successful screen) and a 2xx whose body parsed to zero
/// rows (which was then cached, serving that blindness for the whole 12h TTL).
/// `is_screenable` is the single definition all three now consult, so they cannot
/// drift apart again.
#[test]
fn an_empty_record_set_is_never_screenable_by_any_route() {
    use super::list::{degrade_on_fetch_failure, is_screenable};

    let rec = || super::parse::SdnRecord {
        list: super::parse::OfacList::Sdn,
        ent_num: 1,
        name: "ABBAS, Abu".to_string(),
        kind: SdnKind::Individual,
        program: "SDN".to_string(),
        title: String::new(),
        remarks: String::new(),
    };

    // The shared rule itself.
    assert!(
        !is_screenable(&[]),
        "an empty set answers every query with 'no designations' — never screenable"
    );
    assert!(is_screenable(&[rec()]), "a populated set is screenable");

    // The degradation route consults the same rule, so an empty cache is an error
    // rather than a clean screen.
    degrade_on_fetch_failure(Some(Vec::new()))
        .expect_err("an empty cached set must not be served as a successful screen");
    assert!(
        degrade_on_fetch_failure(Some(vec![rec()])).is_ok(),
        "a populated cached set must still degrade gracefully"
    );
}

// ── List of origin ───────────────────────────────────────────────────────────

/// REGRESSION (docs/PROVIDER_SWEEP_BACKLOG.md #35). Consolidated-list rows are
/// screened alongside SDN rows but are NOT SDN designations: a sectoral / FSE /
/// NS-ISA / PLC listing is a sanction, not a full-blocking one. Every finding
/// off such a row used to be stamped `register = "OFAC Specially Designated
/// Nationals (SDN) List"` and summarised "OFAC SDN list match" — the most
/// serious register asserted for a row that was never on it.
#[test]
fn a_consolidated_list_row_is_never_reported_as_an_sdn_match() {
    let mut rec = organisation_record();
    rec.list = super::parse::OfacList::Consolidated;
    let e = super::entity::build_subject(&rec, "scan-1", super::entity::Provenance::Name)
        .expect("organisation row maps to an entity");
    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("register").map(String::as_str),
        Some("OFAC Consolidated (non-SDN) Sanctions List")
    );
    assert!(
        ev.summary.starts_with("OFAC Consolidated (non-SDN) list match:"),
        "{}",
        ev.summary
    );
    assert!(!ev.summary.contains("SDN list match"), "{}", ev.summary);
    assert!(e.has_tag("ofac-consolidated"), "{:?}", e.tags);
    assert!(!e.has_tag("ofac-sdn"), "{:?}", e.tags);
    // The shared tags still apply — it IS a sanctions designation.
    assert!(e.has_tag("sanctions") && e.has_tag("ofac"), "{:?}", e.tags);
}

/// The control: an SDN row keeps its SDN register, summary and tag.
#[test]
fn an_sdn_row_is_reported_as_an_sdn_match() {
    let rec = organisation_record();
    assert_eq!(rec.list, super::parse::OfacList::Sdn);
    let e = super::entity::build_subject(&rec, "scan-1", super::entity::Provenance::Name)
        .expect("organisation row maps to an entity");
    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("register").map(String::as_str),
        Some("OFAC Specially Designated Nationals (SDN) List")
    );
    assert!(ev.summary.starts_with("OFAC SDN list match:"), "{}", ev.summary);
    assert!(e.has_tag("ofac-sdn") && !e.has_tag("ofac-consolidated"), "{:?}", e.tags);
}

/// The wallet pivot off a consolidated-list row carries the same list, so the
/// address finding cannot claim SDN either.
#[test]
fn a_wallet_off_a_consolidated_list_row_carries_the_consolidated_register() {
    let mut rec = wallet_record();
    rec.list = super::parse::OfacList::Consolidated;
    let addrs = super::crypto::digital_currency_addresses(&rec.remarks);
    let addr = addrs.first().expect("the wallet fixture carries an address");
    let e = super::entity::build_wallet(&rec, addr, "scan-1", super::entity::Provenance::Name);
    assert_eq!(
        e.evidence[0].attributes.get("register").map(String::as_str),
        Some("OFAC Consolidated (non-SDN) Sanctions List")
    );
    assert!(e.has_tag("ofac-consolidated") && !e.has_tag("ofac-sdn"), "{:?}", e.tags);
}

/// REQ-SKIPCLASS-001. A name the screen REFUSED to run is not a clean sanctions
/// result. `Ok(empty)` is recorded by dispatch as `ModuleDone { found: 0 }`,
/// which `core::coverage` aggregates to `ProviderOutcome::CleanNegative` — "the
/// only outcome that is a real negative", and the one `settles_absence()`
/// trusts. For a sanctions screen that is the worst possible misreport: AU-114
/// grades a designation Critical, so the operator's due-diligence answer rests
/// on the ABSENCE of a finding.
///
/// The reach is not hypothetical — `parse_tests.rs` pins
/// `name_tokens("Al Zawahiri") == ["zawahiri"]`, a single token, so that exact
/// query is refused. Mononyms (OFAC's SDN list carries many) and short
/// romanised names ("Li Wu") land the same way.
#[test]
fn a_query_too_weak_to_screen_is_a_typed_skip_not_a_clean_negative() {
    use crate::core::error::Error;
    use crate::core::event::SkipClass;

    for weak in ["Al Zawahiri", "Li Wu", "Madonna", "Abu"] {
        let err = screening_tokens(weak)
            .expect_err("a query below the discriminator floor must not read as screened");
        let Error::Skipped { class, reason } = err else {
            panic!("{weak}: expected Error::Skipped, got {err}");
        };
        // `Scoped`, not `NotApplicable`: OFAC could have answered — this module
        // declined to ask on its own misattribution policy, and the operator can
        // close the gap by supplying a fuller name. `is_coverage_gap()` must
        // therefore be true, which `NotApplicable` would wrongly deny.
        assert_eq!(class, SkipClass::Scoped, "{weak}");
        assert!(class.is_coverage_gap(), "{weak}: the operator is owed this answer");
        assert!(
            reason.contains(weak),
            "{weak}: the reason must name the value it declined: {reason}"
        );
        assert!(
            !reason.to_lowercase().contains("no match")
                && !reason.to_lowercase().contains("found nothing"),
            "{weak}: a skip reason must never read as 'found nothing': {reason}"
        );
    }

    // Non-vacuity: a discriminating two-token name clears the floor and returns
    // its tokens, so the guard cannot be passing by refusing everything.
    let tokens = screening_tokens("Abu Abbas").expect("a two-token name must be screenable");
    assert_eq!(tokens, vec!["abu", "abbas"]);
}

fn skip_test_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "skipclass".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

/// The same defect at the module boundary, driven through the real `process`.
/// Hermetic: the discriminator floor is checked BEFORE `fetch_sdn_list`, so a
/// refused name never opens a socket.
#[tokio::test]
async fn process_refusing_a_weak_name_must_not_answer_ok() {
    let out = SanctionsOfac
        .process(&Target::new(TargetKind::FullName, "Al Zawahiri"), &skip_test_ctx())
        .await;
    match out {
        Ok(r) => panic!(
            "REQ-SKIPCLASS-001: a name the screen refused answered Ok with {} entities — \
             dispatch records that as ModuleDone{{found:0}} and coverage aggregates it to \
             CleanNegative, i.e. 'OFAC holds nothing on this subject' for a list never consulted",
            r.entities.len()
        ),
        Err(crate::core::error::Error::Skipped { .. }) => {}
        Err(other) => panic!("expected a typed skip, got {other}"),
    }
}

// ── REQ-OFAC-002: the list is reached through OFAC's pre-signed S3 redirect,
// and a failed download is fetched once, not once per dispatch ──────────────
//
// Both download endpoints answer `302` to a pre-signed S3 URL. The shared
// client stops that hop (it leaves `treas.gov`'s registrable domain), and the
// fetcher read the `302` as a failed download — so screening never had a list
// in production — and, because only a success was ever recorded, every
// dispatch in a scan re-downloaded and re-failed.

/// The `Location` shape OFAC was observed issuing for `SDN.CSV` (2026-09-23).
/// Bucket, region, path and parameter layout are as captured; the session
/// token, credential and signature VALUES are placeholders — this fixture
/// proves the host/scheme judgement, never that a real URL is still signed.
const S3_LOCATION: &str = "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/6f141e88-8b06-41e6-89e7-d4017d73a738/2026-09-17/ac391fbd-8ac6-4dce-b73b-115435194157/SDN.CSV?X-Amz-Expires=3600&X-Amz-Security-Token=PLACEHOLDER&response-content-disposition=attachment%3B%20filename%3D%22sdn.csv%22&response-content-type=text%2Fcsv&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=PLACEHOLDER%2F20260923%2Fus-gov-west-1%2Fs3%2Faws4_request&X-Amz-Date=20260923T040227Z&X-Amz-SignedHeaders=host&X-Amz-Signature=0000000000000000000000000000000000000000000000000000000000000000";

/// A real SDN row (see `parse_tests.rs`), served by the loopback fixtures below.
const SDN_ROW: &str =
    r#"36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- "#;

/// A context on the SHARED client — the one production dispatches with. A bare
/// `reqwest::Client::new()` follows every redirect itself, so a test on it
/// would pass without this module's hop ever running.
fn shared_client_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "ofac-hop".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

#[test]
fn presigned_hop_accepts_the_s3_location_ofac_actually_issues() {
    use super::list::presigned_hop;

    let hop = presigned_hop(S3_LOCATION).expect("OFAC's own redirect target must be followed");
    assert_eq!(
        hop.host_str(),
        Some("wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com")
    );
    assert!(hop.path().ends_with("/SDN.CSV"), "{}", hop.path());
    // The signature is the whole authorisation — the hop must carry the query
    // through intact, not just the host.
    let query = hop.query().unwrap_or_default();
    assert!(
        query.contains("X-Amz-Signature=") && query.contains("X-Amz-Expires=3600"),
        "{query}"
    );

    // The Consolidated list lands on the same bucket.
    let cons = S3_LOCATION.replace("/SDN.CSV?", "/CONS_PRIM.CSV?");
    assert!(presigned_hop(&cons).is_some());
    // `url` lowercases the host and drops a spelled-out default port, so
    // neither is a way to be refused for a URL that is the same place.
    assert!(
        presigned_hop(
            "https://WC2H-SLS-PROD-PUBLIC-PUBLISHED.S3.US-GOV-WEST-1.AMAZONAWS.COM/SDN.CSV"
        )
        .is_some()
    );
    assert!(
        presigned_hop(
            "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com:443/SDN.CSV"
        )
        .is_some()
    );
}

#[test]
fn presigned_hop_refuses_every_other_redirect_target() {
    use super::list::presigned_hop;

    const S3: &str = "wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com";
    let refused = [
        (
            format!("http://{S3}/SDN.CSV"),
            "plaintext downgrade of the list the screen rests on",
        ),
        (
            "https://evil.example/SDN.CSV".to_string(),
            "a host that is not AWS",
        ),
        (
            "https://amazonaws.com.evil.example/SDN.CSV".to_string(),
            "the AWS suffix as a PREFIX",
        ),
        (
            "https://evilamazonaws.com/SDN.CSV".to_string(),
            "the suffix without its dot",
        ),
        (
            "https://amazonaws.com/SDN.CSV".to_string(),
            "the bare apex — no bucket label",
        ),
        (
            "https://.amazonaws.com/SDN.CSV".to_string(),
            "an empty label in front of the suffix",
        ),
        ("https://52.46.128.1/SDN.CSV".to_string(), "an IPv4 literal"),
        (
            "https://169.254.169.254/latest/meta-data/".to_string(),
            "the cloud-metadata address",
        ),
        (
            "https://2130706433/SDN.CSV".to_string(),
            "an IPv4 literal spelled as one number (127.0.0.1)",
        ),
        (
            "https://[2600:1f14::1]/SDN.CSV".to_string(),
            "an IPv6 literal",
        ),
        (format!("https://user:pass@{S3}/SDN.CSV"), "userinfo"),
        (format!("https://user@{S3}/SDN.CSV"), "a username alone"),
        (
            format!("https://{S3}@evil.example/SDN.CSV"),
            "the S3 host as userinfo in front of another host",
        ),
        (format!("https://{S3}:8443/SDN.CSV"), "a non-default port"),
        (format!("ftp://{S3}/SDN.CSV"), "another scheme"),
        (
            "/Published/SDN.CSV".to_string(),
            "a relative Location (it would resolve onto treas.gov)",
        ),
        (String::new(), "an empty Location"),
    ];
    for (location, why) in &refused {
        assert!(
            presigned_hop(location).is_none(),
            "{why}: `{location}` must not be followed"
        );
    }
}

/// Why the module takes the hop itself, recorded against the client production
/// uses: the shared client does NOT follow a cross-site redirect to S3, it hands
/// the `302` back — and that `302`'s `Location` is one [`presigned_hop`]
/// accepts.
///
/// The decision is `util::http::ssrf::redirect_verdict`, which is private to
/// `util::http` and cannot be called from here, so it is pinned through
/// `build_client()` instead. The origin is a loopback fixture rather than
/// `treas.gov`, but the next hop is a DNS name, so the private-IP arm (which
/// judges IP literals only) is not what stops it: the cross-site arm is. That
/// is the arm that stops `treas.gov` → `amazonaws.com` too, though this test
/// cannot pin that exact pair — an IP origin and a name are never the same site
/// however names are compared — so the pair itself is `redirect_verdict`'s to
/// pin in `util::http`'s own tests. Hermetic while the rule holds; if the client
/// ever followed this hop it would head for S3 and the test fails on the status
/// (or the timeout) — the cue to revisit the hop and the module doc.
///
/// [`presigned_hop`]: super::list::presigned_hop
#[tokio::test]
async fn the_shared_client_hands_back_ofacs_s3_redirect_unfollowed() {
    use crate::util::http::test_server::{Canned, serve};

    let origin = serve(vec![Canned::text(302, "").header("Location", S3_LOCATION)]).await;
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        crate::util::http::build_client()
            .get(format!("{origin}/api/download/SDN.CSV"))
            .send(),
    )
    .await
    .expect("a stopped redirect answers at once; only a followed one leaves loopback")
    .expect("the stopped redirect surfaces as the 3xx response, not a request error");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FOUND,
        "the shared client must hand back OFAC's cross-site 302 unfollowed"
    );
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("the 302 keeps its Location");
    assert!(super::list::presigned_hop(location).is_some());
}

/// The hop is taken ONLY to a pre-signed S3 target, end to end through
/// `fetch_one_list` on the shared client — even when the refused target would
/// have served a perfectly valid list.
///
/// The decoy holds exactly one canned answer, so the direct fetch afterwards
/// proves two things at once: the list there is valid (non-vacuity), and nothing
/// consumed that answer first — the redirect was never followed, by the client
/// or by the module.
#[tokio::test]
async fn fetch_one_list_follows_no_redirect_but_the_presigned_one() {
    use super::list::{fetch_one_list, is_screenable};
    use super::parse::OfacList;
    use crate::util::http::test_server::{Canned, serve};

    let decoy = serve(vec![Canned::text(200, SDN_ROW)]).await;
    let origin = serve(vec![
        Canned::text(302, "").header("Location", format!("{decoy}/SDN.CSV")),
    ])
    .await;
    let ctx = shared_client_ctx();

    assert!(
        fetch_one_list(
            &ctx,
            &format!("{origin}/api/download/SDN.CSV"),
            OfacList::Sdn
        )
        .await
        .is_none(),
        "a redirect to anything but OFAC's pre-signed S3 download must fail the list"
    );
    let direct = fetch_one_list(&ctx, &format!("{decoy}/SDN.CSV"), OfacList::Sdn)
        .await
        .expect("the decoy's single answer must still be unspent");
    assert!(is_screenable(&direct));
    assert_eq!(direct[0].name, "AEROCARIBBEAN AIRLINES");
}

/// The refresh decision, row by row. `(cache_age, since_failure)` are the two
/// durations the store measures; `None` means "no screenable list" and "last
/// attempt succeeded / none made" respectively.
#[test]
fn should_refetch_truth_table() {
    use super::list::{FAILURE_COOLDOWN_SECS, LIST_CACHE_TTL_SECS, should_refetch};
    use std::time::Duration;

    let s = Duration::from_secs;
    let ttl = s(LIST_CACHE_TTL_SECS);
    let cool = s(FAILURE_COOLDOWN_SECS);
    let rows = [
        (
            None,
            None,
            true,
            "cold start: nothing cached, nothing failed",
        ),
        (Some(s(0)), None, false, "just downloaded"),
        (
            Some(ttl - s(1)),
            None,
            false,
            "a list inside its TTL is served as-is",
        ),
        (Some(ttl), None, true, "the TTL has elapsed"),
        // The defect: with no memo, every one of a scan's dispatches re-downloaded.
        (
            None,
            Some(s(0)),
            false,
            "no list, a failure just now — do not re-download",
        ),
        (None, Some(cool - s(1)), false, "still inside the cool-down"),
        (
            None,
            Some(cool),
            true,
            "the cool-down has elapsed — try again",
        ),
        (
            Some(ttl + s(3600)),
            Some(s(30)),
            false,
            "stale list + recent failure: serve the stale list",
        ),
        (
            Some(ttl + s(3600)),
            Some(cool + s(1)),
            true,
            "stale list + an old failure: refresh",
        ),
        (
            Some(s(10)),
            Some(s(10)),
            false,
            "a fresh list wins whatever the memo says",
        ),
    ];
    for (cache_age, since_failure, want, why) in rows {
        assert_eq!(
            should_refetch(cache_age, since_failure),
            want,
            "{why}: cache_age={cache_age:?} since_failure={since_failure:?}"
        );
    }
}

/// Three dispatches arrive together on a cold cache and the download fails: one
/// download, three honest errors — and a fourth dispatch inside the cool-down
/// neither downloads nor answers anything but that same error.
///
/// Before: no gate and no memo, so each dispatch made its own attempt (a real
/// scan logged the failure six times). The yield inside the scripted download
/// is what makes this concurrent: the other two reach the gate while the first
/// is still "downloading".
#[tokio::test]
async fn concurrent_dispatches_share_one_failed_download_and_it_is_remembered() {
    use super::list::ListStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let store = ListStore::default();
    let downloads = AtomicUsize::new(0);
    let failing = || async {
        downloads.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        None::<Vec<SdnRecord>>
    };

    let (a, b, c) = tokio::join!(
        store.get_or_refresh(failing),
        store.get_or_refresh(failing),
        store.get_or_refresh(failing),
    );
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        1,
        "one download for the whole burst"
    );
    for r in [a, b, c] {
        let err = r.expect_err("no list was ever loaded — this is not a clean screen");
        assert!(err.to_string().contains("sanctions_ofac"), "{err}");
    }

    store
        .get_or_refresh(failing)
        .await
        .expect_err("inside the cool-down the answer is still the honest error");
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        1,
        "a failure inside the cool-down must not be re-downloaded"
    );
}

/// The success side of the same gate: the burst shares one download, every
/// dispatch gets the list, and a later one is served from the cache.
#[tokio::test]
async fn concurrent_dispatches_share_one_successful_download() {
    use super::list::ListStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let store = ListStore::default();
    let downloads = AtomicUsize::new(0);
    let succeeding = || async {
        downloads.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        Some(vec![individual_record()])
    };

    let (a, b, c) = tokio::join!(
        store.get_or_refresh(succeeding),
        store.get_or_refresh(succeeding),
        store.get_or_refresh(succeeding),
    );
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        1,
        "one download for the whole burst"
    );
    for r in [a, b, c] {
        let list = r.expect("every queued dispatch gets the list the first one fetched");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "ABBAS, Abu");
    }

    store
        .get_or_refresh(succeeding)
        .await
        .expect("a fresh cache serves");
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        1,
        "a fresh cache is never re-downloaded"
    );
}

/// A download that parses to nothing is a failure to the store too: never
/// cached as a (blind) screen, and remembered like any other failure.
#[tokio::test]
async fn an_empty_download_is_remembered_as_a_failure_not_cached() {
    use super::list::ListStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let store = ListStore::default();
    let downloads = AtomicUsize::new(0);
    let empty = || async {
        downloads.fetch_add(1, Ordering::SeqCst);
        Some(Vec::<SdnRecord>::new())
    };

    store
        .get_or_refresh(empty)
        .await
        .expect_err("an empty list is not a screen");
    store
        .get_or_refresh(empty)
        .await
        .expect_err("and it was not cached as one");
    assert_eq!(
        downloads.load(Ordering::SeqCst),
        1,
        "the empty result was memoised as a failure"
    );
}

/// Live proof of the hop against the REAL service, on the production client:
/// OFAC's `302`, the module's own hop to S3, and a parsed list. Uses the small
/// Consolidated list (~263 KB) rather than SDN (~5.7 MB). Ignored by default
/// (network); run with
/// `cargo test sanctions_ofac::tests::ofac_live -- --ignored --nocapture`.
/// The shared client ignores `HTTPS_PROXY` by design, so it needs direct egress.
#[tokio::test]
#[ignore = "hits the live OFAC Sanctions List Service and its S3 bucket; run manually"]
async fn ofac_live_download_takes_the_presigned_s3_hop() {
    use super::list::{CONS_URL, fetch_one_list, is_screenable};
    use super::parse::OfacList;

    let cons = fetch_one_list(&shared_client_ctx(), CONS_URL, OfacList::Consolidated)
        .await
        .expect("the live Consolidated list must download through the pre-signed hop");
    assert!(is_screenable(&cons));
    assert!(cons.iter().all(|r| r.list == OfacList::Consolidated));
    eprintln!("sanctions_ofac live: {} Consolidated rows", cons.len());
}
