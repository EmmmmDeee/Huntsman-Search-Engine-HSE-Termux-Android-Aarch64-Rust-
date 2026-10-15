use super::*;
use crate::http::Response;
use crate::source_outcome::SourceOutcomeKind;
use crate::test_support::{ScriptedTransport, json_ok};
use crate::x509::tests::EV_RSA;

const DOMAIN: &str = "digicert.com";
const EV_SHA: &str = "2a9018372f2ef9caa8697c62b471e31e42490d9d993fcc1c0df3ea9df438a309";

/// The PEM fixture's body, as Cert Spotter's `cert_der` carries it.
fn der_base64(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

/// The extended-validation certificate as Cert Spotter returned it.
fn ev_issuance() -> String {
    serde_json::json!({
        "id": "15000000001",
        "tbs_sha256": "e3c6f3f2a1cb8f3a0b6e6c1d1d6e6b6f8a8f0e6c9d0d1b1a0c8a8f6e2d1c0b9a",
        "cert_sha256": EV_SHA,
        "dns_names": [
            "admin.digicert.com", "api.digicert.com", "cart.digicert.com",
            "content.digicert.com", "digicert.com", "login.digicert.com",
            "order.digicert.com", "ws.digicert.com", "www.digicert.com"
        ],
        "pubkey_sha256": "9b2f4ad8c6c9b3c2f1e3a1d7e6b4a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3",
        "issuer": {
            "friendly_name": "DigiCert",
            "pubkey_sha256": "c1e2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
            "name": "C=US, O=DigiCert Inc, CN=DigiCert EV RSA CA G2"
        },
        "not_before": "2026-07-28T00:00:00Z",
        "not_after": "2027-02-11T23:59:59Z",
        "revoked": false,
        "revocation": { "time": null, "reason": null, "checked_at": "2026-10-15T14:45:53Z" },
        "problem_reporting": "Send email to revoke@digicert.com",
        "cert_der": der_base64(EV_RSA)
    })
    .to_string()
}

/// A revoked wildcard issuance whose certificate Cert Spotter did not include.
fn revoked_issuance() -> String {
    serde_json::json!({
        "id": "15000000002",
        "cert_sha256": "0000000000000000000000000000000000000000000000000000000000000002",
        "dns_names": ["*.dev.digicert.com", "partner-site.net"],
        "issuer": { "friendly_name": "Sectigo", "name": "C=GB, O=Sectigo Limited, CN=Sectigo DV E36" },
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-12-31T23:59:59Z",
        "revoked": true,
        "revocation": { "time": "2026-03-01T10:00:00Z", "reason": 1, "checked_at": "2026-10-15T00:00:00Z" }
    })
    .to_string()
}

fn page(issuances: &[String]) -> Response {
    json_ok(&format!("[{}]", issuances.join(",")))
}

fn status(code: u16) -> Response {
    let mut response = json_ok("{}");
    response.status = code;
    response
}

/// A transport answering each request with the next of `responses`.
fn script(responses: Vec<Response>) -> ScriptedTransport {
    ScriptedTransport::new(responses.into_iter().map(Ok).collect())
}

fn find<'a>(entities: &'a [Entity], kind: &EntityKind, value: &str) -> &'a Entity {
    entities
        .iter()
        .find(|entity| entity.kind == *kind && (entity.value == value || entity.raw_value == value))
        .unwrap_or_else(|| panic!("no {kind:?} {value} in {entities:#?}"))
}

fn attr<'a>(evidence: &'a Evidence, key: &str) -> &'a str {
    evidence
        .attributes
        .get(key)
        .map_or_else(|| panic!("no {key} on {evidence:#?}"), String::as_str)
}

/// Every page is read, each certificate is a record on the domain with what the certificate
/// itself says, and every name, organisation and certificate behind them is kept.
#[test]
fn every_logged_certificate_is_read_with_its_names_and_holder() {
    let transport = script(vec![
        page(&[ev_issuance()]),
        page(&[revoked_issuance()]),
        page(&[]),
    ]);
    let mut report = lookup(&transport, &Keys::default(), DOMAIN, "s", 1);
    crate::entity::merge_by_uid(&mut report.entities);

    let urls: Vec<String> = transport
        .seen
        .borrow()
        .iter()
        .map(|r| r.url.clone())
        .collect();
    assert_eq!(urls[0], issuances_url(DOMAIN, None));
    assert!(urls[0].contains("include_subdomains=true&match_wildcards=true&expand=dns_names"));
    assert!(urls[0].ends_with("&expand=cert_der"), "{}", urls[0]);
    assert_eq!(urls[1], issuances_url(DOMAIN, Some("15000000001")));
    assert_eq!(urls[2], issuances_url(DOMAIN, Some("15000000002")));
    assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(
        report.outcome.detail.as_deref(),
        Some("2 certificates on 2 pages")
    );

    let domain = find(&report.entities, &EntityKind::Domain, DOMAIN);
    assert_eq!(domain.evidence.len(), 2, "one record per certificate");
    let ev = &domain.evidence[0];
    assert!(
        ev.summary
            .starts_with(&format!("Certificate {EV_SHA} logged for {DOMAIN}"))
    );
    assert_eq!(attr(ev, "certificate"), EV_RSA);
    assert_eq!(
        attr(ev, "issuer"),
        "C=US, O=DigiCert Inc, CN=DigiCert EV RSA CA G2"
    );
    assert!(attr(ev, "subject").ends_with("O=\"DigiCert, Inc.\", CN=www.digicert.com"));
    assert_eq!(attr(ev, "cert_serial"), "087fffc37919d6c85bf2cddda3e02b7d");
    assert_eq!(attr(ev, "public_key"), "RSA 2048");
    assert_eq!(attr(ev, "signature_algorithm"), "sha256WithRSAEncryption");
    assert_eq!(attr(ev, "not_after"), "2027-02-11T23:59:59Z");
    assert_eq!(attr(ev, "revoked"), "false");
    assert_eq!(
        attr(ev, "problem_reporting"),
        "Send email to revoke@digicert.com"
    );
    let revoked = &domain.evidence[1];
    assert_eq!(attr(revoked, "revoked"), "true");
    assert_eq!(attr(revoked, "revocation_reason"), "1");
    assert_eq!(attr(revoked, "revocation_time"), "2026-03-01T10:00:00Z");
    assert!(!revoked.attributes.contains_key("certificate"));

    let www = find(&report.entities, &EntityKind::Domain, "www.digicert.com");
    assert!(www.has_tag(tags::SUBDOMAIN) && www.has_tag(tags::CT_LOG));
    assert_eq!(attr(&www.evidence[0], "certificates"), EV_SHA);
    let wildcard = find(&report.entities, &EntityKind::Domain, "dev.digicert.com");
    assert_eq!(wildcard.raw_value, "*.dev.digicert.com");
    assert_eq!(
        attr(&wildcard.evidence[0], "wildcard"),
        "*.dev.digicert.com"
    );
    let partner = find(&report.entities, &EntityKind::Domain, "partner-site.net");
    assert!(!partner.has_tag(tags::SUBDOMAIN));

    let holder = find(
        &report.entities,
        &EntityKind::Organisation,
        "DigiCert, Inc.",
    );
    let seen = &holder.evidence[0];
    for (key, value) in [
        ("validation", "extended"),
        ("registration_number", "5299537-0142"),
        ("business_category", "Private Organization"),
        ("jurisdiction_region", "Utah"),
        ("city", "Lehi"),
        ("region", "Utah"),
        ("country", "US"),
        ("certificates", EV_SHA),
    ] {
        assert_eq!(attr(seen, key), value, "{key}");
    }
}

/// A key goes as a bearer token; without one no credential is sent and the source still runs.
#[test]
fn a_configured_key_is_a_bearer_token_and_none_is_needed() {
    let keyed = script(vec![page(&[])]);
    let keys = Keys::parse(&format!("{KEY_SLOT}=cs-test-key-123456\n")).expect("keys");
    let report = lookup(&keyed, &keys, DOMAIN, "s", 1);
    assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    let auth = |transport: &ScriptedTransport| {
        transport.seen.borrow()[0]
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
    };
    assert_eq!(auth(&keyed).as_deref(), Some("Bearer cs-test-key-123456"));

    let keyless = script(vec![page(&[])]);
    let report = lookup(&keyless, &Keys::default(), DOMAIN, "s", 1);
    assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    assert_eq!(auth(&keyless), None);
    assert!(API.wanted(&Keys::default()));
}

/// A lookup that stops part way keeps what it read and says where it stopped; one that stops
/// on its first page is that failure.
#[test]
fn a_stop_part_way_keeps_every_certificate_read_and_says_where() {
    let limited = script(vec![page(&[ev_issuance()]), status(429)]);
    let report = lookup(&limited, &Keys::default(), DOMAIN, "s", 1);
    assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    let detail = report.outcome.detail.as_deref().unwrap_or_default();
    assert!(
        detail.starts_with("1 certificates on 1 pages; stopped after issuance 15000000001: rate"),
        "{detail}"
    );
    assert!(
        report
            .entities
            .iter()
            .any(|e| e.value == "www.digicert.com")
    );

    let refused = script(vec![status(429)]);
    let report = lookup(&refused, &Keys::default(), DOMAIN, "s", 1);
    assert_eq!(report.outcome.kind, SourceOutcomeKind::RateLimited);
    assert!(report.entities.is_empty());

    let pages = (0..=MAX_PAGES)
        .map(|_| page(&[revoked_issuance()]))
        .collect();
    let bounded = script(pages);
    let report = lookup(&bounded, &Keys::default(), DOMAIN, "s", 1);
    assert_eq!(bounded.seen.borrow().len(), MAX_PAGES);
    assert_eq!(
        report.outcome.detail.as_deref(),
        Some(
            "20 certificates on 20 pages; stopped at 20 pages, later issuances follow 15000000002"
        )
    );
}

/// In a saved scan each certificate hangs off the domain as Spiderfoot's certificate types.
#[test]
fn a_saved_scan_lists_each_certificate_under_the_domain() {
    let transport = script(vec![page(&[ev_issuance()]), page(&[])]);
    let mut report = lookup(&transport, &Keys::default(), DOMAIN, "s", 1);
    crate::entity::merge_by_uid(&mut report.entities);
    let target = crate::sf_elements::Target {
        value: DOMAIN,
        kind: "INTERNET_NAME",
    };
    // Ten days before the certificate expires.
    let now = 1_801_526_399;
    let found = crate::sf_elements::elements(target, &report.entities, now);
    let root = &found[1].id;
    let one = |kind: &str| {
        found
            .iter()
            .find(|element| element.kind == kind)
            .unwrap_or_else(|| panic!("no {kind} in {found:#?}"))
    };
    assert_eq!(one("SSL_CERTIFICATE_RAW").data, EV_RSA);
    assert!(
        one("SSL_CERTIFICATE_ISSUED")
            .data
            .ends_with("CN=www.digicert.com")
    );
    assert_eq!(
        one("SSL_CERTIFICATE_ISSUER").data,
        "C=US, O=DigiCert Inc, CN=DigiCert EV RSA CA G2"
    );
    assert_eq!(one("SSL_CERTIFICATE_EXPIRING").data, DOMAIN);
    for kind in [
        "SSL_CERTIFICATE_RAW",
        "SSL_CERTIFICATE_ISSUED",
        "SSL_CERTIFICATE_ISSUER",
    ] {
        assert_eq!(one(kind).source.as_ref(), Some(root), "{kind}");
        assert_eq!(one(kind).module, SOURCE);
    }
    assert!(
        found
            .iter()
            .any(|e| e.kind == "INTERNET_NAME" && e.data == "www.digicert.com")
    );
    assert!(
        found
            .iter()
            .any(|e| e.kind == "COMPANY_NAME" && e.data == "DigiCert, Inc.")
    );
    assert!(
        found
            .iter()
            .any(|e| e.kind == "GEOINFO" && e.data == "Lehi, Utah, US")
    );
}
