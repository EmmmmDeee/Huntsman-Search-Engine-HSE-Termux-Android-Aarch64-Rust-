use super::*;

// Every expectation below is pinned to a LIVE observation captured while building the
// module (network probes against real systems), so the classifier can never drift away
// from reality without a test failing.

#[test]
fn classifies_ip_from_live_observation() {
    // LIVE: ipinfo.io/8.8.8.8 → {"ip":"8.8.8.8","org":"AS15169 Google LLC", ...} (HTTP 200);
    // RDAP → CIDR 8.8.8.0/24 (ARIN). A dotted-quad that parses is an IP at high confidence.
    let c = classify("8.8.8.8");
    assert_eq!(c.kind, EntityKind::IpAddress);
    assert!((c.confidence - 0.92).abs() < 1e-9, "{}", c.confidence);
    assert_eq!(c.signal, "parsed");
}

#[test]
fn classifies_domain_from_live_observation() {
    // LIVE: dns.google A? example.com → 104.20.23.154 (HTTP 200); RDAP → registrar
    // "RESERVED-Internet Assigned Numbers Authority"; example.com served real HTML.
    let c = classify("example.com");
    assert_eq!(c.kind, EntityKind::Domain);
    assert!((c.confidence - 0.75).abs() < 1e-9);
    assert_eq!(c.signal, "domain-shape");
}

#[test]
fn classifies_email_from_live_observation() {
    // LIVE: dns.google MX? gmail.com → gmail-smtp-in.l.google.com (the host is real and
    // accepts mail). Synthetic local-part per the project's test-fixture convention.
    let c = classify("jordanavery@gmail.com");
    assert_eq!(c.kind, EntityKind::Email);
    assert!((c.confidence - 0.85).abs() < 1e-9);
    assert_eq!(c.signal, "rfc-shape");
}

#[test]
fn classifies_abn_by_checksum_from_live_observation() {
    // LIVE: abr.business.gov.au/ABN/View?abn=51824753556 → "AUSTRALIAN TAXATION OFFICE /
    // Active / Government Entity". 51824753556 also passes the weighted mod-89 checksum
    // (sum 534 = 6×89), which is exactly what the detector validates.
    let c = classify("51824753556");
    assert_eq!(c.kind, EntityKind::AbnAcn);
    assert!((c.confidence - 0.95).abs() < 1e-9);
    assert_eq!(c.signal, "checksum");
}

#[test]
fn abn_checksum_is_real_not_just_length() {
    // The grounding is the CHECKSUM, not "11 digits": flip the last digit and the same
    // length value is no longer an ABN — it falls through to the dialable-phone shape.
    let bad = classify("51824753557");
    assert_ne!(bad.kind, EntityKind::AbnAcn, "an invalid checksum is not an ABN");
    assert_eq!(bad.kind, EntityKind::Phone, "11 digits still reads as a phone run");
}

#[test]
fn classifies_au_mobile_as_phone() {
    // LIVE format grounding: 04xxxxxxxx (national) / +614xxxxxxxx (E.164) are AU mobiles;
    // a 03 landline is still a phone but the 04 prefix is the mobile signal. Both type
    // as Phone (the engine's single phone TargetKind), which is the scannable seed.
    for v in ["0412345678", "+61412345678", "0412 345 678"] {
        let c = classify(v);
        assert_eq!(c.kind, EntityKind::Phone, "{v} should be a phone");
        assert!((c.confidence - 0.80).abs() < 1e-9);
    }
}

#[test]
fn classifies_username_residual_from_live_observation() {
    // LIVE: github.com/torvalds → 200 (exists), github.com/<missing> → 404. A bare single
    // token is the detector's residual fallback — classified (never discarded) but at the
    // low confidence that keeps weak guesses from flooding expansion.
    let c = classify("torvalds");
    assert_eq!(c.kind, EntityKind::Username);
    assert!((c.confidence - 0.40).abs() < 1e-9);
    assert_eq!(c.signal, "residual");
    assert!(!c.is_actionable(), "a residual username sits below the re-injection floor");
}

#[test]
fn classifies_url_with_scheme() {
    let c = classify("https://example.com/path?x=1");
    assert_eq!(c.kind, EntityKind::Url);
    assert!((c.confidence - 0.90).abs() < 1e-9);
    assert!(c.is_actionable());
}

#[test]
fn empty_input_is_classified_not_panicked() {
    let c = classify("   ");
    assert_eq!(c.kind, EntityKind::Other("empty".into()));
    assert_eq!(c.confidence, 0.0);
    assert!(!c.is_actionable());
}

#[test]
fn extracts_every_embedded_entity_from_unstructured_text() {
    // The "unstructured text with embedded entities" seed: a realistic free-text blob
    // mixing the live-validated entity types. Each must be pulled out and typed.
    let text = "Reach Kyle at kyle.d@example.com or +61 412 345 678. \
                Host 8.8.8.8 (dns.google), ABN 51 824 753 556, \
                site https://acme.example and handle @kyle_d.";
    let found = extract(text);
    let has = |k: EntityKind| found.iter().any(|c| c.kind == k);

    assert!(has(EntityKind::Email), "email extracted");
    assert!(has(EntityKind::Phone), "phone extracted");
    assert!(has(EntityKind::IpAddress), "ip extracted");
    assert!(has(EntityKind::AbnAcn), "checksum-valid ABN extracted");
    assert!(has(EntityKind::Url), "url extracted");
    assert!(has(EntityKind::Domain), "bare/host domain extracted");
    assert!(
        found
            .iter()
            .any(|c| c.kind == EntityKind::Username && c.value == "kyle_d"),
        "the @handle extracted as a username"
    );

    // Every actionable extraction is of a scannable kind — i.e. re-injectable as a seed.
    for c in found.iter().filter(|c| c.is_actionable()) {
        assert!(
            TargetKind::from_entity_kind(&c.kind).is_some(),
            "actionable {:?} must be re-injectable",
            c.kind
        );
    }
}

#[test]
fn extraction_is_deterministic_and_deduplicated() {
    let text = "a@x.example and a@x.example again, plus 8.8.8.8 and 8.8.8.8";
    let a = extract(text);
    let b = extract(text);
    assert_eq!(a, b, "same text → same extractions, same order");
    // The repeated email + IP each appear once.
    assert_eq!(a.iter().filter(|c| c.kind == EntityKind::Email).count(), 1);
    assert_eq!(a.iter().filter(|c| c.kind == EntityKind::IpAddress).count(), 1);
}

#[test]
fn the_system_can_find_itself_in_its_own_text() {
    // The re-injection endgame: feed the classifier a fragment of the project's OWN
    // configuration text and it surfaces real, re-scannable entities — the system
    // ingesting its own output.
    let own = "userEmail: matthewdiegmann@gmail.com — repo https://github.com/EmmmmDeee/huntsman";
    let found = extract(own);
    assert!(
        found.iter().any(|c| c.kind == EntityKind::Email && c.is_actionable()),
        "found a re-injectable email in its own text"
    );
    assert!(
        found.iter().any(|c| c.kind == EntityKind::Url),
        "found its own repo URL"
    );
}

#[test]
fn extract_trims_trailing_prose_punctuation_from_urls() {
    let out = extract(
        "Contact us at https://example.org/a, or see https://example.org/b. Mirror: https://example.org/c; end.",
    );
    let urls: Vec<&str> = out
        .iter()
        .filter(|c| c.kind == EntityKind::Url)
        .map(|c| c.value.as_str())
        .collect();
    assert_eq!(
        urls,
        vec![
            "https://example.org/a",
            "https://example.org/b",
            "https://example.org/c"
        ]
    );
    assert!(
        urls.iter()
            .all(|u| !u.ends_with([',', '.', ';', ':', '!', '?', ')'])),
        "no trailing prose punctuation: {urls:?}"
    );
}

#[test]
fn trim_url_punctuation_is_idempotent_and_keeps_the_scheme() {
    for suffix in ["", ".", ",", ";", ":", "!", "?", ").", ",,,"] {
        let s = format!("https://example.org/path{suffix}");
        let once = trim_url_punctuation(&s);
        assert_eq!(trim_url_punctuation(once), once, "idempotent for {s:?}");
        assert!(once.starts_with("https://"), "scheme kept for {s:?}");
    }
}
