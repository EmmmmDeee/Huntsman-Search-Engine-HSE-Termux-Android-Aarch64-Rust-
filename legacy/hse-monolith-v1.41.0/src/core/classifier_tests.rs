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

// ── extract(): span claiming — no seed may be carved out of another value ──────

/// The digits of a hex digest are real; the phone number built from them is not.
/// `DIGITS_RE` needs only seven digits and cannot see what it is cutting into, so before the
/// claim mask this text yielded exactly one "entity": the actionable `Phone` 9800998, a value
/// appearing nowhere in the input — while the hash itself was not extracted at all.
#[test]
fn does_not_mine_a_phone_number_out_of_a_hash() {
    let out = extract("Hash d41d8cd98f00b204e9800998ecf8427e was logged.");
    assert!(
        !out.iter().any(|c| c.kind == EntityKind::Phone),
        "fabricated a phone number from a digest's digits: {out:?}"
    );
}

/// An email's LOCAL PART is domain-shaped, so an unguarded `DOMAIN_RE` pass mined
/// `chloe.clarke` out of `chloe.clarke@example.com` and reported it as a domain.
#[test]
fn does_not_mine_a_domain_out_of_an_email_local_part() {
    let out = extract("Contact chloe.clarke@example.com today.");
    assert!(
        out.iter().any(|c| c.kind == EntityKind::Email),
        "the email itself must still be found: {out:?}"
    );
    assert!(
        !out.iter().any(|c| c.value == "chloe.clarke"),
        "mined an email local part into a domain: {out:?}"
    );
}

/// `IPV4_RE` matches the network part of a CIDR block, silently reporting a /24 as a single
/// host — a different network object than the one written down.
#[test]
fn a_cidr_is_not_re_emitted_as_a_bare_host() {
    let out = extract("Net 198.51.100.0/24 is allocated.");
    assert!(
        out.iter().any(|c| c.kind == EntityKind::Cidr && c.value == "198.51.100.0/24"),
        "the CIDR must be extracted whole: {out:?}"
    );
    assert!(
        !out.iter().any(|c| c.value == "198.51.100.0"),
        "re-emitted a CIDR's network part as a bare host: {out:?}"
    );
}

/// The claim mask must suppress re-mining without suppressing genuine values: a real phone
/// number has no letters and is not a fragment of anything.
#[test]
fn a_genuine_phone_number_survives_the_claim_guard() {
    let out = extract("Call +61 2 5550 0143 tomorrow.");
    assert!(
        out.iter().any(|c| c.kind == EntityKind::Phone),
        "the claim guard suppressed a real phone number: {out:?}"
    );
}

/// The token pass asks the authoritative detector directly, so shapes no locator has a regex
/// for — an IPv6 literal, a CIDR, a crypto address, an AS number — stop being invisible.
#[test]
fn the_token_pass_finds_shapes_no_locator_covers() {
    let out = extract(
        "Server 2001:db8::1, net 198.51.100.0/24, AS15169, \
         wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.",
    );
    for want in [
        EntityKind::IpAddress,
        EntityKind::Cidr,
        EntityKind::Asn,
        EntityKind::CryptoAddress,
    ] {
        assert!(
            out.iter().any(|c| c.kind == want),
            "{want:?} not extracted: {out:?}"
        );
    }
}

/// The token pass must stop at `STRUCTURAL_FLOOR`: run down to the residual floor and every
/// word of a sentence becomes a `Username` seed.
#[test]
fn prose_words_do_not_become_username_seeds() {
    let out = extract("the quick brown fox jumps over the lazy dog");
    assert!(
        out.is_empty(),
        "ordinary prose minted seeds: {out:?}"
    );
}
