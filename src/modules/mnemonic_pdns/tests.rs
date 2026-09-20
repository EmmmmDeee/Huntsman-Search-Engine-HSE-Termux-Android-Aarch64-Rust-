use super::*;
use crate::core::confidence;
use crate::util::timefmt::ymd_utc;

/// Build a passive-DNS record. Timestamps are epoch **millis** (as the live API
/// emits them), matching the real `github.com` / `140.82.114.3` responses this
/// module was validated against.
fn rec(rrtype: &str, query: &str, answer: &str, times: u64, first_ms: i64, last_ms: i64) -> PdnsRecord {
    PdnsRecord {
        query: query.to_string(),
        answer: answer.to_string(),
        rrtype: rrtype.to_string(),
        times,
        first_seen: first_ms,
        last_seen: last_ms,
    }
}

fn of_kind(ents: &[Entity], kind: EntityKind) -> Vec<&Entity> {
    ents.iter().filter(|e| e.kind == kind).collect()
}

// ── trait metadata ──────────────────────────────────────────────────────────

#[test]
fn forward_aaaa_dedups_an_expanded_and_a_compressed_ipv6_spelling() {
    // Regression: `is_ip` only validates; the dedup key must still be the
    // canonical form, or an expanded/mixed-case IPv6 spelling and a
    // compressed one dedup separately despite colliding on the same uid
    // once `Entity::new` constructs them. A real public address (Google
    // Public DNS) is used, not an RFC 3849 documentation one, purely for
    // realism.
    let records = vec![
        rec(
            "aaaa",
            "github.com",
            "2001:4860:4860:0000:0000:0000:0000:8888",
            1,
            0,
            0,
        ),
        rec("aaaa", "github.com", "2001:4860:4860::8888", 1, 0, 0),
    ];
    let ents = build_entities(&records, "github.com", false, "s");
    let ips = of_kind(&ents, EntityKind::IpAddress);
    assert_eq!(
        ips.len(),
        1,
        "an expanded and a compressed spelling of the same IPv6 address must dedup to one entity: {ips:?}"
    );
}

#[test]
fn accepts_domain_ip_url_only() {
    let m = MnemonicPdns;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "github.com")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "140.82.114.3")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://github.com/x")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "torvalds")));
}

#[test]
fn metadata_sane() {
    let m = MnemonicPdns;
    assert_eq!(m.name(), "mnemonic_pdns");
    assert!(!m.description().is_empty());
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert!(matches!(m.category(), ModuleCategory::DnsRecon));
    // Network module: budget must exceed the 3 s default (architecture guard).
    assert!(m.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    assert_eq!(m.attack_techniques(), &["T1596.001"]);
    let produces = m.produces();
    assert!(produces.contains(&EntityKind::Domain));
    assert!(produces.contains(&EntityKind::IpAddress));
}

// ── pure helpers ──────────────────────────────────────────────────────────────

#[test]
fn helper_classifiers() {
    assert!(is_ip("140.82.114.3"));
    assert!(is_ip("2606:4700:10::6814:179a"));
    assert!(!is_ip("github.com"));

    assert!(is_hostname("aspmx.l.google.com"));
    assert!(!is_hostname("140.82.114.3")); // IP is not a hostname
    assert!(!is_hostname("localhost")); // no dot
    assert!(!is_hostname("3.114.82.140.in-addr.arpa")); // reverse-DNS name excluded

    // IPv6 equality is by value, so compressed and expanded forms match.
    assert!(ip_eq(
        "2606:4700:10::6814:179a",
        "2606:4700:10:0:0:0:6814:179a"
    ));
    assert!(!ip_eq("140.82.114.3", "9.9.9.9"));
}

// ── forward (domain target) ───────────────────────────────────────────────────

#[test]
fn forward_maps_ips_and_infra_and_scopes_them() {
    let recs = vec![
        rec("a", "github.com", "140.82.114.3", 21107, 1_565_133_646_785, 1_785_518_060_896),
        rec("aaaa", "github.com", "2606:50c0:8000::153", 10, 1_600_000_000_000, 1_785_000_000_000),
        // MX to an external provider → EXTERNAL scope.
        rec("mx", "github.com", "aspmx.l.google.com", 100, 1_500_000_000_000, 1_785_000_000_000),
        // MX to an in-zone host → SUBDOMAIN scope.
        rec("mx", "github.com", "smtp.github.com", 5, 1_500_000_000_000, 1_785_000_000_000),
        // NS delegation (external).
        rec("ns", "github.com", "dns1.p08.nsone.net", 50, 1_500_000_000_000, 1_785_000_000_000),
        // Duplicate A row → folded.
        rec("a", "github.com", "140.82.114.3", 3, 1, 2),
        // PTR anchored on a reverse-DNS name (query != target) → skipped forward.
        rec("ptr", "3.114.82.140.in-addr.arpa", "github.com", 1, 1, 2),
        // Blank query → skipped.
        rec("a", "", "1.2.3.4", 1, 1, 2),
    ];
    let ents = build_entities(&recs, "github.com", false, "s");

    // Two distinct historical IPs (v4 + v6), duplicate folded.
    let ips = of_kind(&ents, EntityKind::IpAddress);
    let ip_vals: Vec<&str> = ips.iter().map(|e| e.value.as_str()).collect();
    assert!(ip_vals.contains(&"140.82.114.3"), "v4 IP present: {ip_vals:?}");
    assert_eq!(ips.len(), 2, "v4 + v6, duplicate folded: {ip_vals:?}");
    assert!(ips.iter().all(|e| {
        (e.confidence - confidence::HIGH).abs() < 1e-9
            && e.has_tag(SRC)
            && e.has_tag(PASSIVE_DNS)
    }));

    // Three infra domains: aspmx (mx/external), smtp.github.com (mx/subdomain),
    // dns1... (ns/external). PTR + blank rows contributed nothing.
    let domains = of_kind(&ents, EntityKind::Domain);
    assert_eq!(domains.len(), 3, "mx+mx+ns; ptr and blank skipped");

    let external_mx = domains
        .iter()
        .find(|e| e.value == "aspmx.l.google.com")
        .expect("external MX present");
    assert!(external_mx.has_tag("mx") && external_mx.has_tag(tags::EXTERNAL));
    assert!(!external_mx.has_tag(tags::SUBDOMAIN));

    let in_zone_mx = domains
        .iter()
        .find(|e| e.value == "smtp.github.com")
        .expect("in-zone MX present");
    assert!(in_zone_mx.has_tag("mx") && in_zone_mx.has_tag(tags::SUBDOMAIN));

    assert!(domains.iter().any(|e| e.value == "dns1.p08.nsone.net" && e.has_tag("ns")));
}

#[test]
fn forward_evidence_carries_rrtype_dates_and_observations() {
    let recs = vec![rec(
        "a",
        "github.com",
        "140.82.114.3",
        21107,
        1_565_133_646_785,
        1_785_518_060_896,
    )];
    let ents = build_entities(&recs, "github.com", false, "s");
    let ip = &of_kind(&ents, EntityKind::IpAddress)[0].evidence[0];
    assert_eq!(ip.attributes.get("rrtype").map(String::as_str), Some("a"));
    assert_eq!(ip.attributes.get("observations").map(String::as_str), Some("21107"));
    // Dates are the millis→seconds→YYYY-MM-DD reduction (computed, not hard-coded).
    assert_eq!(
        ip.attributes.get("first_seen").cloned(),
        ymd_utc(1_565_133_646_785 / 1000)
    );
    assert_eq!(
        ip.attributes.get("last_seen").cloned(),
        ymd_utc(1_785_518_060_896 / 1000)
    );
}

#[test]
fn forward_inbound_cname_alias_is_emitted() {
    // A hostname that CNAMEs INTO our domain (answer == target) is an inbound
    // alias worth surfacing.
    let recs = vec![rec("cname", "pages.example.org", "github.com", 4, 1, 2)];
    let ents = build_entities(&recs, "github.com", false, "s");
    let domains = of_kind(&ents, EntityKind::Domain);
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].value, "pages.example.org");
    assert!(domains[0].has_tag("cname") && domains[0].has_tag(PASSIVE_DNS));
    // Regression: the evidence text used to state the DNS relationship
    // backwards ("github.com cname → pages.example.org") — the real record
    // is pages.example.org's own CNAME pointing AT github.com, not the
    // reverse.
    assert_eq!(
        domains[0].evidence[0].summary,
        "Passive DNS: pages.example.org cname → github.com"
    );
}

#[test]
fn a_www_cname_to_the_apex_is_not_emitted_as_a_mislabeled_subdomain_or_external() {
    // Regression: "www" CNAMEing to the apex is one of the most common zone
    // configurations there is — an inbound CNAME whose query is "www.<target>"
    // canonicalises to the exact same identity as `target` once `Entity::new`
    // strips the leading "www." label, even though it's a DIFFERENT raw
    // string from "github.com" (so it isn't caught by the `query == target_l`
    // forward-branch check). Before this was fixed, `forward_infra_domain`
    // classified it against the raw target, found it a "proper subdomain" by
    // string shape, and tagged it SUBDOMAIN — which then collapsed onto the
    // scan's own apex/subject uid via `Entity::merge`'s tag-union, mislabeling
    // the subject's own entity.
    let recs = vec![rec("cname", "www.github.com", "github.com", 4, 1, 2)];
    let ents = build_entities(&recs, "github.com", false, "s");
    assert!(
        of_kind(&ents, EntityKind::Domain).is_empty(),
        "a www-CNAME-to-apex must not mint a mislabeled duplicate of the subject: {ents:?}"
    );
}

// ── reverse (IP target) ───────────────────────────────────────────────────────

#[test]
fn reverse_maps_answer_ip_to_query_domains() {
    let recs = vec![
        rec("a", "github.com", "140.82.114.3", 21107, 1_565_133_646_785, 1_785_518_060_896),
        rec("a", "ghe.com", "140.82.114.3", 18, 1_706_889_686_316, 1_776_267_212_753),
        // Answer is a different IP → not a resolver of our target → skipped.
        rec("a", "unrelated.com", "9.9.9.9", 5, 1, 2),
        // Duplicate → folded.
        rec("a", "github.com", "140.82.114.3", 1, 1, 2),
    ];
    let ents = build_entities(&recs, "140.82.114.3", true, "s");

    let mut vals: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
    vals.sort_unstable();
    assert_eq!(vals, vec!["ghe.com", "github.com"], "reverse pivot, dedup, skip 9.9.9.9");
    assert!(ents.iter().all(|e| {
        e.kind == EntityKind::Domain && e.has_tag(SRC) && e.has_tag(PASSIVE_DNS) && e.has_tag("reverse-ip")
    }));
}

#[test]
fn reverse_matches_ipv6_across_textual_forms() {
    // Target given expanded; the observed answer is compressed — same address.
    let recs = vec![rec(
        "aaaa",
        "host.example",
        "2606:4700:10::6814:179a",
        1,
        1_600_000_000_000,
        1_785_000_000_000,
    )];
    let ents = build_entities(&recs, "2606:4700:10:0:0:0:6814:179a", true, "s");
    assert_eq!(ents.len(), 1, "compressed answer matches expanded target IPv6");
    assert_eq!(ents[0].value, "host.example");
}

#[test]
fn empty_response_yields_nothing() {
    assert!(build_entities(&[], "github.com", false, "s").is_empty());
    assert!(build_entities(&[], "140.82.114.3", true, "s").is_empty());
}

#[test]
fn a_full_page_is_bounded_by_the_cap_and_a_short_page_is_not() {
    // REQ-MNEMONIC-002. The module header promises this API returns "a *sample*
    // — the most-relevant RESULT_LIMIT records, not the exhaustive set". That
    // promise was kept per-entity and nowhere the coverage layer could read it.
    assert!(
        page_was_capped(RESULT_LIMIT as usize),
        "a page returned exactly at the cap was bounded by the cap, not by the data"
    );
    assert!(
        page_was_capped(RESULT_LIMIT as usize + 1),
        "more than the cap is still capped"
    );

    // THE OVER-CORRECTION CONTROL. A provider that ran out of records before
    // the cap did gave an exhaustive answer. Marking it incomplete would trade
    // a silent truncation for a permanent false caveat on every small domain —
    // and "fewer silent truncations" and "everything marked incomplete" look
    // identical without this assertion.
    assert!(
        !page_was_capped(RESULT_LIMIT as usize - 1),
        "a short page is exhaustive and must never be reported as truncated"
    );
    assert!(!page_was_capped(0), "an empty answer is not a truncated one");
    assert!(!page_was_capped(1));
}

#[test]
fn a_capped_page_says_the_total_is_unknown_rather_than_inventing_one() {
    // The `count`/`metaData` siblings this envelope ignores have no semantics
    // established anywhere in this repository, so the honest report is that the
    // provider did not say how many exist — not a confidently wrong number.
    let mut r = crate::core::module::ModuleResult::new();
    r.mark_truncated(
        RESULT_LIMIT as usize,
        None,
        &format!("the API's `limit={RESULT_LIMIT}` page, returned full"),
    );
    let reason = r.truncation.expect("a capped page declares itself truncated");
    assert!(
        reason.contains("did not report how many exist"),
        "an unknown total must be stated as unknown: {reason}"
    );
    assert!(
        reason.contains(&RESULT_LIMIT.to_string()),
        "the operator needs the cap that bit: {reason}"
    );
    // Windowed to the numeric claim: " of " alone also matches the sentence's
    // own "evidence of absence".
    assert!(
        !reason.contains(&format!("{RESULT_LIMIT} of ")),
        "no invented 'N of M' when the provider reported no total: {reason}"
    );
}
