use super::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// Build a `HeaderMap` from `(name, value)` pairs. A repeated name (`set-cookie`,
/// `via`) is appended, mirroring a real multi-valued response.
fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        let name = HeaderName::from_bytes(k.as_bytes()).unwrap();
        h.append(name, HeaderValue::from_str(v).unwrap());
    }
    h
}

fn providers(h: &HeaderMap) -> Vec<&'static str> {
    detect(h).into_iter().map(|d| d.provider).collect()
}

#[test]
fn detects_cloudflare_by_header_and_server_case_insensitively() {
    assert!(providers(&headers(&[("cf-ray", "a04fb07eeea5d717-BNE")])).contains(&"Cloudflare"));
    assert!(providers(&headers(&[("server", "cloudflare")])).contains(&"Cloudflare"));
    // Header-value matching is case-insensitive.
    assert!(providers(&headers(&[("server", "CLOUDFLARE")])).contains(&"Cloudflare"));
}

#[test]
fn detects_cookie_based_wafs_from_set_cookie_values() {
    // Imperva/Incapsula — the fingerprint is a cookie NAME in the Set-Cookie
    // VALUE, not a header key (the way this is usually gotten wrong).
    let h = headers(&[("set-cookie", "incap_ses_123_456=Zm9v; path=/; HttpOnly")]);
    assert!(providers(&h).contains(&"Imperva/Incapsula"));
    // F5 BIG-IP persistence cookie.
    let h = headers(&[("set-cookie", "BIGipServerpool_www=1234.5678.0000; path=/")]);
    assert!(providers(&h).contains(&"F5 BIG-IP"));
    // AWS Application Load Balancer stickiness cookie.
    let h = headers(&[("set-cookie", "AWSALB=abcdef; Expires=Mon, 01 Jan 2035 00:00:00 GMT")]);
    assert!(providers(&h).contains(&"AWS ELB/ALB"));
}

#[test]
fn detects_layered_stack_ranked_high_confidence_first() {
    // Cloudflare (High) in front, Fastly (Medium) behind — both reported.
    let h = headers(&[
        ("server", "cloudflare"),
        ("x-served-by", "cache-iad-kcgs7200123-IAD"),
    ]);
    let dets = detect(&h);
    let names: Vec<_> = dets.iter().map(|d| d.provider).collect();
    assert!(names.contains(&"Cloudflare"));
    assert!(names.contains(&"Fastly"));
    // Confidence-first ordering: the High match precedes the Medium one.
    let cf = dets.iter().position(|d| d.provider == "Cloudflare").unwrap();
    let fa = dets.iter().position(|d| d.provider == "Fastly").unwrap();
    assert!(cf < fa, "High-confidence Cloudflare must rank before Medium Fastly");
}

#[test]
fn dedups_a_provider_to_its_strongest_evidence() {
    // Cloudflare matches cf-ray (High) AND cf-cache-status (Medium): one
    // detection, kept at High.
    let h = headers(&[("cf-ray", "x"), ("cf-cache-status", "HIT")]);
    let cf: Vec<_> = detect(&h)
        .into_iter()
        .filter(|d| d.provider == "Cloudflare")
        .collect();
    assert_eq!(cf.len(), 1, "a provider collapses to a single detection");
    assert_eq!(cf[0].confidence, Confidence::High);
    assert_eq!(cf[0].evidence, "CF-Ray header");
}

#[test]
fn no_false_positive_on_a_plain_origin() {
    assert!(detect(&HeaderMap::new()).is_empty());
    let h = headers(&[("server", "nginx/1.22.1"), ("content-type", "text/html")]);
    assert!(detect(&h).is_empty());
}

#[test]
fn cookie_names_parses_every_set_cookie() {
    let h = headers(&[
        ("set-cookie", "incap_ses_1=a; path=/"),
        ("set-cookie", "visid_incap_2=b; Secure"),
    ]);
    let names = cookie_names(&h);
    assert!(names.contains(&"incap_ses_1"));
    assert!(names.contains(&"visid_incap_2"));
}

#[test]
fn ci_helpers_are_case_insensitive_and_total() {
    assert!(ci_contains("AkamaiGHost", "akamaighost"));
    assert!(ci_contains("X-CDN: Incapsula", "incapsula"));
    assert!(!ci_contains("nginx", "cloudflare"));
    assert!(!ci_contains("a", "")); // empty needle never matches
    assert!(ci_starts_with("BIGipServerpool", "bigipserver"));
    assert!(ci_starts_with("incap_ses_99", "incap_ses_"));
    assert!(!ci_starts_with("AWSALB", "AWSALBCORS")); // prefix longer than the string
}

#[test]
fn signature_table_is_broad_and_well_formed() {
    assert!(
        SIGNATURES.len() >= 40,
        "expected a broad table, got {}",
        SIGNATURES.len()
    );
    let distinct: std::collections::HashSet<_> = SIGNATURES.iter().map(|s| s.provider).collect();
    assert!(
        distinct.len() >= 25,
        "expected >=25 providers, got {}",
        distinct.len()
    );
}

#[tokio::test]
async fn module_metadata() {
    let m = WafDetect;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn module_metadata_shape() {
    let m = WafDetect;
    assert_eq!(m.name(), "waf_detect");
    assert!(!m.description().is_empty());
    assert_eq!(m.max_timeout_ms(), 6_000);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.produces().contains(&EntityKind::Domain));
}
