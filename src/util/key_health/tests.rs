use super::*;

fn sh(module: &str, failures: u32, err: Option<&str>) -> SourceHealth {
    SourceHealth {
        module: module.to_string(),
        last_success_at: None,
        consecutive_failures: failures,
        last_error: err.map(str::to_string),
        ever_yielded: false,
        consecutive_zero_yield: 0,
    }
}

#[test]
fn classifies_real_provider_auth_rejections() {
    // The exact bodies observed on-device (v1.15.0 doctor run).
    assert!(looks_like_auth_failure(
        "[onyphe] HTTP 400 Bad Request: {\"status\":\"nok\",\"text\":\"Invalid API key format\"}"
    ));
    assert!(looks_like_auth_failure(
        "[netlas] HTTP 400 Bad Request: {\"detail\":\"Request had invalid authorization credentials: API key not found\"}"
    ));
    assert!(looks_like_auth_failure(
        "[hunter_io] HTTP 401 Unauthorized: {\"errors\":[{\"id\":\"authentication_failed\",\"details\":\"No user found for the API key supplied\"}]}"
    ));
    assert!(looks_like_auth_failure(
        "[github_code_search] HTTP 401 Unauthorized: Requires authentication"
    ));
}

#[test]
fn does_not_flag_transport_or_empty_as_auth() {
    // Timeouts, DNS/transport errors, and plain non-auth failures must NOT be
    // mistaken for a bad key — misdiagnosing a network blip as "your key is
    // invalid" would send the operator to replace a perfectly good key.
    assert!(!looks_like_auth_failure("timeout"));
    assert!(!looks_like_auth_failure(
        "[psbdmp] transport error (error sending request for url)"
    ));
    assert!(!looks_like_auth_failure(
        "[au_property] all three property-register endpoints returned a non-success HTTP status"
    ));
    assert!(!looks_like_auth_failure("HTTP 500 Internal Server Error"));
    assert!(!looks_like_auth_failure("HTTP 429 Too Many Requests"));
}

#[test]
fn diagnoses_only_drifted_auth_failing_sources_most_broken_first() {
    let health = vec![
        // Drifted + auth-shaped → reported.
        sh("onyphe", 21, Some("HTTP 400: Invalid API key format")),
        sh("hunter_io", 20, Some("HTTP 401 Unauthorized: authentication_failed")),
        // Drifted but a transport failure → NOT an auth issue.
        sh("crtsh", 3, Some("timeout")),
        // Auth-shaped error but NOT yet drifted (below threshold) → not reported.
        sh("shodan", 1, Some("HTTP 401 Unauthorized")),
        // Healthy → not reported.
        sh("wayback", 0, None),
    ];
    let issues = auth_failing_sources(&health);
    assert_eq!(issues.len(), 2, "only drifted + auth-shaped sources");
    // Most-broken first.
    assert_eq!(issues[0].module, "onyphe");
    assert_eq!(issues[0].consecutive_failures, 21);
    assert_eq!(issues[1].module, "hunter_io");
    // Env-var resolution: exact match for onyphe, prefix skew for hunter_io.
    assert_eq!(issues[0].likely_env_var, Some("HUNTSMAN_ONYPHE_KEY"));
    assert_eq!(
        issues[1].likely_env_var,
        Some("HUNTSMAN_HUNTER_KEY"),
        "module `hunter_io` must resolve to the `hunter` service's env var"
    );
}

#[test]
fn empty_health_yields_no_issues() {
    assert!(auth_failing_sources(&[]).is_empty());
}

/// A capped detail must DISCLOSE that it was capped. Silently clipping an
/// upstream's auth error makes a truncated message indistinguishable from the
/// provider's complete reply, so an operator cannot tell the actionable part
/// may be in the portion they cannot see — an undisclosed limit is a defect
/// even when the full string survives elsewhere.
#[test]
fn detail_capped_discloses_the_truncation_and_never_splits_a_codepoint() {
    let issue = |detail: &str| KeyAuthIssue {
        module: "onyphe".to_string(),
        consecutive_failures: 3,
        detail: detail.to_string(),
        likely_env_var: Some("HUNTSMAN_ONYPHE_KEY"),
    };

    // Under the cap: returned verbatim, with NO disclosure suffix added.
    let short = issue("Invalid API key format");
    assert_eq!(short.detail_capped(200), "Invalid API key format");
    assert!(
        !short.detail_capped(200).contains("more chars"),
        "an untruncated detail must not claim a remainder"
    );

    // Over the cap: clipped AND the remainder disclosed.
    let long = issue(&"x".repeat(250));
    let got = long.detail_capped(200);
    assert!(
        got.contains("…(+50 more chars)"),
        "truncation must be disclosed with the remainder size, got: {got:?}"
    );
    assert!(got.starts_with(&"x".repeat(200)), "prefix must be preserved");

    // Exactly at the cap: no suffix (the remainder is zero).
    let exact = issue(&"y".repeat(200));
    assert_eq!(exact.detail_capped(200), "y".repeat(200));

    // Multi-byte: counts CHARACTERS, never splits a codepoint, and reports the
    // remainder in characters too.
    let multi = issue(&"é".repeat(250));
    let got = multi.detail_capped(200);
    assert!(got.starts_with(&"é".repeat(200)), "must not split a codepoint");
    assert!(got.contains("…(+50 more chars)"), "got: {got:?}");
}
