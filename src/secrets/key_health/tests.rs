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
