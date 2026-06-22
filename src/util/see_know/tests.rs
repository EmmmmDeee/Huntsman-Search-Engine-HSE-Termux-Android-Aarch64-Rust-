use serde_json::json;

use super::budget::{
    budget_increment, budget_snapshot, reset_budget, scan_budget_remaining, set_scan_cap_override,
};
use super::client::{
    CLIENT, HARDCODED_KEY_FOR_TESTS, cache_get, cache_key, cache_put, is_auth_error,
    key_fingerprint, parse_response, resolve_key, typed_cache_key,
};
use super::endpoints::{SEARCH_LIMIT, build_search_body, extract_items};
use crate::util::curl_client::AuthScheme;

#[test]
fn client_timeout_budget_exceeds_name_search_server_cap() {
    // Regression: see-know.eu's name/auto `/search` path has a ~55s server
    // cap and returns real data in 50–60s. A curl budget below that (was
    // 12s) guarantees a timeout-exit on every name search — observed live
    // as an opaque "curl failed" with zero entities. The curl ceiling must
    // exceed the cap, and the outer tokio timeout must exceed the curl
    // ceiling so curl's own exit code (28) is what surfaces.
    const SERVER_CAP_SECS: u64 = 55;
    assert!(
        CLIENT.curl_timeout_secs() > SERVER_CAP_SECS,
        "curl --max-time {}s must exceed the ~{SERVER_CAP_SECS}s name-search cap",
        CLIENT.curl_timeout_secs()
    );
    assert!(
        CLIENT.outer_timeout_ms() > CLIENT.curl_timeout_secs() * 1000,
        "outer timeout ({}ms) must exceed curl timeout ({}s) so curl's exit code is observed",
        CLIENT.outer_timeout_ms(),
        CLIENT.curl_timeout_secs()
    );
}

#[test]
fn resolve_key_uses_provided_when_non_empty() {
    assert_eq!(resolve_key(Some("my-key")), "my-key");
}

#[test]
fn key_fingerprint_identifies_origin_without_full_secret() {
    // A SYNTHETIC key in the `seek-…` shape — never a real/embedded value, so
    // the "single source of truth for embedded keys" architecture guard isn't
    // tripped by a literal living outside util::keys.rs.
    let fp = key_fingerprint("seek-1234567890aaaabbbbccccddddeeeeffff0000111122223333");
    // Provider-prefixed, head + tail present, middle elided.
    assert!(fp.starts_with("see-know.eu:seek-12345"), "got {fp}");
    assert!(fp.ends_with("223333"), "got {fp}");
    assert!(fp.contains('\u{2026}'));
    // The full secret never appears verbatim — the elided middle is dropped.
    assert!(!fp.contains("aaaabbbbccccddddeeeeffff"));
    // Short/empty keys degrade gracefully.
    assert_eq!(key_fingerprint(""), "see-know.eu:(no key)");
    assert_eq!(key_fingerprint("short"), "see-know.eu:short");
}

#[test]
fn search_body_includes_limit_and_optional_type() {
    // Auto-detect: no `type`, always the spec's max `limit`.
    assert_eq!(
        build_search_body("john@example.com", "", SEARCH_LIMIT),
        r#"{"query":"john@example.com","limit":500}"#
    );
    // Typed query carries `type` too.
    assert_eq!(
        build_search_body("alice", "username", 50),
        r#"{"query":"alice","type":"username","limit":50}"#
    );
    // The query is JSON-escaped (a quote can't break out of the body).
    assert_eq!(
        build_search_body("a\"b", "", 1),
        r#"{"query":"a\"b","limit":1}"#
    );
    // We request the spec maximum (default would be 100).
    assert_eq!(SEARCH_LIMIT, 500);
}

#[test]
fn seeknow_client_uses_x_api_key_per_spec() {
    // Regression guard for the auth header: see-know.eu requires X-API-Key
    // and rejects Authorization: Bearer ("Missing API key. Use X-API-Key").
    assert_eq!(CLIENT.auth_scheme(), AuthScheme::XApiKey);
}

#[test]
fn resolve_key_falls_back_to_hardcoded_when_none() {
    assert_eq!(resolve_key(None), HARDCODED_KEY_FOR_TESTS);
}

#[test]
fn resolve_key_falls_back_when_empty() {
    assert_eq!(resolve_key(Some("")), HARDCODED_KEY_FOR_TESTS);
}

#[test]
fn auth_error_envelope_is_detected() {
    // The literal body see-know.eu returns for a rejected key (curl exits 0
    // on a 401, so this is what reaches us). Detecting it is what turns
    // "SeekNow found nothing" into the actionable "the key is invalid".
    assert!(is_auth_error(
        r#"{"error":"invalid_api_key","message":"Invalid API key"}"#
    ));
    assert!(is_auth_error(
        r#"{"error":"invalid_api_key","message":"Missing API key. Use X-API-Key"}"#
    ));
    // A recognised key with no paid plan is also terminal — latch + skip.
    // (This is the live see-know.eu response observed for the bundled key.)
    assert!(is_auth_error(
        r#"{"error":"plan_required","message":"API access requires a paid plan. Upgrade at https://see-know.eu/pricing"}"#
    ));
    // A normal (empty or populated) result is NOT an auth error.
    assert!(!is_auth_error(r#"{"data":{"items":[]}}"#));
    assert!(!is_auth_error(r#"{"results":[{"email":"a@b.com"}]}"#));
}

#[test]
fn hardcoded_key_has_correct_prefix() {
    assert!(HARDCODED_KEY_FOR_TESTS.starts_with("seek-"));
    assert!(HARDCODED_KEY_FOR_TESTS.len() >= 50);
}

#[test]
fn extract_items_handles_envelope() {
    let v = json!({"data": {"items": [{"id": 1}, {"id": 2}]}});
    assert_eq!(extract_items(&v).len(), 2);
}

#[test]
fn extract_items_handles_results_array() {
    let v = json!({"results": [{"a": 1}]});
    assert_eq!(extract_items(&v).len(), 1);
}

#[test]
fn extract_items_handles_top_level_array() {
    let v = json!([{"a": 1}, {"b": 2}, {"c": 3}]);
    assert_eq!(extract_items(&v).len(), 3);
}

#[test]
fn extract_items_wraps_single_data_object() {
    let v = json!({"data": {"single": "object"}});
    assert_eq!(extract_items(&v).len(), 1);
}

#[test]
fn extract_items_empty_for_unknown_shape() {
    let v = json!({"unrelated": "value"});
    assert!(extract_items(&v).is_empty());
}

#[test]
fn extract_items_flattens_stealer_victims_into_credentials() {
    // The exact stealer-log shape from the "Ali Kareem" dump: `results` is the
    // scalar 0 (so the array branch falls through) while `victims` carries the
    // leaked logins one level down. Each credential must become a standalone
    // item that inherits the victim's scalar context (log_id), so the extractor
    // sees every password instead of dropping the whole set.
    let v = json!({
        "success": true,
        "results": 0,
        "victims": [{
            "log_id": "ea0621568ccd7fee",
            "ip": "37.236.187.22",
            "credentials": [
                {"username": "ali", "password": "C0R4Pc1", "pwned_at": "2026-05-20T21:00:00Z"},
                {"username": "ali", "password": "Yontem2006", "pwned_at": "2026-05-20T21:00:00Z"}
            ]
        }]
    });
    let items = extract_items(&v);
    assert_eq!(items.len(), 2, "one item per leaked credential");
    // Each flattened item carries both the credential and the victim's scalar
    // context (log_id + host ip), so provenance and the login survive together.
    assert_eq!(items[0]["username"], json!("ali"));
    assert_eq!(items[0]["password"], json!("C0R4Pc1"));
    assert_eq!(items[0]["log_id"], json!("ea0621568ccd7fee"));
    assert_eq!(items[0]["ip"], json!("37.236.187.22"));
    assert_eq!(items[1]["password"], json!("Yontem2006"));
}

#[test]
fn extract_items_victim_without_credentials_still_yields_host_intel() {
    // A victim with host-level data but no credential array must not vanish.
    let v = json!({ "victims": [{ "log_id": "abc", "ip": "8.8.8.8" }] });
    let items = extract_items(&v);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["ip"], json!("8.8.8.8"));
}

#[test]
fn escape_json_handles_quotes_and_backslashes() {
    use super::endpoints::escape_json;
    assert_eq!(escape_json(r#"hello"world"#), r#"hello\"world"#);
    assert_eq!(escape_json(r"path\to\file"), r"path\\to\\file");
}

#[test]
fn typed_cache_key_disambiguates_query_type_from_auto_detect() {
    let auto = typed_cache_key("search", "alice", "");
    let typed = typed_cache_key("search", "alice", "email");
    assert_ne!(
        auto, typed,
        "auto-detect and typed search must NOT share a cache key"
    );
    // Without a type, falls back to the legacy key shape.
    assert_eq!(auto, cache_key("search", "alice"));
    // Typed form includes the type marker.
    assert!(typed.contains("#email"));
}

#[test]
fn empty_results_are_never_cached_but_non_empty_are() {
    // Regression for the transient-empty poisoning bug: cache_put() must
    // refuse an empty result so a transient `total:0` cannot poison later
    // lookups of the same query, while a real hit is memoised.
    let empty_key = typed_cache_key("search", "transient-empty-probe", "name");
    cache_put(empty_key.clone(), Vec::new());
    assert!(
        cache_get(&empty_key).is_none(),
        "an empty result must not be served from cache (would poison retries)"
    );

    let hit_key = typed_cache_key("search", "real-hit-probe", "name");
    cache_put(
        hit_key.clone(),
        vec![serde_json::json!({"email": "x@y.com"})],
    );
    assert_eq!(
        cache_get(&hit_key).map(|v| v.len()),
        Some(1),
        "a non-empty result must be cached and retrievable"
    );
}

// Serialises the tests that touch the shared `BUDGET` global (scan-cap
// override + budget counters). `cargo test` runs tests in parallel, so
// without this they interleave `reset_budget()` / `set_scan_cap_override()`
// and clobber each other — a real CI flake: a concurrent `reset_budget`
// cleared an override mid-test, so `scan_cap` read the default (160)
// instead of the value just set (80). parking_lot::Mutex never poisons if
// a test panics while holding it.
static BUDGET_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[test]
fn scan_budget_remaining_decreases_with_increments() {
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let start = scan_budget_remaining();
    budget_increment();
    let after = scan_budget_remaining();
    assert_eq!(
        start,
        after + 1,
        "increment must consume exactly one credit"
    );
    reset_budget();
}

#[test]
fn budget_snapshot_reports_active_caps() {
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let snap = budget_snapshot();
    assert_eq!(snap.scan_used, 0);
    assert!(snap.scan_cap >= 1);
    assert!(!snap.quota_exhausted);
    budget_increment();
    let snap2 = budget_snapshot();
    assert_eq!(snap2.scan_used, 1);
    reset_budget();
}

#[test]
fn default_scan_cap_is_higher_than_legacy_eight() {
    // Regression guard for the operator's "use see-know.eu extensively"
    // directive. The legacy cap was 8 lookups (99.84% of quota unused);
    // it was raised to 120 and then to 160 so the full endpoint matrix
    // fires across ~10 recursively-discovered pivots per round. Lock the
    // floor at 120 so coverage can't silently regress below "extensive"
    // (the per-round cap; the per-session ceiling is separate, now 500).
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let cap = budget_snapshot().scan_cap;
    assert!(
        (120..=200).contains(&cap),
        "scan cap {cap} outside the extensive-use band [120, 200]"
    );
}

#[test]
fn set_scan_cap_override_replaces_default_until_reset() {
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let base = budget_snapshot().scan_cap;
    set_scan_cap_override(80);
    assert_eq!(budget_snapshot().scan_cap, 80);
    reset_budget();
    // After reset, falls back to env / static default again.
    assert_eq!(budget_snapshot().scan_cap, base);
}

#[test]
fn scan_cap_override_zero_falls_back_to_default() {
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let base = budget_snapshot().scan_cap;
    set_scan_cap_override(0);
    assert_eq!(
        budget_snapshot().scan_cap,
        base,
        "override of 0 must mean 'use default', not 'cap at zero'"
    );
    reset_budget();
}

#[test]
fn snapshot_reflects_override_cap() {
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    set_scan_cap_override(99);
    let snap = budget_snapshot();
    assert_eq!(snap.scan_cap, 99);
    reset_budget();
}

#[test]
fn reset_clears_override_too() {
    let _guard = BUDGET_TEST_LOCK.lock();
    // Regression guard: reset_scan must clear the cap override so
    // the next scan picks up the env / default cap unless the
    // engine installs a fresh override at scan start.
    reset_budget();
    set_scan_cap_override(99);
    assert_eq!(budget_snapshot().scan_cap, 99);
    reset_budget();
    assert_ne!(
        budget_snapshot().scan_cap,
        99,
        "reset_budget must clear the cap override"
    );
}

#[test]
fn parse_response_treats_non_json_body_as_no_results() {
    // A normal "no results" / error-page / empty 200 response is NOT a failure:
    // it must degrade to the Null sentinel (read as empty by extract_items), so it
    // never errors the module or trips the circuit breaker. Regression for the
    // serde "expected value at line 1 column 1" error seen on live empty responses.
    for body in [
        "",
        "   ",
        "\n\n",
        "<html><body>error</body></html>",
        "Gateway Timeout",
    ] {
        let v = parse_response(body).expect("non-JSON body must be Ok(Null), not an error");
        assert!(
            v.is_null(),
            "non-JSON body {body:?} should parse to Null (no results)"
        );
        assert!(extract_items(&v).is_empty(), "Null yields no items");
    }
}

#[test]
fn parse_response_parses_valid_json_and_surfaces_malformed_json() {
    // A real JSON object parses through unchanged.
    let v = parse_response(r#"{"total":1,"results":[{"email":"a@x.com"}]}"#).expect("valid JSON");
    assert_eq!(v["total"], 1);
    // A body that LOOKS like JSON ({…) but is truncated/malformed is genuine drift
    // and must still surface as an error — not be silently swallowed.
    assert!(
        parse_response(r#"{"total":1,"results":["#).is_err(),
        "malformed JSON-shaped body must still error (schema-drift signal)"
    );
}
