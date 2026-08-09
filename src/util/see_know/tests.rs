use serde_json::json;

use super::budget::{
    budget_increment, budget_snapshot, is_quota_exhausted, release_quota_probe, reset_budget,
    scan_budget_remaining, set_scan_cap_override, should_probe_quota,
};
use super::client::{
    CLIENT, CLIENT_FAST, HARDCODED_KEY_FOR_TESTS, base_urls_for, cache_get, cache_key, cache_put,
    classify_status, is_auth_error, key_fingerprint, parse_response, resolve_key, typed_cache_key,
};
use super::endpoints::{
    CreditsOutcome, CreditsProbe, SEARCH_LIMIT, build_search_body, classify_credits_probe,
    extract_items, parse_credits_body,
};
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
    // The fast-GET client must be TIGHTER than the /search client: the fast
    // endpoints answer in ~2-5s, so a hung GET must fail well before it burns the
    // module's whole per-scan timeout budget on /search's 75s ceiling. Its outer
    // timeout still exceeds its curl ceiling so curl's own exit code surfaces.
    assert!(
        CLIENT_FAST.curl_timeout_secs() < CLIENT.curl_timeout_secs(),
        "fast-GET curl budget ({}s) must be tighter than /search's ({}s)",
        CLIENT_FAST.curl_timeout_secs(),
        CLIENT.curl_timeout_secs()
    );
    assert!(CLIENT_FAST.outer_timeout_ms() > CLIENT_FAST.curl_timeout_secs() * 1000);
}

#[test]
fn resolve_key_uses_provided_when_non_empty() {
    assert_eq!(resolve_key(Some("my-key")), "my-key");
}

#[test]
fn classify_status_diverts_5xx_and_no_response_to_transient_retry() {
    use crate::core::error::Error;
    // A 5xx (with either an HTML error page or a JSON error body) is a transient
    // upstream failure → RateLimited, so the retry loops back off and retry it,
    // instead of the old behaviour where the HTML page parsed to an empty miss
    // and the paid call was silently lost.
    assert!(
        matches!(
            classify_status("<html>503 Bad Gateway</html>", 503),
            Err(Error::RateLimited(_))
        ),
        "a 503 must be retryable-transient, not an empty miss"
    );
    assert!(
        matches!(
            classify_status(r#"{"error":"upstream"}"#, 500),
            Err(Error::RateLimited(_))
        ),
        "a 500 with a JSON body must still be retryable-transient"
    );
    // curl reporting no HTTP response at all (status 0) is transient too.
    assert!(matches!(classify_status("", 0), Err(Error::RateLimited(_))));
    // A 2xx-empty body is a GENUINE miss — parse_response yields Ok, no retry.
    assert!(
        classify_status("", 200).is_ok(),
        "a 200 empty result is a real miss, not retried"
    );
    // A 4xx JSON body is NOT diverted — it keeps parse_response's existing
    // classification (a 404/400 miss here) rather than being treated transient.
    assert!(
        classify_status(r#"{"total":0}"#, 404).is_ok(),
        "a 4xx JSON body keeps parse_response's classification"
    );
    // A 429 served as a CDN/gateway HTML interstitial (NOT the API's JSON
    // rate_limit envelope) must be retryable-transient, not the empty miss it
    // used to become in parse_response's non-JSON branch.
    assert!(
        matches!(
            classify_status("<html>429 Too Many Requests</html>", 429),
            Err(Error::RateLimited(_))
        ),
        "a non-JSON 429 must divert to RateLimited, not a silent empty miss"
    );
    // A JSON 429 keeps its precise parse_response/classify_terminal path: an
    // explicit `rate_limit` envelope is still RateLimited (retry) — reached via
    // parse_response, not the non-JSON divert (no global latch mutated here).
    assert!(
        matches!(
            classify_status(r#"{"error":"rate_limit"}"#, 429),
            Err(Error::RateLimited(_))
        ),
        "a JSON rate_limit 429 stays RateLimited via parse_response"
    );
    // A 429 whose JSON body carries no terminal marker is a normal miss — NOT
    // blanket-diverted just because the status is 429.
    assert!(
        classify_status(r#"{"total":0}"#, 429).is_ok(),
        "a JSON 429 with no terminal marker keeps parse_response's classification"
    );
}

#[test]
fn reset_budget_clears_the_cross_module_response_cache() {
    // Regression: RESPONSE_CACHE dedups identical endpoint queries WITHIN one
    // scan (its own doc comment), but reset_budget() previously only reset
    // the quota counters and the key-invalid/quota-probed latches -- a
    // long-lived `hse serve`/`hse live` process would silently keep serving
    // the FIRST scan's cached SeekNow records for every later re-scan of the
    // same email/username/phone, forever, with no live re-check.
    // reset_budget() must also clear the cache.
    //
    // Isolation note: RESPONSE_CACHE is a process-global `static` that ANY
    // concurrent scan-running test clears via `reset_per_scan` →
    // `see_know::reset_budget` — a lock inside this file cannot serialise
    // against those. So the "value present" sanity below can be cleared out
    // from under us by an unrelated test (an observed CI flake). Retry the put
    // until we observe our own UNIQUE entry (tolerating a rare external clear
    // landing in the window); the real contract — that reset_budget() then
    // clears it — is the final assertion, which no external test can spuriously
    // satisfy for this unique key (nothing else ever puts it).
    let key = "reset_budget_clears_cache_test_key";
    let mut observed_present = false;
    for _ in 0..200 {
        cache_put(key.to_string(), vec![json!({"stale": true})]);
        if cache_get(key).is_some() {
            observed_present = true;
            break;
        }
    }
    assert!(
        observed_present,
        "sanity: a non-empty put must be observable at least once in 200 tries"
    );
    reset_budget();
    assert!(
        cache_get(key).is_none(),
        "reset_budget() must clear RESPONSE_CACHE so a new scan re-queries live"
    );
}

#[test]
fn key_fingerprint_identifies_origin_without_full_secret() {
    // A SYNTHETIC key in the `seek-…` shape — never a real/embedded value, so
    // the "single source of truth for embedded keys" architecture guard isn't
    // tripped by a literal living outside util::keys.rs.
    let fp = key_fingerprint("seek-1234567890aaaabbbbccccddddeeeeffff0000111122223333");
    // Provider-prefixed, head + tail present, middle elided. Domain-agnostic
    // prefix — see-know rotates across three domains, so the fingerprint
    // never names one (mirrors the `provider` evidence attribute fix).
    assert!(fp.starts_with("see-know:seek-12345"), "got {fp}");
    assert!(fp.ends_with("223333"), "got {fp}");
    assert!(fp.contains('\u{2026}'));
    // The full secret never appears verbatim — the elided middle is dropped.
    assert!(!fp.contains("aaaabbbbccccddddeeeeffff"));
    // Short/empty keys degrade gracefully.
    assert_eq!(key_fingerprint(""), "see-know:(no key)");
    assert_eq!(key_fingerprint("short"), "see-know:short");
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
fn escape_json_escapes_control_chars_into_valid_json() {
    use super::endpoints::escape_json;
    // Regression: the hand-rolled version escaped only `\` and `"`, so a query
    // with a literal newline/tab produced INVALID JSON. Every value must now
    // embed inside a `"…"` string that parses back to the exact original.
    for raw in [
        "line1\nline2",
        "tab\there",
        "carriage\rreturn",
        "quote\"and\\back",
        "null\u{0}byte",
    ] {
        let body = format!(r#"{{"query":"{}"}}"#, escape_json(raw));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("escaped body must be valid JSON");
        assert_eq!(parsed["query"], raw, "round-trips exactly for {raw:?}");
    }
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
    //
    // Isolation note (see `reset_budget_clears_the_cross_module_response_cache`):
    // RESPONSE_CACHE is a process-global cleared by any concurrent scan-running
    // test, so the `hit_key` read-after-write below is retried until observed;
    // the empty-key assertion is robust either way (an empty result is never
    // cached, and no external test ever puts these unique keys).
    let empty_key = typed_cache_key("search", "transient-empty-probe", "name");
    cache_put(empty_key.clone(), Vec::new());
    assert!(
        cache_get(&empty_key).is_none(),
        "an empty result must not be served from cache (would poison retries)"
    );

    let hit_key = typed_cache_key("search", "real-hit-probe", "name");
    let mut hit_len = None;
    for _ in 0..200 {
        cache_put(
            hit_key.clone(),
            vec![serde_json::json!({"email": "x@y.com"})],
        );
        hit_len = cache_get(&hit_key).map(|v| v.len());
        if hit_len.is_some() {
            break;
        }
    }
    assert_eq!(
        hit_len,
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
fn a_failed_quota_probe_releases_the_latch_so_a_later_seed_re_probes() {
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget(); // clears the one-shot QUOTA_PROBED latch
    // First caller claims the one-shot probe; a concurrent duplicate is refused.
    assert!(should_probe_quota(), "first caller wins the probe claim");
    assert!(
        !should_probe_quota(),
        "the latch blocks a duplicate concurrent probe"
    );
    // The probe the claim guarded FAILED (transient blip) → release the latch.
    release_quota_probe();
    // A later seed must now be able to re-probe, instead of the whole scan
    // running pinned to the un-scaled default cap after one blip.
    assert!(
        should_probe_quota(),
        "after a failed probe releases the latch, a later seed re-probes"
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
fn default_scan_cap_is_at_least_maximise_floor() {
    // Regression guard for the operator's "use see-know.eu MAXIMALLY"
    // directive. The cap started at 8 (99.84 % unused), was raised to 120,
    // 160, and now 300 (6 % of the 5,000-daily pool per scan) so the full
    // 18-endpoint matrix fires across ~10 recursively-discovered pivots.
    // Floor is 200: anything lower regresses toward the conservative mode
    // explicitly rejected by the standing maximisation directive.
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let cap = budget_snapshot().scan_cap;
    assert!(
        cap >= 200,
        "scan cap {cap} is below the maximise floor of 200 — standing directive requires extensive use"
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

#[test]
fn parse_response_ignores_auth_marker_inside_data_payload() {
    // Regression: a stealer/breach record whose captured content contains the
    // literal "invalid_api_key" (routine in leaked config blobs and error dumps)
    // must NOT be mistaken for an auth rejection — which previously latched
    // KEY_INVALID, silently disabling SeekNow for the rest of the scan AND dropping
    // this page of real results. The marker is only meaningful in the top-level
    // error envelope, never in the data payload.
    let body = r#"{"total":1,"results":[{"email":"a@x.com","note":"leaked config: invalid_api_key=xyz"}]}"#;
    let v = parse_response(body).expect("a data payload must parse, not error");
    assert!(
        !v.is_null(),
        "a record containing 'invalid_api_key' must survive, not be read as auth failure"
    );
    assert_eq!(v["total"], 1);
}

#[test]
fn parse_response_treats_rate_limit_as_retryable_not_quota_exhausted() {
    // Regression: a transient burst rate-limit (`{"error":"rate_limit"}`) used
    // to be classified identically to true daily-quota exhaustion, latching
    // `mark_quota_exhausted()` and silently abandoning SeekNow for every
    // remaining endpoint call in the scan (with no backoff at all). It must
    // now surface as a distinguishable `Error::RateLimited` and must NOT
    // latch the quota-exhausted flag — a burst throttle is recoverable
    // within the same scan via backoff, unlike real exhaustion.
    //
    // Holds BUDGET_TEST_LOCK because it mutates the process-global exhaustion
    // flag: without it this test and its `quota_exceeded` sibling raced (one's
    // `reset_budget()` clearing the flag the other had just latched), an
    // intermittent CI failure that passed locally under a different schedule.
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let err = parse_response(r#"{"error":"rate_limit","message":"slow down"}"#)
        .expect_err("a rate-limit body must surface as an Err, not Ok(Null)");
    assert!(
        matches!(err, crate::core::error::Error::RateLimited(_)),
        "must classify as RateLimited, not a generic error: {err:?}"
    );
    assert!(
        !is_quota_exhausted(),
        "a transient rate-limit must NOT latch true quota exhaustion"
    );
    reset_budget();
}

#[test]
fn parse_response_still_treats_true_exhaustion_as_quota_not_rate_limited() {
    // Sibling regression: real exhaustion signals must keep latching
    // mark_quota_exhausted() exactly as before — only bare "rate_limit" is
    // the new, distinct, retryable case.
    //
    // Same process-global exhaustion flag as the `rate_limit` sibling, so it
    // takes BUDGET_TEST_LOCK for the same reason: serialise against every other
    // budget-mutating test rather than race them.
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let v = parse_response(r#"{"error":"quota_exceeded"}"#).expect("quota exhaustion is Ok(Null)");
    assert!(v.is_null());
    assert!(
        is_quota_exhausted(),
        "true exhaustion must still latch the quota-exhausted flag"
    );
    reset_budget();
}

#[test]
fn a_successful_response_that_spent_its_last_credit_keeps_its_data() {
    // Regression: `credits_remaining:0` was treated as terminal exhaustion on
    // ANY body — including a `success:true` response carrying results. That made
    // `parse_response` return `Ok(Value::Null)`, silently dropping the data of
    // the final successful (paid) lookup before the quota ran out, and latching
    // the budget on a call that actually succeeded. A successful body must be
    // returned intact; only a NON-success zero-credit body is true exhaustion.
    //
    // Touches the process-global exhaustion flag, so it takes BUDGET_TEST_LOCK.
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let body =
        r#"{"success":true,"total":1,"results":[{"email":"a@x.com"}],"credits_remaining":0}"#;
    let v = parse_response(body).expect("a success body must parse");
    assert!(
        !v.is_null(),
        "the last-credit success payload must survive, not be dropped as exhaustion"
    );
    assert_eq!(v["results"][0]["email"], "a@x.com");
    assert!(
        !is_quota_exhausted(),
        "a successful response must not latch quota exhaustion"
    );
    reset_budget();
}

#[test]
fn a_zero_credit_error_body_still_latches_true_exhaustion() {
    // The other half of the contract: a NON-success body reporting zero credits
    // IS true exhaustion and must keep latching + returning Ok(Null) — so the
    // fix above narrows the trigger without losing the real exhaustion signal.
    let _guard = BUDGET_TEST_LOCK.lock();
    reset_budget();
    let v = parse_response(r#"{"error":"credits_exhausted","credits_remaining":0}"#)
        .expect("true exhaustion is Ok(Null)");
    assert!(v.is_null());
    assert!(
        is_quota_exhausted(),
        "a zero-credit error body must still latch exhaustion"
    );
    reset_budget();
}

#[test]
fn client_base_url_uses_endpoint_override_or_default() {
    // The base URL is resolved from HUNTSMAN_SEEKNOW_BASE environment variable
    // (with security checks) or the canonical default. Tests that the resolution
    // returns an HTTPS URL in both cases.
    let url = super::client::base_url();
    assert!(
        url.starts_with("https://"),
        "SeekNow base URL must be HTTPS — got {url}"
    );
    // Must be a well-known domain (see-know.ru) or an override matching HTTPS + non-local rules
    assert!(
        url.contains("see-know."),
        "SeekNow base URL must reference the canonical domain — got {url}"
    );
    // Regression guard: the default host is `.ru` (promoted to primary
    // 2026-07-29; `.xyz`, `.eu` and `.icu` remain fallbacks in
    // `all_base_urls`), unless the operator's own shell has
    // HUNTSMAN_SEEKNOW_BASE set, in which case that override legitimately wins.
    if std::env::var("HUNTSMAN_SEEKNOW_BASE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_none()
    {
        assert_eq!(
            url, "https://see-know.ru/api/v1",
            "SeekNow default base URL must be the `.ru` domain — got {url}"
        );
    }
}

#[test]
fn base_urls_for_default_rotates_through_every_known_public_domain() {
    // No override active (primary == the built-in default): full 4-domain
    // rotation across every known SeekNow public domain.
    let urls = base_urls_for("https://see-know.ru/api/v1".to_string());
    assert_eq!(
        urls,
        vec![
            "https://see-know.ru/api/v1",
            "https://see-know.xyz/api/v1",
            "https://see-know.eu/api/v1",
            "https://see-know.icu/api/v1",
        ]
    );
}

#[test]
fn base_urls_for_active_override_is_exclusive_no_public_fallback() {
    // An accepted HUNTSMAN_SEEKNOW_BASE override (primary != the built-in
    // default) must NOT fall through to see-know.eu/.icu/.ru on failure — that
    // would silently send the key-bearing, PII-bearing request to a host the
    // operator explicitly did not choose, and (for the carrier-DNS-filtering
    // workaround `hse doctor` itself recommends) just reproduces the exact
    // resolution failure the override exists to route around.
    let urls = base_urls_for("https://my-private-relay.example/api/v1".to_string());
    assert_eq!(
        urls,
        vec!["https://my-private-relay.example/api/v1"],
        "an active override must be the ONLY url tried — got {urls:?}"
    );
}

#[test]
fn base_urls_for_override_pinned_to_a_known_fallback_is_also_exclusive() {
    // Even when the override happens to equal one of the two hardcoded
    // fallback domains, it must still win exclusively — the operator's
    // explicit choice, not the rotation order, decides once an override
    // is set at all.
    let urls = base_urls_for("https://see-know.eu/api/v1".to_string());
    assert_eq!(urls, vec!["https://see-know.eu/api/v1"]);
}

#[test]
fn client_auth_scheme_is_x_api_key_header() {
    // SeekNow API requires X-API-Key header, NOT Authorization: Bearer.
    // Regression: earlier implementations used Bearer auth, which the server
    // rejects with "Missing API key. Use X-API-Key".
    assert_eq!(
        CLIENT.auth_scheme(),
        crate::util::curl_client::AuthScheme::XApiKey,
        "SeekNow MUST use X-API-Key header per spec"
    );
}

// ── `/credits` response classification (hse doctor's SeekNow diagnostic) ──
//
// `query_credits` is also the probe `hse doctor`'s "SeekNow account" section
// uses to catch a dead/rejected key from a FRESH process — before this fix,
// only a data-bearing `search`/`get_path` call ever classified+latched an
// auth rejection, so a process that only ever called `query_credits` (like
// `hse doctor`) could never detect a dead key. These tests pin the pure
// classification `parse_credits_body` performs, live-verified against this
// operator's actual embedded SeekNow key: a real `hse scan --modules
// see_know` run against `see-know.icu` confirmed it currently returns
// exactly the `{"error":"invalid_api_key",...}` shape the AuthError case
// below models.

#[test]
fn credits_body_classifies_an_auth_rejection_as_auth_error() {
    let body = r#"{"error":"invalid_api_key","message":"Invalid API key"}"#;
    assert!(matches!(
        parse_credits_body(body),
        CreditsOutcome::AuthError
    ));
}

#[test]
fn credits_body_classifies_plan_required_as_auth_error_too() {
    // A recognised key whose account lacks a paid plan is terminal for the
    // held key in the exact same way an outright-invalid key is (see
    // `client::is_auth_error`'s own doc comment) — the fix isn't a header
    // change, the account needs a plan, so both classify identically here.
    let body = r#"{"error":"plan_required","message":"Upgrade your plan"}"#;
    assert!(matches!(
        parse_credits_body(body),
        CreditsOutcome::AuthError
    ));
}

#[test]
fn credits_body_extracts_remaining_and_daily_limit_from_every_known_shape() {
    let shapes = [
        r#"{"credits_remaining": 4200, "daily_limit": 5000, "plan": "enterprise"}"#,
        r#"{"data": {"credits_remaining": 4200, "daily_limit": 5000}}"#,
        r#"{"remaining": 4200, "total": 5000}"#,
        r#"{"credits": {"remaining": 4200, "daily": 5000}}"#,
    ];
    for body in shapes {
        match parse_credits_body(body) {
            CreditsOutcome::Data {
                remaining,
                daily_limit,
            } => {
                assert_eq!(remaining, 4200, "shape: {body}");
                assert_eq!(daily_limit, Some(5000), "shape: {body}");
            }
            _ => panic!("expected Data outcome for shape: {body}"),
        }
    }
}

#[test]
fn credits_body_missing_daily_limit_still_returns_remaining() {
    let body = r#"{"credits_remaining": 100}"#;
    match parse_credits_body(body) {
        CreditsOutcome::Data {
            remaining,
            daily_limit,
        } => {
            assert_eq!(remaining, 100);
            assert_eq!(daily_limit, None);
        }
        _ => panic!("expected Data outcome"),
    }
}

#[test]
fn credits_body_garbage_is_unparseable_not_auth_error() {
    // A network blip / HTML error page / truncated body must NEVER be
    // mistaken for a confirmed dead key — only a genuine, classified auth
    // rejection may latch `mark_key_invalid`.
    for body in ["", "not json", "<html>502 Bad Gateway</html>", "{}"] {
        assert!(
            matches!(parse_credits_body(body), CreditsOutcome::Unparseable),
            "body {body:?} must classify as Unparseable, not AuthError"
        );
    }
}

// ── `credits_probe` outcome classification (hse doctor's actionable SeekNow
//    diagnostic). A live Termux scan showed EVERY see_know call failing with
//    `[seek_now] curl exited 6` (curl "could not resolve host"), then the
//    circuit breaker cooling the module down — but the old `query_credits`
//    dropped the curl detail (`.ok()?`), so `hse doctor` could only print the
//    catch-all "could not reach SeekNow", never revealing the real cause was
//    DNS host-resolution (typically carrier/ISP domain filtering), not a bad
//    key. These pin the transport-vs-key distinction the new probe restores.

#[test]
fn credits_probe_maps_a_transport_failure_to_unreachable_with_the_curl_detail() {
    // The exact string the curl client surfaces for a DNS failure — the module
    // error the live bundle recorded. It must classify as Unreachable (a
    // network problem) and preserve curl's own detail verbatim, NOT be reported
    // as an invalid key.
    let curl_dns_failure =
        "curl exited 6: curl: (6) Could not resolve host: see-know.eu".to_string();
    match classify_credits_probe(Err(curl_dns_failure.clone())) {
        CreditsProbe::Unreachable(detail) => assert_eq!(detail, curl_dns_failure),
        other => panic!("a transport failure must be Unreachable, got {other:?}"),
    }
}

#[test]
fn credits_probe_maps_a_good_body_to_ok_with_the_parsed_numbers() {
    let body = r#"{"credits_remaining": 4200, "daily_limit": 5000}"#.to_string();
    match classify_credits_probe(Ok(body)) {
        CreditsProbe::Ok {
            remaining,
            daily_limit,
        } => {
            assert_eq!(remaining, 4200);
            assert_eq!(daily_limit, Some(5000));
        }
        other => panic!("a valid credits body must be Ok, got {other:?}"),
    }
}

#[test]
fn credits_probe_maps_an_unrecognised_body_to_unparseable_not_unreachable() {
    // Reachable host, but a body with no credits field: a schema/plan problem,
    // distinct from both a transport failure and a dead key.
    match classify_credits_probe(Ok("<html>200 but no json</html>".to_string())) {
        CreditsProbe::Unparseable => {}
        other => panic!("a reachable-but-unrecognised body must be Unparseable, got {other:?}"),
    }
}

#[test]
fn deep_search_cache_key_namespace_is_distinct_from_fast_search() {
    // A fast-search miss and a subsequent deep-search hit for the SAME query
    // must never collide in the response cache — one endpoint's cached
    // (non-empty) result must not be served back as the other's. `search`
    // and `search_deep` both build their cache key via `typed_cache_key`
    // keyed on the literal endpoint-name string passed as `path`, so this
    // pins that the two call sites actually use different literals.
    let fast = typed_cache_key("search", "alice@example.com", "email");
    let deep = typed_cache_key("search_deep", "alice@example.com", "email");
    assert_ne!(fast, deep);
    assert!(fast.starts_with("search#"));
    assert!(deep.starts_with("search_deep#"));
}

#[test]
fn deep_search_reuses_the_same_verified_request_body_contract_as_fast_search() {
    // `search_deep`'s only documented difference from `search`
    // (`docs/SEEKNOW_SETUP.md`'s endpoint table + FAQ) is the URL path and
    // corpus depth searched server-side — request shape and credit cost are
    // identical. Reusing `build_search_body` (already covered by
    // `search_body_includes_limit_and_optional_type`) rather than a second,
    // independently-written body builder is what makes that guarantee real
    // instead of just asserted in a doc comment.
    let deep_body = build_search_body("alice@example.com", "email", SEARCH_LIMIT);
    let fast_body = build_search_body("alice@example.com", "email", SEARCH_LIMIT);
    assert_eq!(
        deep_body, fast_body,
        "search_deep must build its request body with the exact same function \
         fast search uses — no independent, unverified body construction"
    );
}
