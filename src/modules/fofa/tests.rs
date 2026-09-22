use crate::core::scan::{Target, TargetKind};

use super::*;

#[test]
fn encode_fofa_query_handles_host_filter() {
    use base64::Engine as _;
    let filter = "host=\"example.com\"";
    let encoded = encode_fofa_query(filter);
    // Verify it's valid base64 and encodes the input correctly
    assert!(!encoded.is_empty());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("valid base64");
    assert_eq!(String::from_utf8_lossy(&decoded), filter);
}

#[test]
fn fofa_filter_builds_ip_query() {
    let target = Target::new(TargetKind::IpAddress, "1.2.3.4");
    let filter = fofa_filter(&target).expect("valid IP target");
    assert_eq!(filter, "ip=\"1.2.3.4\"");
}

#[test]
fn fofa_filter_builds_domain_query() {
    let target = Target::new(TargetKind::Domain, "example.com");
    let filter = fofa_filter(&target).expect("valid domain target");
    assert_eq!(filter, "host=\"example.com\"");
}

#[test]
fn fofa_filter_rejects_unsupported_target() {
    let target = Target::new(TargetKind::Email, "test@example.com");
    let filter = fofa_filter(&target);
    assert!(filter.is_none());
}

// ── Filter-injection hardening ──
//
// `Target::validate` restricts a seed Domain to ASCII alphanumeric/./-/_ and
// parses a seed IpAddress through `std::net::IpAddr` — neither can carry a
// `"`. But a PIVOT target built during expansion
// (`Target::new(tk, entity.value.clone())`, core/engine/mod.rs) is dispatched
// without going through that gate, and this very module mints Domain/IP
// entities straight from FOFA's own JSON response (`build_entities`, below).
// These tests construct that exact shape directly — a Target carrying a
// value `Target::validate` would already reject — to prove `fofa_filter`
// itself is safe independent of whether any particular caller validated
// first. Constructed via `Target { kind, value }` field literals rather than
// `Target::new(...)` followed by `.validate()`, since asserting the value
// SURVIVES unvalidated into the filter is exactly the point.

#[test]
fn fofa_filter_escapes_a_quote_that_would_close_the_filter_early() {
    let target = Target::new(TargetKind::Domain, "example.com\" || host=\"evil.com");
    let filter = fofa_filter(&target).expect("domain target");
    // The embedded quote must be escaped, not left to terminate the literal.
    assert_eq!(filter, "host=\"example.com\\\" || host=\\\"evil.com\"");
    // Decisive check: unescaped, exactly this substring would appear verbatim
    // and the filter would contain a live, unescaped `" || host="` splice.
    assert!(
        !filter.contains("\" || host=\""),
        "an unescaped injection substring must not survive into the filter: {filter}"
    );
}

#[test]
fn fofa_filter_escapes_a_literal_backslash_before_the_quote() {
    // Order matters: escaping the quote before the backslash would
    // double-escape the backslash this transform itself inserts. A value
    // ending in a backslash immediately before the closing position is the
    // case that catches getting the order wrong.
    let target = Target::new(TargetKind::IpAddress, "1.2.3.4\\");
    // IpAddress' own filter arm ignores parse-validity (fofa_filter is pure
    // and does not re-validate), so this constructs the same "value a real
    // Target::validate would reject" shape as the quote-injection test.
    let filter = fofa_filter(&target).expect("ip arm always returns Some");
    assert_eq!(filter, "ip=\"1.2.3.4\\\\\"");
}

#[test]
fn fofa_filter_leaves_an_ordinary_value_unescaped() {
    // No regression for the overwhelmingly common case: a clean domain/IP
    // round-trips with no backslashes inserted.
    assert_eq!(
        fofa_filter(&Target::new(TargetKind::Domain, "example.com")).unwrap(),
        "host=\"example.com\""
    );
    assert_eq!(
        fofa_filter(&Target::new(TargetKind::IpAddress, "1.2.3.4")).unwrap(),
        "ip=\"1.2.3.4\""
    );
}

#[test]
fn build_entities_emits_ip_domain_from_results() {
    let resp = FofaResp {
        error: Some(false),
        errmsg: None,
        results: Some(vec![FofaResult {
            host: "1.2.3.4:80".to_string(),
            ip: "1.2.3.4".to_string(),
            port: 80,
            protocol: "http".to_string(),
            title: "Example Site".to_string(),
            domain: "example.com".to_string(),
            os: "Linux".to_string(),
        }]),
    };

    let result = build_entities(resp.results.as_deref().unwrap_or_default(), "test-scan");
    assert!(
        result.entities.len() >= 2,
        "should emit IP and domain entities"
    );

    let has_ip = result
        .entities
        .iter()
        .any(|e| e.kind == EntityKind::IpAddress);
    let has_domain = result.entities.iter().any(|e| e.kind == EntityKind::Domain);

    assert!(has_ip, "should have IpAddress entity");
    assert!(has_domain, "should have Domain entity");
}

#[test]
fn build_entities_dedups_an_expanded_and_a_compressed_ipv6_spelling() {
    // Regression: the `ip_entities` map was keyed on the raw `hit.ip`
    // string, not the canonical form `core::entity::normalise` computes —
    // two hits for the same host reporting the same IPv6 address in
    // different textual forms minted two separate `Entity` objects, each
    // accumulating only its own hit's evidence, for what collides on one
    // uid once `Entity::new` constructs it. A real public address (Google
    // Public DNS) is used, not an RFC 3849 documentation one, purely for
    // realism.
    let resp = FofaResp {
        error: Some(false),
        errmsg: None,
        results: Some(vec![
            FofaResult {
                host: "[2001:4860:4860::8888]:80".to_string(),
                ip: "2001:4860:4860:0000:0000:0000:0000:8888".to_string(),
                port: 80,
                protocol: "http".to_string(),
                title: String::new(),
                domain: String::new(),
                os: String::new(),
            },
            FofaResult {
                host: "[2001:4860:4860::8888]:443".to_string(),
                ip: "2001:4860:4860::8888".to_string(),
                port: 443,
                protocol: "https".to_string(),
                title: String::new(),
                domain: String::new(),
                os: String::new(),
            },
        ]),
    };
    let result = build_entities(resp.results.as_deref().unwrap_or_default(), "test-scan");
    let ips: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .collect();
    assert_eq!(
        ips.len(),
        1,
        "an expanded and a compressed spelling of the same IPv6 address must dedup to one entity: {ips:?}"
    );
}

#[test]
fn build_entities_aggregates_multiple_ports_on_one_host_into_one_ip_entity() {
    // Regression: a host with several indexed open ports comes back as
    // multiple result rows sharing the same `ip` (one row per port) — the
    // module used to mint a brand-new IpAddress entity per row, inflating
    // corroboration and losing the "one host, N ports" shape the module's
    // own doc comment claims ("attached as evidence attributes on THE IP
    // entity"). The same host's repeated domain must also fold to one entity.
    let resp = FofaResp {
        error: Some(false),
        errmsg: None,
        results: Some(vec![
            FofaResult {
                host: "1.2.3.4:80".to_string(),
                ip: "1.2.3.4".to_string(),
                port: 80,
                protocol: "http".to_string(),
                title: "Example Site".to_string(),
                domain: "example.com".to_string(),
                os: "Linux".to_string(),
            },
            FofaResult {
                host: "1.2.3.4:443".to_string(),
                ip: "1.2.3.4".to_string(),
                port: 443,
                protocol: "https".to_string(),
                title: "Example Site".to_string(),
                domain: "example.com".to_string(),
                os: "Linux".to_string(),
            },
            FofaResult {
                host: "1.2.3.4:22".to_string(),
                ip: "1.2.3.4".to_string(),
                port: 22,
                protocol: "ssh".to_string(),
                title: String::new(),
                domain: "example.com".to_string(),
                os: "Linux".to_string(),
            },
        ]),
    };

    let result = build_entities(resp.results.as_deref().unwrap_or_default(), "test-scan");
    let ips: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .collect();
    assert_eq!(
        ips.len(),
        1,
        "three rows for the SAME ip must fold to one IpAddress entity: {ips:?}"
    );
    // No per-port detail is lost — each row still contributes its own evidence.
    assert_eq!(
        ips[0].evidence.len(),
        3,
        "each of the 3 ports must still contribute its own evidence record"
    );
    let ports: Vec<Option<&str>> = ips[0]
        .evidence
        .iter()
        .map(|ev| ev.attributes.get("open_port").map(String::as_str))
        .collect();
    assert!(ports.contains(&Some("80")));
    assert!(ports.contains(&Some("443")));
    assert!(ports.contains(&Some("22")));

    let domains: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .collect();
    assert_eq!(
        domains.len(),
        1,
        "the same domain repeating across rows must fold to one Domain entity: {domains:?}"
    );
}

#[test]
fn produces_lists_exactly_the_kinds_build_entities_emits() {
    // Contract guard: `produces()` must advertise exactly the entity kinds the
    // module can actually mint. `Organisation` was declared here but never
    // emitted — `FofaResult` carries no organisation field — which misled scan
    // planning and the `hse modules` reference into thinking the module can yield
    // a kind it structurally cannot.
    let declared = Fofa.produces();
    assert_eq!(
        declared.len(),
        2,
        "fofa should advertise exactly IpAddress + Domain: {declared:?}"
    );
    assert!(declared.contains(&EntityKind::IpAddress));
    assert!(declared.contains(&EntityKind::Domain));
    assert!(
        !declared.contains(&EntityKind::Organisation),
        "Organisation is never emitted by this module and must not be advertised"
    );

    // Bidirectional: every kind a fully-populated result actually emits must be
    // covered by produces(), so the two can never drift apart again.
    let resp = FofaResp {
        error: Some(false),
        errmsg: None,
        results: Some(vec![FofaResult {
            host: "1.2.3.4:443".to_string(),
            ip: "1.2.3.4".to_string(),
            port: 443,
            protocol: "https".to_string(),
            title: "Example".to_string(),
            domain: "example.com".to_string(),
            os: "Linux".to_string(),
        }]),
    };
    for e in &build_entities(resp.results.as_deref().unwrap_or_default(), "s").entities {
        assert!(
            declared.contains(&e.kind),
            "build_entities emitted {:?}, which produces() {declared:?} does not list",
            e.kind
        );
    }
}

#[test]
fn build_entities_skips_empty_results() {
    let resp = FofaResp {
        error: Some(false),
        errmsg: None,
        results: Some(vec![]),
    };

    let result = build_entities(resp.results.as_deref().unwrap_or_default(), "test-scan");
    assert!(
        result.entities.is_empty(),
        "empty results should produce no entities"
    );
}

#[test]
fn build_entities_handles_error_response() {
    let resp = FofaResp {
        error: Some(true),
        errmsg: Some("Invalid query".to_string()),
        results: Some(vec![]),
    };

    let result = build_entities(resp.results.as_deref().unwrap_or_default(), "test-scan");
    assert!(
        result.entities.is_empty(),
        "error response should produce no entities"
    );
}

#[test]
fn an_error_envelope_is_a_failure_and_a_key_shaped_one_is_flagged_for_the_pool() {
    // Backlog #17: `{"error":true,"errmsg":…}` arrives with HTTP 200 for a
    // dead key / unpaid plan / exhausted quota and used to collapse to a clean
    // empty result while the key pool never learnt about it.
    let dead_key = FofaResp {
        error: Some(true),
        errmsg: Some(
            "[820001] Insufficient credits: the account's F-coin balance is exhausted".to_string(),
        ),
        results: Some(vec![]),
    };
    let BodyVerdict::Envelope { msg, key_shaped } = classify(&dead_key) else {
        panic!("error:true is an envelope");
    };
    assert!(msg.contains("Insufficient credits") && key_shaped);
    let bad_query = FofaResp {
        error: Some(true),
        errmsg: Some("[820004] query syntax error".to_string()),
        results: Some(vec![]),
    };
    let BodyVerdict::Envelope { msg, key_shaped } = classify(&bad_query) else {
        panic!("error:true is an envelope");
    };
    assert!(msg.contains("syntax") && !key_shaped);
    let ok = FofaResp {
        error: Some(false),
        errmsg: None,
        results: Some(vec![]),
    };
    assert!(matches!(classify(&ok), BodyVerdict::Searchable(_)));
}

// ── REQ-FOFA-001: a 200 body this module cannot interpret ───────────────────
//
// Every construction above sets `error` explicitly, which is exactly why the
// defect survived: building the struct CANNOT express an ABSENT key. These
// deserialize from JSON text, which is the only way to reach the case.
//
// Mirrors `chain_intel`'s REQ-CHAININTEL-001 pair, including — and especially —
// its over-correction control: "fail closed" is only a fix if a genuine
// zero-result answer still succeeds. Otherwise it is "fail always".

/// LOCK. A 200 body of valid JSON carrying neither the `error` flag nor a
/// `results` array is not a FOFA search response. Before this, it decoded to
/// `error: false, results: []` and was reported as a successful search that
/// found nothing — a provider failure laundered into absence of evidence, which
/// is the `ProviderOutcome` doctrine's central prohibition.
#[test]
fn a_body_with_neither_error_nor_results_is_refused() {
    for raw in [
        "{}",
        r#"{"message":"rate limit exceeded"}"#,
        r#"{"errmsg":"[820001] Insufficient credits"}"#,
        r#"{"code":429,"detail":"slow down"}"#,
    ] {
        let body: FofaResp = serde_json::from_str(raw).unwrap_or_else(|e| {
            panic!("a bare JSON object decodes via serde(default): {raw} — {e}")
        });
        assert!(body.error.is_none(), "no error flag in {raw}");
        assert!(body.results.is_none(), "no results array in {raw}");
        assert!(
            matches!(classify(&body), BodyVerdict::Uninterpretable),
            "{raw} carries nothing this module can read, so it must be refused — \
             not reported as a search that found nothing"
        );
    }
}

/// CONTROL, and the one that matters more than the lock. A REAL FOFA answer
/// with zero hits must stay a successful empty search. A repair that turned
/// honest "nothing indexed" into a module error would be worse than the
/// fail-open it replaces: it would take a working provider offline via the
/// circuit breaker.
#[test]
fn a_genuine_empty_search_is_not_refused() {
    let body: FofaResp =
        serde_json::from_str(r#"{"error":false,"results":[]}"#).expect("a real empty answer");
    assert!(
        matches!(classify(&body), BodyVerdict::Searchable(_)),
        "an explicit error:false with an empty results array is a real answer, \
         not an envelope and not uninterpretable"
    );
    assert!(
        build_entities(body.results.as_deref().unwrap_or_default(), "test-scan")
            .entities
            .is_empty(),
        "and it yields no entities, without erroring"
    );
}

/// CONTROL, and the reason the guard reads TWO fields rather than just `error`.
/// This module's header documents no literal response shape, so nothing here
/// establishes that a successful FOFA response carries the `error` flag. If it
/// does not, refusing on a missing `error` alone would break every real search.
/// A body with `results` and no flag is still a search.
///
/// Mutating `classify` to read `error` alone — or joining the two with `||`
/// instead of `&&` — fails HERE and nowhere else.
#[test]
fn a_success_body_without_the_error_flag_is_still_a_search() {
    let body: FofaResp = serde_json::from_str(
        r#"{"results":[{"host":"1.2.3.4:80","ip":"1.2.3.4","port":80,
             "protocol":"http","title":"nginx","domain":"example.com","os":"linux"}]}"#,
    )
    .expect("a results-only body");
    assert!(
        body.error.is_none(),
        "this body deliberately omits the flag"
    );
    assert!(
        matches!(classify(&body), BodyVerdict::Searchable(_)),
        "a body carrying results is interpretable whether or not it flags error"
    );
    let result = build_entities(body.results.as_deref().unwrap_or_default(), "test-scan");
    assert!(
        result.entities.iter().any(|e| e.value == "1.2.3.4"),
        "the hit must still be emitted — entities: {:?}",
        result.entities.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

/// PRE-REGISTERED PREDICTION, recorded before it was run and kept as a test
/// rather than checked and discarded: `#[serde(default)]` supplies a default
/// for an ABSENT key but does not suppress a type mismatch on a PRESENT one.
///
/// It matters because it bounds what `classify` has to catch. A JSON
/// error body that reuses the key `error` with a string value — a shape
/// `chain_intel`'s own fixtures use (`{"error":"rate limited"}`) — is already a
/// decode failure here, handled by `util::http::json_body_error`. The reachable
/// case is narrower than that precedent's: bodies with no `error` key at all.
/// If this ever starts passing, the guard above is under-specified.
#[test]
fn a_non_boolean_error_value_is_already_a_decode_failure() {
    // Turbofish, not an annotation: `use super::*` brings the crate's own
    // `Result<T>` alias into scope, which takes one parameter.
    assert!(
        serde_json::from_str::<FofaResp>(r#"{"error":"rate limited"}"#).is_err(),
        "a string in a bool field must fail to decode, not default to false"
    );
}

/// LOCK for the key-rotation path, and the one that catches a sentinel reading
/// `results` alone. An error envelope as it ACTUALLY ARRIVES carries no
/// `results` key at all — only `error` and `errmsg`. Every other envelope test
/// in this file constructs `FofaResp` directly with `results` present, which
/// cannot express that, so all of them pass even when a mutated `classify`
/// sends this body to `Uninterpretable`.
///
/// The cost of getting it wrong is not cosmetic: an envelope routed to
/// `Uninterpretable` never reaches `note_keyed_error`, so a dead key, an unpaid
/// plan or an exhausted quota stops rotating out of the pool and every later
/// scan keeps spending on the same dead credential.
#[test]
fn an_error_envelope_arrives_without_a_results_key_and_still_reaches_the_pool() {
    let body: FofaResp =
        serde_json::from_str(r#"{"error":true,"errmsg":"[820001] Insufficient credits: the account's F-coin balance is exhausted"}"#)
            .expect("an error envelope decodes");
    assert!(
        body.results.is_none(),
        "the fixture must omit `results` — that absence is the whole point"
    );
    let BodyVerdict::Envelope { msg, key_shaped } = classify(&body) else {
        panic!(
            "an error:true body with no `results` is an ENVELOPE, not an \
             uninterpretable body — routing it to Uninterpretable silently \
             disables key rotation"
        );
    };
    assert!(
        msg.contains("F-coin"),
        "the provider's own words survive: {msg}"
    );
    assert!(
        key_shaped,
        "a credit-exhaustion message must reach the key pool"
    );
}

/// LOCK for the WIRING, not the classification. `classify` being right is
/// useless if the caller ignores it, and until `handle_body` was extracted from
/// `process` nothing could observe the difference: swapping the
/// `Uninterpretable` arm for an `Ok` compiled, passed every test in this file,
/// and silently restored the defect.
///
/// `process` itself is not reachable from a unit test — it needs a socket, and
/// its endpoint is a literal — so the decision was moved to where it can be
/// called directly rather than the test being built up to reach it
/// (REQ-CI-010's rule, applied to REQ-FOFA-001).
#[test]
fn the_uninterpretable_verdict_actually_reaches_the_caller_as_an_error() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "test-scan".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let refused: FofaResp = serde_json::from_str(r#"{"message":"rate limit exceeded"}"#)
        .expect("a bare JSON object decodes");
    let err = handle_body(&refused, "k", &ctx)
        .expect_err("an uninterpretable body must reach the caller as an Err");
    assert!(
        err.to_string().contains("not a FOFA search response"),
        "and it must say what arrived, so a wrong firing is diagnosable: {err}"
    );

    // Over-correction control on the SAME seam: a real answer still succeeds,
    // so the wiring refuses the uninterpretable case specifically rather than
    // erroring on everything.
    let real: FofaResp = serde_json::from_str(
        r#"{"error":false,"results":[{"host":"1.2.3.4:80","ip":"1.2.3.4","port":80,
             "protocol":"http","title":"nginx","domain":"example.com","os":"linux"}]}"#,
    )
    .expect("a real answer decodes");
    let out = handle_body(&real, "k", &ctx).expect("a real answer must not error");
    assert!(
        out.entities.iter().any(|e| e.value == "1.2.3.4"),
        "and it yields its hit"
    );
}

/// LOCK for the key cascade — the half of the envelope arm that costs money.
///
/// A key/quota-shaped envelope must actually MARK the key, not merely be
/// classified as key-shaped. Deleting the `if key_shaped { note_keyed_error(…) }`
/// line passed every other test in this file: the module would keep erroring
/// correctly while the dead key stayed `Active` in the pool, so every later scan
/// re-spent on the same exhausted credential.
///
/// This test was almost not written, on a chain of reasoning that was WRONG:
/// `report_key_exhausted` → `global_pool()` → `persist_off_thread`, which saves
/// inline outside a tokio runtime, looked like it would write to the operator's
/// real `~/.huntsman/key_pool.json`. It does not. `paths::huntsman_dir_path()`
/// has a `cfg!(test)` branch returning a pid-scoped temp home, and its doc says
/// why that form was chosen over an env var: *"a compile-time switch, not a
/// runtime env mutation, so it needs no unsafe code and can't race a
/// fire-and-forget `spawn_blocking` persist that outlives the test function."*
/// Four links of that chain were read and the fifth was assumed.
///
/// The key VALUE is unique per process and thread because the pool is a
/// process-global keyed by (service, value) and the service is fixed at `fofa`;
/// only the value can keep this assertion from colliding with a parallel test.
#[test]
fn a_key_shaped_envelope_actually_marks_the_key_in_the_pool() {
    use crate::util::key_pool::{KeyEntry, KeyStatus, global_pool};

    let pool = global_pool();
    let dead = format!("fofa-req-fofa-001-dead-{}", std::process::id());
    assert!(
        pool.add("fofa", KeyEntry::new(dead.clone())),
        "fixture: `fofa` must be a poolable service and this value must be new"
    );

    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "test-scan".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let envelope: FofaResp = serde_json::from_str(
        r#"{"error":true,"errmsg":"[820001] Insufficient credits: the account's F-coin balance is exhausted"}"#,
    )
    .expect("an exhausted-credit envelope decodes");
    handle_body(&envelope, &dead, &ctx).expect_err("an error envelope is the module's error");

    assert_eq!(
        pool.entry_status("fofa", &dead),
        Some(KeyStatus::Invalid),
        "a credit-exhaustion envelope must retire the key, or the cascade keeps \
         spending on it every scan"
    );
}

/// OVER-CORRECTION CONTROL for the lock above. Not every error envelope is a
/// key problem — FOFA returns `errmsg: "query syntax error"` for a rejected
/// QUERY, and retiring a perfectly good key over that would take a working
/// credential out of rotation. The module's own comment draws this distinction
/// ("rather than a rejected query"); this is what holds it.
#[test]
fn a_query_shaped_envelope_leaves_the_key_alone() {
    use crate::util::key_pool::{KeyEntry, KeyStatus, global_pool};

    let pool = global_pool();
    let good = format!("fofa-req-fofa-001-good-{}", std::process::id());
    assert!(pool.add("fofa", KeyEntry::new(good.clone())), "fixture");

    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "test-scan".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let envelope: FofaResp =
        serde_json::from_str(r#"{"error":true,"errmsg":"[820004] query syntax error"}"#)
            .expect("a query-error envelope decodes");
    handle_body(&envelope, &good, &ctx).expect_err("still the module's error");

    assert_eq!(
        pool.entry_status("fofa", &good),
        Some(KeyStatus::Untested),
        "a rejected QUERY must not retire the key that sent it"
    );
}
