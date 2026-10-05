use super::*;

/// Every `TargetKind` variant. Listing them exhaustively makes the
/// agreement tests below a compile-time tripwire: a new kind added to the
/// enum forces a decision here (accept with a selector, or decline).
const ALL_KINDS: &[TargetKind] = &[
    TargetKind::Email,
    TargetKind::Username,
    TargetKind::Phone,
    TargetKind::FullName,
    TargetKind::IpAddress,
    TargetKind::Domain,
    TargetKind::Url,
    TargetKind::Asn,
    TargetKind::Cidr,
    TargetKind::Coordinates,
    TargetKind::Address,
    TargetKind::Organisation,
    TargetKind::AbnAcn,
    TargetKind::MacAddress,
    TargetKind::ApiKey,
    TargetKind::CryptoAddress,
];

#[test]
fn cache_ttl_is_24h_so_repeat_scans_dont_re_spend_a_paid_lookup() {
    // Immutable leak/archive corpus ⇒ the inter-scan cache serves a repeat
    // scan for free; a 0 (trait default) would disable it, so pin the window.
    assert_eq!(IntelX.cache_ttl_secs(), 86_400);
}

#[test]
fn accepts_every_kind_intelx_has_a_selector_for() {
    let m = IntelX;
    for k in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::Domain,
        TargetKind::IpAddress,
        TargetKind::Url,
        TargetKind::Cidr,
        TargetKind::MacAddress,
        TargetKind::CryptoAddress,
    ] {
        assert!(m.accepts(&Target::new(k, "x")), "should accept {k:?}");
    }
}

#[test]
fn rejects_kinds_intelx_cannot_resolve() {
    let m = IntelX;
    for k in [
        TargetKind::Asn,
        TargetKind::Coordinates,
        TargetKind::Address,
        TargetKind::Organisation,
        TargetKind::AbnAcn,
        TargetKind::ApiKey,
    ] {
        assert!(!m.accepts(&Target::new(k, "x")), "should reject {k:?}");
        assert_eq!(intelx_selector(k), None);
    }
}

#[test]
fn accepts_is_exactly_the_selector_map() {
    // accepts() and the selector map must agree for EVERY kind — no drift
    // between the gate and the single-sourced coverage definition.
    let m = IntelX;
    for &k in ALL_KINDS {
        assert_eq!(
            m.accepts(&Target::new(k, "x")),
            intelx_selector(k).is_some(),
            "accepts/selector disagree for {k:?}"
        );
    }
}

#[test]
fn selector_labels_are_descriptive() {
    assert_eq!(intelx_selector(TargetKind::Email), Some("email"));
    assert_eq!(intelx_selector(TargetKind::Url), Some("url"));
    assert_eq!(intelx_selector(TargetKind::Cidr), Some("cidr"));
    assert_eq!(intelx_selector(TargetKind::MacAddress), Some("mac"));
    assert_eq!(
        intelx_selector(TargetKind::CryptoAddress),
        Some("crypto-address")
    );
    // Unstructured kinds resolve as a general text search.
    assert_eq!(intelx_selector(TargetKind::Username), Some("text"));
    assert_eq!(intelx_selector(TargetKind::FullName), Some("text"));
}

#[test]
fn produces_covers_every_accepted_kind() {
    // The module re-emits the scanned target, so every accepted kind's
    // entity kind must be declared in produces().
    let produced = IntelX.produces();
    for &k in ALL_KINDS {
        if intelx_selector(k).is_some() {
            let ek = k.to_entity_kind();
            assert!(
                produced.contains(&ek),
                "accepts {k:?} but produces() omits its entity kind {ek:?}"
            );
        }
    }
}

#[test]
fn cost_is_paid() {
    assert!(matches!(IntelX.cost(), ModuleCost::Paid));
}

#[test]
fn media_labels_match_official_table() {
    // Spot-check the corrected media-code table against the SDK docs.
    assert_eq!(media_label(1), Some("paste document"));
    assert_eq!(media_label(14), Some("URL"));
    assert_eq!(media_label(15), Some("PDF document"));
    assert_eq!(media_label(24), Some("text file"));
    // Codes not in the table are reported numerically, not mislabeled.
    assert_eq!(media_label(999), None);
    // The OLD table's wrong mappings must not reappear: code 2 is
    // "paste user", never "breach".
    assert_eq!(media_label(2), Some("paste user"));
}

#[test]
fn bucket_family_collapses_dotted_names() {
    assert_eq!(bucket_family("leaks.public.general"), "leaks");
    assert_eq!(bucket_family("darknet.tor"), "darknet");
    assert_eq!(bucket_family("pastes"), "pastes");
    assert_eq!(bucket_family(""), "");
}

#[test]
fn earliest_breach_date_uses_leaks_family_only_and_gates_on_the_breach_tag() {
    let rec = |bucket: &str, date: &str| Record {
        bucket: Some(bucket.to_string()),
        bucketh: None,
        media: None,
        date: Some(date.to_string()),
    };
    let records = vec![
        rec("pastes", "2010-01-01"), // earlier, but NOT leaks-family
        rec("leaks.public.general", "2019-05-13"), // earliest leaks record
        rec("leaks.private.general", "2021-08-01"),
        rec("darknet.tor", "2009-01-01"), // earlier, but not leaks
    ];
    // Earned the BREACH tag → earliest LEAKS date (paste/darknet ignored).
    assert_eq!(
        earliest_breach_date(&records, true),
        Some("2019-05-13"),
        "must pick the earliest leaks-family date, ignoring paste/darknet buckets"
    );
    // No BREACH tag (e.g. a text search) → no breach_date at all.
    assert_eq!(earliest_breach_date(&records, false), None);
    // No leaks-family records → None even when earned.
    let non_leaks = vec![rec("pastes", "2015-01-01")];
    assert_eq!(earliest_breach_date(&non_leaks, true), None);
}

#[test]
fn text_search_withholds_the_strong_exposure_tags() {
    use crate::core::tags;
    use std::collections::BTreeSet;

    let families: BTreeSet<String> = ["leaks", "pastes", "darknet"]
        .into_iter()
        .map(String::from)
        .collect();

    // Structured selector (email/domain/…): a `leaks`/`pastes` hit is validated
    // against the exact value, so it earns the full exposure semantics.
    let structured = exposure_tags(false, &families);
    assert!(structured.iter().any(|t| t == tags::BREACH));
    assert!(structured.iter().any(|t| t == tags::PASSWORD_AT_RISK));
    assert!(structured.iter().any(|t| t == tags::PASTE_EXPOSED));
    assert!(structured.iter().any(|t| t == "intelx-source:darknet"));

    // Unscoped TEXT search (username/full-name): a hit is a mere text-contains
    // match, so the breach / password-at-risk / paste-exposed claims are withheld
    // — every family collapses to neutral provenance. This is the fabrication the
    // gate prevents: a same-name stranger's leaked paste no longer stamps
    // `password-at-risk` on the subject's anchor.
    let text = exposure_tags(true, &families);
    assert!(
        !text
            .iter()
            .any(|t| t == tags::BREACH || t == tags::PASSWORD_AT_RISK),
        "a text search must not assert breach/password-at-risk exposure"
    );
    assert!(
        !text.iter().any(|t| t == tags::PASTE_EXPOSED),
        "a text search must not assert paste exposure"
    );
    assert_eq!(
        text,
        vec![
            "intelx-source:darknet".to_string(),
            "intelx-source:leaks".to_string(),
            "intelx-source:pastes".to_string(),
        ],
        "every family collapses to neutral provenance, in deterministic order"
    );
}

#[test]
fn result_resp_terminal_status_parsing() {
    let running: ResultResp =
        serde_json::from_str(r#"{"status":1,"records":[]}"#).expect("should succeed");
    assert_eq!(running.status, Some(1)); // must NOT be treated as terminal
    let finished: ResultResp = serde_json::from_str(
        r#"{"status":2,"records":[{"bucket":"leaks.public.general","media":24,"date":"2024-01-01"}]}"#,
    )
    .expect("should succeed");
    assert_eq!(finished.status, Some(2));
    assert_eq!(finished.records[0].media, Some(24));
    assert_eq!(
        finished.records[0].bucket.as_deref(),
        Some("leaks.public.general")
    );
}

#[test]
fn record_tolerates_missing_and_human_bucket() {
    let r: ResultResp =
        serde_json::from_str(r#"{"status":2,"records":[{"bucketh":"Public Leaks","media":1}]}"#)
            .expect("should succeed");
    assert_eq!(r.records[0].bucketh.as_deref(), Some("Public Leaks"));
    assert!(r.records[0].bucket.is_none());
    assert!(r.records[0].date.is_none());
}

// REQ-INTELX-002 — `classify_start` must fail CLOSED on any search-start body
// that is neither a usable poll id nor a recognised status. `StartResp`'s
// fields are both `#[serde(default)]`, so an auth/quota failure, a WAF page, or
// any unexpected 200 JSON shape decodes without error to all-`None`; a search
// *start* has no "no results" state, so treating that as a clean negative is
// the most consequential false clean this engine can produce. These lock the
// policy at the pure seam (no network).

#[test]
fn classify_start_proceeds_only_on_a_usable_id() {
    // status 0 (explicit success) and status omitted both proceed when a
    // non-empty id is present.
    match classify_start(Some("abc123".to_string()), Some(0)).expect("status 0 + id proceeds") {
        StartDecision::Proceed(id) => assert_eq!(id, "abc123"),
        other => panic!("expected Proceed, got {other:?}"),
    }
    match classify_start(Some("abc123".to_string()), None).expect("omitted status + id proceeds") {
        StartDecision::Proceed(id) => assert_eq!(id, "abc123"),
        other => panic!("expected Proceed, got {other:?}"),
    }
}

#[test]
fn classify_start_invalid_term_is_the_one_clean_negative() {
    // status 1 = the API explicitly rejected the term: a genuine clean negative.
    assert!(matches!(
        classify_start(None, Some(1)).expect("invalid term is Ok(InvalidTerm)"),
        StartDecision::InvalidTerm
    ));
}

#[test]
fn classify_start_max_concurrent_is_an_error() {
    let err = classify_start(None, Some(2)).expect_err("max concurrent must be an error");
    assert!(
        matches!(err, crate::core::error::Error::Module { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("max concurrent"), "{err}");
}

#[test]
fn an_unexpected_start_body_fails_closed_not_a_clean_negative() {
    // The core REQ-INTELX-002 lock: an auth/quota failure or unexpected 200
    // decodes to all-`None` and MUST be an error, never a clean negative.
    let start: StartResp = serde_json::from_str(r#"{"error":"Invalid or expired API key"}"#)
        .expect("all-optional StartResp decodes any JSON object without error");
    assert!(start.id.is_none() && start.status.is_none());
    let err = classify_start(start.id, start.status)
        .expect_err("an unexpected-shape start body must fail closed, never a clean negative");
    assert!(
        matches!(err, crate::core::error::Error::Module { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("no usable search id"), "{err}");

    // A success status with no id, and a present-but-empty id, are equally
    // unusable — both fail closed rather than proceed or read as a miss.
    assert!(classify_start(None, Some(0)).is_err());
    assert!(classify_start(Some(String::new()), Some(0)).is_err());
}

#[test]
fn poll_failure_error_preserves_a_typed_rate_limit() {
    // REQ-INTELX-001. A poll loop that spent its attempts on 429s must surface
    // the THROTTLE, not a generic module fault: the breaker treats a fault as a
    // provider defect and the live sweep reads it as "unreachable", so a
    // throttled key would be indistinguishable from a dead endpoint.
    let typed = Error::RateLimited("intelx: HTTP 429 Too Many Requests".to_string());
    let out = poll_failure_error(Some(typed), "abc-123", POLL_ATTEMPTS);
    assert!(
        matches!(out, Error::RateLimited(_)),
        "a throttle must stay RateLimited, got {out:?}"
    );
}

#[test]
fn poll_failure_error_preserves_a_typed_bot_challenge() {
    // Same for an anti-bot interstitial: `Blocked` is its own operator-visible
    // state and must not collapse into a module fault.
    let typed = Error::BotChallenge("intelx: challenge page".to_string());
    let out = poll_failure_error(Some(typed), "abc-123", POLL_ATTEMPTS);
    assert!(
        matches!(out, Error::BotChallenge(_)),
        "a wall must stay BotChallenge, got {out:?}"
    );
}

#[test]
fn poll_failure_error_falls_back_to_a_module_fault_only_when_no_error_was_seen() {
    // Every poll succeeded yet the search never reached a terminal state. There
    // is no typed failure to report, so the generic fault IS the right answer —
    // and it must still name the search and the attempt ceiling.
    let out = poll_failure_error(None, "abc-123", POLL_ATTEMPTS);
    assert!(
        matches!(out, Error::Module { .. }),
        "no typed error seen => module fault, got {out:?}"
    );
    let msg = out.to_string();
    assert!(msg.contains("abc-123"), "must name the search id: {msg}");
    assert!(
        msg.contains(&POLL_ATTEMPTS.to_string()),
        "must name the attempt ceiling: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Phase 2 end to end, against a loopback.
//
// The three `poll_failure_error` tests above lock the SELECTION rule — given a
// typed error, report it — and the REQ-INTELX-001 ledger entry said so plainly
// rather than claiming more: nothing exercised each arm's CAPTURE, because the
// endpoint was a hardcoded `const` and no test could put a 429, a wall or a
// drifted body in front of the real classification. `PollPlan` closes that.
//
// Every test below runs the REAL loop — status classification, `Retry-After`
// reading, body decoding, terminal-state logic, the server-side terminate and
// the fail-closed decision — against a status the test chooses. The first
// three fail on the pre-REQ-INTELX-001 code (the arms that `continue`d past
// their error); the last three pass on it, which is what makes the first
// three attributable to the discarded typing rather than to tests that fail
// indiscriminately.
// ---------------------------------------------------------------------------

/// A context whose client can reach a loopback. `build_client()` filters
/// loopback by design, so the shared engine client cannot be used here.
fn loopback_ctx() -> crate::core::module::ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    crate::core::module::ModuleContext {
        scan_id: "intelx-poll".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

fn plan_for(base: &str, attempts: u32) -> PollPlan<'_> {
    PollPlan {
        base,
        // The live 1.5 s cadence would cost seconds per case. Collapsing it is
        // the reason the SCHEDULE is part of the plan: the alternative — a
        // separate fast loop for tests — is the duplicated authority that lets
        // the tested path and the production path drift apart.
        interval: Duration::ZERO,
        attempts,
    }
}

#[tokio::test]
async fn a_throttled_poll_surfaces_as_the_typed_rate_limit() {
    use crate::util::http::test_server::{Canned, serve};
    // `Retry-After: 0` drives the real backoff branch instantly instead of
    // skipping it. Two attempts, not three: on the third the 429 arm also
    // reports the key to the process-global key pool, and this test is about
    // the typed capture, not about that side effect.
    let base = serve(vec![
        Canned::json(429, r#"{"error":"rate limit exceeded"}"#).header("Retry-After", "0"),
        Canned::json(429, r#"{"error":"rate limit exceeded"}"#).header("Retry-After", "0"),
        // The loop ends unfinished, so it terminates the search server-side.
        Canned::text(200, ""),
    ])
    .await;
    let err = poll_search(&loopback_ctx(), plan_for(&base, 2), "k", "sid-429")
        .await
        .expect_err("an exhausted quota is never a clean negative");
    assert!(
        matches!(err, Error::RateLimited(_)),
        "a throttle must reach the breaker as RateLimited, got {err:?}"
    );
}

#[tokio::test]
async fn a_wall_in_front_of_the_poll_surfaces_as_the_typed_block() {
    use crate::util::http::test_server::{Canned, serve};
    // A real captured interstitial, served with the 503 Cloudflare's classic
    // challenge uses — 401/403/429 would additionally burn the key in the
    // process-global pool, which is a different requirement's concern.
    const WALL: &str =
        include_str!("../../util/html/testdata/cloudflare_block_anubis_2026-09-15.html");
    let base = serve(vec![
        Canned::html(503, WALL),
        Canned::html(503, WALL),
        Canned::text(200, ""),
    ])
    .await;
    let err = poll_search(&loopback_ctx(), plan_for(&base, 2), "k", "sid-wall")
        .await
        .expect_err("a wall is never a clean negative");
    assert!(
        matches!(err, Error::BotChallenge(_)),
        "an anti-bot wall must reach the breaker as BotChallenge, got {err:?}"
    );
}

#[tokio::test]
async fn a_drifted_poll_body_stays_a_decode_fault_not_the_generic_message() {
    use crate::util::http::test_server::{Canned, serve};
    // A 200 whose shape contradicts `ResultResp`: `status` is not an integer
    // and `records` is not an array. `#[serde(default)]` cannot rescue a field
    // that is PRESENT and wrongly typed, so this is a genuine contract drift.
    let drift = r#"{"status":"finished","records":"none"}"#;
    let base = serve(vec![
        Canned::json(200, drift),
        Canned::json(200, drift),
        Canned::text(200, ""),
    ])
    .await;
    let err = poll_search(&loopback_ctx(), plan_for(&base, 2), "k", "sid-drift")
        .await
        .expect_err("an undecodable body is never a clean negative");
    let msg = err.to_string();
    assert!(
        !msg.contains("never reached a terminal state"),
        "the decode fault must survive the loop rather than being replaced by \
         the generic message: {msg}"
    );
    assert!(msg.contains(SRC), "the fault must name the module: {msg}");
    // Non-vacuous on the baseline too: the generic message also names the
    // module, so this second assertion has to be about the decode itself.
    assert!(
        msg.contains("JSON") || msg.contains("json") || msg.contains("expected"),
        "the fault must say the body did not decode: {msg}"
    );
}

#[tokio::test]
async fn every_poll_succeeding_without_a_terminal_state_is_the_generic_fault() {
    use crate::util::http::test_server::{Canned, serve};
    // Status 1 = "no results yet, still running". Nothing went wrong, so there
    // is no typed error to report and the generic module fault is correct.
    // This one passes on the baseline — it is the control for the three above.
    let running = r#"{"status":1,"records":[]}"#;
    let base = serve(vec![
        Canned::json(200, running),
        Canned::json(200, running),
        Canned::text(200, ""),
    ])
    .await;
    let err = poll_search(&loopback_ctx(), plan_for(&base, 2), "k", "sid-slow")
        .await
        .expect_err("a search that never finished is not an authoritative empty");
    let msg = err.to_string();
    assert!(matches!(err, Error::Module { .. }), "{err:?}");
    assert!(
        msg.contains("sid-slow") && msg.contains("never reached a terminal state"),
        "{msg}"
    );
}

#[tokio::test]
async fn a_terminal_none_available_is_the_authoritative_empty() {
    use crate::util::http::test_server::{Canned, serve};
    // Status 3 = "no results available" — terminal, and the ONE empty phase 2
    // may legitimately report. No terminate call: the search finished.
    let base = serve(vec![Canned::json(200, r#"{"status":3,"records":[]}"#)]).await;
    let records = poll_search(&loopback_ctx(), plan_for(&base, 3), "k", "sid-empty")
        .await
        .expect("a terminal none-available is a real clean negative");
    assert!(records.is_empty());
}

#[tokio::test]
async fn records_accumulate_across_batches_and_status_one_is_never_terminal() {
    use crate::util::http::test_server::{Canned, serve};
    // An earlier revision broke out of the loop on status 1, which made a slow
    // search look empty. Batch, then "still running", then the terminal batch.
    let base = serve(vec![
        Canned::json(
            200,
            r#"{"status":0,"records":[{"bucket":"leaks.public.general","media":24}]}"#,
        ),
        Canned::json(200, r#"{"status":1,"records":[]}"#),
        Canned::json(
            200,
            r#"{"status":2,"records":[{"bucket":"pastes","media":1}]}"#,
        ),
    ])
    .await;
    let records = poll_search(&loopback_ctx(), plan_for(&base, 3), "k", "sid-batched")
        .await
        .expect("a finished search with records is not a failure");
    assert_eq!(
        records.len(),
        2,
        "both batches must survive; status 1 is not terminal"
    );
    assert_eq!(records[0].bucket.as_deref(), Some("leaks.public.general"));
    assert_eq!(records[1].bucket.as_deref(), Some("pastes"));
}
