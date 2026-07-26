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
    let running: ResultResp = serde_json::from_str(r#"{"status":1,"records":[]}"#).expect("should succeed");
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
