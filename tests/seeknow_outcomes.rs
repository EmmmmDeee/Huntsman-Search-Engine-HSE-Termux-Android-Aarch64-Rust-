use huntsman_recon::source_outcome::{
    SourceHealthAction, SourceOutcomeKind, recommended_action,
};

#[test]
fn entitlement_and_quota_are_distinct_causal_states() {
    let entitlement = SourceOutcomeKind::EntitlementDenied;
    let quota = SourceOutcomeKind::QuotaExhausted;

    assert!(!entitlement.is_accepted());
    assert!(!quota.is_accepted());
    assert!(!entitlement.normally_retryable());
    assert!(!quota.normally_retryable());

    assert_eq!(recommended_action(entitlement), SourceHealthAction::Investigate);
    assert_eq!(recommended_action(quota), SourceHealthAction::Backoff);
    assert_eq!(
        recommended_action(SourceOutcomeKind::RateLimited),
        SourceHealthAction::Backoff
    );

    assert_eq!(
        serde_json::to_string(&entitlement).unwrap(),
        "\"entitlement_denied\""
    );
    assert_eq!(
        serde_json::to_string(&quota).unwrap(),
        "\"quota_exhausted\""
    );
}
