use huntsman_recon::EntityKind;
use huntsman_recon::collector::{CollectionLimits, CollectorError, ObservationReceipt};
use huntsman_recon::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

#[test]
fn default_collection_limits_are_bounded() {
    let limits = CollectionLimits::default();
    assert_eq!(limits.max_requests, 8);
    assert_eq!(limits.max_entities, 1_000);
    assert_eq!(limits.max_records_per_response, 500);
    assert_eq!(limits.max_pivots, 256);
}

#[test]
fn unsupported_selector_is_typed() {
    assert_eq!(
        CollectorError::UnsupportedSelector(EntityKind::Coordinates),
        CollectorError::UnsupportedSelector(EntityKind::Coordinates)
    );
}

#[test]
fn observation_receipt_keeps_causal_state_without_credentials() {
    let receipt = ObservationReceipt {
        source: "fixture".into(),
        dataset: Some("upstream".into()),
        observed_at_unix: 7,
        response_sha256: Some("a".repeat(64)),
        outcome: SourceExecutionOutcome::valid_zero("fixture", 7),
        parsed_rows: 0,
        truncated: false,
    };

    assert_eq!(receipt.outcome.kind, SourceOutcomeKind::ValidZero);
    assert!(!receipt.truncated);
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(!json.contains("credential"));
    assert!(!json.contains("api_key"));
}
