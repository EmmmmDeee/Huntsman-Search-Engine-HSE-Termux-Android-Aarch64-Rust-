use huntsman_recon::collector::{CollectionLimits, CollectionOutcome};
use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::fetch::Credential;
use huntsman_recon::lineage::Lineage;
use huntsman_recon::seeknow_collector::{
    SeekNowCollectionMode, SeekNowCollector, collect_with_credential, plan_selector,
};
use huntsman_recon::source_outcome::SourceOutcomeKind;

#[allow(dead_code)]
#[path = "support/seeknow_doubles.rs"]
mod seeknow_doubles;

use seeknow_doubles::{ScriptedTransport, credential_with, response};

/// The collector's credential carries its own provenance and secret, so a test can tell it
/// from the client's.
fn credential() -> Credential {
    credential_with("collector-test", "seek-collector-test-secret")
}

fn selector(kind: EntityKind, value: &str) -> Entity {
    Entity::new(kind, value, 1.0, "scan-test")
}

#[test]
fn selector_planning_is_typed_and_rejects_unsupported_before_transport() {
    let cases = [
        (EntityKind::Email, "Alice@Example.COM", Some("email")),
        (EntityKind::Username, "@Alice", Some("username")),
        (EntityKind::Phone, "+61 412 345 678", Some("phone")),
        (EntityKind::IpAddress, "8.8.8.8", Some("ip")),
        (EntityKind::Domain, "Example.COM", Some("domain")),
        (EntityKind::Person, "Alice Example", Some("name")),
        (EntityKind::Url, "https://example.com/login", Some("url")),
        (
            EntityKind::DeviceId,
            "synthetic-machine-001",
            Some("machine_id"),
        ),
    ];
    for (kind, value, expected_type) in cases {
        let plan = plan_selector(&selector(kind, value), &CollectionLimits::default()).unwrap();
        assert_eq!(plan.query_type.api_value(), expected_type);
        assert_ne!(plan.query.trim(), "");
    }

    assert!(
        plan_selector(
            &selector(EntityKind::Person, "A"),
            &CollectionLimits::default()
        )
        .is_err()
    );
    assert!(SeekNowCollector.accepts(&EntityKind::Email));
    assert!(SeekNowCollector.accepts(&EntityKind::Url));
    assert!(SeekNowCollector.accepts(&EntityKind::DeviceId));
}

#[test]
fn fast_positive_stops_and_fast_failure_never_spends_deep_credit() {
    let positive = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[{"email":"alice@example.com","dbname":"Dataset A"}]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "alice@example.com"),
        &positive,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        10,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::Success);
    assert_eq!(positive.request_count(), 1);
    assert_eq!(batch.receipts.len(), 1);

    let failed = ScriptedTransport::new(vec![response(
        401,
        r#"{"success":false,"error":"invalid_api_key"}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "alice@example.com"),
        &failed,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        11,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::Failed);
    assert_eq!(failed.request_count(), 1);
    assert_eq!(
        batch.receipts[0].outcome.kind,
        SourceOutcomeKind::AuthRejected
    );
}

#[test]
fn validated_fast_zero_escalates_once_and_deep_failure_is_partial() {
    let success = ScriptedTransport::new(vec![
        response(200, r#"{"success":true,"data":[]}"#),
        response(
            200,
            r#"{"success":true,"data":[{"username":"alice","breach":"Breach B"}]}"#,
        ),
    ]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &success,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        20,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::Success);
    assert_eq!(success.request_count(), 2);
    assert_eq!(batch.receipts.len(), 2);

    let partial = ScriptedTransport::new(vec![
        response(200, r#"{"success":true,"data":[]}"#),
        response(503, "unavailable"),
    ]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &partial,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        21,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::Partial);
    assert_eq!(partial.request_count(), 2);
    assert_eq!(batch.receipts[0].outcome.kind, SourceOutcomeKind::ValidZero);
    assert_ne!(batch.receipts[1].outcome.kind, SourceOutcomeKind::ValidZero);
}

#[test]
fn adaptive_respects_endpoint_specific_selector_support() {
    let phone = ScriptedTransport::new(vec![response(200, r#"{"success":true,"data":[]}"#)]);
    let batch = collect_with_credential(
        &selector(EntityKind::Phone, "+61 412 345 678"),
        &phone,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        22,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::ValidZero);
    assert_eq!(phone.request_count(), 1);
    assert!(phone.seen.borrow()[0].url.ends_with("/search"));

    let url = ScriptedTransport::new(vec![response(200, r#"{"success":true,"data":[]}"#)]);
    let batch = collect_with_credential(
        &selector(EntityKind::Url, "https://example.com/login"),
        &url,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        23,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::ValidZero);
    assert_eq!(url.request_count(), 1);
    assert!(url.seen.borrow()[0].url.ends_with("/stealer"));

    let unsupported_deep = ScriptedTransport::new(Vec::new());
    assert!(
        collect_with_credential(
            &selector(EntityKind::Person, "Alice Example"),
            &unsupported_deep,
            &credential(),
            &CollectionLimits::default(),
            SeekNowCollectionMode::DeepOnly,
            24,
        )
        .is_err()
    );
    assert_eq!(unsupported_deep.request_count(), 0);

    let unsupported_fast = ScriptedTransport::new(Vec::new());
    assert!(
        collect_with_credential(
            &selector(EntityKind::DeviceId, "synthetic-machine-001"),
            &unsupported_fast,
            &credential(),
            &CollectionLimits::default(),
            SeekNowCollectionMode::FastOnly,
            25,
        )
        .is_err()
    );
    assert_eq!(unsupported_fast.request_count(), 0);
}

#[test]
fn evidence_is_deduped_and_lineage_comes_from_response_dataset_not_seeknow() {
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[
            {"email":"Alice@Example.com","dbname":"Dataset A","source":"mirror-one","record_id":"r1","password":"raw-secret"},
            {"email":"alice@example.com","dbname":"Dataset A","source":"mirror-two","record_id":"r2","password":"other-secret"}
        ]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "alice@example.com"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::FastOnly,
        30,
    )
    .unwrap();

    assert_eq!(batch.outcome, CollectionOutcome::Success);
    let emails: Vec<_> = batch
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Email)
        .collect();
    assert_eq!(emails.len(), 1);
    let entity = emails[0];
    assert_eq!(entity.value, "alice@example.com");
    assert!(
        entity
            .evidence
            .iter()
            .all(|e| e.provenance.source == "seeknow")
    );
    assert_eq!(entity.evidence.len(), 2);
    for evidence in &entity.evidence {
        assert_eq!(Lineage::of(evidence).family(), Some("dataset a"));
        let rendered = serde_json::to_string(evidence).unwrap();
        assert!(!rendered.contains("raw-secret"));
        assert!(!rendered.contains("other-secret"));
    }
}

#[test]
fn stealer_machine_identifiers_map_to_device_entities() {
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[{"machine_id":"synthetic-machine-001","source":"Synthetic Fixture"}]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::DeviceId, "synthetic-machine-001"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::DeepOnly,
        31,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::Success);
    assert!(batch.entities.iter().any(
        |entity| entity.kind == EntityKind::DeviceId && entity.value == "synthetic-machine-001"
    ));
}

#[test]
fn ambiguous_upstream_array_counts_as_no_independent_family() {
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[{"email":"alice@example.com","dbname":["Dataset A","Dataset B"]}]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "alice@example.com"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::FastOnly,
        31,
    )
    .unwrap();
    let evidence = &batch.entities[0].evidence[0];
    assert!(matches!(Lineage::of(evidence), Lineage::Ambiguous { .. }));
}

#[test]
fn entity_capacity_still_absorbs_evidence_for_existing_uid() {
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[
            {"email":"alice@example.com","dbname":"Dataset A","record_id":"r1"},
            {"email":"alice@example.com","dbname":"Dataset A","record_id":"r2"},
            {"username":"overflow","dbname":"Dataset A","record_id":"r3"}
        ]}"#,
    )]);
    let limits = CollectionLimits {
        max_entities: 1,
        ..CollectionLimits::default()
    };
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "alice@example.com"),
        &transport,
        &credential(),
        &limits,
        SeekNowCollectionMode::FastOnly,
        32,
    )
    .unwrap();

    assert_eq!(batch.entities.len(), 1);
    assert_eq!(batch.entities[0].kind, EntityKind::Email);
    assert_eq!(batch.entities[0].value, "alice@example.com");
    assert_eq!(batch.entities[0].evidence.len(), 2);
}
