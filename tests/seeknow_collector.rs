use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::collector::{CollectionLimits, CollectionOutcome};
use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::fetch::{AuthStyle, Credential};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Secret;
use huntsman_recon::lineage::Lineage;
use huntsman_recon::seeknow::KEY_SLOT;
use huntsman_recon::seeknow_collector::{
    SeekNowCollectionMode, SeekNowCollector, collect_with_credential, plan_selector,
};
use huntsman_recon::source_outcome::SourceOutcomeKind;

struct ScriptedTransport {
    responses: RefCell<VecDeque<Response>>,
    seen: RefCell<Vec<Request>>,
}

impl ScriptedTransport {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: RefCell::new(responses.into()),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn request_count(&self) -> usize {
        self.seen.borrow().len()
    }
}

impl Transport for ScriptedTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        Ok(self
            .responses
            .borrow_mut()
            .pop_front()
            .expect("scripted response"))
    }
}

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

fn credential() -> Credential {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "seeknow".into(),
        credential_slot: KEY_SLOT.into(),
        approved_at_unix: 1,
        approval_provenance: "collector-test".into(),
    })
    .unwrap();
    Credential::new(
        authority,
        Secret::new("seek-collector-test-secret").unwrap(),
        AuthStyle::Header("X-API-Key".into()),
    )
    .unwrap()
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
        (EntityKind::Person, "Alice Example", None),
    ];
    for (kind, value, expected_type) in cases {
        let plan = plan_selector(&selector(kind, value), &CollectionLimits::default()).unwrap();
        assert_eq!(plan.query_type.api_value(), expected_type);
        assert!(!plan.query.trim().is_empty());
    }

    assert!(plan_selector(&selector(EntityKind::Url, "https://example.com"), &CollectionLimits::default()).is_err());
    assert!(plan_selector(&selector(EntityKind::Person, "A"), &CollectionLimits::default()).is_err());
    assert!(SeekNowCollector.accepts(&EntityKind::Email));
    assert!(!SeekNowCollector.accepts(&EntityKind::Url));
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
    assert_eq!(batch.receipts[0].outcome.kind, SourceOutcomeKind::AuthRejected);
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
    assert!(entity.evidence.iter().all(|e| e.provenance.source == "seeknow"));
    assert_eq!(entity.evidence.len(), 2);
    for evidence in &entity.evidence {
        assert_eq!(Lineage::of(evidence).family(), Some("dataset a"));
        let rendered = serde_json::to_string(evidence).unwrap();
        assert!(!rendered.contains("raw-secret"));
        assert!(!rendered.contains("other-secret"));
    }
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
