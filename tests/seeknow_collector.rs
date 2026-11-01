use huntsman_recon::collector::{CollectionLimits, CollectionOutcome};
use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::fetch::Credential;
use huntsman_recon::keys::Keys;
use huntsman_recon::lineage::Lineage;
use huntsman_recon::seeknow_collector::{
    SeekNowCollectionMode, SeekNowCollector, collect_for_lookup, collect_with_credential,
    plan_selector,
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

    // A 200 that says `success: false` is not a validated zero, so no deep credit is spent.
    let refused = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":false,"error":"search backend unavailable","data":[]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "alice@example.com"),
        &refused,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        12,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::Failed);
    assert_eq!(refused.request_count(), 1);
    assert_eq!(
        batch.receipts[0].outcome.kind,
        SourceOutcomeKind::Inconclusive
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
fn safe_provider_fields_survive_collection_into_saved_evidence() {
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[{
            "email":"alice@example.com",
            "source":"Dataset One",
            "secretary":"Jane Citizen",
            "session_count":5,
            "tokenomics":"published analysis",
            "accessToken":"must-not-survive-credential"
        }]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "alice@example.com"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::FastOnly,
        42,
    )
    .unwrap();
    assert_eq!(batch.outcome, CollectionOutcome::Success);
    let evidence = &batch.entities[0].evidence[0];
    assert_eq!(evidence.attributes["source"], "Dataset One");
    assert_eq!(evidence.attributes["provider_field.secretary"], "Jane Citizen");
    assert_eq!(evidence.attributes["provider_field.session_count"], "5");
    assert_eq!(
        evidence.attributes["provider_field.tokenomics"],
        "published analysis"
    );
    assert_eq!(
        evidence.attributes["provider_field.email"],
        "alice@example.com"
    );
    assert!(!evidence.attributes.contains_key("provider_field.accessToken"));
    assert!(evidence.attributes["sensitive_fields_present"].contains("accessToken"));
    let serialized = serde_json::to_string(evidence).unwrap();
    assert!(serialized.contains("Jane Citizen"));
    assert!(!serialized.contains("must-not-survive-credential"));
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

#[test]
fn enumerated_contact_fields_are_mapped_not_dropped() {
    // One SeekNow record often packs several contacts under enumerated keys
    // (`email_1`, `name_2`, `phone_1`). Each must become its own entity; before the
    // index was stripped they were silently dropped.
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[
            {"dbname":"Dataset A","email_1":"alice@example.com","name_1":"Alice Roe","email_2":"alice.alt@example.net","phone_1":"+15125550143"}
        ]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Person, "Alice Roe"),
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
        .map(|entity| entity.value.as_str())
        .collect();
    assert!(emails.contains(&"alice@example.com"), "{emails:?}");
    assert!(emails.contains(&"alice.alt@example.net"), "{emails:?}");
    assert!(
        batch
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Phone)
    );
    assert!(
        batch
            .entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Person && entity.value == "alice roe")
    );
}

#[test]
fn record_with_only_enumerated_identifiers_still_yields_entities() {
    // A record whose only identifier keys are enumerated (`email_1`+`email_2`) produced
    // zero entities before the fix; it must now yield both addresses.
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[
            {"email_1":"first@example.com","email_2":"second@example.org"}
        ]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "first@example.com"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::FastOnly,
        30,
    )
    .unwrap();
    let emails: Vec<_> = batch
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Email)
        .map(|entity| entity.value.as_str())
        .collect();
    assert_eq!(emails.len(), 2, "{emails:?}");
    assert!(emails.contains(&"first@example.com"));
    assert!(emails.contains(&"second@example.org"));
}

#[test]
fn non_identifier_numeric_suffixed_fields_stay_unmapped() {
    // Stripping the numeric index must not turn unrelated enumerated keys into entities:
    // `id_1`, `postal_code`, and a bare `email_address` boundary case stay correct.
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[
            {"email_address":"edge@example.com","id_1":"998877","postal_code_11_characters":"12345678901"}
        ]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Email, "edge@example.com"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::FastOnly,
        30,
    )
    .unwrap();
    let kinds: Vec<_> = batch.entities.iter().map(|entity| &entity.kind).collect();
    assert!(kinds.contains(&&EntityKind::Email));
    assert!(!batch.entities.iter().any(|entity| entity.value == "998877"));
    assert!(
        !batch
            .entities
            .iter()
            .any(|entity| entity.value == "12345678901")
    );
}

fn keyed() -> Keys {
    Keys::parse("HUNTSMAN_SEEKNOW_KEY=dummy-seeknow-key-for-tests\n").unwrap()
}

#[test]
fn collect_for_lookup_without_key_makes_no_request_and_says_so() {
    // A lookup with no SeekNow key sends nothing, and its report carries the one row that says
    // the leg was asked and skipped for lack of a key, as every other keyed leg leaves.
    let transport = ScriptedTransport::new(Vec::new());
    let leg = collect_for_lookup(
        &transport,
        EntityKind::Email,
        "alice@example.com",
        &Keys::default(),
        30,
    )
    .expect("the skipped leg is reported");
    assert!(leg.entities.is_empty(), "{:?}", leg.entities);
    assert_eq!(leg.outcomes.len(), 1);
    assert_eq!(leg.outcomes[0].module, "seeknow");
    assert_eq!(leg.outcomes[0].kind, SourceOutcomeKind::NotConfigured);
    assert_eq!(
        leg.outcomes[0].detail.as_deref(),
        Some("no operator key configured; no request made")
    );
    assert_eq!(transport.request_count(), 0);
}

#[test]
fn collect_for_lookup_rejects_unsupported_kind_without_request() {
    // A kind SeekNow does not accept yields None even with a key set, and sends nothing.
    let transport = ScriptedTransport::new(Vec::new());
    let leg = collect_for_lookup(
        &transport,
        EntityKind::Coordinates,
        "-37.8,144.9",
        &keyed(),
        30,
    );
    assert!(leg.is_none());
    assert_eq!(transport.request_count(), 0);
}

#[test]
fn collect_for_lookup_with_key_runs_and_returns_entities_and_outcome() {
    // With the key set the leg always runs, returns the response entities, and records at
    // least one source outcome for the report.
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[{"email":"found@example.com","dbname":"Dataset A"}]}"#,
    )]);
    let leg = collect_for_lookup(
        &transport,
        EntityKind::Email,
        "found@example.com",
        &keyed(),
        30,
    )
    .expect("key configured runs the leg");
    assert!(transport.request_count() >= 1);
    assert!(
        leg.entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Email && entity.value == "found@example.com")
    );
    let outcome_count = leg.outcomes.len();
    assert!(
        outcome_count >= 1,
        "keyed SeekNow records at least one source outcome"
    );
}

#[test]
fn collect_for_lookup_over_a_blocked_egress_is_refused_before_sending() {
    // A blocked egress sends nothing, so the SeekNow leg records a refusal-before-sending row,
    // not the inconclusive "execution failed" it used to read as.
    struct Blocked;
    impl huntsman_recon::http::Transport for Blocked {
        fn send(
            &self,
            _: &huntsman_recon::http::Request,
        ) -> Result<huntsman_recon::http::Response, huntsman_recon::http::TransportFailure>
        {
            Err(huntsman_recon::http::TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "egress-policy: destination (0.0.0.0) is not publicly routable".into(),
                blocked: true,
            })
        }
    }
    let leg = collect_for_lookup(&Blocked, EntityKind::Email, "ada@example.com", &keyed(), 1)
        .expect("a configured, accepted selector runs the leg");
    assert_eq!(leg.outcomes.len(), 1);
    let row = &leg.outcomes[0];
    assert_eq!(row.kind, SourceOutcomeKind::RefusedBeforeSending);
    assert!(
        row.reason()
            .starts_with("seeknow: request refused before sending"),
        "{}",
        row.reason()
    );
}

#[test]
fn collect_for_lookup_runs_person_scan_selector() {
    // The headline `scan NAME` path routes to ScanKind::People, which maps to EntityKind::Person.
    // With the key set that selector must run SeekNow like email and username, not sit dead.
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[{"name":"Alice Example","dbname":"Dataset A"}]}"#,
    )]);
    let leg = collect_for_lookup(
        &transport,
        EntityKind::Person,
        "Alice Example",
        &keyed(),
        30,
    )
    .expect("person scan with a key runs the leg");
    assert!(transport.request_count() >= 1);
    assert!(
        leg.entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Person)
    );
    let outcome_count = leg.outcomes.len();
    assert!(
        outcome_count >= 1,
        "keyed SeekNow records at least one source outcome"
    );
}

#[test]
fn a_handle_is_asked_for_as_it_was_written_never_by_its_identity_key() {
    // `john.doe_99` and `johndoe99` are one entity but two handles: the leg asks for the one the
    // lookup was given, never the separator-free identity key, which names another account.
    let limits = CollectionLimits::default();
    let plan = plan_selector(&selector(EntityKind::Username, "@John.Doe_99"), &limits).unwrap();
    assert_eq!(plan.query, "John.Doe_99");
    // Every other kind is asked for by its canonical value, which loses nothing SeekNow reads.
    let plan = plan_selector(&selector(EntityKind::Email, "Alice@Example.COM"), &limits).unwrap();
    assert_eq!(plan.query, "alice@example.com");
    // The lookup leg sends that spelling in every request it makes, and an answer that echoes the
    // handle in another case is the handle itself, not a pivot from it.
    let transport = ScriptedTransport::new(vec![
        response(200, r#"{"success":true,"data":[]}"#),
        response(
            200,
            r#"{"success":true,"data":[{"username":"JOHN.DOE_99","breach":"Breach C"}]}"#,
        ),
    ]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "john.doe_99"),
        &transport,
        &credential(),
        &limits,
        SeekNowCollectionMode::Adaptive,
        22,
    )
    .unwrap();
    let sent: Vec<String> = transport
        .seen
        .borrow()
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect();
    assert_eq!(sent.len(), 2, "{sent:?}");
    for body in &sent {
        assert!(body.contains(r#""query":"john.doe_99""#), "{body}");
        assert!(!body.contains("johndoe99"), "{body}");
    }
    assert!(batch.pivots.is_empty(), "{:?}", batch.pivots);
}
