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

use seeknow_doubles::{ScriptedTransport, credential_with, response, response_with};

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
fn incomplete_search_rows_propagate_to_collector_receipts() {
    for (body, expected_incomplete) in [
        (
            r#"{"success":true,"data":[{"email":"alice@example.com","dbname":"Dataset A"},null,7]}"#,
            true,
        ),
        (
            r#"{"success":true,"data":[{"email":"alice@example.com","dbname":"Dataset A"}]}"#,
            false,
        ),
    ] {
        let transport = ScriptedTransport::new(vec![response(200, body)]);
        let batch = collect_with_credential(
            &selector(EntityKind::Email, "alice@example.com"),
            &transport,
            &credential(),
            &CollectionLimits::default(),
            SeekNowCollectionMode::FastOnly,
            13,
        )
        .unwrap();

        assert_eq!(transport.request_count(), 1, "{body}");
        assert_eq!(batch.outcome, CollectionOutcome::Success, "{body}");
        assert_eq!(batch.receipts.len(), 1, "{body}");
        assert_eq!(batch.receipts[0].parsed_rows, 1, "{body}");
        assert_eq!(
            batch.receipts[0].outcome.kind,
            SourceOutcomeKind::Success,
            "{body}"
        );
        assert_eq!(batch.receipts[0].truncated, expected_incomplete, "{body}");
        assert!(batch.receipts[0].response_sha256.is_some(), "{body}");
        assert!(!batch.entities.is_empty(), "{body}");
    }
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
    assert_eq!(
        evidence.attributes["provider_field.secretary"],
        "Jane Citizen"
    );
    assert_eq!(evidence.attributes["provider_field.session_count"], "5");
    assert_eq!(
        evidence.attributes["provider_field.tokenomics"],
        "published analysis"
    );
    assert_eq!(
        evidence.attributes["provider_field.email"],
        "alice@example.com"
    );
    assert!(
        !evidence
            .attributes
            .contains_key("provider_field.accessToken")
    );
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
            {"email":"alice@example.com","username":"overflow","dbname":"Dataset A","record_id":"r3"}
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
    // Every row observes alice; the capped `overflow` handle is never added.
    assert_eq!(batch.entities[0].evidence.len(), 3);
    assert!(!batch.entities.iter().any(|e| e.value == "overflow"));
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

fn quota_headers(remaining: u64) -> Vec<(String, String)> {
    vec![
        ("x-ratelimit-limit".to_owned(), "20".to_owned()),
        ("x-ratelimit-remaining".to_owned(), remaining.to_string()),
        ("x-ratelimit-reset".to_owned(), "1793700000".to_owned()),
    ]
}

#[test]
fn an_exhausted_quota_on_the_fast_zero_never_sends_the_stealer_request() {
    let transport = ScriptedTransport::new(vec![response_with(
        200,
        r#"{"success":true,"data":[]}"#,
        quota_headers(0),
        false,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        30,
    )
    .unwrap();
    // One credit-spending request only: the provider said none were left.
    assert_eq!(transport.request_count(), 1);
    assert_eq!(batch.receipts.len(), 1);
    assert_eq!(batch.outcome, CollectionOutcome::ValidZero);
    let quota = batch.receipts[0].quota.as_ref().expect("quota recorded");
    assert_eq!(quota.remaining, Some(0));
    assert_eq!(quota.limit, Some(20));
    assert_eq!(quota.reset.as_deref(), Some("1793700000"));
}

#[test]
fn quota_left_on_the_fast_zero_still_escalates_and_both_receipts_keep_it() {
    let transport = ScriptedTransport::new(vec![
        response_with(
            200,
            r#"{"success":true,"data":[]}"#,
            quota_headers(5),
            false,
        ),
        response_with(
            200,
            r#"{"success":true,"data":[{"username":"alice","breach":"Breach B"}]}"#,
            quota_headers(4),
            false,
        ),
    ]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        31,
    )
    .unwrap();
    assert_eq!(transport.request_count(), 2);
    assert_eq!(batch.outcome, CollectionOutcome::Success);
    let left: Vec<Option<u64>> = batch
        .receipts
        .iter()
        .map(|r| r.quota.as_ref().and_then(|q| q.remaining))
        .collect();
    assert_eq!(left, [Some(5), Some(4)]);
}

#[test]
fn a_response_without_quota_headers_records_no_quota() {
    let transport = ScriptedTransport::new(vec![
        response(200, r#"{"success":true,"data":[]}"#),
        response(200, r#"{"success":true,"data":[]}"#),
    ]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        32,
    )
    .unwrap();
    // No header is never read as an exhausted quota: escalation proceeds as before.
    assert_eq!(transport.request_count(), 2);
    assert!(batch.receipts.iter().all(|r| r.quota.is_none()));
}

#[test]
fn every_row_names_the_endpoint_query_and_response_it_came_from() {
    let deep_body = r#"{"success":true,"data":[{"username":"alice","breach":"Breach B"}]}"#;
    let transport = ScriptedTransport::new(vec![
        response(200, r#"{"success":true,"data":[]}"#),
        response(200, deep_body),
    ]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        33,
    )
    .unwrap();
    let deep_digest = batch.receipts[1]
        .response_sha256
        .clone()
        .expect("deep response digest");
    let evidence: Vec<_> = batch
        .entities
        .iter()
        .flat_map(|entity| entity.evidence.iter())
        .filter(|ev| ev.provenance.source == "seeknow")
        .collect();
    assert!(!evidence.is_empty(), "{:#?}", batch.entities);
    for ev in evidence {
        let attr = |key: &str| ev.attributes.get(key).map(String::as_str);
        // The row came from the stealer escalation, not the fast search that returned zero.
        assert_eq!(attr("endpoint"), Some("seeknow_stealer"));
        assert_eq!(attr("query_type"), Some("username"));
        assert_eq!(attr("query"), Some("alice"));
        assert_eq!(attr("row_index"), Some("0"));
        assert_eq!(attr("response_sha256"), Some(deep_digest.as_str()));
    }
}

#[test]
fn one_remaining_credit_is_insufficient_for_two_credit_deep_search() {
    let transport = ScriptedTransport::new(vec![response_with(
        200,
        r#"{"success":true,"data":[]}"#,
        quota_headers(1),
        false,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        33,
    )
    .unwrap();
    assert_eq!(transport.request_count(), 1);
    assert_eq!(batch.outcome, CollectionOutcome::ValidZero);
    assert_eq!(batch.receipts.len(), 1);
    assert_eq!(batch.receipts[0].quota.as_ref().unwrap().remaining, Some(1));
}

#[test]
fn exactly_two_remaining_credits_allow_adaptive_deep_search() {
    let transport = ScriptedTransport::new(vec![
        response_with(
            200,
            r#"{"success":true,"data":[]}"#,
            quota_headers(2),
            false,
        ),
        response_with(
            200,
            r#"{"success":true,"data":[]}"#,
            quota_headers(0),
            false,
        ),
    ]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "alice"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::Adaptive,
        34,
    )
    .unwrap();
    assert_eq!(transport.request_count(), 2);
    assert_eq!(batch.receipts.len(), 2);
    assert_eq!(batch.outcome, CollectionOutcome::ValidZero);
    assert_eq!(batch.receipts[0].quota.as_ref().unwrap().remaining, Some(2));
    assert_eq!(batch.receipts[1].quota.as_ref().unwrap().remaining, Some(0));
}

/// A full-text breach search for the handle "dubai" answers with rows where the word is only a
/// city: those rows are strangers and attribute nothing; the row whose handle is the query is kept.
#[test]
fn rows_that_match_the_query_only_outside_its_kind_attribute_nothing() {
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[
            {"field_2":"stranger.one","email":"stranger.one@example.com","field_4":"Dubai","dbname":"Dataset A"},
            {"pseudo":"Dubai","email":"owner@example.com","dbname":"Dataset B"},
            {"username":"someone_else","field_5":"dubai","dbname":"Dataset C"}
        ]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Username, "dubai"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::FastOnly,
        32,
    )
    .unwrap();
    let values: Vec<&str> = batch.entities.iter().map(|e| e.value.as_str()).collect();
    assert!(values.contains(&"owner@example.com"), "{values:?}");
    for stranger in ["stranger.one@example.com", "someone_else"] {
        assert!(
            !values.iter().any(|v| v.eq_ignore_ascii_case(stranger)),
            "{values:?}"
        );
        assert!(
            !batch
                .pivots
                .iter()
                .any(|p| p.value.eq_ignore_ascii_case(stranger)),
            "a stranger is never a pivot"
        );
    }
    let detail = batch.receipts[0].outcome.detail.clone().unwrap_or_default();
    assert!(
        detail.contains("2 of 3 rows matched the query outside a username field"),
        "{detail}"
    );
}

/// A domain is named by a stealer row's URL or email on that domain or a subdomain, never by an
/// unrelated host that merely contains the word.
#[test]
fn a_domain_is_named_by_hosts_on_it_and_not_by_lookalikes() {
    let transport = ScriptedTransport::new(vec![response(
        200,
        r#"{"success":true,"data":[
            {"url":"https://login.example.com/auth","username":"keptbyurl","dbname":"Dataset A"},
            {"email":"staff@example.com","username":"keptbyemail","dbname":"Dataset A"},
            {"url":"https://example.com.evil.test/","username":"lookalike","dbname":"Dataset A"}
        ]}"#,
    )]);
    let batch = collect_with_credential(
        &selector(EntityKind::Domain, "example.com"),
        &transport,
        &credential(),
        &CollectionLimits::default(),
        SeekNowCollectionMode::FastOnly,
        32,
    )
    .unwrap();
    let values: Vec<&str> = batch.entities.iter().map(|e| e.value.as_str()).collect();
    assert!(
        values.contains(&"keptbyurl") && values.contains(&"keptbyemail"),
        "{values:?}"
    );
    assert!(!values.contains(&"lookalike"), "{values:?}");
}

/// A synthetic bulk export shaped like the file `SeekNow`'s web app downloads: two spellings of
/// one handle, a block for another handle, a credential column and a provider total above the
/// rows exported.
const BULK_EXPORT: &str = r#"{
  "id":"test-export","createdAt":"2026-11-07T00:00:00Z","format":"json","status":"done",
  "targets":["Dubai","dubai","example_handle"],
  "results":[
    {"target":"Dubai","type":"username","total":3,"sources":2,"breaches":3,"stealers":0,"intel":0,"rows":[
      {"_source":"Dataset A","pseudo":"dubai","email":"owner@example.com","password":"hunter2-secret","_line":"7"},
      {"_source":"Dataset B","field_4":"Dubai","email":"stranger@example.com"}
    ]},
    {"target":"dubai","type":"username","total":3,"rows":[
      {"_source":"Dataset A","pseudo":"dubai","email":"owner@example.com"}
    ]},
    {"target":"example_handle","type":"username","total":0,"rows":[]}
  ]
}"#;

#[test]
fn a_bulk_export_imports_offline_through_the_live_row_rules() {
    use huntsman_recon::seeknow::{is_bulk_export, parse_bulk_export};
    use huntsman_recon::seeknow_collector::{EXPORT_MODULE, collect_from_export};
    assert!(is_bulk_export(BULK_EXPORT.as_bytes()));
    assert!(!is_bulk_export(br#"{"success":true,"data":[]}"#));
    let export = parse_bulk_export(BULK_EXPORT.as_bytes()).expect("export");
    assert_eq!(export.results.len(), 3);
    let import = collect_from_export(&export, &CollectionLimits::default(), 1);

    // Both spellings are independent export blocks: no source record may be skipped.
    // Entities with the same canonical identity are still merged after attribution.
    assert_eq!(import.outcomes.len(), 3, "{:?}", import.outcomes);
    assert!(import.outcomes.iter().all(|o| o.module == EXPORT_MODULE));
    let first = import.outcomes[0].detail.clone().unwrap_or_default();
    assert!(first.contains("bulk export test-export sha256 "), "{first}");
    assert!(
        first.contains("1 of 2 rows matched the query outside a username field"),
        "{first}"
    );
    assert!(
        first.contains("the provider reported 3 rows; the export holds 2"),
        "{first}"
    );
    assert_eq!(import.outcomes[1].kind, SourceOutcomeKind::Success);
    assert_eq!(import.outcomes[2].kind, SourceOutcomeKind::ValidZero);

    let values: Vec<&str> = import.entities.iter().map(|e| e.value.as_str()).collect();
    assert!(values.contains(&"owner@example.com"), "{values:?}");
    // A stranger's row is not ATTRIBUTED to the target (not an entity)...
    assert!(!values.contains(&"stranger@example.com"), "{values:?}");
    // ...but every row is PRESERVED as a record: the two Dubai rows plus the repeated-target
    // block's row = 3 rows kept, the stranger row among them with its fields verbatim.
    assert_eq!(import.records.len(), 3, "every row preserved");
    let records = serde_json::to_string(&import.records).expect("json");
    assert!(
        records.contains("stranger@example.com"),
        "stranger row preserved: {records}"
    );
    assert!(records.contains("owner@example.com"));
    assert!(records.contains("Dataset A") && records.contains("_line"));
    // The credential VALUE is masked everywhere; the field is named as present, never silent.
    let saved = serde_json::to_string(&import.entities).expect("json");
    for blob in [&saved, &records] {
        assert!(
            !blob.contains("hunter2-secret"),
            "credential value never emitted"
        );
    }
    assert!(
        records.contains("password"),
        "the masked field is named in sensitive_fields"
    );
    assert!(saved.contains("sensitive_fields_present"));
    assert!(saved.contains("provider_field._line"));
}

#[test]
fn a_bulk_export_with_an_unknown_type_or_no_target_is_refused_whole() {
    use huntsman_recon::seeknow::parse_bulk_export;
    for bad in [
        r#"{"results":[{"target":"x","type":"telepathy","rows":[]}]}"#,
        r#"{"results":[{"target":"  ","type":"username","rows":[]}]}"#,
        r#"{"rows":[]}"#,
        "not json",
    ] {
        assert!(parse_bulk_export(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn incomplete_empty_bulk_blocks_cannot_claim_valid_zero() {
    use huntsman_recon::seeknow::parse_bulk_export;
    use huntsman_recon::seeknow_collector::collect_from_export;

    // A missing or wrongly typed rows array is not evidence of absence.
    for malformed in [
        r#"{"results":[{"target":"sample_handle","type":"username","total":4}]}"#,
        r#"{"results":[{"target":"sample_handle","type":"username","rows":{}}]}"#,
    ] {
        assert!(parse_bulk_export(malformed.as_bytes()).is_err());
    }

    let input = r#"{"results":[
        {"target":"sample_handle","type":"username","total":4,"rows":[]},
        {"target":"other_handle","type":"username","total":0,"rows":[]},
        {"target":"third_handle","type":"username","total":0,"rows":[null]}
    ]}"#;
    let export = parse_bulk_export(input.as_bytes()).expect("valid export envelope");
    let import = collect_from_export(&export, &CollectionLimits::default(), 1);
    assert_eq!(import.outcomes.len(), 3);
    assert_eq!(import.outcomes[0].kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(import.outcomes[1].kind, SourceOutcomeKind::ValidZero);
    assert_eq!(import.outcomes[2].kind, SourceOutcomeKind::Inconclusive);
    for index in [0, 2] {
        let detail = import.outcomes[index].detail.as_deref().unwrap_or_default();
        assert!(detail.contains("cannot establish a valid zero"), "{detail}");
    }
}
