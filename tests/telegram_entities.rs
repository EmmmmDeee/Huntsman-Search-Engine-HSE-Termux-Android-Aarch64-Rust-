use huntsman_recon::graph::RelationKind;
use huntsman_recon::telegram_intel::{TelegramRecord, correlate_with, record_entities};
use huntsman_recon::{Entity, EntityKind, Evidence, EvidenceProvenance};

fn rich_record() -> TelegramRecord {
    let mut record = TelegramRecord::new(
        -1001234567890,
        3639,
        1_700_000_000,
        "contact ada@example.com https://example.com @Ada",
    );
    record.peer_username = Some("cybdetective".into());
    record.peer_title = Some("Cyber Detective".into());
    record.sender_id = Some(42);
    record.sender_username = Some("Signal_User".into());
    record.sender_phone = Some("+61 400 111 222".into());
    record
}

#[test]
fn record_entities_are_auditable_and_relation_ready() {
    let record = rich_record();
    let uri = "telegram://peer/-1001234567890/message/3639";
    assert_eq!(record.uri(), uri);
    assert_eq!(record.public_url().as_deref(), Some("https://t.me/cybdetective/3639"));

    let (entities, relations) = record_entities(&record, "scan-tg-1");
    let document = entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Document)
        .expect("message document entity");
    assert_eq!(document.value, uri);

    let email = entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Email && entity.value == "ada@example.com")
        .expect("email extracted from message text");
    let url = entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Url && entity.value == "https://example.com/")
        .expect("URL extracted from message text");
    assert_ne!(email.uid, url.uid);

    for entity in [document, email, url] {
        let evidence = entity.evidence.first().expect("telegram evidence");
        assert_eq!(evidence.provenance.source, "telegram");
        assert_eq!(evidence.provenance.scan_id.as_deref(), Some("scan-tg-1"));
        assert_eq!(evidence.attributes.get("peer_id").map(String::as_str), Some("-1001234567890"));
        assert_eq!(evidence.attributes.get("message_id").map(String::as_str), Some("3639"));
        assert_eq!(evidence.attributes.get("telegram_uri").map(String::as_str), Some(uri));
        assert_eq!(
            evidence.attributes.get("telegram_public_url").map(String::as_str),
            Some("https://t.me/cybdetective/3639")
        );
    }

    assert!(relations.iter().any(|relation| {
        relation.from_uid == document.uid
            && relation.to_uid == email.uid
            && relation.kind == RelationKind::MentionedWith
            && relation
                .evidence
                .iter()
                .any(|evidence| evidence.provenance.source == "telegram")
    }));
}

#[test]
fn authoritative_peer_sender_and_phone_metadata_become_typed_entities() {
    let (entities, _) = record_entities(&rich_record(), "scan-tg-2");

    assert!(entities.iter().any(|entity| {
        entity.kind == EntityKind::Username && entity.value == "cybdetective"
    }));
    assert!(entities.iter().any(|entity| {
        entity.kind == EntityKind::Username && entity.value == "signal_user"
    }));
    assert!(entities.iter().any(|entity| {
        entity.kind == EntityKind::Phone && entity.value == "+61400111222"
    }));

    let peer = entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Username && entity.value == "cybdetective")
        .expect("peer username");
    assert!(peer.evidence.iter().any(|evidence| {
        evidence.attributes.get("telegram_role").map(String::as_str) == Some("peer_username")
    }));
}

#[test]
fn cross_source_duplicate_uid_is_absorbed_before_existing_correlator_runs() {
    let mut existing = Entity::new(EntityKind::Email, "ada@example.com", 0.80, "scan-old");
    existing.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("hibp", "scan-old"),
        "HIBP account observation",
    ));

    let (telegram_entities, _) = record_entities(&rich_record(), "scan-tg-3");
    let email_uid = existing.uid.clone();
    let correlations = correlate_with(
        std::slice::from_ref(&existing),
        &telegram_entities,
        "scan-merged",
        1_700_000_100,
    );

    let corroborated = correlations
        .iter()
        .find(|correlation| correlation.rule_id == "AU-003")
        .expect("existing high-corroboration rule fires after UID merge");
    assert_eq!(corroborated.scan_id, "scan-merged");
    assert_eq!(corroborated.ts, 1_700_000_100);
    assert_eq!(corroborated.entity_uids, vec![email_uid]);
}
