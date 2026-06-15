use super::*;
use std::collections::HashMap;

fn ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "t".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: HashMap::default(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        response_sink: None,
    }
}

// ── Tests from email_to_domain ─────────────────────────────────────

#[tokio::test]
async fn extracts_corporate_domain() {
    let t = Target::new(TargetKind::Email, "ceo@acme.com");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    let domains: Vec<&Entity> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .collect();
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].value, "acme.com");
    assert!(domains[0].has_tag("derived"));
    assert!(domains[0].has_tag("email-domain"));
}

#[tokio::test]
async fn skips_freemail_providers() {
    for addr in ["user@gmail.com", "user@yahoo.com", "user@protonmail.com"] {
        let t = Target::new(TargetKind::Email, addr);
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        let domains: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .collect();
        assert!(domains.is_empty(), "should skip freemail domain: {addr}");
    }
}

#[tokio::test]
async fn skips_domain_for_malformed_email() {
    let t = Target::new(TargetKind::Email, "noatsign");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    let domains: Vec<&Entity> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .collect();
    assert!(domains.is_empty());
}

// ── Tests from email_to_username ───────────────────────────────────

#[tokio::test]
async fn derives_multiple_username_candidates() {
    let t = Target::new(TargetKind::Email, "john.doe+work@example.com");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    let usernames: Vec<&str> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    assert!(usernames.contains(&"john"));
    assert!(usernames.contains(&"doe"));
}

// ── Shared / merged tests ──────────────────────────────────────────

#[test]
fn is_passive() {
    assert!(EmailParse.is_passive());
}

#[test]
fn accepts_email_only() {
    assert!(EmailParse.accepts(&Target::new(TargetKind::Email, "x")));
    assert!(!EmailParse.accepts(&Target::new(TargetKind::Domain, "x")));
}

#[tokio::test]
async fn emits_both_domain_and_usernames() {
    // A personal local-part yields the Domain AND derived usernames.
    let t = Target::new(TargetKind::Email, "jane.doe@corp.io");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    let has_domain = r.entities.iter().any(|e| e.kind == EntityKind::Domain);
    let has_username = r.entities.iter().any(|e| e.kind == EntityKind::Username);
    assert!(has_domain, "should emit a Domain entity for corp.io");
    assert!(
        has_username,
        "should emit Username entities from local part"
    );
}

#[tokio::test]
async fn role_localpart_yields_domain_but_no_username_or_person() {
    // A role mailbox (`admin@`, `dns@`, `noreply@`) is not a person's handle:
    // emit the Domain, but never a Username/Person (the `dns@cloudflare.com`
    // → VERIFIED username `dns` bug).
    for addr in ["admin@corp.io", "dns@cloudflare.com", "noreply@example.org"] {
        let r = EmailParse
            .process(&Target::new(TargetKind::Email, addr), &ctx())
            .await
            .unwrap();
        assert!(
            r.entities.iter().any(|e| e.kind == EntityKind::Domain),
            "{addr}: domain still extracted"
        );
        assert!(
            !r.entities
                .iter()
                .any(|e| matches!(e.kind, EntityKind::Username | EntityKind::Person)),
            "{addr}: role mailbox must not seed a Username/Person"
        );
    }
    use crate::util::domains::is_role_localpart;
    assert!(is_role_localpart("dns") && is_role_localpart("no-reply"));
    assert!(!is_role_localpart("jane.doe") && !is_role_localpart("jordanavery"));
}

#[tokio::test]
async fn isp_freemail_outside_inline_list_infers_no_person() {
    // Regression: the username/Person step once used a stale 8-domain inline
    // freemail list, so an ISP/consumer mailbox absent from it (bigpond,
    // comcast, gmx, yandex.ru) was treated as corporate — inferring a Person
    // "John Doe" from `john.doe@…` and scoring usernames at the corporate
    // 0.70. These ARE freemail per the shared list, so: no Person, and
    // usernames at the freemail confidence (0.55).
    for addr in [
        "john.doe@bigpond.com",
        "john.doe@comcast.net",
        "john.doe@gmx.com",
        "john.doe@yandex.ru",
    ] {
        let r = EmailParse
            .process(&Target::new(TargetKind::Email, addr), &ctx())
            .await
            .unwrap();
        assert!(
            !r.entities.iter().any(|e| e.kind == EntityKind::Person),
            "{addr}: consumer mailbox must not infer a Person"
        );
        for e in r.entities.iter().filter(|e| e.kind == EntityKind::Username) {
            assert!(
                (e.confidence - 0.55).abs() < 1e-9,
                "{addr}: freemail username confidence should be 0.55, got {}",
                e.confidence
            );
        }
    }

    // A genuine corporate domain still infers the Person at 0.70 usernames.
    let r = EmailParse
        .process(
            &Target::new(TargetKind::Email, "john.doe@acme-corp.com"),
            &ctx(),
        )
        .await
        .unwrap();
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "John Doe"),
        "corporate address should still infer the Person"
    );
    assert!(
        r.entities
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .all(|e| (e.confidence - 0.70).abs() < 1e-9),
        "corporate username confidence should be 0.70"
    );
}

#[tokio::test]
async fn freemail_still_derives_usernames() {
    let t = Target::new(TargetKind::Email, "john.doe@gmail.com");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    let domains: Vec<&Entity> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .collect();
    let usernames: Vec<&str> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    assert!(domains.is_empty(), "freemail domain should be skipped");
    assert!(!usernames.is_empty(), "usernames should still be derived");
    assert!(usernames.contains(&"john"));
    assert!(usernames.contains(&"doe"));
}

#[tokio::test]
async fn evidence_source_is_email_parse() {
    let t = Target::new(TargetKind::Email, "alice@widgets.co");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    for entity in &r.entities {
        for ev in &entity.evidence {
            assert_eq!(
                ev.source, "email_parse",
                "all evidence should cite email_parse, got: {}",
                ev.source
            );
        }
    }
}
