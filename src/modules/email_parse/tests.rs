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
async fn skips_noncentral_provider_domains_beyond_freemail() {
    // ISP webmail (rr.com), regional providers (web.de) and data brokers
    // (peekyou.com) are caught by the authoritative is_noncentral_domain set but
    // not the narrower freemail list. They must NOT become standalone Domain
    // entities — they are the haystack a mention sits in, not the subject's asset.
    // (Regression for the CRITICAL infrastructure-pollution an on-device scan hit.)
    for addr in ["user@web.de", "user@rochester.rr.com", "user@peekyou.com"] {
        let t = Target::new(TargetKind::Email, addr);
        let r = EmailParse.process(&t, &ctx()).await.unwrap();
        let domains: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .collect();
        assert!(domains.is_empty(), "should skip noncentral domain: {addr}");
    }
    // A genuine corporate/self-owned mail domain is still surfaced.
    let t = Target::new(TargetKind::Email, "jane@acmecorp.com.au");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "acmecorp.com.au"),
        "a real corporate domain must still be emitted"
    );
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

#[tokio::test]
async fn username_candidates_emerge_in_deterministic_sorted_order() {
    // A two-token corporate local part exercises every derivation branch
    // (detag, strip, collapse, split, initial-blend) so the candidate
    // HashSet holds several entries — enough that an unsorted iteration
    // would very likely disagree with the sorted order across the HashSet's
    // randomised per-process seed.
    let t = Target::new(TargetKind::Email, "john.doe+work42@example.com");
    let r = EmailParse.process(&t, &ctx()).await.unwrap();
    let usernames: Vec<&str> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    let mut sorted = usernames.clone();
    sorted.sort_unstable();
    assert_eq!(
        usernames, sorted,
        "username candidates must emerge in sorted, deterministic order"
    );
    assert!(usernames.len() > 1, "expected multiple derived candidates");
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
    // A role mailbox (`admin@`, `dns@`, `noreply@`) is not a person's handle: it
    // must never seed a Username/Person (the `dns@cloudflare.com` → VERIFIED
    // username `dns` bug).
    for addr in ["admin@corp.io", "dns@cloudflare.com", "noreply@example.org"] {
        let r = EmailParse
            .process(&Target::new(TargetKind::Email, addr), &ctx())
            .await
            .unwrap();
        assert!(
            !r.entities
                .iter()
                .any(|e| matches!(e.kind, EntityKind::Username | EntityKind::Person)),
            "{addr}: role mailbox must not seed a Username/Person"
        );
    }
    // The Domain is still emitted for a real corporate host, but a role mailbox at
    // a shared-infrastructure provider (cloudflare.com) yields no Domain entity —
    // it is the provider's estate, not the subject's (is_noncentral_domain gate).
    let corp = EmailParse
        .process(&Target::new(TargetKind::Email, "admin@corp.io"), &ctx())
        .await
        .unwrap();
    assert!(
        corp.entities.iter().any(|e| e.kind == EntityKind::Domain),
        "a real corporate domain (corp.io) is still extracted"
    );
    let infra = EmailParse
        .process(
            &Target::new(TargetKind::Email, "dns@cloudflare.com"),
            &ctx(),
        )
        .await
        .unwrap();
    assert!(
        !infra.entities.iter().any(|e| e.kind == EntityKind::Domain),
        "a shared-infrastructure host (cloudflare.com) must be suppressed"
    );
    use crate::util::domains::is_role_localpart;
    assert!(is_role_localpart("dns") && is_role_localpart("no-reply"));
    assert!(!is_role_localpart("jane.doe") && !is_role_localpart("jordanavery"));
}

#[tokio::test]
async fn isp_freemail_infers_person_at_lower_confidence() {
    // R9-1: freemail firstname.lastname now infers a Person at 0.45 (lower than
    // corporate 0.55) tagged `freemail-inferred`. This enables candidates like
    // ryne.manka@gmail.com → Person "Ryne Manka" to be surfaced for corroboration.
    // Usernames remain at 0.55 for freemail; corporate stays at 0.70.
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
        let persons: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Person)
            .collect();
        assert_eq!(
            persons.len(),
            1,
            "{addr}: freemail firstname.lastname should infer a Person"
        );
        assert_eq!(persons[0].value, "John Doe", "{addr}: wrong person name");
        assert!(
            (persons[0].confidence - 0.45).abs() < 1e-9,
            "{addr}: freemail Person confidence should be 0.45, got {}",
            persons[0].confidence
        );
        assert!(
            persons[0].has_tag("freemail-inferred"),
            "{addr}: Person should carry freemail-inferred tag"
        );
        for e in r.entities.iter().filter(|e| e.kind == EntityKind::Username) {
            assert!(
                (e.confidence - 0.55).abs() < 1e-9,
                "{addr}: freemail username confidence should be 0.55, got {}",
                e.confidence
            );
        }
    }

    // A genuine corporate domain still infers the Person at 0.55 (no freemail tag).
    let r = EmailParse
        .process(
            &Target::new(TargetKind::Email, "john.doe@acme-corp.com"),
            &ctx(),
        )
        .await
        .unwrap();
    let corp_person = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("corporate address should infer a Person");
    assert_eq!(corp_person.value, "John Doe");
    assert!(
        (corp_person.confidence - 0.55).abs() < 1e-9,
        "corporate Person confidence should be 0.55"
    );
    assert!(
        !corp_person.has_tag("freemail-inferred"),
        "corporate Person must not carry freemail-inferred tag"
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

// ── capitalise ────────────────────────────────────────────────────────────────

#[test]
fn capitalise_uppercases_first_char() {
    assert_eq!(capitalise("john"), "John");
    assert_eq!(capitalise("jane doe"), "Jane doe");
}

#[test]
fn capitalise_empty_string_returns_empty() {
    assert_eq!(capitalise(""), "");
}

#[test]
fn capitalise_preserves_already_uppercase_first_char() {
    assert_eq!(capitalise("Alice"), "Alice");
}

#[test]
fn capitalise_handles_multibyte_first_char() {
    assert_eq!(capitalise("ñoño"), "Ñoño");
}
