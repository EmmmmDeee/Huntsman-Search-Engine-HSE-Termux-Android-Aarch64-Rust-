use super::*;

#[test]
fn accepts_username_only() {
    let m = Keybase;
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(Keybase.name(), "keybase");
    assert_eq!(Keybase.priority(), 100);
    assert_eq!(Keybase.max_timeout_ms(), 4_000);
    assert!(!Keybase.description().is_empty());
}

#[test]
fn parse_response() {
    let raw = r#"{
        "status": {"code": 0, "name": "OK"},
        "them": [{
            "id": "abc123",
            "basics": {"username": "alice", "ctime": 1500000000},
            "profile": {"full_name": "Alice Smith", "location": "Sydney, AU", "bio": "dev"},
            "proofs_summary": {
                "all": [
                    {"proof_type": "twitter", "nametag": "alice_s", "state": 1},
                    {"proof_type": "github", "nametag": "alicesmith", "state": 1},
                    {"proof_type": "dns", "nametag": "alice.dev", "state": 1}
                ]
            }
        }]
    }"#;
    let r: KbResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.status.unwrap().code, Some(0));
    let user = &r.them.unwrap()[0];
    assert_eq!(
        user.basics.as_ref().unwrap().username.as_deref(),
        Some("alice")
    );
    assert_eq!(
        user.profile.as_ref().unwrap().full_name.as_deref(),
        Some("Alice Smith")
    );
    assert_eq!(user.proofs_summary.as_ref().unwrap().all.len(), 3);
}

#[test]
fn extract_proofs_maps_verified_links_and_urls() {
    // Shape captured from the live keybase.io lookup for `chris`.
    let proofs: Vec<KbProof> = serde_json::from_str(
        r#"[
            {"proof_type":"twitter","nametag":"malgorithms","state":1,"service_url":"https://twitter.com/malgorithms"},
            {"proof_type":"github","nametag":"malgorithms","state":1,"service_url":"https://github.com/malgorithms"},
            {"proof_type":"gitlab","nametag":"mal","state":1,"service_url":"https://gitlab.com/mal"},
            {"proof_type":"dns","nametag":"chriscoyne.com","state":1,"service_url":"http://chriscoyne.com"},
            {"proof_type":"twitter","nametag":"revoked","state":2,"service_url":"https://twitter.com/revoked"}
        ]"#,
    )
    .unwrap();
    let mut r = ModuleResult::new();
    extract_proofs(&proofs, "chris", "scan", &mut r);
    let has = |k: EntityKind, v: &str| r.entities.iter().any(|e| e.kind == k && e.value == v);

    // Cross-platform handles (incl. the newly-supported gitlab).
    assert!(has(EntityKind::Username, "malgorithms"));
    assert!(
        has(EntityKind::Username, "mal"),
        "gitlab proof now supported"
    );
    // Verified service_url surfaced as a first-class profile link.
    assert!(has(EntityKind::Url, "https://github.com/malgorithms"));
    // DNS proof → owned domain.
    assert!(has(EntityKind::Domain, "chriscoyne.com"));
    // Revoked (state != 1) proof dropped entirely.
    assert!(!has(EntityKind::Username, "revoked"));
    assert!(!has(EntityKind::Url, "https://twitter.com/revoked"));
    // Verified handles carry the `verified` tag.
    let gh = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "malgorithms")
        .unwrap();
    assert!(gh.has_tag("verified") && gh.has_tag("keybase"));
}
