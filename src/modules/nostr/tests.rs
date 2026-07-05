use super::*;

/// Cross-validated vector: the hex came from the **live** NIP-05 endpoint of
/// the protocol author (`_@fiatjaf.com`); the npub was derived by an
/// independent bech32 encoder. Both agree, so this pins the codec to reality.
const NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
const HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

#[test]
fn npub_decodes_to_known_pubkey() {
    assert_eq!(decode_npub(NPUB).as_deref(), Some(HEX));
    // Case-insensitive (bech32 allows upper-case).
    assert_eq!(decode_npub(&NPUB.to_uppercase()).as_deref(), Some(HEX));
}

#[test]
fn pubkey_encodes_to_known_npub_and_round_trips() {
    assert_eq!(encode_npub(HEX).as_deref(), Some(NPUB));
    // decode ∘ encode is the identity on a real key.
    let back = decode_npub(&encode_npub(HEX).unwrap()).unwrap();
    assert_eq!(back, HEX);
}

#[test]
fn decode_npub_rejects_non_npub() {
    // A Bitcoin bech32 address shares the encoding but not the `npub` HRP.
    assert!(decode_npub("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_none());
    // A one-character mutation breaks the checksum.
    let mut bad: Vec<char> = NPUB.chars().collect();
    bad[10] = if bad[10] == 'q' { 'p' } else { 'q' };
    assert!(decode_npub(&bad.into_iter().collect::<String>()).is_none());
    // Junk / wrong shape.
    assert!(decode_npub("not-an-npub").is_none());
    assert!(decode_npub("npub1").is_none());
    assert!(decode_npub("").is_none());
}

#[test]
fn nip05_extraction_builds_full_identity() {
    let mut names = BTreeMap::new();
    names.insert("alice".to_string(), HEX.to_string());
    let mut relays = BTreeMap::new();
    relays.insert(
        HEX.to_string(),
        vec![
            "wss://relay.example.com".to_string(),
            "https://not-a-relay.example".to_string(), // dropped (not a ws scheme)
        ],
    );
    let doc = Nip05 { names, relays };

    let mut result = ModuleResult::new();
    emit_nip05("alice", "example.com", "alice@example.com", HEX, &doc, "scan", &mut result);
    let e = &result.entities;

    // Profile URL is keyed on the npub (so it converges with an npub seed).
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Url
            && x.value.eq_ignore_ascii_case(&format!("https://njump.me/{NPUB}"))
            && x.has_tag("nostr"))
    );
    // Canonical hex pubkey, as a non-dispatched Other identity.
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Other("nostr-pubkey".into())
            && x.value == HEX
            && x.has_tag("nostr-pubkey"))
    );
    // Seed email flagged as a confirmed NIP-05 identity.
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Email
            && x.value.eq_ignore_ascii_case("alice@example.com")
            && x.has_tag("nip05"))
    );
    // Local username pivot.
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Username && x.value.eq_ignore_ascii_case("alice"))
    );
    // The ws relay is surfaced; the non-ws URL is not.
    assert!(
        e.iter().any(|x| x.kind == EntityKind::Other("nostr-relay".into())
            && x.value == "wss://relay.example.com")
    );
    assert!(
        e.iter()
            .all(|x| !x.value.contains("not-a-relay")),
        "a non-ws endpoint must not be emitted as a relay"
    );
}

#[test]
fn nip05_emits_every_distinct_relay_deduped() {
    // A NIP-05 doc listing 10 distinct ws/wss relays (> the old RELAY_CAP = 8)
    // plus a case-variant duplicate of the first. The relays are the identity's
    // own self-published infrastructure — every distinct one must surface, and
    // the duplicate must fold, not double.
    let mut names = BTreeMap::new();
    names.insert("bob".to_string(), HEX.to_string());
    let mut relays = BTreeMap::new();
    let mut list: Vec<String> = (0..10).map(|i| format!("wss://relay{i}.example.com")).collect();
    // A case-variant duplicate of relay0 — must dedup to one entity.
    list.push("WSS://RELAY0.EXAMPLE.COM".to_string());
    // A non-ws endpoint that must still be filtered regardless of cap removal.
    list.push("https://not-a-relay.example".to_string());
    relays.insert(HEX.to_string(), list);
    let doc = Nip05 { names, relays };

    let mut result = ModuleResult::new();
    emit_nip05("bob", "example.com", "bob@example.com", HEX, &doc, "scan", &mut result);

    let relay_entities: Vec<&str> = result
        .entities
        .iter()
        .filter(|x| x.kind == EntityKind::Other("nostr-relay".into()))
        .map(|x| x.value.as_str())
        .collect();
    // All 10 distinct relays, not the first 8 — the duplicate folded, the
    // non-ws endpoint was filtered.
    assert_eq!(
        relay_entities.len(),
        10,
        "every distinct relay emitted, not capped at 8: {relay_entities:?}"
    );
    for i in 0..10 {
        let want = format!("wss://relay{i}.example.com");
        assert!(
            relay_entities.contains(&want.as_str()),
            "missing relay {want}: {relay_entities:?}"
        );
    }
    assert!(
        relay_entities.iter().all(|r| !r.contains("not-a-relay")),
        "a non-ws endpoint must not be emitted as a relay"
    );
}

#[test]
fn nip05_root_underscore_emits_no_username() {
    let mut names = BTreeMap::new();
    names.insert("_".to_string(), HEX.to_string());
    let doc = Nip05 {
        names,
        relays: BTreeMap::new(),
    };
    let mut result = ModuleResult::new();
    emit_nip05("_", "fiatjaf.com", "_@fiatjaf.com", HEX, &doc, "scan", &mut result);
    // The `_` root marker is not a real handle.
    assert!(
        result.entities.iter().all(|x| x.kind != EntityKind::Username),
        "the `_` root identifier must not become a username"
    );
    // But the identity and email confirmation are still emitted.
    assert!(
        result
            .entities
            .iter()
            .any(|x| x.kind == EntityKind::Email && x.has_tag("nip05"))
    );
}

#[test]
fn lookup_pubkey_is_case_insensitive() {
    let mut names = BTreeMap::new();
    names.insert("Alice".to_string(), HEX.to_string());
    let doc = Nip05 {
        names,
        relays: BTreeMap::new(),
    };
    assert_eq!(lookup_pubkey(&doc, "alice"), Some(HEX));
    assert_eq!(lookup_pubkey(&doc, "Alice"), Some(HEX));
    assert_eq!(lookup_pubkey(&doc, "bob"), None);
}

#[tokio::test]
async fn process_decodes_npub_offline() {
    // Fully offline + deterministic — runs in CI (the npub path makes no
    // network call).
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = Nostr
        .process(&Target::new(TargetKind::Username, NPUB), &ctx)
        .await
        .expect("offline npub decode never errors");
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Url && e.value.eq_ignore_ascii_case(&format!("https://njump.me/{NPUB}")))
    );
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Other("nostr-pubkey".into()) && e.value == HEX)
    );
}

#[test]
fn is_free_social_module() {
    let m = Nostr;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Social);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Username, NPUB)));
    assert!(m.accepts(&Target::new(TargetKind::Email, "alice@example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Phone, "+15551234567")));
}

/// Live end-to-end proof against a REAL NIP-05 endpoint — no mock. Ignored by
/// default (network); run with
/// `cargo test -p huntsman-search-engine nostr_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live fiatjaf.com NIP-05 endpoint; run manually"]
async fn nostr_live_resolves_nip05() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let target = Target::new(TargetKind::Email, "_@fiatjaf.com");
    let r = Nostr
        .process(&target, &ctx)
        .await
        .expect("live NIP-05 must not error");
    eprintln!(
        "nostr live (_@fiatjaf.com): {} entities ({} url, {} pubkey, {} relay)",
        r.entities.len(),
        r.entities.iter().filter(|e| e.kind == EntityKind::Url).count(),
        r.entities
            .iter()
            .filter(|e| e.kind == EntityKind::Other("nostr-pubkey".into()))
            .count(),
        r.entities
            .iter()
            .filter(|e| e.kind == EntityKind::Other("nostr-relay".into()))
            .count(),
    );
    // The well-known document pins `_` to the known hex pubkey.
    assert!(
        r.entities.iter().any(|e| e.kind == EntityKind::Other("nostr-pubkey".into())
            && e.value == HEX),
        "expected fiatjaf's known pubkey from the live NIP-05 document"
    );
}

#[test]
fn freemail_domains_are_not_nip05_probed_custom_domains_are() {
    // A freemail provider serves no /.well-known/nostr.json → a certain 404, so
    // it is not probed; a custom domain might self-host NIP-05, so it is.
    for d in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"] {
        assert!(!nip05_worth_probing(d), "{d} (freemail) must be skipped");
    }
    assert!(nip05_worth_probing("fiatjaf.com"));
    assert!(nip05_worth_probing("example.org"));
}
