use super::*;

/// Build a v1 UUID for a known timestamp + node, to round-trip the decoder.
fn build_uuid_v1(unix_secs: i64, node12: &str) -> String {
    let ticks = (unix_secs as u64) * 10_000_000 + UUID_TICKS_BETWEEN_EPOCHS;
    let time_low = ticks & 0xFFFF_FFFF;
    let time_mid = (ticks >> 32) & 0xFFFF;
    let time_hi = (ticks >> 48) & 0x0FFF;
    format!("{time_low:08x}-{time_mid:04x}-1{time_hi:03x}-a765-{node12}")
}

#[test]
fn uuid_v1_round_trips_time_and_real_mac() {
    // 2020-01-01, unicast node (first octet 0x00 → a real MAC).
    let u = build_uuid_v1(1_577_836_800, "00a0c91e6bf6");
    let (secs, mac) = decode_uuid_v1(&u).expect("valid v1 UUID");
    assert_eq!(secs, 1_577_836_800);
    assert_eq!(utc_date(secs), "2020-01-01");
    assert_eq!(mac.as_deref(), Some("00:a0:c9:1e:6b:f6"));
}

#[test]
fn uuid_v1_random_node_yields_no_mac() {
    // Multicast/local bit set (first octet 0x01) → random node, not a real MAC.
    let u = build_uuid_v1(1_577_836_800, "01a0c91e6bf6");
    let (_secs, mac) = decode_uuid_v1(&u).expect("should succeed");
    assert_eq!(mac, None);
}

#[test]
fn decode_uuid_v1_rejects_non_v1_and_malformed() {
    // A v4 UUID (version nibble 4) is random — no embedded time.
    assert!(decode_uuid_v1("f81d4fae-7dec-41d0-a765-00a0c91e6bf6").is_none());
    // Wrong shape.
    assert!(decode_uuid_v1("not-a-uuid").is_none());
    assert!(decode_uuid_v1("f81d4fae7dec11d0a76500a0c91e6bf6").is_none()); // no hyphens
}

#[test]
fn decode_objectid_reads_leading_timestamp() {
    // The leading 4 bytes (507f1f77) are the creation time.
    assert_eq!(decode_objectid("507f1f77bcf86cd799439011"), Some(1_350_508_407));
    assert!(decode_objectid("507f1f77").is_none()); // too short
    assert!(decode_objectid("zzzz1f77bcf86cd799439011").is_none()); // non-hex
}

#[test]
fn is_free_passive_module() {
    let m = StructuredId;
    assert!(m.is_passive());
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Username, "anything")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.produces().contains(&EntityKind::MacAddress));
}

/// Crockford-base32-encode a 48-bit ms timestamp into the 10-char ULID prefix,
/// padded with 16 `0` "random" chars, to round-trip the decoder.
fn build_ulid(unix_ms: u64) -> String {
    let mut ms = unix_ms & 0xFFFF_FFFF_FFFF;
    let mut ts = [0u8; 10];
    for slot in ts.iter_mut().rev() {
        *slot = CROCKFORD[(ms & 0x1F) as usize];
        ms >>= 5;
    }
    let mut s = String::from_utf8(ts.to_vec()).expect("should succeed");
    s.push_str("0000000000000000"); // 16 random chars (`0` is valid base32)
    s
}

/// Base62-encode a KSUID for a known timestamp (zero randomness), to round-trip
/// the decoder.
fn build_ksuid(unix_secs: i64) -> String {
    let ts = (unix_secs - KSUID_EPOCH_SECS) as u32;
    let mut n = [0u8; 20];
    n[0..4].copy_from_slice(&ts.to_be_bytes());
    let mut out = Vec::new();
    loop {
        let mut rem = 0u32;
        let mut nonzero = false;
        for b in &mut n {
            let acc = (rem << 8) | u32::from(*b);
            *b = (acc / 62) as u8;
            rem = acc % 62;
            if *b != 0 {
                nonzero = true;
            }
        }
        out.push(BASE62[rem as usize]);
        if !nonzero {
            break;
        }
    }
    out.reverse();
    while out.len() < 27 {
        out.insert(0, BASE62[0]);
    }
    String::from_utf8(out).expect("should succeed")
}

#[test]
fn ulid_round_trips_creation_time() {
    let u = build_ulid(1_577_836_800_000); // 2020-01-01 in ms
    assert_eq!(u.len(), 26);
    assert_eq!(decode_ulid(&u), Some(1_577_836_800));
    assert_eq!(utc_date(decode_ulid(&u).expect("should succeed")), "2020-01-01");
    assert!(decode_ulid("tooshort").is_none());
    assert!(decode_ulid("0000000000000000000000000U").is_none()); // 'U' not base32
}

#[test]
fn ksuid_round_trips_creation_time() {
    let k = build_ksuid(1_577_836_800); // 2020-01-01
    assert_eq!(k.len(), 27);
    assert_eq!(decode_ksuid(&k), Some(1_577_836_800));
    assert!(decode_ksuid("tooshort").is_none());
    assert!(decode_ksuid("0000000000000000000000000+/").is_none()); // non-base62
}

#[tokio::test]
async fn process_decodes_ksuid_through_target_new_without_case_corruption() {
    // Regression: `Target::new` normalises every Username-kind value (which is
    // where a bare structured ID like a KSUID lands — see `accepts()`'s own
    // comment) before any module sees it. Base62 is case-SIGNIFICANT (unlike
    // Crockford base32/ULID), so folding a KSUID's case used to silently
    // decode a DIFFERENT 160-bit value — this real KSUID's creation date is
    // 2023-01-16, but decoding it after lowercasing instead yields
    // 2024-08-17, a plausible-looking date 580+ days wrong.
    // `hse_core::normalise`'s Username arm now preserves case for this exact
    // shape (see its own tests for that guarantee in isolation); this proves
    // the FULL pipeline a real scan uses — seed → `Target::new` → `process()`
    // — benefits from it, not just `decode_ksuid` called directly (which is
    // how the pre-existing `ksuid_round_trips_creation_time` test above
    // exercises it, bypassing `Target::new` entirely and so never catching
    // this).
    let ksuid = "2KNu8EwGT2LWr6M7B7987uqR6mm";
    assert_eq!(decode_ksuid(ksuid), Some(1_673_827_200)); // 2023-01-16T00:00:00Z
    assert_ne!(
        decode_ksuid(&ksuid.to_ascii_lowercase()),
        Some(1_673_827_200),
        "sanity: lowercasing this KSUID really does change its decoded value"
    );

    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    // `Target::new` is the SAME path every real scan seed and every derived
    // Username entity goes through — not `decode_ksuid` called directly.
    let target = Target::new(TargetKind::Username, ksuid);
    assert_eq!(target.value, ksuid, "case must survive Target::new");
    let r = StructuredId
        .process(&target, &ctx)
        .await
        .expect("offline decode never errors");
    let date = r
        .entities
        .iter()
        .find(|e| e.has_tag("ksuid"))
        .expect("a ksuid-tagged entity")
        .evidence[0]
        .attributes
        .get("ksuid_created_date")
        .cloned();
    assert_eq!(
        date.as_deref(),
        Some("2023-01-16"),
        "the KSUID's real creation date must survive Target::new intact"
    );
}

#[tokio::test]
async fn objectid_and_ksuid_are_reported_below_ulid_confidence() {
    // Regression: ObjectID's and KSUID's ONLY validation beyond shape/charset
    // is the `[PLAUSIBLE_FLOOR_SECS, now]` window — a 32-bit SECOND-resolution
    // timestamp, which a random string of the right shape coincidentally
    // lands inside ~20% (ObjectID) / ~9% (KSUID) of the time. Neither format
    // has a checksum to validate against instead, so this false-positive
    // pathway can't be eliminated — only honestly reflected in confidence.
    // `507f1f77deadbeefcafebabe` is a contrived, obviously-not-a-real-ObjectID
    // 24-hex string (the tail deliberately spells "deadbeefcafebabe") whose
    // leading 4 bytes (507f1f77) still happen to decode to a plausible date —
    // it still gets accepted (there is no way not to), but must be reported
    // at the demoted LOW_MEDIUM tier, not ULID's MEDIUM_HIGH (ULID's 48-bit
    // MILLISECOND timestamp makes its own false-positive rate negligible, so
    // it keeps the higher tier).
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let fake_objectid = "507f1f77deadbeefcafebabe";
    assert_eq!(decode_objectid(fake_objectid), Some(1_350_508_407));
    let target = Target::new(TargetKind::Username, fake_objectid);
    let r = StructuredId
        .process(&target, &ctx)
        .await
        .expect("offline decode never errors");
    let e = r
        .entities
        .iter()
        .find(|e| e.has_tag("mongodb-objectid"))
        .expect("a mongodb-objectid-tagged entity");
    assert!(
        (e.confidence - confidence::LOW_MEDIUM).abs() < 1e-9,
        "a coincidentally-plausible non-ObjectID must not be reported at \
         ULID's higher confidence tier: got {}",
        e.confidence
    );
    // Strict, not the tie-tolerant sibling: this IS the shape the
    // regression took (ObjectID silently sharing ULID's exact constant).
    confidence::assert_metamorphic_strictly_worse(
        confidence::MEDIUM_HIGH,
        e.confidence,
        "structured_id: ObjectID's higher false-positive decode window vs ULID's",
    );

    let ksuid = "2KNu8EwGT2LWr6M7B7987uqR6mm";
    let target = Target::new(TargetKind::Username, ksuid);
    let r = StructuredId
        .process(&target, &ctx)
        .await
        .expect("offline decode never errors");
    let e = r
        .entities
        .iter()
        .find(|e| e.has_tag("ksuid"))
        .expect("a ksuid-tagged entity");
    assert!(
        (e.confidence - confidence::LOW_MEDIUM).abs() < 1e-9,
        "a KSUID decode must also be reported at the demoted tier: got {}",
        e.confidence
    );
    confidence::assert_metamorphic_strictly_worse(
        confidence::MEDIUM_HIGH,
        e.confidence,
        "structured_id: KSUID's higher false-positive decode window vs ULID's",
    );
}

#[tokio::test]
async fn process_decodes_uuid_v1_to_mac_and_time() {
    // Fully offline + deterministic — runs in CI.
    let u = build_uuid_v1(1_577_836_800, "00a0c91e6bf6");
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let r = StructuredId
        .process(&Target::new(TargetKind::Username, &u), &ctx)
        .await
        .expect("offline decode never errors");
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::MacAddress && e.value == "00:a0:c9:1e:6b:f6"),
        "the node MAC must be emitted as a MacAddress entity"
    );
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.has_tag("uuid-v1"))
    );
}
