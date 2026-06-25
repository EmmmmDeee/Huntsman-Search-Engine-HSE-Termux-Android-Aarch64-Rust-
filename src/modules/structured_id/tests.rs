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
    let (_secs, mac) = decode_uuid_v1(&u).unwrap();
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
    let mut s = String::from_utf8(ts.to_vec()).unwrap();
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
    String::from_utf8(out).unwrap()
}

#[test]
fn ulid_round_trips_creation_time() {
    let u = build_ulid(1_577_836_800_000); // 2020-01-01 in ms
    assert_eq!(u.len(), 26);
    assert_eq!(decode_ulid(&u), Some(1_577_836_800));
    assert_eq!(utc_date(decode_ulid(&u).unwrap()), "2020-01-01");
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
        proxy_pool: Default::default(),
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
