use super::*;

fn enr() -> Enrichment {
    Enrichment {
        unit: "BTC",
        decimals: 8,
        balance: 150_000_000,
        received: Some(200_000_000),
        tx_count: Some(7),
        ens: None,
    }
}

#[test]
fn format_units_handles_btc_and_eth_scales() {
    assert_eq!(format_units(150_000_000, 8), "1.5");
    assert_eq!(format_units(100_000_000, 8), "1");
    assert_eq!(format_units(1, 8), "0.00000001");
    assert_eq!(format_units(0, 8), "0");
    // 2.5 ETH in wei (18 decimals) — exceeds f64 exact-int range.
    assert_eq!(format_units(2_500_000_000_000_000_000, 18), "2.5");
}

#[test]
fn evidence_reports_full_esplora_fields() {
    let ev = build_evidence("btc", &enr());
    let g = |k: &str| ev.attributes.get(k).cloned().unwrap_or_default();
    assert_eq!(g("balance"), "1.5 BTC");
    assert_eq!(g("total_received"), "2 BTC");
    assert_eq!(g("tx_count"), "7");
    assert_eq!(g("activity"), "active");
}

#[test]
fn evidence_omits_unknown_fields_and_never_fabricates() {
    // ETH-style: balance + tx_count known, NO total_received, plus ENS.
    let e = Enrichment {
        unit: "ETH",
        decimals: 18,
        balance: 5_688_240_446_715_981_478,
        received: None,
        tx_count: Some(78_246),
        ens: Some("vitalik.eth".into()),
    };
    let ev = build_evidence("eth", &e);
    assert!(
        !ev.attributes.contains_key("total_received"),
        "must NOT fabricate a total_received it doesn't have"
    );
    assert_eq!(ev.attributes.get("tx_count").unwrap(), "78246");
    assert_eq!(ev.attributes.get("activity").unwrap(), "active");
    assert_eq!(ev.attributes.get("ens_name").unwrap(), "vitalik.eth");
    assert_eq!(
        ev.attributes.get("balance").unwrap(),
        "5.688240446715981478 ETH"
    );
}

#[test]
fn activity_falls_back_to_funded_empty_without_tx_count() {
    let funded = Enrichment {
        unit: "ETH",
        decimals: 18,
        balance: 1,
        received: None,
        tx_count: None,
        ens: None,
    };
    assert_eq!(
        build_evidence("eth", &funded)
            .attributes
            .get("activity")
            .unwrap(),
        "funded"
    );
    let empty = Enrichment {
        balance: 0,
        ..funded
    };
    assert_eq!(
        build_evidence("eth", &empty)
            .attributes
            .get("activity")
            .unwrap(),
        "empty"
    );
    // A dormant (seen but zero-tx) address is distinct from unknown.
    let dormant = Enrichment {
        tx_count: Some(0),
        ..empty
    };
    assert_eq!(
        build_evidence("eth", &dormant)
            .attributes
            .get("activity")
            .unwrap(),
        "dormant"
    );
}

#[test]
fn accepts_only_crypto_address() {
    assert!(ChainIntel.accepts(&Target::new(TargetKind::CryptoAddress, "x")));
    assert!(!ChainIntel.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn module_metadata_full() {
    let m = ChainIntel;
    assert_eq!(m.name(), "chain_intel");
    assert!(!m.description().is_empty());
    assert_eq!(m.priority(), 90);
    assert_eq!(m.max_timeout_ms(), 12_000);
    assert!(m.attack_techniques().contains(&"T1596"));
    assert!(m.produces().contains(&EntityKind::CryptoAddress));
}

/// The bug: `enrich_esplora` summed two untrusted, explorer-supplied `u64`
/// tx counts with plain `+` — a sibling explorer response with either count
/// near `u64::MAX` overflows, panicking under `overflow-checks` (the
/// project's dev/test default) or silently wrapping to a bogus small count
/// in a release build (the "trust no input number" class already fixed
/// elsewhere for this exact struct's `funded_txo_sum`/`spent_txo_sum`).
#[test]
fn combined_tx_count_saturates_instead_of_overflowing() {
    assert_eq!(combined_tx_count(u64::MAX - 1, 5), u64::MAX);
    assert_eq!(combined_tx_count(u64::MAX, u64::MAX), u64::MAX);
}

#[test]
fn combined_tx_count_adds_normally_in_the_realistic_range() {
    assert_eq!(combined_tx_count(120, 3), 123);
    assert_eq!(combined_tx_count(0, 0), 0);
}

#[test]
fn format_units_zero_and_minimal() {
    // Zero balance → "0" with any decimal scale.
    assert_eq!(format_units(0, 8), "0");
    assert_eq!(format_units(0, 18), "0");
    // 1 satoshi = 0.00000001 BTC (8 decimals).
    assert_eq!(format_units(1, 8), "0.00000001");
    // Exactly 1 unit.
    assert_eq!(format_units(100_000_000, 8), "1");
}
