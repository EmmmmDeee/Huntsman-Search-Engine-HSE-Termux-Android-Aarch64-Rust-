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
fn blockcypher_doge_balance_deserialises_real_response() {
    // Real response fetched live during this module's extension (a
    // high-activity address, so all three fields are non-trivial).
    let raw = r#"{"address":"DEgDVFa2DoW1533dxeDVdTxQFhMzs1pMke","total_received":3966353566733115617,"total_sent":1249953212756293574,"balance":2716400353976822043,"unconfirmed_balance":0,"final_balance":2716400353976822043,"n_tx":358,"unconfirmed_n_tx":0,"final_n_tx":358}"#;
    let b: BlockcypherBalance = serde_json::from_str(raw).unwrap();
    assert_eq!(b.balance, 2_716_400_353_976_822_043);
    assert_eq!(b.total_received, 3_966_353_566_733_115_617);
    assert_eq!(b.n_tx, 358);
}

#[test]
fn doge_enrichment_reports_full_fields_like_esplora() {
    // Unlike SOL, DOGE (via BlockCypher) gives received + tx_count directly,
    // so it should behave exactly like the BTC/LTC Esplora path — full fields,
    // never falling back to the funded/empty-only branch.
    let e = Enrichment {
        unit: "DOGE",
        decimals: 8,
        balance: 150_000_000,
        received: Some(200_000_000),
        tx_count: Some(3),
        ens: None,
    };
    let ev = build_evidence("doge", &e);
    assert_eq!(ev.attributes.get("balance").unwrap(), "1.5 DOGE");
    assert_eq!(ev.attributes.get("total_received").unwrap(), "2 DOGE");
    assert_eq!(ev.attributes.get("tx_count").unwrap(), "3");
    assert_eq!(ev.attributes.get("activity").unwrap(), "active");
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

#[test]
fn sol_balance_response_deserialises() {
    // Realistic getBalance response shape (a `context` object precedes `value`
    // in the real payload; this struct only needs `value`, so extra fields
    // must not break deserialisation).
    let raw = r#"{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.0.15","slot":123456789},"value":1500000000},"id":1}"#;
    let resp: SolBalanceResp = serde_json::from_str(raw).unwrap();
    assert_eq!(resp.result.unwrap().value, Some(1_500_000_000));
}

#[test]
fn sol_balance_response_missing_result_degrades_cleanly() {
    let resp: SolBalanceResp = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).unwrap();
    assert!(resp.result.is_none());
}

#[test]
fn sol_style_enrichment_never_fabricates_tx_count_or_received() {
    // SOL enrichment (no cheap authoritative tx count / total received —
    // see enrich_sol's doc comment) reuses the exact same honesty path as
    // ETH's missing total_received: both fields simply absent, never faked.
    let e = Enrichment {
        unit: "SOL",
        decimals: 9,
        balance: 1_500_000_000,
        received: None,
        tx_count: None,
        ens: None,
    };
    let ev = build_evidence("sol", &e);
    assert!(!ev.attributes.contains_key("total_received"));
    assert!(!ev.attributes.contains_key("tx_count"));
    assert_eq!(ev.attributes.get("balance").unwrap(), "1.5 SOL");
    // No tx_count and a positive balance -> "funded", not "active"/"dormant".
    assert_eq!(ev.attributes.get("activity").unwrap(), "funded");
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
