use crate::core::confidence;
use super::*;

fn enr() -> Enrichment {
    Enrichment {
        unit: "BTC",
        decimals: 8,
        balance: 150_000_000,
        received: Some(200_000_000),
        tx_count: Some(7),
        ens: None,
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
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
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
    };
    let ev = build_evidence("eth", &e);
    assert!(
        !ev.attributes.contains_key("total_received"),
        "must NOT fabricate a total_received it doesn't have"
    );
    assert_eq!(ev.attributes.get("tx_count").expect("should succeed"), "78246");
    assert_eq!(ev.attributes.get("activity").expect("should succeed"), "active");
    assert_eq!(ev.attributes.get("ens_name").expect("should succeed"), "vitalik.eth");
    assert_eq!(
        ev.attributes.get("balance").expect("should succeed"),
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
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
    };
    assert_eq!(
        build_evidence("eth", &funded)
            .attributes
            .get("activity")
            .expect("should succeed"),
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
            .expect("should succeed"),
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
            .expect("should succeed"),
        "dormant"
    );
}

#[test]
fn blockcypher_doge_balance_deserialises_real_response() {
    // Real response fetched live during this module's extension (a
    // high-activity address, so all three fields are non-trivial).
    let raw = r#"{"address":"DEgDVFa2DoW1533dxeDVdTxQFhMzs1pMke","total_received":3966353566733115617,"total_sent":1249953212756293574,"balance":2716400353976822043,"unconfirmed_balance":0,"final_balance":2716400353976822043,"n_tx":358,"unconfirmed_n_tx":0,"final_n_tx":358}"#;
    let b: BlockcypherBalance = serde_json::from_str(raw).expect("should succeed");
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
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
    };
    let ev = build_evidence("doge", &e);
    assert_eq!(ev.attributes.get("balance").expect("should succeed"), "1.5 DOGE");
    assert_eq!(ev.attributes.get("total_received").expect("should succeed"), "2 DOGE");
    assert_eq!(ev.attributes.get("tx_count").expect("should succeed"), "3");
    assert_eq!(ev.attributes.get("activity").expect("should succeed"), "active");
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
    let resp: SolBalanceResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(resp.result.expect("should succeed").value, Some(1_500_000_000));
}

#[test]
fn sol_balance_response_missing_result_degrades_cleanly() {
    let resp: SolBalanceResp = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).expect("should succeed");
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
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
    };
    let ev = build_evidence("sol", &e);
    assert!(!ev.attributes.contains_key("total_received"));
    assert!(!ev.attributes.contains_key("tx_count"));
    assert_eq!(ev.attributes.get("balance").expect("should succeed"), "1.5 SOL");
    // No tx_count and a positive balance -> "funded", not "active"/"dormant".
    assert_eq!(ev.attributes.get("activity").expect("should succeed"), "funded");
}

#[test]
fn blockscout_address_deserialises_scam_reputation_name_and_tags() {
    // Real-shaped Blockscout v2 response (field names/nesting confirmed
    // live against https://eth.blockscout.com/api/v2/addresses/<addr>):
    // `is_scam`/`reputation`/`name` are top-level scalars and `public_tags`
    // is an array of `{label, display_name}` objects.
    let raw = r#"{"coin_balance":"1000","ens_domain_name":null,"is_scam":true,
        "reputation":"scam","name":"Fake Uniswap","public_tags":[
        {"label":"phishing","display_name":"Phishing"},
        {"label":"scam-address","display_name":null}
    ]}"#;
    let a: BlockscoutAddress = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(a.is_scam, Some(true));
    assert_eq!(a.reputation.as_deref(), Some("scam"));
    assert_eq!(a.name.as_deref(), Some("Fake Uniswap"));
    assert_eq!(a.public_tags.len(), 2);
}

#[test]
fn blockscout_address_defaults_scam_fields_when_absent() {
    // A clean address (the common case) doesn't even set these keys — must
    // degrade to `None`/empty, never a fabricated default.
    let raw = r#"{"coin_balance":"1000","ens_domain_name":null}"#;
    let a: BlockscoutAddress = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(a.is_scam, None);
    assert_eq!(a.reputation, None);
    assert_eq!(a.name, None);
    assert!(a.public_tags.is_empty());
}

#[test]
fn blockscout_tag_labels_prefers_display_name_falls_back_to_label_skips_blank() {
    let tags = vec![
        BlockscoutTag {
            label: Some("phishing".into()),
            display_name: Some("Phishing".into()),
        },
        BlockscoutTag {
            label: Some("scam-address".into()),
            display_name: None,
        },
        BlockscoutTag {
            label: None,
            display_name: None,
        },
        BlockscoutTag {
            label: Some("  ".into()),
            display_name: None,
        },
    ];
    let labels = blockscout_tag_labels(&tags);
    assert_eq!(labels, vec!["Phishing".to_string(), "scam-address".to_string()]);
}

#[test]
fn evidence_reports_blockscout_reputation_signals_when_present() {
    let e = Enrichment {
        unit: "ETH",
        decimals: 18,
        balance: 1,
        received: None,
        tx_count: None,
        ens: None,
        is_scam: Some(true),
        reputation: Some("scam".into()),
        known_name: Some("Fake Uniswap".into()),
        public_tags: vec!["Phishing".into(), "scam-address".into()],
    };
    let ev = build_evidence("eth", &e);
    assert_eq!(ev.attributes.get("is_scam").expect("should succeed"), "true");
    assert_eq!(ev.attributes.get("reputation").expect("should succeed"), "scam");
    assert_eq!(ev.attributes.get("known_name").expect("should succeed"), "Fake Uniswap");
    assert_eq!(
        ev.attributes.get("public_tags").expect("should succeed"),
        "Phishing, scam-address"
    );
}

#[test]
fn evidence_omits_blockscout_reputation_signals_when_absent() {
    // `enr()`'s BTC fixture never sets these — a source with no scam signal
    // must not have the attribute at all, not an empty/false placeholder.
    let ev = build_evidence("btc", &enr());
    assert!(!ev.attributes.contains_key("is_scam"));
    assert!(!ev.attributes.contains_key("reputation"));
    assert!(!ev.attributes.contains_key("known_name"));
    assert!(!ev.attributes.contains_key("public_tags"));
}

#[test]
fn apply_scam_tags_tags_malicious_and_threat_intel_only_when_flagged() {
    let mut scam_entity = Entity::new(EntityKind::CryptoAddress, "0xdead", confidence::HIGH_PLUSPLUS, "scan-1");
    let scam = Enrichment {
        is_scam: Some(true),
        ..enr()
    };
    apply_scam_tags(&mut scam_entity, &scam);
    assert!(scam_entity.tags.contains(&crate::core::tags::MALICIOUS.to_string()));
    assert!(
        scam_entity
            .tags
            .contains(&crate::core::tags::THREAT_INTEL.to_string())
    );

    // False and absent must both be silent — a source explicitly saying
    // "not a scam" is not itself evidence worth a MALICIOUS tag, and an
    // absent verdict must never be treated as a positive one.
    let mut clean_entity = Entity::new(EntityKind::CryptoAddress, "0xclean", confidence::HIGH_PLUSPLUS, "scan-1");
    let clean = Enrichment {
        is_scam: Some(false),
        ..enr()
    };
    apply_scam_tags(&mut clean_entity, &clean);
    assert!(!clean_entity.tags.contains(&crate::core::tags::MALICIOUS.to_string()));

    let mut unknown_entity = Entity::new(EntityKind::CryptoAddress, "0xunknown", confidence::HIGH_PLUSPLUS, "scan-1");
    apply_scam_tags(&mut unknown_entity, &enr());
    assert!(!unknown_entity.tags.contains(&crate::core::tags::MALICIOUS.to_string()));
}

#[test]
fn known_name_entity_mints_organisation_tagged_via_apply_scam_tags() {
    // Same "Fake Uniswap" / is_scam:true fixture as
    // `blockscout_address_deserialises_scam_reputation_name_and_tags` — proves
    // the curated `known_name` label parsed there is minted as a first-class
    // Organisation entity here, not left stranded in evidence text only (the
    // gap: `ens_domain_name` got this treatment, `known_name` never did).
    let e = Enrichment {
        known_name: Some("Fake Uniswap".into()),
        is_scam: Some(true),
        ..enr()
    };
    let org = known_name_entity("Fake Uniswap", "0xdeadbeef", &e, "scan-1")
        .expect("a well-formed known_name label must mint an entity");
    assert_eq!(org.kind, EntityKind::Organisation);
    assert_eq!(org.value, "Fake Uniswap");
    assert!(org.tags.contains(&SRC.to_string()));
    assert!(org.tags.contains(&"known-name".to_string()));
    // apply_scam_tags gating: is_scam:true must carry through onto the new
    // entity exactly like it does for the sibling CryptoAddress entity.
    assert!(org.tags.contains(&crate::core::tags::MALICIOUS.to_string()));
    assert!(
        org.tags
            .contains(&crate::core::tags::THREAT_INTEL.to_string())
    );
    assert_eq!(org.evidence.len(), 1);
    let ev = &org.evidence[0];
    assert_eq!(ev.attributes.get("known_name").expect("should succeed"), "Fake Uniswap");
    assert_eq!(ev.attributes.get("address").expect("should succeed"), "0xdeadbeef");
}

#[test]
fn known_name_entity_omits_scam_tags_when_not_flagged() {
    // A clean (non-scam) known_name label must still mint the Organisation —
    // just without the MALICIOUS/THREAT_INTEL tags apply_scam_tags gates on.
    let e = Enrichment {
        known_name: Some("UniswapV2Router02".into()),
        is_scam: None,
        ..enr()
    };
    let org = known_name_entity("UniswapV2Router02", "0xrouter", &e, "scan-1").expect("should succeed");
    assert_eq!(org.value, "UniswapV2Router02");
    assert!(!org.tags.contains(&crate::core::tags::MALICIOUS.to_string()));
    assert!(!org.tags.contains(&crate::core::tags::THREAT_INTEL.to_string()));
}

#[test]
fn known_name_entity_is_none_for_blank_or_too_short_label() {
    let e = enr();
    assert!(known_name_entity("", "0xaddr", &e, "scan-1").is_none());
    assert!(known_name_entity("   ", "0xaddr", &e, "scan-1").is_none());
    assert!(known_name_entity("a", "0xaddr", &e, "scan-1").is_none());
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

// ── enrich_esplora: a source failure must surface, not masquerade as a
// clean no-op (T2.122) ──────────────────────────────────────────────────
//
// `enrich_esplora` is the one enricher whose base URL is a parameter, so it can
// be driven against a real local server (the other four hardcode their host and
// rely on `fetch_json`'s already-tested non-2xx→Err contract). These pin the
// exact T2.122 fix: the old `fetch_json(…).await.ok()?` turned a 5xx into
// `None`, indistinguishable from a recognised-but-unwired chain or an empty
// address; it must now be an `Err`.

fn live_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

/// A one-shot local HTTP server that answers with `status` + `body` — a real
/// (not mocked) transport for `enrich_esplora` to hit. Mirrors the pattern the
/// `ip_reputation`/`pwned_passwords` tests use.
async fn serve_once(status: u16, body: &'static str) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let reason = if status == 200 { "OK" } else { "Error" };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body.as_bytes()).await;
        let _ = sock.flush().await;
    });
    addr
}

#[tokio::test]
async fn enrich_esplora_propagates_a_source_error_instead_of_a_silent_none() {
    // Regression for T2.122: previously a 503 became `None`, indistinguishable
    // from an unsupported chain / empty address.
    let addr = serve_once(503, "upstream down").await;
    crate::util::circuit_breaker::record_success("127.0.0.1"); // isolate from parallel tests
    let ctx = live_ctx();
    let out = enrich_esplora(&ctx, &format!("http://{addr}"), "1BTCaddr", "BTC").await;
    assert!(
        out.is_err(),
        "a 5xx from the sole Esplora source must surface as Err, not a hollow None"
    );
    crate::util::circuit_breaker::record_success("127.0.0.1"); // reset breaker after the 503
}

#[tokio::test]
async fn enrich_esplora_parses_a_real_shaped_body_into_enrichment() {
    // A real blockstream.info `/address/<a>` body shape (extra fields ignored by
    // `#[serde(default)]`); balance = funded − spent, tx_count = chain + mempool.
    let body = r#"{"address":"1BTCaddr",
        "chain_stats":{"funded_txo_count":5,"funded_txo_sum":200000000,"spent_txo_count":3,"spent_txo_sum":50000000,"tx_count":7},
        "mempool_stats":{"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":1}}"#;
    let addr = serve_once(200, body).await;
    crate::util::circuit_breaker::record_success("127.0.0.1");
    let ctx = live_ctx();
    let enr = enrich_esplora(&ctx, &format!("http://{addr}"), "1BTCaddr", "BTC")
        .await
        .expect("a well-formed 200 body must parse to Ok")
        .expect("a real address body must yield Some(Enrichment)");
    assert_eq!(enr.balance, 150_000_000, "200000000 funded − 50000000 spent");
    assert_eq!(enr.received, Some(200_000_000));
    assert_eq!(enr.tx_count, Some(8), "7 chain + 1 mempool");
    assert_eq!(enr.unit, "BTC");
}
