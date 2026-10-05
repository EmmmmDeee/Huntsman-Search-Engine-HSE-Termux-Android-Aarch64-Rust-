use super::*;

const SCAN: &str = "scan-test";
const TARGET: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

fn stats(funded: i64, spent: i64, txs: i64) -> AddressStats {
    AddressStats {
        chain_stats: ChainStats {
            funded_txo_sum: funded,
            spent_txo_sum: spent,
            tx_count: txs,
        },
        mempool_stats: ChainStats::default(),
    }
}

fn vin(addr: Option<&str>, coinbase: bool) -> Vin {
    Vin {
        prevout: addr.map(|a| Prevout {
            scriptpubkey_address: Some(a.to_string()),
        }),
        is_coinbase: coinbase,
    }
}

fn tx(id: &str, ins: Vec<Vin>, out_values: &[i64]) -> Transaction {
    Transaction {
        txid: id.to_string(),
        vin: ins,
        vout: out_values.iter().map(|v| Vout { value: *v }).collect(),
    }
}

fn cospends(entities: &[Entity]) -> Vec<String> {
    entities
        .iter()
        .filter(|e| e.value != TARGET)
        .map(|e| e.value.clone())
        .collect()
}

#[test]
fn an_unused_address_still_reports_its_ledger_state() {
    // A fresh or vanity address is a real finding, not an empty result.
    let out = build_entities(&stats(0, 0, 0), Ok(&[][..]), TARGET, SCAN);
    assert_eq!(out.len(), 1, "the queried address is always reported");
    assert_eq!(out[0].value, TARGET);
    assert_eq!(out[0].kind, EntityKind::CryptoAddress);
}

#[test]
fn co_spent_inputs_are_clustered_when_the_target_is_a_spender() {
    let t = tx(
        "abc",
        vec![vin(Some(TARGET), false), vin(Some("bc1qsibling"), false)],
        &[1_000, 2_000],
    );
    let out = build_entities(&stats(5_000, 1_000, 2), Ok(&[t][..]), TARGET, SCAN);
    assert_eq!(cospends(&out), vec!["bc1qsibling"]);
}

#[test]
fn payment_outputs_are_never_clustered() {
    // The target only RECEIVES here — it is not among the inputs. Sending coin
    // to an address says nothing about who controls it, so nothing may be
    // attributed from this transaction.
    let t = tx(
        "abc",
        vec![vin(Some("bc1qstranger"), false)],
        &[1_000, 2_000],
    );
    let out = build_entities(&stats(1_000, 0, 1), Ok(&[t][..]), TARGET, SCAN);
    assert!(
        cospends(&out).is_empty(),
        "a payment to the target must not cluster the payer's address"
    );
}

#[test]
fn coinjoin_shaped_transactions_are_refused() {
    // Three inputs and three equal-valued outputs: the classic signature. The
    // inputs belong to different people BY DESIGN, so clustering them would
    // fabricate a link between strangers — the worst failure available here.
    let t = tx(
        "cj",
        vec![
            vin(Some(TARGET), false),
            vin(Some("bc1qalice"), false),
            vin(Some("bc1qbob"), false),
        ],
        &[100_000, 100_000, 100_000],
    );
    let out = build_entities(&stats(300_000, 300_000, 1), Ok(&[t][..]), TARGET, SCAN);
    assert!(
        cospends(&out).is_empty(),
        "a CoinJoin must contribute no cluster links"
    );
}

#[test]
fn coinbase_inputs_are_ignored() {
    // Newly-mined coin has no previous owner to attribute.
    let t = tx(
        "cb",
        vec![vin(None, true), vin(Some(TARGET), false)],
        &[50_000],
    );
    let out = build_entities(&stats(50_000, 0, 1), Ok(&[t][..]), TARGET, SCAN);
    assert!(cospends(&out).is_empty());
}

#[test]
fn the_target_is_never_its_own_sibling() {
    let t = tx(
        "self",
        vec![vin(Some(TARGET), false), vin(Some(TARGET), false)],
        &[1_000],
    );
    let out = build_entities(&stats(2_000, 1_000, 1), Ok(&[t][..]), TARGET, SCAN);
    assert!(cospends(&out).is_empty());
}

#[test]
fn dedup_is_case_sensitive_because_base58_case_is_data() {
    // Two base58check addresses differing only in case are DIFFERENT addresses.
    // A case-folding dedup key would collapse them and silently drop a real
    // sibling, so this pins the exact-match behaviour.
    let a = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    let b = "1bVbMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    let t = tx(
        "case",
        vec![
            vin(Some(TARGET), false),
            vin(Some(a), false),
            vin(Some(b), false),
        ],
        // Deliberately unequal outputs so the CoinJoin guard does not fire.
        &[1, 2, 3],
    );
    let out = build_entities(&stats(9_000, 1_000, 1), Ok(&[t][..]), TARGET, SCAN);
    let c = cospends(&out);
    assert_eq!(
        c.len(),
        2,
        "case-differing addresses must both survive: {c:?}"
    );
}

#[test]
fn the_cospend_cap_is_enforced() {
    let mut ins = vec![vin(Some(TARGET), false)];
    for i in 0..(MAX_COSPEND_ADDRESSES + 25) {
        ins.push(vin(Some(&format!("bc1qaddr{i:04}")), false));
    }
    // Unequal outputs so the CoinJoin guard does not fire on the input count.
    let t = tx("big", ins, &[1, 2, 3, 4]);
    let out = build_entities(&stats(1_000, 0, 1), Ok(&[t][..]), TARGET, SCAN);
    assert_eq!(cospends(&out).len(), MAX_COSPEND_ADDRESSES);
}

#[test]
fn projection_is_deterministic() {
    let t = tx(
        "det",
        vec![
            vin(Some(TARGET), false),
            vin(Some("bc1qone"), false),
            vin(Some("bc1qtwo"), false),
        ],
        &[1, 2, 3],
    );
    let txs = [t];
    let a = build_entities(&stats(3_000, 1_000, 2), Ok(&txs[..]), TARGET, SCAN);
    let b = build_entities(&stats(3_000, 1_000, 2), Ok(&txs[..]), TARGET, SCAN);
    let va: Vec<_> = a.iter().map(|e| &e.value).collect();
    let vb: Vec<_> = b.iter().map(|e| &e.value).collect();
    assert_eq!(va, vb, "identical input must yield an identical projection");
}

#[test]
fn unconfirmed_balance_is_reported_separately() {
    let s = AddressStats {
        chain_stats: ChainStats {
            funded_txo_sum: 200_000,
            spent_txo_sum: 100_000,
            tx_count: 3,
        },
        mempool_stats: ChainStats {
            funded_txo_sum: 0,
            spent_txo_sum: 50_000,
            tx_count: 1,
        },
    };
    let out = build_entities(&s, Ok(&[][..]), TARGET, SCAN);
    let ev = out[0].evidence.first().expect("activity evidence present");
    assert!(
        ev.summary.contains("unconfirmed"),
        "an address being drained right now must say so: {}",
        ev.summary
    );
}

#[test]
fn evm_addresses_are_declined_rather_than_queried() {
    // The classifier accepts 0x… as CryptoAddress; a Bitcoin explorer would
    // return 400 for one, so the module declines it up front.
    assert!(!Bitcoin::handles_value(
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    ));
    assert!(Bitcoin::handles_value(TARGET));
    assert!(!Bitcoin::handles_value("   "));
}

#[test]
fn module_metadata_is_coherent() {
    let m = Bitcoin;
    assert_eq!(m.name(), "bitcoin");
    assert!(m.accepts(&Target::new(TargetKind::CryptoAddress, TARGET)));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(
        m.produces().contains(&EntityKind::CryptoAddress),
        "produces() must declare what build_entities actually emits"
    );
}

#[test]
fn attack_techniques_covers_the_open_technical_database_pivot() {
    // Regression: this module queries the same Esplora block explorer
    // (blockstream.info) that `chain_intel` maps to T1596 (Search Open
    // Technical Databases) for its own BTC/LTC lookups — the claim was
    // missing here despite the identical source/action.
    let m = Bitcoin;
    assert!(
        m.attack_techniques().contains(&"T1596"),
        "querying a public block explorer is Search Open Technical Databases: {:?}",
        m.attack_techniques()
    );
}

// ── Backlog #6: a failed transaction list must not discard the ledger reading,
//    nor pass for "no co-spends" ───────────────────────────────────────────────

#[test]
fn a_failed_transaction_lookup_keeps_the_ledger_reading_and_says_so() {
    let out = build_entities(
        &stats(5_000, 1_000, 2),
        Err("[bitcoin] HTTP 503 Service Unavailable: upstream busy"),
        TARGET,
        SCAN,
    );
    let anchor = out
        .iter()
        .find(|e| e.value == TARGET)
        .expect("the ledger reading survives the transaction-list failure");
    assert!(anchor.has_tag("cospend-unavailable"));
    let ev = &anchor.evidence[0];
    assert_eq!(ev.attributes.get("tx_count").map(String::as_str), Some("2"));
    assert_eq!(
        ev.attributes.get("balance_sats").map(String::as_str),
        Some("4000")
    );
    assert_eq!(
        ev.attributes.get("cospend_lookup").map(String::as_str),
        Some("failed")
    );
    assert!(
        ev.attributes
            .get("cospend_error")
            .is_some_and(|e| e.contains("503")),
        "the reason is on the evidence: {:?}",
        ev.attributes
    );
    assert!(
        cospends(&out).is_empty(),
        "a cluster that was never read is not an empty cluster"
    );

    // The ordinary case carries no such marker.
    let out = build_entities(&stats(5_000, 1_000, 2), Ok(&[][..]), TARGET, SCAN);
    let anchor = out.iter().find(|e| e.value == TARGET).expect("anchor");
    assert!(!anchor.has_tag("cospend-unavailable"));
    assert!(!anchor.evidence[0].attributes.contains_key("cospend_lookup"));
}

/// The transport half against a loopback Esplora: the ledger reading is kept
/// when `/txs` fails; a failed ledger call is the module's error; Esplora's 404
/// is the one clean negative.
#[tokio::test]
async fn lookup_keeps_the_ledger_on_a_txs_failure_and_errors_on_a_ledger_failure() {
    use crate::util::http::test_server::{Canned, serve};
    const STATS: &str = r#"{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","chain_stats":{"funded_txo_count":1,"funded_txo_sum":5000,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":1},"mempool_stats":{"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":0}}"#;
    let client = reqwest::Client::new();

    let base = serve(vec![
        Canned::json(200, STATS),
        Canned::text(503, "upstream busy"),
    ])
    .await;
    let r = lookup(&client, &base, TARGET, SCAN)
        .await
        .expect("a /txs failure must not discard the ledger reading already fetched");
    let anchor = r
        .entities
        .iter()
        .find(|e| e.value == TARGET)
        .expect("anchor kept");
    assert!(anchor.has_tag("cospend-unavailable"));
    assert!(
        anchor.evidence[0]
            .attributes
            .get("cospend_error")
            .is_some_and(|e| e.contains("503")),
        "{:?}",
        anchor.evidence[0].attributes
    );

    let base = serve(vec![Canned::text(500, "Internal Server Error")]).await;
    let err = lookup(&client, &base, TARGET, SCAN)
        .await
        .expect_err("a failed ledger call is the module's error, not an empty result");
    assert!(err.to_string().contains("500"), "{err}");

    let base = serve(vec![Canned::text(404, "Address not found")]).await;
    let r = lookup(&client, &base, TARGET, SCAN)
        .await
        .expect("Esplora's 404 is the clean negative");
    assert!(r.is_empty());
}
