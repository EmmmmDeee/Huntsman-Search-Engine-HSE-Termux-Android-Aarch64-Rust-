//! Keyless Bitcoin address intelligence over blockchain.info.
//!
//! One lookup is one GET to blockchain.info's public `rawaddr` endpoint for a single address, asked
//! for the account summary and its [`MAX_TXS`] most recent transactions. The address is confirmed
//! on-chain and enriched with its balance and lifetime totals, as Spiderfoot's `sfp_blockchain`
//! reports a `BITCOIN_BALANCE` for a `BITCOIN_ADDRESS`, and with the chronology of the sampled
//! transactions. Each address it transacted with in them becomes a lead naming the transaction,
//! its time and block, the exact satoshi amount and its role: `paid_by` (an input of a payment it
//! received), `paid_to` (an output of a payment it made) or `co_input` (another input it was spent
//! together with, the common-input heuristic). Every figure is kept in full: the human-readable
//! BTC amount in the summary and the exact satoshi integer in the evidence. Sharing a transaction
//! is not common ownership ([`COUNTERPARTY_LIMIT`]).

use serde::Deserialize;
use serde_json::Value;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_component};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "blockchain";
const HOST: &str = "https://blockchain.info/rawaddr/";

/// One satoshi is 1e-8 BTC.
const SATOSHIS_PER_BTC: u64 = 100_000_000;

/// Confidence of an address confirmed on-chain.
const ADDRESS_CONFIDENCE: f64 = 0.95;

/// The most recent transactions asked for with the summary; blockchain.info allows 50.
pub const MAX_TXS: usize = 20;
/// The most counterparty addresses kept from one lookup.
const MAX_COUNTERPARTIES: usize = 64;
/// The most counterparties taken from one side of one transaction, so one batch payout cannot
/// fill the list.
const MAX_LEGS_PER_SIDE: usize = 16;
/// Confidence of an address that paid, or was paid by, the looked-up address.
const COUNTERPARTY_CONFIDENCE: f64 = 0.5;
/// Confidence of an address spent together with it: a heuristic, weaker than a payment.
const CO_INPUT_CONFIDENCE: f64 = 0.35;

/// What a counterparty never establishes.
pub const COUNTERPARTY_LIMIT: &str = "Appearing in the same transaction is not common ownership or a relationship between people: the common-input heuristic fails for CoinJoin and payjoin transactions, and an exchange or custodial address links unrelated users. No wallet owner is identified.";

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Account {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    hash160: Option<String>,
    #[serde(default)]
    n_tx: Option<u64>,
    #[serde(default)]
    total_received: Option<u64>,
    #[serde(default)]
    total_sent: Option<u64>,
    #[serde(default)]
    final_balance: Option<u64>,
    /// The sampled transactions, read leniently: a malformed one is skipped and counted, never
    /// allowed to lose the account summary.
    #[serde(default)]
    txs: Vec<Value>,
}

/// One leg of a sampled transaction: an address and the exact satoshis it put in or took out.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Leg {
    address: String,
    satoshis: u64,
}

/// One sampled transaction as the lookup reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sampled {
    hash: String,
    time: u64,
    block_height: Option<u64>,
    inputs: Vec<Leg>,
    outputs: Vec<Leg>,
}

/// The legs of one side (`inputs` read through `prev_out`, or `out`); `None` when the side is
/// not an array or a leg is malformed. A leg without an address (a non-standard script) is
/// skipped.
fn legs(tx: &Value, side: &str) -> Option<Vec<Leg>> {
    let mut out = Vec::new();
    for item in tx.get(side)?.as_array()? {
        let leg = if side == "inputs" {
            match item.get("prev_out") {
                Some(prev) => prev,
                None => continue,
            }
        } else {
            item
        };
        let satoshis = leg.get("value")?.as_u64()?;
        if let Some(address) = leg.get("addr").and_then(Value::as_str) {
            out.push(Leg {
                address: address.trim().to_owned(),
                satoshis,
            });
        }
    }
    Some(out)
}

/// A sampled transaction, or `None` when it lacks a hash, a time or well-formed sides.
fn sampled(tx: &Value) -> Option<Sampled> {
    let hash = tx.get("hash")?.as_str()?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(Sampled {
        hash: hash.to_ascii_lowercase(),
        time: tx.get("time")?.as_u64()?,
        block_height: tx.get("block_height").and_then(Value::as_u64),
        inputs: legs(tx, "inputs")?,
        outputs: legs(tx, "out")?,
    })
}

/// The request URL for an address. **Pure.**
#[must_use]
pub fn url(address: &str) -> String {
    format!(
        "{HOST}{}?limit={MAX_TXS}",
        percent_encode_component(address)
    )
}

/// An amount in satoshis written as a fixed-point BTC string. **Pure.**
#[must_use]
pub fn btc(satoshis: u64) -> String {
    format!(
        "{}.{:08}",
        satoshis / SATOSHIS_PER_BTC,
        satoshis % SATOSHIS_PER_BTC
    )
}

/// Look up one Bitcoin address.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    address: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let fetched = fetch(
        transport,
        Request::get(url(address))
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;

    Ok(interpret(&fetched, scan_id, now_unix).unwrap_or_else(miss))
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Turn one fetched response into a report; `Err` is the outcome of a response that named no
/// account. **Pure.**
fn interpret(
    fetched: &Fetched,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    // blockchain.info answers an address it cannot parse or does not hold with a 400 or 404 and a
    // short text body ("Invalid Bitcoin Address" / "Address not found"); both are clean negatives.
    // A rate limit, a refusal, a challenge page and any other 4xx are not: none of them says the
    // address is absent.
    if let Some(response) = fetched.response.as_ref().filter(|r| {
        matches!(r.status, 400 | 404) && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx
    }) {
        return Err(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status)
        );
    }
    let response = whole_response(fetched, "blockchain.info")?;
    answer(fetched, "blockchain.info")?;
    let account: Account = decode_json(response, SOURCE, now_unix, "blockchain.info")?;
    Ok(decode(&account, scan_id, now_unix, response.status))
}

/// Build the report from a parsed account. **Pure.**
fn decode(account: &Account, scan_id: &str, now_unix: u64, status: u16) -> Report {
    // A record with no address is not an account document, however well it parsed.
    let Some(on_chain) = account
        .address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(status),
            "blockchain.info account carried no address",
        ));
    };

    let balance = account.final_balance.unwrap_or(0);
    let received = account.total_received.unwrap_or(0);
    let sent = account.total_sent.unwrap_or(0);
    let n_tx = account.n_tx.unwrap_or(0);

    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!(
            "Bitcoin address: balance {} BTC over {n_tx} transactions",
            btc(balance)
        ),
    )
    .with_attr("dataset", "blockchain.info account summary")
    .with_attr("balance_btc", btc(balance))
    .with_attr("balance_satoshis", balance.to_string())
    .with_attr("total_received_btc", btc(received))
    .with_attr("total_received_satoshis", received.to_string())
    .with_attr("total_sent_btc", btc(sent))
    .with_attr("total_sent_satoshis", sent.to_string())
    .with_attr("transactions", n_tx.to_string());
    if let Some(hash160) = account
        .hash160
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence = evidence.with_attr("hash160", hash160);
    }

    let sample: Vec<Sampled> = account.txs.iter().filter_map(sampled).collect();
    let skipped = account.txs.len() - sample.len();
    if let (Some(first), Some(last)) = (
        sample.iter().map(|tx| tx.time).min(),
        sample.iter().map(|tx| tx.time).max(),
    ) {
        let utc = |unix: u64| crate::timefmt::format_unix(i64::try_from(unix).unwrap_or(i64::MAX));
        evidence = evidence
            .with_attr("sampled_transactions", sample.len().to_string())
            .with_attr("sample_first_tx_utc", utc(first))
            .with_attr("sample_last_tx_utc", utc(last));
    }

    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::CryptoAddress,
        on_chain,
        ADDRESS_CONFIDENCE,
        scan_id,
        evidence,
        &["blockchain", "bitcoin", "on-chain"],
    );
    counterparties(&mut entities, on_chain, &sample, scan_id);
    merge_by_uid(&mut entities);
    let mut outcome =
        SourceExecutionOutcome::success(SOURCE, now_unix, entities.len()).with_http_status(status);
    if skipped != 0 {
        outcome = outcome.with_detail(format!(
            "{skipped} sampled transaction(s) were malformed and not read"
        ));
    }
    Report { entities, outcome }
}

/// Add the addresses `on_chain` transacted with in `sample`, each with the transaction it shares,
/// at most [`MAX_COUNTERPARTIES`].
fn counterparties(entities: &mut Vec<Entity>, on_chain: &str, sample: &[Sampled], scan_id: &str) {
    let mut added = std::collections::BTreeSet::new();
    for tx in sample {
        let spent = tx.inputs.iter().any(|leg| leg.address == on_chain);
        let received = tx.outputs.iter().any(|leg| leg.address == on_chain);
        // Spending: its co-inputs and whom it paid. Receiving only: who paid it.
        let sides: [(&[Leg], &str); 2] = if spent {
            [(&tx.inputs, "co_input"), (&tx.outputs, "paid_to")]
        } else if received {
            [(&tx.inputs, "paid_by"), (&[], "")]
        } else {
            continue;
        };
        for (legs, role) in sides {
            for leg in legs
                .iter()
                .filter(|leg| leg.address != on_chain && !leg.address.is_empty())
                .take(MAX_LEGS_PER_SIDE)
            {
                if added.len() >= MAX_COUNTERPARTIES && !added.contains(&leg.address) {
                    return;
                }
                added.insert(leg.address.clone());
                let mut evidence = Evidence::new(
                    EvidenceProvenance::for_scan(SOURCE, scan_id),
                    format!(
                        "{role} of {on_chain} in transaction {} ({} BTC); {COUNTERPARTY_LIMIT}",
                        tx.hash,
                        btc(leg.satoshis)
                    ),
                )
                .with_attr("dataset", "blockchain.info address transactions")
                .with_attr("counterparty_of", on_chain)
                .with_attr("role", role)
                .with_attr("transaction", &tx.hash)
                .with_attr(
                    "transaction_utc",
                    crate::timefmt::format_unix(i64::try_from(tx.time).unwrap_or(i64::MAX)),
                )
                .with_attr("leg_satoshis", leg.satoshis.to_string());
                evidence = match tx.block_height {
                    Some(height) => evidence.with_attr("block_height", height.to_string()),
                    None => evidence.with_attr("block_height", "unconfirmed"),
                };
                let (confidence, tag) = if role == "co_input" {
                    (CO_INPUT_CONFIDENCE, "bitcoin-co-input")
                } else {
                    (COUNTERPARTY_CONFIDENCE, "bitcoin-counterparty")
                };
                push_entity(
                    entities,
                    EntityKind::CryptoAddress,
                    &leg.address,
                    confidence,
                    scan_id,
                    evidence,
                    &["blockchain", "bitcoin", tag],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    const GENESIS: &str = r#"{
      "address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      "hash160":"62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
      "n_tx":67080,
      "total_received":10769281547,
      "total_sent":0,
      "final_balance":10769281547
    }"#;

    #[test]
    fn satoshis_render_as_fixed_point_btc() {
        assert_eq!(btc(0), "0.00000000");
        assert_eq!(btc(100_000_000), "1.00000000");
        assert_eq!(btc(10_769_281_547), "107.69281547");
    }

    #[test]
    fn query_asks_for_the_summary_and_the_recent_transactions() {
        assert!(url("1abc").starts_with("https://blockchain.info/rawaddr/1abc"));
        assert!(url("1abc").ends_with("?limit=20"));
    }

    #[test]
    fn confirmed_address_keeps_balance_and_totals() {
        let got = lookup(
            &OneResponse::json(200, GENESIS),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);
        let address = got
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::CryptoAddress)
            .expect("the address entity");
        // The exact on-chain address is kept in raw_value; value is the normalised merge key.
        assert_eq!(address.raw_value, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(address.value, "1a1zp1ep5qgefi2dmptftl5slmv7divfna");
        assert!(address.has_tag("bitcoin"));
        let has = |key: &str, val: &str| {
            address
                .evidence
                .iter()
                .any(|evidence| evidence.attributes.get(key).map(String::as_str) == Some(val))
        };
        assert!(has("balance_satoshis", "10769281547"));
        assert!(has("balance_btc", "107.69281547"));
        assert!(has("total_sent_satoshis", "0"));
        assert!(has("transactions", "67080"));
    }

    #[test]
    fn unknown_or_invalid_address_is_valid_zero() {
        let got = lookup(
            &OneResponse::json(404, "Address not found"),
            "1nope",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(got.entities.is_empty());
    }

    /// `interpret` over `status` and `body` fetched unpaced, so a refusal here never opens the
    /// shared blockchain.info circuit every paced lookup in these tests goes through.
    fn interpreted(status: u16, body: &str) -> Report {
        let fetched = fetch(
            &OneResponse::json(status, body),
            Request::get(url("1abc")),
            None,
            &FetchOptions::no_redirects(),
            SOURCE,
            1,
        )
        .unwrap();
        interpret(&fetched, "scan", 1).unwrap_or_else(miss)
    }

    #[test]
    fn only_a_plain_400_or_404_is_a_clean_negative() {
        let challenge = "<html><title>Just a moment...</title>Cloudflare</html>";
        for (status, body, kind) in [
            (400, "Invalid Bitcoin Address", SourceOutcomeKind::ValidZero),
            (404, "Address not found", SourceOutcomeKind::ValidZero),
            (429, "Too Many Requests", SourceOutcomeKind::RateLimited),
            (403, challenge, SourceOutcomeKind::BotWaf),
            (404, challenge, SourceOutcomeKind::BotWaf),
            (403, "forbidden", SourceOutcomeKind::AuthRejected),
            (401, "", SourceOutcomeKind::AuthRequired),
            (410, "gone", SourceOutcomeKind::Upstream4xx),
        ] {
            let got = interpreted(status, body);
            assert_eq!(got.outcome.kind, kind, "HTTP {status} {body}");
            assert_eq!(got.outcome.http_status, Some(status));
            assert!(got.entities.is_empty());
        }
    }

    #[test]
    fn a_document_without_an_address_is_schema_drift() {
        let got = lookup(&OneResponse::json(200, r#"{"n_tx":1}"#), "1abc", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn non_json_is_parser_drift() {
        let got = lookup(&OneResponse::json(200, "not json"), "1abc", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
    }

    #[test]
    fn a_wrong_typed_account_is_parser_drift_that_quotes_none_of_it() {
        let got = lookup(
            &OneResponse::json(200, r#"{"address":"1abc","n_tx":"secret@example.com"}"#),
            "1abc",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
        let detail = got.outcome.detail.unwrap_or_default();
        assert!(!detail.contains("secret@example.com"), "{detail}");
    }

    /// The shape blockchain.info's `rawaddr` answers today (integers, `addr` on each leg,
    /// `block_height` null while unconfirmed), with fictional addresses.
    const SAMPLE: &str = r#"{
      "address":"1Target","n_tx":3,"total_received":40000,"total_sent":40000,"final_balance":4800,
      "txs":[
        {"hash":"aa00000000000000000000000000000000000000000000000000000000000001","time":1700000000,"block_height":800000,"result":40000,
         "inputs":[{"prev_out":{"addr":"1Payer","value":50000}}],
         "out":[{"addr":"1Target","value":40000},{"addr":"1PayerChange","value":9800}]},
        {"hash":"bb00000000000000000000000000000000000000000000000000000000000002","time":1700100000,"block_height":null,"result":-35200,
         "inputs":[{"prev_out":{"addr":"1Target","value":40000}},{"prev_out":{"addr":"1CoSpend","value":10000}}],
         "out":[{"addr":"1Payee","value":45000},{"addr":"1Target","value":4800}]},
        {"hash":"cc00000000000000000000000000000000000000000000000000000000000003","time":1700200000,
         "inputs":[{"prev_out":{"addr":"1Odd","value":"not a number"}}],"out":[]}
      ]
    }"#;

    #[test]
    fn sampled_transactions_give_a_chronology_and_role_named_counterparties() {
        let got = lookup(&OneResponse::json(200, SAMPLE), "1Target", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);
        assert!(
            got.outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("1 sampled transaction(s) were malformed")),
            "{:?}",
            got.outcome.detail
        );
        let find = |raw: &str| {
            got.entities
                .iter()
                .find(|e| e.raw_value == raw)
                .unwrap_or_else(|| panic!("{raw}: {:?}", got.entities))
        };
        let attr = |entity: &Entity, key: &str| {
            entity.evidence[0]
                .attributes
                .get(key)
                .cloned()
                .unwrap_or_default()
        };
        let target = find("1Target");
        assert_eq!(attr(target, "sampled_transactions"), "2");
        assert_eq!(attr(target, "sample_first_tx_utc"), "2023-11-14T22:13:20Z");
        assert_eq!(attr(target, "sample_last_tx_utc"), "2023-11-16T02:00:00Z");

        let payer = find("1Payer");
        assert_eq!(attr(payer, "role"), "paid_by");
        assert_eq!(attr(payer, "leg_satoshis"), "50000");
        assert_eq!(attr(payer, "block_height"), "800000");
        assert!((payer.confidence - COUNTERPARTY_CONFIDENCE).abs() < 1e-9);
        let co = find("1CoSpend");
        assert_eq!(attr(co, "role"), "co_input");
        assert!(co.has_tag("bitcoin-co-input"));
        assert!((co.confidence - CO_INPUT_CONFIDENCE).abs() < 1e-9);
        let recipient = find("1Payee");
        assert_eq!(attr(recipient, "role"), "paid_to");
        assert_eq!(attr(recipient, "block_height"), "unconfirmed");
        assert_eq!(
            attr(recipient, "transaction"),
            "bb00000000000000000000000000000000000000000000000000000000000002"
        );
        for counterparty in [payer, co, recipient] {
            assert!(
                counterparty.evidence[0]
                    .summary
                    .contains("not common ownership")
            );
            assert_eq!(attr(counterparty, "counterparty_of"), "1Target");
        }
        // The payer's change went back to the payer, not through the looked-up address.
        assert!(!got.entities.iter().any(|e| e.raw_value == "1PayerChange"));
        assert!(!got.entities.iter().any(|e| e.raw_value == "1Odd"));
    }

    #[test]
    fn a_batch_payout_gives_at_most_its_bound_of_counterparties() {
        let outputs: Vec<String> = (0..40)
            .map(|i| format!(r#"{{"addr":"1Out{i}","value":1000}}"#))
            .collect();
        let body = format!(
            r#"{{"address":"1Target","n_tx":1,"txs":[{{"hash":"dd00000000000000000000000000000000000000000000000000000000000004","time":1700000000,"block_height":1,"inputs":[{{"prev_out":{{"addr":"1Target","value":50000}}}}],"out":[{}]}}]}}"#,
            outputs.join(",")
        );
        let got = lookup(&OneResponse::json(200, &body), "1Target", "scan", 1).unwrap();
        let paid = got
            .entities
            .iter()
            .filter(|e| e.has_tag("bitcoin-counterparty"))
            .count();
        assert_eq!(paid, MAX_LEGS_PER_SIDE);
    }

    #[test]
    fn a_summary_without_transactions_is_read_as_before() {
        let got = lookup(
            &OneResponse::json(200, GENESIS),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "scan",
            1,
        )
        .unwrap();
        assert_eq!(got.entities.len(), 1);
        assert_eq!(got.outcome.detail, None);
    }
}
