//! Keyless Bitcoin address intelligence over blockchain.info.
//!
//! One lookup is one GET to blockchain.info's public `rawaddr` endpoint for a single address, asked
//! with `limit=0` so only the account summary comes back, not its transaction list. The address is
//! confirmed on-chain and enriched with its balance and lifetime totals, as Spiderfoot's
//! `sfp_blockchain` reports a `BITCOIN_BALANCE` for a `BITCOIN_ADDRESS`. Every figure is kept in
//! full: the human-readable BTC amount in the summary and the exact satoshi integer in the evidence.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport, percent_encode_component};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SOURCE: &str = "blockchain";
const HOST: &str = "https://blockchain.info/rawaddr/";

/// One satoshi is 1e-8 BTC.
const SATOSHIS_PER_BTC: u64 = 100_000_000;

/// Confidence of an address confirmed on-chain.
const ADDRESS_CONFIDENCE: f64 = 0.95;

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
}

/// The request URL for an address. **Pure.**
#[must_use]
pub fn url(address: &str) -> String {
    format!("{HOST}{}?limit=0", percent_encode_component(address))
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

    let Some(response) = fetched.response else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: fetched.outcome,
        });
    };
    Ok(interpret(&response, scan_id, now_unix))
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Turn one fetched response into a report. **Pure.**
fn interpret(response: &Response, scan_id: &str, now_unix: u64) -> Report {
    // blockchain.info answers an address it cannot parse or does not hold with a 4xx and a short
    // text body ("Address not found" / "Invalid Bitcoin Address"); both are clean negatives.
    if (400..500).contains(&response.status) {
        return miss(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status),
        );
    }
    if response.truncated {
        return miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "truncated blockchain.info response",
        ));
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            classified,
            Some(response.status),
            "blockchain.info response was not an account document",
        ));
    }

    let account: Account = match serde_json::from_slice(&response.body) {
        Ok(account) => account,
        Err(error) => {
            return miss(SourceExecutionOutcome::failed(
                SOURCE,
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                format!("blockchain.info JSON: {error}"),
            ));
        }
    };

    decode(&account, scan_id, now_unix, response.status)
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
    merge_by_uid(&mut entities);
    Report {
        entities,
        outcome: SourceExecutionOutcome::success(SOURCE, now_unix, 1).with_http_status(status),
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
    fn query_asks_only_the_account_summary() {
        assert!(url("1abc").starts_with("https://blockchain.info/rawaddr/1abc"));
        assert!(url("1abc").ends_with("?limit=0"));
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
}
