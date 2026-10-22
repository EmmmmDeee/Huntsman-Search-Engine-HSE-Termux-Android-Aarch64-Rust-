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
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_component};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

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
}
