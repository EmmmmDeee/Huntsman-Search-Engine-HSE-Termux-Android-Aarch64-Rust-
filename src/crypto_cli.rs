//! Shared crypto front-end: Bitcoin address summaries and explicitly prefixed Base
//! mainnet account snapshots, both routed through CLI, saved scans and Web UI.

use std::path::PathBuf;

use crate::base_rpc;
use crate::blockchain;
use crate::canonical::canonical_bitcoin_address;
use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::eth_rpc;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const CRYPTO_USAGE: &str =
    "usage: huntsman-recon crypto BITCOIN-ADDRESS|base:0xADDRESS|eth:0xADDRESS [--save FILE]";
pub const CRYPTO_HELP: &str = "\
crypto BITCOIN-ADDRESS|base:0xADDRESS|eth:0xADDRESS [--save FILE]
Bitcoin: balance, lifetime received/sent and transaction count from blockchain.info, and from its 20 most recent transactions the first and last transaction times and every address it transacted with, by role: paid_by (paid it), paid_to (it paid) or co_input (spent together with it, the common-input heuristic), each with the transaction, its time and block and the exact satoshis. Sharing a transaction is not common ownership: CoinJoin and payjoin break the co-input heuristic and an exchange address links unrelated users, so no wallet owner is identified. Base: 40-hex-digit EVM address explicitly prefixed base:, with finalized balance in exact wei, outgoing nonce and contract-code presence via the rate-limited public Base JSON-RPC. Ethereum: the same for a 40-hex-digit address explicitly prefixed eth:, with finalized balance in exact wei, outgoing nonce and contract-code presence via the rate-limited public Ethereum mainnet JSON-RPC. No keys, full transaction history or ownership assertion. --save FILE writes an unverified ledger; verify can reload it. Makes network requests.";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoArgs {
    pub address: String,
    pub save: Option<PathBuf>,
}

impl CryptoArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] for a value that
    /// is not a Bitcoin mainnet address.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(
            args,
            "crypto needs exactly one Bitcoin, Base or Ethereum address",
        )?;
        let address = canonical_address(&raw)?;
        Ok(Self { address, save })
    }
}

pub type CryptoRun = SourceRun<Report>;

/// `raw` as the lookup keys on a Bitcoin address.
///
/// # Errors
/// [`Error::InvalidValue`] for a value that is not a Bitcoin mainnet address.
pub fn canonical_address(raw: &str) -> Result<String, Error> {
    canonical_bitcoin_address(raw)
        .or_else(|| base_rpc::canonical_selector(raw))
        .or_else(|| eth_rpc::canonical_selector(raw))
        .ok_or_else(|| {
            Error::invalid_value(
                "expected Bitcoin mainnet address, base:0x or eth:0x plus 40 hex digits",
            )
        })
}

/// Look up `address`, the blockchain leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, address: &str, now_unix: u64) -> CryptoRun {
    let address = match canonical_address(address) {
        Ok(address) => address,
        Err(error) => return CryptoRun::Failed(error.to_string()),
    };
    let scan_id = crate::entity::scan_id("crypto", &address);
    let mut report = Report::default();

    if address.starts_with("base:") && transport.runs_module(base_rpc::SOURCE) {
        match base_rpc::lookup(transport, &address, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return CryptoRun::Network(error.to_string()),
        }
    } else if address.starts_with("eth:") && transport.runs_module(eth_rpc::SOURCE) {
        match eth_rpc::lookup(transport, &address, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return CryptoRun::Network(error.to_string()),
        }
    } else if !address.starts_with("base:")
        && !address.starts_with("eth:")
        && transport.runs_module(blockchain::SOURCE)
    {
        match blockchain::lookup(transport, &address, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return CryptoRun::Network(error.to_string()),
        }
    }
    merge_by_uid(&mut report.entities);

    if !report
        .outcomes
        .iter()
        .any(|outcome| outcome.kind.is_accepted())
    {
        return CryptoRun::Failed(format!("no source answered for {address}"));
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => CryptoRun::Printed { text, report },
        Err(message) => CryptoRun::Failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keys;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::OneResponse;

    #[test]
    fn parses_address_and_save() {
        let parsed = CryptoArgs::parse(&[
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(),
            "--save".into(),
            "out.json".into(),
        ])
        .unwrap();
        assert_eq!(parsed.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(parsed.save, Some(PathBuf::from("out.json")));
    }

    #[test]
    fn rejects_non_bitcoin_selectors() {
        // A bare EVM address is ambiguous across chains; only base: is supported.
        assert!(CryptoArgs::parse(&["0x0000000000000000000000000000000000000000".into()]).is_err());
        assert!(
            CryptoArgs::parse(&["base:0x0000000000000000000000000000000000000000".into()]).is_ok()
        );
        assert!(CryptoArgs::parse(&["not-an-address".into()]).is_err());
        let _ = Keys::default();
    }

    #[test]
    fn run_reports_the_on_chain_balance() {
        let body = r#"{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","n_tx":67080,"total_received":10769281547,"total_sent":0,"final_balance":10769281547}"#;
        match run(
            &OneResponse::json(200, body),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            1,
        ) {
            CryptoRun::Printed { text, report } => {
                assert!(text.contains("blockchain\tsuccess"), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.raw_value == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
                );
            }
            CryptoRun::Network(why) | CryptoRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn an_invalid_selector_fails_without_network() {
        match run(&OneResponse::json(200, "{}"), "nonsense", 1) {
            CryptoRun::Failed(_) => {}
            other => panic!(
                "expected a failure, got {}",
                matches!(other, CryptoRun::Printed { .. })
            ),
        }
    }

    #[test]
    fn an_unknown_address_still_prints_its_clean_negative() {
        match run(
            &OneResponse::json(404, "Address not found"),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            1,
        ) {
            CryptoRun::Printed { report, .. } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
            }
            CryptoRun::Network(why) | CryptoRun::Failed(why) => panic!("{why}"),
        }
    }
}
