//! End-to-end front-end for `huntsman-recon crypto` and the crypto arm of `scan`: one Bitcoin
//! address, Spiderfoot's `BITCOIN_ADDRESS` target, enriched with its on-chain balance and totals.

use std::path::PathBuf;

use crate::blockchain;
use crate::canonical::canonical_bitcoin_address;
use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const CRYPTO_USAGE: &str = "usage: huntsman-recon crypto BITCOIN-ADDRESS [--save FILE]";
pub const CRYPTO_HELP: &str = "\
crypto BITCOIN-ADDRESS [--save FILE]
Look up one Bitcoin address: its balance, lifetime received and sent totals and transaction count, confirmed on-chain and keyless from blockchain.info. Base58 (1…, 3…) and bech32 (bc1…) mainnet addresses are accepted. --save FILE writes an unverified ledger that verify can reload. Makes network requests.";

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
        let (raw, save) = LookupTokens::single(args, "crypto needs exactly one Bitcoin address")?;
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
        .ok_or_else(|| Error::invalid_value("not a Bitcoin mainnet address (1…, 3… or bc1…)"))
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

    if transport.runs_module(blockchain::SOURCE) {
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
        // An Ethereum address is a crypto address but not one this lookup can resolve.
        assert!(CryptoArgs::parse(&["0x0000000000000000000000000000000000000000".into()]).is_err());
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
