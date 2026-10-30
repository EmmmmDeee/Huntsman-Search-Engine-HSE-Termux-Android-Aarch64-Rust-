//! Shared crypto front-end: Bitcoin address summaries and explicitly prefixed Base, Ethereum
//! and Solana mainnet account snapshots, all routed through CLI, saved scans and Web UI.

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
use crate::solana_rpc;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const CRYPTO_USAGE: &str = "usage: huntsman-recon crypto BITCOIN-ADDRESS|base:0xADDRESS|eth:0xADDRESS|sol:ADDRESS [--save FILE]";
pub const CRYPTO_HELP: &str = "\
crypto BITCOIN-ADDRESS|base:0xADDRESS|eth:0xADDRESS|sol:ADDRESS [--save FILE]
Bitcoin: balance, lifetime received/sent and transaction count from blockchain.info, and from its 20 most recent transactions the first and last transaction times and every address it transacted with, by role: paid_by (paid it), paid_to (it paid) or co_input (spent together with it, the common-input heuristic), each with the transaction, its time and block and the exact satoshis. Sharing a transaction is not common ownership: CoinJoin and payjoin break the co-input heuristic and an exchange address links unrelated users, so no wallet owner is identified. Base: 40-hex-digit EVM address explicitly prefixed base:, with finalized balance in exact wei, outgoing nonce and contract-code presence via the rate-limited public Base JSON-RPC. Ethereum: the same for a 40-hex-digit address explicitly prefixed eth:, with finalized balance in exact wei, outgoing nonce and contract-code presence via the rate-limited public Ethereum mainnet JSON-RPC. Solana: a base58 address explicitly prefixed sol:, read at finalized commitment via the rate-limited public Solana mainnet-beta JSON-RPC once its genesis hash confirms the cluster: exact lamports and SOL, owner program and account class (native SOL account, token account, mint, program), an SPL token account's mint, raw amount, frozen state and the wallet that owns it with any delegate or close authority, a mint's supply, decimals and mint and freeze authorities, a multisig's required count and signers (each controlling address a sol: pivot), and each of the newest transactions naming the address that the node still holds with its signature, slot, time, error and memo verbatim: any transaction that names the address, whoever signed it, so a listed time, failure or memo is not the address's own act. Token accounts the address owns are not searched. No account and no listed transaction is a clean zero; with no account, an unread transaction list is inconclusive, never a zero. No keys, full transaction history or ownership assertion. --save FILE writes an unverified ledger; verify can reload it. Makes network requests.";

/// The chains a crypto lookup reaches. Every match on it is exhaustive, so a chain cannot be added
/// without its module, its selector rule and its lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    Bitcoin,
    Base,
    Ethereum,
    Solana,
}

/// The chains asked for by an explicit selector prefix. A bare address is Bitcoin's; every other
/// chain is named by its prefix, never inferred, and a selector no chain here accepts is refused
/// rather than sent to Bitcoin's source.
const PREFIXED: [Chain; 3] = [Chain::Base, Chain::Ethereum, Chain::Solana];

impl Chain {
    /// The one module that looks this chain's addresses up.
    const fn module(self) -> &'static str {
        match self {
            Self::Bitcoin => blockchain::SOURCE,
            Self::Base => base_rpc::SOURCE,
            Self::Ethereum => eth_rpc::SOURCE,
            Self::Solana => solana_rpc::SOURCE,
        }
    }

    /// `raw` as this chain's canonical selector, or `None`. **Pure.**
    fn canonical(self, raw: &str) -> Option<String> {
        match self {
            Self::Bitcoin => canonical_bitcoin_address(raw),
            Self::Base => base_rpc::canonical_selector(raw),
            Self::Ethereum => eth_rpc::canonical_selector(raw),
            Self::Solana => solana_rpc::canonical_selector(raw),
        }
    }

    /// The chain a canonical address belongs to: the prefixed chain whose selector it is, else
    /// Bitcoin. **Pure.**
    fn of(address: &str) -> Self {
        PREFIXED
            .into_iter()
            .find(|chain| chain.canonical(address).is_some())
            .unwrap_or(Self::Bitcoin)
    }
}

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
            "crypto needs exactly one Bitcoin, Base, Ethereum or Solana address",
        )?;
        let address = canonical_address(&raw)?;
        Ok(Self { address, save })
    }
}

pub type CryptoRun = SourceRun<Report>;

/// `raw` as an explicitly prefixed Base, Ethereum or Solana selector: the one rule the crypto
/// lookup and scan inference share, so a prefixed chain is never guessed from a bare address.
/// **Pure.**
#[must_use]
pub fn prefixed_selector(raw: &str) -> Option<String> {
    PREFIXED.into_iter().find_map(|chain| chain.canonical(raw))
}

/// `raw` as the lookup keys on a Bitcoin address or a prefixed chain selector.
///
/// # Errors
/// [`Error::InvalidValue`] for a value that is neither a Bitcoin mainnet address nor a prefixed
/// Base, Ethereum or Solana selector.
pub fn canonical_address(raw: &str) -> Result<String, Error> {
    Chain::Bitcoin
        .canonical(raw)
        .or_else(|| prefixed_selector(raw))
        .ok_or_else(|| {
            Error::invalid_value(
                "expected Bitcoin mainnet address, base:0x or eth:0x plus 40 hex digits, or sol: plus a base58 Solana address",
            )
        })
}

/// Look up `address` on its chain's leg, only when the transport's lookup asks that module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, address: &str, now_unix: u64) -> CryptoRun {
    let address = match canonical_address(address) {
        Ok(address) => address,
        Err(error) => return CryptoRun::Failed(error.to_string()),
    };
    let scan_id = crate::entity::scan_id("crypto", &address);
    let mut report = Report::default();

    let chain = Chain::of(&address);
    if transport.runs_module(chain.module()) {
        let found = match chain {
            Chain::Bitcoin => blockchain::lookup(transport, &address, &scan_id, now_unix)
                .map(|found| (found.entities, found.outcome)),
            Chain::Base => base_rpc::lookup(transport, &address, &scan_id, now_unix)
                .map(|found| (found.entities, found.outcome)),
            Chain::Ethereum => eth_rpc::lookup(transport, &address, &scan_id, now_unix)
                .map(|found| (found.entities, found.outcome)),
            Chain::Solana => solana_rpc::lookup(transport, &address, &scan_id, now_unix)
                .map(|found| (found.entities, found.outcome)),
        };
        match found {
            Ok((entities, outcome)) => {
                report.entities.extend(entities);
                report.outcomes.push(outcome);
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
    fn each_selector_routes_to_exactly_its_chains_module() {
        let solana = "sol:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        for (address, chain, module) in [
            (
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                Chain::Bitcoin,
                blockchain::SOURCE,
            ),
            (
                "base:0x1111111111111111111111111111111111111111",
                Chain::Base,
                base_rpc::SOURCE,
            ),
            (
                "eth:0x1111111111111111111111111111111111111111",
                Chain::Ethereum,
                eth_rpc::SOURCE,
            ),
            (solana, Chain::Solana, solana_rpc::SOURCE),
        ] {
            let canonical = canonical_address(address).expect(address);
            assert_eq!(canonical, address);
            assert_eq!(Chain::of(&canonical), chain, "{address}");
            assert_eq!(chain.module(), module, "{address}");
        }
        // Every prefixed chain is reachable, and only through its own selector rule.
        for chain in PREFIXED {
            assert_ne!(chain, Chain::Bitcoin);
            assert_ne!(chain.module(), blockchain::SOURCE);
        }
        assert_eq!(prefixed_selector(solana).as_deref(), Some(solana));
        // A bare Solana address is shared by every SVM chain, so it is never routed to one.
        assert!(canonical_address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").is_err());
        assert!(prefixed_selector("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_none());
    }

    #[test]
    fn a_solana_selector_asks_only_the_solana_leg() {
        struct SolanaOnly;
        impl Transport for SolanaOnly {
            fn send(
                &self,
                request: &crate::http::Request,
            ) -> Result<crate::http::Response, crate::http::TransportFailure> {
                assert_eq!(request.url, solana_rpc::RPC_URL);
                let body = format!(
                    r#"[{{"jsonrpc":"2.0","id":1,"result":"{}"}},{{"jsonrpc":"2.0","id":2,"result":{{"context":{{"slot":7}},"value":{{"data":["","base64"],"executable":false,"lamports":2500000000,"owner":"11111111111111111111111111111111","space":0}}}}}},{{"jsonrpc":"2.0","id":3,"result":[]}},{{"jsonrpc":"2.0","id":4,"result":1}}]"#,
                    solana_rpc::MAINNET_GENESIS_HASH
                );
                Ok(crate::http::Response {
                    status: 200,
                    headers: vec![("content-type".into(), "application/json".into())],
                    body: body.into_bytes(),
                    truncated: false,
                })
            }
            fn runs_module(&self, module: &str) -> bool {
                module == solana_rpc::SOURCE
            }
        }
        let address = "sol:29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
        match run(&SolanaOnly, address, 1) {
            CryptoRun::Printed { text, report } => {
                assert!(text.contains("solana_rpc\tsuccess"), "{text}");
                assert_eq!(report.outcomes.len(), 1);
                assert_eq!(report.entities[0].raw_value, address);
                assert_eq!(
                    report.entities[0].evidence[0].attributes["balance_sol"],
                    "2.500000000"
                );
            }
            CryptoRun::Network(why) | CryptoRun::Failed(why) => panic!("{why}"),
        }
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
