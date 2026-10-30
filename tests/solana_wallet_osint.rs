//! End-to-end offline contract: Solana mainnet-beta OSINT reaches the same crypto lookup used by
//! CLI, saved scans and the embedded Web UI without a proprietary backend, and persists with its
//! own `src/solana_rpc.rs` provenance, the token account's controllers included.

use huntsman_recon::crypto_cli::{self, CryptoRun};
use huntsman_recon::http::{Method, Request, Response, Transport, TransportFailure};
use huntsman_recon::lookup_modules;
use huntsman_recon::lookup_save::{self, CRYPTO_POLICY};
use huntsman_recon::module::reachable_modules;
use huntsman_recon::scan_route::{ScanKind, canonical_selector, infer_kind};
use huntsman_recon::solana_rpc;
use huntsman_recon::source_outcome::SourceOutcomeKind;

// Synthetic addresses ([0x77; 32], [0x22; 32], [0x33; 32]); USDC's public mint.
const TOKEN_ACCOUNT: &str = "sol:93MB2qRDNVLxbmmPuYpLdAqn3u2x9ZhaVZK5wELHueP8";
const OWNER: &str = "sol:3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
const DELEGATE: &str = "sol:4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4";
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
// A frozen SPL Token account of the USDC mint holding 1234567 base units, owned by OWNER, with
// DELEGATE approved for 500; the RPC lists no recent signature.
const SOLANA_ANSWER: &str = r#"[
    {"jsonrpc":"2.0","id":3,"result":[]},
    {"jsonrpc":"2.0","id":2,"result":{"context":{"apiVersion":"4.3.2","slot":463126351},"value":{"data":["xvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWEiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIofWEgAAAAAAAQAAADMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzAgAAAAAAAAAAAAAAAPQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","base64"],"executable":false,"lamports":2039280,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":18446744073709551615,"space":165}}},
    {"jsonrpc":"2.0","id":4,"result":462544720},
    {"jsonrpc":"2.0","id":1,"result":"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"}
]"#;

struct PublicSolanaOnly;

impl Transport for PublicSolanaOnly {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        assert_eq!(request.url, solana_rpc::RPC_URL);
        assert_eq!(request.method, Method::Post);
        let body = String::from_utf8(request.body.clone()).unwrap();
        for method in [
            "getGenesisHash",
            "getAccountInfo",
            "getSignaturesForAddress",
            "getFirstAvailableBlock",
        ] {
            assert!(body.contains(method), "{method}");
        }
        assert!(!body.contains("sendTransaction"));
        assert!(!body.contains("requestAirdrop"));
        Ok(Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: SOLANA_ANSWER.as_bytes().to_vec(),
            truncated: false,
        })
    }

    fn runs_module(&self, module: &str) -> bool {
        module == solana_rpc::SOURCE
    }
}

#[test]
fn solana_address_is_an_explicit_scan_selector_and_registered_public_source() {
    assert_eq!(infer_kind(TOKEN_ACCOUNT), ScanKind::CryptoAddress);
    assert_eq!(
        canonical_selector(ScanKind::CryptoAddress, TOKEN_ACCOUNT).as_deref(),
        Some(TOKEN_ACCOUNT)
    );
    assert!(lookup_modules::modules(ScanKind::CryptoAddress).contains(&solana_rpc::SOURCE));
    assert!(
        reachable_modules()
            .iter()
            .any(|module| module.name == solana_rpc::SOURCE
                && module.access == "keyless"
                && module.network)
    );
    assert_eq!(
        canonical_selector(ScanKind::CryptoAddress, USDC_MINT),
        None,
        "a bare base58 address is shared by every SVM chain and must not presume Solana"
    );
}

#[test]
fn saved_crypto_case_keeps_solana_provenance_and_the_token_accounts_controllers() {
    let (text, report) = match crypto_cli::run(&PublicSolanaOnly, TOKEN_ACCOUNT, 1_760_000_000) {
        CryptoRun::Printed { text, report } => (text, report),
        CryptoRun::Failed(error) | CryptoRun::Network(error) => panic!("{error}"),
    };
    assert!(text.contains(solana_rpc::SOURCE));
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].module, solana_rpc::SOURCE);
    assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
    let value = |raw: &str| {
        report
            .entities
            .iter()
            .find(|entity| entity.raw_value == raw)
            .unwrap_or_else(|| panic!("no {raw}"))
    };
    let account = &value(TOKEN_ACCOUNT).evidence[0].attributes;
    assert_eq!(account["account_class"], "token_account");
    assert_eq!(account["token_mint"], USDC_MINT);
    assert_eq!(account["token_account_state"], "frozen");
    assert_eq!(account["balance_sol"], "0.002039280");
    assert_eq!(
        value(OWNER).evidence[0].attributes["role"],
        "token_account_owner"
    );
    assert_eq!(
        value(DELEGATE).evidence[0].attributes["role"],
        "token_delegate"
    );
    assert_eq!(report.entities.len(), 3, "the shared mint is never a pivot");

    // The saved ledger attributes the evidence to solana_rpc's own canonical component, not the
    // crypto_cli default.
    let ledger = lookup_save::chain(&report.entities, &report.outcomes, CRYPTO_POLICY).unwrap();
    assert!(
        ledger
            .iter()
            .any(|entry| entry.claim.source == solana_rpc::SOURCE
                && entry.claim.component == "src/solana_rpc.rs")
    );
}

#[test]
fn no_selected_solana_module_means_no_network_or_false_success() {
    struct NoneSelected;
    impl Transport for NoneSelected {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            panic!("no Solana request should be made when its source is not selected")
        }
        fn runs_module(&self, _module: &str) -> bool {
            false
        }
    }
    assert!(matches!(
        crypto_cli::run(&NoneSelected, TOKEN_ACCOUNT, 1),
        CryptoRun::Failed(_)
    ));
}
