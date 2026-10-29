//! End-to-end offline contract: Ethereum mainnet OSINT reaches the same crypto lookup used
//! by CLI, saved scans, and the embedded Web UI without a proprietary backend, over the shared
//! `evm_rpc` core, and persists with its own `src/eth_rpc.rs` provenance.

use huntsman_recon::crypto_cli::{self, CryptoRun};
use huntsman_recon::eth_rpc;
use huntsman_recon::http::{Method, Request, Response, Transport, TransportFailure};
use huntsman_recon::lookup_modules;
use huntsman_recon::lookup_save::{self, CRYPTO_POLICY};
use huntsman_recon::module::reachable_modules;
use huntsman_recon::scan_route::{ScanKind, canonical_selector, infer_kind};
use huntsman_recon::source_outcome::SourceOutcomeKind;

const WALLET: &str = "eth:0x1111111111111111111111111111111111111111";
// chainId 0x1 = Ethereum mainnet; balance 1e18 wei; outgoing nonce 7; no contract code.
const ETH_ANSWER: &str = r#"[
    {"jsonrpc":"2.0","id":4,"result":"0x"},
    {"jsonrpc":"2.0","id":2,"result":"0xde0b6b3a7640000"},
    {"jsonrpc":"2.0","id":1,"result":"0x1"},
    {"jsonrpc":"2.0","id":3,"result":"0x7"}
]"#;

struct PublicEthOnly;

impl Transport for PublicEthOnly {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        assert_eq!(request.url, eth_rpc::RPC_URL);
        assert_eq!(request.method, Method::Post);
        let body = String::from_utf8(request.body.clone()).unwrap();
        assert!(body.contains("eth_chainId"));
        assert!(body.contains("eth_getBalance"));
        assert!(body.contains("eth_getTransactionCount"));
        assert!(body.contains("eth_getCode"));
        assert!(!body.contains("eth_send"));
        Ok(Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: ETH_ANSWER.as_bytes().to_vec(),
            truncated: false,
        })
    }

    fn runs_module(&self, module: &str) -> bool {
        module == eth_rpc::SOURCE
    }
}

#[test]
fn ethereum_wallet_is_an_explicit_scan_selector_and_registered_public_source() {
    assert_eq!(infer_kind(WALLET), ScanKind::CryptoAddress);
    assert_eq!(
        canonical_selector(ScanKind::CryptoAddress, WALLET).as_deref(),
        Some(WALLET)
    );
    assert!(lookup_modules::modules(ScanKind::CryptoAddress).contains(&eth_rpc::SOURCE));
    assert!(
        reachable_modules()
            .iter()
            .any(|module| module.name == eth_rpc::SOURCE
                && module.access == "keyless"
                && module.network)
    );
    assert_eq!(
        canonical_selector(
            ScanKind::CryptoAddress,
            "0x1111111111111111111111111111111111111111"
        ),
        None,
        "a bare EVM selector must not silently presume Ethereum"
    );
}

#[test]
fn saved_crypto_case_uses_public_eth_rpc_provenance_and_exact_wei() {
    let (text, report) = match crypto_cli::run(&PublicEthOnly, WALLET, 1_760_000_000) {
        CryptoRun::Printed { text, report } => (text, report),
        CryptoRun::Failed(error) | CryptoRun::Network(error) => panic!("{error}"),
    };
    assert!(text.contains(eth_rpc::SOURCE));
    assert_eq!(report.outcomes.len(), 1);
    assert_eq!(report.outcomes[0].module, eth_rpc::SOURCE);
    assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
    assert_eq!(report.entities.len(), 1);
    let entity = &report.entities[0];
    assert_eq!(entity.raw_value, WALLET);
    assert_eq!(
        entity.evidence[0].attributes.get("balance_wei").unwrap(),
        "1000000000000000000"
    );
    assert_eq!(
        entity.evidence[0].attributes.get("outgoing_nonce").unwrap(),
        "7"
    );
    assert_eq!(
        entity.evidence[0].attributes.get("code_presence").unwrap(),
        "no_code_at_finalized_block"
    );
    assert_eq!(
        entity.evidence[0].attributes.get("network").unwrap(),
        "ethereum_mainnet"
    );

    // The saved ledger must attribute the evidence to eth_rpc's own canonical component, not the
    // crypto_cli default — the fix that wires eth_rpc into lookup_save::crypto_provenance.
    let ledger = lookup_save::chain(&report.entities, &report.outcomes, CRYPTO_POLICY).unwrap();
    assert!(
        ledger
            .iter()
            .any(|entry| entry.claim.source == eth_rpc::SOURCE
                && entry.claim.component == "src/eth_rpc.rs")
    );
}

#[test]
fn no_selected_ethereum_module_means_no_network_or_false_success() {
    struct NoneSelected;
    impl Transport for NoneSelected {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            panic!("no Ethereum request should be made when its source is not selected")
        }
        fn runs_module(&self, _module: &str) -> bool {
            false
        }
    }
    assert!(matches!(
        crypto_cli::run(&NoneSelected, WALLET, 1),
        CryptoRun::Failed(_)
    ));
}
