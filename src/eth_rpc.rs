//! Keyless, read-only Ethereum mainnet account observations via a public JSON-RPC.
//!
//! A thin per-chain wrapper over the shared [`crate::evm_rpc`] core: this module owns only
//! Ethereum mainnet's fixed identity ([`CHAIN`]); the batch, fail-closed decoding and provenance
//! live once in `evm_rpc`. One bounded batch reads the finalized account balance, outgoing nonce,
//! and contract-code presence. An address is not a verified identity; zero balances do not
//! establish absence of past activity. The public RPC is rate-limited and cannot enumerate a full
//! transaction history.

use crate::error::Error;
use crate::evm_rpc::{self, Chain};
use crate::http::{Request, Transport};

pub use crate::evm_rpc::Report;

pub const SOURCE: &str = "eth_rpc";
pub const RPC_URL: &str = "https://ethereum-rpc.publicnode.com";
pub const CHAIN_ID: u64 = 1;

/// Ethereum mainnet's fixed identity for the shared EVM-RPC core.
pub const CHAIN: Chain = Chain {
    source: SOURCE,
    display: "Ethereum RPC",
    network_human: "Ethereum mainnet",
    network_attr: "ethereum_mainnet",
    rpc_url: RPC_URL,
    chain_id: CHAIN_ID,
    prefix: "eth:",
    explorer_prefix: "https://etherscan.io/address/",
    tags: &["ethereum", "evm", "public_rpc", "ownership_unverified"],
};

/// Explicit Ethereum selector. A bare 0x-address is intentionally ambiguous across EVM chains and
/// is never silently routed to Ethereum mainnet.
#[must_use]
pub fn canonical_selector(raw: &str) -> Option<String> {
    evm_rpc::canonical_selector(&CHAIN, raw)
}

/// Fixed, non-mutating Ethereum mainnet RPC batch request.
#[must_use]
pub fn request(address: &str) -> Option<Request> {
    evm_rpc::request(&CHAIN, address)
}

/// Read Ethereum mainnet account state without indexing services, authentication or transfers.
///
/// # Errors
/// Returns guarded network-boundary errors without converting them into a negative account finding.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    selector: &str,
    scan_id: &str,
    now: u64,
) -> Result<Report, Error> {
    evm_rpc::lookup(&CHAIN, transport, selector, scan_id, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::OneResponse;
    use serde_json::Value;

    const WALLET: &str = "eth:0x1111111111111111111111111111111111111111";
    // chainId 0x1 = 1; balance 1e18 wei; nonce 0x2a; non-empty code.
    const BATCH: &str = r#"[
        {"jsonrpc":"2.0","id":3,"result":"0x2a"},
        {"jsonrpc":"2.0","id":1,"result":"0x1"},
        {"jsonrpc":"2.0","id":4,"result":"0x6000"},
        {"jsonrpc":"2.0","id":2,"result":"0xde0b6b3a7640000"}
    ]"#;

    #[test]
    fn selection_is_explicit_and_rejects_ambiguous_or_foreign_chain_selector() {
        assert_eq!(canonical_selector(WALLET).as_deref(), Some(WALLET));
        assert_eq!(canonical_selector(&WALLET.to_uppercase()), None);
        for candidate in [
            "0x1111111111111111111111111111111111111111",
            "base:0x1111111111111111111111111111111111111111",
            "eth:0x111",
            "eth:0x111111111111111111111111111111111111111g",
            "eth:0x1111111111111111111111111111111111111111\n",
        ] {
            assert!(canonical_selector(candidate).is_none(), "{candidate}");
        }
    }

    #[test]
    fn request_posts_the_keyless_batch_to_ethereum_mainnet() {
        let request = request(WALLET).unwrap();
        assert_eq!(request.url, RPC_URL);
        assert_eq!(request.method, crate::http::Method::Post);
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 4);
        assert!(
            rows.iter()
                .all(|row| row["method"].as_str().unwrap().starts_with("eth_"))
        );
        assert!(
            rows.iter()
                .all(|row| !row.to_string().contains("privateKey"))
        );
    }

    #[test]
    fn lookup_yields_ethereum_provenance_without_claiming_ownership() {
        let found = lookup(&OneResponse::json(200, BATCH), WALLET, "scan", 1).unwrap();
        assert_eq!(found.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(found.entities.len(), 1);
        let evidence = &found.entities[0].evidence[0];
        assert_eq!(
            evidence.attributes.get("balance_wei").unwrap(),
            "1000000000000000000"
        );
        assert_eq!(evidence.attributes["network"], "ethereum_mainnet");
        assert_eq!(evidence.attributes["chain_id"], "1");
        assert_eq!(
            evidence.attributes["explorer_url"],
            "https://etherscan.io/address/0x1111111111111111111111111111111111111111"
        );
        assert!(found.entities[0].has_tag("ethereum"));
        assert!(evidence.attributes["does_not_show"].contains("ownership"));
    }

    #[test]
    fn an_ethereum_reply_for_the_wrong_chain_is_not_evidence() {
        // A Base (0x2105) reply to an Ethereum request must never be admitted as ETH evidence.
        let body = BATCH.replace(r#""id":1,"result":"0x1""#, r#""id":1,"result":"0x2105""#);
        let result = lookup(&OneResponse::json(200, &body), WALLET, "scan", 1).unwrap();
        assert!(result.entities.is_empty());
        assert!(!result.outcome.kind.is_accepted());
    }
}
