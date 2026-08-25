//! Bitcoin wallet clustering from a public block explorer (Esplora API).
//!
//! Ported from the sibling `Huntsman-` repository during consolidation. The
//! parsing judgement — the CoinJoin guard and the case-sensitive dedup — is the
//! part worth carrying over verbatim; the trait wrapper is rewritten against
//! this crate's `Module` contract (`accepts`/`process`/`produces`), which the
//! source repository's simpler `is_enabled`/`execute` shape has no equivalent of.
//!
//! What it does: given a Bitcoin address, read its ledger activity and cluster
//! the wallet by **common-input-ownership** — when several addresses are spent
//! together as inputs to one transaction, one party controlled all of them.
//!
//! What it deliberately does NOT do, because each would fabricate a link
//! between two real people:
//!
//! * **Payment outputs are never clustered.** Sending coin to an address says
//!   nothing about who controls it.
//! * **CoinJoin-shaped transactions are skipped entirely.** Their inputs belong
//!   to different people *by design*, so the heuristic inverts there.
//! * **Coinbase inputs are ignored.** Newly-mined coin has no previous owner.
//!
//! The error direction is chosen throughout: a missed link, never a fabricated
//! one. For people-centric OSINT a wrong link between two real individuals is
//! far more damaging than a lead that was never surfaced.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "bitcoin";

/// Public Esplora instance. Keyless, which is why this module is not key-gated.
const API_BASE: &str = "https://blockstream.info/api";

/// Cap on co-spent addresses emitted for one target. A heavily-reused address
/// can co-spend with thousands; past a few dozen the marginal lead is worthless
/// and the frontier cost is not.
const MAX_COSPEND_ADDRESSES: usize = 50;

/// A CoinJoin needs several participants to be worth doing.
const COINJOIN_MIN_INPUTS: usize = 3;
/// ...and its signature is several outputs sharing one exact value.
const COINJOIN_MIN_EQUAL_OUTPUTS: usize = 3;

const SATS_PER_BTC: f64 = 100_000_000.0;

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct ChainStats {
    #[serde(default)]
    pub(super) funded_txo_sum: i64,
    #[serde(default)]
    pub(super) spent_txo_sum: i64,
    #[serde(default)]
    pub(super) tx_count: i64,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct AddressStats {
    #[serde(default)]
    pub(super) chain_stats: ChainStats,
    #[serde(default)]
    pub(super) mempool_stats: ChainStats,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct Prevout {
    #[serde(default)]
    pub(super) scriptpubkey_address: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct Vin {
    #[serde(default)]
    pub(super) prevout: Option<Prevout>,
    #[serde(default)]
    pub(super) is_coinbase: bool,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct Vout {
    #[serde(default)]
    pub(super) value: i64,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct Transaction {
    #[serde(default)]
    pub(super) txid: String,
    #[serde(default)]
    pub(super) vin: Vec<Vin>,
    #[serde(default)]
    pub(super) vout: Vec<Vout>,
}

/// Whether a transaction has the structural signature of a CoinJoin: several
/// inputs, and several outputs sharing one exact value.
///
/// In a CoinJoin the inputs belong to *different* people by design, so applying
/// common-input-ownership to one produces confident false attributions — the
/// single worst failure mode available to this module.
///
/// Pure and network-free, so the judgement is unit-testable on captured shapes.
/// Values are integer satoshis, so equality is exact with no float comparison.
fn looks_like_coinjoin(tx: &Transaction) -> bool {
    if tx.vin.len() < COINJOIN_MIN_INPUTS {
        return false;
    }
    // A BTreeMap keeps the scan deterministic. Data outputs (OP_RETURN, value 0)
    // are counted like any other, so a transaction with three or more of them is
    // treated as a CoinJoin and dropped — the error direction is the safe one.
    let mut by_value: std::collections::BTreeMap<i64, usize> = std::collections::BTreeMap::new();
    for out in &tx.vout {
        *by_value.entry(out.value).or_insert(0) += 1;
    }
    by_value.values().any(|&n| n >= COINJOIN_MIN_EQUAL_OUTPUTS)
}

/// Project the ledger reading and the transaction list onto entities.
///
/// Pure, network-free, deterministic and deduplicated: all parsing judgement
/// lives here so it is tested directly against captured responses rather than
/// through `process`. `target` is the queried address; it is excluded from its
/// own co-spend set, and its presence among a transaction's inputs is what makes
/// that transaction's other inputs attributable at all.
pub(super) fn build_entities(
    stats: &AddressStats,
    txs: &[Transaction],
    target: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut emitted = 0usize;

    // Esplora reports cumulative funded/spent sums rather than a balance, so the
    // balance is their difference. The mempool delta is reported separately: an
    // address being drained right now is exactly what an analyst wants to see.
    let confirmed = stats.chain_stats.funded_txo_sum - stats.chain_stats.spent_txo_sum;
    let pending = stats.mempool_stats.funded_txo_sum - stats.mempool_stats.spent_txo_sum;
    let tx_count = stats.chain_stats.tx_count + stats.mempool_stats.tx_count;

    // A never-used address is itself a real finding (a fresh or vanity address),
    // so this is emitted whatever the counts say.
    let summary = if pending != 0 {
        format!(
            "{tx_count} transactions, balance {:.8} BTC ({:+.8} BTC unconfirmed)",
            confirmed as f64 / SATS_PER_BTC,
            pending as f64 / SATS_PER_BTC,
        )
    } else {
        format!(
            "{tx_count} transactions, balance {:.8} BTC",
            confirmed as f64 / SATS_PER_BTC,
        )
    };

    // The queried address, confirmed on-chain, carrying its activity as evidence.
    let mut anchor = Entity::new(
        EntityKind::CryptoAddress,
        target,
        confidence::VERY_HIGH_PLUS,
        scan_id,
    );
    anchor.tag("bitcoin");
    anchor.tag("on-chain");
    anchor.add_evidence(
        Evidence::new(SRC, summary)
            .with_attr("tx_count", tx_count.to_string())
            .with_attr("balance_sats", confirmed.to_string()),
    );
    out.push(anchor);

    for tx in txs {
        if looks_like_coinjoin(tx) {
            continue;
        }
        let inputs: Vec<&str> = tx
            .vin
            .iter()
            // A coinbase input has no previous output and no address: newly mined
            // coin, not a spend, so it says nothing about who controls anything.
            .filter(|vin| !vin.is_coinbase)
            .filter_map(|vin| vin.prevout.as_ref()?.scriptpubkey_address.as_deref())
            .collect();

        // The heuristic applies only when the target is itself among the
        // spenders: that is what makes the co-signers *its* wallet rather than
        // two strangers who happen to appear in one transaction.
        if !inputs.contains(&target) {
            continue;
        }

        for addr in inputs {
            if addr == target {
                continue;
            }
            if emitted >= MAX_COSPEND_ADDRESSES {
                // Nothing further can be emitted, so stop scanning rather than
                // walking the remaining inputs and transactions to discard them.
                return out;
            }
            // Case-sensitive dedup is REQUIRED here. For base58check addresses
            // case is *data*, not presentation, so a case-folding key would
            // collapse two distinct addresses and drop a real sibling. The API
            // returns canonical spellings, so exact-match dedup is correct.
            if seen.insert(addr.to_string()) {
                let mut e = Entity::new(
                    EntityKind::CryptoAddress,
                    addr,
                    // Common-input-ownership is a strong but heuristic link, not
                    // a proof: it is defeated by a CoinJoin we failed to detect.
                    confidence::VERY_HIGH,
                    scan_id,
                );
                e.tag("bitcoin");
                e.tag("co-spend");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("co-spent with {target} (common-input-ownership)"),
                    )
                    .with_attr("txid", &tx.txid)
                    .with_attr("heuristic", "common-input-ownership"),
                );
                out.push(e);
                emitted += 1;
            }
        }
    }
    out
}

/// Bitcoin wallet clustering — see the module docs for the refusal rules
/// (CoinJoin, payment outputs, coinbase inputs) that make this safe to run.
pub struct Bitcoin;

impl Bitcoin {
    /// Whether this module can act on a value. The classifier accepts EVM `0x`
    /// addresses as `CryptoAddress` too, and querying a Bitcoin explorer for one
    /// is guaranteed nonsense, so they are declined here rather than sent
    /// upstream to produce a 400.
    fn handles_value(value: &str) -> bool {
        let v = value.trim();
        !v.is_empty() && !v.to_ascii_lowercase().starts_with("0x")
    }
}

#[async_trait]
impl Module for Bitcoin {
    fn name(&self) -> &'static str {
        "bitcoin"
    }

    fn description(&self) -> &'static str {
        "Bitcoin wallet clustering (Esplora, keyless) — ledger activity plus co-spent addresses by common-input-ownership, refusing CoinJoin-shaped transactions"
    }

    fn priority(&self) -> u8 {
        100
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::CryptoAddress) && Self::handles_value(&t.value)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1589 Gather Victim Identity Information — a wallet cluster is an
        // identity-linked financial surface.
        &["T1589"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::CryptoAddress];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let addr = target.value.trim();
        if !Self::handles_value(addr) {
            return Ok(ModuleResult::new());
        }
        let enc = crate::util::http::urlencode(addr);

        // Ledger reading first: an address with no transactions is still a
        // reportable finding, and this call is the cheap one.
        let stats: Option<AddressStats> =
            fetch_json_or_404(&ctx.http, SRC, &format!("{API_BASE}/address/{enc}")).await?;
        let Some(stats) = stats else {
            return Ok(ModuleResult::new());
        };

        // Transactions are a separate endpoint. A failure here must not discard
        // the ledger reading we already have, so an absent list degrades to "no
        // co-spends found" rather than to no result at all.
        let txs: Vec<Transaction> =
            fetch_json_or_404(&ctx.http, SRC, &format!("{API_BASE}/address/{enc}/txs"))
                .await?
                .unwrap_or_default();

        let mut result = ModuleResult::new();
        result.entities = build_entities(&stats, &txs, addr, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
