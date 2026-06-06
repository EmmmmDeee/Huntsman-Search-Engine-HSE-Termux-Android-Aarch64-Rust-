//! On-chain enrichment for cryptocurrency wallet addresses — free, no credential.
//!
//! Closes the loop opened by `EntityKind::CryptoAddress`: addresses surfaced in
//! breach/stealer data (clipboard-hijacker malware harvests these in volume) or
//! pasted as a seed are now *enriched* with their on-chain activity, not left as
//! dead-end leads.
//!
//! Sources (both free, keyless, no rate-limit billing):
//!   * BTC — `https://blockstream.info/api/address/<addr>` (Esplora)
//!   * ETH/EVM — `https://eth.blockscout.com/api?module=account&action=balance`
//!
//! Other chains (LTC/DOGE/SOL/XMR) are recognised by the classifier but have no
//! wired free keyless explorer yet, so the module returns cleanly for them
//! rather than guessing. The enrichment is OSINT-grade triage: is this wallet
//! real, funded, and active? — emitted as evidence + an `active`/`dormant` tag
//! on the address entity. One or two small JSON GETs; Termux-friendly.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    crypto::{chain_label, classify_crypto_address},
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

const SRC: &str = "chain_intel";

pub struct ChainIntel;

/// Esplora (`blockstream.info`) address response: confirmed + mempool stats.
#[derive(Deserialize, Default)]
#[serde(default)]
struct EsploraAddress {
    chain_stats: EsploraStats,
    mempool_stats: EsploraStats,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct EsploraStats {
    funded_txo_sum: i64,
    spent_txo_sum: i64,
    tx_count: u64,
}

/// Blockscout `account/balance` response (`result` is wei, as a string).
#[derive(Deserialize, Default)]
#[serde(default)]
struct BlockscoutBalance {
    result: String,
}

#[async_trait]
impl Module for ChainIntel {
    fn name(&self) -> &'static str {
        "chain_intel"
    }

    fn description(&self) -> &'static str {
        "Cryptocurrency wallet enrichment — on-chain balance & activity (BTC/ETH, free)"
    }

    fn priority(&self) -> u8 {
        90
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::CryptoAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::CryptoAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let addr = target.value.trim();
        let Some(chain) = classify_crypto_address(addr) else {
            return Ok(result); // not a recognised address shape
        };

        let enriched = match chain {
            "crypto_btc" => enrich_btc(ctx, addr).await,
            "crypto_eth" => enrich_eth(ctx, addr).await,
            // Recognised but no free keyless explorer wired — clean no-op.
            _ => None,
        };

        if let Some(ev) = enriched {
            let mut e = Entity::new(EntityKind::CryptoAddress, addr, 0.80, &ctx.scan_id);
            e.tag("crypto-address");
            e.tag(format!("chain:{}", chain_label(chain)));
            e.add_evidence(ev);
            result.push(e);
        }
        Ok(result)
    }
}

/// Format satoshis (or wei) as a decimal coin amount with `decimals` places,
/// without floating-point error (balances can exceed f64's exact-integer range).
/// Pure, so it is unit-tested.
fn format_units(amount: u128, decimals: u32) -> String {
    let scale = 10u128.pow(decimals);
    let whole = amount / scale;
    let frac = amount % scale;
    // Trim trailing zeros from the fractional part for readability.
    let frac_str = format!("{frac:0width$}", width = decimals as usize);
    let frac_trimmed = frac_str.trim_end_matches('0');
    if frac_trimmed.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac_trimmed}")
    }
}

/// Build the enrichment evidence shared shape: balance, total received, tx
/// count, and an activity verdict. Pure (no I/O) for unit testing.
fn build_evidence(
    chain: &str,
    unit: &str,
    received: u128,
    balance: u128,
    decimals: u32,
    tx_count: u64,
) -> Evidence {
    let activity = if tx_count == 0 { "dormant" } else { "active" };
    Evidence::new(SRC, format!("{chain} on-chain activity: {activity}"))
        .with_attr("chain", chain)
        .with_attr(
            "balance",
            format!("{} {unit}", format_units(balance, decimals)),
        )
        .with_attr(
            "total_received",
            format!("{} {unit}", format_units(received, decimals)),
        )
        .with_attr("tx_count", tx_count.to_string())
        .with_attr("activity", activity)
}

async fn enrich_btc(ctx: &ModuleContext, addr: &str) -> Option<Evidence> {
    let url = format!("https://blockstream.info/api/address/{addr}");
    let a: EsploraAddress = fetch_json(&ctx.http, SRC, &url).await.ok()?;
    let received = a.chain_stats.funded_txo_sum.max(0) as u128;
    let spent = a.chain_stats.spent_txo_sum.max(0) as u128;
    let balance = received.saturating_sub(spent);
    let tx_count = a.chain_stats.tx_count + a.mempool_stats.tx_count;
    // Satoshis → BTC (8 decimals).
    Some(build_evidence("btc", "BTC", received, balance, 8, tx_count))
}

async fn enrich_eth(ctx: &ModuleContext, addr: &str) -> Option<Evidence> {
    let url =
        format!("https://eth.blockscout.com/api?module=account&action=balance&address={addr}");
    let b: BlockscoutBalance = fetch_json(&ctx.http, SRC, &url).await.ok()?;
    let wei: u128 = b.result.trim().parse().ok()?;
    // Blockscout's balance endpoint reports the current balance only; total
    // received / tx count would need a second heavier call, so report balance
    // and mark activity by whether the balance is non-zero.
    let tx_count = u64::from(wei > 0);
    // Wei → ETH (18 decimals).
    Some(build_evidence("eth", "ETH", wei, wei, 18, tx_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_units_handles_btc_and_eth_scales() {
        // 1.5 BTC in satoshis.
        assert_eq!(format_units(150_000_000, 8), "1.5");
        // Exactly 1 BTC — no trailing fraction.
        assert_eq!(format_units(100_000_000, 8), "1");
        // Dust.
        assert_eq!(format_units(1, 8), "0.00000001");
        assert_eq!(format_units(0, 8), "0");
        // 2.5 ETH in wei (18 decimals) — exceeds f64 exact-int range, so the
        // integer path matters.
        assert_eq!(format_units(2_500_000_000_000_000_000, 18), "2.5");
    }

    #[test]
    fn build_evidence_marks_activity_and_formats_amounts() {
        // A funded, active BTC wallet: received 2 BTC, spent 0.5 (balance 1.5).
        let ev = build_evidence("btc", "BTC", 200_000_000, 150_000_000, 8, 7);
        let g = |k: &str| ev.attributes.get(k).cloned().unwrap_or_default();
        assert_eq!(g("chain"), "btc");
        assert_eq!(g("balance"), "1.5 BTC");
        assert_eq!(g("total_received"), "2 BTC");
        assert_eq!(g("tx_count"), "7");
        assert_eq!(g("activity"), "active");

        // A never-used address is dormant.
        let ev0 = build_evidence("btc", "BTC", 0, 0, 8, 0);
        assert_eq!(ev0.attributes.get("activity").unwrap(), "dormant");
    }

    #[test]
    fn accepts_only_crypto_address() {
        assert!(ChainIntel.accepts(&Target::new(TargetKind::CryptoAddress, "x")));
        assert!(!ChainIntel.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
}
