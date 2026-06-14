//! On-chain enrichment for cryptocurrency wallet addresses — free, no credential.
//!
//! Closes the loop opened by `EntityKind::CryptoAddress`: addresses surfaced in
//! breach/stealer data (clipboard-hijacker malware harvests these in volume) or
//! pasted as a seed are *enriched* with their on-chain activity, not left as
//! dead-end leads.
//!
//! Sources (all free, keyless, no rate-limit billing):
//!   * BTC / LTC — Esplora (`blockstream.info` / `litecoinspace.org`):
//!     confirmed + mempool stats → balance, total received, tx count.
//!   * ETH/EVM — Blockscout v2 (`eth.blockscout.com`): balance, tx count, and
//!     the reverse **ENS name** when set — an EVM address → human handle edge
//!     that feeds the username/identity graph.
//!
//! Honesty is a hard requirement: an evidence field is emitted only when the
//! source actually provides it (e.g. ETH reports no "total received" cheaply, so
//! that attribute is simply absent rather than faked). DOGE/SOL/XMR are
//! recognised by the classifier but have no wired free keyless explorer, so the
//! module returns cleanly for them. One-to-two small JSON GETs; Termux-friendly.

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

/// Esplora address response (`blockstream.info`, `litecoinspace.org`): confirmed
/// + mempool stats.
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

/// Blockscout v2 `/addresses/<addr>` — current balance (wei) + reverse ENS name.
#[derive(Deserialize, Default)]
#[serde(default)]
struct BlockscoutAddress {
    coin_balance: Option<String>,
    ens_domain_name: Option<String>,
}

/// Blockscout v2 `/addresses/<addr>/counters` — authoritative tx count.
#[derive(Deserialize, Default)]
#[serde(default)]
struct BlockscoutCounters {
    transactions_count: Option<String>,
}

/// Normalised enrichment for any chain — only the fields the source genuinely
/// provides are `Some`, so the evidence never fabricates a value.
struct Enrichment {
    unit: &'static str,
    decimals: u32,
    balance: u128,
    /// Lifetime total received (Esplora gives this; Blockscout balance does not).
    received: Option<u128>,
    /// Confirmed transaction count, when the source reports it.
    tx_count: Option<u64>,
    /// Reverse ENS name (EVM only), e.g. `vitalik.eth`.
    ens: Option<String>,
}

#[async_trait]
impl Module for ChainIntel {
    fn name(&self) -> &'static str {
        "chain_intel"
    }

    fn description(&self) -> &'static str {
        "Cryptocurrency wallet enrichment — on-chain balance, activity & ENS (BTC/LTC/ETH, free)"
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Queries public blockchain explorers for a wallet's activity/links —
        // ATT&CK Search Open Technical Databases (T1596); the explorer is the
        // queryable open technical database. (Other category has no default.)
        &["T1596"]
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::CryptoAddress, EntityKind::Username];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let addr = target.value.trim();
        let Some(chain) = classify_crypto_address(addr) else {
            return Ok(result); // not a recognised address shape
        };

        let enriched = match chain {
            "crypto_btc" => enrich_esplora(ctx, "https://blockstream.info/api", addr, "BTC").await,
            "crypto_ltc" => enrich_esplora(ctx, "https://litecoinspace.org/api", addr, "LTC").await,
            "crypto_eth" => enrich_eth(ctx, addr).await,
            // Recognised but no free keyless explorer wired — clean no-op.
            _ => None,
        };

        let Some(enr) = enriched else {
            return Ok(result);
        };

        let mut e = Entity::new(EntityKind::CryptoAddress, addr, 0.80, &ctx.scan_id);
        e.tag("crypto-address");
        e.tag(["chain:", chain_label(chain)].concat());
        e.add_evidence(build_evidence(chain_label(chain), &enr));
        result.push(e);

        // The reverse ENS name links an EVM address to a human-chosen handle —
        // a high-value identity pivot. Emit the handle (its label, minus the
        // `.eth` suffix the username stack can't probe) as a Username, tagged so
        // its origin is clear.
        if let Some(ens) = &enr.ens {
            let handle = ens.strip_suffix(".eth").unwrap_or(ens);
            if handle.len() >= 2 && !handle.contains('.') {
                let mut u = Entity::new(EntityKind::Username, handle, 0.70, &ctx.scan_id);
                u.tag(SRC);
                u.tag("ens");
                u.add_evidence(
                    Evidence::new(SRC, format!("ENS reverse name for {addr}"))
                        .with_attr("ens_name", ens)
                        .with_attr("address", addr),
                );
                result.push(u);
            }
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
    let frac_str = format!("{frac:0width$}", width = decimals as usize);
    let frac_trimmed = frac_str.trim_end_matches('0');
    if frac_trimmed.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac_trimmed}")
    }
}

/// Build enrichment evidence, emitting only the fields the source provided. The
/// activity verdict prefers the precise tx-count signal; absent that, it falls
/// back to a coarser funded/empty signal from the balance — never claiming more
/// than is known. Pure (no I/O) for unit testing.
fn build_evidence(chain: &str, e: &Enrichment) -> Evidence {
    let activity = match e.tx_count {
        Some(0) => "dormant",
        Some(_) => "active",
        None if e.balance > 0 => "funded",
        None => "empty",
    };
    let mut ev = Evidence::new(SRC, format!("{chain} on-chain activity: {activity}"))
        .with_attr("chain", chain)
        .with_attr(
            "balance",
            format!("{} {}", format_units(e.balance, e.decimals), e.unit),
        )
        .with_attr("activity", activity);
    if let Some(received) = e.received {
        ev = ev.with_attr(
            "total_received",
            format!("{} {}", format_units(received, e.decimals), e.unit),
        );
    }
    if let Some(tx) = e.tx_count {
        ev = ev.with_attr("tx_count", tx.to_string());
    }
    if let Some(ens) = &e.ens {
        ev = ev.with_attr("ens_name", ens);
    }
    ev
}

/// Esplora-compatible enrichment (BTC, LTC) — both report 8-decimal coins.
async fn enrich_esplora(
    ctx: &ModuleContext,
    api_base: &str,
    addr: &str,
    unit: &'static str,
) -> Option<Enrichment> {
    let url = format!("{api_base}/address/{addr}");
    let a: EsploraAddress = fetch_json(&ctx.http, SRC, &url).await.ok()?;
    let received = a.chain_stats.funded_txo_sum.max(0) as u128;
    let spent = a.chain_stats.spent_txo_sum.max(0) as u128;
    Some(Enrichment {
        unit,
        decimals: 8,
        balance: received.saturating_sub(spent),
        received: Some(received),
        tx_count: Some(a.chain_stats.tx_count + a.mempool_stats.tx_count),
        ens: None,
    })
}

async fn enrich_eth(ctx: &ModuleContext, addr: &str) -> Option<Enrichment> {
    let base = "https://eth.blockscout.com/api/v2/addresses";
    let a: BlockscoutAddress = fetch_json(&ctx.http, SRC, &format!("{base}/{addr}"))
        .await
        .ok()?;
    let balance: u128 = a
        .coin_balance
        .as_deref()
        .and_then(|s| s.trim().parse().ok())?;
    // tx count is a second, best-effort call — its absence must not drop the
    // balance/ENS we already have.
    let tx_count =
        fetch_json::<BlockscoutCounters>(&ctx.http, SRC, &format!("{base}/{addr}/counters"))
            .await
            .ok()
            .and_then(|c| c.transactions_count)
            .and_then(|s| s.trim().parse::<u64>().ok());
    Some(Enrichment {
        unit: "ETH",
        decimals: 18,
        balance,
        received: None, // Blockscout balance endpoint doesn't expose lifetime received.
        tx_count,
        ens: a.ens_domain_name.filter(|s| !s.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
