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
//!   * SOL — the public Solana JSON-RPC (`api.mainnet-beta.solana.com`)'s
//!     `getBalance` method: balance only (lamports). No cheap authoritative
//!     "total transactions for this address" RPC method exists — getting an
//!     exact count would mean fully paginating `getSignaturesForAddress`
//!     (potentially thousands of calls for a busy address), so `tx_count`/
//!     `received` are left `None` rather than faked or capped-and-mislabelled,
//!     same honesty discipline as the ETH path's missing "total received".
//!   * DOGE — BlockCypher's `/v1/doge/main/addrs/<addr>/balance`: balance,
//!     total received, and tx count, all directly reported (no summing
//!     confirmed+mempool needed, unlike Esplora). `dogechain.info` — the more
//!     commonly cited keyless DOGE source — returned 403 on every fetch
//!     attempt during this module's extension, including its own docs page,
//!     so it was rejected as unverifiable; BlockCypher was confirmed live and
//!     reachable, and its response was checked against a real high-activity
//!     address before wiring it in.
//!
//! Honesty is a hard requirement: an evidence field is emitted only when the
//! source actually provides it (e.g. ETH reports no "total received" cheaply, so
//! that attribute is simply absent rather than faked). XMR is recognised by the
//! classifier but is cryptographically unenrichable from a bare address — its
//! whole design goal is that balances/activity are NOT observable without the
//! private view key, so no explorer, free or paid, could ever answer this for a
//! raw address string. One-to-two small JSON requests per chain; Termux-friendly.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    crypto::{chain_label, classify_crypto_address},
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, fetch_json};

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

/// Blockscout v2 `/addresses/<addr>` — current balance (wei) + reverse ENS name,
/// plus Blockscout's own curated reputation signal: whether the address is
/// flagged as a scam, its reputation verdict, a known entity/contract name,
/// and any public tags analysts have attached to it (exchange, mixer, etc.).
#[derive(Deserialize, Default)]
#[serde(default)]
struct BlockscoutAddress {
    coin_balance: Option<String>,
    ens_domain_name: Option<String>,
    is_scam: Option<bool>,
    reputation: Option<String>,
    name: Option<String>,
    public_tags: Vec<BlockscoutTag>,
}

/// One entry of Blockscout's `public_tags` array — a curated label the
/// explorer's own operators/community have attached to the address (e.g.
/// "exchange", "mixer"). `display_name` is the human-facing label;
/// `label` is its machine-facing slug, kept as a fallback in case a tag
/// only has one or the other set.
#[derive(Deserialize, Default)]
#[serde(default)]
struct BlockscoutTag {
    label: Option<String>,
    display_name: Option<String>,
}

/// Blockscout v2 `/addresses/<addr>/counters` — authoritative tx count.
#[derive(Deserialize, Default)]
#[serde(default)]
struct BlockscoutCounters {
    transactions_count: Option<String>,
}

/// Solana JSON-RPC `getBalance` response: `{"result":{"value":<lamports>}}`
/// (plus a `context` object this module doesn't need).
#[derive(Deserialize, Default)]
#[serde(default)]
struct SolBalanceResp {
    result: Option<SolBalanceResult>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SolBalanceResult {
    value: Option<u64>,
}

/// BlockCypher `/v1/doge/main/addrs/<addr>/balance` — reports amounts in the
/// chain's base unit (koinu, 8 decimals — same convention as the
/// Esplora-sourced BTC/LTC), and unlike Esplora, gives the netted balance and
/// total received directly rather than requiring a funded-minus-spent
/// subtraction.
#[derive(Deserialize, Default)]
#[serde(default)]
struct BlockcypherBalance {
    balance: u64,
    total_received: u64,
    n_tx: u64,
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
    /// Blockscout's own scam flag (EVM only — no equivalent on the other
    /// sources this module calls).
    is_scam: Option<bool>,
    /// Blockscout's reputation verdict, e.g. `"ok"`/`"scam"` (EVM only).
    reputation: Option<String>,
    /// A known contract/entity name Blockscout has identified, e.g.
    /// `"UniswapV2Router02"` (EVM only).
    known_name: Option<String>,
    /// Curated public tags Blockscout has attached to the address, e.g.
    /// `["exchange"]` (EVM only). Empty when the source has none — never
    /// fabricated.
    public_tags: Vec<String>,
}

#[async_trait]
impl Module for ChainIntel {
    fn name(&self) -> &'static str {
        "chain_intel"
    }

    fn description(&self) -> &'static str {
        "Cryptocurrency wallet enrichment — correlates on-chain balance, activity & ENS (BTC/LTC/ETH/SOL/DOGE, free)"
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

        // Each supported chain has exactly one data source. A genuine failure of
        // that source (transport error, non-2xx, unparseable body) is propagated
        // as a real `Error` via `?`, so it is NEVER confused with either a
        // recognised-but-unwired chain (a deliberate `Ok(None)` no-op) or a
        // supported chain whose source honestly reported no data (`Ok(None)`) —
        // the T2.122 distinction, which the former `Option`-returning enrichers
        // (each `fetch_json(…).await.ok()?`) collapsed into one indistinguishable
        // `None`.
        let enriched = match chain {
            "crypto_btc" => enrich_esplora(ctx, "https://blockstream.info/api", addr, "BTC").await,
            "crypto_ltc" => enrich_esplora(ctx, "https://litecoinspace.org/api", addr, "LTC").await,
            "crypto_eth" => enrich_eth(ctx, addr).await,
            "crypto_sol" => enrich_sol(ctx, addr).await,
            "crypto_doge" => enrich_doge(ctx, addr).await,
            // Recognised but no free keyless explorer wired — a deliberate clean
            // no-op, distinct from a source failure.
            _ => Ok(None),
        }?;

        let Some(enr) = enriched else {
            return Ok(result);
        };

        let mut e = Entity::new(EntityKind::CryptoAddress, addr, 0.80, &ctx.scan_id);
        e.tag("crypto-address");
        e.tag(format!("chain:{}", chain_label(chain)));
        apply_scam_tags(&mut e, &enr);
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

/// Tags the entity `MALICIOUS`/`THREAT_INTEL` when the source's own curated
/// scam flag is `true` — never when it is absent or `false`, so a source
/// that doesn't report a scam verdict at all can't be mistaken for a clean
/// bill of health. Pure (no I/O) for unit testing.
fn apply_scam_tags(entity: &mut Entity, e: &Enrichment) {
    if e.is_scam == Some(true) {
        entity.tag(crate::core::tags::MALICIOUS);
        entity.tag(crate::core::tags::THREAT_INTEL);
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
    if let Some(name) = &e.known_name {
        ev = ev.with_attr("known_name", name);
    }
    if let Some(reputation) = &e.reputation {
        ev = ev.with_attr("reputation", reputation);
    }
    if let Some(is_scam) = e.is_scam {
        ev = ev.with_attr("is_scam", is_scam.to_string());
    }
    if !e.public_tags.is_empty() {
        ev = ev.with_attr("public_tags", e.public_tags.join(", "));
    }
    ev
}

/// Esplora-compatible enrichment (BTC, LTC) — both report 8-decimal coins.
/// `Err` on a genuine source failure (transport/non-2xx/unparseable body,
/// propagated by `fetch_json`); `Ok(Some(..))` on a real address (Esplora
/// returns zeroed stats for an unused-but-valid address, so there is no
/// "empty" `Ok(None)` case here). See [`ChainIntel::process`] for why this
/// distinction matters (T2.122).
async fn enrich_esplora(
    ctx: &ModuleContext,
    api_base: &str,
    addr: &str,
    unit: &'static str,
) -> Result<Option<Enrichment>> {
    let url = format!("{api_base}/address/{addr}");
    let a: EsploraAddress = fetch_json(&ctx.http, SRC, &url).await?;
    let received = a.chain_stats.funded_txo_sum.max(0) as u128;
    let spent = a.chain_stats.spent_txo_sum.max(0) as u128;
    Ok(Some(Enrichment {
        unit,
        decimals: 8,
        balance: received.saturating_sub(spent),
        received: Some(received),
        tx_count: Some(a.chain_stats.tx_count + a.mempool_stats.tx_count),
        ens: None,
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
    }))
}

/// EVM (ETH) enrichment via Blockscout. `Err` on a genuine failure of the
/// primary address call (propagated by `fetch_json`); `Ok(None)` when that call
/// succeeds but returns no parseable `coin_balance` (a real answer with nothing
/// to enrich, not a source failure). The second `counters` call for `tx_count`
/// stays best-effort — its own failure must not drop the balance/ENS already in
/// hand. See [`ChainIntel::process`] for the T2.122 distinction.
async fn enrich_eth(ctx: &ModuleContext, addr: &str) -> Result<Option<Enrichment>> {
    let base = "https://eth.blockscout.com/api/v2/addresses";
    let a: BlockscoutAddress = fetch_json(&ctx.http, SRC, &format!("{base}/{addr}")).await?;
    let Some(balance) = a
        .coin_balance
        .as_deref()
        .and_then(|s| s.trim().parse::<u128>().ok())
    else {
        return Ok(None);
    };
    // tx count is a second, best-effort call — its absence must not drop the
    // balance/ENS we already have.
    let tx_count =
        fetch_json::<BlockscoutCounters>(&ctx.http, SRC, &format!("{base}/{addr}/counters"))
            .await
            .ok()
            .and_then(|c| c.transactions_count)
            .and_then(|s| s.trim().parse::<u64>().ok());
    Ok(Some(Enrichment {
        unit: "ETH",
        decimals: 18,
        balance,
        received: None, // Blockscout balance endpoint doesn't expose lifetime received.
        tx_count,
        ens: a.ens_domain_name.filter(|s| !s.is_empty()),
        is_scam: a.is_scam,
        reputation: a.reputation.filter(|s| !s.is_empty()),
        known_name: a.name.filter(|s| !s.is_empty()),
        public_tags: blockscout_tag_labels(&a.public_tags),
    }))
}

/// Reduces Blockscout's `public_tags` array down to display strings, preferring
/// each tag's human-facing `display_name` and falling back to its machine
/// `label` slug only when `display_name` is absent — never emitting a blank
/// entry for a tag with neither field set.
fn blockscout_tag_labels(tags: &[BlockscoutTag]) -> Vec<String> {
    tags.iter()
        .filter_map(|t| {
            t.display_name
                .as_deref()
                .or(t.label.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .collect()
}

/// Solana enrichment via the public JSON-RPC's `getBalance` method — balance
/// only; see the module doc for why `tx_count`/`received` are never populated
/// for SOL rather than estimated from a bounded `getSignaturesForAddress` call.
async fn enrich_sol(ctx: &ModuleContext, addr: &str) -> Result<Option<Enrichment>> {
    let resp = ctx
        .http
        .post("https://api.mainnet-beta.solana.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [addr]
        }))
        .send_tagged(SRC)
        .await?;
    if !resp.status().is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    let body: SolBalanceResp = crate::util::http::json_decode(SRC, resp).await?;
    // A well-formed RPC reply that simply carries no balance (`result`/`value`
    // absent) is an honest "nothing to enrich", distinct from the failures above.
    let Some(balance) = body.result.and_then(|r| r.value) else {
        return Ok(None);
    };
    Ok(Some(Enrichment {
        unit: "SOL",
        decimals: 9,
        balance: u128::from(balance),
        received: None,
        tx_count: None,
        ens: None,
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
    }))
}

/// Dogecoin enrichment via BlockCypher (see module doc for why this source,
/// not `dogechain.info`, was chosen).
async fn enrich_doge(ctx: &ModuleContext, addr: &str) -> Result<Option<Enrichment>> {
    let url = format!("https://api.blockcypher.com/v1/doge/main/addrs/{addr}/balance");
    let b: BlockcypherBalance = fetch_json(&ctx.http, SRC, &url).await?;
    Ok(Some(Enrichment {
        unit: "DOGE",
        decimals: 8,
        balance: u128::from(b.balance),
        received: Some(u128::from(b.total_received)),
        tx_count: Some(b.n_tx),
        ens: None,
        is_scam: None,
        reputation: None,
        known_name: None,
        public_tags: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
