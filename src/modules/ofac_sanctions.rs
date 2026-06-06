//! OFAC sanctions screening for cryptocurrency wallets — offline, authoritative.
//!
//! Screens a `CryptoAddress` against the U.S. Treasury Office of Foreign Assets
//! Control (OFAC) Specially Designated Nationals (SDN) list. A match is the
//! single highest-signal verdict a crypto lead can carry: the wallet belongs to
//! a sanctioned person/entity (Lazarus Group, sanctioned mixers, IRGC fronts,
//! ransomware operators, …), making any interaction with it a legal/criminal
//! exposure rather than a mere "interesting" address.
//!
//! ## Why bundled, not live
//! The screening list is embedded at compile time (`data/ofac_sdn_crypto.tsv`),
//! extracted from OFAC's authoritative *advanced* SDN XML. This is deliberate:
//!   * **Deterministic & offline** — no network dependency, works in the field
//!     on Termux with no connectivity, no key, no rate limit.
//!   * **Authoritative & honest** — every address is verbatim from the U.S.
//!     Government source (public-domain data); nothing is inferred or fabricated.
//!     The snapshot's OFAC date-of-issue is carried in the file header and stamped
//!     onto every finding's evidence so an analyst sees exactly how current it is.
//!
//! The 780-address snapshot is ~52 KB — negligible to bundle, instant to query.
//! Refresh by re-running the extractor against the live `sdn_advanced.xml`.
//!
//! The address→verdict mapping is the pure [`screen`] (unit-tested); the module
//! shell owns only target plumbing.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::core::{
    crypto::classify_crypto_address,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "ofac_sanctions";

/// The bundled OFAC SDN crypto-address snapshot (see module docs).
const SDN_DATA: &str = include_str!("data/ofac_sdn_crypto.tsv");

/// OFAC date-of-issue of the bundled snapshot — stamped on every finding so the
/// analyst can judge currency. Kept in sync with the file header.
const SNAPSHOT_ISSUE_DATE: &str = "2026-06-05";

/// One sanctioned address: the chain code (`XBT`, `ETH`, …) and the SDN party.
struct SdnEntry {
    chain: &'static str,
    name: &'static str,
}

/// Parsed lookup, keyed by lowercased address (ETH checksums and bech32 vary in
/// case; base58 case-collisions are not real-world possible), built once.
static SDN_INDEX: LazyLock<HashMap<String, SdnEntry>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    for line in SDN_DATA.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.splitn(3, '\t');
        let (Some(addr), Some(chain)) = (cols.next(), cols.next()) else {
            continue;
        };
        let name = cols.next().unwrap_or("");
        map.insert(addr.trim().to_lowercase(), SdnEntry { chain, name });
    }
    map
});

/// Human-readable chain label for an OFAC chain code.
fn chain_full(code: &str) -> &'static str {
    match code {
        "XBT" => "Bitcoin",
        "ETH" => "Ethereum",
        "XMR" => "Monero",
        "LTC" => "Litecoin",
        "ZEC" => "Zcash",
        "DASH" => "Dash",
        "BTG" => "Bitcoin Gold",
        "ETC" => "Ethereum Classic",
        "BSV" => "Bitcoin SV",
        "BCH" => "Bitcoin Cash",
        "XVG" => "Verge",
        "USDT" => "Tether (USDT)",
        "XRP" => "Ripple (XRP)",
        "TRX" => "Tron (TRX)",
        "USDC" => "USD Coin (USDC)",
        "ARB" => "Arbitrum",
        "BSC" => "BNB Smart Chain",
        "SOL" => "Solana",
        _ => "Cryptocurrency",
    }
}

/// Screen one address against the bundled SDN list. Returns the matched
/// entry when the wallet is sanctioned. **Pure** (no I/O); unit-tested.
fn screen(address: &str) -> Option<&'static SdnEntry> {
    let key = address.trim().to_lowercase();
    if key.is_empty() {
        return None;
    }
    SDN_INDEX.get(&key)
}

pub struct OfacSanctions;

#[async_trait]
impl Module for OfacSanctions {
    fn name(&self) -> &'static str {
        "ofac_sanctions"
    }

    fn description(&self) -> &'static str {
        "OFAC SDN sanctions screening for crypto wallets (offline, authoritative)"
    }

    fn priority(&self) -> u8 {
        // Above chain_intel (90): a sanctions verdict is the dominant signal and
        // should be attached before enrichment fans out.
        95
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::CryptoAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn max_timeout_ms(&self) -> u64 {
        // Pure in-memory lookup; the timeout is a formality.
        1_000
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::CryptoAddress, EntityKind::Organisation];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let addr = target.value.trim();
        let Some(entry) = screen(addr) else {
            return Ok(result); // clean — not on the SDN list
        };
        let chain_code = classify_crypto_address(addr)
            .map(|c| c.trim_start_matches("crypto_").to_uppercase())
            .unwrap_or_default();
        let _ = chain_code; // classifier kind is advisory; OFAC chain is authoritative

        let chain_label = chain_full(entry.chain);
        let summary = if entry.name.is_empty() {
            format!("Wallet on OFAC SDN list ({chain_label})")
        } else {
            format!("Wallet on OFAC SDN list — {} ({chain_label})", entry.name)
        };

        // Re-emit the wallet, now flagged sanctioned. Merges with the existing
        // CryptoAddress entity (kind+value), attaching the verdict + evidence.
        let mut wallet = Entity::new(EntityKind::CryptoAddress, addr, 1.0, &ctx.scan_id);
        wallet.tag(SRC);
        wallet.tag("ofac-sanctioned");
        wallet.tag("sanctions");
        wallet.tag(format!("chain:{}", entry.chain));
        let mut ev = Evidence::new(SRC, summary)
            .with_attr("list", "OFAC SDN")
            .with_attr("chain", chain_label)
            .with_attr("chain_code", entry.chain)
            .with_attr("snapshot_issue_date", SNAPSHOT_ISSUE_DATE)
            .with_attr(
                "source",
                "U.S. Treasury OFAC Specially Designated Nationals list",
            );
        if !entry.name.is_empty() {
            ev = ev.with_attr("sdn_name", entry.name);
        }
        wallet.add_evidence(ev);
        result.push(wallet);

        // The sanctioned party itself, as an Organisation lead.
        if !entry.name.is_empty() {
            let mut org = Entity::new(EntityKind::Organisation, entry.name, 0.95, &ctx.scan_id);
            org.tag(SRC);
            org.tag("ofac-sanctioned");
            org.tag("sanctions");
            org.add_evidence(
                Evidence::new(SRC, "OFAC SDN-listed party owning the screened wallet")
                    .with_attr("wallet", addr)
                    .with_attr("chain", chain_label)
                    .with_attr("snapshot_issue_date", SNAPSHOT_ISSUE_DATE),
            );
            result.push(org);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    /// A known Lazarus Group address from the bundled snapshot.
    const KNOWN_SDN: &str = "0x08723392Ed15743cc38513C4925f5e6be5c17243";

    fn ctx(scan: &str) -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: scan.into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        }
    }

    #[test]
    fn index_loads_and_is_substantial() {
        assert!(
            SDN_INDEX.len() > 500,
            "expected the full SDN crypto snapshot, got {}",
            SDN_INDEX.len()
        );
    }

    #[test]
    fn screen_flags_a_known_sanctioned_wallet() {
        let hit = screen(KNOWN_SDN).expect("known SDN address must match");
        assert_eq!(hit.chain, "ETH");
        assert!(!hit.name.is_empty());
    }

    #[test]
    fn screen_is_case_insensitive() {
        assert!(screen(&KNOWN_SDN.to_lowercase()).is_some());
        assert!(screen(&KNOWN_SDN.to_uppercase()).is_some());
    }

    #[test]
    fn screen_clears_an_unlisted_wallet() {
        // A well-known non-sanctioned address (Ethereum zero address).
        assert!(screen("0x0000000000000000000000000000000000000001").is_none());
        assert!(screen("").is_none());
        assert!(screen("not-an-address").is_none());
    }

    #[tokio::test]
    async fn process_emits_wallet_and_org_for_a_hit() {
        let m = OfacSanctions;
        let ctx = ctx("scan");
        let t = Target::new(TargetKind::CryptoAddress, KNOWN_SDN);
        let r = m.process(&t, &ctx).await.unwrap();
        assert!(
            r.entities
                .iter()
                .any(|e| e.kind == EntityKind::CryptoAddress && e.has_tag("ofac-sanctioned"))
        );
        assert!(
            r.entities
                .iter()
                .any(|e| e.kind == EntityKind::Organisation && e.has_tag("ofac-sanctioned"))
        );
        let wallet = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::CryptoAddress)
            .unwrap();
        let ev = &wallet.evidence[0];
        assert_eq!(
            ev.attributes.get("list").map(String::as_str),
            Some("OFAC SDN")
        );
        assert_eq!(
            ev.attributes.get("snapshot_issue_date").map(String::as_str),
            Some(SNAPSHOT_ISSUE_DATE)
        );
    }

    #[tokio::test]
    async fn process_is_quiet_for_a_clean_wallet() {
        let m = OfacSanctions;
        let ctx = ctx("scan");
        let t = Target::new(
            TargetKind::CryptoAddress,
            "0x0000000000000000000000000000000000000002",
        );
        assert!(m.process(&t, &ctx).await.unwrap().entities.is_empty());
    }

    #[test]
    fn metadata_is_free_threat_passive() {
        let m = OfacSanctions;
        assert_eq!(m.cost(), ModuleCost::Free);
        assert_eq!(m.category(), ModuleCategory::Threat);
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::CryptoAddress, KNOWN_SDN)));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
}
