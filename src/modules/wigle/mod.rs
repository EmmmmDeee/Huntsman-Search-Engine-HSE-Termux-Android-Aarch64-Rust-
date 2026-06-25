//! WiGLE WiFi network search by geographic point. Key-gated.
//!
//! Endpoint: `GET https://api.wigle.net/api/v2/network/search`
//! Auth:     HTTP Basic — `HUNTSMAN_WIGLE_USER` (API name) + `HUNTSMAN_WIGLE_TOKEN`.
//!
//! Accepts a `Coordinates` target (`"lat,lon"`). WiGLE wants a bounding
//! box; we use an adaptive strategy: start at ±0.002° (~220m), widen to
//! ±0.01° (~1.1km) only if the tight box returns zero results. This
//! preserves API quota while ensuring populated areas get results.
//!
//! Intelligence extracted per API call:
//! - Coordinates entity (corroborated by WiFi observation data)
//! - Address entity from city/region/country fields (free geolocation)
//! - SSID-derived intelligence (names, business identifiers)
//! - WiFi density and encryption breakdown (neighbourhood profiling)
//! - MacAddress entities for device/AP correlation (top 5 only)

mod account;
mod emit;
mod fetch;
#[cfg(test)]
mod tests;

pub use account::{WigleAccountStatus, account_status, is_unverified, refresh_account_status};

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::budget::{BudgetSnapshot, QuotaBudget};

use emit::{emit_bssid_entities, emit_ssid_entities, extract_bluetooth_intel, extract_cell_intel};
use fetch::{fetch_detail, fetch_wigle, fetch_wigle_ssid, fetch_wigle_typed};

// WiGLE credentials (env names + embedded fallbacks) are resolved by the
// single-sourced `crate::util::keys::wigle_credentials`.

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default, rename = "resultCount")]
    result_count: Option<u64>,
    #[serde(default, rename = "totalResults")]
    total_results: Option<u64>,
    #[serde(default)]
    results: Vec<Network>,
}

#[derive(Deserialize)]
struct Network {
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    netid: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    lastupdt: Option<String>,
    #[serde(default)]
    trilat: Option<f64>,
    #[serde(default)]
    trilong: Option<f64>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    postalcode: Option<String>,
}

pub(super) const SRC: &str = "wigle";

/// Per-scan + per-session WiGLE budgets, backed by the shared
/// [`QuotaBudget`] primitive that `util::see_know` and
/// `util::oathnet` already use.
///
/// WiGLE's quota is generous (300/day free, higher tiers paid) so we
/// allow:
///   - 3 geo searches per scan (the most expensive endpoint — bbox
///     scan returns up to 100 networks)
///   - 5 BSSID lookups per scan (single-record, cheap)
///   - 2 cell tower searches per scan
///   - 2 Bluetooth beacon searches per scan
///
/// Session ceilings (50/100/30/30 respectively) keep `hse serve` /
/// `hse live` sessions well below the daily allowance even with deep
/// pivot chains. Both layers are env-tunable so operators on paid
/// tiers can raise them without recompiling.
pub(super) static GEO_BUDGET: QuotaBudget = QuotaBudget::new(
    "wigle_geo",
    3,
    50,
    "HUNTSMAN_WIGLE_GEO_SCAN_CAP",
    "HUNTSMAN_WIGLE_GEO_SESSION_CAP",
);
pub(super) static BSSID_BUDGET: QuotaBudget = QuotaBudget::new(
    "wigle_bssid",
    5,
    100,
    "HUNTSMAN_WIGLE_BSSID_SCAN_CAP",
    "HUNTSMAN_WIGLE_BSSID_SESSION_CAP",
);
pub(super) static CELL_BUDGET: QuotaBudget = QuotaBudget::new(
    "wigle_cell",
    2,
    30,
    "HUNTSMAN_WIGLE_CELL_SCAN_CAP",
    "HUNTSMAN_WIGLE_CELL_SESSION_CAP",
);
pub(super) static BLUETOOTH_BUDGET: QuotaBudget = QuotaBudget::new(
    "wigle_bluetooth",
    2,
    30,
    "HUNTSMAN_WIGLE_BT_SCAN_CAP",
    "HUNTSMAN_WIGLE_BT_SESSION_CAP",
);
pub(super) static SSID_BUDGET: QuotaBudget = QuotaBudget::new(
    "wigle_ssid",
    3,
    40,
    "HUNTSMAN_WIGLE_SSID_SCAN_CAP",
    "HUNTSMAN_WIGLE_SSID_SESSION_CAP",
);

/// Reset all WiGLE per-scan budgets. Called from `engine.rs` at
/// scan start so each scan gets a fresh allowance for every
/// observation type.
pub fn reset_budget() {
    GEO_BUDGET.reset_scan();
    BSSID_BUDGET.reset_scan();
    CELL_BUDGET.reset_scan();
    BLUETOOTH_BUDGET.reset_scan();
    SSID_BUDGET.reset_scan();
}

/// Aggregate snapshot of every WiGLE sub-budget — surfaced on
/// `/api/v1/stats` alongside the SeekNow / OathNet blocks so
/// operators can see remaining quota across all observation types
/// at a glance.
pub fn budget_snapshot() -> WigleBudgets {
    WigleBudgets {
        geo: GEO_BUDGET.snapshot(),
        bssid: BSSID_BUDGET.snapshot(),
        cell: CELL_BUDGET.snapshot(),
        bluetooth: BLUETOOTH_BUDGET.snapshot(),
    }
}

/// All four WiGLE budgets in one struct, for diagnostic surfaces.
#[derive(Debug, Clone, Copy)]
pub struct WigleBudgets {
    pub geo: BudgetSnapshot,
    pub bssid: BudgetSnapshot,
    pub cell: BudgetSnapshot,
    pub bluetooth: BudgetSnapshot,
}

pub struct Wigle;

#[async_trait]
impl Module for Wigle {
    fn name(&self) -> &'static str {
        "wigle"
    }
    fn description(&self) -> &'static str {
        "WiGLE wireless intel — WiFi + cell tower + Bluetooth beacon observations by coords / BSSID"
    }
    fn priority(&self) -> u8 {
        // Geolocation FINALISER — dispatched last so it resolves the coordinates,
        // BSSIDs and addresses surfaced by every other module into a final
        // location fix. Kept the floor of the geolocation band (below ip_geo,
        // geocode, overpass, mylnikov) on purpose.
        10
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1591.002"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        // WiGLE corroborates Coordinates with WiFi density, emits
        // city/region/country as Address, surfaces top APs as
        // MacAddress entities, and (with cell-tower observations
        // enabled) extracts cellular carrier names as Organisation.
        const KINDS: &[EntityKind] = &[
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::MacAddress,
            EntityKind::Organisation,
        ];
        KINDS
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Coordinates | TargetKind::MacAddress | TargetKind::Ssid
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // WiGLE budgets are split across four observation types
        // (WiFi geo / WiFi BSSID / cell tower / Bluetooth beacon) so
        // each high-value pivot reaches the API while still bounded
        // by the operator's daily allowance. Each sub-budget is
        // independent and env-tunable.

        let (user, token) = crate::util::keys::wigle_credentials(ctx);

        if target.kind == TargetKind::Ssid {
            if !SSID_BUDGET.try_increment() {
                return Ok(ModuleResult::new());
            }
            return self
                .ssid_search(user, token, target.value.trim(), ctx)
                .await;
        }

        if target.kind == TargetKind::MacAddress {
            if !BSSID_BUDGET.try_increment() {
                return Ok(ModuleResult::new());
            }
            return self.bssid_lookup(user, token, &target.value, ctx).await;
        }

        if !GEO_BUDGET.try_increment() {
            return Ok(ModuleResult::new());
        }

        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let body = {
            let tight = fetch_wigle(&ctx.http, user, token, lat, lon, 0.002).await?;
            if tight.success == Some(true)
                && tight.total_results.or(tight.result_count).unwrap_or(0) > 0
            {
                tight
            } else {
                fetch_wigle(&ctx.http, user, token, lat, lon, 0.01).await?
            }
        };

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let total = body
            .total_results
            .or(body.result_count)
            .unwrap_or(body.results.len() as u64);
        if total == 0 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // ── Primary: Coordinates entity with WiFi corroboration ─────
        let mut coords_entity =
            Entity::new(EntityKind::Coordinates, &target.value, 0.85, &ctx.scan_id);
        coords_entity.tag("wigle");
        coords_entity.tag("wifi-observed");
        if let Some((lat, lon)) = crate::util::geohash::parse_coords(&target.value)
            && let Some(state) = crate::util::geo::au_state_for_coords(lat, lon)
        {
            coords_entity.tag(format!("au-state:{state}"));
            coords_entity.tag("country:AU");
        }

        let enc_types: Vec<String> = body
            .results
            .iter()
            .filter_map(|n| n.encryption.clone())
            .collect();
        let top_encryption = crate::util::freq::top_n(enc_types.iter().map(String::as_str), 5);

        let most_recent = body
            .results
            .iter()
            .filter_map(|n| n.lastupdt.as_deref())
            .max()
            .map(String::from);

        let mut ev = Evidence::new(
            SRC,
            format!("WiGLE: {total} WiFi network(s) near {}", target.value),
        )
        .with_attr("total", total.to_string())
        .with_attr("returned", body.results.len().to_string());
        if !top_encryption.is_empty() {
            ev = ev.with_attr("top_encryption", top_encryption);
        }
        if let Some(ref t) = most_recent {
            ev = ev.with_attr("most_recent_observation", t);
        }

        // WiFi density classification — intelligence value
        let density = if total >= 50 {
            "dense-urban"
        } else if total >= 10 {
            "suburban"
        } else if total >= 2 {
            "sparse"
        } else {
            "isolated"
        };
        ev = ev.with_attr("density", density);
        coords_entity.tag(format!("wifi-density:{density}"));

        coords_entity.add_evidence(ev);
        result.push(coords_entity);

        // ── Address from WiGLE city/region/country (free geo!) ──────
        // Use the most common city/region/country across results for
        // consensus-based location.
        let cities: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.city.as_deref())
            .filter(|c| !c.is_empty())
            .collect();
        let regions: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.region.as_deref())
            .filter(|r| !r.is_empty())
            .collect();
        let countries: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.country.as_deref())
            .filter(|c| !c.is_empty())
            .collect();
        let postcodes: Vec<&str> = body
            .results
            .iter()
            .filter_map(|n| n.postalcode.as_deref())
            .filter(|p| !p.is_empty())
            .collect();

        let top_city = mode(&cities);
        let top_region = mode(&regions);
        let top_country = mode_or(&countries, || {
            body.results
                .iter()
                .find_map(|n| n.country.as_deref())
                .unwrap_or("")
        });
        let top_postcode = mode(&postcodes);

        let addr_parts: Vec<&str> = [top_city, top_region, top_country]
            .iter()
            .copied()
            .filter(|s| !s.is_empty())
            .collect();

        if addr_parts.len() >= 2 {
            let mut addr_str = addr_parts.join(", ");
            if !top_postcode.is_empty() {
                addr_str = format!("{addr_str} {top_postcode}");
            }
            let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.65, &ctx.scan_id);
            addr.tag("wigle");
            addr.tag("wifi-derived");
            addr.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Address from WiFi AP consensus near {}", target.value),
                )
                .with_attr("networks_sampled", total.to_string())
                .with_attr("city", top_city)
                .with_attr("region", top_region)
                .with_attr("country", top_country),
            );
            if !top_postcode.is_empty() {
                addr.tag(format!("postcode:{top_postcode}"));
            }
            result.push(addr);
        }

        // ── SSID intelligence: extract names and business identifiers ──
        // Named-looking SSIDs ("Smith-Family") → identity leads.
        let mut ssid_names: Vec<String> = body
            .results
            .iter()
            .filter_map(|net| {
                let ssid = net.ssid.as_deref()?.trim();
                if ssid.is_empty() || ssid.len() < 4 || ssid.starts_with("DIRECT-") {
                    return None;
                }
                if is_generic_ssid(ssid) {
                    return None;
                }
                let parts: Vec<&str> = ssid.split(['-', '_', ' ']).collect();
                (parts.len() >= 2
                    && parts[0].len() >= 3
                    && parts[0].starts_with(|c: char| c.is_ascii_uppercase()))
                .then(|| ssid.to_string())
            })
            .collect();
        ssid_names.sort();
        ssid_names.dedup();

        if !ssid_names.is_empty() {
            let top_ssids: Vec<&str> = ssid_names.iter().take(10).map(String::as_str).collect();
            let mut ssid_ev = Evidence::new(
                SRC,
                format!(
                    "{} named WiFi network(s) near {}",
                    top_ssids.len(),
                    target.value
                ),
            )
            .with_attr("named_ssids", top_ssids.join(", "));
            if let Some(ref t) = most_recent {
                ssid_ev = ssid_ev.with_attr("most_recent", t);
            }
            // Attach to the coordinates entity's evidence
            if let Some(first) = result.entities.first_mut() {
                first.add_evidence(ssid_ev);
            }
        }

        // ── Top MAC addresses (AP BSSIDs) for device correlation ────
        let mut macs: Vec<(&str, f64)> = body
            .results
            .iter()
            .filter_map(|n| {
                let mac = n.netid.as_deref()?;
                let dlat = n.trilat.unwrap_or(lat) - lat;
                let dlon = n.trilong.unwrap_or(lon) - lon;
                let dist = (dlat * dlat + dlon * dlon).sqrt();
                Some((mac, dist))
            })
            .collect();
        macs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        macs.dedup_by_key(|m| m.0);

        result.extend(macs.iter().take(5).filter_map(|(mac, _)| {
            if mac.len() < 12 {
                return None;
            }
            let mut e = Entity::new(EntityKind::MacAddress, *mac, 0.60, &ctx.scan_id);
            e.tag("wigle");
            e.tag("wifi-ap");
            let mut ev = Evidence::new(SRC, format!("WiFi AP near {}", target.value))
                .with_attr("coordinates", &target.value);
            if let Some(oui) = crate::util::oui::classify_mac(mac) {
                e.tag(format!("vendor:{}", oui.vendor));
                e.tag(format!("device:{}", oui.class.as_str()));
                ev = ev
                    .with_attr("vendor", oui.vendor)
                    .with_attr("device_class", oui.class.as_str());
            }
            e.add_evidence(ev);
            Some(e)
        }));

        // ── Potentiation: cell-tower + Bluetooth observations ──────
        let cell_fut = async {
            if CELL_BUDGET.try_increment() {
                fetch_wigle_typed(&ctx.http, user, token, lat, lon, 0.01, NetworkKind::Cell)
                    .await
                    .ok()
            } else {
                None
            }
        };
        let bt_fut = async {
            if BLUETOOTH_BUDGET.try_increment() {
                fetch_wigle_typed(
                    &ctx.http,
                    user,
                    token,
                    lat,
                    lon,
                    0.01,
                    NetworkKind::Bluetooth,
                )
                .await
                .ok()
            } else {
                None
            }
        };
        let (cell_resp, bt_resp) = tokio::join!(cell_fut, bt_fut);
        if let Some(cell) = cell_resp {
            extract_cell_intel(&cell, &target.value, &ctx.scan_id, &mut result);
        }
        if let Some(bt) = bt_resp {
            extract_bluetooth_intel(&bt, &target.value, &ctx.scan_id, &mut result);
        }

        Ok(result)
    }
}

/// Observation type for the WiGLE `/network/search` `type` query
/// parameter. WiGLE v2 indexes three; we expose all three so a
/// single Coordinates dispatch can fan out across the full corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkKind {
    Wifi,
    Cell,
    Bluetooth,
}

impl NetworkKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Cell => "cell",
            Self::Bluetooth => "bluetooth",
        }
    }
}

pub(super) fn is_generic_ssid(s: &str) -> bool {
    // One cached `aho-corasick` pass via `util::scan` (SOL-F1) — equivalent to the
    // old `GENERIC_SSIDS.iter().any(|g| lower.contains(g))`. Case-sensitive over the
    // Unicode-lowercased string (the patterns are lowercase), so it preserves the
    // exact `to_lowercase()` fold (non-ASCII included), unlike an ASCII-CI matcher.
    static GENERIC: std::sync::LazyLock<crate::util::scan::MatchSet> =
        std::sync::LazyLock::new(|| crate::util::scan::MatchSet::new(GENERIC_SSIDS));
    GENERIC.is_match(&s.to_lowercase())
}

pub(super) const GENERIC_SSIDS: &[&str] = &[
    "linksys", "netgear", "default", "dlink", "tp-link", "tplink", "asus", "xfinity", "spectrum",
    "att", "optimum", "cox", "telstra", "optus", "vodafone", "nbn", "iinet", "eduroam", "guest",
    "free", "public", "open", "android", "iphone", "galaxy", "pixel", "setup", "config", "admin",
    "test", "hidden", "unknown", "unnamed",
];

impl Wigle {
    async fn bssid_lookup(
        &self,
        user: &str,
        token: &str,
        bssid: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        for kind in [NetworkKind::Wifi, NetworkKind::Cell, NetworkKind::Bluetooth] {
            if let Some(body) = fetch_detail(&ctx.http, user, token, bssid, kind).await
                && body.success == Some(true)
                && !body.results.is_empty()
            {
                return Ok(emit_bssid_entities(
                    bssid,
                    kind,
                    &body.results,
                    &ctx.scan_id,
                ));
            }
        }
        Ok(ModuleResult::new())
    }

    /// WiGLE SSID search. Only a *unique* SSID geolocates: a generic/default name
    /// (`NETGEAR`, `iPhone`, …) is skipped, and a name with too many global
    /// observations is treated as non-unique (its locations would be random
    /// strangers' routers, not the subject's). A unique hit resolves to the GPS
    /// points the network was observed at — placing its owner.
    async fn ssid_search(
        &self,
        user: &str,
        token: &str,
        ssid: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        if ssid.is_empty() || is_generic_ssid(ssid) {
            return Ok(ModuleResult::new());
        }
        let body = fetch_wigle_ssid(&ctx.http, user, token, ssid).await?;
        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let total = body
            .total_results
            .or(body.result_count)
            .unwrap_or(body.results.len() as u64);
        // 0 → not in WiGLE; a large count → the name isn't unique, so no single
        // location places anyone. Only a small match set geolocates a network.
        if total == 0 || total > SSID_UNIQUE_MAX {
            return Ok(ModuleResult::new());
        }
        Ok(emit_ssid_entities(ssid, &body.results, &ctx.scan_id))
    }
}

/// Above this global observation count an SSID is treated as non-unique — its
/// locations are unrelated strangers' networks, not the subject's.
const SSID_UNIQUE_MAX: u64 = 20;

/// Statistical mode: most common value in a slice.
///
/// Ties are broken by the lexicographically smallest value so the result is
/// reproducible. A bare `max_by_key(count)` over a `HashMap` returns the *last*
/// element among equal maxima, and `HashMap` iteration order is randomised — so
/// on a tie (two values seen equally often) the chosen mode would vary run to
/// run and leak into the stored dossier (Determinism Requirement).
pub(super) fn mode<'a>(items: &[&'a str]) -> &'a str {
    if items.is_empty() {
        return "";
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for &item in items {
        *counts.entry(item).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map_or("", |(val, _)| val)
}

pub(super) fn mode_or<'a>(items: &[&'a str], fallback: impl FnOnce() -> &'a str) -> &'a str {
    let m = mode(items);
    if m.is_empty() { fallback() } else { m }
}
