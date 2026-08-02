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
//! - MacAddress entities for the closest APs (true distinct count on each)
//! - Ssid entities for person-named networks, pivotable back to every
//!   location that network has been observed at

mod account;
mod emit;
mod fetch;
#[cfg(test)]
mod tests;

pub use account::{WigleAccountStatus, account_status, is_unverified, refresh_account_status};

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::budget::{BudgetSnapshot, QuotaBudget};

use emit::{emit_bssid_entities, emit_ssid_entities, extract_bluetooth_intel, extract_cell_intel};
#[cfg(test)]
use fetch::get_with_retry;
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

/// Access points emitted per geo search. A bbox query returns up to 100
/// networks; the closest few are the ones that locate anything, and the true
/// distinct count rides along on every emitted entity as `aps_observed`.
const MAX_EMITTED_APS: usize = 5;

/// Per-scan + per-session WiGLE budgets, backed by the shared
/// [`QuotaBudget`] primitive that `util::see_know` and
/// `util::oathnet` already use.
///
/// WiGLE's quota is generous (300/day free, higher tiers paid) so we
/// allow, **per HTTP request issued** — not per dispatch:
///   - 3 geo searches per scan (the most expensive endpoint — bbox
///     scan returns up to 100 networks)
///   - 5 BSSID lookups per scan (single-record, cheap)
///   - 2 cell tower searches per scan
///   - 2 Bluetooth beacon searches per scan
///   - 3 SSID searches per scan
///
/// The per-request denomination is the whole point and was previously
/// only aspirational: a dispatch is charged one unit, but a geo dispatch
/// issues a second request when the tight bounding box comes back empty,
/// and a BSSID dispatch probes the WiFi, cell and Bluetooth corpora in
/// turn. A scan billed for 3 + 5 could therefore spend 6 + 15 against an
/// allowance denominated in requests. Every call site now charges
/// immediately before the request it pays for, so these numbers mean
/// what they say.
///
/// [`BSSID_BUDGET`] is shared with `modules::wifi_intel`, which resolves
/// scanned access points through the same `/detail` endpoint on the same
/// credentials; two modules drawing on one upstream quota have to meter
/// against one budget or neither number is real.
///
/// Session ceilings (50/100/30/30/40 respectively) keep `hse serve` /
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
        ssid: SSID_BUDGET.snapshot(),
    }
}

/// Every WiGLE budget in one struct, for diagnostic surfaces.
///
/// `ssid` was missing here while being declared, reset and consumed like the
/// rest, so an operator whose SSID allowance was exhausted saw nothing on
/// `/api/v1/stats` or in the dossier and had no way to tell why SSID pivots had
/// stopped firing.
#[derive(Debug, Clone, Copy)]
pub struct WigleBudgets {
    pub geo: BudgetSnapshot,
    pub bssid: BudgetSnapshot,
    pub cell: BudgetSnapshot,
    pub bluetooth: BudgetSnapshot,
    pub ssid: BudgetSnapshot,
}

pub struct Wigle;

#[async_trait]
impl Module for Wigle {
    fn name(&self) -> &'static str {
        "wigle"
    }
    fn description(&self) -> &'static str {
        "WiGLE wireless intel — pulls WiFi, cell-tower, and Bluetooth beacon observations by coords or BSSID to geolocate signals"
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
            EntityKind::Ssid,
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

        // Each sub-search charges at the point a request is actually issued —
        // SSID past its skip filters, BSSID per observation kind probed — so a
        // dispatch that ends up making no call costs the operator nothing.
        if target.kind == TargetKind::Ssid {
            return self
                .ssid_search(user, token, target.value.trim(), ctx)
                .await;
        }

        if target.kind == TargetKind::MacAddress {
            return self.bssid_lookup(user, token, &target.value, ctx).await;
        }

        if !GEO_BUDGET.try_increment() {
            return Ok(ModuleResult::new());
        }

        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        // Tight bbox first, widening only when it came back empty. The widened
        // retry is a second billable request, so it draws its own unit: charging
        // once for a path that issues two calls is what made a documented
        // "3 geo searches per scan" cost up to six.
        let tight = fetch_wigle(&ctx.http, user, token, lat, lon, 0.002).await?;
        let empty = tight.success != Some(true)
            || tight.total_results.or(tight.result_count).unwrap_or(0) == 0;
        let body = if empty && GEO_BUDGET.try_increment() {
            fetch_wigle(&ctx.http, user, token, lat, lon, 0.01).await?
        } else {
            tight
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
        let mut coords_entity = Entity::new(
            EntityKind::Coordinates,
            &target.value,
            confidence::HIGH_PLUSPLUS_PLUS,
            &ctx.scan_id,
        );
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
        if let Some(ca) = emit::consensus_address(&body.results, confidence::HIGH, &ctx.scan_id) {
            let mut addr = ca.entity;
            addr.tag("wifi-derived");
            addr.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Address from WiFi AP consensus near {}", target.value),
                )
                .with_attr("networks_sampled", total.to_string())
                .with_attr("city", ca.top_city)
                .with_attr("region", ca.top_region)
                .with_attr("country", ca.top_country),
            );
            result.push(addr);
        }

        // ── SSID intelligence: extract names and business identifiers ──
        // Named-looking SSIDs ("Smith-Family") → identity leads.
        if let Some(ssid_ev) =
            named_ssid_evidence(&body.results, &target.value, most_recent.as_deref())
            && let Some(first) = result.entities.first_mut()
        {
            first.add_evidence(ssid_ev);
        }
        // …and as pivotable entities, so the expansion loop can resolve each
        // name back to every location that network has been observed at.
        result.extend(named_ssid_entities(
            &body.results,
            &target.value,
            &ctx.scan_id,
        ));

        // ── Top MAC addresses (AP BSSIDs) + each AP's OWN observed position ──
        result.extend(wifi_ap_entities(
            &body.results,
            lat,
            lon,
            &target.value,
            &ctx.scan_id,
        ));

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

/// Build the per-AP entities for the WiFi geo path: the five nearest BSSIDs as
/// `MacAddress` device pivots AND — crucially — each AP's OWN WiGLE-trilaterated
/// position as a first-class `geoint` `Coordinates` node. The WiFi path
/// previously tagged every BSSID with the QUERY centre and discarded each AP's
/// real `trilat`/`trilong`, while the cell/BSSID paths already emit them — so the
/// densest WiGLE source threw away its own observed coordinates and mislabelled
/// each AP's location as the query point. APs are ranked by distance from the
/// query centre (closest first); a record with no usable position falls back to
/// the query point for ranking and the MAC's `coordinates` attr, but yields no
/// phantom `Coordinates` node. **Pure** (offline OUI/geo lookups only).
fn wifi_ap_entities(
    results: &[Network],
    qlat: f64,
    qlon: f64,
    query_label: &str,
    scan_id: &str,
) -> Vec<Entity> {
    // (BSSID, distance-from-query-centre, the AP's own position if WiGLE gave one).
    type ApRank<'a> = (&'a str, f64, Option<(f64, f64)>);
    let mut macs: Vec<ApRank> = results
        .iter()
        .filter_map(|n| {
            let mac = n.netid.as_deref()?;
            let ap = match (n.trilat, n.trilong) {
                (Some(t), Some(g)) if crate::util::geo::is_valid_coords(t, g) => Some((t, g)),
                _ => None,
            };
            let (alat, alon) = ap.unwrap_or((qlat, qlon));
            let dist = ((alat - qlat).powi(2) + (alon - qlon).powi(2)).sqrt();
            Some((mac, dist, ap))
        })
        .collect();
    // Deduplicate BEFORE ranking. `dedup_by_key` only removes CONSECUTIVE
    // duplicates, so deduplicating after a distance sort left a BSSID that
    // WiGLE reported twice at slightly different positions as two separate
    // entries — consuming two of the emitted slots with one access point.
    macs.sort_by(|a, b| a.0.cmp(b.0));
    macs.dedup_by_key(|m| m.0);
    let distinct_aps = macs.len();
    macs.sort_by(|a, b| {
        a.1.partial_cmp(&b.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            // Total order: equal distances tie-break on BSSID so the emitted
            // set is identical across runs regardless of response ordering.
            .then_with(|| a.0.cmp(b.0))
    });

    let mut out = Vec::new();
    for &(mac, _, ap) in macs.iter().take(MAX_EMITTED_APS) {
        if mac.len() < 12 {
            continue;
        }
        // The AP's OWN trilaterated position when WiGLE provides it (each AP is
        // observed at its own spot, not the query centre); fall back to the query
        // point only when the record carries no position.
        let (clat, clon) = ap.unwrap_or((qlat, qlon));
        let coord_val = format!("{clat:.6},{clon:.6}");

        let mut e = Entity::new(
            EntityKind::MacAddress,
            mac,
            confidence::MEDIUM_PLUS,
            scan_id,
        );
        e.tag("wigle");
        e.tag(crate::core::tags::WIFI_AP);
        let mut ev = Evidence::new(SRC, format!("WiFi AP near {query_label}"))
            .with_attr("coordinates", &coord_val)
            // The emitted set is the closest `MAX_EMITTED_APS`; state how many
            // distinct APs were actually observed so a bounded view is never
            // mistaken for the whole corpus.
            .with_attr("aps_observed", distinct_aps.to_string());
        if let Some(oui) = crate::util::oui::classify_mac(mac) {
            e.tag(format!("vendor:{}", oui.vendor));
            e.tag(format!("device:{}", oui.class.as_str()));
            ev = ev
                .with_attr("vendor", oui.vendor)
                .with_attr("device_class", oui.class.as_str());
        }
        e.add_evidence(ev);
        out.push(e);

        // Emit the AP's actual observed position as a first-class geoint node —
        // only when WiGLE gave a real per-AP position (no phantom from the
        // query-point fallback).
        if let Some((alat, alon)) = ap {
            let mut ce = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::HIGH_PLUS,
                scan_id,
            );
            ce.tag("wigle");
            ce.tag("wifi-observed");
            ce.tag("geoint");
            if let Some(state) = crate::util::geo::au_state_for_coords(alat, alon) {
                ce.tag(format!("au-state:{state}"));
                ce.tag("country:AU");
            }
            ce.add_evidence(
                Evidence::new(SRC, format!("WiGLE-observed position of WiFi AP {mac}"))
                    .with_attr("bssid", mac)
                    .with_attr("latitude", format!("{alat:.6}"))
                    .with_attr("longitude", format!("{alon:.6}")),
            );
            out.push(ce);
        }
    }
    out
}

/// SSIDs from a result set that look like a name a PERSON chose rather than a
/// vendor default: at least two `-`/`_`/space separated parts, a first part of
/// three or more characters starting with a capital, and not a
/// carrier/default name ([`is_generic_ssid`]). Sorted and deduplicated.
///
/// One definition shared by [`named_ssid_evidence`] and
/// [`named_ssid_entities`], so the prose count and the emitted entities can
/// never disagree about which networks qualified.
fn named_ssids(results: &[Network]) -> Vec<String> {
    let mut names: Vec<String> = results
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
    names.sort();
    names.dedup();
    names
}

/// Named networks observed near the target, as first-class [`EntityKind::Ssid`]
/// entities.
///
/// This closes WiGLE's most valuable pivot. A geo search finds `Smith-Family`
/// 200 m from the subject and the name was previously recorded only as a text
/// attribute on some other entity — a dead end. `TargetKind::Ssid` is a valid
/// scan target that this same module accepts, and [`Wigle::ssid_search`]
/// resolves a sufficiently unique SSID to every GPS point it has ever been
/// observed at. Emitting the name as an entity lets the expansion loop walk
/// that edge: from "a named network near this coordinate" to "everywhere that
/// network has been seen", which places its owner.
///
/// Confidence is deliberately `LOW`: a bounding box returns the neighbours'
/// networks too, so proximity alone does not prove the subject owns this one.
/// It sits above the expansion floor so the pivot runs, and below `MEDIUM` so
/// nothing downstream reads it as an established link — `ssid_search`'s own
/// uniqueness gate, and the correlator, decide whether it means anything.
/// **Pure** (no I/O).
fn named_ssid_entities(results: &[Network], query_label: &str, scan_id: &str) -> Vec<Entity> {
    let names = named_ssids(results);
    let observed = names.len();
    names
        .into_iter()
        .map(|ssid| {
            let mut e = Entity::new(EntityKind::Ssid, &ssid, confidence::LOW, scan_id);
            e.tag(SRC);
            e.tag("wifi-network");
            e.tag("geo-lead");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Named WiFi network observed near {query_label}"),
                )
                .with_attr("ssid", &ssid)
                .with_attr("named_ssids_observed", observed.to_string()),
            );
            e
        })
        .collect()
}

/// Extract named/business-identifier SSIDs ("Smith-Family") from a WiGLE
/// result set and build one summarising evidence record. Returns `None` when
/// no SSID passes the name-shape filter. **Pure** (no I/O) so the headline
/// count is unit-tested directly.
///
/// The evidence headline states the TRUE count of matching SSIDs, while the
/// `named_ssids` attribute lists only the first 10 (bounded attribute size)
/// — the two must stay distinct, or an operator with more than 10 named
/// networks nearby would be told a false, truncated total.
fn named_ssid_evidence(
    results: &[Network],
    target_value: &str,
    most_recent: Option<&str>,
) -> Option<Evidence> {
    let ssid_names = named_ssids(results);
    if ssid_names.is_empty() {
        return None;
    }

    let top_ssids: Vec<&str> = ssid_names.iter().take(10).map(String::as_str).collect();
    let mut ev = Evidence::new(
        SRC,
        format!(
            "{} named WiFi network(s) near {target_value}",
            ssid_names.len()
        ),
    )
    .with_attr("named_ssids", top_ssids.join(", "));
    if let Some(t) = most_recent {
        ev = ev.with_attr("most_recent", t);
    }
    Some(ev)
}

/// True when an SSID is a default/carrier/generic name rather than one a person
/// chose — the names whose WiGLE observations belong to strangers' routers, not
/// the subject's.
///
/// Two matchers, because the terms fall into two very different classes.
///
/// Distinctive vendor and carrier strings ([`GENERIC_SSID_BRANDS`]) match as
/// **substrings**: real defaults concatenate them (`xfinitywifi`, `NETGEAR47`,
/// `TelstraFDA3B2`), and the strings are long and specific enough that they do
/// not turn up inside ordinary words.
///
/// Short English words ([`GENERIC_SSID_WORDS`]) match only as **whole tokens**.
/// Substring-matching these silently destroyed the module's flagship
/// capability: `att`, `free`, `open` and `test` occur inside perfectly ordinary
/// surnames, so `Seattle-Cafe`, `Freeman-Family`, `Openshaw-House` and
/// `Testa-Household` were all classified generic — and because
/// [`Wigle::ssid_search`] consults this before issuing any request, those
/// subjects were never looked up at all. A whole-token test keeps
/// `Free Public WiFi` generic while letting `Freeman-Family` through.
pub(super) fn is_generic_ssid(s: &str) -> bool {
    let lower = s.to_lowercase();

    // One cached `aho-corasick` pass via `util::scan` (SOL-F1). Case-sensitive
    // over the Unicode-lowercased string (the patterns are lowercase), so it
    // preserves the exact `to_lowercase()` fold, unlike an ASCII-CI matcher.
    static BRANDS: std::sync::LazyLock<crate::util::scan::MatchSet> =
        std::sync::LazyLock::new(|| crate::util::scan::MatchSet::new(GENERIC_SSID_BRANDS));
    if BRANDS.is_match(&lower) {
        return true;
    }

    ssid_tokens(&lower).any(|tok| GENERIC_SSID_WORDS.contains(&tok))
}

/// Split an SSID into comparable word tokens: separated on any non-alphanumeric
/// character and at every letter↔digit boundary, so `ATT4G-Home` yields
/// `att`, `4`, `g`, `home` and the carrier prefix is recognised without
/// substring-matching `att` inside `Seattle`.
fn ssid_tokens(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split(|c: char| !c.is_alphanumeric())
        .flat_map(|part| {
            let mut tokens = Vec::new();
            let mut start = 0;
            let mut prev: Option<char> = None;
            for (idx, ch) in part.char_indices() {
                if let Some(p) = prev
                    && p.is_numeric() != ch.is_numeric()
                {
                    tokens.push(&part[start..idx]);
                    start = idx;
                }
                prev = Some(ch);
            }
            if start < part.len() {
                tokens.push(&part[start..]);
            }
            tokens
        })
        .filter(|t| !t.is_empty())
}

/// Vendor/carrier strings distinctive enough to match anywhere in the name —
/// defaults routinely concatenate them with hex or digits.
pub(super) const GENERIC_SSID_BRANDS: &[&str] = &[
    "linksys", "netgear", "dlink", "tp-link", "tplink", "xfinity", "spectrum", "optimum",
    "telstra", "optus", "vodafone", "iinet", "eduroam", "android", "iphone", "galaxy", "unnamed",
    "unknown", "hidden",
];

/// Short, common words that must match as a WHOLE TOKEN. Every one of these
/// occurs inside ordinary surnames and place names; see [`is_generic_ssid`].
/// `wifi`/`wlan` are deliberately absent: they are descriptive suffixes people
/// append to their own names (`Smith-WiFi`), so treating them as generic would
/// re-create the very false-positive class this split exists to remove.
pub(super) const GENERIC_SSID_WORDS: &[&str] = &[
    "default", "asus", "att", "cox", "nbn", "guest", "free", "public", "open", "pixel", "setup",
    "config", "admin", "test",
];

impl Wigle {
    async fn bssid_lookup(
        &self,
        user: &str,
        token: &str,
        bssid: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        // One unit per kind actually probed, not one per dispatch: a BSSID absent
        // from the WiFi and cell corpora costs three requests before the
        // Bluetooth probe answers, and the caller used to be billed for one.
        for kind in [NetworkKind::Wifi, NetworkKind::Cell, NetworkKind::Bluetooth] {
            if !BSSID_BUDGET.try_increment() {
                break;
            }
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
        // Charged here, past the skip filters: a scan whose SSIDs are all
        // carrier defaults issues no request and must keep its full allowance
        // for the one distinctive name that appears later in the pivot chain.
        if !SSID_BUDGET.try_increment() {
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
