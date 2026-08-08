//! Unified WiFi intelligence — access-point survey **and** BSSID geolocation
//! in a single `termux-wifi-scaninfo` invocation.
//!
//! Merges the former `wifi_scan` (AP enumeration → `MacAddress` entities) and
//! `bssid_locate` (top-N strongest BSSIDs → WiGLE detail → `Coordinates` +
//! `Address` entities) into one module that calls the Termux API **once**,
//! halving the radio scan overhead on-device.
//!
//! Auth: HTTP Basic — `HUNTSMAN_WIGLE_USER` / `HUNTSMAN_WIGLE_TOKEN` with
//! hardcoded fallback, same as the `wigle` module.

mod types;
mod wigle;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::modules::termux_sensor;
use crate::util::geo::is_valid_coords;

// ── WiGLE credentials ───────────────────────────────

// Env names + embedded fallbacks are resolved by the single-sourced
// `crate::util::keys::wigle_credentials` (shared with the `wigle` module).

/// How many of the strongest APs to query WiGLE for.
const MAX_BSSIDS: usize = 5;

/// Evidence source tag used throughout this module.
pub(super) const SOURCE: &str = "wifi_intel";

// ── Module implementation ──────────────────────────────

pub struct WifiIntel;

#[async_trait]
impl Module for WifiIntel {
    fn name(&self) -> &'static str {
        "wifi_intel"
    }

    fn description(&self) -> &'static str {
        "WiFi AP survey — sweeps nearby access points via Termux and geolocates each BSSID through WiGLE"
    }

    fn priority(&self) -> u8 {
        65
    }

    fn is_passive(&self) -> bool {
        // Classed passive as a local sensor: the primary action is reading
        // on-device Wi-Fi radios via termux-wifi-scaninfo, and off-Termux
        // the module no-ops before any network use. CAVEAT: when run
        // on-device with scan results, the top-N strongest BSSIDs are
        // enriched via the WiGLE API — so under --passive-only this module
        // CAN still egress for geolocation. This is intentional (it lives in
        // engine::LOCAL_PASSIVE_MODULES as a seed-round sensor); a strict
        // no-egress guarantee would require gating the WiGLE step on a
        // passive flag. Surfaced by `hse modules`.
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        // Surveys the operator's OWN Wi-Fi radios (local APs), so it must not run
        // on a remote-subject scan — engage only on a deliberately-local seed
        // (coordinates / MAC), never a name/email/domain/IP, so the operator's
        // APs aren't attributed to the subject (fault-tree cut set MCS-A).
        matches!(t.kind, TargetKind::Coordinates | TargetKind::MacAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1592"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::MacAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
        ];
        KINDS
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (user, token) = crate::util::keys::wigle_credentials(ctx);

        // ── Single termux-wifi-scaninfo call ─────────────────
        let Some(stdout) = termux_sensor::Sensor::WifiScan.read().await else {
            return Ok(ModuleResult::new());
        };

        // Blank output means the tool exited 0 with nothing to report — an
        // honest empty answer. Non-blank output that will not parse means the
        // tool answered with something broken, which is a malfunction and must
        // surface as a real error: reporting it as zero access points would be
        // indistinguishable from "no Wi-Fi in range". Mirrors
        // `signal_radar::wifi::parse_scan`, which shares this tool.
        if termux_sensor::is_blank(&stdout) {
            return Ok(ModuleResult::new());
        }
        let mut aps: Vec<types::Ap> = serde_json::from_slice(&stdout).map_err(|e| {
            termux_sensor::unparseable_for(SOURCE, termux_sensor::Sensor::WifiScan, &e)
        })?;

        // Drop placeholder/sentinel BSSIDs (empty, or the all-zero row Termux's
        // Wi-Fi scan emits for an unresolved AP entry) before either phase below
        // sees them. `crate::util::oui::is_locally_administered` reads
        // `00:00:00:00:00:00`'s U/L bit as clear — a real, "trackable" hardware
        // address — so an unfiltered placeholder here would mint a MacAddress
        // entity that AU-122 (trackable RF device) wrongly counts as a real,
        // followable device. `signal_radar::wifi::parse_scan` filters this same
        // Termux tool's output for the identical reason; this module reads the
        // same tool but previously had no equivalent guard at all.
        aps.retain(|ap| !crate::util::oui::is_placeholder_bssid(&ap.bssid));

        if aps.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Sort by signal strength (strongest first) so top-N selection is
        // deterministic; we walk the full list for MacAddress entities but
        // only query WiGLE for the first MAX_BSSIDS.
        aps.sort_by_key(|a| std::cmp::Reverse(a.rssi.unwrap_or(-100)));

        let mut result = ModuleResult::with_capacity(aps.len());

        // ── Phase 1: MacAddress entities for ALL APs ────────────
        result.extend(aps.iter().map(|ap| {
            let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
            let mut e = Entity::new(
                EntityKind::MacAddress,
                &ap.bssid,
                confidence::VERY_HIGH_PLUSPLUS,
                &ctx.scan_id,
            );
            e.tag(crate::core::tags::WIFI_AP);
            e.add_evidence(
                Evidence::new(SOURCE, format!("Wi-Fi AP: {ssid}"))
                    .with_attr("ssid", ssid)
                    .with_attr("bssid", &ap.bssid)
                    .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
                    .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
                    .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string()),
            );
            e
        }));

        // ── Phase 2: WiGLE geolocation for top-N strongest APs ─────────
        for ap in aps.iter().take(MAX_BSSIDS) {
            if ctx.cancel.is_cancelled() {
                break;
            }

            if ap.bssid.len() < 12 {
                continue;
            }

            // These are WiGLE `/detail` lookups on the operator's own credentials
            // and daily allowance — the same endpoint and the same quota the
            // `wigle` module meters as BSSID_BUDGET. Drawing on that shared
            // budget rather than none is what keeps the accounting true: this
            // loop could otherwise spend five requests per dispatch, invisibly,
            // and radar now pivots without a depth restriction.
            if !crate::modules::wigle::BSSID_BUDGET.try_increment() {
                break;
            }

            // A refusal is about the ACCOUNT, not this BSSID: a 429 (or an auth
            // failure) will refuse the next four APs identically. Continuing
            // used to spend a shared BSSID_BUDGET unit per remaining AP on
            // requests that could not succeed — a live radar sweep was observed
            // burning all five on one rate-limited dispatch. A miss (`Ok(None)`)
            // is per-BSSID and does keep the loop going.
            let detail = match wigle::query_wigle_detail(&ctx.http, user, token, &ap.bssid).await {
                Ok(found) => found,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "wifi_intel: WiGLE refused — stopping this dispatch's BSSID lookups"
                    );
                    break;
                }
            };

            if let Some(detail) = detail
                && let (Some(lat), Some(lon)) = (detail.trilat, detail.trilong)
            {
                // Shared validator: Null Island + out-of-range + non-finite.
                if !is_valid_coords(lat, lon) {
                    continue;
                }

                let coords = format!("{lat:.6},{lon:.6}");
                let ssid = detail
                    .ssid
                    .as_deref()
                    .or(ap.ssid.as_deref())
                    .unwrap_or("<hidden>");

                let mut e = Entity::new(
                    EntityKind::Coordinates,
                    &coords,
                    confidence::HIGH_PLUSPLUS,
                    &ctx.scan_id,
                );
                e.tag("geoint");
                e.tag(crate::core::tags::WIFI_AP);
                e.tag("bssid-located");

                let mut ev = Evidence::new(
                    SOURCE,
                    format!("BSSID {} ({ssid}) \u{2192} {coords}", ap.bssid),
                )
                .with_attr("bssid", &ap.bssid)
                .with_attr("ssid", ssid)
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "WiGLE");

                if let Some(rssi) = ap.rssi {
                    ev = ev.with_attr("rssi_dbm", rssi.to_string());
                }
                if let Some(c) = detail.city.as_deref() {
                    ev = ev.with_attr("city", c);
                }
                if let Some(r) = detail.region.as_deref() {
                    ev = ev.with_attr("region", r);
                }
                if let Some(c) = detail.country.as_deref() {
                    ev = ev.with_attr("country", c);
                }
                if let Some(p) = detail.postalcode.as_deref() {
                    ev = ev.with_attr("postcode", p);
                }
                if let Some(t) = detail.lastupdt.as_deref() {
                    ev = ev.with_attr("last_updated", t);
                }
                if let Some(enc) = detail.encryption.as_deref() {
                    ev = ev.with_attr("encryption", enc);
                }

                e.add_evidence(ev);
                result.push(e);

                // Also emit an Address entity if we have city + country
                let addr_parts: Vec<&str> = [
                    detail.city.as_deref(),
                    detail.region.as_deref(),
                    detail.country.as_deref(),
                ]
                .iter()
                .filter_map(|p| *p)
                .filter(|p| !p.is_empty())
                .collect();

                if addr_parts.len() >= 2 {
                    let mut addr_str = addr_parts.join(", ");
                    if let Some(p) = detail.postalcode.as_deref()
                        && !p.is_empty()
                    {
                        addr_str = format!("{addr_str} {p}");
                    }
                    let mut addr = Entity::new(
                        EntityKind::Address,
                        &addr_str,
                        confidence::MEDIUM_PLUS,
                        &ctx.scan_id,
                    );
                    addr.tag("geoint");
                    addr.tag("bssid-derived");
                    addr.add_evidence(
                        Evidence::new(SOURCE, format!("Address from BSSID {} location", ap.bssid))
                            .with_attr("bssid", &ap.bssid),
                    );
                    result.push(addr);
                }
            }
        }

        Ok(result)
    }
}

// ── Standalone AP parser ───────────────────────────
//
// A test-only shadow of the AP-parsing half of `process()`, which cannot be
// unit-tested directly because it needs a live `termux-wifi-scaninfo` and a
// `ModuleContext`. It must therefore keep the SAME blank/unparseable/
// placeholder-BSSID contract as `process()`: a shadow that silently diverges
// would let its tests report coverage of behaviour the production path no
// longer has.

#[cfg(test)]
fn parse_aps(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    if termux_sensor::is_blank(stdout) {
        return Ok(ModuleResult::new());
    }
    let aps: Vec<types::Ap> = serde_json::from_slice(stdout)
        .map_err(|e| termux_sensor::unparseable_for(SOURCE, termux_sensor::Sensor::WifiScan, &e))?;

    let mut result = ModuleResult::with_capacity(aps.len());
    for ap in aps {
        if crate::util::oui::is_placeholder_bssid(&ap.bssid) {
            continue;
        }
        let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
        let mut e = Entity::new(
            EntityKind::MacAddress,
            &ap.bssid,
            confidence::VERY_HIGH_PLUSPLUS,
            scan_id,
        );
        e.tag(crate::core::tags::WIFI_AP);
        e.add_evidence(
            Evidence::new(SOURCE, format!("Wi-Fi AP: {ssid}"))
                .with_attr("ssid", ssid)
                .with_attr("bssid", ap.bssid)
                .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
                .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
                .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string()),
        );
        result.push(e);
    }
    Ok(result)
}
