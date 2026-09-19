//! Unified WiFi intelligence — access-point survey **and** BSSID geolocation
//! in a single `termux-wifi-scaninfo` invocation.
//!
//! Merges the former `wifi_scan` (AP enumeration → `MacAddress` entities) and
//! `bssid_locate` (top-N strongest BSSIDs → WiGLE detail → `Coordinates` +
//! `Address` entities) into one module that calls the Termux API **once**,
//! halving the radio scan overhead on-device.
//!
//! Auth: HTTP Basic — `HUNTSMAN_WIGLE_USER` / `HUNTSMAN_WIGLE_TOKEN`, both
//! required, same as the `wigle` module. No credential is embedded in the build.
//!
//! ## A missing coordinate always says why
//!
//! The two phases have different failure semantics and must not be collapsed.
//! Phase 1 is the operator's own radio: seeing an AP on the air is this
//! module's observation and owes nothing to WiGLE. Phase 2 asks WiGLE where
//! each of the strongest APs is, and that question can go unanswered for
//! reasons that have nothing to do with the AP — a revoked token, a spent
//! quota, a WAF, a schema change.
//!
//! Because Phase 1 always produces entities whenever any AP was heard, the
//! result is never empty, so [`ModuleResult::or_hard_failure`] — the shared
//! fold that turns a total outage into a real `ModuleError` — can never fire
//! here, and returning `Err` would throw away genuine local sensor readings to
//! report a WiGLE problem. Both of the usual answers are therefore wrong for
//! this module.
//!
//! What it does instead, per `core::coverage`'s standing rule that PROVIDER
//! FAILURE ≠ ZERO EVIDENCE:
//!
//! * every AP the geolocation leg was willing to ask about carries a
//!   `wigle_lookup` attribute on its own `MacAddress` evidence whenever WiGLE
//!   did **not** answer, naming the refusal or why it was never asked; and
//! * a refusal is additionally reported to the scan's event log as a
//!   `ModuleError`, beside the `ModuleDone` the engine emits for the findings
//!   that were kept, so `provider_coverage_from_events` reads this provider as
//!   `Failed` rather than `Observed`.
//!
//! Without both, an AP with no `Coordinates` beside it reads as "WiGLE holds
//! no position for this access point" — a clean negative the module was in no
//! position to make.

mod types;
mod wigle;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    event::{Event, EventKind},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::modules::termux_sensor;
use crate::util::geo::is_plausible_provider_coord;

// ── WiGLE credentials ──────────────────────────────────────────────────

// Env names are resolved by the single-sourced
// `crate::util::keys::wigle_credentials` (shared with the `wigle` module),
// which yields `None` unless the operator configured BOTH halves of the pair.

/// How many of the strongest APs to query WiGLE for.
const MAX_BSSIDS: usize = 5;

/// Evidence source tag used throughout this module.
pub(super) const SOURCE: &str = "wifi_intel";

/// Evidence attribute naming what became of an AP's WiGLE geolocation lookup.
/// Present only when WiGLE did not answer — its absence means it did.
const LOOKUP_ATTR: &str = "wigle_lookup";

// ── Module implementation ──────────────────────────────────────────────

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
        // T1596 (Search Open Technical Databases): the WiGLE-detail lookup
        // phase queries the same crowdsourced open WiFi/cell database the
        // sibling wigle/mylnikov/opencellid modules claim T1596 for.
        &["T1591.001", "T1592", "T1596"]
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
        // See `wigle`: the API-name/token pair is required, and no credential is
        // embedded in the build.
        let (user, token) = crate::util::keys::wigle_credentials(ctx)
            .ok_or_else(|| Error::MissingKey("HUNTSMAN_WIGLE_TOKEN".into()))?;

        // ── Single termux-wifi-scaninfo call ────────────────────────────
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

        if aps.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Sort by signal strength (strongest first) so top-N selection is
        // deterministic; we walk the full list for MacAddress entities but
        // only query WiGLE for the first MAX_BSSIDS.
        aps.sort_by_key(|a| std::cmp::Reverse(a.rssi.unwrap_or(-100)));

        let mut result = ModuleResult::with_capacity(aps.len());

        // ── Phase 1: MacAddress entities for ALL APs ────────────────────
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
        //
        // `outcomes` records what became of each lookup, in the order they were
        // taken. Phase 3 writes it onto the AP's own entity and Phase 4 reports
        // a refusal to the scan's coverage ledger — see the module header: the
        // silence left by an unanswered lookup is not WiGLE saying no.
        let mut outcomes: Vec<(&str, Lookup)> = Vec::with_capacity(MAX_BSSIDS);
        // What every remaining AP in the window inherits once the leg stops.
        // `None` while it is still running.
        let mut stopped: Option<Lookup> = None;
        for ap in aps.iter().take(MAX_BSSIDS) {
            if ctx.cancel.is_cancelled() {
                stopped = Some(Lookup::NotAttempted("scan cancelled"));
                break;
            }

            if ap.bssid.len() < 12 {
                // Per-AP and not a WiGLE outcome at all: the sensor handed us
                // something that is not a BSSID, so nothing was asked about it.
                outcomes.push((ap.bssid.as_str(), Lookup::NotAttempted("malformed BSSID")));
                continue;
            }

            // These are WiGLE `/detail` lookups on the operator's own credentials
            // and daily allowance — the same endpoint and the same quota the
            // `wigle` module meters as BSSID_BUDGET. Drawing on that shared
            // budget rather than none is what keeps the accounting true: this
            // loop could otherwise spend five requests per dispatch, invisibly,
            // and radar now pivots without a depth restriction.
            if !crate::modules::wigle::BSSID_BUDGET.try_increment() {
                stopped = Some(Lookup::NotAttempted(
                    "shared WiGLE BSSID budget spent for this scan",
                ));
                break;
            }

            // A refusal is about the ACCOUNT, not this BSSID: a 429 (or an auth
            // failure) will refuse the next four APs identically. Continuing
            // used to spend a shared BSSID_BUDGET unit per remaining AP on
            // requests that could not succeed — a live radar sweep was observed
            // burning all five on one rate-limited dispatch. A miss (`Ok(None)`)
            // is per-BSSID and does keep the loop going.
            let detail = match wigle::query_wigle_detail(&ctx.http, user, token, &ap.bssid).await {
                Ok(found) => {
                    // WiGLE spoke about this BSSID. `None` here is a real
                    // negative — the corpus holds no position for it — and is
                    // the ONE case that needs no disclosure.
                    outcomes.push((ap.bssid.as_str(), Lookup::Answered));
                    found
                }
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "wifi_intel: WiGLE refused — stopping this dispatch's BSSID lookups"
                    );
                    stopped = Some(Lookup::Refused(e.to_string()));
                    break;
                }
            };

            if let Some(detail) = detail
                && let (Some(lat), Some(lon)) = (detail.trilat, detail.trilong)
            {
                // REQ-WIFIINTEL-001: WiGLE is a coarse location provider and must
                // reject the near-null-island jitter band (0.001 to 0.01) that geolocation
                // APIs emit as an "unknown" placeholder. The stricter is_plausible_provider_coord
                // gate is required, not the weaker is_valid_coords.
                if !is_plausible_provider_coord(lat, lon) {
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

                // Attributed to the CORPUS this position came from, not to the
                // module that fetched it.
                //
                // The standalone `wigle` module is the PRIMARY resolver for
                // `MacAddress` targets and reaches the same records with the
                // same credentials. This module emits those `MacAddress`
                // entities, so the engine expands them straight into it — the
                // designed pivot, not a corner case — and both mint the AP's
                // position as `{lat:.6},{lon:.6}`. Same value, same kind, so the
                // two entities share a UID and merge. Stamped with this module's
                // own name, that merge produced TWO distinct corroborating
                // sources for ONE record from ONE corpus, and `source_count()`
                // fed it straight into `c_effective`.
                //
                // The `MacAddress` entities above keep `SOURCE`: seeing an AP on
                // the air really is this module's own observation, independent
                // of whether WiGLE has ever recorded it.
                let mut ev = Evidence::new(
                    crate::modules::wigle::SRC,
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
                        // Same corpus as the coordinate above: this locality is
                        // WiGLE's city/region/country for the AP, and `wigle`
                        // builds the identical `city, region, country postcode`
                        // string from the same fields.
                        Evidence::new(
                            crate::modules::wigle::SRC,
                            format!("Address from BSSID {} location", ap.bssid),
                        )
                        .with_attr("bssid", &ap.bssid),
                    );
                    result.push(addr);
                }
            }
        }

        // Every AP the leg would have asked about but never reached inherits
        // the reason it stopped — including the one it was refused on. Their
        // absence of a coordinate has exactly the same cause.
        if let Some(stopped) = stopped {
            let asked: std::collections::HashSet<&str> = outcomes.iter().map(|(b, _)| *b).collect();
            let unreached: Vec<(&str, Lookup)> = aps
                .iter()
                .take(MAX_BSSIDS)
                .map(|a| a.bssid.as_str())
                .filter(|b| !asked.contains(b))
                .map(|b| (b, stopped.clone()))
                .collect();
            outcomes.extend(unreached);
        }

        // ── Phase 3: every unanswered lookup says so on its own entity ──
        disclose_lookups(&mut result, &outcomes);

        // ── Phase 4: a refusal reaches the scan's coverage ledger ───────
        if let Some(reason) = leg_failure(&outcomes) {
            // PROVIDER FAILURE ≠ ZERO EVIDENCE (`core::coverage`). This event
            // sits beside the `ModuleDone` the engine emits for the Phase 1
            // findings, which are kept: `provider_coverage_from_events` is
            // failure-dominant, so the pair reads as `Failed { reason }` with
            // the findings still counted — the shape
            // `a_partial_outage_dominates_the_findings_it_sits_beside` locks.
            // Returning `Err` instead would discard real local sensor readings
            // to report a WiGLE problem, and `or_hard_failure` cannot fire on
            // a result Phase 1 has already filled.
            let _ = ctx.bus.send(Event::new(
                ctx.scan_id.as_str(),
                EventKind::ModuleError {
                    module: SOURCE.to_string(),
                    error: reason,
                },
            ));
        }

        Ok(result)
    }
}

/// What became of one access point's WiGLE geolocation lookup.
///
/// The distinction this type exists to keep is between WiGLE *answering* and
/// WiGLE *not being heard from*. Only the first can make a missing coordinate
/// mean "no position on record"; every other variant leaves the AP's position
/// simply unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Lookup {
    /// WiGLE answered about this BSSID. A `None` answer, or one rejected by
    /// [`is_plausible_provider_coord`], is a genuine negative.
    Answered,
    /// WiGLE refused to answer — auth, quota, transport or schema. Carries the
    /// typed error's own message.
    Refused(String),
    /// Never asked, and why. Not a provider failure: these are this module's
    /// own governors (the shared BSSID budget, scan cancellation) or bad sensor
    /// input, so they are disclosed on the entity but never reported against
    /// WiGLE.
    NotAttempted(&'static str),
}

impl Lookup {
    /// The [`LOOKUP_ATTR`] value for this outcome, or `None` when WiGLE
    /// answered and the entity needs no disclosure.
    fn disclosure(&self) -> Option<String> {
        match self {
            Self::Answered => None,
            Self::Refused(why) => Some(format!("refused: {why}")),
            Self::NotAttempted(why) => Some(format!("not attempted: {why}")),
        }
    }
}

/// Record on each AP's own `MacAddress` evidence what became of its WiGLE
/// lookup, for every outcome that was not a real answer.
///
/// Matched on `raw_value`, which is the BSSID exactly as the sensor reported
/// it; `Entity::value` is the normalised form and need not be byte-equal.
/// **Pure** — no network, no context — so the disclosure is unit-testable
/// against a built result.
fn disclose_lookups(result: &mut ModuleResult, outcomes: &[(&str, Lookup)]) {
    for (bssid, outcome) in outcomes {
        let Some(note) = outcome.disclosure() else {
            continue;
        };
        let Some(entity) = result
            .entities
            .iter_mut()
            .find(|e| e.kind == EntityKind::MacAddress && e.raw_value == *bssid)
        else {
            continue;
        };
        let Some(ev) = entity.evidence.iter_mut().find(|ev| ev.source == SOURCE) else {
            continue;
        };
        ev.attributes.insert(LOOKUP_ATTR.to_string(), note);
    }
}

/// The reason a cut-short geolocation leg reports to the scan's coverage
/// ledger, or `None` when WiGLE answered everything it was asked.
///
/// ONLY a provider refusal qualifies. A leg stopped by this module's own shared
/// BSSID budget, by scan cancellation, or by a BSSID the sensor mangled is not
/// WiGLE failing: reporting it as one would put a fabricated outage in the
/// coverage report and in module health, which is the same class of error —
/// a cause asserted that was never observed — as the silence this whole
/// mechanism exists to prevent. Those cases are disclosed on the entity and
/// stop there.
///
/// **Pure**, so the decision is unit-testable without a radio or a network.
fn leg_failure(outcomes: &[(&str, Lookup)]) -> Option<String> {
    let refused = outcomes.iter().find_map(|(_, o)| match o {
        Lookup::Refused(why) => Some(why.as_str()),
        Lookup::Answered | Lookup::NotAttempted(_) => None,
    })?;
    let answered = outcomes
        .iter()
        .filter(|(_, o)| *o == Lookup::Answered)
        .count();
    Some(format!(
        "WiGLE geolocation refused after {answered} of {} BSSID lookups: {refused}",
        outcomes.len()
    ))
}

// ── Standalone AP parser ───────────────────────────────────────────────
//
// A test-only shadow of the AP-parsing half of `process()`, which cannot be
// unit-tested directly because it needs a live `termux-wifi-scaninfo` and a
// `ModuleContext`. It must therefore keep the SAME blank/unparseable contract
// as `process()`: a shadow that silently diverges would let its tests report
// coverage of behaviour the production path no longer has.

#[cfg(test)]
fn parse_aps(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    if termux_sensor::is_blank(stdout) {
        return Ok(ModuleResult::new());
    }
    let aps: Vec<types::Ap> = serde_json::from_slice(stdout)
        .map_err(|e| termux_sensor::unparseable_for(SOURCE, termux_sensor::Sensor::WifiScan, &e))?;

    let mut result = ModuleResult::with_capacity(aps.len());
    for ap in aps {
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
