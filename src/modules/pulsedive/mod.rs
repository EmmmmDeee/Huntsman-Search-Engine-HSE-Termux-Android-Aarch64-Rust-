//! Pulsedive threat-intelligence / IOC enrichment lookup. Key-gated; a free
//! account (no payment) unlocks 50 requests/day and 500/month, versus 10/day
//! and 100/month for an unregistered/no-key request — see
//! <https://blog.pulsedive.com/pulsedive-plan-updates-2024/>.
//!
//! Endpoint: `GET https://pulsedive.com/api/info.php?indicator=<value>&key=<key>`
//!
//! `info.php` is Pulsedive's long-standing indicator-lookup endpoint (still
//! live and documented by the vendor's own current threat-intel integrations —
//! e.g. TheHive's Cortex-Analyzers Pulsedive analyzer and SpiderFoot's
//! `sfp_pulsedive` both call it exactly this way, `?indicator=<value>&key=<key>`)
//! and is the one this repo already has a verified-working key for. Pulsedive's
//! newer docs site (<https://docs.pulsedive.com/api/indicator/get-by-value.md>)
//! documents a `indicator.php` endpoint with an equivalent response shape
//! (`risk`, `risk_recommended`, `riskfactors`, `threats`, `feeds`,
//! `properties.geo`, `stamp_*` fields — confirmed against that page's own
//! worked example); the two endpoints share the same underlying record, and
//! `info.php` is kept here to match the credential already provisioned for it.
//!
//! Auth: `key` query parameter (not a header — Pulsedive's own scheme).
//!
//! Querying an indicator Pulsedive has never seen does not 404 — it answers
//! `HTTP 200` with a thin/`"unknown"`-risk record (confirmed by SpiderFoot's own
//! handling, which checks only for 403/429 and otherwise treats an empty
//! `threats` list as "nothing to report"); a malformed/rejected indicator value
//! answers with a `{"error": "..."}` body instead. Both are treated as a clean
//! miss here, never fabricated as a finding.
//!
//! Surfaces Pulsedive's own risk classification (`unknown`/`none`/`low`/
//! `medium`/`high`/`critical`, per <https://docs.pulsedive.com/model/risk.md>),
//! the risk-factor descriptions behind it, linked threats (malware/campaign
//! names + categories) and linked feeds (which third-party blocklists/feeds
//! carry the indicator) as evidence, plus the indicator's hosting geo (country/
//! city/organisation) as `Address`/`Organisation` pivots when Pulsedive reports
//! one. Individual threat/feed comments are not stored — Pulsedive's `comments`
//! field is free-text and out of scope for this enrichment.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::str_util::nonempty;

const KEY_ENV: &str = "HUNTSMAN_PULSEDIVE_KEY";
const SRC: &str = "pulsedive";

// ── Response types ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct InfoResp {
    /// Present on a malformed/rejected `indicator` value (e.g. Pulsedive's own
    /// "Indicator not found." message) — a clean miss, not a finding.
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    iid: Option<i64>,
    #[serde(default)]
    risk: Option<String>,
    #[serde(default)]
    risk_recommended: Option<String>,
    #[serde(default)]
    submissions: Option<u64>,
    #[serde(default)]
    stamp_added: Option<String>,
    #[serde(default)]
    stamp_updated: Option<String>,
    #[serde(default)]
    stamp_seen: Option<String>,
    #[serde(default)]
    riskfactors: Vec<RiskFactor>,
    #[serde(default)]
    threats: Vec<Threat>,
    #[serde(default)]
    feeds: Vec<Feed>,
    #[serde(default)]
    properties: Option<Properties>,
}

#[derive(Deserialize)]
struct RiskFactor {
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct Threat {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Deserialize)]
struct Feed {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct Properties {
    #[serde(default)]
    geo: Option<Geo>,
}

/// Subset of Pulsedive's `properties.geo` block (documented shape:
/// `countrycode`/`region`/`country`/`address`/`zip`/`city`/`org`). Populated
/// mainly for IP indicators; routinely empty (`{}`) for domain/URL indicators
/// per Pulsedive's own worked example, hence every field is optional.
#[derive(Deserialize)]
struct Geo {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    org: Option<String>,
}

// ── Pure entity-building ──────────────────────────────────────────────────

/// Per-attribute cap for the linked threat/feed name lists — plenty of signal
/// without letting a heavily-tagged IOC bloat one evidence row (mirrors
/// `threatfox`'s `MAX_FAMILIES`/`MAX_IOC_TAGS`).
const MAX_NAMES: usize = 8;

/// Map Pulsedive's `risk` string to a confidence level. Case-insensitive
/// (Pulsedive's documented values are lowercase, but this stays defensive).
/// Ladder per <https://docs.pulsedive.com/model/risk.md>: `critical` is the
/// vendor's own top severity, `none`/very-low is an actively-confirmed-benign
/// verdict (still worth reporting, at moderate confidence — same policy
/// `greynoise` uses for its "benign" classification), `unknown` means
/// Pulsedive has not yet formed a verdict at all.
fn risk_confidence(risk: &str) -> f64 {
    match risk.to_ascii_lowercase().as_str() {
        "critical" => confidence::HIGH_PLUSPLUS_PLUS,
        "high" => confidence::HIGH_PLUSPLUS,
        "medium" => confidence::HIGH_PLUS,
        "low" => confidence::MEDIUM_PLUS,
        "none" | "very low" => confidence::MEDIUM,
        _ => confidence::MEDIUM_HIGH,
    }
}

/// Build the subject + geo entities from a decoded Pulsedive `info.php`
/// response. **Pure** (no network/IO), so the risk→confidence mapping, the
/// "nothing to report" gate, and the threat/feed/geo derivation are all
/// unit-testable directly off JSON fixtures.
///
/// Gates internally: Pulsedive auto-creates a thin record the first time any
/// indicator is queried, so a `risk` of `unknown` (or absent) with nothing else
/// linked to it (no threats, feeds, or risk factors) is "not yet assessed", not
/// a finding — the caller's `error`-body short-circuit handles the other
/// clean-miss shape (a rejected/malformed indicator value).
fn build_entities(kind: EntityKind, value: &str, body: &InfoResp, scan_id: &str) -> Vec<Entity> {
    let risk = body.risk.as_deref().unwrap_or("");
    let is_unknown = risk.is_empty() || risk.eq_ignore_ascii_case("unknown");
    let nothing_linked =
        body.threats.is_empty() && body.riskfactors.is_empty() && body.feeds.is_empty();
    if is_unknown && nothing_linked {
        return Vec::new();
    }

    let mut entity = Entity::new(kind, value, risk_confidence(risk), scan_id);
    entity.tag("pulsedive");
    entity.tag(crate::core::tags::THREAT_INTEL);
    let risk_lc = risk.to_ascii_lowercase();
    if matches!(risk_lc.as_str(), "high" | "critical") || !body.threats.is_empty() {
        entity.tag(crate::core::tags::MALICIOUS);
    }

    let mut ev = Evidence::new(SRC, format!("Pulsedive risk assessment for {value}"));
    if !risk.is_empty() {
        ev = ev.with_attr("risk", risk);
    }
    if let Some(rr) = nonempty(&body.risk_recommended).filter(|r| !r.eq_ignore_ascii_case(risk)) {
        ev = ev.with_attr("risk_recommended", rr);
    }
    if let Some(s) = body.submissions.filter(|s| *s > 0) {
        ev = ev.with_attr("submissions", s.to_string());
    }

    if !body.riskfactors.is_empty() {
        let descriptions = crate::util::freq::top_n(
            body.riskfactors
                .iter()
                .filter_map(|r| nonempty(&r.description)),
            MAX_NAMES,
        );
        if !descriptions.is_empty() {
            ev = ev.with_attr("risk_factors", descriptions);
        }
    }

    if !body.threats.is_empty() {
        ev = ev.with_attr("threat_count", body.threats.len().to_string());
        let names = crate::util::freq::top_n(
            body.threats.iter().filter_map(|t| nonempty(&t.name)),
            MAX_NAMES,
        );
        if !names.is_empty() {
            ev = ev.with_attr("threat_names", names);
        }
        let categories = crate::util::freq::top_n(
            body.threats.iter().filter_map(|t| nonempty(&t.category)),
            MAX_NAMES,
        );
        if !categories.is_empty() {
            ev = ev.with_attr("threat_categories", categories);
        }
    }

    if !body.feeds.is_empty() {
        ev = ev.with_attr("feed_count", body.feeds.len().to_string());
        let names = crate::util::freq::top_n(
            body.feeds.iter().filter_map(|f| nonempty(&f.name)),
            MAX_NAMES,
        );
        if !names.is_empty() {
            ev = ev.with_attr("feed_names", names);
        }
    }

    if let Some(a) = nonempty(&body.stamp_added) {
        ev = ev.with_attr("first_added", a);
    }
    if let Some(u) = nonempty(&body.stamp_updated) {
        ev = ev.with_attr("last_updated", u);
    }
    if let Some(s) = nonempty(&body.stamp_seen) {
        ev = ev.with_attr("last_seen", s);
    }
    if let Some(iid) = body.iid {
        ev = ev.with_attr(
            "pulsedive_url",
            format!("https://pulsedive.com/indicator/?iid={iid}"),
        );
    }
    entity.add_evidence(ev);

    let mut out = vec![entity];

    // ── Hosting geo → Address + Organisation pivots ───────────────────
    // Only populated for a fraction of records (mainly IP indicators, per
    // Pulsedive's own documented example); every field is independently
    // optional, so each pivot is gated on its own required fields being
    // present rather than assumed alongside the others.
    if let Some(geo) = body.properties.as_ref().and_then(|p| p.geo.as_ref()) {
        if let (Some(city), Some(country)) = (nonempty(&geo.city), nonempty(&geo.country)) {
            let region = nonempty(&geo.region).unwrap_or("");
            let addr = crate::util::geo::compose_address(city, region, country);
            let mut ae = Entity::new(EntityKind::Address, &addr, confidence::MEDIUM_PLUS, scan_id);
            ae.tag("pulsedive");
            ae.tag(crate::core::tags::GEOINT);
            ae.add_evidence(Evidence::new(
                SRC,
                format!("Pulsedive-reported location for {value}"),
            ));
            out.push(ae);
        }
        if let Some(org) = nonempty(&geo.org).filter(|o| o.len() >= 2) {
            let mut oe = Entity::new(
                EntityKind::Organisation,
                org,
                confidence::MEDIUM_HIGH,
                scan_id,
            );
            oe.tag("pulsedive");
            oe.add_evidence(Evidence::new(
                SRC,
                format!("Pulsedive-reported hosting/registrant organisation for {value}"),
            ));
            out.push(oe);
        }
    }

    out
}

// ── Module ───────────────────────────────────────────────────────────

pub struct Pulsedive;

#[async_trait]
impl Module for Pulsedive {
    fn name(&self) -> &'static str {
        "pulsedive"
    }

    fn description(&self) -> &'static str {
        "Pulsedive IOC enrichment — surfaces risk classification, linked threats, and feed hits"
    }

    fn priority(&self) -> u8 {
        // Same band as the other high-signal keyed threat-intel lookups
        // (threatfox 109, urlhaus 110).
        100
    }

    fn cost(&self) -> ModuleCost {
        // Free account registration (no payment) unlocks a key — same policy
        // as threatfox/urlhaus's abuse.ch Auth-Key.
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::IpAddress | TargetKind::Domain | TargetKind::Url
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // A free Pulsedive account is limited to 50 requests/day (10/day
        // unregistered) — see the module doc comment. Risk/threat-feed data is
        // stable within a day, so this reuses the "IP intel: 24h" bracket
        // `Module::cache_ttl_secs` names, the same policy `censys`/`c99` already
        // use for an equivalent data shape, here specifically to conserve a very
        // tight daily quota.
        86_400
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Threat category default (T1597.001, Search Closed Sources: Threat
        // Intel Vendors) covers the aggregated feed/threat data, but Pulsedive
        // also actively probes each indicator itself (whois/HTTP/SSL/DNS
        // properties) — the same scan-database shape as leakix/urlscan/censys
        // (T1596.005) — and, when it reports hosting geo, the indicator's
        // Address (T1591.001) and network-operator Organisation (T1591.002).
        // Superset of the default; coverage cannot regress.
        &["T1597.001", "T1596.005", "T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Address,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://pulsedive.com/api/info.php?indicator={}",
            crate::util::http::urlencode(value)
        );
        // Pulsedive authenticates via a `key` QUERY PARAMETER, not a header, so
        // this can't use `fetch_keyed_json`'s single-header shape — same reason
        // `censys` hand-rolls its request onto the shared cascade primitive.
        // `absent_statuses: &[404]` defensively covers a 404 if Pulsedive ever
        // answers one; in practice an unindexed indicator answers 200 with a
        // thin/`unknown` record, which `build_entities`'s internal gate handles,
        // and a malformed indicator answers 200 with an `error` body, handled
        // below.
        let Some(resp) = crate::util::http::keyed_cascade(ctx, SRC, initial_key, &[404], |key| {
            ctx.http
                .get(format!("{url}&key={}", crate::util::http::urlencode(key)))
        })
        .await?
        else {
            return Ok(ModuleResult::new());
        };
        // json_scanned: Pulsedive's `comments`/`riskfactors`/threat-context
        // fields are free text that could embed a leaked third-party API key —
        // scan the raw body for one.
        let body: InfoResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;
        if body.error.is_some() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.extend(build_entities(
            target.kind.to_entity_kind(),
            value,
            &body,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
