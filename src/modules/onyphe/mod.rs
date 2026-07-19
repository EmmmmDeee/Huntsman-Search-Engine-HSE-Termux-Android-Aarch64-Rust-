//! ONYPHE — cyber-defence search engine. Key-gated; requires
//! `HUNTSMAN_ONYPHE_KEY`.
//!
//! Endpoints (API v2 `summary`, which aggregates every category ONYPHE holds
//! for a selector into one call):
//!   * `GET https://www.onyphe.io/api/v2/summary/ip/{ip}`
//!   * `GET https://www.onyphe.io/api/v2/summary/domain/{domain}`
//!
//! Auth: `Authorization: bearer {APIKEY}` (lowercase `bearer`, per ONYPHE docs).
//!
//! The response is `{ error, status, results: [ … ] }` where each result is a
//! heterogeneous document keyed by `@category` (geoloc, resolver, threatlist,
//! datascan, …). Rather than model every category, the parser walks the
//! `results` array as raw JSON and pulls whatever identifying fields are present
//! — `location`/`latitude`/`longitude`, `asn`, `organization`, `country`/`city`,
//! `domain`/`hostname`/`subdomains`, resolved `ip`, and `threatlist`/`tag`. This
//! is deliberately schema-tolerant: ONYPHE varies field shapes (string vs array)
//! across categories and plans, and a passive enrichment must degrade to "fewer
//! entities" rather than fail on an unexpected shape.
//!
//! NOTE: the exact field set returned depends on the account's ONYPHE plan;
//! validated against ONYPHE's documented v2 `summary` schema. Emitted domains
//! are gated through `is_noncentral_domain` so a resolver's CDN/mega host does
//! not pollute the graph (the lesson from the social_probe/email_parse fix).

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::{handle_keyed_error, urlencode};

const KEY_ENV: &str = "HUNTSMAN_ONYPHE_KEY";
const SRC: &str = "onyphe";

#[derive(Deserialize, Default)]
struct OnypheResp {
    /// ONYPHE signals success with `error: 0`; any other value (no results,
    /// rate-limit, plan limit) means "no usable data".
    #[serde(default)]
    error: i64,
    #[serde(default)]
    results: Vec<Value>,
}

pub struct Onyphe;

#[async_trait]
impl Module for Onyphe {
    fn name(&self) -> &'static str {
        "onyphe"
    }

    fn description(&self) -> &'static str {
        "ONYPHE cyber-defence sweep — surfaces IP/domain geoloc, ASN, resolutions, and threat tags (key-gated)"
    }

    fn priority(&self) -> u8 {
        34
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Open scan/technical database (T1596.005) over IP addresses (T1590.005)
        // that also yields passive-DNS resolutions (T1596.001), the host's
        // physical location (T1591.001), and the AS operator org (T1591.002).
        &[
            "T1590.005",
            "T1596.001",
            "T1596.005",
            "T1591.001",
            "T1591.002",
        ]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(v) => v,
            None => return Ok(ModuleResult::new()),
        };

        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }
        let selector = match target.kind {
            TargetKind::IpAddress => "ip",
            TargetKind::Domain => "domain",
            _ => return Ok(ModuleResult::new()),
        };

        let url = format!(
            "https://www.onyphe.io/api/v2/summary/{selector}/{}",
            urlencode(value)
        );

        let mut retries = 2u8;
        let body: OnypheResp = loop {
            if ctx.cancel.is_cancelled() {
                return Ok(ModuleResult::new());
            }
            let resp = ctx
                .http
                .get(&url)
                // ONYPHE documents a lowercase `bearer` scheme.
                .header("Authorization", format!("bearer {key}"))
                .header("Accept", "application/json")
                .send_tagged(SRC)
                .await?;

            let status = resp.status();
            // Unknown selector returns 404 — not an error, just no data.
            if status.as_u16() == 404 {
                return Ok(ModuleResult::new());
            }
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }
            // json_scanned: onyphe search results may contain leaked credentials —
            // scan the raw body for embedded API keys.
            break crate::util::http::json_scanned(resp, SRC)
                .await
                .map_err(|e| crate::core::error::Error::module(SRC, e))?;
        };

        // error != 0 ⇒ no results / rate-limited / plan limit — treat as empty.
        if body.error != 0 || body.results.is_empty() {
            return Ok(ModuleResult::new());
        }

        // For an IP target that is a CDN/anycast edge, the geoloc is the answering
        // datacentre, not the subject — suppress coordinates (as ip_geo does).
        let skip_coords = matches!(target.kind, TargetKind::IpAddress)
            && crate::core::validation::is_cdn_edge_ip(value);

        Ok(extract_entities(
            &body.results,
            target,
            value,
            selector,
            skip_coords,
            &ctx.scan_id,
        ))
    }
}

/// Pure entity extraction over the ONYPHE summary `results` documents — unit-
/// tested against fixtures so the network shell in `process` stays a thin
/// adapter. `skip_coords` is precomputed by the caller (the CDN-edge suppression
/// needs the IP target). No per-module output cap: every distinct in-scope
/// resolution is emitted (see the resolutions block).
fn extract_entities(
    results: &[Value],
    target: &Target,
    value: &str,
    selector: &str,
    skip_coords: bool,
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    let mut seen: HashSet<String> = HashSet::new();
    for r in results {
        let category = vstr(r, "@category").unwrap_or_default();
        let ev = || {
            let mut e = Evidence::new(SRC, format!("ONYPHE {selector} summary: {value}"));
            if !category.is_empty() {
                e = e.with_attr("category", &category);
            }
            e
        };

        // ── Geolocation ──────────────────────────────────────────────────
        if !skip_coords
            && let Some((lat, lon)) = coords(r)
            && seen.insert(format!("@coord:{lat:.4},{lon:.4}"))
            && let Some(mut ce) = crate::util::geo::coarse_provider_coords(lat, lon, 0.55, scan_id)
        {
            if let Some(cc) = vstr(r, "country") {
                ce.tag(format!("country:{}", cc.to_uppercase()));
            }
            ce.add_evidence(ev());
            result.push(ce);
        }

        // ── City / country as an Address ────────────────────────────────
        if let Some(city) = vstr(r, "city") {
            let country = vstr(r, "countryname").or_else(|| vstr(r, "country"));
            let addr = match country {
                Some(c) => format!("{city}, {c}"),
                None => city,
            };
            if seen.insert(format!("@addr:{}", addr.to_lowercase())) {
                let mut ae = Entity::new(EntityKind::Address, &addr, 0.55, scan_id);
                ae.tag(crate::core::tags::GEOINT);
                ae.add_evidence(ev());
                result.push(ae);
            }
        }

        // ── ASN + operator org ──────────────────────────────────────────
        if let Some(asn) = vstr(r, "asn").map(|a| {
            if a.starts_with("AS") {
                a
            } else {
                format!("AS{a}")
            }
        }) && asn.len() > 2
            && seen.insert(asn.to_lowercase())
        {
            let mut ae = Entity::new(EntityKind::Asn, &asn, 0.75, scan_id);
            ae.add_evidence(ev());
            result.push(ae);
        }
        if let Some(org) = vstr(r, "organization").filter(|o| o.len() >= 3)
            && seen.insert(format!("@org:{}", org.to_lowercase()))
        {
            let mut oe = Entity::new(EntityKind::Organisation, &org, 0.55, scan_id);
            oe.add_evidence(ev());
            result.push(oe);
        }

        // ── Resolved IPs (domain target) ────────────────────────────────
        if matches!(target.kind, TargetKind::Domain)
            && let Some(ip) = vstr(r, "ip")
            && ip != value
            && seen.insert(ip.clone())
        {
            let mut ie = Entity::new(EntityKind::IpAddress, &ip, 0.70, scan_id);
            ie.add_evidence(ev());
            result.push(ie);
        }

        // ── Threat-list hits ─────────────────────────────────────────────
        // ONYPHE's `threatlist` category records that `value` appears on a
        // named third-party block/threat list, with optional descriptive
        // `tag`s (e.g. "Scanner", "SSH"). Both fields were already parsed
        // into the raw `Value` for every other category above but never read
        // back out for `threatlist` specifically — this module's own
        // top-of-file doc comment claims "threatlist classification is
        // surfaced", but until this fix no code path read either field, so
        // every threat-list hit ONYPHE returned was silently dropped.
        if category == "threatlist" {
            let list_name = vstr(r, "threatlist");
            let list_tags = vstrs(r, "tag");
            if (list_name.is_some() || !list_tags.is_empty())
                && seen.insert(format!(
                    "@threat:{}:{}",
                    list_name.as_deref().unwrap_or(""),
                    list_tags.join(",").to_lowercase()
                ))
            {
                let mut te = target.to_entity(0.6, scan_id);
                te.tag(crate::core::tags::THREAT_INTEL);
                te.tag(crate::core::tags::MALICIOUS);
                let mut tev = Evidence::new(SRC, format!("ONYPHE threatlist hit: {value}"));
                if let Some(name) = &list_name {
                    tev = tev.with_attr("threatlist", name);
                }
                if !list_tags.is_empty() {
                    tev = tev.with_attr("tags", list_tags.join(", "));
                }
                te.add_evidence(tev);
                result.push(te);
            }
        }

        // ── Resolutions: hostnames / subdomains / domains ───────────────
        // Every DISTINCT in-scope resolution is emitted — no per-module cap.
        // Each host is a real BFS expansion pivot AND a record in the output;
        // the expansion frontier is owned by the engine's ROI Top-K gate
        // (`core::roi::top_k_for_round`), which ranks candidates BY WEIGHT per
        // round. A leaf `MAX_DOMAINS` cap here would instead drop by ONYPHE's
        // arbitrary return order — silently hiding subdomains from the output
        // and pre-empting the engine's ranked selection with a worse one. The
        // `is_noncentral_domain` / dedup / malformed guards below already strip
        // shared-infra and platform noise, mirroring the crtsh + netlas cert
        // paths (which dropped the same class of leaf cap for this reason).
        for field in ["hostname", "subdomains", "domain"] {
            for host in vstrs(r, field) {
                let h = host.trim().trim_end_matches('.').to_lowercase();
                // Skip the seed itself, malformed hosts, and shared
                // infrastructure / mega platforms (graph-pollution guard).
                if h.len() < 4
                    || !h.contains('.')
                    || h == value.to_lowercase()
                    || crate::core::scan::is_noncentral_domain(&h)
                    || !seen.insert(h.clone())
                {
                    continue;
                }
                let mut de = Entity::new(EntityKind::Domain, &h, 0.65, scan_id);
                de.tag("onyphe");
                de.add_evidence(ev());
                result.push(de);
            }
        }
    }

    result
}

/// Extract a trimmed, non-empty string field from a result document.
fn vstr(v: &Value, key: &str) -> Option<String> {
    let s = v.get(key)?.as_str()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Extract a field that ONYPHE may return as a single string or an array of
/// strings (e.g. `hostname`, `domain`, `subdomains`) into a flat `Vec<String>`.
fn vstrs(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Resolve a result's coordinates from separate `latitude`/`longitude` numbers,
/// or ONYPHE's `location` `"lat,lon"` string, whichever is present.
fn coords(v: &Value) -> Option<(f64, f64)> {
    let num = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_f64().or_else(|| x.as_str()?.parse().ok()))
    };
    if let (Some(lat), Some(lon)) = (num("latitude"), num("longitude")) {
        return Some((lat, lon));
    }
    let loc = v.get("location")?.as_str()?;
    let (lat, lon) = loc.split_once(',')?;
    Some((lat.trim().parse().ok()?, lon.trim().parse().ok()?))
}
