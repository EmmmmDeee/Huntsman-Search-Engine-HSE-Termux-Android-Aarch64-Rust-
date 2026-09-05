//! LeakCheck **public** breach-index lookup — free, keyless email exposure.
//!
//! Endpoint: `GET https://leakcheck.io/api/public?check=<email>`. The public API
//! is keyless and rate-limited; it returns the **named breach sources** an
//! address appears in plus the **categories of data** exposed (the `fields`
//! list — e.g. `password`, `username`, `ip`) — **never the credential values
//! themselves**. This is exposure verification, not credential extraction: like
//! HIBP's `DataClasses`, it confirms *that* an address was in a breach and
//! *what kind* of data leaked, without ever transmitting a password.
//!
//! Contract (verified live against a real response, 2026-09):
//!   * found:    `{"success":true,"found":N,"fields":[…],"sources":[{"name","date"}]}`
//!   * clean:    `{"success":false,"error":"Not found"}` (HTTP 200)
//!   * throttle: HTTP 429 / a non-"Not found" `error` — surfaced as a real
//!     `ModuleError`, never collapsed into a false "clean" (fail-closed).
//!
//! Why a second keyless breach source matters: the `AU-001` correlator rule
//! (multi-source breach corroboration, severity Critical) activates whenever two
//! independent breach sources flag the same email. `leakcheck_public` is an
//! independent corpus beside `hudsonrock`, `xposed_or_not` and `comb_search`, so
//! `hse scan --kind email --value <breached>` can reach that Critical
//! correlation with no paid keys — the distinct-corpus pattern this codebase
//! already uses for `beacondb` beside `mylnikov`.
//!
//! This is the keyless PUBLIC endpoint — distinct from the keyed leakcheck.io
//! search UI carried in the manual `hse batch` provider pack (`app::batch`),
//! which needs an account and returns credential rows.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json, urlencode};

/// Stable evidence-source string. `pub(crate)` so a test can pin it and no
/// sibling module can silently claim the same corpus.
pub(crate) const SRC: &str = "leakcheck_public";

/// LeakCheck public-API response envelope. Both the found and the clean shapes
/// arrive as HTTP 200, distinguished by `success`; every field is optional so a
/// partial or either-shape body deserialises without a hard parse failure that
/// would masquerade as a clean miss.
#[derive(Deserialize, Default)]
#[serde(default)]
struct PublicResp {
    success: bool,
    found: Option<u64>,
    fields: Option<Vec<String>>,
    sources: Option<Vec<Source>>,
    error: Option<String>,
}

/// One breach source the address appears in. `date` is `YYYY-MM` (sometimes
/// empty for undated corpora like stealer logs).
#[derive(Deserialize, Default)]
#[serde(default)]
struct Source {
    name: Option<String>,
    date: Option<String>,
}

/// LeakCheck public-API breach-index module (email → named breaches + exposed
/// data classes, keyless).
pub struct LeakCheckPublic;

#[async_trait]
impl Module for LeakCheckPublic {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "LeakCheck public breach-index — keyless email exposure: which breaches and what data classes leaked"
    }

    fn priority(&self) -> u8 {
        128
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn max_timeout_ms(&self) -> u64 {
        // One small JSON GET; the public API can be slow under rate-limit
        // back-pressure, so budget well above the 3s default.
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!(
            "https://leakcheck.io/api/public?check={}",
            urlencode(target.value.trim())
        );
        // `fetch_json` fails closed on any non-2xx (429 throttle, 5xx outage),
        // so a real outage can never masquerade as "this email is clean".
        let resp: PublicResp = fetch_json(&ctx.http, SRC, &url).await?;
        build_result(&resp, target, &ctx.scan_id)
    }
}

/// Confidence for a hit, scaled by how many independent breach sources name the
/// address — more corroborating corpora, higher confidence, saturating below 1.
fn confidence_for_sources(n: usize) -> f64 {
    match n {
        0 => confidence::ZERO,
        1 => confidence::HIGH_PLUSPLUS,
        2..=4 => confidence::HIGH_PLUSPLUS_PLUS,
        5..=9 => confidence::VERY_HIGH_PLUS,
        _ => confidence::VERY_HIGH_PLUSPLUS,
    }
}

/// Turn a parsed public-API response into entities. Pure of I/O so it is
/// unit-tested against fixtures; `process` stays a thin network adapter.
///
/// A `success:false` body is LeakCheck's own signal: `error == "Not found"` is
/// the ordinary clean negative (empty success); any OTHER error text (rate
/// limit, malformed query) is a genuine failure that must propagate as a real
/// `ModuleError` rather than a false "clean", so a throttled scan is never read
/// as an exoneration.
fn build_result(resp: &PublicResp, target: &Target, scan_id: &str) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();

    let sources = resp.sources.as_deref().unwrap_or(&[]);
    if !resp.success || sources.is_empty() {
        if let Some(err) = resp.error.as_deref()
            && !err.eq_ignore_ascii_case("not found")
            && !err.eq_ignore_ascii_case("no results found")
        {
            return Err(Error::module(
                SRC,
                format!("LeakCheck public API error: {err}"),
            ));
        }
        return Ok(result);
    }

    let names: Vec<&str> = sources
        .iter()
        .filter_map(|s| s.name.as_deref().map(str::trim))
        .filter(|n| !n.is_empty())
        .collect();
    if names.is_empty() {
        return Ok(result);
    }

    let mut ev = Evidence::new(SRC, "LeakCheck public breach index")
        .with_attr("sources_count", names.len().to_string());
    if let Some(found) = resp.found {
        ev = ev.with_attr("records", found.to_string());
    }
    ev = ev.with_attr("breaches", names.join(", "));

    // The `fields` list is the CATEGORIES of data exposed (field-type names),
    // not any credential value — exposure metadata, exactly like HIBP's
    // DataClasses.
    if let Some(fields) = resp.fields.as_deref() {
        let fields: Vec<&str> = fields
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .collect();
        if !fields.is_empty() {
            ev = ev.with_attr("exposed_data_classes", fields.join(";"));
        }
    }

    // Earliest full `YYYY-MM` breach date across the sources — the first-known
    // compromise; empty/undated entries are ignored.
    if let Some(earliest) = sources
        .iter()
        .filter_map(|s| s.date.as_deref().map(str::trim))
        .filter(|d| d.len() == 7 && d.as_bytes()[4] == b'-')
        .min()
    {
        ev = ev.with_attr("earliest_breach_date", earliest);
    }

    let mut e = Entity::new(
        EntityKind::Email,
        target.value.trim(),
        confidence_for_sources(names.len()),
        scan_id,
    );
    e.tag(SRC);
    e.tag(tags::BREACH);
    if names.len() >= 5 {
        e.tag(tags::HIGH_EXPOSURE);
    }
    // `breach:<name>` per source — lowercased to match the convention
    // `xposed_or_not`/`stolen_tax` use, so the same address hit by two corpora
    // carries one merged, deduplicated breach-tag set.
    for n in &names {
        e.tag(format!("breach:{}", n.to_lowercase()));
    }
    e.add_evidence(ev);
    result.push(e);

    Ok(result)
}

#[cfg(test)]
mod tests;
