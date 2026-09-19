//! XposedOrNot domain-breach lookup — free, keyless "was this domain's own
//! operator itself the subject of a known data breach" check.
//!
//! Endpoint: `GET https://api.xposedornot.com/v1/breaches?domain=<domain>`.
//! Distinct from the existing [`crate::modules::xposed_or_not`] module, which
//! asks "has this EMAIL been exposed in a breach" via `/v1/check-email/<email>`
//! and `/v1/breach-analytics` (Email-kind only — its own `accepts` rejects
//! `TargetKind::Domain`) — this asks "was this DOMAIN's own operator the
//! victim of a breach", the Domain-kind analog of what
//! [`crate::modules::ransomware_live`] / [`crate::modules::ransomlook`]
//! already do for ransomware/extortion victims. No module in this crate
//! called this endpoint before this one.
//!
//! Contract (verified live against a real response, 2026-09):
//!   * hit:   `{"status":"success","message":null,"exposedBreaches":[{…}]}`
//!     HTTP 200 — each element carries `breachID`, `breachedDate`, `domain`,
//!     `industry`, `passwordRisk`, `verified`, `exposedData` (a list of
//!     category names, e.g. "Email addresses"/"Names"), `exposedRecords`,
//!     `exposureDescription`, `referenceURL`. Confirmed live against
//!     `adobe.com` (single-breach hit) and an empty `domain=` (which returns
//!     the provider's *entire* breach catalogue — see below).
//!   * clean: `{"status":"Not Found","message":"No breaches found for the
//!     provided criteria","exposedBreaches":null}` — also HTTP 200,
//!     distinguished only by `status`/an empty `exposedBreaches`. Confirmed
//!     live against a domain constructed to have no possible breach record.
//!
//! An empty or missing `domain` query parameter does **not** error — it
//! silently returns the provider's entire breach catalogue (confirmed live:
//! hundreds of unrelated breaches, e.g. companies breached as recently as
//! August 2026). `Target::validate()`'s `Domain` branch already guarantees
//! `target.value` is non-empty and dot-containing before this module ever
//! sees it, but `build_result` still gates every returned record on the
//! record's own `domain` field matching the queried domain (via the same
//! [`is_or_subdomain_of`] authority `ransomware_live` uses, checked in both
//! directions) — defense in depth against ever surfacing an unrelated
//! company's breach as if it were the target's own, whether from a future
//! empty-value regression here or from provider-side fuzzy matching this
//! module has not independently characterised.
//!
//! Independent of, and a Domain-kind complement to, the existing
//! `xposed_or_not` (Email), `ransomware_live` / `ransomlook` (ransomware
//! victims), `leakcheck_public` (Email) and `hudsonrock` (Email, Domain)
//! breach sources — another independent corpus the `AU-001` multi-source
//! correlation rule can draw on for a Domain seed.

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
use crate::util::domains::is_or_subdomain_of;
use crate::util::http::{fetch_json, urlencode};

/// Stable evidence-source string. `pub(crate)` so a test can pin it and no
/// sibling module can silently claim the same corpus.
pub(crate) const SRC: &str = "xposed_or_not_domain";

/// XposedOrNot domain-breach response envelope. Every field optional so an
/// unexpected or partial body deserialises without a hard parse failure that
/// would masquerade as a clean miss — `build_result` reads the actual
/// content (`exposed_breaches`), not just a status string, to decide.
#[derive(Deserialize, Default)]
#[serde(default)]
struct DomainBreachResp {
    status: Option<String>,
    #[serde(rename = "exposedBreaches")]
    exposed_breaches: Option<Vec<BreachRecord>>,
}

/// One breach record naming a domain as its own victim.
#[derive(Deserialize, Default)]
#[serde(default)]
struct BreachRecord {
    #[serde(rename = "breachID")]
    breach_id: Option<String>,
    #[serde(rename = "breachedDate")]
    breached_date: Option<String>,
    domain: Option<String>,
    industry: Option<String>,
    #[serde(rename = "passwordRisk")]
    password_risk: Option<String>,
    verified: Option<bool>,
    #[serde(rename = "exposedData")]
    exposed_data: Option<Vec<String>>,
    #[serde(rename = "exposedRecords")]
    exposed_records: Option<u64>,
    #[serde(rename = "exposureDescription")]
    exposure_description: Option<String>,
    #[serde(rename = "referenceURL")]
    reference_url: Option<String>,
}

/// XposedOrNot domain-breach lookup module (Domain → was this domain's own
/// operator itself breached, keyless).
pub struct XposedOrNotDomain;

#[async_trait]
impl Module for XposedOrNotDomain {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "XposedOrNot domain-breach lookup — keyless: was this domain's own operator the victim of a known data breach"
    }

    fn priority(&self) -> u8 {
        128
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn max_timeout_ms(&self) -> u64 {
        // One small JSON GET; the public API can be slow under rate-limit
        // back-pressure, so budget well above the 3s default (matches the
        // sibling `leakcheck_public`'s public-API-slowness allowance).
        10_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!(
            "https://api.xposedornot.com/v1/breaches?domain={}",
            urlencode(target.value.trim())
        );
        // `fetch_json` fails closed on any non-2xx (429 throttle, 5xx
        // outage), so a real outage can never masquerade as "this domain is
        // clean".
        let resp: DomainBreachResp = fetch_json(&ctx.http, SRC, &url).await?;
        build_result(&resp, target, &ctx.scan_id)
    }
}

/// Confidence for a hit, lifted when the provider's own `verified` flag is
/// set — its signal that the breach has independent secondary confirmation
/// rather than only a self-reported claim.
fn confidence_for(verified: bool) -> f64 {
    if verified {
        confidence::VERY_HIGH_PLUS
    } else {
        confidence::HIGH_PLUSPLUS
    }
}

/// Turn a parsed domain-breach response into entities. Pure of I/O so it is
/// unit-tested against fixtures; `process` stays a thin network adapter.
fn build_result(resp: &DomainBreachResp, target: &Target, scan_id: &str) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();

    // Only the two documented shapes are trusted (fail-closed, matching
    // `leakcheck_public`'s identical discipline): `status: "success"` paired
    // with a present `exposedBreaches` (hit, possibly an empty array — a
    // legitimate "searched, found nothing" success), or `status: "Not
    // Found"` paired with an absent `exposedBreaches`. Every other
    // combination — a malformed/partial 200 body (`{}`,
    // `{"status":"success"}` with no `exposedBreaches` key at all), a
    // throttle or error status, or stale records riding along with a
    // non-"success" status — is a genuine ambiguity that must surface as a
    // real error, never a silent "clean" or a false hit built from records
    // the provider itself did not vouch for under `status: "success"`.
    let status = resp.status.as_deref().unwrap_or_default();
    let records: &[BreachRecord] = match (&resp.exposed_breaches, status) {
        (Some(records), s) if s.eq_ignore_ascii_case("success") => records,
        (None, s) if s.eq_ignore_ascii_case("not found") => return Ok(result),
        _ => {
            return Err(Error::module(
                SRC,
                format!(
                    "XposedOrNot domain-breach API: unexpected response shape (status={status:?}, exposedBreaches present={})",
                    resp.exposed_breaches.is_some()
                ),
            ));
        }
    };
    if records.is_empty() {
        return Ok(result);
    }

    let needle = target.value.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return Ok(result);
    }

    for r in records {
        let Some(dom) = r.domain.as_deref().map(str::trim).filter(|d| !d.is_empty()) else {
            continue;
        };
        let dom_lower = dom.to_ascii_lowercase();
        // Precision gate: keep only a record whose OWN domain is the queried
        // domain (or an apex/subdomain relative of it) — never an incidental
        // catalogue entry (see the module doc comment's empty-`domain=`
        // hazard).
        if !is_or_subdomain_of(&dom_lower, &needle) && !is_or_subdomain_of(&needle, &dom_lower) {
            continue;
        }

        let name = r
            .breach_id
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty());
        let verified = r.verified.unwrap_or(false);

        let mut ev = Evidence::new(SRC, "XposedOrNot domain-breach index").with_optional_attrs([
            ("breach", name),
            ("industry", r.industry.as_deref()),
            ("password_risk", r.password_risk.as_deref()),
            ("breached_date", r.breached_date.as_deref()),
            ("description", r.exposure_description.as_deref()),
            (
                "reference",
                r.reference_url.as_deref().filter(|u| u.starts_with("http")),
            ),
        ]);
        ev = ev.with_attr("verified", verified.to_string());
        if let Some(count) = r.exposed_records {
            ev = ev.with_attr("exposed_records", count.to_string());
        }
        if let Some(classes) = r.exposed_data.as_deref() {
            let classes: Vec<&str> = classes
                .iter()
                .map(String::as_str)
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .collect();
            if !classes.is_empty() {
                ev = ev.with_attr("exposed_data_classes", classes.join(";"));
            }
        }

        let mut e = Entity::new(EntityKind::Domain, dom, confidence_for(verified), scan_id);
        e.tag(SRC);
        e.tag(tags::BREACH);
        if let Some(n) = name {
            e.tag(format!("breach:{}", n.to_lowercase()));
        }
        if r.exposed_records.unwrap_or(0) >= 1_000_000 {
            e.tag(tags::HIGH_EXPOSURE);
        }
        e.add_evidence(ev);
        result.push(e);
    }

    Ok(result)
}

#[cfg(test)]
mod tests;
