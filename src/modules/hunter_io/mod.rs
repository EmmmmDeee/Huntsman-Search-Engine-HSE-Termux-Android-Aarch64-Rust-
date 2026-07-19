//! Hunter.io — find email addresses associated with a domain.
//!
//! Endpoint: `GET https://api.hunter.io/v2/domain-search?domain={d}&api_key={k}`
//! Auth:     `api_key` query param. Key-gated (`HUNTSMAN_HUNTER_KEY`).
//! Free tier: 25 searches/month, 50 verifications/month.
//!
//! The single highest-leverage gap for HSE's identity-enrichment
//! chain: a Domain → list-of-Emails pivot. Pairs naturally with
//! `email_parse` (parsed Emails feed back as new targets) and
//! `hibp` (each discovered Email gets a breach check).

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const KEY_ENV: &str = "HUNTSMAN_HUNTER_KEY";
const SRC: &str = "hunter_io";

pub struct HunterIo;

#[derive(Deserialize)]
struct Wrap {
    #[serde(default)]
    data: Option<HunterData>,
    /// Hunter occasionally returns HTTP 200 with an `errors` array
    /// instead of `data` when the key is rate-limited or out of
    /// quota for the current plan. Capture so we report the key
    /// exhausted rather than silently emitting an empty result.
    #[serde(default)]
    errors: Vec<HunterApiError>,
}

#[derive(Deserialize)]
struct HunterApiError {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    details: Option<String>,
}

#[derive(Deserialize)]
struct HunterData {
    /// Canonical domain Hunter resolved for the organisation. Surfaced as a
    /// `Domain` pivot by [`build_entities`] (it can differ from the queried
    /// host, e.g. a redirect/brand domain).
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    emails: Vec<HunterEmail>,
}

#[derive(Deserialize)]
struct HunterEmail {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    position: Option<String>,
    #[serde(default)]
    department: Option<String>,
    #[serde(default)]
    sources: Vec<HunterSource>,
    /// LinkedIn/Twitter profile fields. Hunter's documented shape for these
    /// has varied across API examples (a full profile URL for one, a bare
    /// handle for the other), so `build_entities` inspects the actual value
    /// rather than assuming a fixed shape per field.
    #[serde(default)]
    linkedin: Option<String>,
    #[serde(default)]
    twitter: Option<String>,
}

#[derive(Deserialize)]
struct HunterSource {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    uri: Option<String>,
}

#[async_trait]
impl Module for HunterIo {
    fn name(&self) -> &'static str {
        "hunter_io"
    }

    fn description(&self) -> &'static str {
        "Email-finder recon — enumerates addresses associated with a target domain for onward pivoting"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Email
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Beyond the Email default (T1589.002 Email Addresses), Hunter.io
        // attributes each address to an employee name (T1589.003 Employee Names)
        // and surfaces their position/department (T1591.004 Identify Roles).
        // Superset of the default — coverage cannot regress.
        &["T1589.002", "T1589.003", "T1591.004"]
    }

    fn priority(&self) -> u8 {
        62
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::Domain]
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Organisation,
            // Hunter's canonical org domain + every email's source domain.
            EntityKind::Domain,
            // The public source pages where Hunter saw each address, plus a
            // LinkedIn/Twitter field when Hunter returns a full profile URL.
            EntityKind::Url,
            // A LinkedIn/Twitter field when Hunter returns a bare handle.
            EntityKind::Username,
        ]
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };
        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.hunter.io/v2/domain-search?domain={}&api_key={}",
            crate::util::http::urlencode(domain),
            crate::util::http::urlencode(key),
        );

        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            // `without_url()` strips the URL (which carries the API key
            // as a query param) before formatting, so transport errors
            // don't leak the key into logs / events.
            .map_err(|e| Error::module(SRC, e.without_url().to_string()))?;
        // 401/403/429 → report_key_exhausted + Err; 404 → Ok(None) (domain
        // absent from Hunter); other non-2xx → Err via http_status_error.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let wrap: Wrap = crate::util::http::json_decode(SRC, resp).await?;
        // HTTP-200-with-errors array: Hunter signals quota / scope /
        // plan problems out-of-band of the HTTP status. Mark the
        // key exhausted instead of silently returning empty.
        if !wrap.errors.is_empty() {
            let first = &wrap.errors[0];
            let detail = first
                .details
                .as_deref()
                .or(first.id.as_deref())
                .unwrap_or("api error");
            ctx.report_key_exhausted(SRC, key, 200);
            return Err(Error::module(SRC, format!("api 200 error: {detail}")));
        }
        let Some(data) = wrap.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        for e in build_entities(&data, domain, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// Map a Hunter.io `domain-search` payload to graph entities. **Pure** (no IO,
/// no quota) so the field-mapping, confidence, source-pivot and
/// pattern-synthesis logic is unit-tested directly, decoupled from the network.
///
/// Surfaces, beyond the headline Email/Person pairs:
///   • the resolved **organisation** (with country + email pattern on evidence);
///   • Hunter's **canonical domain** for the org as a `Domain` pivot (it can
///     differ from the queried host — a redirect or brand domain);
///   • every email's **source** page (`Url`) and source **domain** — the public
///     pages where Hunter saw the address, each a fresh OSINT pivot — not just
///     the first one as an evidence attribute;
///   • for a person Hunter names but gives **no confirmed address**, a
///     pattern-**synthesised** candidate email (`{first}.{last}`-style),
///     emitted as a low-confidence `weak-lead` so it never outranks a verified
///     address but still seeds the email→breach/parse chain.
///
/// A `seen` set collapses duplicate sources/synthesised addresses within one
/// response; the engine's canonical dedup still applies across modules.
fn build_entities(data: &HunterData, target_domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let nonempty = |s: &Option<String>| -> Option<String> {
        s.as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };

    let canonical = nonempty(&data.domain);
    let pattern = nonempty(&data.pattern);

    // ── Organisation entity (if Hunter resolved one for the domain) ──
    if let Some(org) = nonempty(&data.organization) {
        let mut e = Entity::new(EntityKind::Organisation, &org, confidence::HIGH_PLUS, scan_id);
        e.tag("hunter-io");
        let mut ev = Evidence::new(
            SRC,
            format!("Hunter.io resolved organisation for {target_domain}"),
        )
        .with_attr("domain", target_domain);
        if let Some(c) = nonempty(&data.country) {
            ev = ev.with_attr("country", &c);
        }
        if let Some(p) = &pattern {
            ev = ev.with_attr("email_pattern", p);
        }
        if let Some(c) = &canonical {
            ev = ev.with_attr("canonical_domain", c);
        }
        e.add_evidence(ev);
        out.push(e);
    }

    // ── Canonical org domain pivot (previously discarded). ──
    if let Some(dom) = &canonical
        && seen.insert(format!("dom:{}", dom.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Domain, dom, confidence::MEDIUM_PLUS, scan_id);
        e.tag("hunter-io");
        e.tag("org-domain");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("Hunter.io canonical domain for {target_domain}"),
            )
            .with_attr("queried_domain", target_domain),
        );
        out.push(e);
    }

    // Domain to synthesise candidate addresses against: prefer Hunter's
    // canonical domain, fall back to the queried host.
    let synth_domain = canonical.as_deref().unwrap_or(target_domain);

    // ── Email entities + co-located Person entities + source pivots ──
    for entry in &data.emails {
        let conf = confidence_from_hunter_score(entry.confidence);
        let first = nonempty(&entry.first_name);
        let last = nonempty(&entry.last_name);

        // The confirmed address, or — when Hunter names a person but withholds
        // their address — a pattern-synthesised candidate (low-confidence lead).
        let (addr, synthesised) = match nonempty(&entry.value) {
            Some(v) => (Some(v), false),
            None => match (&pattern, &first, &last) {
                (Some(p), Some(f), Some(l)) => (apply_email_pattern(p, f, l, synth_domain), true),
                _ => (None, false),
            },
        };
        let Some(addr) = addr else {
            continue;
        };
        if !seen.insert(format!("mail:{}", addr.to_lowercase())) {
            continue;
        }

        let email_conf = if synthesised { confidence::LOW } else { conf };
        let mut ee = Entity::new(EntityKind::Email, &addr, email_conf, scan_id);
        ee.tag("hunter-io");
        ee.tag("email-finder");
        if synthesised {
            ee.tag("email-pattern-synthesised");
            ee.tag("weak-lead");
        }
        let mut ev = Evidence::new(SRC, format!("Hunter.io email for {target_domain}"))
            .with_attr("domain", target_domain)
            .with_attr(
                "hunter_confidence",
                entry.confidence.unwrap_or(0).to_string(),
            );
        if synthesised && let Some(p) = &pattern {
            ev = ev.with_attr("synthesised_from_pattern", p);
        }
        if let Some(p) = nonempty(&entry.position) {
            ev = ev.with_attr("position", &p);
        }
        if let Some(d) = nonempty(&entry.department) {
            ev = ev.with_attr("department", &d);
        }
        if let Some(src) = entry.sources.first() {
            if let Some(uri) = nonempty(&src.uri) {
                ev = ev.with_attr("source_url", &uri);
            }
            if let Some(d) = nonempty(&src.domain) {
                ev = ev.with_attr("source_domain", &d);
            }
        }
        ee.add_evidence(ev);
        out.push(ee);

        // ── Person entity if Hunter has a name attached ──
        if let (Some(first), Some(last)) = (&first, &last) {
            let full = format!("{first} {last}");
            let mut pe = Entity::new(EntityKind::Person, &full, email_conf.min(confidence::VERY_HIGH), scan_id);
            pe.tag("hunter-io");
            pe.tag("email-attribution");
            let mut pev = Evidence::new(SRC, format!("Hunter.io attributed {addr} to {full}"))
                .with_attr("email", &addr)
                .with_attr("domain", target_domain);
            if let Some(p) = nonempty(&entry.position) {
                pev = pev.with_attr("position", &p);
            }
            if let Some(d) = nonempty(&entry.department) {
                pev = pev.with_attr("department", &d);
            }
            pe.add_evidence(pev);
            out.push(pe);
        }

        // ── Source pivots: every page Hunter saw the address on. ──
        for src in &entry.sources {
            if let Some(uri) = nonempty(&src.uri)
                && seen.insert(format!("url:{}", uri.to_lowercase()))
            {
                let mut e = Entity::new(EntityKind::Url, &uri, confidence::LOW_MEDIUM, scan_id);
                e.tag("hunter-io");
                e.tag("email-source");
                e.add_evidence(
                    Evidence::new(SRC, format!("Hunter.io source page for {addr}"))
                        .with_attr("email", &addr),
                );
                out.push(e);
            }
            if let Some(d) = nonempty(&src.domain)
                && seen.insert(format!("dom:{}", d.to_lowercase()))
            {
                let mut e = Entity::new(EntityKind::Domain, &d, confidence::LOW, scan_id);
                e.tag("hunter-io");
                e.tag("email-source");
                e.add_evidence(
                    Evidence::new(SRC, format!("Hunter.io source domain for {addr}"))
                        .with_attr("email", &addr),
                );
                out.push(e);
            }
        }

        // ── Social-profile pivots: LinkedIn/Twitter, previously deserialized
        // straight past into nothing. A full URL becomes a Url pivot; a bare
        // handle becomes a platform-prefixed Username pivot, mirroring
        // fullcontact's established convention for the same distinction.
        for (network, value) in [("linkedin", &entry.linkedin), ("twitter", &entry.twitter)] {
            let Some(v) = nonempty(value) else {
                continue;
            };
            if v.starts_with("http") {
                if seen.insert(format!("url:{}", v.to_lowercase())) {
                    let mut e = Entity::new(EntityKind::Url, &v, confidence::MEDIUM_HIGH, scan_id);
                    e.tag("hunter-io");
                    e.tag("social-profile");
                    e.add_evidence(
                        Evidence::new(SRC, format!("Hunter.io {network} profile for {addr}"))
                            .with_attr("email", &addr)
                            .with_attr("network", network),
                    );
                    out.push(e);
                }
            } else {
                let handle = format!("{network}:{v}");
                if seen.insert(format!("user:{}", handle.to_lowercase())) {
                    let mut e = Entity::new(EntityKind::Username, &handle, confidence::MEDIUM_HIGH, scan_id);
                    e.tag("hunter-io");
                    e.tag("social-profile");
                    e.add_evidence(
                        Evidence::new(SRC, format!("Hunter.io {network} handle for {addr}"))
                            .with_attr("email", &addr)
                            .with_attr("network", network),
                    );
                    out.push(e);
                }
            }
        }
    }

    out
}

/// Render a Hunter.io email *pattern* into a concrete local-part + domain.
///
/// Hunter expresses an organisation's address convention as a token string —
/// `{first}.{last}`, `{f}{last}`, `{first}`, `{f}.{l}`, … — where `{first}` /
/// `{last}` are the full name parts and `{f}` / `{l}` their initials. Literal
/// separators between tokens (`.`, `_`, `-`) are preserved.
///
/// Returns `None` when the pattern needs a name part the caller doesn't have
/// (so we never emit a malformed `john.@acme.com`), when the domain is empty,
/// or when no token resolved. **Pure.**
fn apply_email_pattern(pattern: &str, first: &str, last: &str, domain: &str) -> Option<String> {
    let first = first.trim().to_lowercase();
    let last = last.trim().to_lowercase();
    let domain = domain.trim().trim_start_matches('@');
    if pattern.trim().is_empty() || domain.is_empty() {
        return None;
    }

    let needs_first = pattern.contains("{first}") || pattern.contains("{f}");
    let needs_last = pattern.contains("{last}") || pattern.contains("{l}");
    if (needs_first && first.is_empty()) || (needs_last && last.is_empty()) {
        return None;
    }

    let mut local = pattern.trim().to_string();
    local = local.replace("{first}", &first).replace("{last}", &last);
    if let Some(c) = first.chars().next() {
        local = local.replace("{f}", &c.to_string());
    }
    if let Some(c) = last.chars().next() {
        local = local.replace("{l}", &c.to_string());
    }

    // Any unresolved token means the pattern referenced something we can't
    // fill — refuse rather than emit a broken address.
    if local.contains('{') || local.contains('}') || local.is_empty() {
        return None;
    }
    Some(format!("{local}@{domain}"))
}

/// Map Hunter's 0-100 confidence score to an HSE confidence in
/// [0.0, 1.0]. Buckets follow Hunter's own tier semantics:
/// 90+ verified, 70-89 high, 40-69 medium, 1-39 low, explicit 0 or
/// missing → uncertain (None and Some(0) collapse to the same
/// floor — an explicit 0 from Hunter means "no signal", which
/// shouldn't outrank a missing field).
fn confidence_from_hunter_score(score: Option<u8>) -> f64 {
    match score {
        Some(c) if c >= 90 => confidence::HIGH_PLUSPLUS_PLUS,
        Some(c) if c >= 70 => confidence::HIGH_PLUS,
        Some(c) if c >= 40 => confidence::MEDIUM_HIGH,
        Some(c) if c > 0 => confidence::LOW_MEDIUM,
        _ => confidence::MEDIUM,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
