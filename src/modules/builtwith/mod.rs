//! BuiltWith technology-profile lookup — domain → tech stack + owner contacts.
//!
//! BuiltWith indexes the technologies a website runs (analytics, CMS, ad
//! networks, frameworks, hosting) and, in its Domain API `Meta` block, the
//! registrant-facing contacts it has observed (company name, emails, phone
//! numbers, social handles). For a Domain target this module surfaces the
//! observed technologies as evidence on the domain and pivots the Meta block
//! into Organisation / Email / Phone entities.
//!
//! Endpoint: `GET https://api.builtwith.com/v21/api.json?KEY={key}&LOOKUP={domain}`
//! Auth: `KEY` query parameter.
//!
//! Output: a technology-annotated Domain plus the owning Organisation and any
//! contact emails/phones — an infrastructure→identity bridge.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "builtwith";
const KEY_ENV: &str = "HUNTSMAN_BUILTWITH_KEY";

pub struct BuiltWith;

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwResp {
    #[serde(rename = "Results")]
    results: Vec<BwResult>,
    #[serde(rename = "Errors")]
    errors: Option<Vec<BwError>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwError {
    #[serde(rename = "Message")]
    message: Option<String>,
    /// BuiltWith's documented error code (api.builtwith.com/errorCodes): `-2`
    /// "API Key is wrong", `-3` "You've run out of API Credits", `-5` "Plan
    /// upgrade needed". Captured alongside `Message` so either signal can
    /// classify the failure (the provider's own page says the message text
    /// "cannot be guaranteed").
    #[serde(rename = "Code")]
    code: Option<i64>,
}

/// The documented BuiltWith errors that mean the CONFIGURED KEY itself is the
/// problem — wrong key (`-2`), no API credits left (`-3`), plan ceiling (`-5`)
/// — as opposed to a per-lookup error (`-8` invalid domain, `-4` unknown
/// technology, …) that is a clean miss for this one target. Matched on the
/// documented code first and the documented message text second (the
/// provider warns the text cannot be guaranteed; the code is the contract).
/// Returns the provider's own message for the operator. **Pure.**
fn builtwith_key_error(errors: &[BwError]) -> Option<String> {
    errors.iter().find_map(|e| {
        let msg = e.message.as_deref().unwrap_or_default();
        let lower = msg.to_ascii_lowercase();
        let keyed = matches!(e.code, Some(-2 | -3 | -5))
            || lower.contains("api key is wrong")
            || lower.contains("run out of api credits")
            || lower.contains("plan upgrade needed");
        keyed.then(|| match e.code {
            Some(code) => format!("{msg} (code {code})"),
            None => msg.to_string(),
        })
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwResult {
    /// The domain THIS entry is for. BuiltWith's `LOOKUP` parameter accepts a
    /// CSV batch of domains in one call, each surfacing as its own `Results[]`
    /// entry naming itself here — checked in `build_entities` before an
    /// entry's `Meta`/technologies are trusted, so a `Lookup` mismatch
    /// (redirect/canonicalization/API anomaly) can't silently attach another
    /// domain's registrant data to the one queried domain this module ever
    /// requests.
    #[serde(rename = "Lookup")]
    lookup: Option<String>,
    #[serde(rename = "Result")]
    result: Option<BwResultInner>,
    #[serde(rename = "Meta")]
    meta: Option<BwMeta>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwResultInner {
    #[serde(rename = "Paths")]
    paths: Vec<BwPath>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwPath {
    #[serde(rename = "Technologies")]
    technologies: Vec<BwTech>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwTech {
    #[serde(rename = "Name")]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwMeta {
    #[serde(rename = "CompanyName")]
    company_name: Option<String>,
    #[serde(rename = "Emails")]
    emails: Option<Vec<String>>,
    #[serde(rename = "Telephones")]
    telephones: Option<Vec<String>>,
    #[serde(rename = "Names")]
    names: Option<Vec<BwName>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BwName {
    #[serde(rename = "Name")]
    name: Option<String>,
}

#[async_trait]
impl Module for BuiltWith {
    fn name(&self) -> &'static str {
        "builtwith"
    }

    fn description(&self) -> &'static str {
        "BuiltWith technology profile: site tech stack + owning company, emails, phones"
    }

    fn priority(&self) -> u8 {
        74
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1590.005 (IP Addresses) is inapplicable — never queries, parses,
        // or emits IP data, only a domain's tech stack and Meta-block
        // registrant contacts. Core purpose is T1592.002 (Software) via
        // BuiltWith tech-stack fingerprinting, with T1589.002 (Email
        // Addresses) as a substantially-coded secondary output from the
        // Meta block. T1596.005 (Scan Databases) holds since BuiltWith
        // itself is the named database being queried.
        &["T1592.002", "T1596.005", "T1589.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Organisation,
            EntityKind::Email,
            EntityKind::Phone,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // Tech stacks and registrant contacts change slowly: cache 7 days to
        // stretch the BuiltWith quota (billed per lookup).
        604_800
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };

        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }
        let lookup = crate::util::http::urlencode(domain);
        let url = format!("https://api.builtwith.com/v21/api.json?KEY={key}&LOOKUP={lookup}");

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: BwResp = crate::util::http::json_decode(SRC, resp).await?;

        if let Some(errors) = &body.errors {
            // BuiltWith answers a wrong key / exhausted credits / plan ceiling
            // with HTTP 200 and an `Errors[]` body (codes -2/-3/-5), so
            // `keyed_ok_or_404` above never sees it. This used to log a warning
            // and return Ok(empty) — a dead credential read exactly like "no
            // tech profile for this domain", the pool was never told, and a
            // second pooled key never got its turn. Same in-body-200 rule
            // hibp/hunter_io/whoisxml/ipqs apply.
            if let Some(detail) = builtwith_key_error(errors) {
                ctx.report_key_exhausted(SRC, key, 200);
                return Err(crate::core::error::Error::module(
                    SRC,
                    format!("api 200 error: {detail}"),
                ));
            }
            if let Some(first) = errors.iter().find_map(|e| e.message.as_deref()) {
                tracing::warn!(target: "module.builtwith", "BuiltWith error: {}", first);
                return Ok(ModuleResult::new());
            }
        }

        Ok(build_entities(&body, domain, &ctx.scan_id))
    }
}

/// Whether a `Results[]` entry's own `Lookup` field (when present) names the
/// SAME domain this module queried. `Lookup` is optional in our model (older
/// API responses / undocumented edge cases might omit it), so its absence is
/// not itself rejected — only a present, mismatched one is. Pure.
fn result_matches_domain(res: &BwResult, domain_lc: &str) -> bool {
    res.lookup
        .as_deref()
        .is_none_or(|l| l.trim().eq_ignore_ascii_case(domain_lc))
}

/// Map a decoded BuiltWith response to entities. **Pure** (no network/IO).
/// Emits a technology-annotated Domain plus the owning Organisation and any
/// observed contact Emails / Phones from the `Meta` block.
fn build_entities(body: &BwResp, domain: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    let domain_lc = domain.trim().to_ascii_lowercase();

    // Collect a deterministic, deduplicated technology list across every path.
    let mut techs: Vec<String> = Vec::new();
    for res in body
        .results
        .iter()
        .filter(|r| result_matches_domain(r, &domain_lc))
    {
        if let Some(inner) = &res.result {
            for path in &inner.paths {
                for tech in &path.technologies {
                    if let Some(name) = tech
                        .name
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        techs.push(name.to_string());
                    }
                }
            }
        }
    }
    techs.sort();
    techs.dedup();

    if !techs.is_empty() {
        // The four confidences below are a deliberate descending gradient, now
        // named rather than magic. The domain is the strongest: BuiltWith
        // returning a technology profile for it is a direct observation of the
        // host that was queried. Everything after it comes out of the `meta`
        // block — the provider's own registrant attribution, not something it
        // fingerprinted — so each step down reflects one more inference between
        // the observation and the claim.
        let mut dom = Entity::new(EntityKind::Domain, domain, confidence::HIGH_PLUS, scan_id);
        dom.tag("builtwith");
        dom.tag("tech-profile");
        dom.add_evidence(
            Evidence::new(SRC, format!("BuiltWith technology profile for {domain}"))
                .with_attr("technology_count", techs.len().to_string())
                .with_attr(
                    "technologies",
                    techs.iter().take(30).cloned().collect::<Vec<_>>().join(","),
                ),
        );
        result.push(dom);
    }

    // Meta block → Organisation / Email / Phone.
    for res in body
        .results
        .iter()
        .filter(|r| result_matches_domain(r, &domain_lc))
    {
        let Some(meta) = &res.meta else { continue };

        // Company name (or the first observed registrant Name) → Organisation.
        let org_name = meta
            .company_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                meta.names.as_ref().and_then(|names| {
                    names
                        .iter()
                        .find_map(|n| n.name.as_deref().map(str::trim).filter(|s| !s.is_empty()))
                        .map(str::to_string)
                })
            });
        if let Some(org) = org_name.filter(|s| s.len() >= 3) {
            let mut oe = Entity::new(EntityKind::Organisation, &org, confidence::HIGH, scan_id);
            oe.tag("builtwith");
            oe.add_evidence(
                Evidence::new(
                    SRC,
                    format!("BuiltWith registrant company for {domain}: {org}"),
                )
                .with_attr("domain", domain),
            );
            result.push(oe);
        }

        if let Some(emails) = &meta.emails {
            let mut seen: Vec<String> = emails
                .iter()
                .map(|e| e.trim().to_ascii_lowercase())
                .filter(|e| e.len() >= 5 && e.contains('@'))
                // A registrant contact block is dominated by automation and
                // role desks — `abuse@`, `hostmaster@`, the registrar's own
                // privacy-proxy mailbox — not the subject's mail. Emitting
                // those as `Email` attributes a provider's helpdesk to the
                // person under investigation, which is precisely the leakage
                // #351 removed from `cert_intel`, `crtsh`, `ip_registry` and
                // `doh_resolver`. This module reads the same class of data from
                // a different provider, so it takes the same gate: the shared
                // `is_infrastructure_email` (role local-part OR known infra
                // mail domain, with freemail explicitly exempted so a personal
                // mailbox is never mislabelled infrastructure).
                .filter(|e| !crate::util::domains::is_infrastructure_email(e))
                .collect();
            seen.sort();
            seen.dedup();
            for email in &seen {
                let mut e = Entity::new(EntityKind::Email, email, confidence::MEDIUM_PLUS, scan_id);
                e.tag("builtwith");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Contact email observed by BuiltWith for {domain}"),
                ));
                result.push(e);
            }
        }

        if let Some(phones) = &meta.telephones {
            let mut seen: Vec<String> = phones
                .iter()
                .map(|p| p.trim().to_string())
                .filter(|p| p.chars().filter(char::is_ascii_digit).count() >= 7)
                .collect();
            seen.sort();
            seen.dedup();
            for phone in &seen {
                // Weakest rung of the gradient: a registrant telephone is one
                // more inference removed again — typically a company
                // switchboard or the registrar's own line rather than the
                // subject's number. Left emitted (a switchboard is a real
                // organisational lead) but at the confidence that says so.
                // There is no phone-side counterpart to
                // `is_infrastructure_email` to gate on, and inventing one here
                // on a guess would be worse than the honest low rung.
                let mut e = Entity::new(EntityKind::Phone, phone, confidence::MEDIUM_HIGH, scan_id);
                e.tag("builtwith");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Contact phone observed by BuiltWith for {domain}"),
                ));
                result.push(e);
            }
        }
    }

    result
}
