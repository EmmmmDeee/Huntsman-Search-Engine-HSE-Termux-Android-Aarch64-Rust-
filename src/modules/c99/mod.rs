//! C99.nl — Subdomain Finder. C99 is actually a large SUITE of dozens of
//! separate, unrelated recon/utility endpoints sharing one dashboard/key
//! (phone lookup, WHOIS, GeoIP, firewall detection, …); this module
//! implements exactly one verified slice of it. Key-gated; no free tier.
//!
//! Endpoint: `GET https://api.c99.nl/subdomainfinder?key={key}&domain={domain}&json=true`
//! Auth:     `key` query-string parameter — the same placement this repo's
//! already-verified auth-check probe uses against `GET https://api.c99.nl/`
//! (`util::service_defs`'s `c99` def, `KeyPlacement::QueryParam("key")`).
//!
//! # Documentation provenance
//!
//! C99 does not publish a static docs page; its dashboard serves a live
//! OpenAPI 3.0 spec, fetched directly for this module from
//! `https://api.c99.nl/documentation?spec=json` (the URL
//! `https://api.c99.nl/dashboard/docs` 301s to, and the Swagger UI there
//! renders under `Domain & IP Tools -> GET /subdomainfinder`). Per that
//! spec's `/subdomainfinder` path:
//!   * Query params: `key` (required), `domain` (required), `json` (optional,
//!     default `true`) — matches the identical `?key=...&domain=...&json`
//!     query string independently built by two third-party API wrappers
//!     (`jthom2/c99-api`'s Python client and `znixbtw/c99`'s JS client, both
//!     inspected on GitHub), corroborating the spec.
//!   * `200` response body: `{success, subdomains: [{subdomain, ip,
//!     cloudflare}], cached, cache_time}`. The spec's own worked example
//!     shows `ip` as the literal string `"none"` when C99 has not resolved an
//!     address for that subdomain (a present key, not an absent one).
//!   * `400` is the ONLY other documented status, and covers both a bad key
//!     *and* a bad parameter with one generic body:
//!     `{success: false, error: "Invalid API key or parameter."}` — C99's own
//!     spec does not disambiguate the two. There is no documented "not
//!     found"/absent status for this endpoint; a domain with nothing indexed
//!     still answers `200` with an empty `subdomains` array. Because that
//!     generic message always contains "Invalid API key", it is caught by
//!     the shared [`crate::util::http::is_auth_failure_400_body`] classifier
//!     that [`crate::util::http::keyed_cascade`] already applies to other
//!     ambiguous-400 providers (Netlas, ONYPHE) — a `400` here rotates the
//!     key pool exactly as those do, rather than needing bespoke handling.
//!   * Pricing (`http://api.c99.nl/shop`, fetched live): cheapest plan is
//!     $5/month with no free tier at all, so this is [`ModuleCost::Paid`],
//!     not key-gated-free.
//!
//! Every discovered subdomain becomes a `Domain` pivot (tagged
//! [`tags::SUBDOMAIN`] when it genuinely sits under the queried domain, the
//! expected case for this endpoint). A subdomain that resolved to a real,
//! non-`"none"` address also yields a corroborating `IpAddress` entity,
//! deduplicated across subdomains that share one IP. Both are tagged
//! `cloudflare` when C99 flags the resolved IP as Cloudflare's — the
//! ordinary meaning in subdomain-enumeration tools ("this host currently
//! sits behind Cloudflare's shared edge"), so the signal is preserved rather
//! than discarded, without this module asserting anything further about
//! whether the address is an unmasked origin (C99's own catalogue names this
//! endpoint the "Subdomain Finder and CloudFlare Resolver", but the spec
//! does not document what that resolution actually recovers, so a stronger
//! claim would not be verified).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{json_decode, keyed_cascade, urlencode};

const KEY_ENV: &str = "HUNTSMAN_C99_KEY";
const SRC: &str = "c99";

/// `/subdomainfinder` response, per the live OpenAPI spec (see module docs).
/// `#[serde(default)]` throughout so a field C99 omits or renames degrades to
/// "not present" rather than a parse failure.
#[derive(Deserialize)]
struct SubdomainFinderResp {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    subdomains: Vec<SubdomainEntry>,
    /// Whether this answer was served from C99's own cache rather than a
    /// fresh scan — broadcast onto every emitted entity's evidence so an
    /// operator can tell a possibly-stale result from a live one.
    #[serde(default)]
    cached: Option<bool>,
    #[serde(default)]
    cache_time: Option<String>,
}

#[derive(Deserialize)]
struct SubdomainEntry {
    #[serde(default)]
    subdomain: Option<String>,
    /// The literal string `"none"` when C99 has not resolved an address for
    /// this subdomain — see [`resolved_ip`].
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    cloudflare: bool,
}

pub struct C99;

#[async_trait]
impl Module for C99 {
    fn name(&self) -> &'static str {
        "c99"
    }
    fn description(&self) -> &'static str {
        "C99.nl subdomain finder — enumerates a domain's subdomains and their resolved IPs"
    }
    fn priority(&self) -> u8 {
        80
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        // C99 documents this as "an advanced scan" (as opposed to a cached
        // key/value lookup) unless the caller opts into `&realtime=true`,
        // which this module deliberately does not add (unverified behaviour/
        // pricing difference) — so budget more than the plain keyed-lookup
        // default.
        15_000
    }
    fn cache_ttl_secs(&self) -> u64 {
        // Paid subdomain/host data, stable within a day — the "IP intel: 24h"
        // bracket `Module::cache_ttl_secs` names, the same policy `censys`
        // and `binaryedge` already use for an equivalent data shape.
        86_400
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // C99's subdomain finder performs passive-DNS-style enumeration
        // (T1596.001, the DnsRecon-category technique) in addition to the
        // Infrastructure default's IP-address gathering (T1590.005) and
        // scan-database lookup (T1596.005) — superset, coverage cannot
        // regress. Mirrors `binaryedge`'s identical override for its own
        // subdomain endpoint.
        &["T1590.005", "T1596.001", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let domain = target.value.trim().trim_end_matches('.');
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }
        let domain_enc = urlencode(domain);

        // Key cascade via the shared primitive (see `leakix`/`binaryedge`):
        // on a terminal key/quota failure, rotate through every pooled key
        // before giving up. `absent_statuses: &[]` — C99's spec documents
        // only `200`/`400` for this endpoint and a domain with nothing
        // indexed still answers `200` with an empty `subdomains` array (see
        // module docs), so no status here means "clean miss"; every `400` is
        // C99's one generic key-or-parameter error, caught by the shared
        // `is_auth_failure_400_body` classifier this primitive already
        // applies (its body always contains "Invalid API key").
        let Some(resp) = keyed_cascade(ctx, SRC, initial_key, &[], |key| {
            ctx.http.get(format!(
                "https://api.c99.nl/subdomainfinder?key={}&domain={domain_enc}&json=true",
                urlencode(key)
            ))
        })
        .await?
        else {
            return Ok(ModuleResult::new());
        };
        let body: SubdomainFinderResp = json_decode(SRC, resp).await?;

        if !body.success || body.subdomains.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.extend(build_entities(domain, &body, &ctx.scan_id));
        Ok(result)
    }
}

/// True when `ip` names a real, parseable address rather than being absent or
/// C99's `"none"` placeholder for an unresolved subdomain. Returns the
/// trimmed string (not a parsed `IpAddr`) since callers only need it as an
/// `Entity` value / evidence attribute.
fn resolved_ip(ip: Option<&str>) -> Option<&str> {
    let v = ip?.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("none") {
        return None;
    }
    v.parse::<std::net::IpAddr>().is_ok().then_some(v)
}

/// Normalise and validity-filter one entry's subdomain hostname: trim, strip
/// a trailing dot, lowercase; reject blank, dotless, whitespace-bearing, the
/// queried domain echoed back verbatim, or a bare IP literal. **Pure.**
/// Mirrors `binaryedge::build_one_subdomain`'s filter set — same endpoint
/// shape (a domain in, a list of subdomain hostnames out), same junk to
/// exclude.
fn normalize_subdomain(raw: Option<&str>, domain_lc: &str) -> Option<String> {
    let host = raw?.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host == domain_lc
        || !host.contains('.')
        || host.contains(char::is_whitespace)
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return None;
    }
    Some(host)
}

/// Build every entity from a decoded C99 subdomain-finder response. **Pure**
/// (no network/IO), so the subdomain-vs-external-host confidence split, the
/// `"none"`-IP filter, and the dedup/Cloudflare tagging are all
/// unit-testable directly off JSON fixtures.
///
/// | source                                   | output                                    |
/// |-------------------------------------------|-------------------------------------------|
/// | each valid `subdomains[]` entry            | `Domain` (+ `c99`, [`tags::SUBDOMAIN`] when a genuine subdomain of the query) |
/// | entry's `ip` (present, not `"none"`)       | `resolved_ip` evidence attr + corroborating `IpAddress` (deduped across entries) |
/// | entry's `cloudflare: true`                 | `cloudflare` tag + evidence attr on both  |
/// | `cached`/`cache_time`                      | evidence attrs on every `Domain` entity   |
///
/// Returns empty when nothing in `body.subdomains` survives normalisation
/// (blank, self-echo, or IP-literal entries only).
fn build_entities(domain: &str, body: &SubdomainFinderResp, scan_id: &str) -> Vec<Entity> {
    let domain_lc = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    // Raw count (pre-filter) — mirrors `binaryedge`'s `total_subdomains`
    // broadcast so a filtered-down entity set never understates how much
    // C99 actually returned.
    let total_str = body.subdomains.len().to_string();
    let mut out = Vec::new();
    let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in &body.subdomains {
        let Some(host) = normalize_subdomain(entry.subdomain.as_deref(), &domain_lc) else {
            continue;
        };

        let is_sub = crate::util::domains::is_proper_subdomain_of(&host, &domain_lc);
        let conf = if is_sub {
            confidence::HIGH_PLUSPLUS
        } else {
            confidence::MEDIUM_PLUS
        };
        let mut d = Entity::new(EntityKind::Domain, &host, conf, scan_id);
        d.tag("c99");
        if is_sub {
            d.tag(tags::SUBDOMAIN);
        }
        if entry.cloudflare {
            d.tag("cloudflare");
        }

        let mut ev = Evidence::new(SRC, format!("Subdomain of {domain} per C99"))
            .with_attr("total_subdomains", total_str.as_str())
            .with_attr("cloudflare", entry.cloudflare.to_string());
        let ip = resolved_ip(entry.ip.as_deref());
        if let Some(ip) = ip {
            ev = ev.with_attr("resolved_ip", ip);
        }
        if let Some(cached) = body.cached {
            ev = ev.with_attr("cached", cached.to_string());
        }
        if let Some(ct) = body.cache_time.as_deref().filter(|s| !s.is_empty()) {
            ev = ev.with_attr("cache_time", ct);
        }
        d.add_evidence(ev);
        out.push(d);

        if let Some(ip) = ip
            && seen_ips.insert(ip.to_string())
        {
            let mut ie = Entity::new(EntityKind::IpAddress, ip, confidence::HIGH, scan_id);
            ie.tag("c99");
            if entry.cloudflare {
                ie.tag("cloudflare");
            }
            ie.add_evidence(Evidence::new(
                SRC,
                format!("Resolved IP for {host} per C99 subdomain finder"),
            ));
            out.push(ie);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
