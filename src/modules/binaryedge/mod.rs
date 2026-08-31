//! BinaryEdge internet-wide host/exposure scan data. Key-gated (paid; no
//! free tier — see `HUNTSMAN_BINARYEDGE_KEY`'s entry in
//! `util::keys::constants`).
//!
//! Endpoints:
//!   * `GET https://api.binaryedge.io/v2/query/ip/{ip}` — open ports,
//!     detected services (name/product/version/CPE) for a host.
//!   * `GET https://api.binaryedge.io/v2/query/domains/subdomain/{domain}` —
//!     known subdomains for a domain.
//!
//! Auth: `X-Key: <key>` request header — the same header this repo's
//! already-verified auth-check probe uses against
//! `GET https://api.binaryedge.io/v2/user/subscription`
//! (`util::service_defs`'s `binaryedge` def).
//!
//! # Documentation provenance
//!
//! BinaryEdge was acquired by Coalition Inc., and as of this writing
//! `docs.binaryedge.io` (and every page under it, including `/api-v2/` and
//! `/errors/`) 301-redirects to a Coalition support article rather than
//! serving the API reference. The exact request/response shapes below were
//! instead confirmed from a still-live, un-redirected mirror of the same
//! GitBook documentation at `https://docs.sand.binaryedge.io/api-v2/` (full
//! worked JSON examples for both endpoints, including the `X-Key` header
//! and the `400`/`401`/`403`/`404` status meanings) and
//! `https://docs.sand.binaryedge.io/errors/`, cross-checked against the
//! independently-maintained `Te-k/pybinaryedge` API client (same `v2/query/
//! ip/{target}` and `v2/query/domains/subdomain/{target}` paths, same
//! `X-Key` header, and a real captured CLI response in its README showing
//! the identical `events[].port`/`events[].results[].origin|target|result`
//! nesting) and the `wjlin0/uncover` Go client's `binaryedge` source
//! adapter (identical `page`/`page_size`/`total`/`query`/`events[]` shape
//! for the subdomain endpoint). Only the fields corroborated across these
//! sources are modelled (see `types.rs`); the module deliberately does not
//! attempt CVE/vulnerability data, historical events, or risk scoring,
//! none of which could be verified this way.
//!
//! Per-result raw service **banners are not stored** — like `leakix`,
//! individual banners can carry credentials or other sensitive text. The
//! raw response body is still scanned for embedded API keys regardless via
//! [`crate::util::http::json_scanned`], independent of which fields the
//! response struct extracts.

mod types;

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
use crate::util::http::{json_decode, json_scanned, keyed_cascade, urlencode};

use types::{IpResp, SubdomainResp};

const KEY_ENV: &str = "HUNTSMAN_BINARYEDGE_KEY";
const SRC: &str = "binaryedge";

/// Cap on the ports/services/CPEs listed per evidence attribute — enough
/// signal for a heavily-exposed host without letting one noisy target bloat
/// the row (mirrors `leakix`'s `MAX_PORTS`/`TOP_N` rationale).
const MAX_LIST: usize = 25;

pub struct BinaryEdge;

#[async_trait]
impl Module for BinaryEdge {
    fn name(&self) -> &'static str {
        "binaryedge"
    }
    fn description(&self) -> &'static str {
        "BinaryEdge host recon — surfaces open ports/services from internet-wide scans, plus subdomain enumeration"
    }
    fn priority(&self) -> u8 {
        78
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }
    fn cache_ttl_secs(&self) -> u64 {
        // Host scan/exposure + subdomain data is stable within a day — the "IP
        // intel: 24h" bracket the `Module::cache_ttl_secs` doc names, same
        // policy `censys` already uses for the identical data shape.
        86_400
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // BinaryEdge IS a scan database (T1596.005) and gathers IP address
        // info (T1590.005) — both the Infrastructure default. Its subdomain
        // endpoint additionally performs passive-DNS-style enumeration
        // (T1596.001, the DnsRecon-category technique), which the
        // Infrastructure default does not include. Superset — coverage
        // cannot regress.
        &["T1590.005", "T1596.001", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        match target.kind {
            TargetKind::IpAddress => query_ip(target, initial_key, ctx).await,
            TargetKind::Domain => query_subdomains(target, initial_key, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

async fn query_ip(target: &Target, initial_key: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let ip = target.value.trim();
    if ip.is_empty() {
        return Ok(ModuleResult::new());
    }
    let url = format!("https://api.binaryedge.io/v2/query/ip/{}", urlencode(ip));
    // Key cascade via the shared primitive (see `leakix`): on a terminal
    // key/quota failure, rotate through every pooled key before giving up.
    // `absent_statuses: &[404]` — BinaryEdge's documented "Page not found"
    // for an unindexed target (`docs.sand.binaryedge.io/errors/`), a clean
    // miss rather than an error.
    let Some(resp) = keyed_cascade(ctx, SRC, initial_key, &[404], |key| {
        ctx.http
            .get(&url)
            .header("X-Key", key)
            .header("Accept", "application/json")
    })
    .await?
    else {
        return Ok(ModuleResult::new());
    };
    // json_scanned: per-port service results can carry arbitrary grabbed
    // text (banners) — scan the raw body for embedded API keys even though
    // this module never stores a banner verbatim.
    let body: IpResp = json_scanned(resp, SRC)
        .await
        .map_err(|e| crate::core::error::Error::module(SRC, e))?;

    let mut result = ModuleResult::new();
    result.extend(build_ip_entities(&body, ip, &ctx.scan_id));
    Ok(result)
}

async fn query_subdomains(
    target: &Target,
    initial_key: &str,
    ctx: &ModuleContext,
) -> Result<ModuleResult> {
    let domain = target.value.trim().trim_end_matches('.');
    if domain.is_empty() {
        return Ok(ModuleResult::new());
    }
    let url = format!(
        "https://api.binaryedge.io/v2/query/domains/subdomain/{}",
        urlencode(domain)
    );
    let Some(resp) = keyed_cascade(ctx, SRC, initial_key, &[404], |key| {
        ctx.http
            .get(&url)
            .header("X-Key", key)
            .header("Accept", "application/json")
    })
    .await?
    else {
        return Ok(ModuleResult::new());
    };
    let body: SubdomainResp = json_decode(SRC, resp).await?;

    let mut result = ModuleResult::new();
    result.extend(build_subdomain_entities(domain, &body, &ctx.scan_id));
    Ok(result)
}

/// One port's flattened scan result — owned so it outlives the per-event
/// borrow that produced it. Built by `flatten_ports`.
struct FlatPort {
    port: u32,
    protocol: String,
    name: Option<String>,
    product: Option<String>,
    version: Option<String>,
    cpes: Vec<String>,
}

/// Flatten `events[].results[]` into one row per observed port. **Pure** (no
/// IO). A port event with no `results` (bare open-port detection, no service
/// identification yet) still yields one row so the port itself is counted —
/// mirrors `leakix`'s "bare service, no metadata" handling.
fn flatten_ports(body: &IpResp) -> Vec<FlatPort> {
    body.events
        .iter()
        .flat_map(|event| {
            let Some(event_port) = event.port else {
                return Vec::new();
            };
            if event.results.is_empty() {
                return vec![FlatPort {
                    port: event_port,
                    protocol: "tcp".to_string(),
                    name: None,
                    product: None,
                    version: None,
                    cpes: Vec::new(),
                }];
            }
            event
                .results
                .iter()
                .map(|r| {
                    let port = r.target.as_ref().and_then(|t| t.port).unwrap_or(event_port);
                    let protocol = r
                        .target
                        .as_ref()
                        .and_then(|t| t.protocol.as_deref())
                        .unwrap_or("tcp")
                        .to_string();
                    let service = r
                        .result
                        .as_ref()
                        .and_then(|w| w.data.as_ref())
                        .and_then(|d| d.service.as_ref());
                    FlatPort {
                        port,
                        protocol,
                        name: service.and_then(|s| s.name.clone()),
                        product: service.and_then(|s| s.product.clone()),
                        version: service.and_then(|s| s.version.clone()),
                        cpes: service.map_or_else(Vec::new, |s| s.cpe.clone()),
                    }
                })
                .collect::<Vec<FlatPort>>()
        })
        .collect()
}

/// Build the subject `IpAddress` entity from a `v2/query/ip` response.
/// **Pure** (no network/IO), so the port/service/CPE aggregation is
/// unit-testable directly off JSON fixtures. Returns empty when the
/// response carries no port events at all.
fn build_ip_entities(body: &IpResp, ip: &str, scan_id: &str) -> Vec<Entity> {
    let flat = flatten_ports(body);
    if flat.is_empty() {
        return Vec::new();
    }

    let mut ports: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut cpes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut services: Vec<String> = Vec::new();
    for f in flat {
        ports.insert(f.port);
        if f.name.is_some() || f.product.is_some() {
            let port = f.port;
            let protocol = &f.protocol;
            let name = f.name.as_deref().unwrap_or("unknown");
            let mut s = format!("{port}/{protocol} {name}");
            if let Some(p) = f.product.as_deref() {
                s.push(' ');
                s.push_str(p);
                if let Some(v) = f.version.as_deref() {
                    s.push(' ');
                    s.push_str(v);
                }
            }
            services.push(s);
        }
        cpes.extend(f.cpes);
    }

    let mut entity = Entity::new(
        EntityKind::IpAddress,
        ip,
        confidence::VERY_HIGH_PLUS,
        scan_id,
    );
    entity.tag("binaryedge");

    let total_events = body.total.unwrap_or(body.events.len() as u64);
    let mut ev = Evidence::new(
        SRC,
        format!(
            "BinaryEdge: {} open port(s) across {total_events} scan event(s)",
            ports.len()
        ),
    )
    .with_attr("port_count", ports.len().to_string())
    .with_attr(
        "ports",
        ports
            .iter()
            .take(MAX_LIST)
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(","),
    )
    .with_attr("total_events", total_events.to_string());

    if !services.is_empty() {
        ev = ev.with_attr(
            "services",
            services
                .iter()
                .take(MAX_LIST)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    if !cpes.is_empty() {
        ev = ev.with_attr(
            "cpes",
            cpes.iter()
                .take(MAX_LIST)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    entity.add_evidence(ev);
    vec![entity]
}

/// Build `Domain` pivots from a `v2/query/domains/subdomain` response.
/// **Pure** (no network/IO). Each item in `events` is already a full
/// hostname (not a bare label, unlike `securitytrails`'s subdomain shape),
/// so this only normalises and validity-filters: drops a blank entry, the
/// queried domain echoed back verbatim, a bare IP literal, and anything
/// carrying whitespace. `total` is BinaryEdge's own reported match count
/// (falls back to the page length), carried on every entity so a
/// page-capped response never hides how large the real subdomain set is
/// (mirrors `securitytrails::build_subdomain_entity`'s `total_subdomains`).
fn build_subdomain_entities(domain: &str, body: &SubdomainResp, scan_id: &str) -> Vec<Entity> {
    let domain_lc = domain.to_ascii_lowercase();
    let total = body.total.unwrap_or(body.events.len() as u64).to_string();
    body.events
        .iter()
        .filter_map(|raw| build_one_subdomain(domain, &domain_lc, raw, &total, scan_id))
        .collect()
}

fn build_one_subdomain(
    domain: &str,
    domain_lc: &str,
    raw: &str,
    total_str: &str,
    scan_id: &str,
) -> Option<Entity> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host == domain_lc
        || !host.contains('.')
        || host.contains(char::is_whitespace)
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return None;
    }
    // Defensive: BinaryEdge's subdomain-enumeration endpoint can echo back a
    // host that passes the filters above (not blank/self/dotless/IP-literal)
    // yet isn't actually under the queried domain — a CNAME target or a
    // loosely-associated host. Mirrors c99's `is_proper_subdomain_of` gate for
    // the identical endpoint shape (a domain in, a flat hostname list out): a
    // verified subdomain keeps the top confidence and the `subdomain` tag; an
    // unverified one is still reported, but at a lower confidence and without
    // the tag, rather than an unverified host outranking c99's own verified one.
    let is_sub = crate::util::domains::is_proper_subdomain_of(&host, domain_lc);
    let conf = if is_sub {
        confidence::EXPERT
    } else {
        confidence::MEDIUM_PLUS
    };
    let mut e = Entity::new(EntityKind::Domain, &host, conf, scan_id);
    e.tag("binaryedge");
    if is_sub {
        e.tag("subdomain");
    }
    e.add_evidence(
        Evidence::new(SRC, format!("Subdomain of {domain} per BinaryEdge"))
            .with_attr("parent_domain", domain)
            .with_attr("total_subdomains", total_str),
    );
    Some(e)
}
