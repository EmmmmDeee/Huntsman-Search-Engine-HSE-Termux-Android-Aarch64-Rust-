//! PassiveTotal / RiskIQ historical passive DNS. Key-gated; **paid plans
//! required** (no free tier — see `.env.example`'s
//! `HUNTSMAN_PASSIVETOTAL_KEY` note and <https://community.riskiq.com/>).
//!
//! Endpoint: `GET https://api.passivetotal.org/v2/dns/passive?query={value}`
//! Auth:     HTTP Basic (`username:api_key`).
//!
//! Unlike Censys's two separate env vars (`HUNTSMAN_CENSYS_ID` +
//! `HUNTSMAN_CENSYS_SECRET`), `HUNTSMAN_PASSIVETOTAL_KEY` carries BOTH halves
//! of the Basic-Auth pair as one `username:api_key` string (per
//! `.env.example`'s "Format: username:api_key (HTTP Basic Auth pair)" note
//! and `service_defs`'s `passivetotal` entry, `KeyPlacement::BasicAuth`), so
//! this module splits it on the first `:` before building the request. The
//! whole raw string is what the key pool tracks as one credential (mirroring
//! `api_key_probe::probes::request_for`'s `KeyPlacement::BasicAuth` handling,
//! which hands the same unsplit value to `-u` for a curl probe).
//!
//! Docs: <https://api.passivetotal.org/api/docs/#api-DNS-GetV2DnsPassiveQuery>.
//! The interactive docs host answered every fetch attempt during research
//! with a bare `503`, so the schema below is corroborated instead against
//! three independent secondary sources that all agree on the same field set:
//! the EclecticIQ "PassiveTotal Passive DNS" enricher integration doc, the
//! Cortex XSOAR / Demisto `PassiveTotal_v2` pack's documented
//! `PassiveTotal.PDNS.*` context-output fields (`resolve`, `resolveType`,
//! `value`, `source`, `firstSeen`, `lastSeen`, `collected`, `recordType`,
//! `recordHash`) with a worked JSON example, and the official `passivetotal`
//! Python SDK's `DnsRequest`/`DnsResponse` wrapper. The `crits_services`
//! PassiveTotal integration additionally confirms the operative error
//! handling: only 401 (bad credentials) and 403 (quota exceeded) are checked
//! as failures — a query with no history is a normal `200` carrying an empty
//! `results` array, not a distinct "not found" status.
//!
//! A record pairs a queried `value` with what it historically `resolve`d to
//! (`resolveType` says whether that answer is an `ip` or a `domain`), tagged
//! with the DNS `recordType` (A/AAAA/CNAME/MX/NS/…), first/last-seen +
//! collected timestamps, and the sensor `source`s that observed it. A
//! `Domain` target surfaces its historical A/AAAA answers as `IpAddress`
//! pivots and CNAME/MX/NS answers as `Domain` pivots (scoped `subdomain` vs
//! `external`, mirroring `mnemonic_pdns`); an `IpAddress` target surfaces the
//! domains that have historically resolved to it (reverse passive DNS).
//! Client-side capped at [`RESULT_LIMIT`] records per query — a long-lived
//! domain can carry many thousands of historical rows, and the API takes no
//! limit parameter of its own.

use std::collections::HashSet;
use std::net::IpAddr;

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
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

const KEY_ENV: &str = "HUNTSMAN_PASSIVETOTAL_KEY";
const SRC: &str = "passivetotal";

/// Entity tag stamped on every finding so a correlator rule or the report can
/// distinguish a *historical, observed* edge from a live resolution — same
/// convention as `mnemonic_pdns`'s `PASSIVE_DNS` tag.
const PASSIVE_DNS: &str = "passive-dns";

/// Records processed per query. The API has no `limit` parameter of its own
/// (unlike mnemonic's `pdns/v3`); a long-lived popular domain can carry many
/// thousands of historical rows, and a low-RAM Termux device should not be
/// asked to map an unbounded list into entities. A sample, never a
/// completeness claim.
const RESULT_LIMIT: usize = 200;

/// The `v2/dns/passive` envelope — only `results` is load-bearing (the
/// `totalRecords`/`queryValue`/`queryType` siblings are ignored; a query with
/// no history is simply `results: []`, per the `crits_services` integration's
/// error-handling code).
#[derive(Deserialize, Default)]
#[serde(default)]
struct PdnsResp {
    results: Vec<PdnsRecord>,
}

/// One passive-DNS record. Field names and the worked example
/// (`{"collected":"2020-06-17 12:26:33","firstSeen":"2010-12-15 09:10:10",
/// "lastSeen":"2020-06-17 05:26:33","recordType":"CNAME",
/// "resolve":"furth.com.ar","resolveType":"domain",
/// "source":["riskiq","pingly"],"value":"www.furth.com.ar"}`) are as
/// documented by the Cortex XSOAR / Demisto `PassiveTotal_v2` pack.
/// Timestamps are the API's own `YYYY-MM-DD HH:MM:SS` strings, carried
/// through verbatim rather than reparsed into another format.
#[derive(Deserialize, Default)]
#[serde(default)]
struct PdnsRecord {
    /// The queried-side value (echoes the query for a forward/domain lookup;
    /// the historically-resolving domain for a reverse/IP lookup).
    value: Option<String>,
    /// What `value` resolved to.
    resolve: Option<String>,
    /// Whether `resolve` is an `"ip"` or a `"domain"`.
    #[serde(rename = "resolveType")]
    resolve_type: Option<String>,
    /// DNS record type: `A`, `AAAA`, `CNAME`, `MX`, `NS`, …
    #[serde(rename = "recordType")]
    record_type: Option<String>,
    #[serde(rename = "firstSeen")]
    first_seen: Option<String>,
    #[serde(rename = "lastSeen")]
    last_seen: Option<String>,
    collected: Option<String>,
    source: Vec<String>,
}

/// True when `s` parses as an IPv4 or IPv6 literal.
fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// IP-aware equality: parses both sides so textually different
/// representations of the same address (e.g. IPv6 forms) still compare
/// equal; falls back to string equality when either side doesn't parse.
/// Mirrors `mnemonic_pdns::ip_eq`.
fn ip_eq(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// True when `s` looks like a routable hostname: dotted, not an IP literal,
/// and free of whitespace. Shared shape check for every `Domain` pivot this
/// module emits, so a malformed record never becomes a bogus entity.
fn is_hostname(s: &str) -> bool {
    !s.is_empty() && s.contains('.') && !is_ip(s) && !s.contains(char::is_whitespace)
}

/// Lower-case and strip a trailing root dot so `Example.com.` and
/// `example.com` compare and de-duplicate as one host.
fn normalise(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Shared passive-DNS evidence: the record type plus first/last-seen/collected
/// timestamps and the observing-source list, so downstream weighting can judge
/// recency and corroboration instead of treating every edge alike. A blank
/// field is omitted rather than emitted empty.
fn pdns_evidence(summary: String, r: &PdnsRecord) -> Evidence {
    let mut ev = Evidence::new(SRC, summary);
    if let Some(rt) = r.record_type.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("record_type", rt.to_ascii_uppercase());
    }
    if let Some(fs) = r.first_seen.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("first_seen", fs);
    }
    if let Some(ls) = r.last_seen.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("last_seen", ls);
    }
    if let Some(c) = r.collected.as_deref().filter(|s| !s.is_empty()) {
        ev = ev.with_attr("collected", c);
    }
    if !r.source.is_empty() {
        ev = ev.with_attr("sources", r.source.join(","));
    }
    ev
}

/// Map a decoded `v2/dns/passive` response to entities, given the queried
/// `target` and whether it is an IP (reverse lookup) or a domain (forward
/// lookup). **Pure** (no network/IO), so the record→entity classification is
/// unit-tested directly off JSON fixtures.
///
/// * Reverse (IP target): each record's `value` is a domain that historically
///   resolved to the queried IP — emitted as a `Domain` pivot.
/// * Forward (domain target): classified by `resolveType` — an `"ip"` answer
///   (A/AAAA) becomes an `IpAddress` pivot; a `"domain"` answer (CNAME/MX/NS/…)
///   becomes a `Domain` pivot, scoped `subdomain` vs `external` relative to the
///   queried domain.
///
/// De-duplicated within the response (IPs under an `ip:` key so a host and an
/// IP string never collide); blank/malformed sides are skipped. Capped at
/// [`RESULT_LIMIT`] input records.
fn build_entities(
    records: &[PdnsRecord],
    target: &str,
    target_is_ip: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let target_l = normalise(target);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for r in records.iter().take(RESULT_LIMIT) {
        if target_is_ip {
            // Reverse passive DNS: `value` is the domain that historically
            // resolved to our queried IP. Verify the record's own `resolve`
            // field (when present) actually names the queried IP before
            // trusting `value` as a pivot — PassiveTotal's schema pairs the
            // two fields specifically so this is checkable; a present,
            // mismatched `resolve` means the record concerns a different IP.
            if r.resolve
                .as_deref()
                .is_some_and(|resolved| !ip_eq(resolved.trim(), &target_l))
            {
                continue;
            }
            let Some(domain) = r.value.as_deref().map(normalise).filter(|h| is_hostname(h)) else {
                continue;
            };
            if !seen.insert(domain.clone()) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Domain, &domain, confidence::HIGH, scan_id);
            e.tag(SRC);
            e.tag(PASSIVE_DNS);
            e.tag("reverse-ip");
            e.add_evidence(pdns_evidence(
                format!("PassiveTotal: {domain} historically resolved to {target_l}"),
                r,
            ));
            out.push(e);
            continue;
        }

        // Forward (domain target): verify the record's own `value` field
        // (when present) actually echoes the queried domain before trusting
        // its `resolve` answer — `value` is documented to "echo the query
        // for a forward/domain lookup", so a present, mismatched `value`
        // means the record concerns a different domain entirely.
        if r.value
            .as_deref()
            .map(normalise)
            .is_some_and(|v| !v.eq_ignore_ascii_case(&target_l))
        {
            continue;
        }
        // Classify the answer by `resolveType`, falling back to shape when
        // the field is blank/absent.
        let Some(resolve) = r
            .resolve
            .as_deref()
            .map(normalise)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let resolve_type = r.resolve_type.as_deref().unwrap_or("").trim();
        let record_type_l = r
            .record_type
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        let looks_ip =
            resolve_type.eq_ignore_ascii_case("ip") || (resolve_type.is_empty() && is_ip(&resolve));

        if looks_ip {
            if !is_ip(&resolve) || !seen.insert(format!("ip:{resolve}")) {
                continue;
            }
            let mut e = Entity::new(EntityKind::IpAddress, &resolve, confidence::HIGH, scan_id);
            e.tag(SRC);
            e.tag(PASSIVE_DNS);
            e.add_evidence(pdns_evidence(
                format!("PassiveTotal: {target_l} historically resolved to {resolve}"),
                r,
            ));
            out.push(e);
        } else if is_hostname(&resolve) && seen.insert(resolve.clone()) {
            let mut e = Entity::new(EntityKind::Domain, &resolve, confidence::HIGH, scan_id);
            e.tag(SRC);
            e.tag(PASSIVE_DNS);
            if !record_type_l.is_empty() {
                e.tag(record_type_l.clone());
            }
            if crate::util::domains::is_or_subdomain_of(&resolve, &target_l) {
                e.tag(tags::SUBDOMAIN);
            } else {
                e.tag(tags::EXTERNAL);
            }
            let label = if record_type_l.is_empty() {
                "resolved to".to_string()
            } else {
                format!("{} →", record_type_l.to_ascii_uppercase())
            };
            e.add_evidence(pdns_evidence(
                format!("PassiveTotal: {target_l} {label} {resolve}"),
                r,
            ));
            out.push(e);
        }
    }

    out
}

pub struct PassiveTotal;

#[async_trait]
impl Module for PassiveTotal {
    fn name(&self) -> &'static str {
        "passivetotal"
    }

    fn description(&self) -> &'static str {
        "PassiveTotal / RiskIQ historical passive DNS — domain↔IP resolution pairs over time"
    }

    fn priority(&self) -> u8 {
        60
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // PassiveTotal's core function is a passive-DNS database query —
        // Search Open Technical Databases: DNS/Passive DNS (T1596.001, the
        // same sub-technique `mnemonic_pdns` cites) is the precise fit, more
        // specific than the generic T1596.005 "Scan Databases" the
        // Infrastructure default alongside pairs with. T1590.005 IP Addresses
        // stays from that default since the module also emits IpAddress
        // pivots. Superset of the default — coverage cannot regress.
        &["T1590.005", "T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    fn cache_ttl_secs(&self) -> u64 {
        // Historical passive-DNS resolution pairs don't change retroactively
        // and a paid per-query allowance is worth conserving — the same "IP
        // intel: 24h" bracket `censys` uses.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let raw = match ctx.key_opt(KEY_ENV) {
            Some(v) => v,
            None => return Ok(ModuleResult::new()),
        };
        // `HUNTSMAN_PASSIVETOTAL_KEY` is "username:api_key" — split on the
        // FIRST `:` (an api_key value itself never contains one in practice,
        // but a username can't either way — this is the only unambiguous
        // split point).
        let Some((username, api_key)) = raw.split_once(':') else {
            // Missing separator — an unusable/misconfigured credential, not a
            // network failure.
            return Ok(ModuleResult::new());
        };
        if username.trim().is_empty() || api_key.trim().is_empty() {
            return Ok(ModuleResult::new());
        }

        let (query, target_is_ip) = match target.kind {
            TargetKind::Domain => (target.value.trim().to_string(), false),
            TargetKind::IpAddress => (target.value.trim().to_string(), true),
            _ => return Ok(ModuleResult::new()),
        };
        if query.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.passivetotal.org/v2/dns/passive?query={}",
            urlencode(&query)
        );

        // Manual retry loop (not `keyed_cascade`): mirrors `censys`'s
        // Basic-Auth pattern — a bounded in-place 429 backoff-retry via
        // `handle_keyed_error`, terminal failure reported + surfaced on
        // 401/403. `raw` (the whole `username:api_key` string) is what the
        // key pool tracks as one credential for this service, so it — not
        // just `api_key` — is what gets marked exhausted.
        let mut retries = 2u8;
        let body: PdnsResp = loop {
            if ctx.cancel.is_cancelled() {
                return Ok(ModuleResult::new());
            }
            let resp = ctx
                .http
                .get(&url)
                .basic_auth(username, Some(api_key))
                .header("Accept", "application/json")
                .send_tagged(SRC)
                .await?;

            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if crate::util::http::handle_keyed_error(
                    code,
                    resp.headers(),
                    &mut retries,
                    SRC,
                    raw,
                    ctx,
                )
                .await
                {
                    continue;
                }
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }

            break crate::util::http::json_decode(SRC, resp).await?;
        };

        let mut result = ModuleResult::new();
        result.extend(build_entities(
            &body.results,
            &query,
            target_is_ip,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
