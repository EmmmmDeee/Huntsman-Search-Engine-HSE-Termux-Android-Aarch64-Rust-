//! Mnemonic Passive DNS (PDNS) — free, keyless historical DNS-resolution intel.
//!
//! Mnemonic's public Passive DNS API (`api.mnemonic.no/pdns/v3/{query}`) is a
//! keyless, TLP:WHITE corpus of *observed* DNS answers — every resolution a
//! sensor network actually saw, with first/last-seen timestamps and an
//! observation count. It answers the two questions live/active DNS cannot:
//!
//!   * **Domain → historical IPs.** Every A/AAAA a domain ever resolved to, not
//!     just the record live right now — so an IP a target has since rotated away
//!     from (and the infrastructure it shares) is still a lead. Pairs with the
//!     active resolvers (`dns_intel`, `doh_resolver`), which only see *now*.
//!   * **IP → historical domains (reverse passive DNS).** Which domains have
//!     resolved to an IP over time — the co-hosting / shared-infrastructure pivot
//!     a single live PTR lookup (`hackertarget` reverse-DNS) misses entirely.
//!
//! It also surfaces the CNAME/MX/NS graph anchored on a domain (the related
//! third-party infrastructure it delegates to). Keyless, one JSON request per
//! target, Termux-friendly — no daemon, no local index.
//!
//! Honesty discipline (Operational Constitution): the API returns a *sample* —
//! the most-relevant [`RESULT_LIMIT`] records, not the exhaustive set — and every
//! edge is *historical* (an observed **past** resolution whose present-day
//! validity is not asserted). Entities are therefore emitted at
//! [`confidence::HIGH`] (a reliable source, not a live confirmation) and carry the
//! first/last-seen dates and observation count as evidence so recency can be
//! weighed downstream rather than assumed.

use std::collections::HashSet;
use std::net::IpAddr;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "mnemonic_pdns";
const BASE: &str = "https://api.mnemonic.no/pdns/v3";

/// Entity tag stamped on every passive-DNS finding so a correlator rule or the
/// report can distinguish a *historical, observed* edge from a live resolution.
const PASSIVE_DNS: &str = "passive-dns";

/// Records requested per query. A busy domain/IP can hold hundreds of observed
/// answers; we deliberately cap the pull so a low-RAM Termux device is never
/// asked to buffer and map an unbounded list. This is a *sample of the most
/// relevant* records, never a completeness claim — see the module honesty note.
const RESULT_LIMIT: u32 = 100;

pub struct MnemonicPdns;

/// The `pdns/v3` envelope — only the `data` array is load-bearing (the
/// `responseCode`/`count`/`metaData` siblings are ignored; an empty or
/// object-not-found reply is simply `data: []`).
#[derive(Deserialize, Default)]
#[serde(default)]
struct PdnsResponse {
    data: Vec<PdnsRecord>,
}

/// One passive-DNS observation. The search matches the query string against
/// **both** the `query` and `answer` sides, so a single call yields forward
/// (domain→answer) and reverse (query→ip) records interleaved; the mapper below
/// classifies each by the queried target. `first_seen`/`last_seen` are epoch
/// **milliseconds** (divided by 1000 before formatting).
#[derive(Deserialize, Default)]
#[serde(default)]
struct PdnsRecord {
    query: String,
    answer: String,
    rrtype: String,
    times: u64,
    #[serde(rename = "firstSeenTimestamp")]
    first_seen: i64,
    #[serde(rename = "lastSeenTimestamp")]
    last_seen: i64,
}

/// Lower-case and strip a trailing root dot so `Example.com.` and `example.com`
/// compare and de-duplicate as one host. Also used on IPs (harmless — an IP
/// literal has no trailing dot and lower-casing only affects hex IPv6 digits).
fn normalise_host(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// True when `s` parses as an IPv4 or IPv6 literal.
fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// True when `s` looks like a routable hostname: dotted, not an IP literal, and
/// not a reverse-DNS `.arpa` name (a PTR query side we never emit as a Domain).
fn is_hostname(s: &str) -> bool {
    s.contains('.') && !is_ip(s) && !s.ends_with(".arpa")
}

/// Compare two IP strings by parsed value so differing textual forms of the same
/// address (compressed vs expanded IPv6) still match; falls back to string
/// equality when either side is not a parseable IP.
fn ip_eq(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Shared passive-DNS evidence: the record type plus first/last-seen dates and
/// the observation count, so downstream weighting can judge recency instead of
/// treating a stale edge like a live one. A non-positive epoch yields no date
/// attribute (never a fake `1970-01-01`); a zero observation count is omitted.
fn pdns_evidence(summary: String, rrtype: &str, r: &PdnsRecord) -> Evidence {
    let mut ev = Evidence::new(SRC, summary).with_attr("rrtype", rrtype);
    if let Some(first) = crate::util::timefmt::ymd_utc(r.first_seen / 1000) {
        ev = ev.with_attr("first_seen", first);
    }
    if let Some(last) = crate::util::timefmt::ymd_utc(r.last_seen / 1000) {
        ev = ev.with_attr("last_seen", last);
    }
    if r.times > 0 {
        ev = ev.with_attr("observations", r.times.to_string());
    }
    ev
}

/// A domain from the forward CNAME/MX/NS graph (or an inbound CNAME alias),
/// tagged with its record type and scoped `subdomain` vs `external` relative to
/// the queried domain so the report can keep third-party infra out of the
/// subject's own footprint.
fn forward_infra_domain(
    host: &str,
    target: &str,
    rrtype: &str,
    r: &PdnsRecord,
    scan_id: &str,
) -> Entity {
    let mut e = Entity::new(EntityKind::Domain, host, confidence::HIGH, scan_id);
    e.tag(SRC);
    e.tag(PASSIVE_DNS);
    e.tag(rrtype);
    if crate::util::domains::is_or_subdomain_of(host, target) {
        e.tag(tags::SUBDOMAIN);
    } else {
        e.tag(tags::EXTERNAL);
    }
    e.add_evidence(pdns_evidence(
        format!("Passive DNS: {target} {rrtype} → {host}"),
        rrtype,
        r,
    ));
    e
}

/// Map a passive-DNS response to entities, given the queried `target` and whether
/// it is an IP (reverse lookup) or a domain (forward lookup). **Pure** (no
/// network), so the record→entity classification is unit-tested directly.
///
/// * Reverse (IP target): each A/AAAA whose *answer* is the target IP yields the
///   *query* domain — the historical resolvers of that IP.
/// * Forward (domain target): each A/AAAA yields the historical *answer* IP; each
///   CNAME/MX/NS yields the related-infrastructure hostname; an inbound CNAME
///   whose answer is the target yields the aliasing hostname.
///
/// De-duplicated within the response (IPs under an `ip:` key so a host and an IP
/// string never collide); blank sides and non-matching records are skipped.
fn build_entities(
    records: &[PdnsRecord],
    target: &str,
    target_is_ip: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let target_l = normalise_host(target);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for r in records {
        let rrtype = r.rrtype.trim().to_ascii_lowercase();
        let query = normalise_host(&r.query);
        let answer = normalise_host(&r.answer);
        if query.is_empty() || answer.is_empty() {
            continue;
        }

        if target_is_ip {
            // Reverse passive DNS: an A/AAAA whose ANSWER is our IP means the
            // QUERY is a domain that resolved here — the co-hosting pivot.
            if (rrtype == "a" || rrtype == "aaaa")
                && ip_eq(&answer, &target_l)
                && is_hostname(&query)
                && seen.insert(query.clone())
            {
                let mut e = Entity::new(EntityKind::Domain, &query, confidence::HIGH, scan_id);
                e.tag(SRC);
                e.tag(PASSIVE_DNS);
                e.tag("reverse-ip");
                e.add_evidence(pdns_evidence(
                    format!("Passive DNS reverse: {query} {rrtype} → {answer}"),
                    &rrtype,
                    r,
                ));
                out.push(e);
            }
            continue;
        }

        // Forward (domain target): records anchored on our domain. The dedup /
        // shape checks live in the match guards (a side-effecting `seen.insert`
        // only runs once the record type matches), so each arm's body is the
        // emission itself — no nested `if`.
        if query == target_l {
            match rrtype.as_str() {
                "a" | "aaaa" if is_ip(&answer) && seen.insert(format!("ip:{answer}")) => {
                    let mut e =
                        Entity::new(EntityKind::IpAddress, &answer, confidence::HIGH, scan_id);
                    e.tag(SRC);
                    e.tag(PASSIVE_DNS);
                    e.add_evidence(pdns_evidence(
                        format!("Passive DNS: {target_l} {rrtype} → {answer}"),
                        &rrtype,
                        r,
                    ));
                    out.push(e);
                }
                "cname" | "mx" | "ns" if is_hostname(&answer) && seen.insert(answer.clone()) => {
                    out.push(forward_infra_domain(
                        &answer, &target_l, &rrtype, r, scan_id,
                    ));
                }
                _ => {}
            }
        } else if rrtype == "cname"
            && answer == target_l
            && is_hostname(&query)
            && seen.insert(query.clone())
        {
            // A name that CNAMEs *into* our domain — an inbound alias.
            out.push(forward_infra_domain(&query, &target_l, &rrtype, r, scan_id));
        }
    }

    out
}

#[async_trait]
impl Module for MnemonicPdns {
    fn name(&self) -> &'static str {
        "mnemonic_pdns"
    }

    fn description(&self) -> &'static str {
        "Mnemonic passive DNS (free) — historical domain→IP resolutions, reverse-IP domain pivots, and CNAME/MX/NS infra"
    }

    fn priority(&self) -> u8 {
        25
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::IpAddress | TargetKind::Url
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Querying an open passive-DNS corpus for a target's historical
        // resolutions is ATT&CK Search Open Technical Databases: DNS/Passive DNS.
        &["T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (query, target_is_ip) = match target.kind {
            TargetKind::Domain => (target.value.trim().to_string(), false),
            TargetKind::IpAddress => (target.value.trim().to_string(), true),
            TargetKind::Url => match crate::util::url_util::host_from_url(&target.value) {
                Some(h) => {
                    let is_ip = is_ip(&h);
                    (h, is_ip)
                }
                None => return Ok(ModuleResult::new()),
            },
            _ => return Ok(ModuleResult::new()),
        };
        if query.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Mnemonic always answers 200 (an unknown target is `data: []`), so a
        // non-2xx from `fetch_json` is a genuine outage/rate-limit worth
        // surfacing to the operator and the circuit breaker.
        let url = format!("{BASE}/{}?limit={RESULT_LIMIT}", urlencode(&query));
        let resp: PdnsResponse = fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        result.extend(build_entities(
            &resp.data,
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
