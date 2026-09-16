//! IP reputation — AlienVault OTX threat intel + passive DNS + Tor exit check.
//!
//! Merges the former `alienvault_otx` and `tor_exit_check` modules.
//!
//! - **IpAddress** targets → OTX pulse lookup AND Tor exit-relay check.
//! - **Domain** targets   → OTX pulse lookup AND OTX passive-DNS enumeration
//!   (historical resolving IPs + observed subdomains); the Tor list is IP-only.
//!
//! The Tor exit-relay list is fetched once and cached via `OnceCell` so
//! subsequent calls within the same process are free. A transient network
//! failure on the first fetch leaves the cache uninitialised, allowing
//! the next scan to retry.
//!
//! Works keyless, but OTX throttles the free tier hard (a single request often
//! `429`s). An **optional** pooled `HUNTSMAN_ALIENVAULT_KEY` is sent as the
//! `X-OTX-API-KEY` header (OTX's documented auth) — the same key OTX issues for
//! free on signup — lifting every OTX pass, especially the supplementary
//! passive-DNS enumeration, off the keyless rate-limit wall. Without a key the
//! keyless path is byte-for-byte unchanged.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::OnceCell;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, fetch_json_or_404, fetch_keyed_json, urlencode};
use crate::util::threat::is_meaningful_tag;

// ── OTX response types ─────────────────────────────────────────────

#[derive(Deserialize)]
struct OtxResp {
    pulse_info: Option<PulseInfo>,
}

#[derive(Deserialize)]
struct PulseInfo {
    count: Option<u64>,
    #[serde(default)]
    pulses: Vec<Pulse>,
}

#[derive(Deserialize)]
struct Pulse {
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    adversary: Option<String>,
    tlp: Option<String>,
    created: Option<String>,
}

// ── OTX passive-DNS response types ─────────────────────────────────

#[derive(Deserialize)]
struct PassiveDnsResp {
    #[serde(default)]
    passive_dns: Vec<PassiveDnsRow>,
}

#[derive(Deserialize)]
struct PassiveDnsRow {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    record_type: Option<String>,
    #[serde(default)]
    first: Option<String>,
    #[serde(default)]
    last: Option<String>,
}

// ── Tor exit-relay cache ───────────────────────────────────────────

/// Successful fetches are memoised here. Stored as `Arc<HashSet<…>>` so
/// readers get a cheap clone-of-pointer rather than the whole set.
static EXIT_SET: OnceCell<Arc<HashSet<String>>> = OnceCell::const_new();

const TOR_EXIT_LIST_URL: &str = "https://check.torproject.org/exit-addresses";

/// Fetch + parse, with a single timeout covering BOTH the request and body
/// download. `url` is parameterised so tests can point this at a local
/// server; production always calls it with [`TOR_EXIT_LIST_URL`].
///
/// Returns `Err` for every genuine failure mode (transport error, non-2xx
/// status, an oversized/unreadable body, a timeout, or a body that parses
/// to zero `ExitAddress` lines) instead of silently collapsing them all to
/// `None` — see T2.111: a real Tor-list outage used to look identical to
/// "checked, this IP isn't a Tor exit" from the operator's side.
async fn fetch_exit_set(http: &reqwest::Client, url: &str) -> Result<HashSet<String>> {
    let body_res = tokio::time::timeout(Duration::from_secs(8), async {
        let resp = http.get(url).send_tagged(SRC).await?;
        if !resp.status().is_success() {
            return Err(Error::module(
                SRC,
                format!("tor exit list fetch returned HTTP {}", resp.status()),
            ));
        }
        // Cap the body so a hostile reputation endpoint can't OOM a phone.
        crate::util::http::read_body_capped(resp, 256 * 1024)
            .await
            .ok_or_else(|| {
                Error::module(
                    SRC,
                    "tor exit list body exceeded the size cap or was unreadable",
                )
            })
    })
    .await
    .map_err(|_| Error::module(SRC, "tor exit list fetch timed out"))??;

    let estimated = body_res
        .lines()
        .filter(|l| l.starts_with("ExitAddress "))
        .count();
    let mut set = HashSet::with_capacity(estimated);
    for line in body_res.lines() {
        if let Some(rest) = line.strip_prefix("ExitAddress ")
            && let Some(ip) = rest.split_whitespace().next()
        {
            set.insert(ip.to_string());
        }
    }
    if set.is_empty() {
        return Err(Error::module(
            SRC,
            "tor exit list fetch succeeded but yielded zero ExitAddress entries",
        ));
    }
    Ok(set)
}

/// Returns the cached set on a cache hit or successful fresh fetch; `Err`
/// when the upstream is unreachable AND we have no cached copy yet. A
/// transient failure leaves the cache uninitialised so the next call
/// retries — unchanged from before T2.111, only the failure signal changed
/// from a silent `None` to a propagated `Error`.
async fn exit_set(http: &reqwest::Client) -> Result<Arc<HashSet<String>>> {
    // `get_or_try_init` single-flights the fetch: when several IP targets miss the
    // cache concurrently, exactly ONE runs the (full Tor exit-list) download and
    // the rest await its result — instead of the old get/fetch/set pattern where
    // every concurrent first-caller fetched the whole list independently. On a
    // fetch error the cell stays uninitialised, so the next call retries (the
    // documented transient-failure contract above is preserved).
    EXIT_SET
        .get_or_try_init(|| async { fetch_exit_set(http, TOR_EXIT_LIST_URL).await.map(Arc::new) })
        .await
        .map(Arc::clone)
}

// ── Module ─────────────────────────────────────────────────────────

const SRC: &str = "ip_reputation";
/// Optional AlienVault OTX API key. OTX works keyless (heavily throttled — a
/// single request often 429s), so a pooled key is what makes the OTX passes —
/// especially the supplementary passive-DNS enumeration — reliable in a real
/// multi-target scan. Sent as the `X-OTX-API-KEY` header per OTX's auth spec.
const OTX_KEY_ENV: &str = "HUNTSMAN_ALIENVAULT_KEY";
const OTX_KEY_HEADER: &str = "X-OTX-API-KEY";

pub struct IpReputation;

#[async_trait]
impl Module for IpReputation {
    fn name(&self) -> &'static str {
        "ip_reputation"
    }

    fn description(&self) -> &'static str {
        "IP reputation recon — correlates AlienVault OTX threat intel, passive DNS, and Tor exit-relay status"
    }

    fn priority(&self) -> u8 {
        78
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // OTX pulse lookup → threat-intelligence vendor data (T1597.001);
        // surfaced adversary/organisation context (T1591.002); IP addresses
        // confirmed as Tor exits (T1590.005). Replaces the Infrastructure
        // default T1596.005. (No ISP data: this module never fetches or
        // surfaces one — that's ip_geo/ip_whois_geo.)
        &["T1590.005", "T1591.002", "T1597.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        // The last genuine transport/parse failure seen across the two
        // sub-checks (T2.111). Real evidence is never discarded because a
        // *different* sub-check failed — see `combine_result` below.
        let mut hard_failure: Option<Error> = None;

        // ── 1. AlienVault OTX (IpAddress + Domain) ─────────────────
        if let Err(e) = run_otx(target, ctx, &mut result).await {
            hard_failure = Some(e);
        }

        // ── 2. Tor exit-relay check (IpAddress only) ────────────────
        if target.kind == TargetKind::IpAddress
            && let Err(e) = run_tor_check(target, ctx, &mut result).await
        {
            hard_failure.get_or_insert(e);
        }

        // ── 3. OTX passive DNS (Domain only, best-effort enumeration) ─
        // Supplementary: never contributes to `hard_failure` (a keyless 429
        // must not fail the module when the reputation pass succeeded).
        run_otx_passive_dns(target, ctx, &mut result).await;

        result.or_hard_failure(hard_failure)
    }
}

// ── OTX sub-routine ────────────────────────────────────────────────

/// Middle tier of [`otx_confidence`]'s graduation (2-4 corroborating pulses) —
/// between `confidence::MEDIUM_HIGH` (0-1 pulses) and `confidence::VERY_HIGH`
/// (5+), with no existing ladder rung at this exact value.
const OTX_MULTI_PULSE_CONFIDENCE: f64 = 0.68;

/// Confidence for an OTX-flagged indicator, graduated by corroborating pulse
/// count. A lone pulse is often self-published low-signal noise — a lead, not a
/// probable finding — while many independent pulses agreeing is stronger
/// evidence. A flat score inflated a single noisy pulse to the same weight as a
/// broad consensus. Kept conservative: OTX pulse counts are not fully independent
/// (one actor can publish several), so the top tier only slightly exceeds the
/// former flat value rather than approaching certainty.
fn otx_confidence(pulse_count: u64) -> f64 {
    match pulse_count {
        0 | 1 => confidence::MEDIUM_HIGH,
        2..=4 => OTX_MULTI_PULSE_CONFIDENCE,
        _ => confidence::VERY_HIGH,
    }
}

/// OTX GET with OTX's *optional-key* auth model. When a pooled
/// [`OTX_KEY_ENV`] key is present it is sent as the `X-OTX-API-KEY` header via
/// the shared keyed-fetch helper (401/403/429 burn the key, 404 → `Ok(None)`);
/// when absent the request falls back to the exact keyless path OTX has always
/// used ([`fetch_json_or_404`], curl-fallback and all), so the free tier is
/// byte-for-byte unchanged. This is what lets an operator lift OTX out of the
/// keyless 429 wall without changing any call site.
async fn otx_fetch<T: serde::de::DeserializeOwned>(
    ctx: &ModuleContext,
    url: &str,
) -> Result<Option<T>> {
    if ctx.key_opt(OTX_KEY_ENV).is_some() {
        fetch_keyed_json(ctx, SRC, url, OTX_KEY_ENV, OTX_KEY_HEADER).await
    } else {
        fetch_json_or_404(&ctx.http, SRC, url).await
    }
}

/// Whether an OTX `adversary` value is a threat actor's *name*. The field is
/// free text a pulse author types; a name is short — `APT28`, `Lazarus
/// Group`, `Mirai`, `NSO Group`, `APT28 / Fancy Bear` — and never a sentence.
/// The 2026-09-15 capture for a Tor exit carried, in one community pulse of
/// fifty, `Adversary Profile: Salt Typhoon Alignment The architectural gap
/// identified by mudoSO mirrors the act` (OTX's own 100-character cut of a
/// paragraph), which this module minted as an `Organisation` "threat actor
/// linked to" the address. A parenthesised alias (`Lazarus Group (a.k.a.
/// Hidden Cobra)`) is trimmed to the lead name by the caller.
fn is_actor_name(name: &str) -> bool {
    let n = name.trim();
    let chars = n.chars().count();
    let tokens = n.split_whitespace().count();
    (2..=48).contains(&chars)
        && (1..=5).contains(&tokens)
        && !n.contains([':', ';', '.', '!', '?'])
        && !n.ends_with(',')
}

/// The adversary the pulses name, and how many of them name it: the lead
/// name of each pulse's `adversary` (before any parenthesised alias) that
/// [`is_actor_name`] accepts, counted case-insensitively, the most-named one
/// chosen (the first seen on a tie — OTX lists pulses newest first). A
/// paragraph is never an adversary, and one pulse's free text never outranks
/// the name the rest agree on.
fn named_adversary(pulses: &[Pulse]) -> Option<(String, usize)> {
    let mut names: Vec<(String, String, usize)> = Vec::new(); // (key, display, count)
    for raw in pulses.iter().filter_map(|p| p.adversary.as_deref()) {
        let lead = raw.split('(').next().unwrap_or(raw).trim();
        if !is_actor_name(lead) {
            continue;
        }
        let key = lead.to_lowercase();
        match names.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, _, count)) => *count += 1,
            None => names.push((key, lead.to_string(), 1)),
        }
    }
    names
        .into_iter()
        .enumerate()
        .max_by(|(ia, a), (ib, b)| a.2.cmp(&b.2).then_with(|| ib.cmp(ia)))
        .map(|(_, (_, display, count))| (display, count))
}

/// An actor named by a single pulse is one author's claim; named by two or
/// more it is the corroborated rung the module always used.
fn adversary_confidence(naming_pulses: usize) -> f64 {
    if naming_pulses >= 2 {
        confidence::MEDIUM_SOLID
    } else {
        confidence::LOW_MEDIUM
    }
}

async fn run_otx(target: &Target, ctx: &ModuleContext, result: &mut ModuleResult) -> Result<()> {
    let itype = match target.kind {
        TargetKind::IpAddress => "IPv4",
        TargetKind::Domain => "domain",
        _ => return Ok(()),
    };

    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/{}/{}/general",
        itype,
        urlencode(&target.value)
    );

    // Propagate transport/parse failures (T2.111) instead of swallowing
    // them into the same `return` a clean 404 takes — `otx_fetch`
    // already maps the 404 case to `Ok(None)`, so an `Err` here means the
    // request or the JSON genuinely failed, not "no indicator on file".
    let data: Option<OtxResp> = otx_fetch(ctx, &url).await?;

    let Some(data) = data else { return Ok(()) };

    let pulse_info = match data.pulse_info {
        Some(p) => p,
        None => return Ok(()),
    };
    let pulse_count = pulse_info.count.unwrap_or(0);
    if pulse_count == 0 {
        return Ok(());
    }

    let mut entity = target.to_entity(otx_confidence(pulse_count), &ctx.scan_id);
    entity.tag(crate::core::tags::THREAT_INTEL);

    // Surface a few pulse names + the most SIGNIFICANT tags. OTX pulses dump
    // hashes, filenames, single characters and freeform notes into `tags`; the
    // old code sorted them alphabetically and kept the first 50, which surfaced
    // a noise blob (".cc", "0007", "MD5 Hash: …", "NSO Group" all jumbled). We
    // now rank by frequency across pulses (the genuinely-recurring threat
    // categories) and keep only clean, meaningful tags — see `is_meaningful_tag`.
    let pulse_names: Vec<&str> = pulse_info
        .pulses
        .iter()
        .filter_map(|p| p.name.as_deref())
        .take(5)
        .collect();
    let mut tag_freq: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for p in &pulse_info.pulses {
        for t in &p.tags {
            let t = t.trim();
            if is_meaningful_tag(t) {
                *tag_freq.entry(t).or_default() += 1;
            }
        }
    }
    let mut ranked: Vec<(&str, u32)> = tag_freq.into_iter().collect();
    // Most frequent first; alphabetical tiebreak for determinism.
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let all_tags: Vec<&str> = ranked.into_iter().take(12).map(|(t, _)| t).collect();
    let adversary = named_adversary(&pulse_info.pulses);

    let latest_tlp = pulse_info
        .pulses
        .iter()
        .find_map(|p| p.tlp.as_deref().filter(|s| !s.is_empty()));
    let earliest_created = pulse_info
        .pulses
        .iter()
        .filter_map(|p| p.created.as_deref())
        .min();

    // Tag high-level threat hints for SPA colour-coding.
    let combined_tags = all_tags.join(",").to_lowercase();
    for hint in ["malware", "ransomware", "apt", "phishing", "botnet", "c2"] {
        if combined_tags.contains(hint) {
            entity.tag(format!("ti:{hint}"));
        }
    }

    let mut ev = Evidence::new(SRC, format!("OTX: {pulse_count} threat pulse(s)"))
        .with_attr("pulse_count", pulse_count.to_string())
        .with_attr("indicator_type", itype);
    if !pulse_names.is_empty() {
        ev = ev.with_attr("recent_pulses", pulse_names.join(" | "));
    }
    if !all_tags.is_empty() {
        ev = ev.with_attr("pulse_tags", all_tags.join(", "));
    }
    if let Some((name, naming)) = &adversary {
        ev = ev
            .with_attr("adversary", name)
            .with_attr("adversary_pulses", format!("{naming} of {pulse_count}"));
    }
    if let Some(t) = latest_tlp {
        ev = ev.with_attr("tlp", t);
    }
    if let Some(c) = earliest_created {
        ev = ev.with_attr("first_pulse_created", c);
    }
    entity.add_evidence(ev);
    result.push(entity);

    // The named adversary/threat-actor (e.g. "Mirai", "NSO Group") is a
    // correlatable Organisation pivot, not just an evidence string — at a
    // rung that says how many pulses name it.
    if let Some((name, naming)) = adversary {
        let mut o = Entity::new(
            EntityKind::Organisation,
            &name,
            adversary_confidence(naming),
            &ctx.scan_id,
        );
        o.tag(crate::core::tags::THREAT_INTEL);
        o.tag("adversary");
        o.add_evidence(
            Evidence::new(
                SRC,
                format!("Threat actor linked to {} per OTX", target.value),
            )
            .with_attr("indicator", target.value.as_str())
            .with_attr("adversary_pulses", format!("{naming} of {pulse_count}")),
        );
        result.push(o);
    }

    Ok(())
}

// ── OTX passive-DNS sub-routine ────────────────────────────────────

/// Turn OTX passive-DNS rows for a **Domain** into entities. **Pure** (no I/O),
/// unit-tested. Two clean, low-noise directions only:
///
///   * distinct `address` that parses as an IP → `IpAddress` — the domain's own
///     resolving-IP history (the origin-behind-CDN / prior-hosting pivot the
///     live A record hides).
///   * distinct `hostname` that is the domain or a subdomain of it → `Domain`
///     (subdomain enumeration).
///
/// The reverse (IP → co-hosted hostnames) is deliberately NOT emitted: on a CDN
/// / shared IP it returns hundreds of unrelated tenants — exactly the
/// shared-infrastructure noise the correlator works to suppress. Each side is
/// capped so one busy domain cannot flood the expansion frontier.
fn passive_dns_entities(rows: &[PassiveDnsRow], domain: &str, scan_id: &str) -> Vec<Entity> {
    const MAX_IPS: usize = 25;
    const MAX_SUBDOMAINS: usize = 50;
    // A passively-observed subdomain hostname (a real DNS label OTX saw
    // resolve) — no existing `confidence::` rung sits at this exact value;
    // above `NOTABLE` (0.62, used for the sibling historical-IP entity below)
    // since the hostname string itself is a more durable signal than a
    // point-in-time resolved address.
    const OBSERVED_SUBDOMAIN_CONFIDENCE: f64 = 0.68;
    let base = domain.trim().to_ascii_lowercase();
    // Canonicalised once, matching how each candidate `host` below is
    // canonicalised before comparison — not the raw `base` a bare
    // `.ends_with`/equality check would use. Otherwise a passively-observed
    // "www.<base>" row is a proper subdomain of the raw base by string shape
    // alone, even though `Entity::new` strips the "www." label and collapses
    // it onto the domain's own apex uid; the wrongly-earned SUBDOMAIN tag
    // then survives onto the merged apex via `Entity::merge`'s tag-union. A
    // "www" A/CNAME record is near-universal, so this is the routine case.
    let canonical_base = crate::core::entity::normalise(&EntityKind::Domain, &base);
    let mut out = Vec::new();
    let mut seen_ips: HashSet<String> = HashSet::new();
    let mut seen_hosts: HashSet<String> = HashSet::new();

    for row in rows {
        // Scope gate FIRST: attribute a row to this domain only when its hostname
        // IS the target or a subdomain of it. A domain-scoped OTX query returns
        // only such rows, but gating defensively means a malformed/shared
        // response can never attribute an unrelated host's IP to the subject.
        let Some(host) = row
            .hostname
            .as_deref()
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| !h.is_empty())
        else {
            continue;
        };
        let canonical_host = crate::core::entity::normalise(&EntityKind::Domain, &host);
        let is_apex = canonical_host == canonical_base;
        if !is_apex
            && !crate::util::domains::is_proper_subdomain_of(&canonical_host, &canonical_base)
        {
            continue;
        }

        // Observed hostname → Domain (subdomain enumeration). Skip a hostname
        // that is itself an IP literal.
        if seen_hosts.len() < MAX_SUBDOMAINS
            && host.parse::<std::net::IpAddr>().is_err()
            && seen_hosts.insert(canonical_host.clone())
        {
            let mut d = Entity::new(
                EntityKind::Domain,
                &host,
                OBSERVED_SUBDOMAIN_CONFIDENCE,
                scan_id,
            );
            d.tag(SRC);
            d.tag("otx");
            d.tag("passive-dns");
            if !is_apex {
                d.tag(crate::core::tags::SUBDOMAIN);
            }
            d.add_evidence(
                Evidence::new(SRC, format!("OTX passive DNS: observed host for {domain}"))
                    .with_attr("source", "otx-passive-dns"),
            );
            out.push(d);
        }

        // Historical resolving IP from the SAME in-scope row.
        if seen_ips.len() < MAX_IPS
            && let Some(addr) = row
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            && addr.parse::<std::net::IpAddr>().is_ok()
            // `addr.to_string()` clones the raw `&str` — it is NOT the same
            // as `core::entity::normalise`'s parse-then-reformat, so two
            // differently-formatted spellings of the same address (e.g. an
            // expanded vs compressed IPv6 form) dedup separately despite
            // colliding on the same uid `Entity::new` constructs.
            && seen_ips.insert(crate::core::entity::normalise(&EntityKind::IpAddress, addr))
        {
            let mut e = Entity::new(EntityKind::IpAddress, addr, confidence::NOTABLE, scan_id);
            e.tag(SRC);
            e.tag("otx");
            e.tag("passive-dns");
            e.tag("historical");
            let mut ev = Evidence::new(SRC, format!("OTX passive DNS: historical IP for {domain}"))
                .with_attr("source", "otx-passive-dns");
            if let Some(rt) = row.record_type.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("record_type", rt);
            }
            if let Some(f) = row.first.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("first_seen", f);
            }
            if let Some(l) = row.last.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("last_seen", l);
            }
            e.add_evidence(ev);
            out.push(e);
        }
    }
    out
}

/// Supplementary OTX passive-DNS enumeration for a Domain target. **Best-effort**:
/// a failure — very common on the keyless tier's 429 wall — is logged and
/// swallowed, never failing the module, since the `/general` reputation pass and
/// the Tor check stand on their own. A pooled [`OTX_KEY_ENV`] key is what makes
/// this pass reliably return in a real multi-target scan.
async fn run_otx_passive_dns(target: &Target, ctx: &ModuleContext, result: &mut ModuleResult) {
    if target.kind != TargetKind::Domain {
        return;
    }
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        urlencode(&target.value)
    );
    match otx_fetch::<PassiveDnsResp>(ctx, &url).await {
        Ok(Some(resp)) => {
            for e in passive_dns_entities(&resp.passive_dns, target.value.trim(), &ctx.scan_id) {
                result.push(e);
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::debug!(
                target: "huntsman::ip_reputation",
                domain = %target.value,
                error = %e,
                "OTX passive DNS best-effort fetch failed (keyless throttling is expected)"
            );
        }
    }
}

// ── Tor exit-relay sub-routine ─────────────────────────────────────

async fn run_tor_check(
    target: &Target,
    ctx: &ModuleContext,
    result: &mut ModuleResult,
) -> Result<()> {
    let ip = target.value.trim();
    if ip.is_empty() {
        return Ok(());
    }
    // Propagates a genuine fetch failure now (T2.111) instead of the old
    // silent `None` — see `exit_set`/`fetch_exit_set`.
    let set = exit_set(&ctx.http).await?;
    if !set.contains(ip) {
        return Ok(());
    }

    let mut entity = Entity::new(
        EntityKind::IpAddress,
        ip,
        confidence::VERY_HIGH_PLUSPLUS,
        &ctx.scan_id,
    );
    entity.tag("tor-exit");
    entity.tag("anonymous-network");
    entity.add_evidence(
        Evidence::new(SRC, format!("{ip} is on the public Tor exit-relay list"))
            .with_attr("source", "check.torproject.org/exit-addresses")
            .with_attr("exit_list_size", set.len().to_string()),
    );
    result.push(entity);
    Ok(())
}

// ── Tests (merged from alienvault_otx + tor_exit_check) ────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
