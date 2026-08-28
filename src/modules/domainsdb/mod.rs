//! domainsdb.info — domain registration search (keyed).
//!
//! Endpoint: `GET https://api.domainsdb.info/v1/domains/search?domain={query}&zone={tld}&limit=20`
//! Auth:     `Authorization: Bearer <HUNTSMAN_DOMAINSDB_KEY>`.
//!
//! Searches registered domains matching a keyword — useful for finding
//! related/typosquatting domains from an Organisation or FullName target.
//!
//! **Key-gated (2026):** the provider disabled anonymous access — a keyless
//! request now returns `401 {"error":"API key required","message":"Anonymous
//! access is disabled. Please sign in to obtain an API key…"}` (live-confirmed
//! against real keyword/zone queries). The module was previously registered
//! Free and, once anonymous access was cut, silently returned nothing on every
//! scan: each 401 failed the success check and was swallowed by the loop's
//! `continue`, so the operator was never told the source had stopped working.
//! It is now [`ModuleCost::KeyGated`]: an unconfigured key yields a clean
//! "needs key" skip (via `ctx.key`'s `Error::MissingKey`), and a configured
//! key is sent as a Bearer token; a `401`/`403` on a configured key is
//! reported to the key pool for rotation instead of being silently dropped.
//!
//! Both response fields are used: `update_date` is surfaced (a recently-updated
//! look-alike domain is a live-threat signal), and the per-zone `total` gates a
//! `broad-match` dampening — a keyword that matches hundreds of domains in one
//! TLD is generic, so those hits are weakly related to the target and their
//! confidence is reduced. The per-entry mapping lives in the pure
//! [`build_domain_entity`] so it is unit-tested without a live API.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

/// Env var holding the operator's domainsdb.info API key. Registered in
/// `util::keys::KNOWN_KEYS` with a signup hint so an unconfigured scan tells
/// the operator where to obtain one.
const KEY_ENV: &str = "HUNTSMAN_DOMAINSDB_KEY";

const SRC: &str = "domainsdb";

/// A keyword matching more than this many domains in a single TLD is generic;
/// its hits are keyword coincidences, not target-specific, so they are tagged
/// `broad-match` and down-weighted.
const BROAD_MATCH_THRESHOLD: u64 = 200;

#[derive(Deserialize)]
struct DbResp {
    #[serde(default)]
    domains: Vec<DomainEntry>,
    #[serde(default)]
    total: Option<u64>,
}

#[derive(Deserialize)]
struct DomainEntry {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    create_date: Option<String>,
    #[serde(default)]
    update_date: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default, rename = "isDead")]
    is_dead: Option<String>,
}

use crate::util::str_util::nonempty;

/// Map one registered-domain record to a `Domain` entity. **Pure** (no
/// network/IO). `broad_match` (from the zone's `total` exceeding
/// [`BROAD_MATCH_THRESHOLD`]) flags + dampens generic keyword coincidences.
/// Returns `None` for a blank domain.
fn build_domain_entity(entry: &DomainEntry, broad_match: bool, scan_id: &str) -> Option<Entity> {
    let domain = entry.domain.trim();
    if domain.is_empty() {
        return None;
    }
    let is_dead = entry.is_dead.as_deref() == Some("True");
    // Live domain confidence::MEDIUM_HIGH, dead 0.35; a broad keyword match is weakly related to
    // the target, so dampen it (0.7×).
    let mut conf = if is_dead {
        0.35
    } else {
        confidence::MEDIUM_HIGH
    };
    if broad_match {
        conf *= 0.7;
    }

    let mut e = Entity::new(EntityKind::Domain, domain, conf, scan_id);
    e.tag("domainsdb");
    if is_dead {
        e.tag("dead-domain");
    }
    if broad_match {
        e.tag("broad-match");
    }
    let mut ev = Evidence::new(SRC, format!("Registered domain: {domain}"));
    if let Some(d) = nonempty(&entry.create_date) {
        ev = ev.with_attr("created", d);
    }
    if let Some(d) = nonempty(&entry.update_date) {
        ev = ev.with_attr("updated", d);
    }
    if let Some(c) = nonempty(&entry.country) {
        ev = ev.with_attr("country", c);
    }
    e.add_evidence(ev);
    Some(e)
}

pub struct DomainsDb;

#[async_trait]
impl Module for DomainsDb {
    fn name(&self) -> &'static str {
        "domainsdb"
    }
    fn description(&self) -> &'static str {
        "Domain-registration recon via domainsdb.info — sweeps registered domains for infrastructure pivots (free, no key)"
    }
    fn priority(&self) -> u8 {
        19
    }
    /// Key-gated since the provider disabled anonymous access (2026). Was
    /// `Free`; leaving it Free meant every keyless request 401'd and was
    /// silently dropped, so the source vanished without a word to the operator.
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Organisation | TargetKind::FullName
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Domain/passive-DNS database — ATT&CK DNS/Passive DNS (T1596.001).
        &["T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Key-gated: an unconfigured key returns `Error::MissingKey`, which the
        // dispatch finaliser turns into a clean "needs key" skip (with the
        // signup hint) — NOT a silent zero-yield. This is the honest state the
        // module lacked while it was still classified Free against an endpoint
        // that had already disabled anonymous access.
        let key = ctx.key(KEY_ENV)?;

        let query = match target.kind {
            TargetKind::Domain => {
                let base = target
                    .value
                    .trim()
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .to_lowercase();
                if base.len() < 3 {
                    return Ok(ModuleResult::new());
                }
                base
            }
            TargetKind::Organisation | TargetKind::FullName => {
                let cleaned: String = target
                    .value
                    .to_lowercase()
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == ' ')
                    .collect();
                let parts: Vec<&str> = cleaned.split_whitespace().collect();
                if parts.is_empty() {
                    return Ok(ModuleResult::new());
                }
                parts.join("")
            }
            _ => return Ok(ModuleResult::new()),
        };

        // `report_key_exhausted` needs the context, so `collect_zones` records
        // the rejecting status instead of touching the pool itself — that keeps
        // it free of `ModuleContext` (and therefore of the pool's `$HOME` write)
        // so the rejected-key contract below is testable against a loopback
        // listener. The key is still reported on BOTH the error and the
        // partial-success path, so rotation happens either way.
        let mut auth_rejected = None;
        let out = collect_zones(
            &ctx.http,
            BASE_URL,
            key,
            &query,
            &ctx.scan_id,
            &ctx.cancel,
            &mut auth_rejected,
        )
        .await;
        if let Some(status) = auth_rejected {
            ctx.report_key_exhausted(SRC, key, status);
        }
        out
    }
}

/// Endpoint the zone sweep queries. Parameterised at [`collect_zones`] rather
/// than inlined so the rejected-key path can be driven from a loopback test.
pub(super) const BASE_URL: &str = "https://api.domainsdb.info/v1/domains/search";

/// Env-free core of [`DomainsDb::process`]: query every zone against `base`.
///
/// On a 401/403 the rejecting status is written to `auth_rejected` (the caller
/// owns the pool report — this fn does no pool IO) and the sweep stops, since
/// the same key earns the same rejection from every remaining zone.
///
/// If nothing at all was collected, that rejection is returned as an `Err`
/// rather than an empty `Ok`. A dead key must never be indistinguishable from
/// "this subject has no look-alike domains" — the invariant
/// [`ModuleResult::or_hard_failure`] exists to enforce, and which the sibling
/// keyed modules in this house style (`hunter_io`, `whoisxml`) already honour.
/// Because `or_hard_failure` only errors when the result is empty, findings
/// collected from earlier zones are never discarded by a later zone's rejection.
async fn collect_zones(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    query: &str,
    scan_id: &str,
    cancel: &crate::core::cancel::CancelHandle,
    auth_rejected: &mut Option<u16>,
) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();
    let mut seen: HashSet<String> = HashSet::new();

    for zone in &["com", "net", "org", "io", "com.au", "co.uk"] {
        if cancel.is_cancelled() {
            break;
        }
        let url = format!(
            "{base}?domain={}&zone={zone}&limit=20",
            crate::util::http::urlencode(query)
        );
        let resp = http
            .get(&url)
            .header("Authorization", format!("Bearer {key}"))
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await;
        let Ok(r) = resp else { continue };
        let status = r.status().as_u16();
        // An auth failure on a configured key is retry-futile for every
        // remaining zone (same key, same rejection), and it must not be
        // swallowed the way the pre-fix loop swallowed the anonymous 401:
        // record it so the caller reports the key to the pool (a later scan
        // rotates to another), then stop — the surfaced error is the operator's
        // signal that the configured domainsdb key is bad/expired, not that the
        // subject has no look-alike domains.
        if status == 401 || status == 403 {
            *auth_rejected = Some(status);
            break;
        }
        if !r.status().is_success() {
            continue;
        }
        let Ok(data) = crate::util::http::json_scanned::<DbResp>(r, SRC).await else {
            continue;
        };

        let broad_match = data.total.is_some_and(|t| t > BROAD_MATCH_THRESHOLD);
        result.extend(data.domains.iter().filter_map(|entry| {
            if !seen.insert(entry.domain.trim().to_lowercase()) {
                return None;
            }
            build_domain_entity(entry, broad_match, scan_id)
        }));
    }

    result.or_hard_failure(auth_rejected.map(|s| {
        crate::core::error::Error::module(
            SRC,
            format!("HTTP {s} — the configured domainsdb key was rejected"),
        )
    }))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
