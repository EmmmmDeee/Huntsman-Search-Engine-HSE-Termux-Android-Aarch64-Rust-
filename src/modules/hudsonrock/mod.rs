//! HudsonRock free stealer-log lookup. Public endpoint, no API key required.
//!
//! Endpoints:
//!   /api/json/v2/osint-tools/search-by-login?username=<email_or_username>
//!   `/api/json/v2/osint-tools/search-by-domain?domain=<domain>`
//!
//! Security: stealer credentials are NEVER stored in evidence — only the
//! aggregate compromise metadata (machine name, OS, date, malware family,
//! credential count). Passwords, session cookies, and raw credential
//! content are intentionally never read from the response.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "hudsonrock";

pub struct HudsonRock;

#[derive(Deserialize)]
struct CavalierResp {
    #[serde(default)]
    stealers: Vec<Stealer>,
}

#[derive(Deserialize)]
struct Stealer {
    computer_name: Option<String>,
    operating_system: Option<String>,
    date_compromised: Option<String>,
    date_uploaded: Option<String>,
    stealer_family: Option<String>,
    ip: Option<String>,
    malware_path: Option<String>,
    #[serde(default)]
    credentials: Vec<serde_json::Value>,
}

/// Base confidence for stealer-log hits. Stealer logs are high-fidelity
/// (actual malware exfiltration, not compilations), so the baseline is
/// higher than database breaches. Recent compromises get boosted further
/// by `freshness_boost`.
const BASE_CONFIDENCE: f64 = 0.85;

/// Boost confidence to this value when the compromise date is within
/// 90 days. Per Recorded Future's 2025 report, 53% of credentials are
/// indexed within one week — a recent date means the exposure is likely
/// still live.
const FRESH_CONFIDENCE: f64 = 0.92;

/// Number of days within which a compromise is considered "fresh".
const FRESHNESS_WINDOW_DAYS: u64 = 90;

#[async_trait]
impl Module for HudsonRock {
    fn name(&self) -> &'static str {
        "hudsonrock"
    }

    fn description(&self) -> &'static str {
        "HudsonRock Cavalier recon (free) — sweeps stealer-log corpora for a target's infostealer exposure"
    }

    fn priority(&self) -> u8 {
        130
    }

    fn accepts(&self, t: &Target) -> bool {
        // `search-by-login` validates its login as an email — a bare handle
        // 400s with "Email is required" (observed live on a `javery88`
        // username scan) — and `search-by-domain` takes a domain. So the
        // honest input set is Email + Domain only. A Username seed is never
        // routed here: the engine surfaces discovered emails as Email targets,
        // which this module already consumes. Keeping `accepts()`
        // value-INDEPENDENT is also what lets the dispatch index (built from
        // `consumes()`) and `accepts()` agree for every probe value — a
        // value-shape gate here diverged the two registry invariants.
        matches!(t.kind, TargetKind::Email | TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        // Stealer-log / infostealer intelligence — a breach-corpus source, not
        // network infrastructure. The `Breach` category is documented as
        // "breach corpora, paste exposure, stealer logs, leaked credentials",
        // and the correlator already lists hudsonrock among its breach sources
        // (rules/breach.rs), so this aligns the catalogue label with how the
        // rest of the engine treats it.
        ModuleCategory::Breach
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Breach default (T1589.001 Credentials + T1589.002 Email Addresses).
        // Stealer logs also capture the victim device's IP address, which
        // HudsonRock surfaces as an IpAddress entity → T1590.005 IP Addresses,
        // missing from the Breach category default.
        &["T1589.001", "T1589.002", "T1590.005"]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        // Primary entity enriches the seed; discovered stealer-origin IPs
        // become IpAddress pivots (exposed_machine_ip from the stealer log).
        const KINDS: &[EntityKind] =
            &[EntityKind::Email, EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = match target.kind {
            // `search-by-login` requires an email-shaped login (a bare handle
            // 400s with "Email is required"). `accepts()` only admits Email and
            // Domain, but a direct `process()` call (tests, future callers) with
            // any other kind falls through to an empty result rather than firing
            // the doomed request.
            TargetKind::Email => {
                // Defensive guard: skip values that lack `@` (should be
                // unreachable via the engine, but blocks the 400 if any entity
                // mislabelled as Email reaches process() directly).
                if !target.value.contains('@') {
                    return Ok(ModuleResult::new());
                }
                search_by_login_url(&target.value)
            }
            TargetKind::Domain => {
                // A reverse-DNS Android/iOS app package (`com.facebook.katana`)
                // is not a web domain: `search-by-domain` for it returns other
                // app users' stealer records (strangers), not the subject's. Such
                // a value can still reach process() by recall of a Domain minted
                // before the upstream gate existed, so skip the doomed query here.
                if crate::util::domains::is_app_package_id(&target.value) {
                    return Ok(ModuleResult::new());
                }
                format!(
                    "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
                    urlencode(&target.value)
                )
            }
            _ => return Ok(ModuleResult::new()),
        };

        let Some(data): Option<CavalierResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        Ok(build_result(target, &data, &ctx.scan_id))
    }
}

/// Build the deduplicated victim-device IP pivots from a stealer list. **Pure**
/// (no network/IO).
///
/// No-fabrication gate. Every emitted IP is tagged [`crate::core::tags::GEOLOCATION_LEAD`]
/// and fed to the GEOINT fusion, so it MUST be a routable public address. A
/// stealer log's `ip` field routinely carries the victim's LAN address (RFC1918
/// `10.x`/`192.168.x`, loopback, link-local, CGNAT `100.64.x`) or a non-IP
/// string — the prior `!ip.contains('.')` check admitted all of these (any
/// dotted string passed, and every IPv6 address was wrongly rejected).
/// Geolocating a private/reserved IP fabricates a position that maps nowhere, so
/// [`crate::util::preflight::is_public_ip`] now gates each candidate: it parses
/// the value as an `IpAddr` (v4 **and** v6) and rejects the private/reserved
/// ranges, mirroring the same gate `dehashed` applies to breach-record IPs.
fn victim_ip_entities(stealers: &[Stealer], scan_id: &str) -> Vec<Entity> {
    let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    stealers
        .iter()
        .filter_map(|stealer| {
            let ip = stealer.ip.as_deref()?.trim();
            if !crate::util::preflight::is_public_ip(ip) || !seen_ips.insert(ip.to_string()) {
                return None;
            }
            let mut e = Entity::new(
                crate::core::entity::EntityKind::IpAddress,
                ip,
                0.70,
                scan_id,
            );
            e.tag(tags::STEALER_LOG);
            e.tag("hudsonrock");
            e.tag(crate::core::tags::GEOLOCATION_LEAD);
            e.add_evidence(Evidence::new(
                "hudsonrock",
                "Victim device IP from stealer log".to_string(),
            ));
            Some(e)
        })
        .collect()
}

/// Build the Cavalier `search-by-login` URL for `email`.
///
/// The endpoint is keyed by the **`email`** query parameter. It was previously
/// `username`, and the upstream drift silently broke every login lookup: a
/// `username=…` request now returns HTTP 400 `{"error":"Email is required"}`
/// regardless of the value. Live end-to-end testing (a real email seed) caught
/// this. The `email=` endpoint URL-decodes normally, so a standard form-encoded
/// value works (no `%40`→`@` dance is needed, unlike the old `username=` path).
fn search_by_login_url(email: &str) -> String {
    format!(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?email={}",
        urlencode(email)
    )
}

/// Build the module's entities from an already-fetched Cavalier response.
///
/// Split out of [`HudsonRock::process`] as a pure, HTTP-free seam so the
/// entity/evidence shape — in particular the canonical `breach_date` stamping
/// AU-019's temporal breach-cluster rule (`rules/breach.rs`) depends on — is
/// unit-testable without a live endpoint.
fn build_result(target: &Target, data: &CavalierResp, scan_id: &str) -> ModuleResult {
    if data.stealers.is_empty() {
        return ModuleResult::new();
    }

    let confidence = compute_confidence(&data.stealers);
    let mut entity = target.to_entity(confidence, scan_id);
    entity.tag(tags::BREACH);
    entity.tag(tags::STEALER_LOG);

    let seen_families: std::collections::BTreeSet<&str> = data
        .stealers
        .iter()
        .filter_map(|s| s.stealer_family.as_deref())
        .collect();
    let seen_hosts: std::collections::BTreeSet<&str> = data
        .stealers
        .iter()
        .filter_map(|s| s.computer_name.as_deref())
        .collect();

    data.stealers.iter().for_each(|stealer| {
        let cred_count = stealer.credentials.len();
        let family = stealer.stealer_family.as_deref().unwrap_or("-");
        let ev = [
            ("date_uploaded", stealer.date_uploaded.as_deref()),
            ("victim_ip", stealer.ip.as_deref()),
            // The compromise date IS the breach/exposure event (date_uploaded is
            // merely when the log was indexed), so stamp it under the canonical
            // `breach_date` key AU-019 reads — the entity is `breach`-tagged, and
            // without this its stealer-log dates could never date-cluster with
            // other breach sources. Only stamped when present (this optional
            // array skips `None`), so AU-019 never parses the "-" placeholder the
            // separate `date_compromised` attribute below carries.
            ("breach_date", stealer.date_compromised.as_deref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(
                SRC,
                format!("Stealer log: {cred_count} credentials on compromised machine"),
            )
            .with_attr(
                "computer_name",
                stealer.computer_name.as_deref().unwrap_or("-"),
            )
            .with_attr(
                "operating_system",
                stealer.operating_system.as_deref().unwrap_or("-"),
            )
            .with_attr(
                "date_compromised",
                stealer.date_compromised.as_deref().unwrap_or("-"),
            )
            .with_attr("stealer_family", family)
            .with_attr(
                "malware_path",
                stealer.malware_path.as_deref().unwrap_or("-"),
            )
            .with_attr("credential_count", cred_count.to_string()),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        entity.add_evidence(ev);
    });

    seen_families
        .iter()
        .for_each(|family| entity.tag(format!("stealer:{}", family.to_lowercase())));
    if seen_hosts.len() >= 2 {
        entity.tag(tags::MULTI_DEVICE);
    }
    entity.tag(format!("stealer-count:{}", data.stealers.len()));

    let mut result = ModuleResult::new();
    result.push(entity);
    result.extend(victim_ip_entities(&data.stealers, scan_id));

    result
}

fn compute_confidence(stealers: &[Stealer]) -> f64 {
    let now_secs = crate::core::entity::unix_now();
    let cutoff = now_secs.saturating_sub(FRESHNESS_WINDOW_DAYS * 86400);

    let has_recent = stealers.iter().any(|s| {
        s.date_compromised
            .as_deref()
            .and_then(parse_iso_epoch)
            .is_some_and(|ts| ts >= cutoff)
    });

    if has_recent {
        FRESH_CONFIDENCE
    } else {
        BASE_CONFIDENCE
    }
}

fn parse_iso_epoch(s: &str) -> Option<u64> {
    let date_part = s.split('T').next()?;
    let mut parts = date_part.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if year < 2000 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Exact day count (Howard Hinnant via core::timeline) — the previous
    // `(year-1970)*365 + (month-1)*30 + day` approximation ignored leap days and
    // assumed 30-day months, under-counting by ~2 weeks for recent dates. Since
    // compute_confidence compares this against a *real* unix-epoch cutoff, that
    // skew mis-classified records near the 90-day freshness boundary.
    let days = crate::core::timeline::days_from_civil(year, month, day);
    u64::try_from(days).ok().map(|d| d * 86400)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
