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
        "Free stealer-log lookup via HudsonRock Cavalier"
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
                // HudsonRock's search-by-login validates `@` presence in the
                // raw query string BEFORE URL-decoding, so `dns%40cloudflare.com`
                // fails its check with "Email is required". Preserve the literal
                // `@` by reversing form-urlencoding's `%40` substitution.
                let encoded = urlencode(&target.value).replace("%40", "@");
                format!(
                    "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?username={encoded}"
                )
            }
            TargetKind::Domain => format!(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
                urlencode(&target.value)
            ),
            _ => return Ok(ModuleResult::new()),
        };

        let Some(data): Option<CavalierResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        if data.stealers.is_empty() {
            return Ok(ModuleResult::new());
        }

        let confidence = compute_confidence(&data.stealers);
        let mut entity = target.to_entity(confidence, &ctx.scan_id);
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

        let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        result.extend(data.stealers.iter().filter_map(|stealer| {
            let ip = stealer.ip.as_deref()?;
            if ip.is_empty() || !ip.contains('.') || !seen_ips.insert(ip.to_string()) {
                return None;
            }
            let mut e = Entity::new(
                crate::core::entity::EntityKind::IpAddress,
                ip,
                0.70,
                &ctx.scan_id,
            );
            e.tag(tags::STEALER_LOG);
            e.tag("hudsonrock");
            e.tag(crate::core::tags::GEOLOCATION_LEAD);
            e.add_evidence(Evidence::new(
                "hudsonrock",
                "Victim device IP from stealer log".to_string(),
            ));
            Some(e)
        }));

        Ok(result)
    }
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
    let year: u64 = parts.next()?.parse().ok()?;
    let month: u64 = parts.next()?.parse().ok()?;
    let day: u64 = parts.next()?.parse().ok()?;
    if year < 2000 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days_approx = (year - 1970) * 365 + (month - 1) * 30 + day;
    Some(days_approx * 86400)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
