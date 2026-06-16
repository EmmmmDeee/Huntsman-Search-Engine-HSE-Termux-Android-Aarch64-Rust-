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
            TargetKind::Email => format!(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?username={}",
                urlencode(&target.value)
            ),
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

        let mut seen_families: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut seen_hosts: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();

        for stealer in &data.stealers {
            let cred_count = stealer.credentials.len();
            let family = stealer.stealer_family.as_deref().unwrap_or("-");

            if let Some(f) = stealer.stealer_family.as_deref() {
                seen_families.insert(f);
            }
            if let Some(h) = stealer.computer_name.as_deref() {
                seen_hosts.insert(h);
            }

            let mut ev = Evidence::new(
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
            .with_attr("credential_count", cred_count.to_string());
            if let Some(uploaded) = stealer.date_uploaded.as_deref() {
                ev = ev.with_attr("date_uploaded", uploaded);
            }
            if let Some(ip) = stealer.ip.as_deref() {
                ev = ev.with_attr("victim_ip", ip);
            }
            entity.add_evidence(ev);
        }

        for family in &seen_families {
            entity.tag(format!("stealer:{}", family.to_lowercase()));
        }
        if seen_hosts.len() >= 2 {
            entity.tag(tags::MULTI_DEVICE);
        }
        entity.tag(format!("stealer-count:{}", data.stealers.len()));

        let mut result = ModuleResult::new();
        result.push(entity);

        let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for stealer in &data.stealers {
            if let Some(ip) = stealer.ip.as_deref()
                && !ip.is_empty()
                && ip.contains('.')
                && seen_ips.insert(ip.to_string())
            {
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
                result.push(e);
            }
        }

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
    use super::*;

    #[test]
    fn accepts_only_email_and_domain() {
        let m = HudsonRock;
        assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "b.com")));
        // Usernames are NEVER routed here — search-by-login 400s ("Email is
        // required") on a bare handle (seen live on the `javery88` scan), and
        // the engine surfaces real emails as Email targets. Reject both a bare
        // handle AND an email-shaped one so `accepts()` stays value-independent
        // (the property the two registry-dispatch invariants rely on).
        assert!(!m.accepts(&Target::new(TargetKind::Username, "javery88")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "javery88@gmail.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[tokio::test]
    async fn username_target_yields_nothing_without_a_request() {
        // A Username never reaches process() via the engine (accepts() rejects
        // it); a direct call still falls through to empty — no doomed 400.
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        };
        let r = HudsonRock
            .process(&Target::new(TargetKind::Username, "javery88"), &ctx)
            .await
            .unwrap();
        assert!(
            r.is_empty(),
            "username must not call the email-only endpoint"
        );
    }

    #[test]
    fn fresh_compromise_gets_higher_confidence() {
        let recent = Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: Some("2026-05-01T00:00:00Z".into()),
            date_uploaded: None,
            stealer_family: Some("Lumma".into()),
            ip: None,
            malware_path: None,
            credentials: vec![],
        };
        assert!((compute_confidence(&[recent]) - FRESH_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn old_compromise_gets_base_confidence() {
        let old = Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: Some("2020-01-01T00:00:00Z".into()),
            date_uploaded: None,
            stealer_family: None,
            ip: None,
            malware_path: None,
            credentials: vec![],
        };
        assert!((compute_confidence(&[old]) - BASE_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn parse_iso_epoch_works() {
        assert!(parse_iso_epoch("2025-06-15T12:00:00Z").is_some());
        assert!(parse_iso_epoch("2025-06-15").is_some());
        assert!(parse_iso_epoch("garbage").is_none());
        assert!(parse_iso_epoch("").is_none());
    }
}
