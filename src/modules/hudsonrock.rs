//! HudsonRock free stealer-log lookup. Public endpoint, no API key required.
//!
//! Endpoints:
//!   /api/json/v2/osint-tools/search-by-login?username=<email_or_username>
//!   /api/json/v2/osint-tools/search-by-domain?domain=<domain>
//!
//! Output: the subject entity (Email/Domain) is tagged + enriched with the
//! aggregate compromise metadata; victim device IPs and the victim's
//! compromised-**service** domains (the hosts they had saved credentials for —
//! their digital footprint) are surfaced as pivot entities so a stealer-log hit
//! recursively expands ("every node becomes a new origin").
//!
//! Security: stealer **credentials** are NEVER read or stored — the `Credential`
//! struct deliberately declares only the service locator (URL/host), so serde
//! drops the username/password/cookie fields entirely. Only the public service
//! host (e.g. `paypal.com`) is surfaced — that is the victim's footprint, not a
//! secret — alongside the aggregate metadata (machine name, OS, date, malware
//! family, credential count).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
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
    credentials: Vec<Credential>,
}

/// One credential record inside a stealer log.
///
/// **Security**: only the *service locator* (the URL/host the credential was
/// for) is declared, so serde drops the `username`/`password` (and any other)
/// fields entirely — they are never read, parsed, or stored. The host of a
/// service the victim had a saved credential for is their digital footprint
/// (public infrastructure), not a secret, and is the single richest pivot a
/// stealer log offers: "this victim used these services".
#[derive(Deserialize, Default)]
#[serde(default)]
struct Credential {
    #[serde(alias = "URL", alias = "Url")]
    url: Option<String>,
    #[serde(alias = "Domain", alias = "host", alias = "hostname")]
    domain: Option<String>,
}

impl Credential {
    /// The normalised host of the service this credential was for, if it can be
    /// resolved to a real domain. Lowercased, `www.`-stripped; bare IPs, app
    /// pseudo-hosts (`android://…`), and hostless junk are rejected.
    fn locator_host(&self) -> Option<String> {
        let raw = self.url.as_deref().or(self.domain.as_deref())?.trim();
        if raw.is_empty() {
            return None;
        }
        // A scheme'd value is a pivotable web host only when the scheme is
        // http(s). App deep-links (`android://`, `ios://`, `chrome-extension://`,
        // …) have no DNS host. Match the SCHEME, not a substring of the value —
        // `starts_with("android")` wrongly dropped bare domains like
        // `android.com` / `androidpolice.com`, and was case-sensitive so an
        // `Android://` pseudo-host slipped through.
        let host = if let Some((scheme, _)) = raw.split_once("://") {
            if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                return None;
            }
            url::Url::parse(raw).ok()?.host_str()?.to_string()
        } else {
            raw.split('/').next().unwrap_or(raw).to_string()
        };
        let mut host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(stripped) = host.strip_prefix("www.") {
            host = stripped.to_string();
        }
        // Must look like a domain, and never an app pseudo-host or a bare IP
        // (those are not pivotable Domain entities).
        if host.is_empty()
            || !host.contains('.')
            || host.contains('@')
            || host.parse::<std::net::IpAddr>().is_ok()
        {
            return None;
        }
        Some(host)
    }
}

/// Upper bound on distinct service domains surfaced per stealer-log hit. A
/// heavily-infected machine can carry hundreds of saved credentials; capping
/// keeps the graph (and a low-power Termux device) bounded while still
/// surfacing the victim's most significant service footprint.
const MAX_SERVICE_DOMAINS: usize = 40;

/// Distinct, normalised service domains the victim had saved credentials for,
/// across all stealer logs — the victim's compromised-service footprint.
/// Pure (no I/O), deduplicated, deterministic order, capped at
/// [`MAX_SERVICE_DOMAINS`]. Reads only the service host, never credentials.
fn service_domains(stealers: &[Stealer]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for s in stealers {
        for c in &s.credentials {
            let Some(host) = c.locator_host() else {
                continue;
            };
            if seen.insert(host.clone()) {
                out.push(host);
                if out.len() >= MAX_SERVICE_DOMAINS {
                    return out;
                }
            }
        }
    }
    out
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
        // 400s with "Email is required" (observed live on a `mdieg123`
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
        ModuleCategory::Infrastructure
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Victim device IPs and the victim's compromised-service domains — the
        // pivots that let a stealer-log hit expand into IP-geo / DNS / WHOIS
        // recursion. (The subject Email/Domain is enriched in place, not
        // "produced".) Declaring these wires the new fan-out into the
        // dependency-graph pivot chain.
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
        KINDS
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

        // The victim's compromised-service footprint: the distinct service
        // domains they had saved credentials for. The single richest pivot a
        // stealer log offers ("every node becomes a new origin") — surfaced as
        // an aggregate on the subject entity AND as Domain pivots below.
        let services = service_domains(&data.stealers);
        if !services.is_empty() {
            let sample: Vec<&str> = services.iter().take(10).map(String::as_str).collect();
            entity.add_evidence(
                Evidence::new(SRC, "Compromised-service footprint from stealer log")
                    .with_attr("distinct_service_domains", services.len().to_string())
                    .with_attr("services_sample", sample.join(", ")),
            );
            entity.tag(format!("services:{}", services.len()));
        }

        let mut result = ModuleResult::new();
        result.push(entity);

        let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for stealer in &data.stealers {
            if let Some(ip) = stealer.ip.as_deref()
                && !ip.is_empty()
                && ip.contains('.')
                && seen_ips.insert(ip.to_string())
            {
                let mut e = Entity::new(EntityKind::IpAddress, ip, 0.70, &ctx.scan_id);
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

        // Emit the victim's compromised-service domains as Domain *leads*. The
        // victim merely had an account on these third-party services, so they
        // are context, NOT targets to recurse into (expanding paypal.com pulls
        // in PayPal's infrastructure — scope blow-out + false attribution).
        // Confidence 0.35 sits below every expansion floor (default 0.50, the
        // auto band's 0.40–0.55, and `--recursive`'s 0.40), so they enrich the
        // graph + correlator without auto-spending expansion budget — matching
        // name_intel's candidate-pivot policy (an operator who *wants* to pivot
        // lowers `--min-expand-confidence`). Only the public host is ever
        // surfaced — never the credential.
        for dom in &services {
            let mut e = Entity::new(EntityKind::Domain, dom, 0.35, &ctx.scan_id);
            e.tag(tags::BREACH);
            e.tag(tags::STEALER_LOG);
            e.tag("compromised-service");
            e.tag("hudsonrock");
            e.add_evidence(Evidence::new(
                SRC,
                "Service domain from a stealer-log credential record (victim had a saved \
                 credential here; the credential itself is never read)",
            ));
            result.push(e);
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
        // required") on a bare handle (seen live on the `mdieg123` scan), and
        // the engine surfaces real emails as Email targets. Reject both a bare
        // handle AND an email-shaped one so `accepts()` stays value-independent
        // (the property the two registry-dispatch invariants rely on).
        assert!(!m.accepts(&Target::new(TargetKind::Username, "mdieg123")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "mdieg123@gmail.com")));
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
            .process(&Target::new(TargetKind::Username, "mdieg123"), &ctx)
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

    // ── compromised-service footprint (credential → service-domain pivots) ──

    fn cred(url: Option<&str>, domain: Option<&str>) -> Credential {
        Credential {
            url: url.map(str::to_string),
            domain: domain.map(str::to_string),
        }
    }

    fn stealer_with(credentials: Vec<Credential>) -> Stealer {
        Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: None,
            date_uploaded: None,
            stealer_family: None,
            ip: None,
            malware_path: None,
            credentials,
        }
    }

    #[test]
    fn locator_host_extracts_and_normalises() {
        // Full URL → host, lowercased, www-stripped.
        assert_eq!(
            cred(Some("https://www.PayPal.com/login"), None)
                .locator_host()
                .as_deref(),
            Some("paypal.com")
        );
        // Subdomains are preserved (a distinct service surface).
        assert_eq!(
            cred(Some("https://accounts.google.com/signin"), None)
                .locator_host()
                .as_deref(),
            Some("accounts.google.com")
        );
        // Bare domain field, and "domain/path" without a scheme.
        assert_eq!(
            cred(None, Some("Coinbase.com")).locator_host().as_deref(),
            Some("coinbase.com")
        );
        assert_eq!(
            cred(Some("vpn.company.com/path"), None)
                .locator_host()
                .as_deref(),
            Some("vpn.company.com")
        );
    }

    #[test]
    fn locator_host_rejects_non_pivotable() {
        // App pseudo-hosts, bare IPs, hostless junk, and empties never become
        // Domain pivots.
        assert!(
            cred(Some("android://aGVsbG8=@com.spotify.music/"), None)
                .locator_host()
                .is_none()
        );
        assert!(
            cred(Some("http://192.168.1.1/"), None)
                .locator_host()
                .is_none()
        );
        assert!(cred(Some("localhost"), None).locator_host().is_none());
        assert!(cred(Some(""), None).locator_host().is_none());
        assert!(cred(None, None).locator_host().is_none());
    }

    #[test]
    fn locator_host_keeps_android_prefixed_domains_but_drops_app_scheme() {
        // Regression: the guard must match the `android://` SCHEME, not the
        // substring "android" — bare domains that merely start with "android"
        // are legitimate pivots and must survive.
        assert_eq!(
            cred(None, Some("android.com")).locator_host().as_deref(),
            Some("android.com")
        );
        assert_eq!(
            cred(Some("https://androidpolice.com/news"), None)
                .locator_host()
                .as_deref(),
            Some("androidpolice.com")
        );
        // The app pseudo-scheme is still dropped — case-insensitively now.
        assert!(
            cred(Some("android://h@com.app/"), None)
                .locator_host()
                .is_none()
        );
        assert!(
            cred(Some("ANDROID://h@com.app/"), None)
                .locator_host()
                .is_none()
        );
        // Other non-web deep-link schemes are dropped too.
        assert!(
            cred(Some("ios://x@com.app/"), None)
                .locator_host()
                .is_none()
        );
    }

    #[test]
    fn service_domains_dedupe_and_order() {
        // Dedup is global across stealers; first-seen order is preserved; a
        // www/non-www pair collapses to one.
        let s1 = stealer_with(vec![
            cred(Some("https://paypal.com/"), None),
            cred(Some("https://github.com/login"), None),
        ]);
        let s2 = stealer_with(vec![
            cred(Some("https://www.paypal.com/account"), None),
            cred(None, Some("coinbase.com")),
        ]);
        assert_eq!(
            service_domains(&[s1, s2]),
            vec![
                "paypal.com".to_string(),
                "github.com".to_string(),
                "coinbase.com".to_string()
            ]
        );
    }

    #[test]
    fn service_domains_never_reads_credentials_and_caps() {
        // A heavily-infected machine is capped, and only hosts are ever read —
        // there is no field through which a username/password could surface
        // (the Credential struct declares only url/domain).
        let creds: Vec<Credential> = (0..100)
            .map(|i| cred(Some(&format!("https://svc{i}.example{i}.com/login")), None))
            .collect();
        let doms = service_domains(&[stealer_with(creds)]);
        assert_eq!(doms.len(), MAX_SERVICE_DOMAINS);
    }
}
