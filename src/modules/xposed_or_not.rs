//! XposedOrNot breach lookup — free public email-to-breach-list service.
//!
//! Endpoint: `https://api.xposedornot.com/v1/check-email/<email>`.
//! Returns the list of named breaches the email appears in (company names
//! like "MyFitnessPal", "Quizlet", etc.) — **not credentials**. Confirms
//! breach exposure without ever transmitting a password through our process.
//!
//! Breach analytics: when the check-email endpoint returns hits, the module
//! also calls `/v1/breach-analytics` to enrich with risk metrics, exposed
//! data types, and paste exposure counts. This second call is best-effort —
//! if it fails the basic breach list is still returned.
//!
//! Why a second breach source matters: the `AU-001` correlator rule
//! (multi-source breach corroboration, severity Critical) was wired up
//! in v0.4 but had been dormant — only `hudsonrock` was registered as a
//! breach source. With this module, the rule activates whenever
//! HudsonRock and XposedOrNot both flag the same email, so
//! `hse scan --kind email --value <breached>` can surface a Critical
//! correlation without any paid keys.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

pub struct XposedOrNot;

/// XposedOrNot's response shape. Successful lookups return one of:
///   { "breaches": [["MyFitnessPal", "Quizlet", ...]] }  — exposed
///   { "Error": "Not found" }                            — clean
#[derive(Deserialize, Default)]
#[serde(default)]
struct XonResp {
    breaches: Option<Vec<Vec<String>>>,
}

/// Breach analytics response (`/v1/breach-analytics?email=`).
#[derive(Deserialize, Default)]
#[serde(default)]
struct AnalyticsResp {
    #[serde(alias = "ExposedBreaches")]
    exposed_breaches: Option<AnalyticsBreaches>,
    #[serde(alias = "PastesSummary")]
    pastes_summary: Option<PastesSummary>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AnalyticsBreaches {
    #[serde(alias = "breaches_details")]
    breaches_details: Option<Vec<BreachDetail>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BreachDetail {
    breach: Option<String>,
    #[serde(alias = "xposed_data")]
    xposed_data: Option<String>,
    #[serde(alias = "xposed_records")]
    xposed_records: Option<u64>,
    #[serde(alias = "xposure_desc")]
    xposure_desc: Option<String>,
    #[serde(alias = "password_risk")]
    password_risk: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PastesSummary {
    cnt: Option<u64>,
}

/// High-profile breach names that warrant individual tagging.
const NOTABLE_BREACHES: &[&str] = &[
    "linkedin", "adobe", "dropbox", "myspace", "twitter", "facebook",
    "yahoo", "lastfm", "tumblr", "myfitnesspal", "canva", "zynga",
    "dubsmash", "haveibeenpwned", "verifications.io", "collection",
    "exactis", "apollo", "evite",
];

#[async_trait]
impl Module for XposedOrNot {
    fn name(&self) -> &'static str {
        "xposed_or_not"
    }

    fn priority(&self) -> u8 {
        128
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!(
            "https://api.xposedornot.com/v1/check-email/{}",
            urlencode(&target.value)
        );

        let Some(data): Option<XonResp> =
            fetch_json_or_404(&ctx.http, "xposed_or_not", &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        let inner = match data.breaches.as_ref().and_then(|outer| outer.first()) {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(ModuleResult::new()),
        };

        let analytics = fetch_analytics(&ctx.http, &target.value).await;

        Ok(build_result(inner, analytics.as_ref(), target, &ctx.scan_id))
    }
}

async fn fetch_analytics(http: &reqwest::Client, email: &str) -> Option<AnalyticsResp> {
    let url = format!(
        "https://api.xposedornot.com/v1/breach-analytics?email={}",
        urlencode(email)
    );
    fetch_json_or_404::<AnalyticsResp>(http, "xposed_or_not", &url)
        .await
        .ok()
        .flatten()
}

fn build_result(
    breaches: &[String],
    analytics: Option<&AnalyticsResp>,
    target: &Target,
    scan_id: &str,
) -> ModuleResult {
    let count = breaches.len();
    if count == 0 {
        return ModuleResult::new();
    }
    let confidence = confidence_for_count(count);

    let mut entity = Entity::new(EntityKind::Email, &target.value, confidence, scan_id);
    entity.tag("breach");

    for name in breaches {
        let lower = name.to_lowercase();
        if NOTABLE_BREACHES.iter().any(|n| lower.contains(n)) {
            entity.tag(format!("breach:{lower}"));
        }
    }

    if count >= 5 {
        entity.tag("high-exposure");
    }

    let joined = breaches.join(", ");
    let mut ev = Evidence::new("xposed_or_not", format!("Found in {count} breach(es)"))
        .with_attr("count", count.to_string())
        .with_attr("breaches", joined);

    if let Some(a) = analytics {
        if let Some(pastes) = a.pastes_summary.as_ref().and_then(|p| p.cnt) {
            if pastes > 0 {
                ev = ev.with_attr("paste_count", pastes.to_string());
                entity.tag("paste-exposed");
            }
        }
        if let Some(details) = a
            .exposed_breaches
            .as_ref()
            .and_then(|eb| eb.breaches_details.as_ref())
        {
            let data_types: std::collections::BTreeSet<&str> = details
                .iter()
                .filter_map(|d| d.xposed_data.as_deref())
                .flat_map(|s| s.split(';'))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if !data_types.is_empty() {
                let joined_types: Vec<&str> = data_types.into_iter().collect();
                ev = ev.with_attr("exposed_data_types", joined_types.join(", "));
            }
            let has_password_risk = details
                .iter()
                .any(|d| {
                    d.password_risk
                        .as_deref()
                        .is_some_and(|r| !r.eq_ignore_ascii_case("none") && !r.is_empty())
                });
            if has_password_risk {
                entity.tag("password-at-risk");
                ev = ev.with_attr("password_risk", "true");
            }
        }
    }

    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);
    result
}

fn confidence_for_count(count: usize) -> f64 {
    match count {
        0 => 0.0,
        1..=2 => 0.80,
        3..=5 => 0.85,
        _ => 0.92,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_only() {
        let m = XposedOrNot;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_name_matches_correlator_breach_list() {
        assert_eq!(XposedOrNot.name(), "xposed_or_not");
    }

    #[test]
    fn empty_breaches_yields_no_entity() {
        let target = Target::new(TargetKind::Email, "clean@example.com");
        let r = build_result(&[], None, &target, "scan-1");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn populated_response_yields_breach_tagged_email() {
        let breaches = vec![
            "MyFitnessPal".into(),
            "Quizlet".into(),
            "LinkedIn".into(),
        ];
        let target = Target::new(TargetKind::Email, "pwned@example.com");
        let r = build_result(&breaches, None, &target, "scan-1");

        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Email);
        assert_eq!(e.value, "pwned@example.com");
        assert!(e.has_tag("breach"));
        assert!(e.has_tag("breach:linkedin"));
        assert!(e.has_tag("breach:myfitnesspal"));

        assert_eq!(e.evidence.len(), 1);
        assert_eq!(e.evidence[0].source, "xposed_or_not");
        assert_eq!(e.evidence[0].attributes.get("count").unwrap(), "3");
    }

    #[test]
    fn confidence_scales_with_breach_count() {
        assert!((confidence_for_count(1) - 0.80).abs() < 1e-9);
        assert!((confidence_for_count(4) - 0.85).abs() < 1e-9);
        assert!((confidence_for_count(10) - 0.92).abs() < 1e-9);
    }

    #[test]
    fn high_exposure_tagged_at_five_breaches() {
        let breaches: Vec<String> = (0..6).map(|i| format!("breach_{i}")).collect();
        let target = Target::new(TargetKind::Email, "many@example.com");
        let r = build_result(&breaches, None, &target, "s");
        assert!(r.entities[0].has_tag("high-exposure"));
    }
}
