use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json_or_404, urlencode};

pub struct XposedOrNot;

#[derive(Deserialize, Default)]
#[serde(default)]
struct XonResp {
    breaches: Option<Vec<Vec<String>>>,
}

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
    #[serde(alias = "xposed_date")]
    xposed_date: Option<String>,
    #[serde(alias = "password_risk")]
    password_risk: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PastesSummary {
    cnt: Option<u64>,
}

const NOTABLE_BREACHES: &[&str] = &[
    "linkedin",
    "adobe",
    "dropbox",
    "myspace",
    "twitter",
    "facebook",
    "yahoo",
    "lastfm",
    "tumblr",
    "myfitnesspal",
    "canva",
    "zynga",
    "dubsmash",
    "haveibeenpwned",
    "verifications.io",
    "collection",
    "exactis",
    "apollo",
    "evite",
];

#[async_trait]
impl Module for XposedOrNot {
    fn name(&self) -> &'static str {
        "xposed_or_not"
    }

    fn description(&self) -> &'static str {
        "Email breach lookup with analytics enrichment"
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

        Ok(build_result(
            inner,
            analytics.as_ref(),
            target,
            &ctx.scan_id,
        ))
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

    let mut entity = target.to_entity(confidence, scan_id);
    entity.tag(tags::BREACH);

    for name in breaches {
        let lower = name.to_lowercase();
        if NOTABLE_BREACHES.iter().any(|n| lower.contains(n)) {
            entity.tag(format!("breach:{lower}"));
        }
    }

    entity.tag_if(count >= 5, tags::HIGH_EXPOSURE);

    let joined = breaches.join(", ");
    let mut ev = Evidence::new("xposed_or_not", format!("Found in {count} breach(es)"))
        .with_attr("count", count.to_string())
        .with_attr("breaches", joined);

    if let Some(a) = analytics {
        if let Some(pastes) = a.pastes_summary.as_ref().and_then(|p| p.cnt)
            && pastes > 0
        {
            ev = ev.with_attr("paste_count", pastes.to_string());
            entity.tag(tags::PASTE_EXPOSED);
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
            let has_password_risk = details.iter().any(|d| {
                d.password_risk
                    .as_deref()
                    .is_some_and(|r| !r.eq_ignore_ascii_case("none") && !r.is_empty())
            });
            if has_password_risk {
                entity.tag(tags::PASSWORD_AT_RISK);
                ev = ev.with_attr("password_risk", "true");
            }

            let mut breach_summaries: Vec<String> = Vec::new();
            let mut descriptions: Vec<String> = Vec::new();
            for d in details {
                let name = match d.breach.as_deref() {
                    Some(n) if !n.is_empty() => n,
                    _ => continue,
                };

                let year = d
                    .xposed_date
                    .as_deref()
                    .and_then(|s| s.get(..4))
                    .filter(|y| y.chars().all(|c| c.is_ascii_digit()));

                let records_label = d.xposed_records.map(|n| {
                    if n >= 1_000_000 {
                        format!("{}M records", n / 1_000_000)
                    } else if n >= 1_000 {
                        format!("{}K records", n / 1_000)
                    } else {
                        format!("{n} records")
                    }
                });

                let data = d.xposed_data.as_deref().unwrap_or("");

                let mut parts = Vec::new();
                if let Some(y) = year {
                    parts.push(y.to_string());
                }
                if let Some(ref rl) = records_label {
                    parts.push(rl.clone());
                }

                let summary = if parts.is_empty() && data.is_empty() {
                    name.to_string()
                } else if parts.is_empty() {
                    format!("{name}: {data}")
                } else if data.is_empty() {
                    format!("{name} ({})", parts.join(", "))
                } else {
                    format!("{name} ({}):{data}", parts.join(", "))
                };
                breach_summaries.push(summary);

                if let Some(desc) = d.xposure_desc.as_deref() {
                    let desc = desc.trim();
                    if !desc.is_empty() {
                        descriptions.push(format!("{name}: {desc}"));
                    }
                }
            }
            if !breach_summaries.is_empty() {
                ev = ev.with_attr("breach_summaries", breach_summaries.join(" | "));
            }
            if !descriptions.is_empty() {
                ev = ev.with_attr("breach_descriptions", descriptions.join(" | "));
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
    use crate::core::entity::EntityKind;

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
        let breaches = vec!["MyFitnessPal".into(), "Quizlet".into(), "LinkedIn".into()];
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

    #[test]
    fn analytics_surfaces_breach_summaries_and_descriptions() {
        let breaches = vec!["LinkedIn".into()];
        let analytics = AnalyticsResp {
            exposed_breaches: Some(AnalyticsBreaches {
                breaches_details: Some(vec![BreachDetail {
                    breach: Some("LinkedIn".into()),
                    xposed_data: Some("Emails;Passwords".into()),
                    xposed_records: Some(117_000_000),
                    xposure_desc: Some("LinkedIn suffered a data breach in 2012".into()),
                    xposed_date: Some("2012-06-05".into()),
                    password_risk: Some("none".into()),
                }]),
            }),
            pastes_summary: None,
        };
        let target = Target::new(TargetKind::Email, "a@b.com");
        let r = build_result(&breaches, Some(&analytics), &target, "s");

        let ev = &r.entities[0].evidence[0];
        let summaries = ev.attributes.get("breach_summaries").unwrap();
        assert!(summaries.contains("LinkedIn"));
        assert!(summaries.contains("2012"));
        assert!(summaries.contains("117M records"));
        assert!(summaries.contains("Emails;Passwords"));

        let descs = ev.attributes.get("breach_descriptions").unwrap();
        assert!(descs.contains("LinkedIn: LinkedIn suffered a data breach in 2012"));
    }

    #[test]
    fn analytics_without_desc_omits_descriptions_attr() {
        let breaches = vec!["SomeService".into()];
        let analytics = AnalyticsResp {
            exposed_breaches: Some(AnalyticsBreaches {
                breaches_details: Some(vec![BreachDetail {
                    breach: Some("SomeService".into()),
                    xposed_data: Some("Emails".into()),
                    xposed_records: Some(500),
                    xposure_desc: None,
                    xposed_date: None,
                    password_risk: None,
                }]),
            }),
            pastes_summary: None,
        };
        let target = Target::new(TargetKind::Email, "a@b.com");
        let r = build_result(&breaches, Some(&analytics), &target, "s");

        let ev = &r.entities[0].evidence[0];
        let summaries = ev.attributes.get("breach_summaries").unwrap();
        assert!(summaries.contains("SomeService"));
        assert!(summaries.contains("500 records"));
        assert!(!ev.attributes.contains_key("breach_descriptions"));
    }
}
