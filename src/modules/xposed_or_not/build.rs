//! Pure result-building helpers for XposedOrNot breach data.

use crate::core::{
    entity::Evidence,
    module::ModuleResult,
    scan::Target,
    tags,
};

use super::types::{AnalyticsResp, BreachDetail};

pub(super) const SRC: &str = "xposed_or_not";

/// High-profile breach names that warrant individual tagging.
pub(super) const NOTABLE_BREACHES: &[&str] = &[
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

pub(super) fn confidence_for_count(count: usize) -> f64 {
    match count {
        0 => 0.0,
        1..=2 => 0.80,
        3..=5 => 0.85,
        6..=9 => 0.92,
        _ => 0.95,
    }
}

pub(super) fn build_result(
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

    breaches
        .iter()
        .map(|name| name.to_lowercase())
        .filter(|lower| NOTABLE_BREACHES.iter().any(|n| lower.contains(n)))
        .for_each(|lower| entity.tag(format!("breach:{lower}")));

    if count >= 5 {
        entity.tag(tags::HIGH_EXPOSURE);
    }

    let joined = breaches.join(", ");
    let mut ev = Evidence::new(SRC, format!("Found in {count} breach(es)"))
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

            ev = attach_breach_detail_attrs(ev, details);
        }
    }

    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);
    result
}

fn attach_breach_detail_attrs(
    mut ev: Evidence,
    details: &[BreachDetail],
) -> Evidence {
    // Surface per-breach summaries with description and record counts.
    let mut breach_summaries: Vec<String> = Vec::new();
    let mut descriptions: Vec<String> = Vec::new();
    for d in details {
        let name = match d.breach.as_deref() {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };

        // Build summary like "LinkedIn (2012, 117M records): Emails;Passwords"
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

        // Surface xposure_desc when present and non-empty.
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
    ev
}

/// Fetch breach analytics from the XposedOrNot analytics endpoint. Best-effort.
pub(super) async fn fetch_analytics(
    http: &reqwest::Client,
    email: &str,
) -> Option<AnalyticsResp> {
    use crate::util::http::{fetch_json_or_404, urlencode};
    let url = format!(
        "https://api.xposedornot.com/v1/breach-analytics?email={}",
        urlencode(email)
    );
    fetch_json_or_404::<AnalyticsResp>(http, SRC, &url)
        .await
        .ok()
        .flatten()
}
