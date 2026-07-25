//! AU-119 — Dating-platform exposure.
//!
//! A confirmed profile on a **dating** platform is a distinct, high-value OSINT
//! signal that the generic cross-platform footprint rules (AU-011 "present on N
//! platforms", AU-055 "primary-source accounts") bury inside a long list. Dating
//! apps geolocate their users and expose age, photos, and preferences, so a
//! dating footprint is a personal-safety / location-attribution surface — not
//! just "another platform". An analyst triaging correlations should see it
//! flagged on its own, at a severity that reflects the exposure.
//!
//! Delegates entirely to `username_search`'s existing taxonomy: each profile it
//! confirms is a `Url` entity tagged `cat:<category>` plus either
//! `verified-detection` (a body-marker match) or `weak-detection` (a status-only
//! `200`, which many dating sites return for EVERY handle). This rule keeps only
//! the `cat:dating` profiles confirmed by a body marker — the status-only hits
//! are exactly the false positives, and they remain visible in AU-011's raw
//! roster without inflating a personal-safety finding here.
//!
//! Severity: **Medium** for one or two confirmed dating platforms; **High** for
//! three or more — a broad dating presence is a materially larger location /
//! personal-exposure and catfishing/impersonation surface.

use super::*;

/// AU-119 — Dating-platform exposure.
///
/// Entity-only: collects the body-marker-confirmed `cat:dating` `Url` profiles,
/// names their platforms, and emits one finding. `entity_uids` carries the
/// dating profile entities in entity order.
pub(in crate::core::correlator) fn rule_au_119_dating_platform_exposure(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::BTreeSet;

    let mut platforms: BTreeSet<String> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();

    for e in entities {
        if e.kind != EntityKind::Url || !e.has_tag("cat:dating") || !e.has_tag("verified-detection")
        {
            continue;
        }
        // Platform name from the `platform:<name>` tag, else the evidence attr.
        let platform = e
            .tags
            .iter()
            .find_map(|t| t.strip_prefix("platform:"))
            .map(str::to_string)
            .or_else(|| {
                e.evidence
                    .iter()
                    .find_map(|ev| ev.attributes.get("platform").cloned())
            });
        if let Some(p) = platform {
            platforms.insert(p);
        }
        uids.push(e.uid.clone());
    }

    if uids.is_empty() {
        return Vec::new();
    }

    let n = platforms.len().max(1);
    let severity = if n >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };
    let listed = platforms
        .iter()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let more = platforms.len().saturating_sub(8);
    let suffix = if more > 0 {
        format!(", +{more} more")
    } else {
        String::new()
    };

    vec![Correlation::new(
        "AU-119",
        "Dating-platform exposure",
        severity,
        format!(
            "Subject holds {n} confirmed dating-app profile(s){}: {listed}{suffix} — a \
             location-bearing, personal-exposure surface (dating platforms geolocate users and \
             expose age, photos and preferences), materially higher OSINT / personal-safety \
             signal than a generic account footprint.",
            if n == 1 {
                ""
            } else {
                " across distinct platforms"
            },
        ),
        uids,
        scan_id,
        ts,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dating_profile(url: &str, platform: &str, verified: bool) -> Entity {
        let mut e = Entity::new(EntityKind::Url, url, 0.8, "s");
        e.tag("social-profile");
        e.tag(format!("platform:{platform}"));
        e.tag("cat:dating");
        e.tag(if verified {
            "verified-detection"
        } else {
            "weak-detection"
        });
        e
    }

    #[test]
    fn au119_fires_on_a_confirmed_dating_profile() {
        let a = dating_profile("https://tinder.com/@rhino", "Tinder", true);
        let out = rule_au_119_dating_platform_exposure(
            &RuleContext::new(std::slice::from_ref(&a)),
            "s",
            0,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-119");
        assert_eq!(out[0].severity, Severity::Medium);
        assert!(out[0].entity_uids.contains(&a.uid));
        assert!(out[0].description.contains("Tinder"));
    }

    #[test]
    fn au119_high_severity_across_three_platforms() {
        let ents = [
            dating_profile("https://tinder.com/@x", "Tinder", true),
            dating_profile("https://pof.com/@x", "PlentyOfFish", true),
            dating_profile("https://badoo.com/@x", "Badoo", true),
        ];
        let out = rule_au_119_dating_platform_exposure(&RuleContext::new(&ents), "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn au119_ignores_status_only_weak_detections() {
        // A dating site that 200s for every handle (weak detection) is not proof
        // of a real profile — it must not manufacture a personal-safety finding.
        let a = dating_profile("https://badoo.com/@x", "Badoo", false);
        assert!(
            rule_au_119_dating_platform_exposure(&RuleContext::new(&[a]), "s", 0).is_empty(),
            "a status-only dating hit is not a confirmed profile"
        );
    }

    #[test]
    fn au119_ignores_non_dating_profiles() {
        let mut github = Entity::new(EntityKind::Url, "https://github.com/x", 0.8, "s");
        github.tag("cat:dev");
        github.tag("verified-detection");
        assert!(
            rule_au_119_dating_platform_exposure(&RuleContext::new(&[github]), "s", 0).is_empty(),
            "a dev profile is not a dating exposure"
        );
    }
}
