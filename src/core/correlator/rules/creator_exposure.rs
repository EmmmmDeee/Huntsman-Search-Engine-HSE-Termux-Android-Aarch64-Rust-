//! AU-120 — Monetized / adult-content creator exposure.
//!
//! A confirmed profile on a subscription-creator, webcam, or adult-video
//! platform (OnlyFans, Fansly, ManyVids, Chaturbate, a Pornhub model page, …) is
//! one of the highest-value OSINT signals a username footprint can carry, yet
//! the generic footprint rules (AU-011/055) bury it in a flat roster. A
//! monetized-creator presence is a DELIBERATE, identity-linked account: it is
//! tied to a real name and payout details through the platform's payment /
//! KYC / age-verification, it usually cross-promotes the subject's other socials
//! and a location, and it is a significant personal-safety / reputational
//! exposure. It deserves its own finding, elevated above "another platform".
//!
//! Delegates entirely to `streaming_probe`'s taxonomy: each confirmed hit is a
//! `Url` entity tagged `cat:fans` / `cat:cam` / `cat:adult` plus
//! `verified-detection` (a body marker) or `weak-detection` (a status-only
//! `200`, which several of these platforms return for any handle). This rule
//! keeps only the body-marker-confirmed profiles — the status-only hits are the
//! false positives and stay visible in AU-011's raw roster without manufacturing
//! a sensitive finding here. (A dating footprint is AU-119's separate concern.)
//!
//! Severity: **Medium** for one or two confirmed platforms; **High** for three
//! or more — a broad monetized-creator footprint is a materially larger
//! real-identity / financial-attribution and reputational surface.

use super::*;

/// The `streaming_probe` category buckets this rule elevates: subscription
/// creator, webcam, and adult-video. Dating (`cat:dating`) is AU-119's domain.
const CREATOR_CATEGORIES: &[&str] = &["cat:fans", "cat:cam", "cat:adult"];

/// AU-120 — Monetized / adult-content creator exposure.
///
/// Entity-only: collects the body-marker-confirmed creator/cam/adult `Url`
/// profiles, names their platforms, and emits one finding. `entity_uids`
/// carries the profile entities in entity order.
pub(in crate::core::correlator) fn rule_au_120_monetized_creator_exposure(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::BTreeSet;

    let mut platforms: BTreeSet<String> = BTreeSet::new();
    let mut uids: Vec<String> = Vec::new();

    for e in entities {
        if e.kind != EntityKind::Url || !e.has_tag("verified-detection") {
            continue;
        }
        if !CREATOR_CATEGORIES.iter().any(|c| e.has_tag(c)) {
            continue;
        }
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
        "AU-120",
        "Monetized/adult-content creator exposure",
        severity,
        format!(
            "Subject holds {n} confirmed subscription-creator / webcam / adult-content \
             profile(s): {listed}{suffix} — a deliberate, identity-linked footprint tied to a real \
             name and payout details through the platform's payment / KYC / age verification, and \
             a significant real-identity, financial-attribution and personal-safety exposure.",
        ),
        uids,
        scan_id,
        ts,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creator_profile(url: &str, platform: &str, cat: &str, verified: bool) -> Entity {
        let mut e = Entity::new(EntityKind::Url, url, 0.9, "s");
        e.tag(format!("platform:{platform}"));
        e.tag(format!("cat:{cat}"));
        e.tag(if verified {
            "verified-detection"
        } else {
            "weak-detection"
        });
        e
    }

    #[test]
    fn au120_fires_on_a_confirmed_creator_profile() {
        let a = creator_profile("https://onlyfans.com/rhino", "OnlyFans", "fans", true);
        let out = rule_au_120_monetized_creator_exposure(std::slice::from_ref(&a), "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-120");
        assert_eq!(out[0].severity, Severity::Medium);
        assert!(out[0].entity_uids.contains(&a.uid));
        assert!(out[0].description.contains("OnlyFans"));
    }

    #[test]
    fn au120_high_across_three_platforms_of_mixed_categories() {
        let ents = [
            creator_profile("https://onlyfans.com/x", "OnlyFans", "fans", true),
            creator_profile("https://chaturbate.com/x", "Chaturbate", "cam", true),
            creator_profile("https://pornhub.com/model/x", "Pornhub", "adult", true),
        ];
        let out = rule_au_120_monetized_creator_exposure(&ents, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn au120_ignores_status_only_weak_detections() {
        let a = creator_profile("https://onlyfans.com/x", "OnlyFans", "fans", false);
        assert!(
            rule_au_120_monetized_creator_exposure(std::slice::from_ref(&a), "s", 0).is_empty(),
            "a status-only creator hit is not a confirmed profile"
        );
    }

    #[test]
    fn au120_ignores_dating_and_ordinary_profiles() {
        // Dating is AU-119's concern; a dev profile is neither.
        let dating = creator_profile("https://tinder.com/x", "Tinder", "dating", true);
        let dev = creator_profile("https://github.com/x", "GitHub", "dev", true);
        assert!(
            rule_au_120_monetized_creator_exposure(&[dating, dev], "s", 0).is_empty(),
            "only fans/cam/adult categories are creator exposure"
        );
    }
}
