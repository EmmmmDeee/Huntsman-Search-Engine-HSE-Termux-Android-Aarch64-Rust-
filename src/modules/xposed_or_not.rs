//! XposedOrNot breach lookup — free public email-to-breach-list service.
//!
//! Endpoint: `https://api.xposedornot.com/v1/check-email/<email>`.
//! Returns the list of named breaches the email appears in (company names
//! like "MyFitnessPal", "Quizlet", etc.) — **not credentials**. Confirms
//! breach exposure without ever transmitting a password through our process.
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
///
/// We only need the `breaches` field. The `"Error"` envelope arrives
/// with no `breaches`, so `build_result` naturally early-returns on
/// an empty list — no Error field needed in the struct, and serde
/// silently ignores the unknown JSON key.
#[derive(Deserialize, Default)]
#[serde(default)]
struct XonResp {
    breaches: Option<Vec<Vec<String>>>,
}

#[async_trait]
impl Module for XposedOrNot {
    fn name(&self) -> &'static str {
        // Stable name — referenced by `BREACH_SOURCES` in `core::correlator`
        // for the AU-001 rule. Don't rename without updating that list.
        "xposed_or_not"
    }

    fn priority(&self) -> u8 {
        // Slightly below `hudsonrock` (130) — hudsonrock's stealer-log data
        // is richer, so we'd rather have it dispatched first.
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

        // 404 = clean (per XposedOrNot semantics); other non-2xx →
        // surfaced as `module_error` so 429 / 5xx stay visible.
        let Some(data): Option<XonResp> =
            fetch_json_or_404(&ctx.http, "xposed_or_not", &url).await?
        else {
            return Ok(ModuleResult::new());
        };
        Ok(build_result(&data, target, &ctx.scan_id))
    }
}

/// Pure transformation of the API response into a `ModuleResult`. Extracted
/// so the parser can be unit-tested without a live HTTP call.
fn build_result(data: &XonResp, target: &Target, scan_id: &str) -> ModuleResult {
    let breaches: Vec<&str> = data
        .breaches
        .as_ref()
        .and_then(|outer| outer.first())
        .map(|inner| inner.iter().map(String::as_str).collect())
        .unwrap_or_default();

    if breaches.is_empty() {
        return ModuleResult::new();
    }

    let mut entity = Entity::new(EntityKind::Email, &target.value, 0.85, scan_id);
    entity.tag("breach");
    entity.add_evidence(
        Evidence::new(
            "xposed_or_not",
            format!("Found in {} breach(es)", breaches.len()),
        )
        .with_attr("count", breaches.len().to_string())
        .with_attr("breaches", breaches.join(", ")),
    );

    let mut result = ModuleResult::new();
    result.push(entity);
    result
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
        // Tight coupling — if either side renames, AU-001 stops firing.
        // Catching this in a unit test is cheap insurance.
        assert_eq!(XposedOrNot.name(), "xposed_or_not");
    }

    #[test]
    fn empty_response_yields_no_entity() {
        let data = XonResp::default();
        let target = Target::new(TargetKind::Email, "clean@example.com");
        let r = build_result(&data, &target, "scan-1");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn populated_response_yields_breach_tagged_email() {
        let data = XonResp {
            breaches: Some(vec![vec![
                "MyFitnessPal".into(),
                "Quizlet".into(),
                "LinkedIn".into(),
            ]]),
        };
        let target = Target::new(TargetKind::Email, "pwned@example.com");
        let r = build_result(&data, &target, "scan-1");

        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Email);
        assert_eq!(e.value, "pwned@example.com");
        assert!(e.has_tag("breach"));

        // Evidence source must match the correlator's BREACH_SOURCES entry.
        assert_eq!(e.evidence.len(), 1);
        assert_eq!(e.evidence[0].source, "xposed_or_not");
        assert_eq!(e.evidence[0].attributes.get("count").unwrap(), "3");
    }

    #[test]
    fn nested_empty_array_yields_no_entity() {
        // XposedOrNot has been seen returning `{"breaches": [[]]}`
        // when the outer envelope is there but no breaches matched.
        let data = XonResp {
            breaches: Some(vec![vec![]]),
        };
        let target = Target::new(TargetKind::Email, "edge@example.com");
        let r = build_result(&data, &target, "scan-1");
        assert_eq!(r.entities.len(), 0);
    }
}
