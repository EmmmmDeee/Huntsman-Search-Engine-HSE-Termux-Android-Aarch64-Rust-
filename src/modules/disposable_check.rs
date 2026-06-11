//! Disposable email detection via debounce.io (free, no key, unlimited).
//!
//! Endpoint: `GET https://disposable.debounce.io/?email={email}`
//! Auth: None.
//!
//! Tags email entities as `disposable` when they use throwaway domains
//! (mailinator, guerrillamail, etc.). A throwaway address is weak OSINT footing
//! — it points at no durable identity — so it is heavily down-weighted to keep
//! it from anchoring expansion noise. The verdict→entity mapping lives in the
//! pure [`build_email_entity`] so it is unit-tested without a live API.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "disposable_check";

/// Confidence for a confirmed disposable/throwaway address — deliberately low:
/// it anchors no durable identity, so it should not pull expansion toward it.
const DISPOSABLE_CONFIDENCE: f64 = 0.20;
/// Confidence for an address on a legitimate (non-throwaway) provider.
const LEGIT_CONFIDENCE: f64 = 0.75;

/// debounce.io returns its boolean verdict as the JSON *string* `"true"` /
/// `"false"`, not a bare bool — hence `String`, parsed via [`is_disposable`].
#[derive(Deserialize)]
struct Resp {
    disposable: String,
}

/// Interpret debounce.io's stringly-typed `disposable` field. The API emits
/// `"true"`/`"false"`; we accept any case and surrounding whitespace, and treat
/// anything that is not an affirmative `true` as not-disposable (fail-open — a
/// malformed verdict must not silently brand a real address as throwaway).
fn is_disposable(raw: &str) -> bool {
    raw.trim().eq_ignore_ascii_case("true")
}

/// Map a disposable verdict onto the target email's entity. **Pure** (no
/// network/IO): always tags `email-validated` (the address resolved through the
/// checker), and on a disposable verdict additionally tags `disposable` and
/// collapses confidence to [`DISPOSABLE_CONFIDENCE`]. Either way the verdict is
/// recorded as a `disposable=<bool>` evidence attribute so a downstream rule can
/// read it without re-deriving it from the confidence.
fn build_email_entity(email: &str, disposable: bool, scan_id: &str) -> Entity {
    let conf = if disposable {
        DISPOSABLE_CONFIDENCE
    } else {
        LEGIT_CONFIDENCE
    };
    let mut entity = Entity::new(EntityKind::Email, email, conf, scan_id);
    entity.tag("email-validated");

    let ev = if disposable {
        entity.tag("disposable");
        Evidence::new(SRC, format!("{email} uses a disposable/throwaway domain"))
            .with_attr("disposable", "true")
    } else {
        Evidence::new(SRC, format!("{email} uses a legitimate email provider"))
            .with_attr("disposable", "false")
    };
    entity.add_evidence(ev);
    entity
}

pub struct DisposableCheck;

#[async_trait]
impl Module for DisposableCheck {
    fn name(&self) -> &'static str {
        "disposable_check"
    }
    fn description(&self) -> &'static str {
        "Disposable/throwaway email detection via debounce.io (free, unlimited)"
    }
    fn priority(&self) -> u8 {
        97
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn is_passive(&self) -> bool {
        true
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Email
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // The request carries a 5s reqwest timeout; on the 3s default
        // MODULE_TIMEOUT_MS the engine would kill process() before that
        // timeout could fire, so a slow endpoint yielded a spurious engine
        // "timeout" instead of the module's own clean no-op. Budget above
        // the request timeout with headroom for JSON read.
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let email = target.value.trim();
        if email.is_empty() || !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://disposable.debounce.io/?email={}",
            crate::util::http::urlencode(email)
        );
        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        let mut result = ModuleResult::new();
        result.push(build_email_entity(
            email,
            is_disposable(&data.disposable),
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_only() {
        assert!(DisposableCheck.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!DisposableCheck.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            DisposableCheck.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn deser_keeps_stringly_typed_verdict() {
        let r: Resp = serde_json::from_str(r#"{"disposable":"true"}"#).unwrap();
        assert_eq!(r.disposable, "true");
    }

    #[test]
    fn verdict_parsing_is_affirmative_only_and_lenient() {
        assert!(is_disposable("true"));
        assert!(is_disposable("  TRUE \n"));
        assert!(is_disposable("True"));
        assert!(!is_disposable("false"));
        // Fail-open: an unexpected/garbage verdict is NOT branded disposable.
        assert!(!is_disposable(""));
        assert!(!is_disposable("yes"));
        assert!(!is_disposable("1"));
    }

    #[test]
    fn disposable_verdict_tags_and_collapses_confidence() {
        let e = build_email_entity("burner@mailinator.com", true, "s");
        assert_eq!(e.kind, EntityKind::Email);
        assert!(e.has_tag("email-validated") && e.has_tag("disposable"));
        assert!((e.confidence - DISPOSABLE_CONFIDENCE).abs() < 1e-9);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("disposable").map(String::as_str),
            Some("true")
        );
        assert!(ev.summary.contains("disposable/throwaway"));
    }

    #[test]
    fn legit_verdict_validates_without_disposable_tag() {
        let e = build_email_entity("person@gmail.com", false, "s");
        assert!(e.has_tag("email-validated") && !e.has_tag("disposable"));
        assert!((e.confidence - LEGIT_CONFIDENCE).abs() < 1e-9);
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("disposable")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn disposable_is_far_lower_confidence_than_legit() {
        // The whole point: a throwaway must not out-weigh a real address.
        let disp = build_email_entity("x@guerrillamail.com", true, "s");
        let legit = build_email_entity("x@outlook.com", false, "s");
        assert!(disp.confidence < legit.confidence);
    }
}
