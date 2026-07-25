//! AU-068 — Anonymous / burner SIM (attribution caveat).
//!
//! A phone is only as strong an identity anchor as the SIM behind it. When
//! `hlr_cnam` resolves a number to a VoIP / virtual provider or an
//! anonymity-friendly prepaid MVNO, the number can be held with little or no
//! verified identity — a likely burner. This rule surfaces that as a first-class
//! finding so the operator (and the recursive linker) weighs a phone-based link
//! accordingly. It reads the SIM anonymity tags `hlr_cnam` set via
//! [`crate::util::sim_anonymity`], so the rule and the classifier can't drift.

use super::*;
use crate::util::sim_anonymity::{ANONYMITY_TAGS, tier_for_tag};

/// AU-068 — Anonymous / burner SIM.
pub(in crate::core::correlator) fn rule_au_068_anonymous_sim(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    let mut out = Vec::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Phone) {
        let Some(tier) = ANONYMITY_TAGS
            .iter()
            .find_map(|t| if e.has_tag(t) { tier_for_tag(t) } else { None })
        else {
            continue;
        };
        out.push(Correlation::new(
            "AU-068",
            "Anonymous / burner SIM",
            Severity::Medium,
            format!(
                "Phone '{}' resolves to a {} — a number obtainable with little or no verified \
                 identity, so a connection resting on it carries weaker attribution",
                e.value,
                tier.label(),
            ),
            vec![e.uid.clone()],
            scan_id,
            ts,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn au068_fires_on_a_voip_tagged_phone() {
        let mut phone = Entity::new(EntityKind::Phone, "+61400000000", 0.85, "s");
        phone.tag("sim-voip");
        let out = rule_au_068_anonymous_sim(&RuleContext::new(&[phone]), "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-068");
        assert!(out[0].description.contains("VoIP"));
    }

    #[test]
    fn au068_fires_on_an_mvno_tagged_phone() {
        let mut phone = Entity::new(EntityKind::Phone, "+61400000001", 0.85, "s");
        phone.tag("sim-mvno-prepaid");
        let out = rule_au_068_anonymous_sim(&RuleContext::new(&[phone]), "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Medium);
    }

    #[test]
    fn au068_silent_on_an_ordinary_phone() {
        // A verified phone with no anonymity tag is not a burner finding.
        let mut phone = Entity::new(EntityKind::Phone, "+61400000002", 0.85, "s");
        phone.tag("hlr-verified");
        assert!(rule_au_068_anonymous_sim(&RuleContext::new(&[phone]), "s", 0).is_empty());
        // Neither is a non-phone entity.
        let email = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
        assert!(rule_au_068_anonymous_sim(&RuleContext::new(&[email]), "s", 0).is_empty());
    }
}
