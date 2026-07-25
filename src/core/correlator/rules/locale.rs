//! AU correlation rules — locale / linguistic-geography family.

use super::*;

/// AU-083 — Multi-email locale corroboration.
///
/// `email_locale` infers a coarse geographic region from the naming conventions
/// in each email's local-part (e.g. `-sson` → Scandinavia, `-owski` → Poland).
/// When ≥2 distinct emails within a scan independently produce the **same**
/// locale-inferred `Address` entity — evidenced by that entity accumulating ≥2
/// `email_locale` evidence entries — the inference is no longer a single-signal
/// guess: multiple email addresses, each shaped by the same linguistic culture,
/// triangulate to the same geographic area.  The rule fires at **Medium**
/// severity; the region stays coarse (continent/country-group), so it signals
/// direction, not an exact address.
pub(in crate::core::correlator) fn rule_au_083_locale_multi_email_corroboration(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Address
                && e.confidence >= 0.30
                && e.tags.iter().any(|t| t == "locale-inferred")
        })
        .filter_map(|e| {
            // Count distinct email_locale evidence entries — each represents one
            // email address that independently matched this locale pattern.
            let locale_count = e
                .evidence
                .iter()
                .filter(|ev| ev.source == "email_locale")
                .count();
            if locale_count < 2 {
                return None;
            }
            // Extract the locale code from the first matching evidence entry.
            let locale_code = e
                .evidence
                .iter()
                .find(|ev| ev.source == "email_locale")
                .and_then(|ev| ev.attributes.get("locale"))
                .map_or("unknown", String::as_str);
            Some(Correlation::new(
                "AU-083",
                "Multi-email locale corroboration",
                Severity::Medium,
                format!(
                    "{} independent email addresses share the '{}' locale naming pattern \
                     \u{2192} consistent geographic area: {} \
                     (coarse, locale-inferred \u{2014} not a fixed address)",
                    locale_count, locale_code, e.value,
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::Evidence;

    #[test]
    fn au083_locale_multi_email_corroboration_fires_on_two_locale_evidence() {
        let mut a = Entity::new(
            EntityKind::Address,
            "Scandinavia (Sweden/Iceland)",
            0.35,
            "scan-au083",
        );
        a.tags.push("locale-inferred".into());
        a.add_evidence(
            Evidence::new("email_locale", "Email local part matches sv naming pattern")
                .with_attr("locale", "sv")
                .with_attr("pattern", "surname_suffix"),
        );
        a.add_evidence(
            Evidence::new("email_locale", "Email local part matches sv naming pattern")
                .with_attr("locale", "sv")
                .with_attr("pattern", "surname_suffix"),
        );
        let results = rule_au_083_locale_multi_email_corroboration(&[a], "scan-au083", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-083 must fire when >=2 email_locale evidence entries share the same locale"
        );
        assert_eq!(results[0].rule_id, "AU-083");
    }

    #[test]
    fn au083_does_not_fire_on_single_locale_evidence() {
        let mut a = Entity::new(
            EntityKind::Address,
            "Scandinavia (Sweden/Iceland)",
            0.35,
            "scan-au083-neg",
        );
        a.tags.push("locale-inferred".into());
        a.add_evidence(
            Evidence::new("email_locale", "Email local part matches sv naming pattern")
                .with_attr("locale", "sv")
                .with_attr("pattern", "surname_suffix"),
        );
        let results = rule_au_083_locale_multi_email_corroboration(&[a], "scan-au083-neg", 0);
        assert!(
            results.is_empty(),
            "AU-083 must not fire for a single-email locale assertion"
        );
    }
}
