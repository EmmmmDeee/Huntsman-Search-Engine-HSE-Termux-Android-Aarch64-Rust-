//! AU correlation rules — PayID family.
//!
//! Surfaces the consolidated NPP payment-identity once a subject is reachable by
//! more than one PayID handle. See `super` (rules/mod.rs) for the shared helpers;
//! every rule reaches them through `use super::*`.

use super::*;

/// AU-072 — Consolidated PayID payment-identity surface.
///
/// The `payid` module tags each PayID-eligible identifier (email / phone / ABN)
/// individually. This rule fires once a subject carries **two or more** of them,
/// because the aggregate is itself a finding: each is an independent NPP
/// confirm-payee route to the SAME registered account-holder name, so multiple
/// handles both widen the de-anonymisation surface and cross-confirm the name.
/// A register-resolvable ABN among them lifts the severity — its holder name is
/// resolvable from the public register now, with no banking app.
///
/// Runs on the confirmed (candidate-filtered) view, so speculative name-permuted
/// addresses — kept at CANDIDATE — never inflate the count.
pub(in crate::core::correlator) fn rule_au_072_payid_payment_surface(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;
    const MIN_PAYIDS: usize = 2;

    let payids: Vec<&Entity> = entities.iter().filter(|e| e.has_tag("payid")).collect();
    if payids.len() < MIN_PAYIDS {
        return Vec::new();
    }

    // Distinct channel types present (email / phone / abn), sorted for a stable
    // description; the `registry-resolvable` marker tag is deliberately excluded.
    let types: BTreeSet<&str> = payids
        .iter()
        .flat_map(|e| e.tags.iter())
        .filter_map(|t| t.strip_prefix("payid:"))
        .filter(|s| matches!(*s, "email" | "phone" | "abn"))
        .collect();

    let registry_resolvable = payids
        .iter()
        .any(|e| e.has_tag("payid:registry-resolvable"));

    // Full member set, sorted by uid — the live and finalise passes must yield
    // the same uid SET so containment-dedup folds them (the AU-039 determinism
    // discipline: never sample an unsorted, HashMap-ordered slice into output).
    let mut uids: Vec<String> = payids.iter().map(|e| e.uid.clone()).collect();
    uids.sort_unstable();

    let types_listed: Vec<&str> = types.iter().copied().collect();
    let (severity, tail) = if registry_resolvable {
        (
            Severity::High,
            "; an ABN PayID among them resolves the holder name from the public register now",
        )
    } else {
        (
            Severity::Medium,
            " — each is an NPP confirm-payee route to the registered account-holder name",
        )
    };

    vec![Correlation {
        rule_id: "AU-072".into(),
        rule_name: "Consolidated PayID payment-identity surface".into(),
        severity,
        description: format!(
            "Subject reachable by {} PayID identifier(s) across {} channel(s) ({}){}",
            payids.len(),
            types_listed.len(),
            types_listed.join(", "),
            tail
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}
