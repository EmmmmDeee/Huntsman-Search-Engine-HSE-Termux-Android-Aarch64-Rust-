//! AU correlation rule — Australian authoritative-register convergence (AU-106).
//!
//! The HSE module catalogue includes a cluster of authoritative Australian
//! government / regulatory registers (`agor`, the `asic_*` family, `abn_lookup`,
//! `acnc_charities`, `gleif_lei`, `ahpra`, `austender`, …). Each independently
//! attests, from an official source, that a name / organisation / ABN-ACN is a
//! real registered entity; a few of them (`asic_banned_persons`,
//! `asic_banned_orgs`, `dfat_sanctions`) instead record a *material adverse
//! action* against the subject.
//!
//! Same-UID entities merge with GREATEST semantics, so an organisation found in
//! the company register and also flagged by the banned register is a single
//! entity carrying BOTH evidence sources. This rule reads that merged provenance
//! and synthesises it into one explicit finding — closing the loop between the
//! raw register modules and the analyst-facing correlation surface:
//!
//! * **High** — the subject carries an adverse Australian regulatory record
//!   (banned/disqualified or sanctioned). Surfaced as a severity-tagged finding
//!   rather than left as a tag buried in evidence.
//! * **Medium** — the subject is independently corroborated across **two or
//!   more** authoritative identity registers: an official, cross-attested
//!   Australian corporate identity (distinct from the generic cross-source
//!   corroboration of AU-003, which counts *any* source — this rule is specific
//!   to authoritative-register provenance and names the registers).
//!
//! The candidate quarantine upstream (`confirmed_only`) means only confirmed,
//! target-relevant entities ever reach this rule, so a broad-search stranger
//! row can never manufacture a register-convergence finding.

use super::*;

/// Authoritative Australian identity / corporate registers whose presence
/// independently attests to a real registered entity. Each `&str` is the exact
/// `Module::name()` the module stamps on its evidence (`evidence.source`).
const AU_IDENTITY_REGISTERS: &[&str] = &[
    "agor",
    "asic_companies",
    "asic_director",
    "asic_persons",
    "asic_business_names",
    "asic_afs_licensees",
    "asic_afs_representatives",
    "asic_credit_licensees",
    "asic_registered_auditors",
    "asic_liquidators",
    "abn_lookup",
    "au_business_id",
    "acnc_charities",
    "gleif_lei",
    "ahpra",
    "austender",
];

/// Australian adverse / regulatory-action registers: a confirmed hit here is a
/// material adverse finding on the subject (a ban, disqualification or
/// sanction), not merely an identity attestation.
const AU_ADVERSE_REGISTERS: &[&str] =
    &["asic_banned_persons", "asic_banned_orgs", "dfat_sanctions"];

/// AU-106 — Australian authoritative-register convergence. One finding per
/// confirmed organisation / person / ABN-ACN entity whose merged evidence spans
/// an adverse register (High) or two-or-more authoritative identity registers
/// (Medium). Pure and deterministic: the member set is the single entity's uid
/// and the register list is sorted, so the live and finalise passes yield an
/// identical finding for storage's containment-dedup to fold.
pub(in crate::core::correlator) fn rule_au_106_au_register_convergence(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities {
        // Only entities that carry register provenance: a registered body, a
        // named officer, or the ABN/ACN identifier itself.
        if !matches!(
            e.kind,
            EntityKind::Organisation | EntityKind::Person | EntityKind::AbnAcn
        ) {
            continue;
        }

        let identity: BTreeSet<&str> = tagged_matching_sources(e, AU_IDENTITY_REGISTERS)
            .into_iter()
            .collect();
        let adverse: BTreeSet<&str> = tagged_matching_sources(e, AU_ADVERSE_REGISTERS)
            .into_iter()
            .collect();

        if !adverse.is_empty() {
            // High: an adverse regulatory record. List the adverse register(s)
            // first, then any corroborating identity register, all sorted.
            let registers: Vec<&str> = adverse.iter().chain(identity.iter()).copied().collect();
            let registers: BTreeSet<&str> = registers.into_iter().collect();
            let list = registers.into_iter().collect::<Vec<_>>().join(", ");
            out.push(Correlation::new(
                "AU-106",
                "Australian authoritative-register convergence",
                Severity::High,
                format!(
                    "'{}' carries an adverse Australian regulatory record (registers: {list})",
                    e.value
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        } else if identity.len() >= 2 {
            // Medium: corroborated across 2+ authoritative identity registers.
            let list = identity.iter().copied().collect::<Vec<_>>().join(", ");
            out.push(Correlation::new(
                "AU-106",
                "Australian authoritative-register convergence",
                Severity::Medium,
                format!(
                    "'{}' is corroborated across {} authoritative Australian registers ({list})",
                    e.value,
                    identity.len()
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}
