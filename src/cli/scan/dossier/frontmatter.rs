//! The dossier's front matter: who the subject is, what the scan did, and the
//! calibrated exposure headline an operator reads before anything else.
//!
//! Everything here is scan-level metadata. Findings begin in [`super::findings`].

use crate::core::{correlator::Correlation, entity::Entity, scan::Scan};

/// The header's "Entities:" line: the count actually rendered by the findings
/// sections below (`shown` — the caller's already infra-filtered entities),
/// with a disclosure when the scan's raw persisted total (`raw_total`,
/// [`Scan::entity_count`], set before any display-layer filter runs) exceeds
/// it.
///
/// This line used to print the RAW total even though every section below
/// renders the filtered list — a scan with platform-infra entities showed a
/// header count higher than anything actually listed, with no explanation of
/// the gap (`--include-infra` shows them and closes it). Pure.
pub(super) fn entities_header_line(shown: usize, raw_total: usize) -> String {
    if raw_total > shown {
        format!(
            "  Entities:  {shown} ({} platform-infra excluded of {raw_total} total — pass \
             --include-infra to show)",
            raw_total - shown
        )
    } else {
        format!("  Entities:  {shown}")
    }
}

/// Banner, subject, scan accounting, expansion curve and exposure index.
pub(super) fn print(
    scan: &Scan,
    entities: &[Entity],
    correlations: &[Correlation],
    kind: &str,
    value: &str,
) {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  HUNTSMAN SEARCH ENGINE — INTELLIGENCE DOSSIER              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {kind} = {value}");
    println!("  Scan ID:   {}", &scan.id[..16]);
    println!("  Status:    {}", scan.status.as_str());
    println!(
        "{}",
        entities_header_line(entities.len(), scan.entity_count)
    );
    println!("  Modules:   {}", scan.module_accounting_line());

    // Expansion timeline — the scan's expansion curve: how many entities were
    // first surfaced in each generation as the working graph expanded outward
    // from the seed. Shown only when expansion reached beyond the seed round
    // (more than one generation present).
    let timeline = crate::core::entity::expansion_timeline(entities);
    if timeline.len() > 1 {
        let parts: Vec<String> = timeline
            .iter()
            .map(|(g, n)| format!("gen{g}:{n}"))
            .collect();
        println!("  Expansion: {}", parts.join(" → "));
    }

    // Exposure Index — the calibrated 0–100 headline (with its transparent
    // breakdown) an operator reads first, aggregated from the breach/
    // sensitive-PII/identifier/correlation signals computed for the sections
    // below.
    let exposure = crate::core::exposure::assess(entities, correlations);
    println!("  {}", exposure.summary_line());
    for c in &exposure.components {
        println!(
            "    · {:<22} {:>2}/{:<2}  {}",
            c.name, c.score, c.max, c.detail
        );
    }
    println!();
}
