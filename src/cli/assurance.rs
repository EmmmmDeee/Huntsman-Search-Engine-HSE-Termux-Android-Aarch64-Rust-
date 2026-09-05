//! `hse assurance` — print the BSI / IT-Grundschutz assurance status: every
//! catalogued control with its EVIDENCE-DERIVED state and maturity level.
//!
//! This is the reachable production surface over [`crate::core::assurance`]. It
//! reports only what the evidence earns — no fabricated percentages, no control
//! green without recorded evidence — and marks a `NOT_APPLICABLE` control as
//! out-of-scope rather than a deficiency.

use crate::core::assurance::{Profile, ResolvedControl, resolve_catalog, summarise};
use crate::core::error::{Error, Result};

/// Parse a `--profile` filter value to a [`Profile`] (case-insensitive), or an
/// actionable error naming the valid values.
fn parse_profile(s: &str) -> Result<Profile> {
    let want = s.trim().to_ascii_lowercase();
    Profile::all()
        .iter()
        .copied()
        .find(|p| {
            // Match either the bare word ("android") or the full id
            // ("hse-bsi-android").
            let id = p.id().to_ascii_lowercase();
            id == want || id.strip_prefix("hse-bsi-") == Some(want.as_str())
        })
        .ok_or_else(|| {
            let valid: Vec<String> = Profile::all()
                .iter()
                .map(|p| {
                    p.id()
                        .strip_prefix("HSE-BSI-")
                        .unwrap_or(p.id())
                        .to_lowercase()
                })
                .collect();
            Error::Other(format!(
                "unknown profile '{s}'; valid: {}",
                valid.join(", ")
            ))
        })
}

/// `hse assurance [--profile P] [--json]`.
pub(super) fn cmd_assurance(profile_filter: Option<String>, as_json: bool) -> Result<()> {
    let filter = profile_filter.as_deref().map(parse_profile).transpose()?;

    let mut resolved: Vec<ResolvedControl> = resolve_catalog();
    if let Some(p) = filter {
        resolved.retain(|r| r.control.profile == p);
    }
    let summary = summarise(&resolved);

    if as_json {
        let payload = serde_json::json!({
            "controls": resolved,
            "summary": summary,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .map_err(|e| { Error::Other(format!("serialise assurance status: {e}")) })?
        );
        return Ok(());
    }

    // Text table.
    println!("BSI / IT-Grundschutz assurance — evidence-derived control status\n");
    println!(
        "{:<20}  {:<10}  {:<15}  {:<4}  {:<20}",
        "CONTROL", "MODULE", "STATE", "LVL", "PROFILE"
    );
    println!("{}", "─".repeat(78));
    for r in &resolved {
        println!(
            "{:<20}  {:<10}  {:<15}  {:<4}  {:<20}",
            r.control.id,
            r.control.module,
            r.state.id(),
            r.level.code(),
            r.control.profile.id(),
        );
    }
    println!();
    println!(
        "{} control(s): {} not-applicable (out of scope), {} deficiency(ies), \
         {} tested+ (A4+), {} observed+ (A5+), {} assured (A6).",
        summary.total,
        summary.not_applicable,
        summary.deficiencies,
        summary.tested_or_higher,
        summary.observed_or_higher,
        summary.assured,
    );
    println!(
        "\nMaturity is derived from recorded evidence, never asserted. A5/A6 require \
         runtime-observation / independent-assurance evidence not held by the static \
         catalogue, so no control here claims them."
    );
    Ok(())
}
