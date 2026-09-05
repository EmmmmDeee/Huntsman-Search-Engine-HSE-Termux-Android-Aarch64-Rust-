//! `hse bsi <verb>` — the BSI / IT-Grundschutz assurance command family: focused
//! views over the ONE authoritative model in [`crate::core::assurance`].
//!
//! Every verb resolves the catalogue and derives control state from recorded
//! evidence — no verb prints a static framework mapping as if it were a verified
//! control. `controls` and `profile` delegate to the existing `hse assurance`
//! renderer so the full table has a single home; the other verbs are distinct
//! drill-downs (`scope`, `protection`, `gaps`, `regressions`, `status`) or the
//! real evidence-derived gate (`verify`, which exits non-zero on a regression or
//! a High/Critical gap — it is verification, not a print).

use clap::Subcommand;

use super::assurance::{cmd_assurance, parse_profile};
use crate::core::assurance::{
    Criticality, GapFinding, Profile, ProtectionDimension, ProtectionLevel, ResolvedControl,
    VerifyVerdict, findings, resolve_catalog, summarise, verify,
};
use crate::core::error::{Error, Result};

/// The `hse bsi` sub-grammar. Each verb offers `--json` for the machine-readable
/// shape; the scoped verbs take `--profile` to restrict to one `HSE-BSI-*`
/// profile.
#[derive(Subcommand)]
pub enum BsiAction {
    /// Overall roll-up: global counts plus a per-profile applicable / deficiency
    /// breakdown. The fastest "where do we stand" view.
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Every catalogued control with its evidence-derived state, level and
    /// severity (the full `hse assurance` table).
    Controls {
        /// Restrict to one profile (`core`, `android`, `ble`, `web`, `termux`,
        /// `storage`, `cloud`, `development`, `intelligence`; `railway` = cloud).
        #[arg(short, long)]
        profile: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Applicability of each control (APPLICABLE / CONDITIONAL / NOT_APPLICABLE)
    /// and the recorded reason — a scoped-out control is shown, not hidden, so
    /// the scope decision is auditable.
    Scope {
        /// Restrict to one profile.
        #[arg(short, long)]
        profile: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Per-dimension Schutzbedarf (protection need) for each control across
    /// confidentiality / integrity / availability / authenticity / traceability
    /// / privacy.
    Protection {
        /// Restrict to one profile.
        #[arg(short, long)]
        profile: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open deficiencies, most-severe first — each graded from the control's
    /// criticality and Schutzbedarf. A clean catalogue prints none.
    Gaps {
        /// Restrict to one profile.
        #[arg(short, long)]
        profile: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Controls that have REGRESSED — a previously-earned rung the current
    /// evidence no longer supports.
    Regressions {
        /// Restrict to one profile.
        #[arg(short, long)]
        profile: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The full control view for one named profile — e.g. `hse bsi profile
    /// android`, `hse bsi profile railway` (cloud).
    Profile {
        /// Profile name (`core`, `android`, `ble`, `web`, `termux`, `storage`,
        /// `cloud`, `development`, `intelligence`; `railway` aliases `cloud`).
        name: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify the assurance gate: real, evidence-derived verification that exits
    /// non-zero if any control has REGRESSED or any open deficiency is graded
    /// High or Critical. Low/Medium gaps are reported but do not fail the gate.
    Verify {
        /// Restrict verification to one profile.
        #[arg(short, long)]
        profile: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Dispatch an `hse bsi` verb.
pub(super) fn cmd_bsi(action: BsiAction) -> Result<()> {
    match action {
        BsiAction::Status { json } => status(json),
        // The full table has one home: the `hse assurance` renderer.
        BsiAction::Controls { profile, json } => cmd_assurance(profile, json),
        BsiAction::Profile { name, json } => cmd_assurance(Some(name), json),
        BsiAction::Scope { profile, json } => scope(profile.as_deref(), json),
        BsiAction::Protection { profile, json } => protection(profile.as_deref(), json),
        BsiAction::Gaps { profile, json } => gaps(profile.as_deref(), json),
        BsiAction::Regressions { profile, json } => regressions(profile.as_deref(), json),
        BsiAction::Verify { profile, json } => run_verify(profile.as_deref(), json),
    }
}

/// Resolve the catalogue, optionally filtered to one profile. Shares
/// [`parse_profile`] so the profile vocabulary (including the `railway` alias)
/// is identical to `hse assurance`.
fn resolve_scope(profile: Option<&str>) -> Result<Vec<ResolvedControl>> {
    let filter = profile.map(parse_profile).transpose()?;
    let mut resolved = resolve_catalog();
    if let Some(p) = filter {
        resolved.retain(|r| r.control.profile == p);
    }
    Ok(resolved)
}

/// Emit a JSON value pretty-printed, or a serialise error.
fn print_json(value: &serde_json::Value) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value)
            .map_err(|e| Error::Other(format!("serialise bsi output: {e}")))?
    );
    Ok(())
}

/// The single-letter Schutzbedarf code for a protection level.
fn lvl_code(l: ProtectionLevel) -> char {
    match l {
        ProtectionLevel::Normal => '·',
        ProtectionLevel::High => 'H',
        ProtectionLevel::VeryHigh => 'V',
    }
}

/// A short criticality label.
fn crit_label(c: Criticality) -> &'static str {
    match c {
        Criticality::Routine => "routine",
        Criticality::Important => "important",
        Criticality::Critical => "critical",
    }
}

/// `hse bsi status` — global counts + a per-profile breakdown.
fn status(json: bool) -> Result<()> {
    let resolved = resolve_catalog();
    let summary = summarise(&resolved);

    // Per-profile roll-up.
    let per_profile: Vec<(Profile, usize, usize, usize)> = Profile::all()
        .iter()
        .map(|&p| {
            let in_p: Vec<&ResolvedControl> =
                resolved.iter().filter(|r| r.control.profile == p).collect();
            let applicable = in_p
                .iter()
                .filter(|r| {
                    r.control.applicability != crate::core::assurance::Applicability::NotApplicable
                })
                .count();
            let deficiencies = in_p.iter().filter(|r| r.state.is_deficiency()).count();
            (p, in_p.len(), applicable, deficiencies)
        })
        .filter(|(_, total, _, _)| *total > 0)
        .collect();

    if json {
        let profiles: Vec<serde_json::Value> = per_profile
            .iter()
            .map(|(p, total, applicable, deficiencies)| {
                serde_json::json!({
                    "profile": p.id(),
                    "controls": total,
                    "applicable": applicable,
                    "deficiencies": deficiencies,
                })
            })
            .collect();
        return print_json(&serde_json::json!({
            "summary": summary,
            "profiles": profiles,
        }));
    }

    println!("BSI / IT-Grundschutz assurance — status roll-up\n");
    println!(
        "{} control(s): {} not-applicable (out of scope), {} deficiency(ies) \
         ({} critical, {} high), {} tested+ (A4+), {} observed+ (A5+), {} assured (A6).",
        summary.total,
        summary.not_applicable,
        summary.deficiencies,
        summary.critical_findings,
        summary.high_findings,
        summary.tested_or_higher,
        summary.observed_or_higher,
        summary.assured,
    );
    match summary.highest_open_severity {
        Some(sev) => println!("Highest open finding: {}.", sev.label()),
        None => println!("No open deficiencies."),
    }
    println!();
    println!(
        "{:<20}  {:>8}  {:>10}  {:>12}",
        "PROFILE", "CONTROLS", "APPLICABLE", "DEFICIENCIES"
    );
    println!("{}", "─".repeat(56));
    for (p, total, applicable, deficiencies) in &per_profile {
        println!(
            "{:<20}  {:>8}  {:>10}  {:>12}",
            p.id(),
            total,
            applicable,
            deficiencies
        );
    }
    Ok(())
}

/// `hse bsi scope` — applicability and reason per control.
fn scope(profile: Option<&str>, json: bool) -> Result<()> {
    let resolved = resolve_scope(profile)?;

    if json {
        let rows: Vec<serde_json::Value> = resolved
            .iter()
            .map(|r| {
                serde_json::json!({
                    "control": r.control.id,
                    "profile": r.control.profile.id(),
                    "applicability": r.control.applicability,
                    "reason": r.control.applicability_reason,
                })
            })
            .collect();
        return print_json(&serde_json::json!({ "scope": rows }));
    }

    println!("BSI / IT-Grundschutz assurance — applicability (scope)\n");
    println!(
        "{:<20}  {:<20}  {:<15}  REASON",
        "CONTROL", "PROFILE", "APPLICABILITY"
    );
    println!("{}", "─".repeat(90));
    for r in &resolved {
        // `{:?}` on a small fieldless enum is the SCREAMING vocabulary via serde
        // rename only in JSON; for the table use a stable manual label.
        let ap = match r.control.applicability {
            crate::core::assurance::Applicability::Applicable => "APPLICABLE",
            crate::core::assurance::Applicability::Conditional => "CONDITIONAL",
            crate::core::assurance::Applicability::NotApplicable => "NOT_APPLICABLE",
        };
        println!(
            "{:<20}  {:<20}  {:<15}  {}",
            r.control.id,
            r.control.profile.id(),
            ap,
            r.control.applicability_reason,
        );
    }
    Ok(())
}

/// `hse bsi protection` — per-dimension Schutzbedarf per control.
fn protection(profile: Option<&str>, json: bool) -> Result<()> {
    let resolved = resolve_scope(profile)?;

    if json {
        let rows: Vec<serde_json::Value> = resolved
            .iter()
            .map(|r| {
                serde_json::json!({
                    "control": r.control.id,
                    "criticality": r.control.criticality,
                    "protection_need": r.control.protection_need,
                })
            })
            .collect();
        return print_json(&serde_json::json!({ "protection": rows }));
    }

    println!("BSI / IT-Grundschutz assurance — Schutzbedarf (protection need)\n");
    println!(
        "Dimensions: C=Confidentiality I=Integrity A=Availability Au=Authenticity Tr=Traceability Pr=Privacy  (·=normal H=high V=very-high)\n"
    );
    println!(
        "{:<20}  {:<10}  {:>2} {:>2} {:>2} {:>2} {:>2} {:>2}",
        "CONTROL", "CRIT", "C", "I", "A", "Au", "Tr", "Pr"
    );
    println!("{}", "─".repeat(56));
    for r in &resolved {
        let n = &r.control.protection_need;
        println!(
            "{:<20}  {:<10}  {:>2} {:>2} {:>2} {:>2} {:>2} {:>2}",
            r.control.id,
            crit_label(r.control.criticality),
            lvl_code(n.level(ProtectionDimension::Confidentiality)),
            lvl_code(n.level(ProtectionDimension::Integrity)),
            lvl_code(n.level(ProtectionDimension::Availability)),
            lvl_code(n.level(ProtectionDimension::Authenticity)),
            lvl_code(n.level(ProtectionDimension::Traceability)),
            lvl_code(n.level(ProtectionDimension::Privacy)),
        );
    }
    Ok(())
}

/// Render a list of findings as a table (shared by `gaps` and `regressions`).
fn print_findings(title: &str, open: &[GapFinding], empty_note: &str) {
    println!("{title}\n");
    if open.is_empty() {
        println!("{empty_note}");
        return;
    }
    println!(
        "{:<8}  {:<20}  {:<12}  {:<11}  {:<10}  HIGH-NEED",
        "SEV", "CONTROL", "MODULE", "STATE", "CRIT"
    );
    println!("{}", "─".repeat(78));
    for f in open {
        println!(
            "{:<8}  {:<20}  {:<12}  {:<11}  {:<10}  {}",
            f.severity.label(),
            f.control_id,
            f.module,
            f.state.id(),
            crit_label(f.criticality),
            if f.high_protection_need { "yes" } else { "no" },
        );
    }
}

/// `hse bsi gaps` — open deficiencies, most-severe first.
fn gaps(profile: Option<&str>, json: bool) -> Result<()> {
    let resolved = resolve_scope(profile)?;
    let open = findings(&resolved);
    if json {
        return print_json(&serde_json::json!({ "gaps": open }));
    }
    print_findings(
        "BSI / IT-Grundschutz assurance — open deficiencies (worst first)",
        &open,
        "No open deficiencies: every in-scope control holds at least its defined rung.",
    );
    Ok(())
}

/// `hse bsi regressions` — controls that have gone backwards.
fn regressions(profile: Option<&str>, json: bool) -> Result<()> {
    let resolved = resolve_scope(profile)?;
    let regs: Vec<GapFinding> = findings(&resolved)
        .into_iter()
        .filter(|f| f.state == crate::core::assurance::ControlState::Regressed)
        .collect();
    if json {
        return print_json(&serde_json::json!({ "regressions": regs }));
    }
    print_findings(
        "BSI / IT-Grundschutz assurance — regressions",
        &regs,
        "No regressions: no control has lost a previously-earned rung.",
    );
    Ok(())
}

/// `hse bsi verify` — the real, evidence-derived gate. Returns `Err` (process
/// exit 1) when the verdict fails, so it is usable directly in CI / scripts.
fn run_verify(profile: Option<&str>, json: bool) -> Result<()> {
    let resolved = resolve_scope(profile)?;
    let v: VerifyVerdict = verify(&resolved);

    if json {
        print_json(
            &serde_json::to_value(&v)
                .map_err(|e| Error::Other(format!("serialise verify verdict: {e}")))?,
        )?;
    } else {
        println!("BSI / IT-Grundschutz assurance — verification gate\n");
        if v.ok {
            println!(
                "PASS: {} control(s) checked; 0 regressions, 0 High/Critical open gap(s).",
                v.summary.total
            );
            if !v.warnings.is_empty() {
                println!(
                    "\n{} advisory low/medium gap(s) (non-blocking):",
                    v.warnings.len()
                );
                for f in &v.warnings {
                    println!(
                        "  {:<8} {} ({})",
                        f.severity.label(),
                        f.control_id,
                        f.module
                    );
                }
            }
        } else {
            println!(
                "FAIL: {} regression(s), {} High/Critical blocking gap(s).\n",
                v.regressions.len(),
                v.blocking.len()
            );
            for f in &v.regressions {
                println!("  REGRESSED  {} ({})", f.control_id, f.module);
            }
            for f in &v.blocking {
                println!(
                    "  {:<8}   {} ({}) — {}",
                    f.severity.label(),
                    f.control_id,
                    f.module,
                    f.state.id()
                );
            }
        }
    }

    if v.ok {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "assurance verification failed: {} regression(s), {} High/Critical gap(s)",
            v.regressions.len(),
            v.blocking.len()
        )))
    }
}
