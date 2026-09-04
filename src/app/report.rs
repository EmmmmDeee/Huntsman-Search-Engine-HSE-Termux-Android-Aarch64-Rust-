//! `hse report` — one scan's full quality picture in a single pass.
//!
//! Audit, benchmark and discovery-gaps are three lenses on the same object: a
//! completed scan. They were three top-level commands, so answering "how good
//! was this scan, and what is it missing?" took three invocations and three
//! `--scan-id` repetitions, and an operator who did not know all three existed
//! saw only the part they happened to run.
//!
//! This runs ALL THREE by default. The individual commands still exist (hidden)
//! so existing scripts and the Web UI keep working unchanged; this is the
//! comprehensive default, not a replacement for the parts.

use crate::core::error::{Error, Result};

/// Which lenses to run. Nothing selected means every one — the default.
struct Lenses {
    audit: bool,
    benchmark: bool,
    gaps: bool,
}

impl Lenses {
    fn from_flags(audit: bool, benchmark: bool, gaps: bool) -> Self {
        if audit || benchmark || gaps {
            Self {
                audit,
                benchmark,
                gaps,
            }
        } else {
            Self {
                audit: true,
                benchmark: true,
                gaps: true,
            }
        }
    }

    fn count(&self) -> usize {
        usize::from(self.audit) + usize::from(self.benchmark) + usize::from(self.gaps)
    }
}

/// Run the selected lenses over one scan.
///
/// `--json` emits a machine-readable document, and three documents concatenated
/// is not valid JSON — so a JSON run must name exactly one lens. Erroring is the
/// honest answer: silently picking one, or emitting a malformed stream, would
/// both be worse than saying which flag is missing.
pub async fn cmd_report(
    scan_id: Option<String>,
    csv: Option<String>,
    log: Option<String>,
    json: bool,
    audit: bool,
    benchmark: bool,
    gaps: bool,
) -> Result<()> {
    let lenses = Lenses::from_flags(audit, benchmark, gaps);

    if json && lenses.count() > 1 {
        return Err(Error::Other(
            "`--json` needs exactly one lens: pass --audit, --benchmark or --gaps. \
             (The default text report runs all three; three JSON documents \
             concatenated would not be valid JSON.)"
                .into(),
        ));
    }

    // Headers only when more than one lens runs — a single-lens run should read
    // exactly like the individual command it replaces.
    let banner = |title: &str| {
        if lenses.count() > 1 {
            println!("\n═══ {title} ═══\n");
        }
    };

    if lenses.audit {
        banner("AUDIT — output quality, noise and missed PII");
        crate::app::audit::cmd_audit(csv.clone(), scan_id.clone(), log.clone(), json).await?;
    }
    if lenses.benchmark {
        banner("BENCHMARK — measurable OSINT dimensions");
        crate::app::benchmark::cmd_benchmark(scan_id.clone(), json)?;
    }
    if lenses.gaps {
        banner("GAPS — validated seeds with no evidence-backed link");
        crate::app::gap::cmd_gaps(scan_id, json)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Lenses;

    #[test]
    fn no_flags_means_every_lens() {
        // The whole point of the command: comprehensive by default, so an
        // operator who does not know all three lenses exist still sees all three.
        let l = Lenses::from_flags(false, false, false);
        assert!(l.audit && l.benchmark && l.gaps);
        assert_eq!(l.count(), 3);
    }

    #[test]
    fn naming_a_lens_selects_only_it() {
        let l = Lenses::from_flags(false, true, false);
        assert!(!l.audit && l.benchmark && !l.gaps);
        assert_eq!(l.count(), 1);
    }

    #[test]
    fn lenses_compose() {
        let l = Lenses::from_flags(true, false, true);
        assert_eq!(l.count(), 2);
        assert!(l.audit && l.gaps && !l.benchmark);
    }
}
