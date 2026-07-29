//! `hse selftest` — run the full self-validation suite ([`crate::selftest`]).
//!
//! Runs every module + feature check automatically and exits non-zero on any
//! failure, so it doubles as a CI / post-install smoke gate. `--json` emits the
//! same structured report the `GET /api/v1/selftest` endpoint returns.
//!
//! A failing run returns an `Err`, NOT a direct `std::process::exit` — the
//! binary's `main` maps any returned error to a non-zero exit, so the standalone
//! `hse selftest` exit-code contract is unchanged. The
//! distinction matters for the aggregate `hse diagnostics` command
//! ([`super::diagnostics::cmd_diagnostics`]), which invokes this as one of three
//! sections and needs a *catchable* failure: a bare `process::exit(1)` here would
//! kill the whole process mid-run, so the later `engines` section would never run
//! and the aggregate "N section(s) failed" summary would never print.

pub(super) async fn cmd_selftest(json: bool) -> crate::core::error::Result<()> {
    let report = crate::selftest::run().await;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
    } else {
        // Table → stderr so stdout stays clean for piping the `--json` form.
        eprintln!("HSE v{} — self-test\n", crate::VERSION);
        eprint!("{}", report.render());
        eprintln!();
    }
    report_to_result(&report)
}

/// Map a completed self-test [`crate::selftest::Report`] to the command's result:
/// `Ok(())` when every check passed, else an [`crate::core::error::Error::Other`]
/// naming the failure count.
///
/// Kept separate from [`cmd_selftest`]'s I/O so the pass/fail contract is
/// unit-testable and, crucially, so a failure is *returned* rather than exiting
/// the process — the aggregate `hse diagnostics` command depends on catching this
/// (see the module docs and [`super::diagnostics::cmd_diagnostics`]).
fn report_to_result(report: &crate::selftest::Report) -> crate::core::error::Result<()> {
    if report.ok {
        Ok(())
    } else {
        Err(crate::core::error::Error::Other(format!(
            "self-test failed: {} of {} checks failed",
            report.failed, report.total
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selftest::Report;

    /// Build a synthetic report with the given pass/fail tallies (no warnings),
    /// bypassing the real (private) `Report::build` so the pure result-mapping
    /// contract can be exercised without running the whole suite.
    fn report(passed: usize, failed: usize) -> Report {
        Report {
            ok: failed == 0,
            passed,
            warned: 0,
            failed,
            total: passed + failed,
            elapsed_ms: 0,
            version: "test".into(),
            checks: Vec::new(),
        }
    }

    #[test]
    fn all_passing_report_maps_to_ok() {
        assert!(report_to_result(&report(9, 0)).is_ok());
    }

    #[test]
    fn any_failure_maps_to_err_naming_the_count() {
        // The failure must be a returned `Err` (so `hse diagnostics` can catch it
        // and still run its remaining sections), never a `process::exit`.
        let err = report_to_result(&report(7, 2)).expect_err("should be an error");
        let msg = err.to_string();
        assert!(msg.contains("2 of 9"), "unexpected message: {msg}");
    }
}
