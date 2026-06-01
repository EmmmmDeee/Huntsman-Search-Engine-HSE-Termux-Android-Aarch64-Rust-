//! `hse selftest` — run the full self-validation suite ([`crate::selftest`]).
//!
//! Runs every module + feature check automatically and exits non-zero on any
//! failure, so it doubles as a CI / post-install smoke gate. `--json` emits the
//! same structured report the `GET /api/v1/selftest` endpoint returns.

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
    if !report.ok {
        std::process::exit(1);
    }
    Ok(())
}
