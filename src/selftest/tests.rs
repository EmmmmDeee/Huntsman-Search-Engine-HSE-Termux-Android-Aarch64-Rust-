use super::*;

    #[tokio::test]
    async fn selftest_passes_on_a_healthy_build() {
        let report = run().await;
        // No check may fail on a healthy tree. (logs.capture warns under the
        // bare test harness — that's expected and does not flip `ok`.)
        assert!(
            report.ok,
            "self-test reported failures: {}",
            report
                .checks
                .iter()
                .filter(|c| c.status == Status::Fail)
                .map(|c| format!("{}: {}", c.name, c.detail))
                .collect::<Vec<_>>()
                .join(" | ")
        );
        assert_eq!(report.failed, 0);
        assert!(report.total >= 9, "expected the full check suite");
        // The core wiring + feature checks must be PRESENT and passing.
        for required in [
            "modules.registry",
            "modules.dispatch_graph",
            "modules.consumes_accepts",
            "core.math",
            "storage.correlator",
        ] {
            let c = report
                .checks
                .iter()
                .find(|c| c.name == required)
                .expect("check present");
            assert_eq!(c.status, Status::Pass, "{required} must pass: {}", c.detail);
        }
        // Summary + render are non-empty and reflect the pass state.
        assert!(report.summary().contains("OK"));
        assert!(report.render().contains("modules.registry"));
    }
