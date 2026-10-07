use huntsman_recon::event::{Event, EventKind};
use huntsman_recon::scraper_health::{aggregate_source_health, quarantined_modules_at};

fn done(scan: &str, ts: u64, found: usize) -> Event {
    Event::new(
        scan,
        ts,
        EventKind::ModuleDone {
            module: "profile_lookup".to_string(),
            found,
        },
    )
}

#[test]
fn successful_empty_lookups_preserve_source_availability() {
    let health = aggregate_source_health(&[
        done("missing-c", 400, 0),
        done("missing-b", 300, 0),
        done("missing-a", 200, 0),
        done("known-positive", 100, 2),
    ]);
    assert!(health[0].is_yield_drifted());
    assert_eq!(health[0].consecutive_failures, 0);
    assert_eq!(quarantined_modules_at(&health, 401).len(), 0);
}

#[test]
fn actual_failures_quarantine_until_expiry_or_success() {
    let events: Vec<_> = (0..3)
        .map(|index| {
            Event::new(
                format!("failed-{index}"),
                400 - index,
                EventKind::ModuleError {
                    module: "profile_lookup".to_string(),
                    error: "timeout".to_string(),
                },
            )
        })
        .collect();
    let health = aggregate_source_health(&events);
    assert!(quarantined_modules_at(&health, 401).contains("profile_lookup"));
    assert_eq!(
        quarantined_modules_at(
            &health,
            400 + huntsman_recon::scraper_health::DRIFT_RETRY_TTL_SECS,
        )
        .len(),
        0
    );
    let recovered: Vec<_> = std::iter::once(done("recovered-empty", 500, 0))
        .chain(events)
        .collect();
    assert_eq!(
        quarantined_modules_at(&aggregate_source_health(&recovered), 501).len(),
        0
    );
}
