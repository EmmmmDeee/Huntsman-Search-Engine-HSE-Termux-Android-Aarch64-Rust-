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
