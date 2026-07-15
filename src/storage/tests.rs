//! Unit tests for the SQLite store.
//!
//! Split out of the module file (mechanical, behaviour-preserving) so the
//! source reads as implementation; tests reach private items via `use super::*`.

use super::*;
use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::core::event::EventKind;
use crate::core::scan::{Scan, Target, TargetKind};

fn tmp_db() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = format!(
        "{}/.huntsman-test-{}-{}.db",
        std::env::temp_dir().to_string_lossy(),
        std::process::id(),
        n
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
    path
}

fn insert_scan(store: &Store, id: &str) {
    let target = Target::new(TargetKind::Email, "x@y.com");
    let scan = Scan::new(id, target);
    store.upsert_scan(&scan).unwrap();
}

#[test]
#[cfg(unix)]
fn open_restricts_the_db_file_to_owner_only() {
    // §7 S3: the store holds PII + harvested keys, so it must not be left
    // world-readable (SQLite creates it with the process umask, often 0644).
    use std::os::unix::fs::PermissionsExt;
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "s-perm"); // a write so the -wal/-shm siblings exist too
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "the DB must be owner-only (§7 S3)");
    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[test]
#[cfg(unix)]
fn restrict_to_owner_only_logs_when_a_chmod_fails() {
    // The chmod loop in `open` is best-effort (must not block startup on a
    // transient/permission-denied failure) but must not be silent — the
    // store holds PII + harvested keys, so a failed chmod leaving it at the
    // process umask (often world-readable) deserves a trace. A chmod on a
    // nonexistent path reliably fails without needing a read-only fixture.
    let missing = format!(
        "{}/.huntsman-missing-{}-{}.db",
        std::env::temp_dir().to_string_lossy(),
        std::process::id(),
        line!()
    );
    let _ = std::fs::remove_file(&missing);
    let (_, log) = capture_warn_logs(|| restrict_to_owner_only(std::slice::from_ref(&missing)));
    assert!(
        log.contains(&missing),
        "the warning must name the failing path; got: {log:?}"
    );
    assert!(
        log.contains("failed to restrict"),
        "the warning must say why; got: {log:?}"
    );
}

#[test]
fn integrity_check_reports_ok_on_healthy_db() {
    // A fresh, written-to database must report exactly `["ok"]` — the
    // signal `hse doctor` relies on to distinguish a clean store from a
    // corrupt one (FTA E5.1 / T5).
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-ic");
    let e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "scan-ic");
    store.upsert_entity(&e).unwrap();
    assert_eq!(store.integrity_check().unwrap(), vec!["ok".to_string()]);
}

#[test]
fn entity_observed_by_two_scans_appears_in_both() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-a");
    insert_scan(&store, "scan-b");
    let mut e_a = Entity::new(EntityKind::Email, "x@y.com", 0.7, "scan-a");
    e_a.observed_at = 1000;
    store.upsert_entity(&e_a).unwrap();
    let mut e_b = Entity::new(EntityKind::Email, "x@y.com", 0.9, "scan-b");
    e_b.observed_at = 2000;
    store.upsert_entity(&e_b).unwrap();
    let from_a = store.entities_for_scan("scan-a").unwrap();
    let from_b = store.entities_for_scan("scan-b").unwrap();
    assert_eq!(from_a.len(), 1, "scan-a should still see the entity");
    assert_eq!(from_b.len(), 1, "scan-b should see the entity");
    assert_eq!(from_a[0].uid, from_b[0].uid);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn latest_completed_scan_is_deterministic_on_same_second_ties() {
    // `started_at` is 1-second resolution; two scans completing in the same second
    // must resolve `latest` deterministically (PROBLEM_TREE T2.9). Without the
    // `, id DESC` tie-break SQLite picks arbitrarily, so `hse export/diff/audit
    // latest` could resolve to a different scan on identical state.
    use crate::core::scan::ScanStatus;
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let mk = |id: &str| {
        let mut s = Scan::new(id, Target::new(TargetKind::Email, "x@y.com"));
        s.status = ScanStatus::Complete;
        s.started_at = 1_700_000_000; // identical second for both rows
        store.upsert_scan(&s).unwrap();
    };
    mk("scan-aaa");
    mk("scan-zzz");
    // id DESC tie-break ⇒ the lexicographically larger id wins on every call.
    let winner = store.latest_completed_scan().unwrap().unwrap().id;
    assert_eq!(
        winner, "scan-zzz",
        "tie must break deterministically on id DESC"
    );
    for _ in 0..5 {
        assert_eq!(
            store.latest_completed_scan().unwrap().unwrap().id,
            winner,
            "latest must be stable across repeated calls on identical state"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn latest_completed_scan_errors_loudly_on_a_corrupt_row_instead_of_reporting_none() {
    // `latest_completed_scan` backs `resolve_scan_id`'s `latest` selector
    // (`hse export/diff/audit latest`, the SPA's "open latest scan"). If the
    // one row matching `status = 'complete'` has a corrupted/schema-drifted
    // `data_json`, the function must propagate that as an `Err` — exactly
    // like the sibling `get_scan` already does via `?` — never silently
    // report `Ok(None)`, which `resolve_scan_id` turns into the misleading
    // "no completed scans in store" when a complete scan actually exists.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    {
        let conn = store.conn.lock();
        // Valid JSON (so the `json_extract(...) = 'complete'` SQL filter
        // matches and the row is selected) but missing every field `Scan`
        // requires, so `serde_json::from_str::<Scan>` fails.
        conn.execute(
            "INSERT INTO scans(id, target_kind, target_value, status, started_at, \
             finished_at, entity_count, error, data_json) \
             VALUES('scan-corrupt', 'email', 'x@y.com', 'complete', 0, 0, 0, NULL, ?1)",
            params![r#"{"status":"complete"}"#],
        )
        .unwrap();
    }
    let result = store.latest_completed_scan();
    assert!(
        result.is_err(),
        "a corrupted complete-scan row must surface as an error, not Ok(None) \
         (which resolve_scan_id would misreport as 'no completed scans'); got: {result:?}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_for_scan_orders_deterministically_on_confidence_ties() {
    // `ORDER BY confidence DESC` alone is non-deterministic when entities
    // share a confidence (the common case — e.g. every name permutation gets
    // the same score): SQLite returns tied rows in unspecified order, which
    // varies with insertion/btree order and leaks into the scan's JSON/dossier
    // output (proven end-to-end: identical scans differed only in entity
    // order). The `, uid ASC` tie-break must make retrieval order a pure
    // function of the data. Insert the same set in two different orders and
    // require identical retrieval order, sorted by (confidence desc, uid asc).
    let order_of = |insert: &[&str]| -> Vec<String> {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "s-tie");
        for v in insert {
            // Identical confidence on purpose, so uid is the only tie-break.
            store
                .upsert_entity(&Entity::new(EntityKind::Username, *v, 0.5, "s-tie"))
                .unwrap();
        }
        let got: Vec<String> = store
            .entities_for_scan("s-tie")
            .unwrap()
            .into_iter()
            .map(|e| e.uid)
            .collect();
        let _ = std::fs::remove_file(&path);
        got
    };

    let forward = order_of(&["alice", "bob", "carol", "dave", "erin"]);
    let reversed = order_of(&["erin", "dave", "carol", "bob", "alice"]);
    assert_eq!(
        forward, reversed,
        "retrieval order must not depend on insertion order"
    );

    // And it must be exactly ascending-by-uid (all confidences equal).
    let mut expected = forward.clone();
    expected.sort();
    assert_eq!(forward, expected, "tie-break must be uid ascending");
}

#[test]
fn entities_for_scan_ranks_by_corroboration_and_demotes_shared_infra() {
    // Operator-facing ranking must surface the needle, not the haystack:
    //   * a finding confirmed by several DISTINCT sources outranks an
    //     equally-(raw)-confident single-source one — the corroboration signal
    //     `c_effective()` carries, which ordering by the stored `confidence`
    //     column discarded;
    //   * a CDN/anycast edge IP is legitimately high-confidence (every infra
    //     probe agrees it exists) but it's shared infrastructure, so it sinks
    //     below subject-relevant findings regardless of how corroborated its
    //     mere existence is.
    use crate::core::entity::Evidence;
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "s-rank");

    // Multi-source identity: same RAW confidence as the single-source one below,
    // but three distinct corroborating sources lift its c_effective.
    let mut subject = Entity::new(EntityKind::Email, "subject@corp.example", 0.60, "s-rank");
    for src in ["hibp", "oathnet_pro", "smtp_vrfy"] {
        subject.add_evidence(Evidence::new(src, "breach hit"));
    }
    // Single-source identity at the identical raw confidence.
    let mut single = Entity::new(EntityKind::Email, "lonely@corp.example", 0.60, "s-rank");
    single.add_evidence(Evidence::new("oathnet_pro", "breach hit"));
    // Shared infrastructure: a Cloudflare edge IP, maximally corroborated.
    let mut cdn = Entity::new(EntityKind::IpAddress, "104.20.37.187", 0.95, "s-rank");
    for src in [
        "dns_intel",
        "shodan",
        "greynoise",
        "urlscan",
        "hackertarget",
    ] {
        cdn.add_evidence(Evidence::new(src, "resolves here"));
    }

    // Insert in an order that the OLD `confidence DESC` rule would have led with
    // the CDN IP (0.95) — proving the new ranking overrides raw confidence.
    store.upsert_entity(&cdn).unwrap();
    store.upsert_entity(&single).unwrap();
    store.upsert_entity(&subject).unwrap();

    let order: Vec<String> = store
        .entities_for_scan("s-rank")
        .unwrap()
        .into_iter()
        .map(|e| e.value)
        .collect();
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        order,
        vec![
            "subject@corp.example".to_string(), // corroborated identity first
            "lonely@corp.example".to_string(),  // single-source identity next
            "104.20.37.187".to_string(),        // shared infra demoted last
        ],
        "ranking must be (subject-relevant, then c_effective desc); got {order:?}"
    );
}

#[test]
fn scan_ids_for_entity_returns_all_observers() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "s1");
    insert_scan(&store, "s2");
    insert_scan(&store, "s3");
    let mut e = Entity::new(EntityKind::Domain, "example.com", 0.8, "s1");
    e.observed_at = 100;
    store.upsert_entity(&e).unwrap();
    let mut e = Entity::new(EntityKind::Domain, "example.com", 0.8, "s2");
    e.observed_at = 200;
    store.upsert_entity(&e).unwrap();
    let mut e = Entity::new(EntityKind::Domain, "example.com", 0.8, "s3");
    e.observed_at = 300;
    store.upsert_entity(&e).unwrap();
    let uid = &e.uid;
    let scans = store.scan_ids_for_entity(uid).unwrap();
    assert_eq!(scans.len(), 3);
    assert_eq!(scans[0], "s3");
    assert_eq!(scans[2], "s1");
    assert_eq!(store.observation_count(uid).unwrap(), 3);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entity_only_in_other_scan_does_not_leak() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "s1");
    insert_scan(&store, "s2");
    let e = Entity::new(EntityKind::Email, "only-in-s1@x.com", 0.7, "s1");
    store.upsert_entity(&e).unwrap();
    let from_s2 = store.entities_for_scan("s2").unwrap();
    assert!(from_s2.is_empty(), "s2 never observed this entity");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn re_observing_same_pair_is_idempotent() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "s1");
    let e = Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s1");
    store.upsert_entity(&e).unwrap();
    store.upsert_entity(&e).unwrap();
    store.upsert_entity(&e).unwrap();
    assert_eq!(store.observation_count(&e.uid).unwrap(), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_scan_cascade_removes_orphans_but_keeps_shared_entities() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-doomed");
    insert_scan(&store, "scan-keeper");
    let shared = Entity::new(EntityKind::Domain, "example.com", 0.8, "scan-doomed");
    store.upsert_entity(&shared).unwrap();
    let mut shared2 = Entity::new(EntityKind::Domain, "example.com", 0.8, "scan-keeper");
    shared2.observed_at = shared.observed_at + 1;
    store.upsert_entity(&shared2).unwrap();
    let only_doomed = Entity::new(EntityKind::Email, "lonely@example.com", 0.6, "scan-doomed");
    store.upsert_entity(&only_doomed).unwrap();
    assert_eq!(store.entities_for_scan("scan-doomed").unwrap().len(), 2);
    let removed = store.delete_scan("scan-doomed").unwrap();
    assert!(removed);
    let keeper = store.entities_for_scan("scan-keeper").unwrap();
    assert_eq!(keeper.len(), 1);
    assert_eq!(keeper[0].value, "example.com");
    assert!(
        store
            .scan_ids_for_entity(&only_doomed.uid)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.observation_count(&only_doomed.uid).unwrap(), 0);
    assert!(store.get_scan("scan-doomed").unwrap().is_none());
    assert!(store.get_scan("scan-keeper").unwrap().is_some());
    assert!(!store.delete_scan("scan-doomed").unwrap());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_scan_with_unknown_id_does_not_purge_orphans() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "real-scan");
    let conn = parking_lot::Mutex::new(rusqlite::Connection::open(&path).unwrap());
    {
        let c = conn.lock();
        c.execute(
                "INSERT INTO entities(uid, scan_id, kind, value, confidence, corroboration, observed_at, data_json)
                 VALUES('orphan-uid', 'real-scan', 'domain', 'orphan.example.com', 0.5, 1, 1, '{}')",
                [],
            ).unwrap();
    }
    assert!(!store.delete_scan("nonexistent-scan-id").unwrap());
    let count: i64 = {
        let c = conn.lock();
        c.query_row(
            "SELECT COUNT(*) FROM entities WHERE uid='orphan-uid'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count, 1, "delete_scan must not purge on unknown id");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn list_scans_returns_newest_first() {
    use crate::core::entity::unix_now;
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let base = unix_now();
    for (id, offset) in [("oldest", 0u64), ("middle", 100), ("newest", 200)] {
        let target = Target::new(TargetKind::Email, "x@y.com");
        let mut scan = Scan::new(id, target);
        scan.started_at = base + offset;
        store.upsert_scan(&scan).unwrap();
    }
    let scans = store.list_scans(10).unwrap();
    assert_eq!(scans.len(), 3);
    assert_eq!(scans[0].id, "newest");
    assert_eq!(scans[1].id, "middle");
    assert_eq!(scans[2].id, "oldest");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn list_scans_respects_limit() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    for i in 0..5 {
        let target = Target::new(TargetKind::Email, "x@y.com");
        let mut scan = Scan::new(format!("scan-{i}"), target);
        scan.started_at = 1000 + i as u64;
        store.upsert_scan(&scan).unwrap();
    }
    let scans = store.list_scans(2).unwrap();
    assert_eq!(scans.len(), 2, "should return exactly 2 scans");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn list_scans_empty_db_returns_empty_vec() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let scans = store.list_scans(10).unwrap();
    assert!(scans.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn radar_history_returns_only_radar_sentinel_scans_newest_first() {
    use crate::core::entity::unix_now;
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let base = unix_now();
    // Two ordinary (non-radar) scans that must NEVER appear in radar history,
    // even though one shares Coordinates/MacAddress kinds with a real value.
    let mut ordinary_email = Scan::new("ordinary-email", Target::new(TargetKind::Email, "x@y.com"));
    ordinary_email.started_at = base;
    store.upsert_scan(&ordinary_email).unwrap();
    let mut ordinary_coords = Scan::new(
        "ordinary-coords",
        Target::new(TargetKind::Coordinates, "-33.8688,151.2093"),
    );
    ordinary_coords.started_at = base + 50;
    store.upsert_scan(&ordinary_coords).unwrap();
    // The two genuine radar sentinel shapes `radar_scan_spec` produces.
    let mut radar_gps = Scan::new("radar-gps", Target::new(TargetKind::Coordinates, "0,0"));
    radar_gps.started_at = base + 100;
    store.upsert_scan(&radar_gps).unwrap();
    let mut radar_mac = Scan::new(
        "radar-mac",
        Target::new(TargetKind::MacAddress, "00:00:00:00:00:00"),
    );
    radar_mac.started_at = base + 200;
    store.upsert_scan(&radar_mac).unwrap();

    let sweeps = store.radar_history(10).unwrap();
    assert_eq!(
        sweeps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        vec!["radar-mac", "radar-gps"],
        "only the two radar-sentinel scans must be returned, newest first: {sweeps:?}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn radar_history_respects_limit() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    for i in 0..5 {
        let mut scan = Scan::new(
            format!("radar-{i}"),
            Target::new(TargetKind::Coordinates, "0,0"),
        );
        scan.started_at = 1000 + i as u64;
        store.upsert_scan(&scan).unwrap();
    }
    let sweeps = store.radar_history(2).unwrap();
    assert_eq!(sweeps.len(), 2, "should return exactly 2 sweeps");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn radar_history_empty_db_returns_empty_vec() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let sweeps = store.radar_history(10).unwrap();
    assert!(sweeps.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upsert_scan_updates_existing() {
    use crate::core::scan::ScanStatus;
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut scan = Scan::new("update-me", target);
    scan.status = ScanStatus::Running;
    store.upsert_scan(&scan).unwrap();
    scan.status = ScanStatus::Complete;
    scan.entity_count = 42;
    store.upsert_scan(&scan).unwrap();
    let fetched = store.get_scan("update-me").unwrap().unwrap();
    assert_eq!(fetched.status, ScanStatus::Complete);
    assert_eq!(fetched.entity_count, 42);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn get_scan_nonexistent_returns_none() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let result = store.get_scan("nonexistent").unwrap();
    assert!(result.is_none());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upsert_correlation_and_correlations_for_scan_round_trip() {
    use crate::core::correlator::{Correlation, Severity};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "corr-scan");
    let c = Correlation::new(
        "AU-001",
        "Test rule",
        Severity::High,
        "test desc".into(),
        vec!["uid1".into()],
        "corr-scan",
        12345,
    );
    store.upsert_correlation(&c).unwrap();
    let corrs = store.correlations_for_scan("corr-scan").unwrap();
    assert_eq!(corrs.len(), 1);
    assert_eq!(corrs[0].rule_id, "AU-001");
    assert_eq!(corrs[0].rule_name, "Test rule");
    assert_eq!(corrs[0].severity, Severity::High);
    assert_eq!(corrs[0].description, "test desc");
    assert_eq!(corrs[0].entity_uids, vec!["uid1".to_string()]);
    assert_eq!(corrs[0].scan_id, "corr-scan");
    assert_eq!(corrs[0].ts, 12345);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upsert_correlation_supersedes_growing_aggregate_cluster() {
    use crate::core::correlator::{Correlation, Severity};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "agg");
    let mk = |desc: &str, uids: Vec<&str>, ts: u64| {
        Correlation::new(
            "AU-013",
            "Local-network discovery",
            Severity::Low,
            desc.into(),
            uids.into_iter().map(String::from).collect(),
            "agg",
            ts,
        )
    };
    // Round 1: a partial cluster {A,B}.
    store
        .upsert_correlation(&mk("2 entities on the local network", vec!["A", "B"], 1))
        .unwrap();
    // Round 2: the SAME cluster grown to {A,B,C} with a new count — must
    // supersede the partial row, not add a second one.
    store
        .upsert_correlation(&mk(
            "3 entities on the local network",
            vec!["A", "B", "C"],
            2,
        ))
        .unwrap();
    let got = store.correlations_for_scan("agg").unwrap();
    assert_eq!(
        got.len(),
        1,
        "growing aggregate must collapse to one row, got {got:?}"
    );
    assert_eq!(
        got[0].entity_uids.len(),
        3,
        "the surviving row is the superset"
    );
    // A stale subset re-emission (round 1 again) is ignored.
    store
        .upsert_correlation(&mk("2 entities on the local network", vec!["A", "B"], 3))
        .unwrap();
    assert_eq!(store.correlations_for_scan("agg").unwrap().len(), 1);
    // A genuinely distinct cluster (disjoint uids) coexists as its own row.
    store
        .upsert_correlation(&mk("cluster 2", vec!["X", "Y"], 4))
        .unwrap();
    assert_eq!(
        store.correlations_for_scan("agg").unwrap().len(),
        2,
        "disjoint clusters must coexist"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn correlations_for_scan_empty_scan_returns_empty() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let corrs = store.correlations_for_scan("unknown-scan").unwrap();
    assert!(corrs.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn correlations_for_scan_orders_by_severity() {
    use crate::core::correlator::{Correlation, Severity};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "sev-scan");
    let c_low = Correlation::new(
        "R-LOW",
        "Low rule",
        Severity::Low,
        "low finding".into(),
        vec!["u1".into()],
        "sev-scan",
        100,
    );
    let c_crit = Correlation::new(
        "R-CRIT",
        "Critical rule",
        Severity::Critical,
        "critical finding".into(),
        vec!["u2".into()],
        "sev-scan",
        200,
    );
    let c_high = Correlation::new(
        "R-HIGH",
        "High rule",
        Severity::High,
        "high finding".into(),
        vec!["u3".into()],
        "sev-scan",
        300,
    );
    store.upsert_correlation(&c_low).unwrap();
    store.upsert_correlation(&c_crit).unwrap();
    store.upsert_correlation(&c_high).unwrap();
    let corrs = store.correlations_for_scan("sev-scan").unwrap();
    assert_eq!(corrs.len(), 3);
    assert_eq!(corrs[0].severity, Severity::Critical);
    assert_eq!(corrs[1].severity, Severity::High);
    assert_eq!(corrs[2].severity, Severity::Low);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn duplicate_correlation_is_ignored_upsert_idempotent() {
    use crate::core::correlator::{Correlation, Severity};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "dup-scan");
    let c = Correlation::new(
        "AU-001",
        "Test rule",
        Severity::High,
        "test desc".into(),
        vec!["uid1".into()],
        "dup-scan",
        12345,
    );
    store.upsert_correlation(&c).unwrap();
    store.upsert_correlation(&c).unwrap();
    let corrs = store.correlations_for_scan("dup-scan").unwrap();
    assert_eq!(corrs.len(), 1, "duplicate correlation should be ignored");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn event_log_round_trips_in_emission_order() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-evt");
    for (i, kind) in [
        EventKind::ScanStart {
            target_kind: "domain".into(),
            target_value: "example.com".into(),
        },
        EventKind::ModuleStart {
            module: "dns_intel".into(),
        },
        EventKind::ModuleDone {
            module: "dns_intel".into(),
            found: 3,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let mut ev = Event::new("scan-evt", kind);
        ev.ts = 1000 + i as u64;
        store.insert_event(&ev).unwrap();
    }
    let other = Event::new("scan-other", EventKind::ModuleStart { module: "x".into() });
    store.insert_event(&other).unwrap();
    let evs = store.events_for_scan("scan-evt").unwrap();
    assert_eq!(evs.len(), 3, "expected three events for scan-evt only");
    let kinds: Vec<&'static str> = evs
        .iter()
        .map(|e| match &e.kind {
            EventKind::ScanStart { .. } => "scan_start",
            EventKind::ModuleStart { .. } => "module_start",
            EventKind::ModuleDone { .. } => "module_done",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["scan_start", "module_start", "module_done"]);
    let other_evs = store.events_for_scan("scan-other").unwrap();
    assert_eq!(other_evs.len(), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn recent_module_outcome_events_filters_orders_and_bounds_across_scans() {
    // The substrate for the per-source health signal (T2.7 / SOL-HEALTH-SIGNAL):
    // only ModuleDone/ModuleError matter, newest-first, across ALL scan_ids, and
    // respecting the caller's limit.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-a");
    insert_scan(&store, "scan-b");

    let rows = [
        (
            "scan-a",
            100,
            EventKind::ScanStart {
                target_kind: "domain".into(),
                target_value: "example.com".into(),
            },
        ),
        (
            "scan-a",
            101,
            EventKind::ModuleStart {
                module: "dns_intel".into(),
            },
        ),
        (
            "scan-a",
            102,
            EventKind::ModuleDone {
                module: "dns_intel".into(),
                found: 3,
            },
        ),
        (
            "scan-b",
            200,
            EventKind::ModuleError {
                module: "shodan".into(),
                error: "timeout".into(),
            },
        ),
        (
            "scan-b",
            201,
            EventKind::ModuleSkipped {
                module: "crtsh".into(),
                reason: "no key".into(),
            },
        ),
    ];
    for (scan_id, ts, kind) in rows {
        let mut ev = Event::new(scan_id, kind);
        ev.ts = ts;
        store.insert_event(&ev).unwrap();
    }

    let outcomes = store.recent_module_outcome_events(100).unwrap();
    assert_eq!(
        outcomes.len(),
        2,
        "only module_done/module_error rows, across both scans"
    );
    // Newest first.
    assert!(matches!(
        &outcomes[0].kind,
        EventKind::ModuleError { module, .. } if module == "shodan"
    ));
    assert!(matches!(
        &outcomes[1].kind,
        EventKind::ModuleDone { module, .. } if module == "dns_intel"
    ));

    // limit is respected.
    let bounded = store.recent_module_outcome_events(1).unwrap();
    assert_eq!(bounded.len(), 1);
    assert!(matches!(&bounded[0].kind, EventKind::ModuleError { .. }));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_for_scan_recovers_from_event_log_when_not_finalised() {
    // The "Ali Kareem" failure: a scan found 558 entities but the export read
    // an empty result because the scan never finalised (a module hung / the
    // process was killed before the entities table was written). The DB-writer
    // had already durably logged every EntityFound, so entities_for_scan must
    // recover from that log instead of reporting nothing — folding duplicate
    // UIDs through merge exactly once (corroboration summed, NOT double-counted).
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-live");

    // Two distinct entities plus a DUPLICATE of the first (same kind+value =>
    // same UID), each emitted as a real-time event. Nothing is written to the
    // entities table — the scan never finalised.
    let e1 = Entity::new(EntityKind::Email, "ali@example.com", 0.70, "scan-live");
    let e1_uid = e1.uid.clone();
    let e1_again = Entity::new(EntityKind::Email, "ali@example.com", 0.65, "scan-live");
    let e2 = Entity::new(EntityKind::Person, "Ali Kareem", 0.85, "scan-live");
    for (i, entity) in [e1, e1_again, e2].into_iter().enumerate() {
        let mut ev = Event::new("scan-live", EventKind::EntityFound { entity });
        ev.ts = 2000 + i as u64;
        store.insert_event(&ev).unwrap();
    }

    // entities_for_scan transparently falls back to the event log.
    let recovered = store.entities_for_scan("scan-live").unwrap();
    assert_eq!(
        recovered.len(),
        2,
        "two distinct UIDs recovered (the duplicate folds into one)"
    );
    let email = recovered
        .iter()
        .find(|e| e.uid == e1_uid)
        .expect("recovered email entity");
    assert_eq!(
        email.corroboration, 2,
        "duplicate-UID emissions fold once: corroboration summed (1+1), not 1 (unfolded) nor >2 (double-counted)"
    );

    // The direct reconstruction agrees with the fallback.
    assert_eq!(store.entities_from_events("scan-live").unwrap().len(), 2);

    // A genuinely empty scan (no EntityFound events) recovers empty — the
    // fallback never invents a false positive.
    insert_scan(&store, "scan-empty");
    assert!(store.entities_for_scan("scan-empty").unwrap().is_empty());

    // A FINALISED scan (rows in the entities table) keeps using them, never the
    // event log: upsert one entity, log a DIFFERENT one as an event, and confirm
    // only the persisted row is returned.
    insert_scan(&store, "scan-final");
    let persisted = Entity::new(EntityKind::Email, "final@example.com", 0.9, "scan-final");
    store.upsert_entity(&persisted).unwrap();
    store
        .insert_event(&Event::new(
            "scan-final",
            EventKind::EntityFound {
                entity: Entity::new(EntityKind::Person, "Decoy Person", 0.8, "scan-final"),
            },
        ))
        .unwrap();
    let finalised = store.entities_for_scan("scan-final").unwrap();
    assert_eq!(
        finalised.len(),
        1,
        "finalised read uses the table, not events"
    );
    assert_eq!(finalised[0].value, "final@example.com");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_from_events_canonicalizes_evidence_order_regardless_of_arrival_order() {
    // C7 (forensic determinism): entities_from_events is the recovery path used
    // whenever a scan didn't finalise (routine on Termux/Android). The finalised
    // path already normalises each entity's evidence/tag order before persist
    // (core/engine/mod.rs, via Entity::canonicalize_order) so concurrent dispatch's
    // completion-order merging can't leak into the exported result — this proves
    // the recovery path gives the same guarantee, by folding the SAME two evidence
    // sources in opposite arrival order across two scans and asserting the
    // recovered entity's evidence vec is byte-identical either way.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-order-a");
    insert_scan(&store, "scan-order-b");

    let mut zzz_a = Entity::new(EntityKind::Email, "shared@example.com", 0.5, "scan-order-a");
    zzz_a.add_evidence(Evidence::new("zzz_module", "seen"));
    let mut aaa_a = Entity::new(EntityKind::Email, "shared@example.com", 0.5, "scan-order-a");
    aaa_a.add_evidence(Evidence::new("aaa_module", "seen"));

    // Scan A: zzz_module's EntityFound event arrives before aaa_module's.
    for (i, entity) in [zzz_a, aaa_a].into_iter().enumerate() {
        let mut ev = Event::new("scan-order-a", EventKind::EntityFound { entity });
        ev.ts = 3000 + i as u64;
        store.insert_event(&ev).unwrap();
    }

    // Scan B: the same two sources, reversed (aaa_module arrives first) — its
    // own entities, scan_id-tagged "scan-order-b", not clones of scan A's (
    // Entity::merge never updates scan_id, so reusing scan A's entities here
    // would recover an entity whose scan_id lies about which scan it came
    // from, masking any future regression where scan_id becomes relevant to
    // recovery/export behaviour).
    let mut zzz_b = Entity::new(EntityKind::Email, "shared@example.com", 0.5, "scan-order-b");
    zzz_b.add_evidence(Evidence::new("zzz_module", "seen"));
    let mut aaa_b = Entity::new(EntityKind::Email, "shared@example.com", 0.5, "scan-order-b");
    aaa_b.add_evidence(Evidence::new("aaa_module", "seen"));
    for (i, entity) in [aaa_b, zzz_b].into_iter().enumerate() {
        let mut ev = Event::new("scan-order-b", EventKind::EntityFound { entity });
        ev.ts = 3000 + i as u64;
        store.insert_event(&ev).unwrap();
    }

    let recovered_a = store.entities_from_events("scan-order-a").unwrap();
    let recovered_b = store.entities_from_events("scan-order-b").unwrap();
    assert_eq!(recovered_a.len(), 1);
    assert_eq!(recovered_b.len(), 1);
    let sources_a: Vec<&str> = recovered_a[0]
        .evidence
        .iter()
        .map(|ev| ev.source.as_str())
        .collect();
    let sources_b: Vec<&str> = recovered_b[0]
        .evidence
        .iter()
        .map(|ev| ev.source.as_str())
        .collect();
    assert_eq!(
        sources_a, sources_b,
        "evidence order must be canonicalised, not leak arrival order: {sources_a:?} vs {sources_b:?}"
    );
    assert_eq!(
        sources_a,
        ["aaa_module", "zzz_module"],
        "canonical order is lexicographic by source, per Entity::canonicalize_order"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn events_for_scan_returns_empty_for_unknown_id() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let evs = store.events_for_scan("never-existed").unwrap();
    assert!(evs.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_scan_cascades_to_events() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-with-events");
    insert_scan(&store, "scan-keeper");
    store
        .insert_event(&Event::new(
            "scan-with-events",
            EventKind::ModuleStart {
                module: "dns_intel".into(),
            },
        ))
        .unwrap();
    store
        .insert_event(&Event::new(
            "scan-with-events",
            EventKind::ModuleDone {
                module: "dns_intel".into(),
                found: 1,
            },
        ))
        .unwrap();
    store
        .insert_event(&Event::new(
            "scan-keeper",
            EventKind::ModuleStart {
                module: "whois".into(),
            },
        ))
        .unwrap();
    assert_eq!(store.events_for_scan("scan-with-events").unwrap().len(), 2);
    assert!(store.delete_scan("scan-with-events").unwrap());
    assert!(
        store
            .events_for_scan("scan-with-events")
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.events_for_scan("scan-keeper").unwrap().len(), 1);
    let _ = std::fs::remove_file(&path);
}

// ── Tests (from entities.rs) ───────────────────────────────────────────

#[test]
fn entities_filtered_by_kind() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "filt-scan");
    let email = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "filt-scan");
    let domain = Entity::new(EntityKind::Domain, "example.com", 0.7, "filt-scan");
    store.upsert_entity(&email).unwrap();
    store.upsert_entity(&domain).unwrap();
    let results = store
        .entities_filtered("filt-scan", Some("email"), None, None)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].kind, EntityKind::Email);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_filtered_returns_the_complete_result_not_a_capped_500() {
    // Full-fidelity: a breach-heavy scan's filtered result can exceed 500 entities;
    // the filtered query must return the COMPLETE deterministically-ordered set — it
    // is a SUBSET of the canonical `entities_for_scan`, which is itself unbounded.
    // Fail-before: a hardcoded `LIMIT 500` silently dropped the lowest-confidence
    // matches past rank 500 with no total/flag/pagination.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "big-scan");
    for i in 0..600 {
        let conf = 0.30 + (i % 50) as f64 / 100.0; // varied, exercises the ordering
        let e = Entity::new(
            EntityKind::Email,
            format!("user{i:04}@example.com"),
            conf,
            "big-scan",
        );
        store.upsert_entity(&e).unwrap();
    }
    let results = store
        .entities_filtered("big-scan", Some("email"), None, None)
        .unwrap();
    assert_eq!(
        results.len(),
        600,
        "the filtered query must return every matching entity, not a capped 500"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_filtered_by_kind_and_min_confidence() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "conf-scan");
    let low = Entity::new(EntityKind::Email, "low@example.com", 0.3, "conf-scan");
    let high = Entity::new(EntityKind::Email, "high@example.com", 0.9, "conf-scan");
    store.upsert_entity(&low).unwrap();
    store.upsert_entity(&high).unwrap();
    let results = store
        .entities_filtered("conf-scan", Some("email"), Some(0.5), None)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "high@example.com");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_filtered_by_kind_min_conf_and_value() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "val-scan");
    let alice = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "val-scan");
    let bob = Entity::new(EntityKind::Email, "bob@test.com", 0.8, "val-scan");
    store.upsert_entity(&alice).unwrap();
    store.upsert_entity(&bob).unwrap();
    let results = store
        .entities_filtered("val-scan", Some("email"), Some(0.1), Some("alice"))
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "alice@example.com");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_filtered_min_confidence_without_kind() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "gap-scan");
    let low = Entity::new(EntityKind::Email, "lo@y.com", 0.2, "gap-scan");
    let high = Entity::new(EntityKind::Domain, "hi.com", 0.9, "gap-scan");
    store.upsert_entity(&low).unwrap();
    store.upsert_entity(&high).unwrap();
    let results = store
        .entities_filtered("gap-scan", None, Some(0.5), None)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "hi.com");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_filtered_value_contains_without_kind() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "vc-scan");
    let alice = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "vc-scan");
    let bob = Entity::new(EntityKind::Email, "bob@test.com", 0.8, "vc-scan");
    store.upsert_entity(&alice).unwrap();
    store.upsert_entity(&bob).unwrap();
    let results = store
        .entities_filtered("vc-scan", None, None, Some("alice"))
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "alice@example.com");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entities_filtered_with_no_filters_returns_all() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "all-scan");
    let e1 = Entity::new(EntityKind::Email, "a@example.com", 0.8, "all-scan");
    let e2 = Entity::new(EntityKind::Domain, "example.com", 0.7, "all-scan");
    let e3 = Entity::new(EntityKind::Phone, "+61400000000", 0.6, "all-scan");
    store.upsert_entity(&e1).unwrap();
    store.upsert_entity(&e2).unwrap();
    store.upsert_entity(&e3).unwrap();
    let results = store
        .entities_filtered("all-scan", None, None, None)
        .unwrap();
    assert_eq!(results.len(), 3, "all three entities should be returned");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entity_facets_counts_by_kind() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "facet-scan");
    let e1 = Entity::new(EntityKind::Email, "a@example.com", 0.8, "facet-scan");
    let e2 = Entity::new(EntityKind::Email, "b@example.com", 0.7, "facet-scan");
    let e3 = Entity::new(EntityKind::Domain, "example.com", 0.6, "facet-scan");
    store.upsert_entity(&e1).unwrap();
    store.upsert_entity(&e2).unwrap();
    store.upsert_entity(&e3).unwrap();
    let facets = store.entity_facets("facet-scan").unwrap();
    assert_eq!(facets.len(), 2);
    assert_eq!(facets[0].0, "email");
    assert_eq!(facets[0].1, 2);
    assert_eq!(facets[1].0, "domain");
    assert_eq!(facets[1].1, 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn get_entity_found() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "get-scan");
    let e = Entity::new(EntityKind::Email, "found@example.com", 0.8, "get-scan");
    let uid = e.uid.clone();
    store.upsert_entity(&e).unwrap();
    let fetched = store.get_entity(&uid).unwrap().unwrap();
    assert_eq!(fetched.uid, uid);
    assert_eq!(fetched.value, "found@example.com");
    assert_eq!(fetched.kind, EntityKind::Email);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entity_survives_a_full_fidelity_storage_roundtrip() {
    use crate::core::entity::{Evidence, derive_uid, normalise};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "rt");
    // Exercise every field that a lossy persistence layer could drop or
    // reorder: a `raw_value` that differs from the normalised value, ordered
    // evidence attributes, multiple tags, and a non-unit corroboration.
    let mut e = Entity::new(EntityKind::Email, "Found.User+Tag@Example.COM", 0.83, "rt");
    e.corroboration = 4;
    e.tag("breach");
    e.tag("au:source");
    e.add_evidence(
        Evidence::new("hibp", "breach hit")
            .with_attr("zbreach", "Z")
            .with_attr("abreach", "A"),
    );
    e.add_evidence(Evidence::new("hunter_io", "verified"));
    let uid = e.uid.clone();

    // The strongest single invariant: serialise → persist → reload →
    // serialise must be byte-identical. Catches any dropped/reordered field.
    let before = serde_json::to_string(&e).unwrap();
    store.upsert_entity(&e).unwrap();
    let got = store.get_entity(&uid).unwrap().unwrap();
    assert_eq!(
        before,
        serde_json::to_string(&got).unwrap(),
        "storage round-trip changed the entity"
    );
    // The persisted UID must remain reconstructible from its (kind, value),
    // so a reloaded entity still dedups against a freshly-derived one.
    assert_eq!(
        got.uid,
        derive_uid(&got.kind, &normalise(&got.kind, &got.value))
    );
    // The human-facing display value survives, distinct from the normalised
    // dedup key.
    assert_eq!(got.value, "found.user+tag@example.com");
    assert_eq!(got.raw_value, "Found.User+Tag@Example.COM");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn get_entity_not_found() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let result = store.get_entity("nonexistent-uid").unwrap();
    assert!(result.is_none());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn search_entities_matches_substring() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "search-scan");
    let e1 = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "search-scan");
    let e2 = Entity::new(EntityKind::Email, "bob@test.com", 0.7, "search-scan");
    let e3 = Entity::new(EntityKind::Domain, "alice-domain.com", 0.6, "search-scan");
    store.upsert_entity(&e1).unwrap();
    store.upsert_entity(&e2).unwrap();
    store.upsert_entity(&e3).unwrap();
    let results = store.search_entities("alice", 10).unwrap();
    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(
            r.value.contains("alice"),
            "result '{}' should contain 'alice'",
            r.value
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn search_entities_respects_limit() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "lim-scan");
    for i in 0..5 {
        let e = Entity::new(
            EntityKind::Email,
            format!("user{i}@matching.com"),
            0.8,
            "lim-scan",
        );
        store.upsert_entity(&e).unwrap();
    }
    let results = store.search_entities("matching", 1).unwrap();
    assert_eq!(results.len(), 1, "should return exactly 1 result");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn search_entities_empty_query_returns_nothing() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "empty-scan");
    let e = Entity::new(EntityKind::Email, "x@y.com", 0.8, "empty-scan");
    store.upsert_entity(&e).unwrap();
    let results = store.search_entities("zzzz_no_match_xyzzy_42", 10).unwrap();
    assert!(results.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn escape_like_neutralises_all_metacharacters() {
    // `\` first, then `%`/`_` — order matters so the added escapes aren't
    // themselves re-escaped.
    assert_eq!(super::escape_like("a%b_c"), "a\\%b\\_c");
    assert_eq!(super::escape_like("back\\slash"), "back\\\\slash");
    assert_eq!(super::escape_like("100%_\\"), "100\\%\\_\\\\");
    assert_eq!(super::escape_like("plain"), "plain"); // no-op on ordinary text
}

#[test]
fn search_like_fallback_escapes_backslash() {
    // A bare `\` query has no FTS tokens, so it exercises the LIKE fallback.
    // It must match a literal backslash, not (mis-escaped) a `%`.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "bs");
    store
        .upsert_entity(&Entity::new(EntityKind::Username, "back\\slash", 0.9, "bs"))
        .unwrap();
    store
        .upsert_entity(&Entity::new(EntityKind::Username, "plainname", 0.9, "bs"))
        .unwrap();
    let hits = store.search_entities("\\", 10).unwrap();
    assert!(
        hits.iter().any(|e| e.value == "back\\slash"),
        "backslash query must match a literal backslash: {hits:?}"
    );
    assert!(
        hits.iter().all(|e| e.value.contains('\\')),
        "must not match values without a backslash: {hits:?}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fts_prefix_token_search_matches_partial_word() {
    // FTS5 path: a partial word token must hit via prefix matching — what
    // the old LIKE-only search could only do as an anchored substring.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "fts-scan");
    store
        .upsert_entity(&Entity::new(
            EntityKind::Person,
            "Jordan Meyer",
            0.9,
            "fts-scan",
        ))
        .unwrap();
    // Token prefix: "jord" -> "Jordan"; "mey" -> "Meyer".
    assert_eq!(store.search_entities("jord", 10).unwrap().len(), 1);
    assert_eq!(store.search_entities("mey", 10).unwrap().len(), 1);
    // A non-matching token returns nothing (and doesn't fall through to a
    // spurious LIKE hit).
    assert!(store.search_entities("smith", 10).unwrap().is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fts_matches_tokens_in_any_order_unlike_like() {
    // FTS-ONLY capability: a multi-token query matches regardless of word
    // order ("meyer jordan" finds "Jordan Meyer"). A substring LIKE of the
    // raw query CANNOT — "%meyer jordan%" never matches "Jordan Meyer".
    // This isolates the FTS path from the LIKE fallback.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "order-scan");
    store
        .upsert_entity(&Entity::new(
            EntityKind::Person,
            "Jordan Meyer",
            0.9,
            "order-scan",
        ))
        .unwrap();
    assert_eq!(
        store.search_entities("meyer jordan", 10).unwrap().len(),
        1,
        "FTS must match tokens in any order; the LIKE fallback alone cannot"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fts_index_stays_synchronized_on_value_change() {
    // The FTS index must track entity-value changes inside the same write
    // (the 'always-synchronized index' invariant). Simulate a value change
    // by writing two entities that share a uid-determining identity is not
    // possible (uid derives from value), so instead verify a freshly
    // inserted entity is immediately searchable and a rebuild is a no-op.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "sync-scan");
    store
        .upsert_entity(&Entity::new(
            EntityKind::Domain,
            "syncexample.org",
            0.8,
            "sync-scan",
        ))
        .unwrap();
    // Immediately visible via FTS, no separate index step.
    assert_eq!(store.search_entities("syncexample", 10).unwrap().len(), 1);
    // Re-upsert the same entity (merge path) — index must remain correct,
    // not duplicate.
    store
        .upsert_entity(&Entity::new(
            EntityKind::Domain,
            "syncexample.org",
            0.9,
            "sync-scan",
        ))
        .unwrap();
    assert_eq!(
        store.search_entities("syncexample", 10).unwrap().len(),
        1,
        "merge must not duplicate the FTS row"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fts_backfill_indexes_preexisting_rows() {
    // A DB whose entities predate the FTS index must become searchable
    // after reopen (the open() backfill path).
    let path = tmp_db();
    {
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "bf-scan");
        store
            .upsert_entity(&Entity::new(
                EntityKind::Username,
                "backfilluser",
                0.7,
                "bf-scan",
            ))
            .unwrap();
        // Drop the FTS table to emulate a pre-index DB, then reopen.
        let conn = store.conn.lock();
        conn.execute_batch("DROP TABLE entities_fts;").unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(
        store.search_entities("backfill", 10).unwrap().len(),
        1,
        "reopen must backfill the FTS index from existing rows"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upsert_entity_cross_scan_merge_preserves_evidence_and_tags() {
    use crate::core::entity::Evidence;
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-a");
    insert_scan(&store, "scan-b");
    let mut e_a = Entity::new(EntityKind::Email, "shared@example.com", 0.6, "scan-a");
    e_a.add_evidence(Evidence::new("module_a", "found in source A"));
    e_a.tag("tag-a");
    store.upsert_entity(&e_a).unwrap();
    let mut e_b = Entity::new(EntityKind::Email, "shared@example.com", 0.9, "scan-b");
    e_b.add_evidence(Evidence::new("module_b", "found in source B"));
    e_b.tag("tag-b");
    store.upsert_entity(&e_b).unwrap();
    let merged = store.get_entity(&e_a.uid).unwrap().unwrap();
    assert!(
        (merged.confidence - 0.9).abs() < 1e-9,
        "confidence should be max(0.6, 0.9) = 0.9, got {}",
        merged.confidence
    );
    assert_eq!(merged.corroboration, 2, "corroboration should accumulate");
    let sources: Vec<&str> = merged.evidence.iter().map(|e| e.source.as_str()).collect();
    assert!(
        sources.contains(&"module_a"),
        "evidence from scan-a must survive merge: {sources:?}"
    );
    assert!(
        sources.contains(&"module_b"),
        "evidence from scan-b must survive merge: {sources:?}"
    );
    assert!(merged.has_tag("tag-a"), "tag-a must survive merge");
    assert!(merged.has_tag("tag-b"), "tag-b must survive merge");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upsert_entity_merge_result_is_insertion_order_independent() {
    // `merge_and_persist_entity`'s slow (ON CONFLICT) path merges the
    // incoming entity into the already-stored one via `Entity::merge`, whose
    // `absorb` appends evidence/tags in whatever order the two sides happen
    // to arrive in (see `Entity::absorb`'s doc comment) — so without a
    // re-canonicalisation after the merge, which of two same-uid entities
    // reaches storage FIRST leaks into the persisted evidence/tag order.
    // `entities_from_events` already re-canonicalises after its own in-memory
    // merge fold; this pins the same guarantee for the direct storage-merge
    // path. Insert the same two entities in both orders and require
    // byte-identical persisted evidence/tag order either way.
    use crate::core::entity::Evidence;
    let persisted_order = |first_source: &str, second_source: &str| -> (Vec<String>, Vec<String>) {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "order-scan");
        let mut a = Entity::new(EntityKind::Email, "dup@x.com", 0.5, "order-scan");
        a.add_evidence(Evidence::new(first_source, "seen"));
        a.tag("z-tag");
        store.upsert_entity(&a).unwrap();
        let mut b = Entity::new(EntityKind::Email, "dup@x.com", 0.5, "order-scan");
        b.add_evidence(Evidence::new(second_source, "seen"));
        b.tag("a-tag");
        store.upsert_entity(&b).unwrap();
        let merged = store.get_entity(&a.uid).unwrap().unwrap();
        let _ = std::fs::remove_file(&path);
        (
            merged.evidence.iter().map(|e| e.source.clone()).collect(),
            merged.tags,
        )
    };
    let forward = persisted_order("mod_a", "mod_b");
    let reversed = persisted_order("mod_b", "mod_a");
    assert_eq!(
        forward, reversed,
        "persisted evidence/tag order must not depend on which same-uid entity was upserted first"
    );
}

// ── upsert_entities_batch ──────────────────────────────────────────────

#[test]
fn upsert_entities_batch_persists_all_and_records_observations() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "batch-scan");
    let entities = vec![
        Entity::new(EntityKind::Email, "a@x.com", 0.8, "batch-scan"),
        Entity::new(EntityKind::Domain, "x.com", 0.7, "batch-scan"),
        Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "batch-scan"),
    ];
    let n = store.upsert_entities_batch(&entities).unwrap();
    assert_eq!(n, 3, "batch should report every entity persisted");
    let got = store.entities_for_scan("batch-scan").unwrap();
    assert_eq!(got.len(), 3);
    // The observation junction must be populated for every entity, exactly
    // as the per-entity upsert path does.
    for e in &entities {
        assert_eq!(store.observation_count(&e.uid).unwrap(), 1);
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upsert_entities_batch_merges_on_conflict() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "bm-scan");
    let first = Entity::new(EntityKind::Email, "dup@x.com", 0.5, "bm-scan");
    store.upsert_entity(&first).unwrap();
    // Same uid, higher confidence → GREATEST-merge through the batch path.
    let again = Entity::new(EntityKind::Email, "dup@x.com", 0.9, "bm-scan");
    let n = store
        .upsert_entities_batch(std::slice::from_ref(&again))
        .unwrap();
    assert_eq!(n, 1);
    let merged = store.get_entity(&first.uid).unwrap().unwrap();
    assert!(
        (merged.confidence - 0.9).abs() < 1e-9,
        "GREATEST-merge must apply inside the batch path"
    );
    assert_eq!(
        merged.corroboration, 2,
        "corroboration must accumulate through the batch path"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn upsert_entities_batch_empty_is_zero() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    assert_eq!(store.upsert_entities_batch(&[]).unwrap(), 0);
    let _ = std::fs::remove_file(&path);
}

// ── relations ──────────────────────────────────────────────────────────

#[test]
fn relation_round_trip_and_idempotent_upsert() {
    use crate::core::relation::{Relation, RelationKind};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "rel-scan");
    let r = Relation::new(
        "childUid",
        "parentUid",
        RelationKind::SubdomainOf,
        0.8,
        "rel-scan",
    );
    store.upsert_relation(&r).unwrap();
    // Re-inserting the same deterministic id is a no-op (no duplicate row).
    store.upsert_relation(&r).unwrap();
    let got = store.relations_for_scan("rel-scan").unwrap();
    assert_eq!(got.len(), 1, "idempotent on deterministic id");
    assert_eq!(got[0].from_uid, "childUid");
    assert_eq!(got[0].to_uid, "parentUid");
    assert_eq!(got[0].kind, RelationKind::SubdomainOf);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn relations_for_scan_is_scan_scoped() {
    use crate::core::relation::{Relation, RelationKind};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "rs-a");
    insert_scan(&store, "rs-b");
    store
        .upsert_relation(&Relation::new(
            "a",
            "b",
            RelationKind::HostedOn,
            1.0,
            "rs-a",
        ))
        .unwrap();
    assert_eq!(store.relations_for_scan("rs-a").unwrap().len(), 1);
    assert!(store.relations_for_scan("rs-b").unwrap().is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_scan_cascades_to_relations() {
    use crate::core::relation::{Relation, RelationKind};
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "rd-scan");
    store
        .upsert_relation(&Relation::new(
            "x",
            "y",
            RelationKind::BelongsToDomain,
            0.9,
            "rd-scan",
        ))
        .unwrap();
    assert_eq!(store.relations_for_scan("rd-scan").unwrap().len(), 1);
    assert!(store.delete_scan("rd-scan").unwrap());
    assert!(store.relations_for_scan("rd-scan").unwrap().is_empty());
    let _ = std::fs::remove_file(&path);
}
/// Characterisation: pins the EXACT schema (tables + indexes) and the
/// connection pragmas a freshly-opened store produces, so the `Store::open`
/// refactor that lifts the DDL into a constant can be proven schema-identical.
#[test]
fn open_produces_exact_schema_and_pragmas() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let conn = store.conn.lock();
    let mut stmt = conn
        .prepare("SELECT type || '|' || name FROM sqlite_master ORDER BY type, name")
        .unwrap();
    let got: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    drop(stmt);
    let expected = [
        "index|idx_corr_scan",
        "index|idx_entities_kind",
        "index|idx_entities_scan",
        "index|idx_events_scan",
        "index|idx_events_type",
        "index|idx_obs_entity",
        "index|idx_obs_scan",
        "index|idx_relations_scan",
        "index|idx_scans_started",
        "index|idx_stealer_rows_log",
        "index|idx_stealer_rows_scan",
        "index|sqlite_autoindex_correlations_1",
        "index|sqlite_autoindex_entities_1",
        "index|sqlite_autoindex_entity_observations_1",
        "index|sqlite_autoindex_pathway_templates_1",
        "index|sqlite_autoindex_raw_archive_1",
        "index|sqlite_autoindex_relations_1",
        "index|sqlite_autoindex_scans_1",
        "table|correlations",
        "table|entities",
        "table|entities_fts",
        "table|entities_fts_config",
        "table|entities_fts_data",
        "table|entities_fts_docsize",
        "table|entities_fts_idx",
        "table|entity_observations",
        "table|events",
        "table|pathway_templates",
        "table|raw_archive",
        "table|relations",
        "table|scans",
        "table|sqlite_sequence",
        // `PRAGMA optimize` (run at open — see `Store::open`) materialises
        // the query-planner statistics tables. The bundled SQLite shipped
        // with rusqlite ≥0.39 creates both stat1 and stat4 here; very early
        // bundles left a fresh DB without them. Benign — these only feed the
        // planner, no app data, and improve query plans on Termux.
        "table|sqlite_stat1",
        "table|sqlite_stat4",
        "table|stealer_rows",
    ];
    assert_eq!(got, expected, "schema (tables + indexes) must be identical");

    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    let jm: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1, "foreign_keys must stay ON");
    assert_eq!(jm, "wal", "journal_mode must stay WAL");
    drop(conn);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn wal_autocheckpoint_bound_is_asserted() {
    // The WAL bound must be explicit (512 pages), not SQLite's implicit
    // 1000-page default — the 'WAL+checkpoint, everything bounded'
    // invariant.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    let n: i64 = {
        let conn = store.conn.lock();
        conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(
        n, 512,
        "WAL autocheckpoint must be the asserted 512-page bound"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_truncate_resets_wal_file_and_keeps_data() {
    // checkpoint_truncate() must reset the -wal file to zero bytes (PASSIVE
    // autocheckpoint never shrinks it) without losing durable data.
    let path = tmp_db();
    let wal = format!("{path}-wal");
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "wal-scan");
    // Force the WAL to grow: many separate commits, each appending frames.
    for i in 0..300 {
        store
            .upsert_entity(&Entity::new(
                EntityKind::Email,
                format!("user{i}@example.com"),
                0.5,
                "wal-scan",
            ))
            .unwrap();
    }
    let pre = std::fs::metadata(&wal).map_or(0, |m| m.len());
    assert!(
        pre > 0,
        "WAL should hold frames before checkpoint (was {pre})"
    );

    store.checkpoint_truncate().unwrap();

    let post = std::fs::metadata(&wal).map_or(0, |m| m.len());
    assert_eq!(post, 0, "TRUNCATE checkpoint must reset the -wal to zero");
    // Data survived the fold-back into the main DB.
    assert_eq!(
        store.entities_for_scan("wal-scan").unwrap().len(),
        300,
        "checkpoint must not lose committed entities"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

#[test]
fn search_entities_never_errors_on_adversarial_queries() {
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "adv");
    for v in [
        "Jordan Meyer",
        "example.com",
        "AND",
        "NEAR test",
        "中文名字",
    ] {
        store
            .upsert_entity(&Entity::new(EntityKind::Person, v, 0.9, "adv"))
            .unwrap();
    }
    for q in [
        "\"",
        "*",
        "(",
        ")",
        "AND",
        "OR",
        "NOT",
        "a AND b",
        "NEAR(a b)",
        "foo*bar",
        "中文",
        "col:val",
        "^abc",
        "a OR b OR",
        "(((",
        "'; DROP TABLE entities;--",
        "😀emoji",
        "a.b@c.d",
        "\"\"\"",
        "x\"*y",
    ] {
        store
            .search_entities(q, 10)
            .unwrap_or_else(|e| panic!("search_entities({q:?}) ERRORED: {e}"));
    }
    // entities table still present after the injection-y query
    assert!(!store.search_entities("jordan", 10).unwrap().is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_scan_syncs_fts_so_rowid_reuse_cannot_poison_search() {
    // A contentless-external FTS5 index never observes a bare DELETE on its
    // content table. If delete_scan purges orphaned entities without emitting
    // the FTS 'delete' commands, the stale posting survives — and once SQLite
    // reuses the freed rowid for a new entity, a search for the DELETED value
    // returns that unrelated entity. Reproduce exactly that rowid-reuse
    // scenario and prove the index stays clean.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();

    insert_scan(&store, "scan-old");
    store
        .upsert_entity(&Entity::new(
            EntityKind::Person,
            "Jordan Meyer",
            0.9,
            "scan-old",
        ))
        .unwrap();
    assert_eq!(store.search_entities("jordan", 10).unwrap().len(), 1);

    // Purge the scan — the entity is orphaned and deleted; its rowid (the
    // table's highest) is freed for reuse.
    assert!(store.delete_scan("scan-old").unwrap());

    // New entity takes the freed rowid.
    insert_scan(&store, "scan-new");
    store
        .upsert_entity(&Entity::new(
            EntityKind::Person,
            "Casey Smith",
            0.9,
            "scan-new",
        ))
        .unwrap();

    // The deleted value must match NOTHING — a stale posting would join the
    // reused rowid and hand back "Casey Smith" for a "jordan" query.
    assert!(
        store.search_entities("jordan", 10).unwrap().is_empty(),
        "deleted entity's text must not resolve to the entity that reused its rowid"
    );
    // The new entity is still searchable normally.
    let hits = store.search_entities("casey", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].value, "Casey Smith");
    // And FTS5's own structural audit agrees the index matches the content
    // table ('integrity-check' errors on any desync).
    {
        let conn = store.conn.lock();
        conn.execute_batch(
            "INSERT INTO entities_fts(entities_fts, rank) VALUES('integrity-check', 1);",
        )
        .expect("FTS index must match the entities content table after delete_scan");
    }
    let _ = std::fs::remove_file(&path);
}

/// A `MakeWriter` that tees formatted log lines into a shared buffer, so a
/// test can assert on what a scoped `tracing` subscriber actually emitted
/// without touching the process-global subscriber. Mirrors the pattern
/// established in `core::engine::tests::module_dispatch_is_logged_...`.
#[derive(Clone)]
struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl tracing_subscriber::fmt::MakeWriter<'_> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

fn capture_warn_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(VecWriter(std::sync::Arc::clone(&buf)))
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    let log = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    (out, log)
}

#[test]
fn deserialize_rows_drops_corrupt_json_but_logs_the_failure() {
    // Every multi-row reader used to swallow a bad `data_json` row via a
    // bare `.filter_map(|s| serde_json::from_str(&s).ok())`, with zero
    // trace — the same "search is broken, no diagnostic" failure mode the
    // FTS-rebuild path already treats as unacceptable. `deserialize_rows`
    // must keep the "one bad row must not fail the whole page" behaviour
    // AND leave a trace naming the caller; a bare filter_map would pass the
    // first assertion here but not the second.
    #[derive(serde::Deserialize)]
    struct Probe {
        uid: String,
    }
    let raw = vec![
        r#"{"uid":"e1"}"#.to_string(),
        "not valid json".to_string(),
        r#"{"uid":"e2"}"#.to_string(),
    ];
    let (out, log) = capture_warn_logs(|| deserialize_rows::<Probe>(raw, "test_probe_deserialize"));

    assert_eq!(
        out.iter().map(|p| p.uid.as_str()).collect::<Vec<_>>(),
        vec!["e1", "e2"],
        "the well-formed rows must survive, in order, around the corrupt one"
    );
    assert!(
        log.contains("test_probe_deserialize"),
        "dropped-row warning must be keyed by the caller's context; got: {log:?}"
    );
    assert!(
        log.contains("failed to deserialize"),
        "dropped-row warning must say why; got: {log:?}"
    );
}

#[test]
fn collect_rows_drops_sql_errors_but_logs_the_failure() {
    // Mirror of the deserialize_rows test above, for the SQL-extraction
    // layer: a genuine per-row read error (e.g. a corrupt column) must be
    // dropped without failing the whole page, but must not vanish silently.
    let rows: Vec<rusqlite::Result<String>> = vec![
        Ok("a".to_string()),
        Err(rusqlite::Error::QueryReturnedNoRows),
        Ok("b".to_string()),
    ];
    let (out, log) = capture_warn_logs(|| collect_rows(rows.into_iter(), "test_probe_collect"));

    assert_eq!(out, vec!["a".to_string(), "b".to_string()]);
    assert!(
        log.contains("test_probe_collect"),
        "dropped-row warning must be keyed by the caller's context; got: {log:?}"
    );
    assert!(
        log.contains("failed to read a stored row"),
        "dropped-row warning must say why; got: {log:?}"
    );
}

#[test]
fn list_scans_drops_a_corrupt_row_end_to_end_without_erroring() {
    // Integration-level proof that the collect_rows/deserialize_rows wiring
    // in `list_scans` is real, not just exercised in isolation above: a
    // corrupt `data_json` row inserted directly (bypassing upsert_scan)
    // must not error or panic the read, and the well-formed sibling row
    // must still come back.
    let path = tmp_db();
    let store = Store::open(&path).unwrap();
    insert_scan(&store, "scan-good");
    {
        let conn = store.conn.lock();
        conn.execute(
            "INSERT INTO scans(id, target_kind, target_value, status, started_at, \
             finished_at, entity_count, error, data_json) \
             VALUES('scan-corrupt', 'email', 'x@y.com', 'completed', 0, NULL, 0, NULL, ?1)",
            params!["not valid json"],
        )
        .unwrap();
    }
    let scans = store
        .list_scans(10)
        .expect("a corrupt sibling row must not fail the whole read");
    assert_eq!(scans.len(), 1, "only the well-formed row must be returned");
    assert_eq!(scans[0].id, "scan-good");
    let _ = std::fs::remove_file(&path);
}
