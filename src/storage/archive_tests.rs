use crate::core::entity::{Entity, EntityKind};
use crate::storage::Store;

fn open_temp() -> Store {
    Store::open(":memory:").expect("in-memory store")
}

fn make_entity(value: &str) -> Entity {
    Entity::new(EntityKind::IpAddress, value, 0.9, "test_scan")
}

#[test]
fn round_trip_archive_and_lookup() {
    let store = open_temp();
    let entities = vec![make_entity("1.2.3.4"), make_entity("5.6.7.8")];
    store
        .archive_module_result("test:ip_address:1.2.3.4", 3600, &entities, None)
        .expect("archive");
    let cached = store
        .lookup_module_result_fresh("test:ip_address:1.2.3.4")
        .expect("lookup")
        .expect("should be present");
    assert_eq!(cached.entities.len(), 2);
    assert_eq!(cached.entities[0].value, "1.2.3.4");
    assert_eq!(cached.entities[1].value, "5.6.7.8");
    assert!(cached.truncation.is_none(), "a complete answer stays complete");
}

#[test]
fn miss_on_unknown_key() {
    let store = open_temp();
    let result = store
        .lookup_module_result_fresh("nosuchkey")
        .expect("lookup");
    assert!(result.is_none());
}

#[test]
fn replace_overwrites_previous_entry() {
    let store = open_temp();
    let first = vec![make_entity("1.1.1.1")];
    let second = vec![make_entity("2.2.2.2"), make_entity("3.3.3.3")];
    store
        .archive_module_result("mod:ip_address:1.1.1.1", 3600, &first, None)
        .expect("should succeed");
    store
        .archive_module_result("mod:ip_address:1.1.1.1", 3600, &second, None)
        .expect("should succeed");
    let cached = store
        .lookup_module_result_fresh("mod:ip_address:1.1.1.1")
        .expect("should succeed")
        .expect("should succeed");
    assert_eq!(cached.entities.len(), 2);
    assert_eq!(cached.entities[0].value, "2.2.2.2");
}

#[test]
fn prune_deletes_expired_rows_and_caps_to_newest() {
    let store = open_temp();
    let e = vec![make_entity("1.1.1.1")];
    // Three still-fresh entries (ttl 3600) plus one already-expired (ttl 0).
    for key in ["A", "B", "C"] {
        store.archive_module_result(key, 3600, &e, None).expect("should succeed");
    }
    store.archive_module_result("X", 0, &e, None).expect("should succeed"); // expired on write

    // Cap to the newest 2 fresh rows: prune must delete the expired X AND one
    // excess fresh row (3 fresh − cap 2 = 1), never more.
    let pruned = store.prune_module_result_cache(2).expect("prune");
    assert_eq!(pruned, 2, "one expired + one excess row deleted");

    // The expired entry is gone regardless of which fresh rows the cap kept.
    assert!(
        store.lookup_module_result_fresh("X").expect("should succeed").is_none(),
        "expired row must be pruned"
    );
    // Exactly the cap of fresh rows survives (which two is timing-dependent on the
    // one-second archival tie-break, so assert the count, not the identity).
    let survivors = ["A", "B", "C"]
        .iter()
        .filter(|k| store.lookup_module_result_fresh(k).expect("should succeed").is_some())
        .count();
    assert_eq!(survivors, 2, "capped to the newest max_rows fresh rows");
}

#[test]
fn expired_entry_returns_none() {
    // TTL of 0 means the entry expires immediately (archived_at + 0 ≤ unixepoch()).
    let store = open_temp();
    let entities = vec![make_entity("9.9.9.9")];
    store
        .archive_module_result("mod:ip_address:9.9.9.9", 0, &entities, None)
        .expect("should succeed");
    let result = store
        .lookup_module_result_fresh("mod:ip_address:9.9.9.9")
        .expect("should succeed");
    assert!(
        result.is_none(),
        "ttl=0 entry must be treated as already expired"
    );
}

#[test]
fn a_partial_answer_is_replayed_as_partial() {
    // REQ-CACHE-001: FAILS before the fix — the cache stored the entities
    // only, and a replay within the TTL reported the module's partial answer
    // as complete.
    let store = open_temp();
    let why = "200 of 5000 retrieved — stopped by the client-side cap.";
    store
        .archive_module_result("pdns:domain:example.com", 3600, &[make_entity("1.2.3.4")], Some(why))
        .expect("archive");
    let cached = store
        .lookup_module_result_fresh("pdns:domain:example.com")
        .expect("lookup")
        .expect("fresh");
    assert_eq!(cached.entities.len(), 1);
    assert_eq!(cached.truncation.as_deref(), Some(why));
}

#[test]
fn a_row_archived_before_the_verdict_was_recorded_is_a_miss() {
    // A pre-REQ-CACHE-001 row is a bare JSON array: entities, and no record
    // of whether the answer was complete. Replaying it would claim
    // completeness on the module's behalf, so it is re-asked instead.
    let store = open_temp();
    let legacy = serde_json::to_string(&vec![make_entity("1.2.3.4")]).expect("json");
    store
        .conn
        .lock()
        .execute(
            "INSERT INTO raw_archive(id, archived_at, ttl_secs, result_json)
             VALUES('legacy', unixepoch(), 3600, ?1)",
            rusqlite::params![legacy],
        )
        .expect("insert a legacy row");
    assert!(
        store.lookup_module_result_fresh("legacy").expect("lookup").is_none(),
        "a legacy row must not be replayed with an invented verdict"
    );
    // The re-asked answer replaces it in the new shape.
    store
        .archive_module_result("legacy", 3600, &[make_entity("1.2.3.4")], None)
        .expect("archive");
    assert!(store.lookup_module_result_fresh("legacy").expect("lookup").is_some());
}
