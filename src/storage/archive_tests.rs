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
        .archive_module_result("test:ip_address:1.2.3.4", 3600, &entities)
        .expect("archive");
    let cached = store
        .lookup_module_result_fresh("test:ip_address:1.2.3.4")
        .expect("lookup")
        .expect("should be present");
    assert_eq!(cached.len(), 2);
    assert_eq!(cached[0].value, "1.2.3.4");
    assert_eq!(cached[1].value, "5.6.7.8");
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
        .archive_module_result("mod:ip_address:1.1.1.1", 3600, &first)
        .expect("should succeed");
    store
        .archive_module_result("mod:ip_address:1.1.1.1", 3600, &second)
        .expect("should succeed");
    let cached = store
        .lookup_module_result_fresh("mod:ip_address:1.1.1.1")
        .expect("should succeed")
        .expect("should succeed");
    assert_eq!(cached.len(), 2);
    assert_eq!(cached[0].value, "2.2.2.2");
}

#[test]
fn prune_deletes_expired_rows_and_caps_to_newest() {
    let store = open_temp();
    let e = vec![make_entity("1.1.1.1")];
    // Three still-fresh entries (ttl 3600) plus one already-expired (ttl 0).
    for key in ["A", "B", "C"] {
        store.archive_module_result(key, 3600, &e).expect("should succeed");
    }
    store.archive_module_result("X", 0, &e).expect("should succeed"); // expired on write

    // Cap to the newest 2 fresh rows: prune must delete the expired X AND one
    // excess fresh row (3 fresh − cap 2 = 1), never more.
    let pruned = store.prune_raw_archive(2).expect("prune");
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
        .archive_module_result("mod:ip_address:9.9.9.9", 0, &entities)
        .expect("should succeed");
    let result = store
        .lookup_module_result_fresh("mod:ip_address:9.9.9.9")
        .expect("should succeed");
    assert!(
        result.is_none(),
        "ttl=0 entry must be treated as already expired"
    );
}
