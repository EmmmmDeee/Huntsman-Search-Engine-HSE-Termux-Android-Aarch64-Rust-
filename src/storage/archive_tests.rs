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
        .unwrap();
    store
        .archive_module_result("mod:ip_address:1.1.1.1", 3600, &second)
        .unwrap();
    let cached = store
        .lookup_module_result_fresh("mod:ip_address:1.1.1.1")
        .unwrap()
        .unwrap();
    assert_eq!(cached.len(), 2);
    assert_eq!(cached[0].value, "2.2.2.2");
}

#[test]
fn expired_entry_returns_none() {
    // TTL of 0 means the entry expires immediately (archived_at + 0 ≤ unixepoch()).
    let store = open_temp();
    let entities = vec![make_entity("9.9.9.9")];
    store
        .archive_module_result("mod:ip_address:9.9.9.9", 0, &entities)
        .unwrap();
    let result = store
        .lookup_module_result_fresh("mod:ip_address:9.9.9.9")
        .unwrap();
    assert!(
        result.is_none(),
        "ttl=0 entry must be treated as already expired"
    );
}
