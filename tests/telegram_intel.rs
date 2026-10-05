use std::fs;

use huntsman_recon::telegram_intel::{TelegramIndex, TelegramRecord};

fn record(peer_id: i64, message_id: i32, text: &str) -> TelegramRecord {
    TelegramRecord::new(peer_id, message_id, 1_700_000_000, text)
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("huntsman-telegram-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("scratch dir");
    path
}

#[test]
fn duplicate_message_identity_updates_in_place() {
    let mut index = TelegramIndex::new();
    assert!(index.ingest(record(42, 7, "Brisbane port first")).inserted);
    let outcome = index.ingest(record(42, 7, "Brisbane port corrected"));
    assert!(!outcome.inserted);
    assert_eq!(index.len(), 1);

    let hits = index.search("corrected", 10);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.peer_id, 42);
    assert_eq!(hits[0].record.message_id, 7);
    assert_eq!(hits[0].record.text, "Brisbane port corrected");
}

#[test]
fn local_search_requires_every_distinct_query_term_and_is_deterministic() {
    let mut index = TelegramIndex::new();
    index.ingest(record(1, 1, "Brisbane port schedule port"));
    index.ingest(record(2, 1, "Brisbane harbour notice"));
    index.ingest(record(3, 1, "Port of Sydney"));

    let hits = index.search("brisbane port", 10);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.peer_id, 1);
    assert_eq!(hits[0].score, 3);
    assert!(index.search("", 10).is_empty());
    assert!(index.search("!", 10).is_empty());
    assert!(index.search("brisbane", 0).is_empty());
}

#[test]
fn snapshot_round_trip_preserves_searchability_and_schema() {
    let root = scratch("roundtrip");
    let path = root.join("telegram-index.json");

    let mut index = TelegramIndex::new();
    index.ingest(record(77, 9, "Maleny example@example.com"));
    index.save(&path).expect("save index");

    let loaded = TelegramIndex::load(&path).expect("load index");
    assert_eq!(loaded.schema_version(), 1);
    let hits = loaded.search("maleny", 10);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.peer_id, 77);
    assert_eq!(hits[0].record.message_id, 9);

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn load_is_strict_and_load_or_new_only_defaults_missing_files() {
    let root = scratch("strict-load");
    let path = root.join("telegram-index.json");

    assert!(TelegramIndex::load(&path).is_err());
    assert!(
        TelegramIndex::load_or_new(&path)
            .expect("new index")
            .is_empty()
    );

    fs::write(&path, b"{not-json").expect("corrupt fixture");
    assert!(TelegramIndex::load(&path).is_err());
    assert!(TelegramIndex::load_or_new(&path).is_err());

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn capacity_evicts_oldest_record_deterministically() {
    let mut index = TelegramIndex::with_capacity(2).expect("capacity");
    index.ingest(TelegramRecord::new(1, 1, 100, "oldest alpha"));
    index.ingest(TelegramRecord::new(1, 2, 200, "middle beta"));
    let outcome = index.ingest(TelegramRecord::new(1, 3, 300, "newest gamma"));

    assert!(outcome.inserted);
    let evicted = outcome.evicted.expect("one eviction");
    assert_eq!(evicted.peer_id, 1);
    assert_eq!(evicted.message_id, 1);
    assert_eq!(index.len(), 2);
    assert!(index.search("oldest", 10).is_empty());
    assert_eq!(index.search("gamma", 10).len(), 1);
}
