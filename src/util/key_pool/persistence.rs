//! Pool persistence: load from / save to `~/.huntsman/key_pool.json`.

use std::collections::HashMap;
use std::path::PathBuf;

use super::KeyEntry;
use super::pool::{KeyPool, PoolData};

pub fn pool_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".huntsman");
    // 0700 (owner-only): `~/.huntsman` holds the key pool and intelligence DB, so
    // a world-readable default-umask (0755) dir would let another local user
    // enumerate its contents. The `key_pool.json` file itself is already 0600.
    let _ = crate::util::atomic_file::create_dir_private(&dir);
    dir.join("key_pool.json")
}

pub fn load_pool() -> KeyPool {
    let path = pool_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return KeyPool::new(),
    };

    if let Some((data, dropped)) = parse_pool_text(&content) {
        if dropped > 0 {
            tracing::warn!(
                "key pool at {}: dropped {dropped} unreadable entr(ies), kept the rest",
                path.display()
            );
        }
        return KeyPool::from_data(data);
    }

    // Not even a recoverable pool object → back up under a UNIQUE (timestamped)
    // name so a second failed load can't clobber the only prior backup, then
    // start fresh.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let backup = path.with_extension(format!("json.bak.{stamp}"));
    tracing::warn!(
        "key pool at {} is not valid JSON; backing up to {} and starting fresh",
        path.display(),
        backup.display()
    );
    let _ = std::fs::rename(&path, &backup);
    KeyPool::new()
}

/// Shape mirror of [`PoolData`] whose entries stay raw [`serde_json::Value`]s, so
/// the lenient salvage can deserialize the *recoverable* entries one-by-one even
/// when a sibling entry is unreadable (e.g. an unknown `status` enum written by a
/// newer build and read back by a downgrade).
///
/// `deny_unknown_fields` is load-bearing: without it, a bare `{svc: [..]}` map
/// (no `services` key) would parse as this struct with `services` defaulting to
/// empty and silently swallow the whole file. Denying unknown fields makes such a
/// file fail this parse so it falls through to the bare-map interpretation.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPoolData {
    #[serde(default)]
    services: HashMap<String, Vec<serde_json::Value>>,
}

/// Parse pool JSON, tolerating a single unreadable entry. Returns the recovered
/// [`PoolData`] together with the number of entries dropped during salvage, or
/// `None` when the text is not even a recoverable pool object (the caller then
/// backs the file up and starts fresh).
///
/// A strict [`PoolData`] parse is tried first — the overwhelmingly common clean
/// case (0 dropped). If that fails because ONE entry is unreadable, a strict parse
/// of the whole file would discard EVERY harvested key; instead the services map
/// is re-read with each entry as raw JSON and only the unreadable ones are
/// dropped. Both the canonical `{"services": {svc: [..]}}` shape that `save_pool`
/// writes AND a bare `{svc: [..]}` map are accepted, so a hand-edited or legacy
/// file still salvages.
///
/// Extracted from `load_pool` (which owns the file IO and backup) so the recovery
/// logic is pure and unit-tested without touching `$HOME`.
fn parse_pool_text(content: &str) -> Option<(PoolData, usize)> {
    // Strict parse first — the overwhelmingly common clean case.
    if let Ok(data) = serde_json::from_str::<PoolData>(content) {
        return Some((data, 0));
    }

    // Lenient salvage: a SINGLE unreadable entry must NOT discard EVERY harvested
    // key. Accept the wrapped `{"services": {..}}` shape (the format `save_pool`
    // persists) first, then a bare `{svc: [..]}` map, re-reading each entry as raw
    // JSON so the readable siblings survive.
    let raw = serde_json::from_str::<RawPoolData>(content)
        .map(|r| r.services)
        .or_else(|_| serde_json::from_str::<HashMap<String, Vec<serde_json::Value>>>(content))
        .ok()?;

    let mut services: HashMap<String, Vec<KeyEntry>> = HashMap::new();
    let mut dropped = 0usize;
    for (svc, entries) in raw {
        let good: Vec<KeyEntry> = entries
            .into_iter()
            .filter_map(|v| match serde_json::from_value::<KeyEntry>(v) {
                Ok(entry) => Some(entry),
                Err(_) => {
                    dropped += 1;
                    None
                }
            })
            .collect();
        if !good.is_empty() {
            services.insert(svc, good);
        }
    }
    Some((PoolData { services }, dropped))
}

pub fn save_pool(pool: &KeyPool) -> std::io::Result<()> {
    let path = pool_path();
    let data = pool.snapshot();
    let json = serde_json::to_string_pretty(&data).map_err(std::io::Error::other)?;
    // Atomic write via the shared helper: a UNIQUE temp + fsync + rename. A plain
    // truncate-then-write leaves corrupt/truncated JSON if the process is killed
    // mid-write (the OOM-killer is realistic on a 4 GB device), and `load_pool`
    // then discards EVERY harvested key. The unique temp also makes concurrent
    // saves safe: modules harvest keys during overlapping scans in `hse serve`,
    // and a shared fixed temp could be interleaved by two writers into a corrupt
    // file. The rename is atomic on the same filesystem, so a crash leaves the
    // previous valid pool intact.
    crate::util::atomic_file::write(&path, json.as_bytes())
}

/// Write secret text (an exported key pool) to an arbitrary path with `0600`
/// permissions, atomically. Shared by `hse keys export --out` so an exported
/// secret is never left world-readable.
pub fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
    crate::util::atomic_file::write(std::path::Path::new(path), contents.as_bytes())
}

/// Persist the pool, logging (not propagating) any failure.
///
/// Use this at the fire-and-forget sites that harvest keys during a scan: a
/// persistence failure there must not abort the scan, but it must not be silent
/// either. `save_pool` takes pains to write atomically so harvested keys survive
/// a crash; dropping its error with `let _ =` would mean a disk-full / read-only
/// `$HOME` (both realistic on a Termux device) silently discards every key
/// harvested this run with no trace to debug from. Callers that genuinely need
/// to surface the failure to a user (e.g. CLI key-management commands) should
/// call [`save_pool`] directly and handle the `Result`.
pub fn save_pool_best_effort(pool: &KeyPool) {
    if let Err(e) = save_pool(pool) {
        tracing::warn!(
            error = %e,
            path = %pool_path().display(),
            "failed to persist harvested API keys — they will be lost when the process exits"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parse_of_the_persisted_shape_drops_nothing() {
        // The exact shape `save_pool` writes: PoolData = {"services": {svc: [..]}}.
        let json = r#"{"services":{"intelx":[{"value":"k","status":"untested"}]}}"#;
        let (data, dropped) = parse_pool_text(json).expect("clean pool parses");
        assert_eq!(dropped, 0);
        assert_eq!(data.services["intelx"].len(), 1);
        assert_eq!(data.services["intelx"][0].value, "k");
    }

    #[test]
    fn lenient_salvage_keeps_good_entries_when_a_sibling_is_unreadable() {
        // Regression: previously the salvage parsed the file as a bare
        // `HashMap<String, Vec<Value>>`, which does NOT match the persisted
        // `{"services": {..}}` shape — so a single unreadable entry forced a full
        // backup-and-reset, discarding EVERY harvested key. The good sibling must
        // now survive while only the bad entry (unknown status enum) is dropped.
        let json = r#"{"services":{"shodan":[
            {"value":"good-key","status":"active"},
            {"value":"bad-key","status":"from_the_future"}
        ]}}"#;
        let (data, dropped) = parse_pool_text(json).expect("recoverable pool");
        assert_eq!(dropped, 1, "only the unreadable entry is dropped");
        let shodan = data.services.get("shodan").expect("service retained");
        assert_eq!(shodan.len(), 1, "the readable sibling survives");
        assert_eq!(shodan[0].value, "good-key");
    }

    #[test]
    fn bare_map_shape_also_salvages() {
        // A hand-edited / legacy bare `{svc: [..]}` map (no "services" wrapper)
        // still salvages rather than resetting the pool.
        let json = r#"{"hunter":[{"value":"x","status":"active"}]}"#;
        let (data, dropped) = parse_pool_text(json).expect("bare map recoverable");
        assert_eq!(dropped, 0);
        assert_eq!(data.services["hunter"][0].value, "x");
    }

    #[test]
    fn unrecoverable_text_returns_none() {
        assert!(parse_pool_text("not json at all").is_none());
    }

    #[test]
    fn corroboration_round_trips_through_persistence() {
        // The field added in 1/7 survives a save→load cycle via serde, and a
        // pre-existing file without the field still loads (serde default → 0).
        let mut e = KeyEntry::new("k");
        e.corroboration = 4;
        let mut services = HashMap::new();
        services.insert("shodan".to_string(), vec![e]);
        let json = serde_json::to_string(&PoolData { services }).unwrap();
        let (data, dropped) = parse_pool_text(&json).expect("round-trips");
        assert_eq!(dropped, 0);
        assert_eq!(data.services["shodan"][0].corroboration, 4);

        // A legacy record with no corroboration field defaults to 0.
        let legacy = r#"{"services":{"shodan":[{"value":"k","status":"active"}]}}"#;
        let (legacy_data, _) = parse_pool_text(legacy).expect("legacy parses");
        assert_eq!(legacy_data.services["shodan"][0].corroboration, 0);
    }
}
