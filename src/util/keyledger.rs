use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;

#[derive(Serialize)]
struct LedgerEntry {
    timestamp: u64,
    service: String,
    username: String,
    credential: String,
    url: String,
    source_module: String,
    scan_id: String,
    entity_kind: String,
    tags: Vec<String>,
}

fn ledger_path() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from(".huntsman/discovered_keys.jsonl"),
        |home| {
            let dir = std::path::Path::new(&home).join(".huntsman");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("discovered_keys.jsonl")
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn append_key(
    service: &str,
    username: &str,
    credential: &str,
    url: &str,
    source_module: &str,
    scan_id: &str,
    entity_kind: &str,
    tags: &[String],
) {
    if credential.is_empty() && username.is_empty() {
        return;
    }
    let entry = LedgerEntry {
        timestamp: crate::core::entity::unix_now(),
        service: service.to_string(),
        username: username.to_string(),
        credential: credential.to_string(),
        url: url.to_string(),
        source_module: source_module.to_string(),
        scan_id: scan_id.to_string(),
        entity_kind: entity_kind.to_string(),
        tags: tags.to_vec(),
    };

    let path = ledger_path();
    let line = match serde_json::to_string(&entry) {
        Ok(json) => json,
        Err(_) => return,
    };

    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return,
    };

    let _ = writeln!(file, "{line}");
}

pub fn ledger_file_path() -> String {
    ledger_path().to_string_lossy().into_owned()
}

pub fn read_ledger() -> Vec<serde_json::Value> {
    let path = ledger_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

pub fn ledger_count() -> usize {
    let path = ledger_path();
    match std::fs::read_to_string(&path) {
        Ok(c) => c.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_entry_serializes_to_json() {
        let entry = LedgerEntry {
            timestamp: 1234567890,
            service: "shodan.io".into(),
            username: "testuser".into(),
            credential: "sk_live_test123".into(),
            url: "https://shodan.io".into(),
            source_module: "oathnet_pro".into(),
            scan_id: "scan-test".into(),
            entity_kind: "api_key".into(),
            tags: vec!["service:shodan".into(), "api-key-exposed".into()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["service"], "shodan.io");
        assert_eq!(parsed["credential"], "sk_live_test123");
        assert_eq!(parsed["entity_kind"], "api_key");
    }

    #[test]
    fn append_key_skips_empty_credentials() {
        // Should not panic or write when both credential and username are empty
        append_key("test", "", "", "", "test", "s", "api_key", &[]);
    }
}
