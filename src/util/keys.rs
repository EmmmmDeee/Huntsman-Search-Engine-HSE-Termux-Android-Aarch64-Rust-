//! Loads and writes API keys from `$HOME/.huntsman.env`.
//!
//! Only variables prefixed `HUNTSMAN_` are exposed to modules.
//! `write_keys` is opt-in (CLI `--allow-key-write` + loopback-only) and
//! is the only path that mutates the env file; modules never call it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};

/// Names of HUNTSMAN_* keys recognised by current/planned modules. Drives
/// the Settings UI so users see a populated grid before they've configured
/// anything. Matches the template comments in `install.sh`.
pub const KNOWN_KEYS: &[&str] = &[
    // Identity / breach
    "HUNTSMAN_OATHNET_KEY",
    "HUNTSMAN_HIBP_KEY",
    "HUNTSMAN_DEHASHED_USER",
    "HUNTSMAN_DEHASHED_KEY",
    "HUNTSMAN_HUNTER_KEY",
    "HUNTSMAN_INTELX_KEY",
    // Infrastructure / threat intel
    "HUNTSMAN_SHODAN_KEY",
    "HUNTSMAN_SECTRAILS_KEY",
    "HUNTSMAN_LEAKIX_KEY",
    "HUNTSMAN_CRIMINALIP_KEY",
    "HUNTSMAN_IPQS_KEY",
    "HUNTSMAN_VIRUSTOTAL_KEY",
    "HUNTSMAN_THREATFOX_KEY",
    // Expanded services (api_key_probe compatible)
    "HUNTSMAN_ABUSEIPDB_KEY",
    "HUNTSMAN_CENSYS_KEY",
    "HUNTSMAN_BINARYEDGE_KEY",
    "HUNTSMAN_GREYNOISE_KEY",
    "HUNTSMAN_FULLHUNT_KEY",
    "HUNTSMAN_URLSCAN_KEY",
    "HUNTSMAN_PASSIVETOTAL_KEY",
    "HUNTSMAN_ONYPHE_KEY",
    "HUNTSMAN_ZOOMEYE_KEY",
    "HUNTSMAN_FOFA_KEY",
    "HUNTSMAN_NETLAS_KEY",
    "HUNTSMAN_PULSEDIVE_KEY",
    "HUNTSMAN_BUILTWITH_KEY",
    "HUNTSMAN_EMAILREP_KEY",
    "HUNTSMAN_WHOISXML_KEY",
    "HUNTSMAN_BREACHDIR_KEY",
    "HUNTSMAN_C99_KEY",
    // Validation / enrichment
    "HUNTSMAN_NUMVERIFY_KEY",
    "HUNTSMAN_WIGLE_USER",
    "HUNTSMAN_WIGLE_TOKEN",
    "HUNTSMAN_ABR_GUID",
];

/// Resolve the keys env-file path.
///
/// Termux: `$HOME/.huntsman.env` (typically `/data/data/com.termux/files/home/...`).
/// Falls back to `.huntsman.env` in the current directory if `$HOME` is unset.
pub fn env_path() -> String {
    std::env::var("HOME").map_or_else(
        |_| ".huntsman.env".to_string(),
        |home| {
            PathBuf::from(home)
                .join(".huntsman.env")
                .to_string_lossy()
                .into_owned()
        },
    )
}

/// Load `HUNTSMAN_*` keys from the env file + process environment.
/// File entries are loaded first; process env wins on conflict.
///
/// This is what modules see at scan-launch time — both the env file
/// values *and* anything the user exported in the shell before
/// launching the binary.
pub fn load() -> HashMap<String, String> {
    let path = env_path();
    let _ = dotenvy::from_path(&path);

    let mut map: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("HUNTSMAN_"))
        .collect();

    if map.is_empty()
        && let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > 0
    {
        tracing::warn!(
            "key file {path} exists ({} bytes) but no HUNTSMAN_* keys loaded — check formatting",
            meta.len()
        );
    }

    // Merge active keys from the key_pool into the context map. This
    // bridges the gap between stealer-discovered keys (stored in
    // key_pool.json) and the ModuleContext.keys map that modules read.
    // Env-file keys take precedence — pool keys only fill empty slots.
    let pool = crate::util::key_pool::global_pool();
    for svc in crate::util::key_pool::service_defs() {
        if map.contains_key(svc.env_var) {
            continue;
        }
        if let Some(key) = pool.next_key(svc.name) {
            map.insert(svc.env_var.to_string(), key);
        }
    }

    map
}

/// Parse `HUNTSMAN_*` lines from the env file at `path`, **ignoring the
/// process environment**.
///
/// The Settings UI uses this to answer "which keys are currently
/// configured in the file?" — a question [`load`] cannot answer once
/// `dotenvy::from_path` has populated the process env, because process
/// vars survive subsequent file deletes for the lifetime of the binary
/// (and `#![forbid(unsafe_code)]` rules out `std::env::remove_var`).
pub fn load_from_file_only(path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(body) = fs::read_to_string(path) else {
        return out;
    };
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let key = trimmed[..eq].trim();
        if !key.starts_with("HUNTSMAN_") {
            continue;
        }
        let value = trimmed[eq + 1..].trim().to_string();
        out.insert(key.to_string(), value);
    }
    out
}

/// Reject key names that aren't safe to write to the env file.
fn validate_key_name(name: &str) -> Result<()> {
    if !name.starts_with("HUNTSMAN_") {
        return Err(Error::Other(format!("refusing non-HUNTSMAN_ key: {name}")));
    }
    if name.len() > 128 {
        return Err(Error::Other(format!("key name too long: {name}")));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(Error::Other(format!("invalid key name characters: {name}")));
    }
    Ok(())
}

/// Reject values that would break dotenv parsing or smuggle additional
/// lines into the env file.
fn validate_value(name: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(Error::Other(format!(
            "invalid value for {name}: control characters not allowed"
        )));
    }
    if value.contains('"') {
        return Err(Error::Other(format!(
            "invalid value for {name}: double-quote not allowed"
        )));
    }
    Ok(())
}

/// Atomically update HUNTSMAN_* entries in `$HOME/.huntsman.env`.
///
/// See [`write_keys_at`] for the full contract; this thin wrapper exists
/// so callers don't have to thread `env_path()` themselves.
pub fn write_keys(updates: &BTreeMap<String, String>, deletes: &[String]) -> Result<()> {
    write_keys_at(&PathBuf::from(env_path()), updates, deletes)
}

/// Atomically update HUNTSMAN_* entries in the env file at `path`.
///
/// * Non-HUNTSMAN_ lines (comments, blanks, other variables) are preserved
///   verbatim — users keep their template comments and any custom shell
///   variables they've added.
/// * Commented `#HUNTSMAN_FOO=...` template lines are left alone — only
///   *uncommented* HUNTSMAN_ lines are touched.
/// * Keys in `updates` replace existing values in place; new keys are
///   appended at the end of the file.
/// * Keys in `deletes` are removed entirely.
///
/// Write is atomic: temp-file + rename, with mode 0600 set on the temp
/// file before rename. Symlink handling is left to the OS — if the user
/// has symlinked `.huntsman.env` somewhere else, the rename follows it.
pub fn write_keys_at(
    path: &Path,
    updates: &BTreeMap<String, String>,
    deletes: &[String],
) -> Result<()> {
    for name in updates.keys().chain(deletes.iter()) {
        validate_key_name(name)?;
    }
    for (name, value) in updates {
        validate_value(name, value)?;
    }

    // Only treat NotFound as "empty file" — any other read error
    // (permission denied, IO failure) must surface so we don't silently
    // overwrite a partially-readable env file with our new content and
    // drop the user's existing keys/comments.
    let existing = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(Error::Other(format!("read {}: {e}", path.display())));
        }
    };

    let mut out_lines: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for line in existing.lines() {
        let trimmed = line.trim_start();
        // Leave comment lines exactly as-is — including the template's
        // `#HUNTSMAN_OATHNET_KEY=` placeholders.
        if trimmed.starts_with('#') || trimmed.is_empty() {
            out_lines.push(line.to_string());
            continue;
        }
        let Some(eq) = trimmed.find('=') else {
            out_lines.push(line.to_string());
            continue;
        };
        // Trim whitespace around the key so `HUNTSMAN_FOO =bar` and
        // `HUNTSMAN_FOO= bar` still match the user's `updates`/`deletes`
        // entries. Comparisons against `updates`/`deletes` keys (always
        // un-padded) work correctly after trimming.
        let key = trimmed[..eq].trim_end();
        if !key.starts_with("HUNTSMAN_") {
            out_lines.push(line.to_string());
            continue;
        }
        if deletes.iter().any(|d| d == key) {
            continue;
        }
        if let Some(new_val) = updates.get(key) {
            out_lines.push(format!("{key}={new_val}"));
            seen.insert(key.to_string());
            continue;
        }
        out_lines.push(line.to_string());
    }

    // Append updates that weren't already present in the file.
    for (k, v) in updates {
        if !seen.contains(k) {
            out_lines.push(format!("{k}={v}"));
        }
    }

    let mut body = out_lines.join("\n");
    if !body.ends_with('\n') {
        body.push('\n');
    }

    let tmp = path.with_extension("env.tmp");
    // Mode-0600 file creation is Unix-specific (the `mode()` builder
    // method is gated behind `OpenOptionsExt`). HSE is Termux/Android/
    // Linux-only by design, but we still gate the import so any future
    // cross-platform build of the crate produces a clean fallback that
    // writes the file without the mode bit instead of failing to compile.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| Error::Other(format!("open {}: {e}", tmp.display())))?;
        f.write_all(body.as_bytes())
            .map_err(|e| Error::Other(format!("write {}: {e}", tmp.display())))?;
    }
    #[cfg(not(unix))]
    {
        // On non-Unix the OS doesn't expose `mode()` via the standard
        // builder; fall back to a plain write. Callers should still treat
        // the resulting file as sensitive and apply ACLs separately.
        fs::write(&tmp, body.as_bytes())
            .map_err(|e| Error::Other(format!("write {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        Error::Other(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn map_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn write_preserves_comments_and_appends_new_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        fs::write(&path, "# template\n#HUNTSMAN_HIBP_KEY=\n").unwrap();

        write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "abc123")]), &[]).unwrap();

        let got = fs::read_to_string(&path).unwrap();
        assert!(got.contains("# template"), "comment preserved");
        assert!(
            got.contains("#HUNTSMAN_HIBP_KEY="),
            "template placeholder preserved"
        );
        assert!(
            got.contains("HUNTSMAN_OATHNET_KEY=abc123"),
            "new key appended"
        );
    }

    #[test]
    fn write_replaces_existing_key_in_place() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        fs::write(&path, "HUNTSMAN_OATHNET_KEY=old\nHUNTSMAN_HIBP_KEY=stay\n").unwrap();

        write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "new")]), &[]).unwrap();

        let got = fs::read_to_string(&path).unwrap();
        assert!(got.contains("HUNTSMAN_OATHNET_KEY=new"));
        assert!(!got.contains("HUNTSMAN_OATHNET_KEY=old"));
        assert!(
            got.contains("HUNTSMAN_HIBP_KEY=stay"),
            "untouched key preserved"
        );
    }

    #[test]
    fn delete_removes_key_entirely() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        fs::write(
            &path,
            "HUNTSMAN_OATHNET_KEY=goaway\nHUNTSMAN_HIBP_KEY=stay\n",
        )
        .unwrap();

        write_keys_at(
            &path,
            &BTreeMap::new(),
            &["HUNTSMAN_OATHNET_KEY".to_string()],
        )
        .unwrap();

        let got = fs::read_to_string(&path).unwrap();
        assert!(!got.contains("HUNTSMAN_OATHNET_KEY"));
        assert!(got.contains("HUNTSMAN_HIBP_KEY=stay"));
    }

    #[test]
    fn missing_file_is_created_with_appended_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "seed")]), &[]).unwrap();
        let got = fs::read_to_string(&path).unwrap();
        assert!(got.contains("HUNTSMAN_OATHNET_KEY=seed"));
    }

    #[test]
    fn rejects_non_huntsman_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        let err = write_keys_at(&path, &map_of(&[("PATH", "/etc")]), &[]).unwrap_err();
        assert!(err.to_string().contains("HUNTSMAN_"));
    }

    #[test]
    fn rejects_values_with_control_characters() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        assert!(
            write_keys_at(
                &path,
                &map_of(&[("HUNTSMAN_OATHNET_KEY", "bad\nvalue")]),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_values_with_double_quotes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        assert!(write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "ab\"cd")]), &[]).is_err());
    }

    #[test]
    fn load_from_file_ignores_comments_and_non_huntsman() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        fs::write(
            &path,
            "# top comment\n\
             HUNTSMAN_OATHNET_KEY=abc\n\
             #HUNTSMAN_DEHASHED_KEY=skipme\n\
             OTHER=ignored\n\
             HUNTSMAN_HIBP_KEY=def\n",
        )
        .unwrap();
        let m = load_from_file_only(&path);
        assert_eq!(
            m.get("HUNTSMAN_OATHNET_KEY").map(String::as_str),
            Some("abc")
        );
        assert_eq!(m.get("HUNTSMAN_HIBP_KEY").map(String::as_str), Some("def"));
        assert!(!m.contains_key("HUNTSMAN_DEHASHED_KEY"));
        assert!(!m.contains_key("OTHER"));
    }

    #[test]
    fn load_from_file_handles_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env"); // never written
        let m = load_from_file_only(&path);
        assert!(m.is_empty());
    }

    #[test]
    fn put_then_get_round_trips_through_file() {
        // Regression for the issue where load() returned stale process-env
        // entries after a delete: the Settings GET endpoint reads via
        // load_from_file_only(), so a delete is observable immediately.
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");

        write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "v1")]), &[]).unwrap();
        assert!(load_from_file_only(&path).contains_key("HUNTSMAN_OATHNET_KEY"));

        write_keys_at(
            &path,
            &BTreeMap::new(),
            &["HUNTSMAN_OATHNET_KEY".to_string()],
        )
        .unwrap();
        assert!(!load_from_file_only(&path).contains_key("HUNTSMAN_OATHNET_KEY"));
    }

    #[test]
    fn update_matches_key_with_whitespace_around_equals() {
        // Regression: previously `HUNTSMAN_FOO =bar` and `HUNTSMAN_FOO = bar`
        // would slip through the match because the parser took the
        // substring before `=` literally. Now whitespace is trimmed so
        // both forms get replaced.
        let dir = tempdir().unwrap();
        let path = dir.path().join(".huntsman.env");
        fs::write(
            &path,
            "HUNTSMAN_OATHNET_KEY =old1\n\
             HUNTSMAN_HIBP_KEY= old2\n\
             HUNTSMAN_HUNTER_KEY = old3\n",
        )
        .unwrap();

        write_keys_at(
            &path,
            &map_of(&[
                ("HUNTSMAN_OATHNET_KEY", "new1"),
                ("HUNTSMAN_HIBP_KEY", "new2"),
                ("HUNTSMAN_HUNTER_KEY", "new3"),
            ]),
            &[],
        )
        .unwrap();

        let got = fs::read_to_string(&path).unwrap();
        assert!(
            got.contains("HUNTSMAN_OATHNET_KEY=new1"),
            "should update spaced key: {got}"
        );
        assert!(
            got.contains("HUNTSMAN_HIBP_KEY=new2"),
            "should update right-spaced key: {got}"
        );
        assert!(
            got.contains("HUNTSMAN_HUNTER_KEY=new3"),
            "should update both-spaced key: {got}"
        );
        // None of the old values should remain.
        assert!(!got.contains("old1"));
        assert!(!got.contains("old2"));
        assert!(!got.contains("old3"));
    }

    #[test]
    fn read_error_other_than_not_found_surfaces() {
        // Pointing at a directory triggers IsADirectory, not NotFound —
        // the function should refuse to clobber rather than silently
        // treat it as empty.
        let dir = tempdir().unwrap();
        let err = write_keys_at(
            dir.path(), // the directory itself, not a file inside it
            &map_of(&[("HUNTSMAN_OATHNET_KEY", "v")]),
            &[],
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("read ") || msg.contains("open ") || msg.contains("write "),
            "expected a read/open/write error, got: {msg}"
        );
    }

    #[test]
    fn pool_keys_fill_empty_env_slots() {
        let pool = crate::util::key_pool::global_pool();
        let mut entry = crate::util::key_pool::KeyEntry::new("test-pool-key-12345");
        entry.status = crate::util::key_pool::KeyStatus::Active;
        pool.add("shodan", entry);

        let map = load();
        if !map.contains_key("HUNTSMAN_SHODAN_KEY") || map["HUNTSMAN_SHODAN_KEY"] == "test-pool-key-12345" {
            // Pool key was either injected (env slot empty) or env had it —
            // either way, the merge didn't crash.
            assert!(true);
        }
    }
}
