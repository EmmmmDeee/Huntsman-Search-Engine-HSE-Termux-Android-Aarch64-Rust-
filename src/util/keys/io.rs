//! Env-file I/O: loading keys from disk, writing/rotating entries atomically.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};

use super::constants::{DEFAULT_SEED_ENV, HARDCODED, SUPERSEDED};

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

/// Pure precedence resolver for [`default_seed`]: the process-environment value
/// wins, else the env-file map. Trims surrounding whitespace and treats a blank
/// result as unset. Split out so the precedence is unit-testable without
/// mutating the global environment.
pub fn pick_default_seed(
    env_value: Option<String>,
    file: &HashMap<String, String>,
) -> Option<String> {
    env_value
        .or_else(|| file.get(DEFAULT_SEED_ENV).cloned())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve the operator-configured default scan seed, if any.
///
/// Reads [`DEFAULT_SEED_ENV`] from the same sources as [`load`] — the
/// git-ignored `~/.huntsman.env` file and the process environment, with the
/// process environment winning. Returns `None` when unset or blank so callers
/// fall back to requiring an explicit `--value`. Never returns a value baked
/// into the binary or the repo; there is none.
pub fn default_seed() -> Option<String> {
    let env_value = std::env::var(DEFAULT_SEED_ENV).ok();
    let file = load_from_file_only(Path::new(&env_path()));
    pick_default_seed(env_value, &file)
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

    // Multi-key support: if an env var contains comma-separated values,
    // load each into the pool for round-robin rotation. The first key
    // stays in the env map for backward compat; extras go to the pool.
    let pool = crate::util::key_pool::global_pool();
    for svc in crate::util::key_pool::service_defs() {
        let val = map.get(svc.env_var).cloned();
        if let Some(val) = val {
            if val.contains(',') {
                let keys: Vec<&str> = val
                    .split(',')
                    .map(str::trim)
                    .filter(|k| !k.is_empty())
                    .collect();
                if keys.len() > 1 {
                    map.insert(svc.env_var.to_string(), keys[0].to_string());
                    for k in &keys {
                        let mut entry = crate::util::key_pool::KeyEntry::new(*k);
                        entry.status = crate::util::key_pool::KeyStatus::Active;
                        pool.add(svc.name, entry);
                    }
                    tracing::info!(
                        service = svc.name,
                        count = keys.len(),
                        "loaded {} keys for rotation",
                        keys.len()
                    );
                }
            }
            continue;
        }
        if let Some(key) = pool.next_key(svc.name) {
            map.insert(svc.env_var.to_string(), key);
        }
    }

    map
}

/// Proactively populate API keys before a scan starts:
///
/// 1. Ensure hardcoded keys (OathNet, HIBP, WiGLE) are in the env file
///    so they persist across sessions.
/// 2. Run the OathNet stealer credential harvest to fill the key pool
///    with discovered API keys from stealer logs.
/// 3. Return the merged key map (env file + pool).
///
/// Call this once at scan start. The harvest is async and runs against
/// the OathNet stealer API (~30 service domain queries).
pub async fn populate_and_load() -> HashMap<String, String> {
    ensure_hardcoded_keys();
    // Pre-scan OathNet harvest disabled — costs 38 API calls before any
    // scan begins. The oathnet_pro module extracts credentials from
    // breach/stealer results during the seed query instead, getting the
    // same data as a side-effect of the 2-3 high-value queries it makes.
    load()
}

/// Compute the `{env_var: value}` writes needed to bring `existing` (the
/// current env-file contents) up to date with the embedded defaults: fill any
/// absent slot, and rotate any slot still holding a superseded embedded value.
/// Pure so the fill-vs-rotate-vs-preserve policy is unit-testable. A slot the
/// user has set to a custom (non-superseded) value is left untouched.
pub fn hardcoded_key_writes(existing: &HashMap<String, String>) -> BTreeMap<String, String> {
    let mut updates: BTreeMap<String, String> = BTreeMap::new();
    // Rotate superseded embedded values to the current default.
    for (env_var, old_value) in SUPERSEDED {
        if existing.get(*env_var).map(String::as_str) == Some(*old_value)
            && let Some((_, new_value)) = HARDCODED.iter().find(|(k, _)| k == env_var)
        {
            updates.insert((*env_var).to_string(), (*new_value).to_string());
        }
    }
    // Fill empty slots (never overwrites a value already present).
    for (env_var, value) in HARDCODED {
        if !existing.contains_key(*env_var) {
            updates.insert((*env_var).to_string(), (*value).to_string());
        }
    }
    updates
}

/// Ensure the embedded API keys are present and current in the env file:
/// fill absent slots and rotate any superseded embedded value in place. Uses
/// the atomic, comment-preserving [`write_keys`] path (so a rotation replaces
/// the old line rather than appending a duplicate). Never overwrites a user's
/// custom key — see [`hardcoded_key_writes`].
fn ensure_hardcoded_keys() {
    let path = env_path();
    let existing = load_from_file_only(Path::new(&path));
    let updates = hardcoded_key_writes(&existing);
    if updates.is_empty() {
        return;
    }
    let n = updates.len();
    match write_keys(&updates, &[]) {
        Ok(()) => tracing::info!("ensured {n} embedded key(s) current in {path}"),
        Err(e) => tracing::warn!("cannot write embedded keys to {path}: {e}"),
    }
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
    // The value is written double-quoted (so spaces/`#` survive — an UNquoted
    // value with a space fails dotenvy's parser, which would break loading of the
    // whole env file). Inside double quotes dotenvy processes escape sequences, so
    // a literal `"` or `\` would be reinterpreted on read; reject both so the
    // written value always round-trips byte-for-byte. (API keys, usernames and
    // seeds never legitimately contain either.)
    if value.contains(['"', '\\']) {
        return Err(Error::Other(format!(
            "invalid value for {name}: double-quote and backslash not allowed"
        )));
    }
    Ok(())
}

/// Render one `KEY="value"` env line. The value is double-quoted so spaces and
/// `#` survive dotenvy's parser (an unquoted spaced value fails to parse and
/// would break loading of the whole file). [`validate_value`] guarantees the
/// value has no `"`, `\`, or control chars, so the quoted form round-trips
/// byte-for-byte. Caller must have validated `value` first.
fn env_line(key: &str, value: &str) -> String {
    format!("{key}=\"{value}\"")
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
            out_lines.push(env_line(key, new_val));
            seen.insert(key.to_string());
            continue;
        }
        out_lines.push(line.to_string());
    }

    // Append updates that weren't already present in the file.
    for (k, v) in updates {
        if !seen.contains(k) {
            out_lines.push(env_line(k, v));
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
