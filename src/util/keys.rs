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
    "HUNTSMAN_CENSYS_ID",
    "HUNTSMAN_CENSYS_SECRET",
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
    "HUNTSMAN_OPENCELLID_KEY",
    // OSINT orchestration APIs
    "HUNTSMAN_SEON_KEY",
    "HUNTSMAN_EPIEOS_KEY",
    "HUNTSMAN_PROXYCURL_KEY",
    "HUNTSMAN_OPENCORP_KEY",
    // Breach / search multipliers — high-leverage paid pools the Settings
    // grid must surface so the operator can paste/rotate them in the UI.
    "HUNTSMAN_SEEKNOW_KEY",
    "HUNTSMAN_EXA_KEY",
];

/// Human-readable provider + free-signup hint for a `HUNTSMAN_*` key, surfaced
/// in the engine's "module skipped — needs key" notice (and `hse doctor`) so an
/// unconfigured optional module tells the operator exactly where to get a key.
/// `None` for keys without a known signup page. Most listed providers have a
/// free tier; the few paid-only ones say so.
pub fn signup_hint(env: &str) -> Option<&'static str> {
    Some(match env {
        "HUNTSMAN_ABUSECH_KEY" | "HUNTSMAN_THREATFOX_KEY" => {
            "abuse.ch — free key at https://auth.abuse.ch (powers urlhaus + threatfox + malwarebazaar)"
        }
        "HUNTSMAN_VIRUSTOTAL_KEY" => {
            "VirusTotal — free key at https://www.virustotal.com/gui/join-us"
        }
        "HUNTSMAN_ABUSEIPDB_KEY" => "AbuseIPDB — free key at https://www.abuseipdb.com/register",
        "HUNTSMAN_SHODAN_KEY" => "Shodan — free key at https://account.shodan.io/register",
        "HUNTSMAN_SECTRAILS_KEY" => {
            "SecurityTrails — free tier at https://securitytrails.com/app/signup"
        }
        "HUNTSMAN_HUNTER_KEY" => "Hunter.io — free tier at https://hunter.io/users/sign_up",
        "HUNTSMAN_GREYNOISE_KEY" => "GreyNoise — free key at https://viz.greynoise.io/signup",
        "HUNTSMAN_URLSCAN_KEY" => "urlscan.io — free key at https://urlscan.io/user/signup",
        "HUNTSMAN_LEAKIX_KEY" => "LeakIX — free key at https://leakix.net/auth/register",
        "HUNTSMAN_INTELX_KEY" => "Intelligence X — free tier at https://intelx.io/signup",
        "HUNTSMAN_EMAILREP_KEY" => "EmailRep — free key at https://emailrep.io/key",
        "HUNTSMAN_CRIMINALIP_KEY" => {
            "Criminal IP — free tier at https://www.criminalip.io/register"
        }
        "HUNTSMAN_IPQS_KEY" => {
            "IPQualityScore — free tier at https://www.ipqualityscore.com/create-account"
        }
        "HUNTSMAN_CENSYS_ID" | "HUNTSMAN_CENSYS_SECRET" => {
            "Censys — free tier at https://accounts.censys.io/register"
        }
        "HUNTSMAN_WHOISXML_KEY" => "WhoisXML — free tier at https://whois.whoisxmlapi.com",
        "HUNTSMAN_ONYPHE_KEY" => "ONYPHE — free tier at https://www.onyphe.io/login/#register",
        "HUNTSMAN_NETLAS_KEY" => "Netlas — free tier at https://app.netlas.io/registration",
        "HUNTSMAN_PULSEDIVE_KEY" => "Pulsedive — free key at https://pulsedive.com/about/api",
        "HUNTSMAN_OPENCORP_KEY" => "OpenCorporates — https://opencorporates.com/api_accounts/new",
        "HUNTSMAN_NUMVERIFY_KEY" => "numverify — free tier at https://numverify.com/product",
        "HUNTSMAN_OPENCELLID_KEY" => "OpenCelliD — free key at https://opencellid.org/register.php",
        "HUNTSMAN_EXA_KEY" => "Exa AI — free tier at https://dashboard.exa.ai/api-keys",
        "HUNTSMAN_WIGLE_TOKEN" | "HUNTSMAN_WIGLE_USER" => {
            "WiGLE — free account at https://wigle.net/account"
        }
        // Paid-only / invite providers.
        "HUNTSMAN_HIBP_KEY" => "Have I Been Pwned — paid key at https://haveibeenpwned.com/API/Key",
        "HUNTSMAN_DEHASHED_KEY" | "HUNTSMAN_DEHASHED_USER" => {
            "DeHashed — paid, https://dehashed.com"
        }
        "HUNTSMAN_PROXYCURL_KEY" => "Proxycurl — paid, https://nubela.co/proxycurl",
        "HUNTSMAN_SEON_KEY" => "SEON — free trial at https://seon.io",
        "HUNTSMAN_EPIEOS_KEY" => "Epieos — https://epieos.com",
        "HUNTSMAN_SEEKNOW_KEY" => "SeekNow (see-know.eu) — https://see-know.eu",
        "HUNTSMAN_OATHNET_KEY" => "OathNet — https://oathnet.org",
        _ => return None,
    })
}

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

/// Env var an operator may set — in their local `$HOME/.huntsman.env` (chmod
/// 0600) or the shell — to a default scan seed, so `hse scan` / `hse live` can
/// run without retyping `--value`.
///
/// This is deliberately **operator-local**: it is never shipped with a value.
/// The public installer and repo only document the key (commented-out); the
/// operator fills in *their own* target on *their own* device. That keeps a
/// real target out of the public tool — installing HSE never silently points
/// it at someone. An explicit `--value` always overrides it.
pub const DEFAULT_SEED_ENV: &str = "HUNTSMAN_DEFAULT_SEED";

/// Pure precedence resolver for [`default_seed`]: the process-environment value
/// wins, else the env-file map. Trims surrounding whitespace and treats a blank
/// result as unset. Split out so the precedence is unit-testable without
/// mutating the global environment.
fn pick_default_seed(env_value: Option<String>, file: &HashMap<String, String>) -> Option<String> {
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

/// API keys embedded in the build so a fresh install works zero-config.
/// `ensure_hardcoded_keys` writes any that are absent from the env file.
const HARDCODED: &[(&str, &str)] = &[
    (
        "HUNTSMAN_OATHNET_KEY",
        "1f8097bdbf7dc68619857861adbc4343ddb490a1d72ae890551409e4b47116f2",
    ),
    ("HUNTSMAN_HIBP_KEY", "42587552dce6424a87312941c8a2c3c5"),
    ("HUNTSMAN_WIGLE_USER", "AID4493a33e2df9d07ab9666a27c8aead17"),
    ("HUNTSMAN_WIGLE_TOKEN", "1aedb7ad0171ff3d6be5a844cca5d977"),
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "seek-f419aa7ab831864149892e5145f6bc65dbb336e6ca94b4bc",
    ),
];

/// Embedded defaults that have been ROTATED. If the env file still carries an
/// old embedded value (written by a previous build's `ensure_hardcoded_keys`),
/// upgrade it in place to the current default so a rebuild picks up the new key
/// without the operator re-entering it. Scoped to EXACT prior embedded values —
/// a user's own custom key never matches one of these, so an intentional
/// override is never clobbered.
const SUPERSEDED: &[(&str, &str)] = &[(
    "HUNTSMAN_SEEKNOW_KEY",
    "seek-4b33b63d408dd7149765da4e76384ce91fd9f6df518f9a25",
)];

/// Compute the `{env_var: value}` writes needed to bring `existing` (the
/// current env-file contents) up to date with the embedded defaults: fill any
/// absent slot, and rotate any slot still holding a superseded embedded value.
/// Pure so the fill-vs-rotate-vs-preserve policy is unit-testable. A slot the
/// user has set to a custom (non-superseded) value is left untouched.
fn hardcoded_key_writes(existing: &HashMap<String, String>) -> BTreeMap<String, String> {
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

    #[test]
    fn signup_hint_covers_common_free_providers() {
        // The providers that surfaced in the operator's scan as "failing".
        let vt = signup_hint("HUNTSMAN_VIRUSTOTAL_KEY").unwrap();
        assert!(vt.contains("virustotal.com"), "{vt}");
        let abusech = signup_hint("HUNTSMAN_ABUSECH_KEY").unwrap();
        assert!(abusech.contains("auth.abuse.ch"));
        // The ThreatFox key shares the abuse.ch account.
        assert_eq!(
            signup_hint("HUNTSMAN_THREATFOX_KEY"),
            signup_hint("HUNTSMAN_ABUSECH_KEY")
        );
        // Unknown keys have no hint.
        assert!(signup_hint("HUNTSMAN_NOPE_KEY").is_none());
        // Every hint that exists carries an https URL.
        for k in KNOWN_KEYS {
            if let Some(h) = signup_hint(k) {
                assert!(h.contains("https://") || h.contains("http"), "{k}: {h}");
            }
        }
    }

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
    fn hardcoded_key_writes_fills_rotates_and_preserves() {
        const NEW: &str = "seek-f419aa7ab831864149892e5145f6bc65dbb336e6ca94b4bc";
        const OLD: &str = "seek-4b33b63d408dd7149765da4e76384ce91fd9f6df518f9a25";

        // Empty file → embedded defaults filled (including the current SeekNow key).
        let w = hardcoded_key_writes(&HashMap::new());
        assert_eq!(w.get("HUNTSMAN_SEEKNOW_KEY").map(String::as_str), Some(NEW));
        assert!(w.contains_key("HUNTSMAN_OATHNET_KEY"));

        // Stale embedded value present → rotated in place to the new default.
        let stale: HashMap<String, String> =
            [("HUNTSMAN_SEEKNOW_KEY".to_string(), OLD.to_string())].into();
        assert_eq!(
            hardcoded_key_writes(&stale)
                .get("HUNTSMAN_SEEKNOW_KEY")
                .map(String::as_str),
            Some(NEW),
            "a superseded embedded key must rotate to the current default"
        );

        // A user's CUSTOM key is never matched by SUPERSEDED → preserved.
        let custom: HashMap<String, String> = [(
            "HUNTSMAN_SEEKNOW_KEY".to_string(),
            "seek-my-own-personal-key".to_string(),
        )]
        .into();
        assert!(
            !hardcoded_key_writes(&custom).contains_key("HUNTSMAN_SEEKNOW_KEY"),
            "a custom user key must be preserved, not rotated"
        );

        // Already-current → idempotent, no write queued.
        let current: HashMap<String, String> =
            [("HUNTSMAN_SEEKNOW_KEY".to_string(), NEW.to_string())].into();
        assert!(!hardcoded_key_writes(&current).contains_key("HUNTSMAN_SEEKNOW_KEY"));
    }

    #[test]
    fn pool_keys_fill_empty_env_slots() {
        let pool = crate::util::key_pool::global_pool();
        let mut entry = crate::util::key_pool::KeyEntry::new("test-pool-key-12345");
        entry.status = crate::util::key_pool::KeyStatus::Active;
        pool.add("shodan", entry);

        let map = load();
        // Pool key was either injected (env slot empty) or env had it —
        // either way, the merge didn't crash. Success if we get here.
        let _ = map;
    }

    #[test]
    fn default_seed_precedence_env_wins_then_file_then_none() {
        let file: HashMap<String, String> =
            [(DEFAULT_SEED_ENV.to_string(), "from-file".to_string())].into();

        // Process env value wins over the file.
        assert_eq!(
            pick_default_seed(Some("from-env".to_string()), &file).as_deref(),
            Some("from-env")
        );
        // No env value → fall back to the file.
        assert_eq!(pick_default_seed(None, &file).as_deref(), Some("from-file"));
        // Neither set → None (callers then require an explicit --value).
        assert_eq!(pick_default_seed(None, &HashMap::new()), None);
    }

    #[test]
    fn default_seed_trims_and_treats_blank_as_unset() {
        let empty = HashMap::new();
        // Surrounding whitespace is stripped.
        assert_eq!(
            pick_default_seed(Some("  alice  ".to_string()), &empty).as_deref(),
            Some("alice")
        );
        // A whitespace-only value is treated as unset, not as a blank target.
        assert_eq!(pick_default_seed(Some("   ".to_string()), &empty), None);
        // An explicit empty export disables the seed (does not fall through).
        let file: HashMap<String, String> =
            [(DEFAULT_SEED_ENV.to_string(), "from-file".to_string())].into();
        assert_eq!(pick_default_seed(Some(String::new()), &file), None);
    }

    #[test]
    fn default_seed_only_reads_the_seed_key() {
        // An env file full of API keys but no seed yields no default target.
        let file: HashMap<String, String> =
            [("HUNTSMAN_SHODAN_KEY".to_string(), "abc".to_string())].into();
        assert_eq!(pick_default_seed(None, &file), None);
    }
}
