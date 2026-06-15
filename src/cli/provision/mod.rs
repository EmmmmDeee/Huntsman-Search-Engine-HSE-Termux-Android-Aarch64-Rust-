//! `hse provision` — Rust-native replacement for the post-build phases of
//! the Termux provisioning pipeline (env-file merge + diagnostics + smoke
//! test). The pre-build phases (Termux wake-lock, `pkg install`, `git`,
//! `cargo build`) stay in `install.sh` — by definition they have to run
//! before this binary exists.
//!
//! Sub-flow:
//!   * `hse provision --env-only`    → atomic merge of `~/.huntsman.env`
//!   * `hse provision --verify-only` → doctor + passive smoke test
//!   * `hse provision`               → both
//!
//! The env-merge logic is the canonical source of truth for the
//! template; the script-side bash port that previously lived in
//! `tools/provision-termux.sh` has been removed in favour of this.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::{
    entity::unix_now,
    error::{Error, Result},
    event::EventKind,
    module::ModuleContext,
    scan::{Scan, ScanOptions, Target, TargetKind},
};
use crate::storage::Store;
use crate::util::{http::build_client, keys, uid::scan_id};

/// Canonical env-file template, embedded at compile time. Edit
/// `src/cli/env_template.txt` to change the on-disk shape; the binary
/// picks it up on next build.
const ENV_TEMPLATE: &str = include_str!("env_template.txt");

const PLACEHOLDER_PREFIX: &str = "insert_";
const PLACEHOLDER_SUFFIX: &str = "_here";

/// Parse a single env-file line of the form `KEY="value"` (with optional
/// trailing whitespace / inline comment). Returns `Some((key, value))`
/// when the line is shaped right, `None` for blank / comment / malformed
/// lines.
fn parse_kv(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.is_empty() {
        return None;
    }
    let eq = trimmed.find('=')?;
    let key = trimmed[..eq].trim();
    if !key.starts_with("HUNTSMAN_") {
        return None;
    }
    let rest = trimmed[eq + 1..].trim_start();
    // Accept double-quoted values; reject anything we can't safely round-trip
    // back through the keys::write_keys_at validator (which forbids `"` in
    // values). A bare unquoted value works too — dotenvy accepts both.
    let value = if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        rest[..end].to_string()
    } else {
        // Stop at first whitespace or '#'.
        rest.split(['#', ' ', '\t']).next()?.to_string()
    };
    Some((key.to_string(), value))
}

fn is_placeholder(value: &str) -> bool {
    value.starts_with(PLACEHOLDER_PREFIX) && value.ends_with(PLACEHOLDER_SUFFIX)
}

/// Merge `existing` env-file contents into `template`, preserving every
/// real (non-placeholder) value from `existing` and appending any
/// `HUNTSMAN_*` entries that exist in `existing` but not in `template`.
///
/// Pure, deterministic, side-effect-free. The CLI driver layers backup
/// / atomic-write / chmod 0600 on top of this.
pub fn merge_template(existing: &str, template: &str) -> String {
    // Real values from the existing file: key → value, only when the
    // value is not a template placeholder and not empty.
    let mut real_values: BTreeMap<String, String> = BTreeMap::new();
    for line in existing.lines() {
        if let Some((k, v)) = parse_kv(line)
            && !is_placeholder(&v)
            && !v.is_empty()
        {
            real_values.insert(k, v);
        }
    }

    // Track which template keys we re-emit so we know what's "leftover"
    // (user-custom keys not in the template).
    let mut seen_in_template: BTreeMap<String, ()> = BTreeMap::new();

    let mut out = String::with_capacity(template.len() + 256);
    for line in template.lines() {
        if let Some((k, _)) = parse_kv(line) {
            seen_in_template.insert(k.clone(), ());
            if let Some(real) = real_values.get(&k) {
                // Substitute the real value in place. Drop any inline
                // comment — the template's per-line comments described
                // "what this key is for" and are still in the file via
                // the template-shape lines; we don't need them on the
                // populated line.
                out.push_str(&format!("{k}=\"{real}\"\n"));
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }

    // Append user-custom HUNTSMAN_* values that the template doesn't
    // know about (e.g. an integration the user added before a future
    // module ships).
    let leftover: Vec<(&String, &String)> = real_values
        .iter()
        .filter(|(k, _)| !seen_in_template.contains_key(*k))
        .collect();
    if !leftover.is_empty() {
        out.push_str("\n# --- USER-CUSTOM KEYS (not in template) ---\n");
        for (k, v) in leftover {
            out.push_str(&format!("{k}=\"{v}\"\n"));
        }
    }
    out
}

/// Write the merged content to `path` atomically (temp-file + rename),
/// after first backing up any pre-existing file to `path + .bak.<ts>`.
/// File mode is 0600 on Unix; on non-Unix the OS-default mode applies.
fn write_env_file(path: &Path, contents: &str) -> Result<Option<PathBuf>> {
    let backup = if path.exists() {
        let bak = path.with_extension(format!("env.bak.{}", unix_now()));
        fs::copy(path, &bak).map_err(|e| {
            Error::Other(format!(
                "backup {} → {}: {e}",
                path.display(),
                bak.display()
            ))
        })?;
        Some(bak)
    } else {
        None
    };

    let tmp = path.with_extension("env.provision.tmp");
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
        f.write_all(contents.as_bytes())
            .map_err(|e| Error::Other(format!("write {}: {e}", tmp.display())))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, contents.as_bytes())
            .map_err(|e| Error::Other(format!("write {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        Error::Other(format!(
            "rename {} → {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(backup)
}

/// Run the env-merge phase. Prints a summary of what changed.
pub fn cmd_provision_env(dry_run: bool) -> Result<()> {
    let path = PathBuf::from(keys::env_path());
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let merged = merge_template(&existing, ENV_TEMPLATE);

    let (template_keys, real_keys, custom_keys) = count_keys(&existing);

    println!("==> Phase: env merge");
    println!("    target file:    {}", path.display());
    println!("    template keys:  {template_keys}");
    println!("    real values:    {real_keys}");
    println!("    custom keys:    {custom_keys} (not in template, will be preserved)");

    if dry_run {
        println!("    (--dry-run; no changes written)");
        println!("\n--- merged content preview ---");
        println!("{merged}");
        return Ok(());
    }

    let backup = write_env_file(&path, &merged)?;
    if let Some(bak) = backup {
        println!("    backed up to:   {}", bak.display());
    }
    println!("    wrote:          {} (mode 0600)", path.display());
    Ok(())
}

fn count_keys(existing: &str) -> (usize, usize, usize) {
    let template_keys = ENV_TEMPLATE
        .lines()
        .filter_map(parse_kv)
        .map(|(k, _)| k)
        .collect::<std::collections::BTreeSet<_>>();
    let mut real = 0usize;
    let mut custom = 0usize;
    for line in existing.lines() {
        if let Some((k, v)) = parse_kv(line)
            && !is_placeholder(&v)
            && !v.is_empty()
        {
            if template_keys.contains(&k) {
                real += 1;
            } else {
                custom += 1;
            }
        }
    }
    (template_keys.len(), real, custom)
}

/// Run the verify phase: doctor + passive smoke test + missing-key
/// micro-test pinned to `oathnet_pro`.
pub async fn cmd_provision_verify() -> Result<()> {
    use crate::modules::registry;

    println!("==> Phase: verify");

    // ── 1. Doctor-like snapshot ─────────────────────────────────────────
    let mods = registry();
    println!(
        "    modules:        {} registered ({} free, {} key-gated, {} paid)",
        mods.len(),
        mods.iter()
            .filter(|m| matches!(m.cost(), crate::core::module::ModuleCost::Free))
            .count(),
        mods.iter()
            .filter(|m| matches!(m.cost(), crate::core::module::ModuleCost::KeyGated))
            .count(),
        mods.iter()
            .filter(|m| matches!(m.cost(), crate::core::module::ModuleCost::Paid))
            .count(),
    );
    println!("    db path:        {}", crate::default_db_path());
    println!("    keys path:      {}", keys::env_path());

    let loaded = keys::load();
    // Count REAL key values (skip template placeholders) so the report
    // reflects what the operator actually has set.
    let real_count = loaded
        .iter()
        .filter(|(k, v)| k.starts_with("HUNTSMAN_") && !is_placeholder(v) && !v.is_empty())
        .count();
    let placeholder_count = loaded
        .iter()
        .filter(|(k, v)| k.starts_with("HUNTSMAN_") && is_placeholder(v))
        .count();
    println!(
        "    keys loaded:    {real_count} real, {placeholder_count} placeholders awaiting values"
    );

    // ── 2. Passive smoke scan ───────────────────────────────────────────
    println!("    smoke test:     passive-only scan against example.com…");
    let SmokeResult {
        entity_count,
        correlation_count,
        missing_keys,
        completed,
    } = run_smoke(
        Target::new(TargetKind::Domain, "example.com"),
        ScanOptions {
            passive_only: true,
            ..Default::default()
        },
    )
    .await?;
    println!(
        "                    {} {entity_count} entit{}, {correlation_count} correlation{}",
        if completed { "✓" } else { "!" },
        if entity_count == 1 { "y" } else { "ies" },
        if correlation_count == 1 { "" } else { "s" },
    );

    // ── 3. Missing-key micro-test ───────────────────────────────────────
    // Pin a scan to `oathnet_pro` to force the missing-key path. Skip
    // entirely if the key has a real (non-placeholder) value — the
    // assertion only makes sense when the key is genuinely absent.
    let oathnet_real = loaded
        .get("HUNTSMAN_OATHNET_KEY")
        .is_some_and(|v| !is_placeholder(v) && !v.is_empty());
    if oathnet_real {
        println!("    missing-key:    HUNTSMAN_OATHNET_KEY populated — sub-test skipped");
    } else {
        let mk = run_smoke(
            Target::new(TargetKind::Domain, "example.com"),
            ScanOptions {
                modules: Some(vec!["oathnet_pro".into()]),
                ..Default::default()
            },
        )
        .await?;
        let saw_oathnet = mk.missing_keys.iter().any(|k| k == "HUNTSMAN_OATHNET_KEY");
        if saw_oathnet {
            println!(
                "    missing-key:    ✓ engine reported `missing key: HUNTSMAN_OATHNET_KEY` and \
                returned a clean envelope (no panic)"
            );
        } else {
            println!(
                "    missing-key:    ! oathnet_pro ran without reporting a missing key — \
                expected error not observed"
            );
        }
        // Also report any other missing keys the scan encountered.
        for k in &missing_keys {
            if k != "HUNTSMAN_OATHNET_KEY" {
                println!("                    (also missing: {k})");
            }
        }
    }

    Ok(())
}

struct SmokeResult {
    entity_count: usize,
    correlation_count: usize,
    missing_keys: Vec<String>,
    completed: bool,
}

/// Run one scan synchronously and harvest the diagnostic metrics we
/// care about (entity count, correlation count, missing-key errors).
async fn run_smoke(target: Target, options: ScanOptions) -> Result<SmokeResult> {
    let store: Arc<dyn crate::core::port::StoragePort> =
        Arc::new(Store::open(&crate::default_db_path())?);
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let engine = Arc::new(crate::core::engine::ScanEngine::new(
        crate::modules::registry(),
        Arc::clone(&store),
        bus.clone(),
    ));

    let sid = scan_id(target.kind.canonical_str(), &target.value);
    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);

    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus: bus.clone(),
        http: build_client(),
        keys: keys::load(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        response_sink: None,
    };

    // Capture ModuleError events to extract `missing key: …` strings —
    // the cheapest way to verify the engine's error path fires correctly.
    // We don't spawn a long-lived collector because the engine + bus
    // would need to be Drop-ed for the receiver's `.recv()` to return
    // `Err`, and the bus is held inside `engine` (an Arc the engine
    // struct owns a strong ref of). Instead, we drain non-blockingly
    // after `engine.run` returns — by then every module has flushed
    // its events through the broadcast channel.
    let mut rx = bus.subscribe();

    let completed = engine.run(scan.clone(), target, ctx).await.is_ok();

    let entities = store.entities_for_scan(&sid).unwrap_or_default();
    let correlations = store.correlations_for_scan(&sid).unwrap_or_default();

    // Drain queued events; never block waiting for more. `try_recv`
    // returns `Err(Empty)` once the buffer is exhausted, ending the loop.
    let mut missing_keys = Vec::<String>::new();
    while let Ok(ev) = rx.try_recv() {
        match &ev.kind {
            // Legacy path: a module that still propagates `missing key: …`
            // through a ModuleError.
            EventKind::ModuleError { error, .. } => {
                if let Some(rest) = error.strip_prefix("missing key: ") {
                    missing_keys.push(rest.to_string());
                }
            }
            // Current path: the engine turns `Error::MissingKey` into a clean
            // ModuleSkipped("needs API key HUNTSMAN_X_KEY — <hint>").
            EventKind::ModuleSkipped { reason, .. } => {
                if let Some(rest) = reason.strip_prefix("needs API key ")
                    && let Some(key) = rest.split_whitespace().next()
                    && !key.is_empty()
                {
                    missing_keys.push(key.to_string());
                }
            }
            _ => {}
        }
    }

    Ok(SmokeResult {
        entity_count: entities.len(),
        correlation_count: correlations.len(),
        missing_keys,
        completed,
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
