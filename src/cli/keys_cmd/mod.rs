//! `hse keys` — manage the global API-key pool.
//!
//! Subcommands: add / list / validate / remove / status / bank / services /
//! import-tsv. The pool lives at $HOME/.huntsman_keys.json (mode 0600)
//! and is shared across scans; every `identify_api_key` discovery and
//! `hse set-key` mutation lands here.
//!
//! `bank` is different: it reads the persistent **retention bank**
//! (`util::key_vault`, `~/.huntsman/key_vault.db`) — every API key ever found in
//! a victim/stealer query, categorised and OSINT-providers-first. The bank is
//! retention-only (never used to authenticate); it is the operator-facing view
//! of harvested keys as OSINT intelligence.

use clap::Subcommand;

use crate::core::error::{Error, Result};

#[derive(Subcommand)]
pub enum KeysAction {
    /// Write a `HUNTSMAN_*` variable directly to `~/.huntsman.env`
    /// (the same operation as the legacy `hse set-key` shorthand).
    /// Use this for env-file keys; use `add` for the rotation pool.
    #[command(visible_alias = "set-key", visible_alias = "write")]
    Set {
        /// Variable name, e.g. `HUNTSMAN_SHODAN_KEY`. Must start with `HUNTSMAN_`.
        name: String,
        /// Raw value to store.
        value: String,
    },
    /// Add a key to the pool for a service.
    Add {
        /// Service name (shodan, intelx, dehashed, wigle, etc.)
        service: String,
        /// The API key value.
        key: String,
        /// Optional notes (e.g. "free tier", "expires 2026-12").
        #[arg(long)]
        notes: Option<String>,
        /// Environment this key belongs to (e.g. prod, dev, personal).
        #[arg(long)]
        env: Option<String>,
    },
    /// List all keys in the pool.
    List {
        /// Filter by service name.
        service: Option<String>,
        /// Filter by environment (e.g. prod, dev). Omit for all.
        #[arg(long)]
        env: Option<String>,
    },
    /// Export the pool (or one environment) to JSON for backup / transfer.
    ///
    /// Writes the SAME shape `import-json` reads, so an export round-trips. The
    /// output contains PLAINTEXT key values — it is written `0600` to a file, or
    /// to stdout with a stderr warning. Treat the result as a secret.
    Export {
        /// Destination file. Omit to write JSON to stdout.
        #[arg(long)]
        out: Option<String>,
        /// Export only this environment (e.g. prod). Omit for the whole pool.
        #[arg(long)]
        env: Option<String>,
    },
    /// Import keys from a JSON export (merges; dedup by value, idempotent).
    ImportJson {
        /// Path to the JSON file produced by `keys export`.
        file: String,
        /// Stamp every imported key with this environment label.
        #[arg(long)]
        env: Option<String>,
    },
    /// Revoke a key — retained for audit but never used again (compromised /
    /// retired).
    Revoke {
        /// Service name.
        service: String,
        /// Key value to revoke.
        key: String,
    },
    /// Rotate a key: revoke the old value and add a new one in the same
    /// environment, preserving provenance.
    Rotate {
        /// Service name.
        service: String,
        /// The current (old) key value to revoke.
        old: String,
        /// The new key value to add.
        new: String,
    },
    /// Validate keys against live endpoints.
    Validate {
        /// Validate only this service. Omit to validate all.
        service: Option<String>,
    },
    /// Remove a key from the pool.
    Remove {
        /// Service name.
        service: String,
        /// Key value to remove.
        key: String,
    },
    /// Show pool status summary.
    Status,
    /// Show the persistent retention **BANK** (`key_vault`) — every API key ever
    /// found in a victim/stealer query, categorised, OSINT-providers first (★).
    ///
    /// This is the catalogue of harvested keys as OSINT intelligence: it is
    /// **retention-only**, never used to authenticate, and is distinct from the
    /// rotation pool shown by `list`/`status`. Use it to compare detected OSINT
    /// keys against your own and to identify other OSINT practitioners.
    Bank {
        /// Show only OSINT/recon-provider keys (the practitioner-identifying set).
        #[arg(long)]
        osint: bool,
        /// Filter by service name (e.g. shodan, dehashed).
        #[arg(long)]
        service: Option<String>,
        /// Reveal full key values (default: masked). Output is a secret.
        #[arg(long)]
        reveal: bool,
        /// Print a per-category OSINT-provider census instead of each key.
        #[arg(long)]
        census: bool,
    },
    /// List supported service names and their categories.
    Services,
    /// Import candidate keys/credentials from a TSV file.
    ///
    /// Expected format (tab-separated, header optional):
    ///   source_file\tfield\ttags\tvalue\turl_or_context
    ///
    /// This is the format produced by `extract_all.py` on OathNet
    /// stealer/breach dumps. The value column is matched against the
    /// 80+ API-key prefix patterns and the 165+ service-domain map;
    /// only entries that classify as recognised keys are imported.
    ///
    /// The TSV stays on disk — no values are committed anywhere. The
    /// pool file ($HOME/.huntsman_keys.json, chmod 0600) records the
    /// imported entries with `discovered_by="tsv_import:<source>"`
    /// provenance so they can be removed later.
    ImportTsv {
        /// Path to the TSV file.
        file: String,
        /// Validate each imported key against its service's live
        /// endpoint after import (default: store as Untested).
        #[arg(long)]
        validate: bool,
        /// Dry run — print what would be imported without writing.
        #[arg(long)]
        dry_run: bool,
    },
}

pub(super) async fn cmd_keys(action: KeysAction) -> Result<()> {
    use crate::util::key_pool::{self, KeyEntry, KeyStatus};

    let pool = key_pool::global_pool();

    match action {
        KeysAction::Set { name, value } => {
            use std::collections::BTreeMap;
            let mut updates = BTreeMap::new();
            updates.insert(name.clone(), value);
            crate::util::keys::write_keys(&updates, &[])
                .map_err(|e| Error::Other(e.to_string()))?;
            println!("✓ {name} set in {}", crate::util::keys::env_path());
        }
        KeysAction::Add {
            service,
            key,
            notes,
            env,
        } => {
            // The rotation pool only holds reusable keyed-provider keys
            // (`pool.add` rejects everything else via `is_poolable_service`).
            // Check poolability up front so a non-poolable service gets an honest
            // error + non-zero exit, instead of the old "Adding anyway" promise
            // followed by a silent drop and a false "already exists" (T2.12).
            if !crate::util::service_defs::is_poolable_service(&service) {
                let names: Vec<&str> = key_pool::service_defs().iter().map(|s| s.name).collect();
                return Err(Error::Other(format!(
                    "'{service}' is not a poolable service — its key can't be added to the \
                     rotation pool. Poolable services: {}. For a one-off key, use \
                     `hse set-key <HUNTSMAN_*_KEY> <value>`.",
                    names.join(", ")
                )));
            }
            let mut entry = KeyEntry::new(&key);
            entry.notes = notes;
            entry.environment = env;
            if pool.add(&service, entry) {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
                println!(
                    "Added key to '{service}' pool ({} total)",
                    pool.service_count(&service)
                );
            } else {
                // Poolability is verified above, so a `false` here is a genuine
                // duplicate value, not a non-poolable rejection.
                println!("Key already exists in '{service}' pool.");
            }
        }

        KeysAction::List { service, env } => {
            let snap = pool.snapshot();
            let services: Vec<(&String, &Vec<KeyEntry>)> = if let Some(ref s) = service {
                let lower = s.to_lowercase();
                snap.services.iter().filter(|(k, _)| **k == lower).collect()
            } else {
                snap.services.iter().collect()
            };

            if services.is_empty() {
                println!("No keys in pool.");
                return Ok(());
            }

            for (svc, entries) in &services {
                // Apply the optional environment filter per service.
                let shown: Vec<&KeyEntry> = entries
                    .iter()
                    .filter(|e| env.as_deref().is_none_or(|want| e.environment() == want))
                    .collect();
                if shown.is_empty() {
                    continue;
                }
                println!("\n[{svc}] ({} keys)", shown.len());
                for (i, e) in shown.iter().enumerate() {
                    // Char-aware truncation: byte-indexing panics on
                    // multi-byte UTF-8 keys (rare but real for
                    // imported test tokens).
                    let masked = mask_key(&e.value);
                    let notes = e.notes.as_deref().unwrap_or("");
                    println!(
                        "  {}: {} [{}] env={} uses={} {}",
                        i + 1,
                        masked,
                        e.status.as_str(),
                        e.environment(),
                        e.use_count,
                        notes
                    );
                    if let Some(ts) = e.discovered_at {
                        let by = e.discovered_by.as_deref().unwrap_or("unknown");
                        let scan = e
                            .discovered_in_scan
                            .as_deref()
                            .map_or("-", |s| &s[..8.min(s.len())]);
                        let src = e.source_entity.as_deref().unwrap_or("-");
                        println!("       discovered: ts={ts} by={by} scan={scan} entity={src}");
                    }
                }
            }
        }

        KeysAction::Validate { service } => {
            let snap = pool.snapshot();
            let targets: Vec<(String, Vec<KeyEntry>)> = if let Some(ref s) = service {
                let lower = s.to_lowercase();
                snap.services
                    .into_iter()
                    .filter(|(k, _)| *k == lower)
                    .collect()
            } else {
                snap.services.into_iter().collect()
            };

            if targets.is_empty() {
                println!("No keys to validate.");
                return Ok(());
            }

            let mut validated = 0u32;
            let mut active = 0u32;
            for (svc, entries) in &targets {
                for entry in entries {
                    print!("  {svc}: testing {}… ", char_prefix(&entry.value, 8));
                    match key_pool::validate_key(svc, &entry.value).await {
                        Some(true) => {
                            pool.mark_validated(svc, &entry.value, true);
                            println!("ACTIVE");
                            active += 1;
                        }
                        Some(false) => {
                            pool.mark_validated(svc, &entry.value, false);
                            println!("INVALID");
                        }
                        None => {
                            println!("UNKNOWN (no validator for service)");
                        }
                    }
                    validated += 1;
                }
            }
            key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
            println!("\nValidated {validated} keys: {active} active.");
        }

        KeysAction::Remove { service, key } => {
            if pool.remove(&service, &key) {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
                println!("Removed key from '{service}' pool.");
            } else {
                println!("Key not found in '{service}' pool.");
            }
        }

        KeysAction::Export { out, env } => {
            let json = pool
                .export_json(env.as_deref())
                .map_err(|e| Error::Other(format!("export: {e}")))?;
            match out {
                Some(path) => {
                    // Reuse the pool's own `0600` writer so an exported secret is
                    // never left world-readable.
                    key_pool::write_secret_file(&path, &json)
                        .map_err(|e| Error::Other(format!("write {path}: {e}")))?;
                    eprintln!(
                        "Exported {} to {path} (mode 0600). It contains PLAINTEXT keys — keep it secret.",
                        env.as_deref().map_or_else(
                            || "the key pool".to_string(),
                            |e| format!("environment '{e}'")
                        )
                    );
                }
                None => {
                    eprintln!(
                        "# WARNING: the JSON below contains PLAINTEXT API keys — treat as a secret."
                    );
                    println!("{json}");
                }
            }
        }

        KeysAction::ImportJson { file, env } => {
            let json = std::fs::read_to_string(&file)
                .map_err(|e| Error::Other(format!("read {file}: {e}")))?;
            let added = pool
                .import_json(&json, env.as_deref())
                .map_err(|e| Error::Other(format!("parse {file}: {e}")))?;
            if added > 0 {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
            }
            println!(
                "Imported {added} new key(s) from {file}{}.",
                env.as_deref()
                    .map_or_else(String::new, |e| format!(" into environment '{e}'"))
            );
        }

        KeysAction::Revoke { service, key } => {
            if pool.revoke(&service, &key) {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
                println!("Revoked key in '{service}' pool (retained for audit, never used again).");
            } else {
                println!("Key not found in '{service}' pool.");
            }
        }

        KeysAction::Rotate { service, old, new } => {
            if pool.rotate(&service, &old, &new) {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
                println!("Rotated '{service}' key: old value revoked, new value added.");
            } else {
                println!("Old key not found in '{service}' pool — nothing rotated.");
            }
        }

        KeysAction::Status => {
            let snap = pool.snapshot();
            if snap.services.is_empty() {
                println!("Key pool is empty. Use `hse keys add <service> <key>` to add keys.");
                println!("\nPool file: {}", key_pool::pool_path().display());
                return Ok(());
            }

            println!(
                "{:<20} {:>5} {:>6} {:>7} {:>8}  CATEGORY",
                "SERVICE", "TOTAL", "ACTIVE", "INVALID", "USED"
            );
            println!("{}", "-".repeat(65));

            let mut sorted: Vec<_> = snap.services.iter().collect();
            sorted.sort_by_key(|(a, _)| *a);

            for (svc, entries) in &sorted {
                let active = entries.iter().filter(|e| e.is_usable()).count();
                let invalid = entries
                    .iter()
                    .filter(|e| e.status == KeyStatus::Invalid)
                    .count();
                let total_uses: u64 = entries.iter().map(|e| e.use_count).sum();
                let cat = key_pool::find_service(svc).map_or("custom", |d| d.category);
                println!(
                    "{:<20} {:>5} {:>6} {:>7} {:>8}  {cat}",
                    svc,
                    entries.len(),
                    active,
                    invalid,
                    total_uses
                );
            }
            println!(
                "\nTotal: {} keys ({} active) across {} services",
                pool.total_keys(),
                pool.total_active(),
                snap.services.len()
            );
            println!("Pool file: {}", key_pool::pool_path().display());
        }

        KeysAction::Bank {
            osint,
            service,
            reveal,
            census,
        } => {
            use crate::util::key_vault;

            if census {
                let rows = key_vault::osint_provider_census();
                if rows.is_empty() {
                    println!("No OSINT-provider keys banked yet.");
                } else {
                    println!("OSINT-provider key census (retained, never used):");
                    let mut last_cat = "";
                    for (cat, svc, n) in &rows {
                        if *cat != last_cat {
                            println!("\n[{cat}]");
                            last_cat = cat;
                        }
                        println!("  {svc:<22} {n:>4} key(s)");
                    }
                }
                println!("\nBank file: {}", key_vault::vault_path().display());
                return Ok(());
            }

            let mut entries = if osint {
                key_vault::osint_entries()
            } else {
                key_vault::all_entries()
            };
            if let Some(ref s) = service {
                let lower = s.to_lowercase();
                entries.retain(|e| e.service.to_lowercase() == lower);
            }
            // Full list: OSINT providers first, then by category / frequency.
            if !osint {
                entries.sort_by(|a, b| {
                    b.is_osint()
                        .cmp(&a.is_osint())
                        .then(a.osint_category().cmp(&b.osint_category()))
                        .then(b.discovery_count.cmp(&a.discovery_count))
                        .then(a.service.cmp(&b.service))
                });
            }

            if entries.is_empty() {
                println!("Key bank is empty (no keys found in scans yet).");
                println!("Bank file: {}", key_vault::vault_path().display());
                return Ok(());
            }

            let osint_n = entries.iter().filter(|e| e.is_osint()).count();
            if reveal {
                eprintln!(
                    "# WARNING: --reveal prints PLAINTEXT keys. Treat the output as a secret."
                );
            }
            println!(
                "BANK — {} retained key(s), {osint_n} OSINT-provider (★). Retention-only; never reused.\n",
                entries.len()
            );
            println!(
                "{:<2} {:<20} {:<18} {:<24} {:<9} SOURCE",
                "", "CATEGORY", "SERVICE", "KEY", "SEEN"
            );
            println!("{}", "-".repeat(86));
            for e in &entries {
                println!("{}", bank_row(e, reveal));
            }
            println!("\nBank file: {}", key_vault::vault_path().display());
        }

        KeysAction::Services => {
            let defs = key_pool::service_defs();
            println!(
                "{:<18} {:<14} {:<26} ENV VAR",
                "SERVICE", "CATEGORY", "TEST ENDPOINT"
            );
            println!("{}", "-".repeat(85));
            for d in defs {
                let short_url = if d.test_url.len() > 25 {
                    format!("{}…", &d.test_url[..24])
                } else {
                    d.test_url.to_string()
                };
                println!(
                    "{:<18} {:<14} {:<26} {}",
                    d.name, d.category, short_url, d.env_var
                );
            }
        }

        KeysAction::ImportTsv {
            file,
            validate,
            dry_run,
        } => {
            let path = std::path::Path::new(&file);
            if !path.exists() {
                return Err(Error::Other(format!("TSV file not found: {file}")));
            }
            let content = std::fs::read_to_string(path)
                .map_err(|e| Error::Other(format!("read {file}: {e}")))?;

            let pool_snapshot_before = pool.total_keys();
            let summary = run_tsv_import(&content, &file, dry_run, &pool);

            if !dry_run {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save pool: {e}")))?;
            }

            let added = pool.total_keys() as i64 - pool_snapshot_before as i64;
            println!(
                "\nTSV import {}: {} key(s) recognised, {} non-key values skipped (plaintext \
                 passwords / hashes / etc.), {} non-poolable (no vendor identity — surfaced as \
                 ApiKey entities elsewhere, not pooled), {} duplicates, {added} net additions \
                 to pool.",
                if dry_run { "DRY-RUN" } else { "complete" },
                summary.imported,
                summary.skipped_nonkey,
                summary.skipped_nonpoolable,
                summary.skipped_dup,
            );
            if !summary.stats.is_empty() {
                println!("\nBy service:");
                for (svc, n) in &summary.stats {
                    let roi = crate::util::key_roi::classify(svc);
                    println!("  {svc:<18}  {n:>4}  ({} tier)", roi.label());
                }
            }

            if validate && !dry_run {
                // Validate exactly the (service, value) pairs THIS run added —
                // tracked explicitly in `summary.imported_this_run` — never
                // the whole pool. The prior implementation matched entries by
                // comparing the TSV row's own internal `source_file` column
                // against the CLI's `file` argument, which are almost never
                // equal, so its fallback clause silently widened to "every
                // entry from any prior tsv_import run, ever" — re-testing
                // historical keys against live endpoints on every subsequent
                // import.
                println!(
                    "\nValidating {} key(s) imported by this run against live endpoints...",
                    summary.imported_this_run.len()
                );
                let mut active = 0u32;
                let mut invalid = 0u32;
                for (svc, value) in &summary.imported_this_run {
                    match key_pool::validate_key(svc, value).await {
                        Some(true) => {
                            pool.mark_validated(svc, value, true);
                            active += 1;
                        }
                        Some(false) => {
                            pool.mark_validated(svc, value, false);
                            invalid += 1;
                        }
                        None => {}
                    }
                }
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save pool: {e}")))?;
                println!("Validation done: {active} active, {invalid} invalid.");
            }
        }
    }
    Ok(())
}

/// Take up to `n` chars from the start of `s` — char-aware to avoid
/// the byte-indexing panic on multi-byte UTF-8 values.
fn char_prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Outcome of one `run_tsv_import` pass, everything the caller's summary
/// print + `--validate` step need.
#[derive(Debug)]
struct TsvImportSummary {
    stats: std::collections::BTreeMap<&'static str, usize>,
    imported: usize,
    skipped_nonkey: usize,
    skipped_nonpoolable: usize,
    skipped_dup: usize,
    /// (service, value) pairs actually added to the pool by THIS call —
    /// tracked explicitly so `--validate` tests only what this invocation
    /// imported, not every key any prior `import-tsv` run ever added.
    imported_this_run: Vec<(&'static str, String)>,
}

/// Classify and import every TSV row's `value` column as an API key. No
/// network I/O (that's the caller's separate `--validate` step) — takes
/// `pool: &key_pool::KeyPool` directly so it is unit-testable against a
/// fresh in-memory pool, not just the process-wide `global_pool()` singleton.
fn run_tsv_import(
    content: &str,
    file: &str,
    dry_run: bool,
    pool: &crate::util::key_pool::KeyPool,
) -> TsvImportSummary {
    use crate::util::key_harvest::identify_api_key;
    use crate::util::key_pool::{KeyEntry, KeyStatus};

    let mut summary = TsvImportSummary {
        stats: std::collections::BTreeMap::new(),
        imported: 0,
        skipped_nonkey: 0,
        skipped_nonpoolable: 0,
        skipped_dup: 0,
        imported_this_run: Vec::new(),
    };

    for (lineno, line) in content.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        // Header: source_file\tfield\ttags\tvalue\turl_or_context
        if lineno == 0 && (line.starts_with("source_file\t") || line.starts_with("source\t")) {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 4 {
            continue;
        }
        let source = fields[0];
        let field_name = fields[1];
        let value = fields[3].trim();
        if value.is_empty() {
            continue;
        }
        // Only import entries that classify as known API keys. Plaintext
        // dashboard passwords are deliberately skipped — they're account
        // credentials, not API keys, and using them would be account
        // takeover rather than API use.
        let Some((service, _)) = identify_api_key(value) else {
            summary.skipped_nonkey += 1;
            continue;
        };
        // Some shape-classified services carry no vendor identity
        // (`generic_hex`, `url_param_key`, …) and are never poolable —
        // `pool.add` rejects them just like a genuine duplicate value would,
        // so check up front (before the dry-run branch, so a dry run
        // accurately previews what a real run would do) and tally the two
        // cases separately instead of mislabelling every non-poolable
        // rejection as a "duplicate" (the same distinction `KeysAction::Add`
        // already makes explicit).
        if !crate::util::service_defs::is_poolable_service(service) {
            summary.skipped_nonpoolable += 1;
            continue;
        }
        if dry_run {
            println!("would import: service={service:<18}  src={source:<32}  field={field_name}");
            *summary.stats.entry(service).or_insert(0) += 1;
            summary.imported += 1;
            continue;
        }
        let mut entry = KeyEntry::new(value);
        entry.status = KeyStatus::Untested;
        entry.discovered_at = Some(crate::core::entity::unix_now());
        entry.discovered_by = Some(format!("tsv_import:{source}"));
        entry.notes = Some(format!(
            "Imported from TSV file: {file} (field={field_name})"
        ));
        let value_owned = value.to_string();
        if pool.add(service, entry) {
            summary.imported += 1;
            *summary.stats.entry(service).or_insert(0) += 1;
            summary.imported_this_run.push((service, value_owned));
        } else {
            summary.skipped_dup += 1;
        }
    }

    summary
}

/// Format one retention-bank entry as a display row. OSINT-provider keys are
/// marked `★` and show their category; infrastructure keys show `infrastructure`.
/// The key is masked unless `reveal`. Pure (no I/O) so it is unit-tested.
fn bank_row(e: &crate::util::key_vault::VaultEntry, reveal: bool) -> String {
    let cat = e.osint_category().unwrap_or("infrastructure");
    let mark = if e.is_osint() { "★" } else { " " };
    let key = if reveal {
        e.key_value.clone()
    } else {
        mask_key(&e.key_value)
    };
    format!(
        "{mark:<2} {cat:<20} {svc:<18} {key:<24} {seen:<9} {prov}",
        svc = e.service,
        seen = format!("×{}", e.discovery_count),
        prov = e.provider,
    )
}

/// Masked key display for the `hse keys` bank — delegates to the single
/// masking policy shared with the web dashboard's key-pool view
/// ([`crate::util::str_util::mask_secret`]), so the CLI and API can never
/// independently drift on how much of a stored key they reveal (as they once
/// did: this used to reimplement an `> 8`-char threshold, revealing 8 of an
/// unmasked 9-char key — or all of one 8 chars or shorter — instead of the
/// correct `< 16` full-mask cutoff).
fn mask_key(value: &str) -> String {
    crate::util::str_util::mask_secret(value)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
