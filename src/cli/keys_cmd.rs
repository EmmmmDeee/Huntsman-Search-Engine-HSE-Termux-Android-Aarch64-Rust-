//! `hse keys` — manage the global API-key pool.
//!
//! Subcommands: add / list / validate / remove / status / services /
//! import-tsv. The pool lives at $HOME/.huntsman_keys.json (mode 0600)
//! and is shared across scans; every `identify_api_key` discovery and
//! `hse set-key` mutation lands here.

use clap::Subcommand;

use crate::core::error::{Error, Result};

#[derive(Subcommand)]
pub enum KeysAction {
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
    /// Actively harvest API keys from OathNet stealer logs.
    ///
    /// Queries OathNet's stealer index for high-value provider domains and pools
    /// every API key found — unlike a normal scan, which only sees keys that
    /// happen to appear in the *target's* own rows. Self-scaling: harvested
    /// breach-API keys (OathNet / see-know / dehashed) grow the pools the engine
    /// reuses. Uses the OathNet key (env `HUNTSMAN_OATHNET_KEY` or the embedded
    /// default) and respects its daily/per-run quota budget.
    Harvest {
        /// Maximum service domains to query (each costs one OathNet lookup).
        #[arg(long)]
        limit: Option<usize>,
        /// Skip validating harvested keys against their live endpoints. By
        /// default every harvested key is validated and marked Active/Invalid
        /// so the pool only hands modules verified-live keys.
        #[arg(long)]
        no_validate: bool,
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
        KeysAction::Add {
            service,
            key,
            notes,
            env,
        } => {
            if key_pool::find_service(&service).is_none() {
                let names: Vec<&str> = key_pool::service_defs().iter().map(|s| s.name).collect();
                println!("Unknown service '{service}'. Known: {}", names.join(", "));
                println!("Adding anyway — key will be stored but not auto-validated.");
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
                            .map(|s| &s[..8.min(s.len())])
                            .unwrap_or("-");
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

        KeysAction::Harvest { limit, no_validate } => {
            use crate::modules::oathnet_pro::key_harvest;
            let limit = limit.unwrap_or(key_harvest::DEFAULT_HARVEST_LIMIT);
            let oathnet_key = crate::util::oathnet::resolve_key(None).to_string();
            let targets = key_harvest::harvest_targets(limit);
            println!(
                "Harvesting API keys from OathNet across {} service domain(s) \
                 (limit {limit})…",
                targets.len()
            );
            // The shared budget is per-scan; reset so a manual harvest gets its
            // own allowance instead of inheriting a prior run's exhaustion.
            crate::util::oathnet::reset_budget();
            let (report, entities) =
                key_harvest::harvest_keys(&oathnet_key, limit, "keys-harvest").await;
            // harvest_keys pools each discovered key via the emit path; persist.
            key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save: {e}")))?;
            println!(
                "Queried {} domain(s); found {} key(s).",
                report.domains_queried, report.keys_found
            );
            if report.keys_found > 0 {
                let mut svcs: Vec<(&String, &usize)> = report.by_service.iter().collect();
                svcs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                for (svc, n) in svcs {
                    println!("  {svc}: {n}");
                }
                if no_validate {
                    println!("\nPooled (Untested) to {}", key_pool::pool_path().display());
                } else {
                    println!("\nValidating harvested keys against live endpoints…");
                    let (live, checked) = key_harvest::validate_harvested(&entities).await;
                    println!(
                        "Validated {checked} key(s): {live} live, {} dead/invalid.",
                        checked.saturating_sub(live)
                    );
                    println!("Pooled to {}", key_pool::pool_path().display());
                }
            } else {
                println!("No keys found (empty stealer matches, or OathNet quota exhausted).");
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
            use crate::modules::oathnet_pro::key_harvest::identify_api_key;
            let path = std::path::Path::new(&file);
            if !path.exists() {
                return Err(Error::Other(format!("TSV file not found: {file}")));
            }
            let content = std::fs::read_to_string(path)
                .map_err(|e| Error::Other(format!("read {file}: {e}")))?;

            let mut stats: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            let mut imported = 0usize;
            let mut skipped_nonkey = 0usize;
            let mut skipped_dup = 0usize;
            let pool_snapshot_before = pool.total_keys();

            for (lineno, line) in content.lines().enumerate() {
                if line.is_empty() {
                    continue;
                }
                // Header: source_file\tfield\ttags\tvalue\turl_or_context
                if lineno == 0
                    && (line.starts_with("source_file\t") || line.starts_with("source\t"))
                {
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
                // Only import entries that classify as known API keys.
                // Plaintext dashboard passwords are deliberately skipped —
                // they're account credentials, not API keys, and using
                // them would be account takeover rather than API use.
                let Some((service, _)) = identify_api_key(value) else {
                    skipped_nonkey += 1;
                    continue;
                };
                if dry_run {
                    println!(
                        "would import: service={service:<18}  src={source:<32}  field={field_name}"
                    );
                    *stats.entry(service).or_insert(0) += 1;
                    imported += 1;
                    continue;
                }
                let mut entry = key_pool::KeyEntry::new(value);
                entry.status = key_pool::KeyStatus::Untested;
                entry.discovered_at = Some(crate::core::entity::unix_now());
                entry.discovered_by = Some(format!("tsv_import:{source}"));
                entry.notes = Some(format!(
                    "Imported from TSV file: {file} (field={field_name})"
                ));
                if pool.add(service, entry) {
                    imported += 1;
                    *stats.entry(service).or_insert(0) += 1;
                } else {
                    skipped_dup += 1;
                }
            }

            if !dry_run {
                key_pool::save_pool(&pool).map_err(|e| Error::Other(format!("save pool: {e}")))?;
            }

            let added = pool.total_keys() as i64 - pool_snapshot_before as i64;
            println!(
                "\nTSV import {}: {imported} key(s) recognised, {skipped_nonkey} non-key \
                 values skipped (plaintext passwords / hashes / etc.), {skipped_dup} \
                 duplicates, {added} net additions to pool.",
                if dry_run { "DRY-RUN" } else { "complete" }
            );
            if !stats.is_empty() {
                println!("\nBy service:");
                for (svc, n) in &stats {
                    let roi = crate::util::key_roi::classify(svc);
                    println!("  {svc:<18}  {n:>4}  ({} tier)", roi.label());
                }
            }

            if validate && !dry_run {
                println!("\nValidating imported keys against live endpoints...");
                let snap = pool.snapshot();
                let mut active = 0u32;
                let mut invalid = 0u32;
                for (svc, entries) in &snap.services {
                    for entry in entries {
                        if entry.discovered_by.as_deref() != Some(&format!("tsv_import:{file}"))
                            && !entry
                                .discovered_by
                                .as_deref()
                                .map(|s| s.starts_with("tsv_import:"))
                                .unwrap_or(false)
                        {
                            continue;
                        }
                        match key_pool::validate_key(svc, &entry.value).await {
                            Some(true) => {
                                pool.mark_validated(svc, &entry.value, true);
                                active += 1;
                            }
                            Some(false) => {
                                pool.mark_validated(svc, &entry.value, false);
                                invalid += 1;
                            }
                            None => {}
                        }
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

/// Char-aware masked key display: `ABCD…WXYZ` for values longer than
/// 8 chars, full value otherwise. Byte-indexing the value directly
/// panics when the key contains multi-byte UTF-8 (rare but real for
/// imported test tokens). Operates on chars instead.
fn mask_key(value: &str) -> String {
    let total = value.chars().count();
    if total > 8 {
        let head: String = value.chars().take(4).collect();
        let tail: String = value.chars().skip(total - 4).collect();
        format!("{head}…{tail}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{char_prefix, mask_key};

    #[test]
    fn mask_key_short_value_returned_verbatim() {
        assert_eq!(mask_key(""), "");
        assert_eq!(mask_key("abc"), "abc");
        assert_eq!(mask_key("abcdefgh"), "abcdefgh");
    }

    #[test]
    fn mask_key_long_value_truncates() {
        assert_eq!(mask_key("AKIAIOSFODNN7EXAMPLE"), "AKIA…MPLE");
    }

    #[test]
    fn mask_key_handles_multibyte_chars() {
        // Pre-fix this byte-indexed `&v[..4]`/`&v[len-4..]` would panic
        // for a value whose 4th byte falls inside a multi-byte char.
        let v = "𝕊éCRet𝕊éCRet"; // 12 chars, 22 bytes
        let m = mask_key(v);
        assert!(m.contains('…'));
        assert_eq!(m.chars().count(), 9);
    }

    #[test]
    fn char_prefix_byte_safe() {
        assert_eq!(char_prefix("abcdef", 4), "abcd");
        // Multi-byte safe: 𝕊 is 4 bytes, so byte-slicing at 1 would panic.
        assert_eq!(char_prefix("𝕊abc", 2), "𝕊a");
    }
}
