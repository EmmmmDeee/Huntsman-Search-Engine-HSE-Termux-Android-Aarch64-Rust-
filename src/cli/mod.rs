//! CLI entry point: scan / serve / live / modules / keys / config /
//! diagnostics / update / export / import / ingest / diff / audit / radar.
//!
//! Surfaces every `ScanOptions` field as a flag so each scan is fully
//! customisable before launch. `serve` boots the HTTP server + SPA;
//! `live` re-runs the same scan on a fixed interval. `update` upgrades
//! the binary in place via `install.sh`. See `docs/USAGE.md` for the
//! full reference.

mod audit;
mod benchmark;
pub(crate) mod cells;
mod config;
mod diagnostics;
mod diff;
mod doctor;
mod engines;
pub(crate) mod export;
mod gap;
mod ingest;
mod keys_cmd;
mod live;
mod logging;
mod modules;
mod oathnet_batch;
mod provision;
mod radar;
mod scan;
mod selftest;
mod serve;
pub(crate) mod update;

use std::io::IsTerminal;
use std::sync::Arc;

use clap::Parser;
use crate::{
    core::{
        engine::ScanEngine,
        error::{Error, Result},
        module::ModuleCost,
        scan::{ScanStatus, TargetKind},
    },
    default_db_path,
    modules::registry,
    storage::Store,
    util::keys,
};

/// Resolve a scan-id selector for the read commands (`export` / `diff` / `audit`):
/// `latest` → the most-recent completed scan, anything else → itself, but only
/// after confirming the scan exists so a typo errors loudly instead of silently
/// operating on an empty/absent scan. One definition shared by all three so the
/// selector semantics can't drift (they were three near-identical copies).
pub(crate) fn resolve_scan_id(store: &Store, raw: &str) -> Result<String> {
    if raw == "latest" {
        return store
            .latest_completed_scan()?
            .map(|s| s.id)
            .ok_or_else(|| Error::Other("no completed scans in store".into()));
    }
    match store.get_scan(raw)? {
        None => Err(Error::Other(format!("scan {raw} not found"))),
        Some(scan) => {
            // A scan interrupted before finalise — a hang, a kill, an OOM, a power
            // loss — still CHECKPOINTED its enumerated/validated entities to the
            // store; its status simply never flipped to Complete. Refusing to read
            // it (the old behaviour) silently lost every collected identifier: a
            // breach-confirmed email, a SeekNow-enumerated handle, gone because the
            // run didn't reach the end. Never discard collected data: surface the
            // partial scan with a loud warning instead, so the findings are always
            // recoverable. (`latest` still resolves to the most-recent COMPLETE
            // scan, so routine reads are unaffected.)
            if scan.status != ScanStatus::Complete {
                eprintln!(
                    "⚠ scan {raw} is {status}, not complete — recovering its checkpointed \
                     (partial) entities; results may be incomplete",
                    status = scan.status.as_str()
                );
            }
            Ok(raw.to_string())
        }
    }
}

mod command;
pub use command::{Cli, Command};

pub async fn run() -> Result<()> {
    logging::initialize();

    let cli = Cli::parse();
    // Opportunistic, throttled, non-blocking self-update: any routine CLI use
    // keeps the binary current with GitHub main (the server has its own loop).
    // Best-effort and time-boxed — never delays or fails the command below.
    update::maybe_auto_update_cli(&cli.command).await;
    run_command(cli.command).await
}

async fn run_command(command: Command) -> Result<()> {
    match command {
        Command::Scan {
            kind,
            value,
            input_file,
            modules,
            exclude,
            throttle,
            min_confidence,
            free_only,
            passive_only,
            timeout,
            depth,
            recursive,
            full,
            auto,
            min_expand_confidence,
            max_entities,
            max_wall_time,
            max_concurrent,
            adaptive,
            max_roi,
            no_convex_budget,
            no_skip_dead_modules,
            no_regional,
            min_marginal_yield,
            expansion_strategy,
            seeknow_scan_cap,
            expand_all_identities,
            gate_speculative,
            profile,
            output,
            include_infra,
        } => {
            // In batch mode (`--input-file`) the per-line seeds supply the
            // targets, so a top-level `--value`/default seed is not required —
            // pass an empty placeholder that `run_batch` overwrites per seed.
            let value = if input_file.is_some() {
                value.unwrap_or_default()
            } else {
                resolve_seed(value, keys::default_seed())?
            };
            // `--full` is the no-compromise preset: force every module on (drop
            // the free/passive filters and any allowlist), deep recursion, and
            // no ROI pruning. It composes by overriding the narrowing flags.
            scan::cmd_scan(scan::ScanCmd {
                kind,
                value,
                input_file,
                modules: if full { None } else { modules },
                exclude,
                throttle_ms: throttle,
                min_confidence,
                free_only: free_only && !full,
                passive_only: passive_only && !full,
                module_timeout_ms: timeout,
                depth,
                recursive: recursive || full,
                auto,
                min_expand_confidence,
                max_entities,
                max_wall_time_secs: max_wall_time,
                max_concurrent,
                adaptive,
                max_roi: max_roi && !full,
                // Optionality/barbell allocation is on unless explicitly disabled
                // — every scan maximises value-per-query out of the box.
                convex_budget: !no_convex_budget,
                // Capability-aware dispatch is on unless explicitly disabled;
                // `--full` is the no-compromise preset, so it forces EVERY module
                // to run regardless of health (like its other narrowing-flag
                // overrides), never quarantining anything.
                skip_dead_modules: !no_skip_dead_modules && !full,
                // AU-focused regional searching is on unless explicitly disabled.
                regional_search: !no_regional,
                min_marginal_yield,
                expansion_strategy,
                seeknow_scan_cap,
                // `--full` is the no-compromise preset: maximise recall, so the
                // wrong-identity gate is lifted alongside the other narrowing
                // filters it already drops.
                expand_all_identities: expand_all_identities || full,
                gate_speculative,
                profile,
                output,
                // `--full` is the no-compromise preset: it also restores
                // platform-infra entities, matching the flag's documented
                // "implied by --full" behaviour.
                include_infra: include_infra || full,
            })
            .await
        }
        Command::Modules { category, json } => modules::cmd_modules(category, json),
        Command::Engines { json } => engines::cmd_engines(json).await,
        Command::Config { key, value } => config::cmd_config(key, value),
        Command::Diagnostics { json } => diagnostics::cmd_diagnostics(json).await,
        Command::Audit {
            csv,
            scan_id,
            log,
            json,
        } => audit::cmd_audit(csv, scan_id, log, json).await,
        Command::Benchmark { scan_id, json } => benchmark::cmd_benchmark(scan_id, json),
        Command::Gaps { scan_id, json } => gap::cmd_gaps(scan_id, json),
        Command::Doctor { live } => doctor::cmd_doctor(live).await,
        Command::Selftest { json } => selftest::cmd_selftest(json).await,
        Command::Provision {
            env_only,
            verify_only,
            dry_run,
        } => cmd_provision(env_only, verify_only, dry_run).await,
        Command::SetKey { name, value } => cmd_set_key(name, value),
        Command::Keys { action } => keys_cmd::cmd_keys(action).await,
        Command::Import { file, output } => cmd_import(&file, &output).await,
        Command::Ingest {
            file,
            output_format,
            min_confidence,
            auto_scan,
            output,
            extract_geolocation,
            generate_reverse_search_variants,
            image_variant_output_dir,
        } => {
            let args = ingest::IngestArgs {
                file: std::path::PathBuf::from(file),
                output_format,
                min_confidence,
                auto_scan,
                output: output.map(std::path::PathBuf::from),
                extract_geolocation,
                generate_reverse_search_variants,
                image_variant_output_dir: image_variant_output_dir.map(std::path::PathBuf::from),
            };
            ingest::run(args)
                .await
                .map_err(|e| Error::Other(e.to_string()))
        }
        Command::Serve { bind, no_key_write } => serve::cmd_serve(bind, !no_key_write).await,
        Command::Live {
            kind,
            value,
            interval,
            iterations,
            depth,
            free_only,
            passive_only,
            modules,
            exclude,
            throttle,
            min_confidence,
            min_expand_confidence,
            max_entities,
            max_wall_time,
            max_concurrent,
            max_roi,
            no_convex_budget,
            no_skip_dead_modules,
            no_regional,
            min_marginal_yield,
            expansion_strategy,
            seeknow_scan_cap,
            expand_all_identities,
            gate_speculative,
            radar,
            json,
        } => {
            let value = resolve_seed(value, keys::default_seed())?;
            live::cmd_live(live::LiveCmd {
                kind,
                value,
                interval,
                iterations,
                depth,
                free_only,
                passive_only,
                modules,
                exclude,
                throttle_ms: throttle,
                min_confidence,
                min_expand_confidence,
                max_entities,
                max_wall_time_secs: max_wall_time,
                max_concurrent,
                max_roi,
                // Optionality/barbell allocation is on unless explicitly disabled.
                convex_budget: !no_convex_budget,
                // Capability-aware dispatch is on unless explicitly disabled.
                skip_dead_modules: !no_skip_dead_modules,
                // AU-focused regional searching is on unless explicitly disabled.
                regional_search: !no_regional,
                min_marginal_yield,
                expansion_strategy,
                seeknow_scan_cap,
                expand_all_identities,
                gate_speculative,
                radar,
                json,
            })
            .await
        }
        Command::Radar {} => radar::cmd_radar().await,
        Command::Export {
            scan_id,
            format,
            out,
            include_infra,
            redact,
        } => export::cmd_export(scan_id, format, out, include_infra, redact).await,
        Command::Diff { from, to, format } => diff::cmd_diff(from, to, format),
        Command::Update { check, r#ref } => update::cmd_update(check, r#ref).await,
        Command::OathnetBatch {
            value,
            kind,
            no_stealer,
            no_permute,
            synthesize_emails,
            recurse_depth,
            max,
            page_size,
            execute,
            json,
        } => {
            oathnet_batch::cmd_oathnet_batch(oathnet_batch::BatchCmd {
                value,
                kind,
                no_stealer,
                no_permute,
                synthesize_emails,
                recurse_depth,
                max,
                page_size,
                execute,
                json,
            })
            .await
        }
        Command::Cells { action } => cells::cmd_cells(action).await,
    }
}

/// Resolve the effective `scan`/`live` target: the explicit CLI `--value` when
/// given (a blank value is treated as absent), otherwise the operator-local
/// default seed (`HUNTSMAN_DEFAULT_SEED`). Errors with actionable guidance when
/// neither is set. Pure over its inputs so the precedence is unit-testable and
/// the default-seed lookup stays a thin caller concern.
fn resolve_seed(cli_value: Option<String>, default_seed: Option<String>) -> Result<String> {
    cli_value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(default_seed)
        .ok_or_else(|| {
            Error::Other(
                "no target: pass --value <seed>, or set HUNTSMAN_DEFAULT_SEED in \
                 ~/.huntsman.env to your own default seed (kept local — never shipped)"
                    .to_string(),
            )
        })
}

// ─── Inline commands (small enough not to warrant their own file) ───────────

async fn cmd_provision(env_only: bool, verify_only: bool, dry_run: bool) -> Result<()> {
    println!("HSE v{} — provision", crate::VERSION);
    if !verify_only {
        provision::cmd_provision_env(dry_run)?;
    }
    if !env_only && !dry_run {
        provision::cmd_provision_verify().await?;
    } else if !env_only && dry_run {
        println!("==> Phase: verify (skipped under --dry-run)");
    }
    println!("\nDone.");
    Ok(())
}

fn cmd_set_key(name: String, value: String) -> Result<()> {
    use std::collections::BTreeMap;
    let mut updates = BTreeMap::new();
    updates.insert(name.clone(), value);
    keys::write_keys(&updates, &[]).map_err(|e| Error::Other(e.to_string()))?;
    println!("✓ {name} set in {}", keys::env_path());
    Ok(())
}

pub(crate) mod import;
use import::cmd_import;

// ─── Shared helpers (used by subcommand files) ─────────────────────────────

/// Parse a CLI `--kind` string into a [`TargetKind`], accepting both the terse
/// command-line aliases (`name`, `ip`, `org`, `coords`, …) and the canonical
/// snake_case form the system itself emits (`full_name`, `ip_address`) so a copied
/// canonical kind round-trips. Errors list every valid kind.
pub(super) fn parse_target_kind(s: &str) -> Result<TargetKind> {
    match s.to_lowercase().trim() {
        "email" => Ok(TargetKind::Email),
        "username" => Ok(TargetKind::Username),
        "phone" => Ok(TargetKind::Phone),
        // Accept the canonical snake_case form (`full_name`, `ip_address`) the
        // system itself emits (`canonical_str`, serde, API, entity `kind`) so a
        // copied canonical kind round-trips, alongside the terse CLI aliases.
        "full_name" | "fullname" | "name" => Ok(TargetKind::FullName),
        "ip_address" | "ipaddress" | "ip" => Ok(TargetKind::IpAddress),
        "domain" => Ok(TargetKind::Domain),
        "url" => Ok(TargetKind::Url),
        "asn" => Ok(TargetKind::Asn),
        "cidr" | "netblock" | "netrange" => Ok(TargetKind::Cidr),
        "coordinates" | "coords" => Ok(TargetKind::Coordinates),
        "address" => Ok(TargetKind::Address),
        "organisation" | "org" => Ok(TargetKind::Organisation),
        "abn" | "acn" | "abn_acn" => Ok(TargetKind::AbnAcn),
        "apikey" | "api_key" | "key" => Ok(TargetKind::ApiKey),
        "mac" | "bssid" | "mac_address" => Ok(TargetKind::MacAddress),
        "crypto" | "crypto_address" | "wallet" | "btc" | "eth" => Ok(TargetKind::CryptoAddress),
        "device_id" | "deviceid" | "tower" | "cell" => Ok(TargetKind::DeviceId),
        "ssid" | "wifi" | "wifi_name" => Ok(TargetKind::Ssid),
        "tracking_id" | "trackingid" | "ga" | "gtm" => Ok(TargetKind::TrackingId),
        other => Err(Error::InvalidTarget(format!(
            "unknown target kind '{other}'. Valid: email, username, phone, name, ip, cidr, domain, url, asn, coords, address, org, abn, apikey, mac, crypto, tower, tracking_id"
        ))),
    }
}

/// Human-display form of a module cost for CLI tables ("key-gated", hyphen).
/// Deliberately distinct from the canonical machine identifier
/// [`ModuleCost::as_str`] ("key_gated"), which serde/the API/the module graph
/// emit — this is presentation, that is wire format.
pub(super) fn cost_label(c: ModuleCost) -> &'static str {
    match c {
        ModuleCost::Free => "free",
        ModuleCost::KeyGated => "key-gated",
        ModuleCost::Paid => "paid",
    }
}

/// Split a comma-separated CLI option (e.g. `--modules a,b,c`) into trimmed
/// parts, or `None` when the option was absent.
pub(super) fn split_csv(s: Option<String>) -> Option<Vec<String>> {
    s.map(|s| s.split(',').map(|m| m.trim().to_string()).collect())
}

/// Build the shared on-device CLI runtime: open the SQLite store (pruning aged
/// events first), create the broadcast [`EventBus`](crate::core::event::EventBus),
/// and construct the [`ScanEngine`] over the full module registry. Every
/// scan/live/audit command starts from this one setup.
pub(super) fn build_runtime(
    bus_capacity: usize,
) -> Result<(
    Arc<dyn crate::core::port::StoragePort>,
    crate::core::event::EventBus,
    Arc<ScanEngine>,
)> {
    let db = Store::open(&default_db_path())?;
    let _ = db.prune_events(
        crate::core::port::EVENTS_RETENTION_SECS,
        crate::core::port::EVENTS_MAX_ROWS,
    );
    let _ = db.prune_raw_archive(crate::core::port::RAW_ARCHIVE_MAX_ROWS);
    let store: Arc<dyn crate::core::port::StoragePort> = Arc::new(db);
    let (bus, _rx) = tokio::sync::broadcast::channel(bus_capacity);
    let engine = Arc::new(ScanEngine::new(registry(), Arc::clone(&store), bus.clone()));
    Ok((store, bus, engine))
}

/// Whether to emit ANSI colour: false when `NO_COLOR` is set (the de-facto
/// standard) or when stdout is not a TTY (piped/redirected output stays plain).
pub(super) fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

/// Colour a value by its confidence TIER (green Verified / yellow Probable /
/// red Candidate) — driven by the canonical
/// [`Classification`](crate::core::entity::Classification) ladder rather than
/// re-stated threshold literals, so a tier recalibration recolours the CLI
/// automatically.
pub(super) fn color_confidence(c_eff: f64, text: &str, color: bool) -> String {
    use crate::core::entity::Classification;
    if !color {
        return text.to_string();
    }
    match Classification::from_c_eff(c_eff) {
        Classification::Verified => format!("\x1b[32m{text}\x1b[0m"),
        Classification::Probable => format!("\x1b[33m{text}\x1b[0m"),
        Classification::Candidate => format!("\x1b[31m{text}\x1b[0m"),
    }
}

/// Colour a correlation severity label for the CLI (bold-red Critical, red High,
/// yellow Medium, dim otherwise) — the severity sibling of [`color_confidence`].
/// A no-op when `color` is false (piped output / `NO_COLOR`).
pub(super) fn color_severity(severity: &str, color: bool) -> String {
    if !color {
        return severity.to_string();
    }
    match severity.trim() {
        "critical" => format!("\x1b[1;31m{severity}\x1b[0m"),
        "high" => format!("\x1b[31m{severity}\x1b[0m"),
        "medium" => format!("\x1b[33m{severity}\x1b[0m"),
        _ => format!("\x1b[2m{severity}\x1b[0m"),
    }
}

/// Truncate `s` to at most `max` **characters** (not bytes — Unicode-safe),
/// appending `…` when shortened. A bare `s.truncate(max)` would panic on a
/// multi-byte boundary, so column-fitting CLI output goes through this.
pub(super) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Resolve a relation-endpoint UID to a human label: apply `found` to the
/// entity when `by_uid` resolves it, else a short-uid stub `"abcd1234…"`. The
/// hex-slice fallback lives HERE, in one place, so every relations renderer
/// (dossier RELATIONS, the `export` full render, and any future one) shows the
/// identical stub for an unresolvable endpoint and can never drift. UIDs are
/// hex ASCII, so the byte slice is char-boundary safe.
pub(super) fn relation_endpoint_label(
    by_uid: &std::collections::HashMap<&str, &crate::core::entity::Entity>,
    uid: &str,
    found: impl FnOnce(&crate::core::entity::Entity) -> String,
) -> String {
    by_uid
        .get(uid)
        .map_or_else(|| format!("{}…", &uid[..uid.len().min(8)]), |e| found(e))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
