//! `hse` command-line surface: the clap `Parser`/`Subcommand` definitions.
//!
//! Split out of `cli/mod.rs` so the argument grammar (one large
//! `#[derive(Subcommand)]` enum mirroring the full `ScanOptions` flag surface)
//! lives apart from `run()`'s dispatch and the shared helpers. Reaches the
//! sibling `keys_cmd::KeysAction` sub-grammar through `super`.

use clap::{Parser, Subcommand};

use super::keys_cmd::KeysAction;

#[derive(Parser)]
#[command(
    name = "hse",
    version = crate::VERSION,
    about = "Huntsman Search Engine — Termux aarch64 OSINT / GEOINT prototype",
    long_about = "Pure-Rust OSINT scaffold for Termux on Android aarch64.\n\
                  80+ modules (most free, no key), autonomous depth-bounded expansion.\n\
                  Docs: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
// Scan has many fields (intentional — full ScanOptions surface as CLI flags).
// Boxing every field is uglier than the size disparity warrants.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Run a single scan and print the entities found.
    Scan {
        /// Target kind: email, username, phone, name, ip, domain, url, asn, coords,
        /// address, org, abn, mac, apikey. Omit (or pass `auto`) to auto-detect the
        /// kind from the value — the unified scan, e.g. `hse scan -v alice@example.com`.
        #[arg(short, long)]
        kind: Option<String>,
        /// Target value (e.g. example.com, foo@bar.com). Optional — omit to use
        /// the operator-local default seed (`HUNTSMAN_DEFAULT_SEED` in
        /// ~/.huntsman.env), so you can run a bare `hse scan` without retyping it.
        // allow_hyphen_values so a value that legitimately begins with `-`
        // (e.g. a southern-hemisphere coordinate `-33.86,151.20`) is taken as
        // the value, not parsed by clap as an unknown short flag.
        #[arg(short, long, allow_hyphen_values = true)]
        value: Option<String>,
        /// Comma-separated allowlist of module names.
        #[arg(short, long)]
        modules: Option<String>,
        /// Comma-separated exclude list.
        #[arg(long)]
        exclude: Option<String>,
        /// Delay between module dispatches, in milliseconds. Default 250 paces
        /// dispatch so a deep/everything scan doesn't flood the link or trip
        /// provider rate limits; set 0 for the fastest (burstier) behaviour.
        #[arg(short, long, default_value_t = 250)]
        throttle: u64,
        /// Drop entities whose base confidence is below this.
        #[arg(long)]
        min_confidence: Option<f64>,
        /// Skip key-gated and paid modules.
        #[arg(long)]
        free_only: bool,
        /// Skip non-passive modules (network-reaching).
        #[arg(long)]
        passive_only: bool,
        /// Per-module timeout override, in milliseconds.
        #[arg(long)]
        timeout: Option<u64>,
        /// Recursive expansion depth. 0 = single round; 1+ auto-feeds discovered
        /// entities back as new scan targets, up to N rounds deep. Omit to use
        /// the product default (2); `--auto`/`--recursive` override an omitted
        /// value.
        #[arg(short, long)]
        depth: Option<u32>,
        /// Shorthand for deep recursive expansion: sets depth to MAX_DEPTH (3)
        /// and min_expand_confidence=0.40. Overridden by an explicit --depth.
        #[arg(short = 'R', long)]
        recursive: bool,
        /// COMPLETE scan — the no-compromise preset. Auto-detects the seed kind,
        /// runs EVERY module (overrides --free-only/--passive-only/--modules),
        /// expands to MAX_DEPTH (3) at the Probable floor, and disables ROI
        /// pruning so nothing is skipped. The single "get everything" option.
        #[arg(
            short = 'F',
            long,
            visible_alias = "complete",
            visible_alias = "everything"
        )]
        full: bool,
        /// Automatically select optimal expansion depth based on seed type
        /// and available API keys. Uses expected-value analysis to determine
        /// the depth where marginal yield justifies the cost.
        #[arg(short = 'A', long)]
        auto: bool,
        /// Only expand entities whose C_eff is at least this. Default 0.50
        /// (Probable tier and above). Set 0.75 for strict Verified-only expansion.
        #[arg(long, default_value_t = 0.50)]
        min_expand_confidence: f64,
        /// Hard cap on total entities. Stops expansion when reached.
        #[arg(long)]
        max_entities: Option<usize>,
        /// Hard cap on total wall-time in seconds. Stops expansion when exceeded.
        #[arg(long)]
        max_wall_time: Option<u64>,
        /// Modules to run in parallel per round. Default 2 (gentle — avoids
        /// flooding the link / tripping rate limits). Raise it when the network
        /// can take it; set 0 for fully sequential dispatch (low-power devices).
        #[arg(long, default_value_t = 2)]
        max_concurrent: usize,
        /// Read ~/.huntsman/module_stats.json and skip modules with
        /// historical zero-yield rate ≥80% over ≥5 scans. Closes the
        /// self-optimization feedback loop — every scan informs the next.
        #[arg(long)]
        adaptive: bool,
        /// Maximise ROI per dispatch: skip already-saturated entities
        /// (≥2 corroborating sources, c_eff ≥ 0.85), keep only top-K
        /// candidates per round (K = 2×max_concurrent + 8), and
        /// terminate recursion when marginal yield falls below floor
        /// (default 0.75 new entities per dispatched target).
        #[arg(long)]
        max_roi: bool,
        /// Convex (optionality / barbell) budget allocation: re-weight expansion
        /// candidates by a convexity premium for heavy-tailed upside over
        /// per-kind dispatch cost, so the bounded budget favours cheap,
        /// high-optionality identity leads over saturated infrastructure.
        #[arg(long)]
        convex_budget: bool,
        /// Australian-focused regional searching is ON by default: the search
        /// module adds minimal `.au` / AU-directory dorks on top of the
        /// geolocation-neutral base (a seed with no region signal defaults to
        /// AU). Pass `--no-regional` for a purely global scan.
        #[arg(long = "no-regional", action = clap::ArgAction::SetTrue)]
        no_regional: bool,
        /// When `--max-roi` is set, override the default marginal-yield
        /// floor (0.75). Lower = recurse further before giving up.
        #[arg(long)]
        min_marginal_yield: Option<f64>,
        /// Expansion ordering strategy: `geo_converge` (default; legacy),
        /// `breadth_first`, `depth_first`, `richest_first`. Changes how
        /// the engine prioritises expansion candidates each round.
        #[arg(long, default_value = "geo_converge")]
        expansion_strategy: String,
        /// Per-scan SeekNow (see-know.eu) budget override. Caps the
        /// number of SeekNow API queries this scan may dispatch.
        /// Default (None) falls back to HUNTSMAN_SEEKNOW_SCAN_CAP env
        /// (160). Hard-clamped at 200 to preserve the daily session
        /// ceiling. Raise for investigative scans on high-value
        /// targets; lower for passive recces that shouldn't burn
        /// quota.
        #[arg(long)]
        seeknow_scan_cap: Option<u32>,
        /// Expand EVERY discovered username/person, including uncorroborated,
        /// single-source aliases that share no handle/name overlap with the
        /// subject. Disables the wrong-identity gate for maximum recall at the
        /// cost of pulling in unrelated footprints (prune by hand). Implied by
        /// `--full`. Default keeps the gate on; excluded aliases are logged.
        #[arg(long)]
        expand_all_identities: bool,
        /// Preset bundle (recommended | passive | footprint | investigate | fast).
        /// `recommended` is the zero-setup out-of-box default: free/keyless sources,
        /// one expansion round for cross-service correlation, phone-safe budgets.
        /// Sets depth/free-only/budgets; `--modules`/`--exclude`/`--output` still apply.
        #[arg(long)]
        profile: Option<String>,
        /// Output format: table | json | dossier. "dossier" shows full intel grouped by category.
        #[arg(short, long, default_value = "table")]
        output: String,
    },
    /// List registered modules with their cost tier and accepted target kinds.
    ///
    /// Filter with `--category <cat>` (dns_recon / breach / infrastructure /
    /// search / geo / social / email / phone / corporate / threat / sensor
    /// / people / web / other) or `--json` to get the machine-readable
    /// shape that `/api/v1/modules` returns.
    Modules {
        /// Restrict listing to one module category.
        #[arg(short, long)]
        category: Option<String>,
        /// Output as JSON (same shape as `/api/v1/modules`).
        #[arg(long)]
        json: bool,
    },
    /// Liveness panel: probe every free search engine and report up/blocked/down
    /// + latency. Subsumed by `hse diagnostics`; kept for scripting.
    #[command(hide = true)]
    Engines {
        /// Output as JSON instead of the status table.
        #[arg(long)]
        json: bool,
    },
    /// View or set persistent capability toggles (universal toggleability,
    /// SpiderFoot-style). No args lists all toggles; `hse config <key> <on|off>`
    /// sets one — e.g. `hse config engine.google off`.
    Config {
        /// Toggle key (e.g. `engine.google`). Omit to list all toggles.
        key: Option<String>,
        /// `on` / `off` to set the toggle; omit to just show its value.
        value: Option<String>,
    },
    /// Run ALL diagnostics in one pass: environment (doctor) + module/core
    /// self-test (selftest) + search-engine liveness (engines). Exits non-zero
    /// if any section fails. The one command to verify a fresh install.
    #[command(visible_alias = "diag", visible_alias = "check")]
    Diagnostics {
        /// Emit machine-readable JSON for the sections that support it
        /// (selftest, engines); doctor remains human-readable.
        #[arg(long)]
        json: bool,
    },
    /// Score and explain a scan's output quality: noise, infrastructure
    /// pollution, fragment values, missed PII, and source health, with
    /// actionable recommendations. Ingests a CSV export (`--csv`), a stored scan
    /// (`--scan-id`, `latest` allowed), and/or a debug log (`--log`, JSONL or
    /// tracing text). A self-audit of every scan: it surfaces weaknesses so they
    /// can be addressed.
    #[command(visible_alias = "score")]
    Audit {
        /// CSV export to audit (`hse export --format csv`).
        #[arg(long)]
        csv: Option<String>,
        /// Stored scan id to audit (`latest` for the most recent completed scan).
        #[arg(long)]
        scan_id: Option<String>,
        /// Debug log / event stream to mine for source-health signals.
        #[arg(long)]
        log: Option<String>,
        /// Emit the machine-readable JSON report instead of the text scorecard.
        #[arg(long)]
        json: bool,
    },
    /// Verify environment: DB path, key file, Termux detection, module counts.
    /// (Subsumed by `hse diagnostics`; kept for scripting and the API/UI.)
    #[command(hide = true)]
    Doctor,
    /// Validate every module and core feature, then exit (non-zero on any
    /// failure). (Subsumed by `hse diagnostics`; kept for scripting and the Web UI.)
    #[command(hide = true)]
    Selftest {
        /// Emit the machine-readable JSON report instead of the text table.
        #[arg(long)]
        json: bool,
    },
    /// Provision the local environment: write/merge `$HOME/.huntsman.env`
    /// from the canonical template and run a diagnostic smoke test.
    ///
    /// Replaces the post-install phases of the Termux bootstrap script:
    /// pre-build phases (toolchain / git clone / `cargo build`) still
    /// live in `install.sh` because they must run before this binary
    /// exists. After install, prefer `hse provision`.
    ///
    /// Idempotent: existing real key values are preserved across runs;
    /// the file is backed up to `<path>.env.bak.<epoch>` before any
    /// change.
    #[command(hide = true, visible_alias = "setup")]
    Provision {
        /// Merge the env file but skip the diagnostic smoke test.
        #[arg(long, conflicts_with = "verify_only")]
        env_only: bool,
        /// Run the diagnostic smoke test but don't touch the env file.
        #[arg(long, conflicts_with = "env_only")]
        verify_only: bool,
        /// Show the merged env content without writing to disk.
        #[arg(long)]
        dry_run: bool,
    },

    /// Write a single `HUNTSMAN_*` key to `$HOME/.huntsman.env`.
    /// Prefer `hse keys set NAME VALUE` — this shorthand is kept for scripts.
    #[command(hide = true)]
    SetKey {
        /// Variable name, e.g. `HUNTSMAN_SHODAN_KEY`. Must start with `HUNTSMAN_`.
        name: String,
        /// Raw value to store. Quote in the shell to avoid mis-parsing.
        value: String,
    },
    /// Import an OathNet JSON export file. Extracts breach results,
    /// stealer metadata, IP geolocation, and Holehe platform checks
    /// into a new scan record with full entity extraction.
    Import {
        /// Path to the OathNet export JSON file.
        file: String,
        /// Output format: json, table, dossier.
        #[arg(short, long, default_value = "table")]
        output: String,
    },
    /// Start the HTTP server + SPA (browse to http://127.0.0.1:8080 from Chrome).
    Serve {
        /// Bind address. Localhost-only by default — change at your own risk.
        #[arg(short, long, default_value = crate::DEFAULT_BIND, env = "HSE_BIND")]
        bind: String,
        /// Disable the Settings page's key-write endpoint
        /// (`PUT /api/v1/settings/keys`). Key writes are ENABLED BY DEFAULT so
        /// the Settings page works out of the box on a personal device — and
        /// the endpoint *always* additionally requires the request to originate
        /// from a loopback peer, so a network-exposed bind still can't write
        /// keys. Pass this to lock writes down entirely for shared/hardened
        /// deployments.
        #[arg(long)]
        no_key_write: bool,
    },
    /// Manage the multi-key pool (add, list, validate, remove, status).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Run a target continuously, re-scanning on an interval. Streams events
    /// to stdout as compact JSON until Ctrl-C or `--iterations` is exhausted.
    Live {
        /// Target kind (same vocabulary as `scan --kind`). Omit (or pass `auto`)
        /// to auto-detect the kind from the value — the unified live scan.
        #[arg(short, long)]
        kind: Option<String>,
        /// Target value. Optional — omit to use the operator-local default seed
        /// (`HUNTSMAN_DEFAULT_SEED` in ~/.huntsman.env).
        // allow_hyphen_values so a value that legitimately begins with `-`
        // (e.g. a southern-hemisphere coordinate `-33.86,151.20`) is taken as
        // the value, not parsed by clap as an unknown short flag.
        #[arg(short, long, allow_hyphen_values = true)]
        value: Option<String>,
        /// Seconds between iterations.
        #[arg(short, long, default_value_t = crate::LIVE_DEFAULT_INTERVAL_SECS)]
        interval: u64,
        /// Stop after this many iterations. Omit for infinite.
        #[arg(long)]
        iterations: Option<u32>,
        /// Same as `scan --depth` — applies to each iteration.
        #[arg(short, long, default_value_t = 0)]
        depth: u32,
        /// Same as `scan --free-only`.
        #[arg(long)]
        free_only: bool,
        /// Same as `scan --passive-only`.
        #[arg(long)]
        passive_only: bool,
        /// Comma-separated module allowlist.
        #[arg(short, long)]
        modules: Option<String>,
        /// Radar mode: persist the keyed-module dispatch ledger across
        /// iterations so paid APIs are never re-queried on a seed an earlier
        /// sweep already covered — each sweep spends quota only on NEW seeds.
        #[arg(long)]
        radar: bool,
        /// Emit the raw newline-delimited JSON event stream (machine-readable)
        /// instead of the default human-readable, fully-unredacted structured
        /// view. Both carry identical data — the default just renders it for a
        /// human interpreter; `--json` is for piping into another tool.
        #[arg(long)]
        json: bool,
    },
    /// Radar mode: continuous Termux signal sweep → automatic pivoting.
    ///
    /// Sweeps device sensors (GPS, WiFi, cell towers, ARP, network interfaces)
    /// on a fast interval. Each newly discovered entity (coordinates, BSSIDs,
    /// IPs, cell tower IDs) is automatically fed into the full OSINT pivot
    /// pipeline at the configured depth. Only NEW discoveries trigger pivots —
    /// previously seen entities are skipped.
    ///
    /// Think of it as an intermittent radar that detects signals and
    /// automatically enriches them through all available modules.
    Radar {
        /// Seconds between sensor sweeps. Default 10.
        #[arg(short, long, default_value_t = 10)]
        interval: u64,
        /// Expansion depth for each discovered entity. Default 2.
        #[arg(short, long, default_value_t = 2)]
        depth: u32,
        /// Stop after this many sweeps. Omit for infinite (Ctrl-C to stop).
        #[arg(long)]
        sweeps: Option<u32>,
        /// Skip paid modules when pivoting.
        #[arg(long)]
        free_only: bool,
    },
    /// Export a previous scan's entities to JSON / CSV / GEXF / JSON-report / full.
    ///
    /// JSON           — `[{ kind, value, ... }, ...]` flat entity list
    /// CSV            — operator-friendly tabular form (same shape as
    ///                  the `/api/v1/scans/{id}/entities.csv` endpoint)
    /// GEXF           — Gephi/Cytoscape-importable graph with
    ///                  scan-id + observed_at on every node
    /// Report         — pretty-printed JSON dossier (scan + entities +
    ///                  correlations + counts; same shape as
    ///                  `/api/v1/scans/{id}/report.json`)
    /// Full           — Huntsman's STANDARD maximum-detail dossier: every
    ///                  entity (incl. candidates) with its full evidence
    ///                  chain — every raw field, the provenance
    ///                  (provider / api_key_origin / endpoint) and source
    ///                  website — nothing hashed, masked, or omitted
    ///
    /// Output goes to stdout by default; pass `--out <path>` to write
    /// to a file.
    Export {
        /// Scan ID (or `latest` for the most-recent completed scan).
        #[arg(short, long)]
        scan_id: String,
        /// Output format: json | csv | gexf | report | full | navigator.
        /// `navigator` emits a MITRE ATT&CK Navigator layer of the
        /// Reconnaissance techniques the scan exercised. Default `json`.
        #[arg(short, long, default_value = "json")]
        format: String,
        /// File path to write to. Omit for stdout.
        #[arg(short, long)]
        out: Option<String>,
    },

    /// Compare two completed scans: entities added / removed / re-scored.
    Diff {
        /// Baseline scan ID (or `latest` for the most-recent completed scan).
        from: String,
        /// Later scan ID to compare against the baseline (or `latest`).
        to: String,
        /// Output format: text | json. Default `text`.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Generate (and optionally run) a large batch of OathNet queries from one seed.
    ///
    /// Fans a single seed out across breach/stealer surfaces, derived selector
    /// fields (an email's local part → username, its domain → domain), and value
    /// permutations (names/handles → the handle shapes real accounts use; phone
    /// numbers → their digit/E.164 formats). Prints the plan by default (free);
    /// `--execute` dispatches it, bounded by the per-session OathNet budget.
    #[command(
        hide = true,
        visible_alias = "oathnet-queries",
        visible_alias = "obatch"
    )]
    OathnetBatch {
        /// Seed value (e.g. `john.doe@example.com`, `"John Doe"`, `+61412345678`).
        #[arg(short, long, allow_hyphen_values = true)]
        value: String,
        /// Seed kind (same vocabulary as `scan --kind`). Omit (or `auto`) to
        /// auto-detect from the value.
        #[arg(short, long)]
        kind: Option<String>,
        /// Don't emit stealer-surface queries (breach only).
        #[arg(long)]
        no_stealer: bool,
        /// Don't fan names / email local parts out into handle permutations.
        #[arg(long)]
        no_permute: bool,
        /// Also synthesise candidate emails (handle/role crossed with common
        /// providers). Explosive — off by default.
        #[arg(long)]
        synthesize_emails: bool,
        /// Cap the number of queries (after de-duplication). 0 = no cap.
        #[arg(long, default_value_t = 0)]
        max: usize,
        /// Per-query record page size when executing. Default 100.
        #[arg(long, default_value_t = 100)]
        page_size: u32,
        /// Actually dispatch the plan against OathNet (spends credits). Without
        /// this the command only prints the plan.
        #[arg(long)]
        execute: bool,
        /// Emit JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },

    /// Manage the local OpenCelliD cell-tower database.
    ///
    /// `hse cells status` — show tower count, MCC breakdown, last import time.
    /// `hse cells import --file PATH` — import a local CSV or CSV.GZ file.
    /// `hse cells import --country AU` — download from OpenCelliD and import.
    /// `hse cells clear [--yes]` — truncate the cells table.
    Cells {
        #[command(subcommand)]
        action: super::cells::CellsAction,
    },

    /// Upgrade hse in place: `git pull` + rebuild + atomic binary swap.
    ///
    /// Finds the source directory (from `HUNTSMAN_INSTALL_DIR` written by
    /// `install.sh`, then `~/hse`, `~/.local/share/hse`, or the binary's
    /// parent tree) and re-runs `install.sh`. The running process is not
    /// affected — Unix keeps the old inode in memory; new invocations pick
    /// up the replacement binary immediately.
    #[command(visible_alias = "upgrade")]
    Update {
        /// Check for available updates without installing.
        #[arg(long)]
        check: bool,
        /// Install a specific branch/tag/SHA instead of the current ref.
        #[arg(long, value_name = "REF")]
        r#ref: Option<String>,
    },
}
