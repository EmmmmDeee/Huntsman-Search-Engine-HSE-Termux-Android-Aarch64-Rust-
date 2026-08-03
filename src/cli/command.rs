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
    about = "Huntsman Search Engine (HSE) — GhostSec-tradition all-source OSINT / GEOINT recon for Termux aarch64",
    long_about = "Huntsman Search Engine (HSE) — an all-source OSINT / GEOINT / NETINT reconnaissance\n\
                  engine in the GhostSec tradition: SpiderFoot-inspired breadth without the daemon or the\n\
                  footprint. Pure-Rust, keyless-first, autonomous depth-bounded expansion, forged to run\n\
                  entirely inside Termux on Android aarch64 — single binary, zero native dependencies.\n\
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
        /// Batch mode: path to a file of seeds, one target per line (blank lines
        /// and `#` comments ignored). Runs the SAME scan for every listed seed —
        /// bulk-scan an IP / domain / email / username list. When set, `--value`
        /// is ignored; each seed's findings are stored and exportable per scan_id.
        #[arg(long, value_name = "PATH")]
        input_file: Option<String>,
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
        /// the comprehensive product default (MAX_DEPTH = 3); `--auto` overrides an
        /// omitted value.
        #[arg(short, long)]
        depth: Option<u32>,
        /// Shorthand for deep recursive expansion: pins depth to MAX_DEPTH (3) and
        /// clamps the expansion floor to ≤0.40. With the comprehensive default
        /// (depth 3, floor 0.20) this now matches the default; kept for explicitness
        /// and for use alongside a raised `--min-expand-confidence`. Overridden by
        /// an explicit --depth.
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
        /// Only expand entities whose C_eff is at least this. Default 0.20 so the
        /// scan is comprehensive — the seed's own derived identifiers (name → email
        /// / username / handle permutations, emitted at 0.20–0.30) expand and feed
        /// every downstream module, instead of starving the pipeline after the seed
        /// round (those permutations are frequently the subject's real accounts, so
        /// pivoting on them is what confirms which are real). Correlation still
        /// applies its own strict floors, so recall is wide while the resolved
        /// findings stay precise. Raise it (e.g. 0.50 Probable, 0.75 Verified-only),
        /// or pass `--gate-speculative`, for a tighter, faster sweep.
        #[arg(long, default_value_t = crate::core::scan::DEFAULT_MIN_EXPAND_CONFIDENCE)]
        min_expand_confidence: f64,
        /// Hard cap on total entities; stops expansion when reached. Omitted ⇒ the
        /// product default (2500) — a generous Termux on-device safety bound for the
        /// comprehensive depth-3 default sweep. Pass a larger value (or use a
        /// profile) to go further.
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
        /// Convex (optionality / barbell) budget allocation is ON by default:
        /// expansion candidates are re-weighted by a convexity premium for
        /// heavy-tailed upside over per-kind dispatch cost, so the bounded budget
        /// favours cheap, high-optionality identity leads over saturated
        /// infrastructure — maximising the value of each scan. Pass
        /// `--no-convex-budget` for the plain expected-value ranking.
        #[arg(long = "no-convex-budget", action = clap::ArgAction::SetTrue)]
        no_convex_budget: bool,
        /// Capability-aware dispatch is ON by default: modules whose parser has
        /// provably gone dead across recent scans (persistent failures or silent
        /// zero-yield drift) are skipped so their dispatch slot goes to a source
        /// that still works — maximising each scan's useful return. Only culls
        /// the automatic comprehensive fan-out; an explicit `--modules` set or
        /// `--full` always runs everything. Pass `--no-skip-dead-modules` to run
        /// every module regardless of health.
        #[arg(long = "no-skip-dead-modules", action = clap::ArgAction::SetTrue)]
        no_skip_dead_modules: bool,
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
        /// Per-scan SeekNow (see-know.ru) budget override. Caps the
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
        /// Tighter, faster sweep: gate uncorroborated name-permutation guesses
        /// (`firstname.lastname@provider` / handle candidates) out of expansion
        /// until a reliable source confirms them. OFF by default — those
        /// permutations are often the subject's REAL accounts, so the default
        /// expands and validates them (the point of a name scan); enable this only
        /// when a name collides with many namesakes and you want to suppress the
        /// speculative fan-out. Overridden by `--expand-all-identities` / `--full`.
        #[arg(long)]
        gate_speculative: bool,
        /// Preset bundle (recommended | passive | footprint | investigate | fast).
        /// `recommended` is the zero-setup out-of-box default: free/keyless sources,
        /// one expansion round for cross-service correlation, phone-safe budgets.
        /// Sets depth/free-only/budgets; `--modules`/`--exclude`/`--output` still apply.
        #[arg(long)]
        profile: Option<String>,
        /// Output format: table | json | dossier. "dossier" shows full intel grouped by category.
        #[arg(short, long, default_value = "table")]
        output: String,
        /// Include platform-infrastructure entities (cloud buckets, CDN IPs,
        /// analytics tracking IDs from platforms) in scan output. Excluded by
        /// default; implied by `--full`.
        #[arg(long)]
        include_infra: bool,
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
    /// General web search: run an everyday free-text query across every free
    /// search engine and print ranked results.
    ///
    /// Unlike `hse search`, which treats its input as an OSINT target
    /// (email / username / domain / …) and wraps it in `site:`/`intext:` dorks,
    /// `query` searches the text verbatim — e.g.
    /// `hse query "buy panadeine forte online"` — and returns the raw web
    /// results, deduplicated across engines and ranked by how many independent
    /// engines surfaced each URL.
    Query {
        /// The free-text search query. Quote multi-word queries.
        #[arg(allow_hyphen_values = true)]
        query: String,
        /// Maximum results to print (0 = no limit).
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
        /// Overall time budget in seconds (clamped to 3–60). Each engine
        /// request self-clamps to this deadline.
        #[arg(long)]
        timeout: Option<u64>,
        /// Output format: `table` (default) or `json`.
        #[arg(short, long, default_value = "table")]
        output: String,
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
    /// Benchmark a scan: a consolidated scorecard of the measurable OSINT dimensions
    /// (discovery depth, graph coverage, corroboration, density, throughput, pivots)
    /// for a reproducible, auditable comparison against another tool on the same seed.
    Benchmark {
        /// Stored scan id to benchmark (`latest` for the most recent completed scan).
        #[arg(long)]
        scan_id: Option<String>,
        /// Emit the machine-readable JSON report instead of the text scorecard.
        #[arg(long)]
        json: bool,
    },
    /// Discovery gaps: the validated seeds with no evidence-backed link, why each is
    /// isolated, and the corrective scans that would connect it — the gap-resolution loop.
    Gaps {
        /// Stored scan id to analyse (`latest` for the most recent completed scan).
        #[arg(long)]
        scan_id: Option<String>,
        /// Emit the machine-readable JSON report instead of the text summary.
        #[arg(long)]
        json: bool,
    },
    /// Verify environment: DB path, key file, Termux detection, module counts.
    /// (Subsumed by `hse diagnostics`; kept for scripting and the API/UI.)
    #[command(hide = true)]
    Doctor {
        /// Also run a live capability preflight: probe every keyless module
        /// against its real provider and report alive/empty/unreachable per
        /// module. Opt-in and network-bound — the default run stays offline.
        #[arg(long)]
        live: bool,
    },
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
        /// Autonomously discover HUNTSMAN_* API keys already present in the
        /// process environment (exported in a shell rc, CI, or passed inline)
        /// that the env file doesn't yet carry, and pre-configure them into
        /// `~/.huntsman.env`. Turns any key the operator already has into a
        /// persisted, active one with zero manual `keys set`. No-op under
        /// `--verify-only` (which never touches the env file).
        #[arg(long)]
        discover: bool,
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
    /// Parse documents (image/PDF/CSV/JSON/JSONL/text), extract entities (email, phone, IP, domain, hash, etc.),
    /// classify by kind, assign confidence scores, and output as HSE-ready batch queries (JSONL/JSON/CSV/table).
    Ingest {
        /// Input file path (image, PDF, CSV, JSON, JSONL, text).
        #[arg(short, long, value_name = "PATH")]
        file: String,
        /// Output format: jsonl (default), json, csv, table, or hse
        /// (full core::entity::Entity records ready for the scan pipeline).
        ///
        /// Short flag is `-F`: `-f` is the input file and `-o` the output
        /// file, and clap panics at startup on a duplicate short name.
        #[arg(short = 'F', long, default_value = "jsonl")]
        output_format: String,
        /// Minimum confidence threshold (0.0-1.0, default 0.30).
        #[arg(long, default_value = "0.30")]
        min_confidence: f64,
        /// Auto-scan extracted entities (future integration).
        #[arg(long)]
        auto_scan: bool,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
        /// Extract EXIF geolocation from images.
        #[arg(long)]
        extract_geolocation: bool,
        /// Generate reverse image search variants for detected images.
        #[arg(long)]
        generate_reverse_search_variants: bool,
        /// Output directory for reverse image search variants.
        #[arg(long, value_name = "DIR")]
        image_variant_output_dir: Option<String>,
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
        /// Same as `scan --exclude`.
        #[arg(long)]
        exclude: Option<String>,
        /// Same as `scan --throttle` — applies to each iteration's module dispatch.
        #[arg(long, default_value_t = 0)]
        throttle: u64,
        /// Same as `scan --min-confidence`.
        #[arg(long)]
        min_confidence: Option<f64>,
        /// Same as `scan --min-expand-confidence`.
        #[arg(long, default_value_t = crate::core::scan::DEFAULT_MIN_EXPAND_CONFIDENCE)]
        min_expand_confidence: f64,
        /// Same as `scan --max-entities` — applies per iteration. Omitted ⇒ the
        /// product default (2500), matching `hse scan` and the API's live/scan
        /// defaults.
        #[arg(long)]
        max_entities: Option<usize>,
        /// Same as `scan --max-wall-time` — applies per iteration.
        #[arg(long)]
        max_wall_time: Option<u64>,
        /// Same as `scan --max-concurrent`.
        #[arg(long, default_value_t = 2)]
        max_concurrent: usize,
        /// Same as `scan --max-roi`.
        #[arg(long)]
        max_roi: bool,
        /// Same as `scan --no-convex-budget` (convex allocation is on by default).
        #[arg(long = "no-convex-budget", action = clap::ArgAction::SetTrue)]
        no_convex_budget: bool,
        /// Same as `scan --no-skip-dead-modules` (capability-aware dispatch is on
        /// by default).
        #[arg(long = "no-skip-dead-modules", action = clap::ArgAction::SetTrue)]
        no_skip_dead_modules: bool,
        /// Same as `scan --no-regional`.
        #[arg(long = "no-regional", action = clap::ArgAction::SetTrue)]
        no_regional: bool,
        /// Same as `scan --min-marginal-yield`.
        #[arg(long)]
        min_marginal_yield: Option<f64>,
        /// Same as `scan --expansion-strategy`.
        #[arg(long, default_value = "geo_converge")]
        expansion_strategy: String,
        /// Same as `scan --seeknow-scan-cap`.
        #[arg(long)]
        seeknow_scan_cap: Option<u32>,
        /// Same as `scan --expand-all-identities`.
        #[arg(long)]
        expand_all_identities: bool,
        /// Same as `scan --gate-speculative`.
        #[arg(long)]
        gate_speculative: bool,
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
    ///
    /// Takes no options: it is either running or stopped. Start it with
    /// `hse radar`, stop it with Ctrl-C. Everything it needs it reads from this
    /// device's own radios.
    Radar {},
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
        /// Output format: json | csv | gexf | report | full | debug. Default `json`.
        #[arg(short, long, default_value = "json")]
        format: String,
        /// File path to write to. Omit for stdout.
        #[arg(short, long)]
        out: Option<String>,
        /// Include platform/shared-infrastructure entities (cloud buckets, CDN
        /// IPs, analytics IDs sourced from third-party platform pages) that are
        /// hidden by default. Equivalent to `--format full` for the report
        /// format but scoped only to the infra filter.
        #[arg(long, default_value_t = false)]
        include_infra: bool,
        /// Redact subject PII for a shareable export: mask credential-class
        /// values (passwords, credentials, harvested API keys) and coarsen
        /// precise coordinates to ~11 km. Applies to json / csv / gexf only —
        /// the full/debug dossiers are unredacted by contract.
        #[arg(long, default_value_t = false)]
        redact: bool,
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
        /// Recursively re-expand derived query values this many extra levels: a
        /// derived username re-derives its own handles / candidate emails, a
        /// derived domain its role emails, a synthesised email its own local-part
        /// username + domain, and so on. Bounded and cycle-safe (a value is never
        /// expanded twice), so it always terminates; `0` (default) keeps the
        /// precise single-level plan. Compounds with `--synthesize-emails`, so use
        /// `--max` to cap the result.
        #[arg(long, default_value_t = 0)]
        recurse_depth: u32,
        /// Cap the number of queries (after de-duplication). 0 = no cap.
        #[arg(long, default_value_t = 0)]
        max: usize,
        /// Per-query record page size when executing. Default 1000 — the
        /// documented ceiling for Breach Search, clamped down automatically
        /// per query to Stealer's own lower 100 maximum.
        #[arg(long, default_value_t = 1000)]
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
        action: crate::app::cells::CellsAction,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Validate the whole command tree at test time.
    ///
    /// clap's consistency checks (duplicate short flags, conflicting IDs,
    /// malformed defaults) run inside a `debug_assert` on first parse — so a
    /// broken definition does not fail the build, it panics at startup on
    /// every invocation of the affected subcommand. `hse ingest` shipped that
    /// way: `-o` was claimed by both `--output-format` and `--output`, and the
    /// command aborted before doing any work. Asserting here turns that class
    /// of defect into a failing test instead of a runtime crash.
    #[test]
    fn cli_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }
}
