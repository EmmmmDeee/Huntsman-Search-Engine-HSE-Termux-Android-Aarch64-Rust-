//! Per-scan options and expansion strategy.
//!
//! The scan-configuration unit — `ScanOptions`, the `ExpansionStrategy`
//! selector, the recursion-depth constants, and the serde default helpers —
//! split out of the `scan` parent so the target-kind / target / scan-record
//! types stay readable. Reaches the parent's shared imports through
//! `use super::*`, exactly as the sibling `classify` / `detect` modules do.

use super::*;

/// Per-scan customisation. All fields optional; defaults preserve plain-scan
/// behaviour. The engine respects every field at dispatch time.
///
/// Adding a knob = add a field here; CLI/API/UI surface it as needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Allowlist of module names. None = run every module that accepts the target.
    pub modules: Option<Vec<String>>,

    /// Modules to exclude after allowlist filtering.
    #[serde(default)]
    pub exclude_modules: Vec<String>,

    /// Restrict dispatch to modules in these functional categories. Empty (the
    /// default) means *no restriction* — every accepting module runs. When
    /// non-empty, a module whose [`crate::core::module::ModuleCategory`] is not
    /// listed is skipped on every round. Selection is by the type-owned category
    /// rather than a brittle module-name list, so a focused profile (e.g.
    /// `skiptrace`, which targets the person-locating categories) can't drift as
    /// modules are renamed and automatically includes new modules in-category.
    #[serde(default)]
    pub category_focus: Vec<crate::core::module::ModuleCategory>,

    /// Delay between module dispatches, in milliseconds. 0 = no throttle.
    #[serde(default)]
    pub throttle_ms: u64,

    /// Concurrent module cap. 0 = fully sequential dispatch; the default is
    /// the product's deliberately-gentle 2 (see [`Default`] and the CLI's
    /// `--max-concurrent`). The serde default matches, so an API request whose
    /// `options` object omits the field gets the same dispatch mode as one
    /// that omits `options` entirely — previously `"options": {}` silently
    /// fell back to 0/sequential while `{}`-less requests ran concurrent.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,

    /// Per-module timeout override (ms). None = `MODULE_TIMEOUT_MS`.
    pub module_timeout_ms: Option<u64>,

    /// Drop entities whose base `confidence` is below this. None = no filter.
    pub min_confidence: Option<f64>,

    /// Skip modules whose `cost()` is `KeyGated` or `Paid`.
    #[serde(default)]
    pub free_only: bool,

    /// Skip modules where `is_passive()` returns false.
    #[serde(default)]
    pub passive_only: bool,

    // ── Autonomous expansion (v0.2+) ────────────────────────────────────────
    /// Recursive expansion depth. 0 = no expansion (single round, v0.1 behaviour).
    /// Each round picks high-confidence entities from prior rounds, converts
    /// them to scan targets, and runs all accepting modules on them. Deserialises
    /// to the product default ([`DEFAULT_SCAN_DEPTH`] = 2) when omitted, so an
    /// API/web scan recurses two hops by default just like `hse scan`.
    #[serde(default = "default_scan_depth")]
    pub depth: u32,

    /// Only expand entities whose `c_effective()` is at least this. Default 0.50
    /// (Probable tier) — keeps expansion focused on the data the engine itself
    /// rates as solid. Stronger filter than `min_confidence`, which gates the
    /// base confidence at first encounter.
    #[serde(default = "default_min_expand_confidence")]
    pub min_expand_confidence: f64,

    /// Hard cap on total entities. Stops expansion once reached. `None` = no cap.
    pub max_entities: Option<usize>,

    /// Hard cap on total wall-time, in seconds. Stops expansion once exceeded. `None` = no cap.
    pub max_wall_time_secs: Option<u64>,

    /// User-assigned labels for campaign tracking (e.g., "apt-29", "q2-audit").
    #[serde(default)]
    pub scan_tags: Vec<String>,

    /// Freeform notes / investigation context.
    #[serde(default)]
    pub notes: Option<String>,

    /// Webhook URL to POST scan results to on completion. None = no webhook.
    #[serde(default)]
    pub webhook_url: Option<String>,

    /// Named scan profile (passive, footprint, investigate, fast).
    /// When set, overrides individual option fields with the profile's values.
    #[serde(default)]
    pub profile: Option<String>,

    // ── ROI-maximisation (v0.3+) ───────────────────────────────────────────
    /// Enable the ROI bundle: convergence-pruning of saturated entities,
    /// top-K candidate gating per round, and adaptive-depth termination.
    /// Off by default (preserves v0.2 behaviour exactly).
    #[serde(default)]
    pub max_roi: bool,

    /// Enable **convex (optionality / barbell) budget allocation**: re-weight
    /// expansion candidates by a convexity premium for heavy-tailed upside
    /// divided by per-kind dispatch cost (see [`crate::core::convex`]), so the
    /// bounded budget favours cheap, high-optionality identity leads over
    /// expensive, saturated infrastructure. Off by default (the base
    /// expected-value ranking is unchanged).
    #[serde(default)]
    pub convex_budget: bool,

    /// Australian-focused regional searching. **On by default** — the search
    /// module adds a minimal set of `.au`/AU-directory dorks on top of the
    /// geolocation-neutral base for every seed (one carrying no region signal of
    /// its own defaults to AU), so results favour Australian sources out of the
    /// box. Opt out (purely global) via CLI `--no-regional` or the API/Settings.
    #[serde(default = "default_regional_search")]
    pub regional_search: bool,

    /// When `max_roi` is on, terminate recursion as soon as a round's
    /// marginal yield (`new_entities / dispatched_targets`) drops below
    /// this floor. None = use [`crate::core::roi::DEFAULT_MIN_MARGINAL_YIELD`].
    #[serde(default)]
    pub min_marginal_yield: Option<f64>,

    // ── Expansion strategy (v1.1+) ─────────────────────────────────────────
    /// How the engine orders expansion candidates within each round.
    /// Defaults to [`ExpansionStrategy::GeoConverge`] — the current
    /// production behaviour. Selecting a different strategy changes
    /// what's prioritised when many entities exceed the confidence
    /// floor.
    #[serde(default)]
    pub expansion_strategy: ExpansionStrategy,

    // ── SeekNow per-scan budget override (v1.1+) ───────────────────────────
    /// Per-scan budget cap for SeekNow (`see-know.eu`) API queries.
    /// `None` falls back to the env-tunable
    /// `HUNTSMAN_SEEKNOW_SCAN_CAP` (default 24). Setting this on a
    /// scan-by-scan basis lets the operator burn a larger slice of the
    /// 5000/day quota on a specific high-value target — e.g. raise
    /// to 80 for an investigative scan, drop to 6 for a wide passive
    /// recce. Values above 200 are clamped to 200 to preserve the
    /// session ceiling.
    #[serde(default)]
    pub seeknow_scan_cap: Option<u32>,

    // ── Identity-gate override (v1.3+) ─────────────────────────────────────
    /// Expand *every* discovered Username/Person, even an uncorroborated,
    /// single-source one that shares no handle/name overlap with the subject's
    /// confirmed identity.
    ///
    /// The default (`false`) keeps the wrong-identity gate active: such a
    /// candidate is recorded but not pivoted on, because chasing it pulls a
    /// stranger's whole footprint into the scan (the canonical `arizonambb`
    /// off an `jordanavery` seed). The gate is the right default for a
    /// focused investigation, but it is by design conservative and can drop a
    /// genuine alias whose handle looks unrelated (a pseudonym, an initials
    /// handle, a married name). An operator who would rather over-collect and
    /// prune by hand sets this to `true` — every excluded alias is still logged
    /// as `identity_mismatch` when the gate is on, so the trade-off is visible
    /// either way.
    #[serde(default)]
    pub expand_all_identities: bool,

    // ── Live-sensor activation (radar-only) ────────────────────────────────
    /// Permit the live device-sensor modules (`signal_radar`, `device_sensors`,
    /// `wifi_intel`, `cell_intel`, `local_net`) to run.
    ///
    /// These read the **operator's own** real-time RF/network environment — the
    /// GPS fix, visible Wi-Fi APs, serving cell towers, the LAN ARP table — so on
    /// an ordinary scan they would attribute the operator's location and
    /// surroundings to the scanned *subject* (contamination, and pure noise on a
    /// remote target). They are therefore an **entirely separate activation**:
    /// this stays `false` on every `hse scan` / API scan / `hse live` run, and is
    /// set `true` ONLY by the dedicated radar entry points — the `hse radar` CLI
    /// command and the web UI's Live Signal Radar button (`POST /api/v1/radar`) —
    /// each of which sweeps the device's own sensors with no target seed. The gate
    /// is enforced in `engine::dispatch::module_skip_reason` on every round.
    #[serde(default)]
    pub allow_live_sensors: bool,
}

/// How the engine orders expansion candidates within a round.
///
/// All strategies still respect the `min_expand_confidence` floor and
/// the ROI top-K gate; they only differ in the *primary sort key*.
/// Spiderfoot 4.0 has a single hard-coded ordering (by event priority);
/// HSE's selectable strategies let operators trade off pivot depth
/// against breadth for the investigation at hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExpansionStrategy {
    /// Geographic-convergence weighting: `geo_npv × c_eff × domain_factor
    /// × geo_proximity × richness`. Existing production default.
    /// Prioritises entities one hop from Coordinates/Address.
    #[default]
    GeoConverge,
    /// Breadth-first: every confident candidate gets one dispatch
    /// before any candidate gets two. Sort key is `c_eff × richness`
    /// only — no geo bias. Good for wide reconnaissance.
    BreadthFirst,
    /// Depth-first: the most-confident candidate dominates the queue;
    /// secondary tiebreaker is richness. Good for verifying a single
    /// high-confidence lead deeply before fanning out.
    DepthFirst,
    /// Richness-first: candidates that unlock the largest number of
    /// modules expand first. Maximises *new modules touched per
    /// dispatch* — the closest analogue to Spiderfoot's
    /// `produced_events → watched_events` chain optimiser.
    RichestFirst,
}

impl ExpansionStrategy {
    /// Stable snake_case identifier — matches the serde-serialised form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GeoConverge => "geo_converge",
            Self::BreadthFirst => "breadth_first",
            Self::DepthFirst => "depth_first",
            Self::RichestFirst => "richest_first",
        }
    }
}

impl std::str::FromStr for ExpansionStrategy {
    type Err = String;

    /// Parse the same snake_case identifiers that `as_str()` emits
    /// (and serde uses). Empty string is treated as the default
    /// (`GeoConverge`) so callers don't need a separate guard for the
    /// "unset" case. Any other input returns a human-readable error
    /// listing the accepted variants — useful for the CLI's
    /// `--expansion-strategy` argument and direct API consumers.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "geo_converge" | "" => Ok(Self::GeoConverge),
            "breadth_first" => Ok(Self::BreadthFirst),
            "depth_first" => Ok(Self::DepthFirst),
            "richest_first" => Ok(Self::RichestFirst),
            other => Err(format!(
                "unknown expansion strategy '{other}'; expected one of: \
                 geo_converge, breadth_first, depth_first, richest_first"
            )),
        }
    }
}

/// Hard ceiling on recursive expansion depth, enforced at every operator-input
/// boundary (CLI / API / live) via [`ScanOptions::clamp_depth`]. The engine
/// itself cannot infinite-loop regardless (per-target visited-set + entity
/// budget + wall-time watchdog — see `tests/halting.rs`), but on a low-RAM
/// Termux device each extra hop fans the frontier out roughly exponentially, so
/// operator-requested depth is capped here. Change this one constant to raise
/// or lower the ceiling.
pub const MAX_DEPTH: u32 = 3;

/// Default recursive-expansion depth for the `hse scan` product surface when
/// the operator gives neither an explicit `--depth` nor `--auto`/`--recursive`.
/// Defaults to the full [`MAX_DEPTH`] so the standard scan is **comprehensive by
/// default** — the seed → discovered identifiers → their pivots → infrastructure
/// chain runs to completion, giving every module a target of a kind it accepts
/// (e.g. the Email→Domain→IP pipeline only reaches the IP modules at the third
/// hop). The library [`ScanOptions`] default stays `0` (single round) so
/// programmatic/API callers and the test suite remain deterministic; this product
/// default is applied at the CLI boundary in `cli::scan`. Operators who want a
/// faster, shallower sweep set `--depth` explicitly.
pub const DEFAULT_SCAN_DEPTH: u32 = MAX_DEPTH;

// Compile-time guard: the product default must never exceed the clamp ceiling,
// or a bare `hse scan` would emit the "clamped to MAX_DEPTH" warning on every run.
const _: () = assert!(DEFAULT_SCAN_DEPTH <= MAX_DEPTH);

impl ScanOptions {
    /// Clamp `depth` to [`MAX_DEPTH`], warning once if it actually clamps.
    /// Applied at the CLI/API/live input boundaries — deliberately NOT inside
    /// the engine core, whose halting proofs are driven at high depth on purpose.
    #[must_use]
    pub fn clamp_depth(mut self) -> Self {
        if self.depth > MAX_DEPTH {
            tracing::warn!(
                requested = self.depth,
                cap = MAX_DEPTH,
                "expansion depth clamped to MAX_DEPTH (Termux resource guard)"
            );
            self.depth = MAX_DEPTH;
        }
        self
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            modules: None,
            exclude_modules: Vec::new(),
            category_focus: Vec::new(),
            throttle_ms: 0,
            // Deliberately gentle (2, not the old 4): two concurrent network
            // modules paces dispatch so a deep/everything scan does not flood
            // the link or trip provider rate limits. Operators can raise it
            // with `--max-concurrent` when they know the network can take it.
            // Single-sourced with the serde default so the two can't diverge.
            max_concurrent: default_max_concurrent(),
            module_timeout_ms: None,
            min_confidence: None,
            free_only: false,
            passive_only: false,
            depth: 0,
            min_expand_confidence: default_min_expand_confidence(),
            max_entities: None,
            max_wall_time_secs: None,
            scan_tags: Vec::new(),
            notes: None,
            webhook_url: None,
            profile: None,
            max_roi: false,
            convex_budget: false,
            // AU-focused by default: every scan adds Australian-source dorks
            // (`.au` TLDs, AU directories) on top of the geo-neutral base, so the
            // tool favours Australian results out of the box. Opt out with
            // `--no-regional` / the API/Settings toggle for a purely global scan.
            regional_search: true,
            min_marginal_yield: None,
            expansion_strategy: ExpansionStrategy::default(),
            seeknow_scan_cap: None,
            expand_all_identities: false,
            // Live device sensors are radar-only: never on a default/manual scan.
            allow_live_sensors: false,
        }
    }
}

fn default_min_expand_confidence() -> f64 {
    0.50
}

/// Serde default for [`ScanOptions::max_concurrent`] — the product's gentle
/// concurrency (2), matching `ScanOptions::default()` and the CLI flag default,
/// so omitting the field inside an `options` object behaves identically to
/// omitting the `options` object altogether.
fn default_max_concurrent() -> usize {
    2
}

/// Serde default for [`ScanOptions::regional_search`] — AU-focused on by default
/// so API/web requests that omit it still favour Australian sources (matches the
/// CLI `hse scan` default; opt out with the Settings toggle).
fn default_regional_search() -> bool {
    true
}

/// Serde default for [`ScanOptions::depth`] — the product default applied to
/// API/web requests that omit `depth` (mirrors the CLI's `hse scan` default).
fn default_scan_depth() -> u32 {
    DEFAULT_SCAN_DEPTH
}

/// Serde default for [`ScanRequest::options`] — used when a request omits the
/// whole `options` object, so it still gets the product default depth (2)
/// rather than the inert library `ScanOptions::default()` (depth 0).
/// `pub(crate)` because [`crate::core::live::LiveRequest`] shares it: a live
/// request that omits `options` must behave like a scan request that does.
pub(crate) fn default_scan_options() -> ScanOptions {
    ScanOptions {
        depth: DEFAULT_SCAN_DEPTH,
        ..Default::default()
    }
}
