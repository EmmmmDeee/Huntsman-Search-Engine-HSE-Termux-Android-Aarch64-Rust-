//! Scan request, target, status, and per-scan customisation options.

use serde::{Deserialize, Serialize};

use crate::core::entity::{EntityKind, unix_now};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Email,
    Username,
    Phone,
    FullName,
    IpAddress,
    Domain,
    Url,
    Asn,
    Coordinates,
    Address,
    Organisation,
    AbnAcn,
    MacAddress,
    ApiKey,
}

impl TargetKind {
    /// Map an entity kind to a target kind, so an entity produced by one
    /// module can become the input target for another module.
    ///
    /// Returns `None` for entity kinds that have no natural scan target
    /// (organisations, MACs, raw URLs, credentials, etc.).
    pub fn from_entity_kind(kind: &EntityKind) -> Option<Self> {
        match kind {
            EntityKind::Email => Some(Self::Email),
            EntityKind::Username => Some(Self::Username),
            EntityKind::Phone => Some(Self::Phone),
            EntityKind::Person => Some(Self::FullName),
            EntityKind::IpAddress => Some(Self::IpAddress),
            EntityKind::Domain => Some(Self::Domain),
            EntityKind::Asn => Some(Self::Asn),
            EntityKind::Coordinates => Some(Self::Coordinates),
            EntityKind::Address => Some(Self::Address),
            EntityKind::Url => Some(Self::Url),
            EntityKind::Organisation => Some(Self::Organisation),
            EntityKind::AbnAcn => Some(Self::AbnAcn),
            EntityKind::ApiKey => Some(Self::ApiKey),
            EntityKind::MacAddress => Some(Self::MacAddress),
            EntityKind::Credential
            | EntityKind::DeviceId
            | EntityKind::Password
            | EntityKind::Other(_) => None,
        }
    }

    /// The matching entity kind for normalisation purposes. Always defined.
    pub fn to_entity_kind(self) -> EntityKind {
        match self {
            Self::Email => EntityKind::Email,
            Self::Username => EntityKind::Username,
            Self::Phone => EntityKind::Phone,
            Self::FullName => EntityKind::Person,
            Self::IpAddress => EntityKind::IpAddress,
            Self::Domain => EntityKind::Domain,
            Self::Url => EntityKind::Url,
            Self::Asn => EntityKind::Asn,
            Self::Coordinates => EntityKind::Coordinates,
            Self::Address => EntityKind::Address,
            Self::Organisation => EntityKind::Organisation,
            Self::AbnAcn => EntityKind::AbnAcn,
            Self::ApiKey => EntityKind::ApiKey,
            Self::MacAddress => EntityKind::MacAddress,
        }
    }

    /// Canonical lowercase snake_case identifier — matches the
    /// serde-serialised form (`#[serde(rename_all = "snake_case")]`).
    ///
    /// Used at every site that needs a machine-readable target-kind
    /// string (storage column, event payload, scan-id input). Per-scan
    /// IDs are *not* deterministic across re-scans of the same target —
    /// `util::uid::scan_id()` mixes `unix_now()` so each invocation
    /// produces a fresh id. The invariant this method enforces is the
    /// narrower one: CLI and HTTP API feed the same canonical string
    /// into the hash, so a given run produces the same id regardless of
    /// which interface launched the scan.
    pub fn canonical_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Phone => "phone",
            Self::FullName => "full_name",
            Self::IpAddress => "ip_address",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Asn => "asn",
            Self::Coordinates => "coordinates",
            Self::Address => "address",
            Self::Organisation => "organisation",
            Self::AbnAcn => "abn_acn",
            Self::ApiKey => "api_key",
            Self::MacAddress => "mac_address",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
}

impl Target {
    pub fn new(kind: TargetKind, value: impl Into<String>) -> Self {
        let raw: String = value.into();
        let normalised = crate::core::entity::normalise(&kind.to_entity_kind(), &raw);
        Self {
            kind,
            value: normalised,
        }
    }

    /// Create an entity pre-filled with the target's kind and value.
    /// Shorthand for `Entity::new(target.kind.to_entity_kind(), &target.value, confidence, scan_id)`.
    pub fn to_entity(&self, confidence: f64, scan_id: &str) -> crate::core::entity::Entity {
        crate::core::entity::Entity::new(
            self.kind.to_entity_kind(),
            &self.value,
            confidence,
            scan_id,
        )
    }

    /// Light shape-check for the user-supplied value, applied at the
    /// API boundary so a clearly-bogus scan request fails fast with a
    /// useful 400 rather than queueing a scan that no module accepts.
    ///
    /// This is intentionally lax — it rejects only the cases where the
    /// shape is *definitely* wrong (empty value, "email" that's missing
    /// the `@`, IP that doesn't parse). Modules still perform their own
    /// stricter validation as needed.
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        let v = self.value.trim();
        if v.is_empty() {
            return Err("value is empty");
        }
        if v.len() > 1024 {
            return Err("value too long (>1024 chars)");
        }
        if v.chars().any(char::is_control) {
            return Err("value contains control characters");
        }
        match self.kind {
            TargetKind::Email => {
                let (local, host) = v.split_once('@').ok_or("email missing '@'")?;
                if local.is_empty() || host.is_empty() {
                    return Err("email has empty local or host part");
                }
                if !host.contains('.') {
                    return Err("email host has no '.'");
                }
            }
            TargetKind::Domain => {
                if !v.contains('.') {
                    return Err("domain has no '.'");
                }
                if !v
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                {
                    return Err("domain has invalid characters");
                }
            }
            TargetKind::IpAddress => {
                v.parse::<std::net::IpAddr>()
                    .map_err(|_| "not a valid IPv4 or IPv6 address")?;
            }
            TargetKind::Asn => {
                let upper = v.to_uppercase();
                let digits = upper.strip_prefix("AS").unwrap_or(&upper);
                if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                    return Err("ASN must be digits, optionally prefixed by 'AS'");
                }
            }
            TargetKind::Phone => {
                let digits: String = v.chars().filter(char::is_ascii_digit).collect();
                if digits.len() < 6 {
                    return Err("phone needs at least 6 digits");
                }
            }
            TargetKind::Coordinates => {
                let (lat_s, lon_s) = v.split_once(',').ok_or("coordinates must be 'lat,lon'")?;
                let lat: f64 = lat_s
                    .trim()
                    .parse()
                    .map_err(|_| "coordinates lat is not a number")?;
                let lon: f64 = lon_s
                    .trim()
                    .parse()
                    .map_err(|_| "coordinates lon is not a number")?;
                if !(-90.0..=90.0).contains(&lat) {
                    return Err("latitude must be in [-90, 90]");
                }
                if !(-180.0..=180.0).contains(&lon) {
                    return Err("longitude must be in [-180, 180]");
                }
            }
            TargetKind::Url => {
                if !(v.starts_with("http://") || v.starts_with("https://")) {
                    return Err("URL must start with http:// or https://");
                }
                if v.len() < 10 {
                    return Err("URL too short");
                }
            }
            // Free-form text kinds: only the universal checks above apply.
            TargetKind::ApiKey => {
                if v.len() < 8 {
                    return Err("API key too short (min 8 chars)");
                }
            }
            TargetKind::Username
            | TargetKind::FullName
            | TargetKind::Address
            | TargetKind::Organisation
            | TargetKind::AbnAcn
            | TargetKind::MacAddress => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Complete,
    Failed,
    /// Operator-initiated cancellation (issue #23). Distinct from
    /// `Failed` because the scan didn't error — it was told to stop.
    /// Any entities + correlations produced before the cancel are
    /// persisted as for a `Complete` scan.
    Aborted,
}

impl ScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub target: Target,
    pub status: ScanStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub entity_count: usize,
    pub error: Option<String>,
    #[serde(default)]
    pub modules_run: usize,
    #[serde(default)]
    pub modules_errored: usize,
    #[serde(default)]
    pub modules_timed_out: usize,
    #[serde(default)]
    pub modules_deduped: usize,
    #[serde(default)]
    pub options: ScanOptions,
}

impl Scan {
    pub fn new(id: impl Into<String>, target: Target) -> Self {
        Self {
            id: id.into(),
            target,
            status: ScanStatus::Pending,
            started_at: unix_now(),
            finished_at: None,
            entity_count: 0,
            error: None,
            modules_run: 0,
            modules_errored: 0,
            modules_timed_out: 0,
            modules_deduped: 0,
            options: ScanOptions::default(),
        }
    }

    pub fn with_options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub kind: TargetKind,
    pub value: String,
    #[serde(default)]
    pub options: ScanOptions,
}

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

    /// Delay between module dispatches, in milliseconds. 0 = no throttle.
    #[serde(default)]
    pub throttle_ms: u64,

    /// Concurrent module cap. 0 = sequential (default for v0.1).
    /// Reserved for v0.3+ parallel dispatcher.
    #[serde(default)]
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
    /// them to scan targets, and runs all accepting modules on them.
    #[serde(default)]
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

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            modules: None,
            exclude_modules: Vec::new(),
            throttle_ms: 0,
            max_concurrent: 4,
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
            min_marginal_yield: None,
            expansion_strategy: ExpansionStrategy::default(),
            seeknow_scan_cap: None,
        }
    }
}

fn default_min_expand_confidence() -> f64 {
    0.50
}

/// Compute the geo-maximising expansion depth for a given seed type and
/// API tier. Generous with depth — geolocation is paramount. Prioritises
/// free API paths to amplify pivot economy before spending paid queries.
///
/// Returns (depth, min_expand_confidence) tuple.
pub fn optimal_depth(kind: TargetKind, has_paid_keys: bool) -> (u32, f64) {
    // Geolocation chain: Seed → IP/Domain → IP → Coords → Address → Coords
    // Every identity seed needs at least 3 hops to reach refined geo.
    // With paid keys, 5 hops catches OathNet → IP → geo → geocode → refine.
    //
    // v1.0 recalibration: 11 new modules widen the expansion graph.
    //   keybase/proxycurl/epieos enrich Username/Email → Person + Address
    //   opencorporates enriches Organisation → Address → geocode
    //   photon/mylnikov/overpass add geo corroboration paths
    let depth = match kind {
        // Identity seeds: richest expansion graph.
        //   R0: oathnet_pro/intelx/dehashed → IPs, emails, usernames, phones
        //       seon/emailrep/epieos → Person, Address; search_engines → domains
        //   R1: dns_intel/doh on domains → IPs; ip_geo → coords;
        //       keybase/proxycurl on usernames → Person, Email, Phone, Org
        //   R2: geocode/photon on coords → addresses; wigle → WiFi
        //       opencorporates on Org → Address
        //   R3: overpass on coords → infra; web_crawler → more emails
        //   R4: (paid) secondary OathNet on R1 discovered emails → geo
        TargetKind::Email | TargetKind::Username | TargetKind::FullName => {
            if has_paid_keys {
                5
            } else {
                4
            }
        }

        TargetKind::Domain => {
            if has_paid_keys {
                5
            } else {
                4
            }
        }

        TargetKind::IpAddress => {
            if has_paid_keys {
                4
            } else {
                3
            }
        }

        TargetKind::Url => {
            if has_paid_keys {
                4
            } else {
                3
            }
        }

        // Phone: seon → carrier/platform presence at R0; geo_intel → coords.
        // R1 geocodes. R2 expands breach IPs → domains. R3 catches remaining.
        TargetKind::Phone => {
            if has_paid_keys {
                4
            } else {
                3
            }
        }

        TargetKind::Asn => {
            if has_paid_keys {
                4
            } else {
                3
            }
        }

        // Coordinates: photon + geocode reverse → Address. R2 overpass + wigle.
        // R3 sunrise_sunset chronolocation + BSSID expansion.
        TargetKind::Coordinates => 3,

        // Address is an extremely high-value pivot when validated:
        //   R0: geocode/photon → Coordinates (bidirectional, dual-source)
        //   R1: overpass → infrastructure nodes; wigle → WiFi/BSSIDs
        //   R2: mylnikov on BSSIDs → more coords; sunrise_sunset → chronoloc
        //   R3: search_engines → associated entities; geo_intel → breach context
        TargetKind::Address => {
            if has_paid_keys {
                5
            } else {
                4
            }
        }

        // Organisation/ABN: opencorporates → addresses + company registry.
        // R1 geocode → coords. R2 overpass for nearby infrastructure.
        // R3 catches cross-links from company → directors → identity.
        TargetKind::Organisation | TargetKind::AbnAcn => {
            if has_paid_keys {
                4
            } else {
                3
            }
        }

        TargetKind::ApiKey => 3,

        // MacAddress: wigle + mylnikov → coords at R0.
        // R1 geocode/photon → address. R2 overpass for infrastructure.
        TargetKind::MacAddress => 3,
    };

    let min_conf = if has_paid_keys { 0.40 } else { 0.45 };

    (depth, min_conf)
}

/// Geo-specific NPV: expected Coordinates + Address entity yield.
///
/// v2.0 recalibration for 79-module pipeline. New geo paths:
///   Email: +email_header_geo, +email_locale, +seon, +epieos, +contact_enrich
///   Phone: +phone_area_geo, +phone_carrier_geo
///   Username: +social_location (GitHub/Reddit profile location extraction)
///   Domain: +geo_domain_classifier (ccTLD/service → country)
///   Organisation: +cloud_storage exposure scanning → domain → geo
///   Address: +geocode/photon bidirectional, +overpass infrastructure
///   IP: +abuseipdb country_code, +bgpview ASN→prefix→geo
pub fn geo_npv(kind: TargetKind, has_paid_keys: bool) -> f64 {
    match kind {
        TargetKind::Email => {
            if has_paid_keys {
                68.0
            } else {
                22.5
            }
        }
        TargetKind::FullName => {
            if has_paid_keys {
                58.0
            } else {
                28.0
            }
        }
        TargetKind::Domain => 32.0,
        TargetKind::IpAddress => 18.5,
        TargetKind::Username => 20.0,
        TargetKind::Phone => {
            if has_paid_keys {
                16.0
            } else {
                9.5
            }
        }
        TargetKind::Address => 24.0,
        TargetKind::MacAddress => 14.0,
        TargetKind::Asn => 10.5,
        TargetKind::Url => 12.0,
        TargetKind::Organisation => 11.0,
        TargetKind::Coordinates => 8.5,
        TargetKind::AbnAcn => 7.0,
        TargetKind::ApiKey => 3.8,
    }
}

/// Composite expansion weight: `geo_npv × c_eff × domain_factor × geo_proximity`.
///
/// - `c_eff` rewards entities confirmed by multiple sources
/// - `domain_factor` dampens known-generic mega-domains (0.15x)
/// - `geo_proximity` boosts entities one hop from Coordinates/Address
///   (IpAddress 1.8x, MacAddress 2.0x, Address 2.2x, Phone 1.5x)
///   so the pipeline converges on geolocation as fast as possible
pub fn expansion_weight(kind: TargetKind, c_eff: f64, value: &str, has_paid_keys: bool) -> f64 {
    let base = geo_npv(kind, has_paid_keys);
    let dampener = if kind == TargetKind::Domain {
        domain_expansion_factor(value)
    } else {
        1.0
    };
    let geo_boost = geo_proximity_boost(kind);
    base * c_eff * dampener * geo_boost
}

/// Strategy-aware expansion weight.
///
/// Each variant of [`ExpansionStrategy`] computes a different primary
/// score so the engine can sort the round's candidate queue with a
/// single comparison. `richness ∈ [0.0, 1.0]` is the normalised
/// module-count yield from [`crate::core::dependency::ModuleGraph`].
///
/// The legacy `expansion_weight()` corresponds exactly to
/// `GeoConverge` with `richness = 1.0`, so callers that haven't
/// migrated still get the established production behaviour.
pub fn expansion_weight_for_strategy(
    strategy: ExpansionStrategy,
    kind: TargetKind,
    c_eff: f64,
    value: &str,
    has_paid_keys: bool,
    richness: f64,
) -> f64 {
    let r = richness.clamp(0.0, 1.0);
    match strategy {
        ExpansionStrategy::GeoConverge => {
            // Established weight, plus a gentle (0.5–1.0) richness lift
            // so two candidates with identical geo weight tie-break on
            // module yield. Reaches 1.0 at the most-served kind.
            expansion_weight(kind, c_eff, value, has_paid_keys) * (0.5 + 0.5 * r)
        }
        ExpansionStrategy::BreadthFirst => {
            // Confidence × richness only. No geo bias, no domain
            // dampener — every confident lead competes flat.
            c_eff * (0.25 + 0.75 * r)
        }
        ExpansionStrategy::DepthFirst => {
            // c_eff dominates; richness used only as a tiebreaker.
            // Multiplying by 1.0 + 0.01·r keeps the order strictly by
            // c_eff for distinct values but breaks ties deterministic-
            // ally toward richer kinds.
            c_eff * (1.0 + 0.01 * r)
        }
        ExpansionStrategy::RichestFirst => {
            // Richness dominates. Confidence is the secondary key —
            // we still gate by `min_expand_confidence` upstream, so
            // letting it act here only as a tiebreaker is safe.
            r * (0.5 + 0.5 * c_eff)
        }
    }
}

/// Multiplicative boost for entity types that are one hop from producing
/// Coordinates or Address entities. Ensures the expansion pipeline
/// prioritises geo-convergent paths over non-geo paths at every round.
fn geo_proximity_boost(kind: TargetKind) -> f64 {
    match kind {
        // Coordinates ARE the terminal node — promote them above Address
        // so geo-rich entities resolve first when both appear in the
        // expansion queue. Was 1.6 (below Address 2.2); now 2.5.
        TargetKind::Coordinates => 2.5,
        // Address with a string value → geocode/photon → Coordinates.
        // Single hop, high reliability.
        TargetKind::Address => 2.2,
        // MAC → wigle/mylnikov → Coordinates. Single hop.
        TargetKind::MacAddress => 2.0,
        // IP → ip_geo/ipinfo → Coordinates. Single hop, highly reliable.
        TargetKind::IpAddress => 1.8,
        // Phone → phone_area_geo/phone_carrier_geo → Country/State. Two hops.
        TargetKind::Phone => 1.5,
        // Organisation → opencorporates → registered address → Coords. Two hops.
        TargetKind::Organisation => 1.3,
        // ASN → bgpview → prefixes → IPs → Coords. Three hops, but each
        // ASN often resolves to a fixed datacenter location.
        TargetKind::Asn => 1.2,
        _ => 1.0,
    }
}

/// Dampening factor for domain targets. Mega-domains (top internet
/// properties that appear in nearly every search result) get a 0.15×
/// penalty so they expand after target-specific entities.
///
/// Calibrated from JLM scan: facebook.com (corr=337), reddit.com (111),
/// whitepages.com (83) are noise. Target-specific domains like
/// welcometothejungle.com (corr=262) are valuable but indistinguishable
/// by corroboration alone, so we blocklist by known mega-domain.
fn domain_expansion_factor(domain: &str) -> f64 {
    let d = domain.trim().to_lowercase();
    let d = d.strip_prefix("www.").unwrap_or(&d);
    if MEGA_DOMAINS.iter().any(|m| {
        d == *m
            || (d.len() > m.len() && d.as_bytes()[d.len() - m.len() - 1] == b'.' && d.ends_with(m))
    }) {
        0.15
    } else {
        1.0
    }
}

const MEGA_DOMAINS: &[&str] = &[
    // Major platforms & social media
    "amazon.com",
    "amazon.com.au",
    "apple.com",
    "discord.com",
    "facebook.com",
    "github.com",
    "google.com",
    "google.com.au",
    "instagram.com",
    "linkedin.com",
    "microsoft.com",
    "netflix.com",
    "pinterest.com",
    "quora.com",
    "reddit.com",
    "spotify.com",
    "stackoverflow.com",
    "tiktok.com",
    "tumblr.com",
    "twitch.tv",
    "twitter.com",
    "whatsapp.com",
    "wikipedia.org",
    "x.com",
    "yahoo.com",
    "youtube.com",
    // Search engines & AI
    "bing.com",
    "chatgpt.com",
    "duckduckgo.com",
    "openai.com",
    // Content platforms & blogs
    "blogspot.com",
    "medium.com",
    "telegram.org",
    "wordpress.com",
    // News & media
    "bbc.co.uk",
    "bbc.com",
    "businessinsider.com",
    "cnn.com",
    "forbes.com",
    "nytimes.com",
    "reuters.com",
    "techcrunch.com",
    "theguardian.com",
    "washingtonpost.com",
    // Commerce & entertainment
    "aliexpress.com",
    "ebay.com",
    "ebay.com.au",
    "imdb.com",
    "pornhub.com",
    "xhamster.com",
    "xvideos.com",
    // CDN / infrastructure
    "akamai.com",
    "cloudflare.com",
    "fastly.com",
    // People-search / OSINT aggregators
    "anywho.com",
    "beenverified.com",
    "idcrawl.com",
    "intelius.com",
    "mylife.com",
    "nuwber.com",
    "peekyou.com",
    "pipl.com",
    "radaris.com",
    "socialcatfish.com",
    "spokeo.com",
    "truepeoplesearch.com",
    "usphonebook.com",
    "whitepages.com",
    "zabasearch.com",
    // Email providers
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "office365.com",
    "outlook.com",
    "protonmail.com",
    // DNS / IP lookup tools
    "dnschecker.org",
    "domaintools.com",
    "ip2location.com",
    "ipaddress.com",
    "iplocation.io",
    "whatismyip.com",
    "whatismyipaddress.com",
    "whois.com",
    // Australian mega-sites (common noise in AU OSINT)
    "abc.net.au",
    "news.com.au",
    "smh.com.au",
    "nine.com.au",
    "realestate.com.au",
    "seek.com.au",
    "yellowpages.com.au",
    // Additional global platforms
    "archive.org",
    "mastodon.social",
    "paypal.com",
    "snapchat.com",
    "threads.net",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default_is_inert() {
        let o = ScanOptions::default();
        assert!(o.modules.is_none());
        assert_eq!(o.throttle_ms, 0);
        assert!(!o.free_only);
        assert!(!o.passive_only);
        assert_eq!(o.depth, 0);
        assert!((o.min_expand_confidence - 0.50).abs() < 1e-9);
        assert_eq!(o.max_concurrent, 4);
    }

    #[test]
    fn expansion_weight_dampens_mega_domains() {
        let facebook = expansion_weight(TargetKind::Domain, 1.0, "facebook.com", false);
        let specific = expansion_weight(TargetKind::Domain, 1.0, "target-company.com.au", false);
        assert!(
            specific > facebook * 5.0,
            "target-specific domain ({specific:.1}) should far outrank facebook ({facebook:.1})"
        );
    }

    #[test]
    fn expansion_weight_address_beats_mega_domain() {
        let addr = expansion_weight(TargetKind::Address, 0.80, "Brisbane, QLD", false);
        let fb = expansion_weight(TargetKind::Domain, 1.0, "facebook.com", false);
        assert!(
            addr > fb,
            "validated address ({addr:.1}) should outrank dampened mega-domain ({fb:.1})"
        );
    }

    #[test]
    fn expansion_weight_respects_confidence() {
        let high = expansion_weight(TargetKind::Domain, 0.90, "example.com", false);
        let low = expansion_weight(TargetKind::Domain, 0.45, "example.com", false);
        assert!(high > low * 1.9);
    }

    #[test]
    fn mega_domain_list_catches_common_noise() {
        assert!(domain_expansion_factor("facebook.com") < 0.5);
        assert!(domain_expansion_factor("www.reddit.com") < 0.5);
        assert!(domain_expansion_factor("whitepages.com") < 0.5);
        assert!((domain_expansion_factor("target-specific.com.au") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn target_kind_round_trips_via_entity_kind() {
        for tk in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::FullName,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::Url,
            TargetKind::Asn,
            TargetKind::Coordinates,
            TargetKind::Address,
            TargetKind::Organisation,
            TargetKind::AbnAcn,
            TargetKind::ApiKey,
        ] {
            let ek = tk.to_entity_kind();
            assert_eq!(TargetKind::from_entity_kind(&ek), Some(tk));
        }
    }

    #[test]
    fn unscannable_entity_kinds_return_none() {
        assert!(TargetKind::from_entity_kind(&EntityKind::Password).is_none());
        assert!(TargetKind::from_entity_kind(&EntityKind::Credential).is_none());
    }

    #[test]
    fn mac_address_entity_expands() {
        assert_eq!(
            TargetKind::from_entity_kind(&EntityKind::MacAddress),
            Some(TargetKind::MacAddress)
        );
    }

    #[test]
    fn api_key_entity_expands() {
        assert_eq!(
            TargetKind::from_entity_kind(&EntityKind::ApiKey),
            Some(TargetKind::ApiKey)
        );
    }

    #[test]
    fn options_round_trip_json() {
        let o = ScanOptions {
            modules: Some(vec!["hibp".into(), "crtsh".into()]),
            throttle_ms: 250,
            free_only: true,
            ..Default::default()
        };
        let s = serde_json::to_string(&o).unwrap();
        let back: ScanOptions = serde_json::from_str(&s).unwrap();
        assert_eq!(back.modules.as_ref().unwrap().len(), 2);
        assert_eq!(back.throttle_ms, 250);
        assert!(back.free_only);
    }

    #[test]
    fn scan_request_round_trip() {
        let req = ScanRequest {
            kind: TargetKind::Email,
            value: "x@y.com".into(),
            options: ScanOptions::default(),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"kind\":\"email\""));
    }

    // ── Target::validate ────────────────────────────────────────────────────
    #[test]
    fn validate_rejects_empty_and_oversize() {
        assert!(Target::new(TargetKind::Email, "").validate().is_err());
        assert!(
            Target::new(TargetKind::Email, "x".repeat(2000))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_rejects_control_chars() {
        assert!(
            Target::new(TargetKind::Email, "x@y\ncom")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_email() {
        assert!(Target::new(TargetKind::Email, "a@b.com").validate().is_ok());
        assert!(
            Target::new(TargetKind::Email, "noatsign")
                .validate()
                .is_err()
        );
        assert!(Target::new(TargetKind::Email, "@b.com").validate().is_err());
        assert!(Target::new(TargetKind::Email, "a@b").validate().is_err()); // no dot
    }

    #[test]
    fn validate_domain() {
        assert!(
            Target::new(TargetKind::Domain, "example.com")
                .validate()
                .is_ok()
        );
        assert!(
            Target::new(TargetKind::Domain, "single")
                .validate()
                .is_err()
        ); // no dot
        assert!(
            Target::new(TargetKind::Domain, "bad domain.com")
                .validate()
                .is_err()
        ); // space
    }

    #[test]
    fn validate_ip() {
        assert!(
            Target::new(TargetKind::IpAddress, "1.1.1.1")
                .validate()
                .is_ok()
        );
        assert!(Target::new(TargetKind::IpAddress, "::1").validate().is_ok());
        assert!(
            Target::new(TargetKind::IpAddress, "999.999.999.999")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_asn() {
        assert!(Target::new(TargetKind::Asn, "AS13335").validate().is_ok());
        assert!(Target::new(TargetKind::Asn, "13335").validate().is_ok());
        assert!(Target::new(TargetKind::Asn, "BS13335").validate().is_err());
    }

    #[test]
    fn validate_phone() {
        assert!(
            Target::new(TargetKind::Phone, "+1-234-567-8901")
                .validate()
                .is_ok()
        );
        assert!(Target::new(TargetKind::Phone, "+1").validate().is_err()); // too short
    }

    #[test]
    fn validate_coordinates() {
        assert!(
            Target::new(TargetKind::Coordinates, "-33.8688,151.2093")
                .validate()
                .is_ok()
        );
        assert!(
            Target::new(TargetKind::Coordinates, "91,0")
                .validate()
                .is_err()
        ); // lat out of range
        assert!(
            Target::new(TargetKind::Coordinates, "0,181")
                .validate()
                .is_err()
        ); // lon out of range
        assert!(
            Target::new(TargetKind::Coordinates, "not-coords")
                .validate()
                .is_err()
        );
    }

    // ── ExpansionStrategy ───────────────────────────────────────────────────

    #[test]
    fn expansion_strategy_default_is_geo_converge() {
        assert_eq!(ExpansionStrategy::default(), ExpansionStrategy::GeoConverge);
        assert_eq!(ExpansionStrategy::default().as_str(), "geo_converge");
    }

    #[test]
    fn expansion_strategy_round_trips_json() {
        for s in [
            ExpansionStrategy::GeoConverge,
            ExpansionStrategy::BreadthFirst,
            ExpansionStrategy::DepthFirst,
            ExpansionStrategy::RichestFirst,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json.trim_matches('"'), s.as_str());
            let back: ExpansionStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(back, s);
        }
    }

    #[test]
    fn expansion_strategy_from_str_accepts_every_variant() {
        for s in [
            ExpansionStrategy::GeoConverge,
            ExpansionStrategy::BreadthFirst,
            ExpansionStrategy::DepthFirst,
            ExpansionStrategy::RichestFirst,
        ] {
            let parsed: ExpansionStrategy = s.as_str().parse().unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn expansion_strategy_from_str_treats_empty_as_default() {
        let parsed: ExpansionStrategy = "".parse().unwrap();
        assert_eq!(parsed, ExpansionStrategy::default());
    }

    #[test]
    fn expansion_strategy_from_str_rejects_unknown_with_useful_message() {
        let err = "wat".parse::<ExpansionStrategy>().unwrap_err();
        assert!(err.contains("wat"));
        assert!(err.contains("geo_converge"));
        assert!(err.contains("breadth_first"));
        assert!(err.contains("depth_first"));
        assert!(err.contains("richest_first"));
    }

    #[test]
    fn strategy_geo_converge_matches_legacy_weight_at_full_richness() {
        let legacy = expansion_weight(TargetKind::Domain, 0.8, "example.com", false);
        let strat = expansion_weight_for_strategy(
            ExpansionStrategy::GeoConverge,
            TargetKind::Domain,
            0.8,
            "example.com",
            false,
            1.0,
        );
        assert!((legacy - strat).abs() < 1e-9);
    }

    #[test]
    fn strategy_breadth_first_is_geo_agnostic() {
        // BreadthFirst should rank IP and Domain similarly when c_eff
        // matches — geo_proximity_boost no longer dominates.
        let ip = expansion_weight_for_strategy(
            ExpansionStrategy::BreadthFirst,
            TargetKind::IpAddress,
            0.8,
            "1.1.1.1",
            false,
            0.5,
        );
        let domain = expansion_weight_for_strategy(
            ExpansionStrategy::BreadthFirst,
            TargetKind::Domain,
            0.8,
            "example.com",
            false,
            0.5,
        );
        // Same c_eff and richness → identical weight under BreadthFirst.
        assert!((ip - domain).abs() < 1e-9);
    }

    #[test]
    fn strategy_richest_first_prioritises_high_richness() {
        let rich = expansion_weight_for_strategy(
            ExpansionStrategy::RichestFirst,
            TargetKind::Email,
            0.6,
            "a@b.com",
            false,
            1.0,
        );
        let poor = expansion_weight_for_strategy(
            ExpansionStrategy::RichestFirst,
            TargetKind::Email,
            0.9,
            "a@b.com",
            false,
            0.1,
        );
        // Richer entity wins despite lower confidence.
        assert!(rich > poor);
    }

    #[test]
    fn strategy_depth_first_sorts_by_confidence() {
        let high = expansion_weight_for_strategy(
            ExpansionStrategy::DepthFirst,
            TargetKind::Domain,
            0.95,
            "example.com",
            false,
            0.5,
        );
        let low = expansion_weight_for_strategy(
            ExpansionStrategy::DepthFirst,
            TargetKind::Domain,
            0.55,
            "example.com",
            false,
            1.0,
        );
        // c_eff dominates even when low-confidence has max richness.
        assert!(high > low);
    }

    #[test]
    fn scan_options_default_uses_geo_converge() {
        let opts = ScanOptions::default();
        assert_eq!(opts.expansion_strategy, ExpansionStrategy::GeoConverge);
    }

    #[test]
    fn scan_options_serde_round_trips_expansion_strategy() {
        let opts = ScanOptions {
            expansion_strategy: ExpansionStrategy::RichestFirst,
            ..Default::default()
        };
        let json = serde_json::to_string(&opts).unwrap();
        let back: ScanOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expansion_strategy, ExpansionStrategy::RichestFirst);
    }

    #[test]
    fn validate_url() {
        assert!(
            Target::new(TargetKind::Url, "https://example.com/path")
                .validate()
                .is_ok()
        );
        assert!(
            Target::new(TargetKind::Url, "http://x.com")
                .validate()
                .is_ok()
        );
        assert!(
            Target::new(TargetKind::Url, "ftp://nope.com")
                .validate()
                .is_err()
        );
        assert!(
            Target::new(TargetKind::Url, "not-a-url")
                .validate()
                .is_err()
        );
    }
}
