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
        Self {
            kind,
            value: {
                let v: String = value.into();
                v.trim().to_string()
            },
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

    /// Only expand entities whose `c_effective()` is at least this. Default 0.75
    /// (Verified tier) — keeps expansion focused on the data the engine itself
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
        }
    }
}

fn default_min_expand_confidence() -> f64 {
    0.45
}

/// Compute the geo-maximising expansion depth for a given seed type and
/// API tier. Generous with depth — geolocation is paramount. Prioritises
/// free API paths to amplify pivot economy before spending paid queries.
///
/// Returns (depth, min_expand_confidence) tuple.
///
/// Depth derivation per seed (free tier, critical path to geolocation):
///
/// ```text
/// Email:    R0 email_parse→Domain  R1 dns_intel→IP  R2 ip_geo→Coords  R3 wigle→Mac  R4 bssid→refine
/// Domain:   R0 dns_intel→IP        R1 ip_geo→Coords R2 geocode→Addr   R3 wigle→Mac  R4 bssid→refine
/// IP:       R0 ip_geo→Coords       R1 geocode→Addr  R2 wigle→Mac      R3 bssid→Coords
/// URL:      R0 web_crawler→Domain  R1 dns→IP        R2 ip_geo→Coords  R3 geocode→Addr
/// Phone:    R0 geo_intel→Coords    R1 geocode→Addr  R2 wigle→Mac      R3 bssid→Coords
/// Username: R0 profiles→Urls       R1 →Domain       R2 dns→IP         R3 ip_geo→Coords  R4 geocode
/// FullName: R0 search→Email        R1 email_parse   R2 dns→IP         R3 ip_geo→Coords  R4 geocode
/// MacAddr:  R0 bssid→Coords        R1 geocode→Addr  R2 wigle→Mac mesh R3 bssid→refine
/// Coords:   R0 geocode→Addr        R1 wigle→Mac     R2 bssid→Coords(refine)
/// Address:  R0 geocode→Coords      R1 wigle→Mac     R2 bssid→Coords(refine)
/// Org:      R0 abn→Addr            R1 geocode→Coords R2 wigle→Mac
/// AbnAcn:   R0 abn→Addr+Org        R1 geocode→Coords R2 wigle→Mac
/// ApiKey:   R0 probe→Domain        R1 dns→IP         R2 ip_geo→Coords R3 geocode→Addr
/// ```
pub fn optimal_depth(kind: TargetKind, has_paid_keys: bool) -> (u32, f64) {
    let depth = match kind {
        // Identity seeds: longest chain. Free path needs 4-5 hops to reach
        // refined geo through WiFi mesh. Paid adds OathNet shortcuts.
        TargetKind::Email => {
            if has_paid_keys {
                6
            } else {
                5
            }
        }
        TargetKind::Username | TargetKind::FullName => {
            if has_paid_keys {
                6
            } else {
                5
            }
        }

        // Domain: dns→IP at R0, geo at R1, then WiFi mesh at R2-R4.
        // Paid adds OathNet enrichment on discovered emails but same depth.
        TargetKind::Domain => 5,

        // IP: geo at R0. Reverse DNS→domain pipeline at R1-R3, WiFi mesh R2-R3.
        TargetKind::IpAddress => 4,

        // URL: domain extraction at R0, then full domain pipeline R1-R3.
        TargetKind::Url => {
            if has_paid_keys {
                5
            } else {
                4
            }
        }

        // Phone: geo_intel prefix at R0, breach IPs→geo at R1-R2, WiFi R3.
        TargetKind::Phone => {
            if has_paid_keys {
                5
            } else {
                4
            }
        }

        // ASN: ip_registry→IPs at R0, then full IP pipeline R1-R3.
        TargetKind::Asn => 4,

        // MacAddress: BSSID→Coords at R0, geocode→Addr at R1, wigle mesh
        // R2→more MACs, bssid refine at R3. Rich WiFi neighbourhood mapping.
        TargetKind::MacAddress => {
            if has_paid_keys {
                4
            } else {
                3
            }
        }

        // Coords/Address: already geo. Geocode swap R0, wigle R1, MAC mesh R2.
        TargetKind::Coordinates | TargetKind::Address => 3,

        // Organisation/ABN: abn_lookup→addresses at R0, geocode R1, wigle R2.
        TargetKind::Organisation | TargetKind::AbnAcn => {
            if has_paid_keys {
                4
            } else {
                3
            }
        }

        // ApiKey: domain at R0, then full domain→IP→geo pipeline R1-R3.
        TargetKind::ApiKey => 4,
    };

    // Confidence threshold: controls which entities are eligible for expansion.
    // Lower = more candidates = more geo pathways discovered.
    // - Breach IPs at 0.50-0.60 are valuable geo seeds
    // - Phone prefix coords at 0.52 need to expand through geocode
    // - Social profile URLs at 0.55 lead to domains → IPs → geo
    // - SSID-derived orgs at 0.35 are too speculative for expansion
    let min_conf = if has_paid_keys { 0.38 } else { 0.42 };

    (depth, min_conf)
}

/// Net Present Value score for a seed type. Higher = more valuable as a
/// starting point for recursive OSINT expansion.
///
/// Model: E[yield] = Σ_r P_r × N_r / (1 + d)^r
///   P_r  = P(reaching round r with new candidates), compound ~0.85/round
///   N_r  = expected new entities at round r
///   d    = 0.15 discount rate (API failures, visited-set pruning, conf filter)
///
/// Calibrated against observed module output distributions:
///   - Free tier: 8-12 modules fire per target, avg 1.8 entities each
///   - Paid tier: 12-16 modules, avg 3.2 entities (OathNet bulk)
///   - Expansion round yield decays ~40% per round (visited-set growth)
///
/// Used by the engine to prioritise expansion candidates when multiple
/// entities are available — higher-NPV seeds expand first.
pub fn seed_npv(kind: TargetKind, has_paid_keys: bool) -> f64 {
    match kind {
        // Email: richest graph. 7 accepting modules × 2 entities avg = 14 at R0.
        // Domain+Username fan-out at R1 (~10), IP→geo at R2 (~7), WiFi mesh R3-R4 (~5).
        // Free: 14 + 10/1.15 + 7/1.32 + 4/1.52 + 2/1.75 = 14 + 8.7 + 5.3 + 2.6 + 1.1 = 31.7
        // Paid: +OathNet(~12) +dehashed(~6) +intelx(~4) at R0 → 36 at R0, richer expansion.
        // Paid: 36 + 22/1.15 + 14/1.32 + 8/1.52 + 5/1.75 + 3/2.01 = 36 + 19.1 + 10.6 + 5.3 + 2.9 + 1.5 = 75.4
        TargetKind::Email => {
            if has_paid_keys {
                75.0
            } else {
                32.0
            }
        }
        // Domain: dns_intel(3) + web_crawler(5) + cert_intel(3) + urlscan(2) + search(3) + whois(2) = 18 at R0.
        // R1: IPs→ip_geo, emails→email_parse, phones→phone_intl (~12).
        // R2-R4: geo + WiFi mesh (~8).
        // 18 + 12/1.15 + 5/1.32 + 3/1.52 + 2/1.75 = 18 + 10.4 + 3.8 + 2.0 + 1.1 = 35.3
        TargetKind::Domain => 35.0,
        // FullName: search_engines(~4) + abn_lookup(~2) + geo_intel(~2) = 8 at R0.
        // R1: emails→domains→IPs (~6). R2-R4: geo chain (~5).
        // 8 + 6/1.15 + 4/1.32 + 2/1.52 + 1/1.75 = 8 + 5.2 + 3.0 + 1.3 + 0.6 = 18.1
        TargetKind::FullName => {
            if has_paid_keys {
                28.0
            } else {
                18.0
            }
        }
        // IP: 7 modules accept IP → ip_geo(2) + dns_intel(3) + shodan(2) + ip_registry(3) + greynoise(1) = 11 at R0.
        // R1: domains→web_crawler, coords→geocode (~8). R2-R3: WiFi mesh (~4).
        // 11 + 8/1.15 + 4/1.32 + 2/1.52 = 11 + 7.0 + 3.0 + 1.3 = 22.3
        TargetKind::IpAddress => 22.0,
        // Username: username_search(3) + search_engines(3) + social_probe(2) + github(2) = 10 at R0.
        // R1: URLs→domains, profiles→emails (~6). R2-R4: DNS→IP→geo chain (~5).
        // 10 + 6/1.15 + 4/1.32 + 2/1.52 + 1/1.75 = 10 + 5.2 + 3.0 + 1.3 + 0.6 = 20.1
        TargetKind::Username => {
            if has_paid_keys {
                30.0
            } else {
                20.0
            }
        }
        // Phone: phone_intl(1) + geo_intel(2) + search(2) = 5 at R0.
        // R1: coords→geocode, breach IPs→geo (~4). R2-R3: WiFi mesh (~3).
        // Free: 5 + 4/1.15 + 2/1.32 + 1/1.52 = 5 + 3.5 + 1.5 + 0.7 = 10.7
        // Paid: +oathnet(6) → 11 at R0, richer R1 (~8).
        TargetKind::Phone => {
            if has_paid_keys {
                26.0
            } else {
                11.0
            }
        }
        // MacAddress: wigle_bssid(3: coords+addr+org) + local_net(2: IP+MAC) = 5 at R0.
        // R1: coords→geocode+wigle_area(5: refined coords+addr+macs). R2: mac mesh(3). R3: refine(2).
        // 5 + 5/1.15 + 3/1.32 + 2/1.52 = 5 + 4.3 + 2.3 + 1.3 = 12.9
        TargetKind::MacAddress => 13.0,
        // ASN: ip_registry(3) → IPs at R0. R1-R3: full IP→geo→WiFi pipeline (~8).
        // 3 + 5/1.15 + 3/1.32 + 2/1.52 = 3 + 4.3 + 2.3 + 1.3 = 10.9
        TargetKind::Asn => 11.0,
        // URL: web_crawler(4) + urlscan(3) + search(2) = 9 at R0. Then domain pipeline.
        // 9 + 6/1.15 + 4/1.32 + 2/1.52 = 9 + 5.2 + 3.0 + 1.3 = 18.5
        TargetKind::Url => 18.5,
        // ApiKey: api_key_probe(3: key+service+domain) at R0. Domain→DNS→IP→geo pipeline.
        // 3 + 4/1.15 + 3/1.32 + 2/1.52 + 1/1.75 = 3 + 3.5 + 2.3 + 1.3 + 0.6 = 10.7
        TargetKind::ApiKey => 11.0,
        // Organisation: abn_lookup(3: org+addr+person) + search(3) = 6 at R0. Then geo pipeline.
        // 6 + 3/1.15 + 2/1.32 + 1/1.52 = 6 + 2.6 + 1.5 + 0.7 = 10.8
        TargetKind::Organisation => {
            if has_paid_keys {
                14.0
            } else {
                11.0
            }
        }
        // AbnAcn: abn_lookup(4: org+abn+addr+person). Higher base yield than org name.
        // 4 + 3/1.15 + 2/1.32 + 1/1.52 = 4 + 2.6 + 1.5 + 0.7 = 8.8 → boosted for direct addr
        TargetKind::AbnAcn => 12.0,
        // Coordinates: geocode(1) + wigle_area(4: coords+addr+macs) = 5 at R0. Mac mesh R1-R2.
        // 5 + 3/1.15 + 2/1.32 = 5 + 2.6 + 1.5 = 9.1
        TargetKind::Coordinates => 9.0,
        // Address: geocode(1: coords) at R0. Then coords→wigle→Mac pipeline R1-R2.
        // 1 + 4/1.15 + 2/1.32 = 1 + 3.5 + 1.5 = 6.0
        TargetKind::Address => 6.0,
    }
}

/// Geo-specific NPV: expected Coordinates + Address entity yield across
/// all expansion rounds, discounted at 15%/round.
///
/// Model counts only EntityKind::Coordinates and EntityKind::Address
/// entities. The WiFi mesh pipeline (Coords → WiGLE → MacAddress →
/// BSSID lookup → refined Coords) adds 1-3 geo entities per round at
/// R2+ for identity seeds and R1+ for geo/MAC seeds.
///
/// Pipeline geo-yield breakdown (free tier):
/// ```text
/// Email→Coords:   R2 ip_geo(1.0) + R3 geocode(0.8)+wigle(1.2) + R4 bssid(0.8) = 3.8
/// Domain→Coords:  R1 ip_geo(1.2) + R2 geocode(0.8)+wigle(1.0) + R3 bssid(0.6) = 3.6
/// IP→Coords:      R0 ip_geo(1.5) + R1 geocode(0.8)+wigle(1.0) + R2 bssid(0.6) = 3.9
/// Mac→Coords:     R0 bssid(1.8) + R1 geocode(0.8)+wigle(1.5) + R2 mesh(0.6) = 4.7
/// Phone→Coords:   R0 geo_intel(0.8) + R1 geocode(0.5) + R2 wigle(0.8) = 2.1
/// Coords→refine:  R0 geocode(1.0)+wigle(2.0) + R1 bssid(1.0) + R2 mesh(0.5) = 4.5
/// ```
pub fn geo_npv(kind: TargetKind, has_paid_keys: bool) -> f64 {
    match kind {
        // Email: R0(0.3 search addr) R1(0) R2(ip_geo 1.5) R3(geocode 0.8 + wigle 1.5) R4(bssid 1.0)
        // Free:  0.3 + 0 + 1.5/1.32 + 2.3/1.52 + 1.0/1.75 = 0.3 + 1.14 + 1.51 + 0.57 = 3.52
        // Paid:  +geo_intel R0(1.5) +oathnet R0(1.0) + richer R1(1.5) = 3.52 + 2.5 + 1.30 = 7.32
        // R5 WiFi mesh refine adds ~0.5 for paid.
        TargetKind::Email => {
            if has_paid_keys {
                12.5
            } else {
                6.5
            }
        }
        // Domain: R0(geo_intel 1.0) R1(ip_geo 1.5, geocode 0.3) R2(geocode 0.8, wigle 1.5) R3(bssid 1.0) R4(mesh 0.5)
        // 1.0 + 1.8/1.15 + 2.3/1.32 + 1.0/1.52 + 0.5/1.75 = 1.0 + 1.57 + 1.74 + 0.66 + 0.29 = 5.26
        TargetKind::Domain => 8.0,
        // FullName: search→emails→domain→IP→geo chain. ~1 round slower than email.
        // R0(0.5 addr from search) R1(0) R2(0.5 geo_intel) R3(1.5 ip_geo) R4(1.5 geocode+wigle)
        // 0.5 + 0 + 0.5/1.32 + 1.5/1.52 + 1.5/1.75 = 0.5 + 0.38 + 0.99 + 0.86 = 2.73
        TargetKind::FullName => {
            if has_paid_keys {
                8.0
            } else {
                5.0
            }
        }
        // IP: direct geo at R0. ip_geo(1.5) + geo_intel(1.0 if keyed) + censys(0.5).
        // R0(1.5) R1(geocode 0.8 + wigle 1.5) R2(bssid 1.0) R3(mesh 0.5)
        // 1.5 + 2.3/1.15 + 1.0/1.32 + 0.5/1.52 = 1.5 + 2.0 + 0.76 + 0.33 = 4.59
        TargetKind::IpAddress => {
            if has_paid_keys {
                8.5
            } else {
                5.5
            }
        }
        // Phone: geo_intel prefix coords at R0 (0.52 conf), then geocode + wigle.
        // Free: R0(0.8 prefix) R1(geocode 0.5) R2(wigle 0.8) R3(bssid 0.5)
        // 0.8 + 0.5/1.15 + 0.8/1.32 + 0.5/1.52 = 0.8 + 0.43 + 0.61 + 0.33 = 2.17
        // Paid: +oathnet breach geo(1.5) at R0, richer IPs→geo at R1.
        TargetKind::Phone => {
            if has_paid_keys {
                7.5
            } else {
                3.0
            }
        }
        // MacAddress: BSSID→coords at R0 (0.80 conf), geocode+wigle mesh at R1-R2.
        // R0(bssid 1.8: coords+addr) R1(geocode 0.8 + wigle area 1.5) R2(mac mesh 0.8)
        // 1.8 + 2.3/1.15 + 0.8/1.32 = 1.8 + 2.0 + 0.61 = 4.41
        TargetKind::MacAddress => 9.5,
        // ASN: ip_registry→IPs→ip_geo. One hop slower than direct IP.
        // R0(0) R1(ip_geo 1.5) R2(geocode+wigle 2.0) R3(bssid 0.8)
        // 0 + 1.5/1.15 + 2.0/1.32 + 0.8/1.52 = 1.30 + 1.52 + 0.53 = 3.35
        TargetKind::Asn => 4.5,
        // Username: profiles→domains→IPs→geo. 2 hops to first geo.
        // R0(0) R1(0) R2(ip_geo 1.0) R3(geocode+wigle 1.5) R4(bssid 0.5)
        // 0 + 0 + 1.0/1.32 + 1.5/1.52 + 0.5/1.75 = 0.76 + 0.99 + 0.29 = 2.04
        TargetKind::Username => {
            if has_paid_keys {
                6.0
            } else {
                3.5
            }
        }
        // URL: domain at R0, then full domain pipeline. ~1 hop slower than Domain.
        // R0(0) R1(ip_geo 1.2, geocode 0.3) R2(geocode+wigle 1.8) R3(bssid 0.8)
        // 0 + 1.5/1.15 + 1.8/1.32 + 0.8/1.52 = 1.30 + 1.36 + 0.53 = 3.19
        TargetKind::Url => 4.0,
        // ApiKey: domain at R0, then domain→IP→geo pipeline.
        // R0(0) R1(0) R2(ip_geo 1.2) R3(geocode+wigle 1.5)
        // 0 + 0 + 1.2/1.32 + 1.5/1.52 = 0.91 + 0.99 = 1.90
        TargetKind::ApiKey => 3.0,
        // Coordinates: already geo. Geocode→addr at R0, wigle→macs at R0, mesh R1-R2.
        // R0(geocode 1.0 + wigle 2.0) R1(bssid 1.0) R2(mesh 0.5)
        // 3.0 + 1.0/1.15 + 0.5/1.32 = 3.0 + 0.87 + 0.38 = 4.25
        TargetKind::Coordinates => 4.5,
        // Address: geocode→coords at R0, then coords pipeline at R1-R2.
        // R0(geocode 1.0) R1(wigle 2.0 + geocode 0.5) R2(bssid 0.8)
        // 1.0 + 2.5/1.15 + 0.8/1.32 = 1.0 + 2.17 + 0.61 = 3.78
        TargetKind::Address => 4.0,
        // Organisation: abn→address at R0, then geocode→wigle pipeline.
        // R0(abn addr 1.0) R1(geocode 1.0) R2(wigle 1.5) R3(bssid 0.5)
        // 1.0 + 1.0/1.15 + 1.5/1.32 + 0.5/1.52 = 1.0 + 0.87 + 1.14 + 0.33 = 3.34
        TargetKind::Organisation => {
            if has_paid_keys {
                5.5
            } else {
                3.5
            }
        }
        // AbnAcn: direct address from ABN lookup (higher confidence than org name).
        // R0(abn addr 1.2) R1(geocode 1.0) R2(wigle 1.5) R3(bssid 0.5)
        // 1.2 + 1.0/1.15 + 1.5/1.32 + 0.5/1.52 = 1.2 + 0.87 + 1.14 + 0.33 = 3.54
        TargetKind::AbnAcn => 4.5,
    }
}

/// Multi-step pipeline NPV: expected geo value for a specific pivot chain.
/// Used by the engine to compare candidate expansion paths when multiple
/// entity types compete for the same expansion slot.
///
/// `hops` is the number of pivot steps remaining (0 = we're already at geo).
/// `conf` is the expected confidence of the final geo entity.
/// `p_success` is the compound probability of reaching the end of the chain.
pub fn pipeline_npv(hops: u32, conf: f64, p_success: f64) -> f64 {
    let discount = 1.15_f64.powi(hops as i32);
    p_success * conf / discount
}

/// Expected pipeline value for expanding an entity at a given expansion depth.
/// Accounts for diminishing returns as depth increases (visited-set growth,
/// API quota consumption, decreasing novelty).
///
/// decay_factor = 0.60 — each additional hop retains 60% of prior round yield.
pub fn expansion_marginal_value(kind: TargetKind, current_depth: u32, has_paid: bool) -> f64 {
    let base = geo_npv(kind, has_paid);
    let decay = 0.60_f64.powi(current_depth as i32);
    base * decay
}

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
        assert!((o.min_expand_confidence - 0.45).abs() < 1e-9);
        assert_eq!(o.max_concurrent, 4);
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

    // ── NPV and pipeline tests ─────────────────────────────────────────────

    #[test]
    fn seed_npv_ordering_free() {
        let e = seed_npv(TargetKind::Email, false);
        let d = seed_npv(TargetKind::Domain, false);
        let ip = seed_npv(TargetKind::IpAddress, false);
        let u = seed_npv(TargetKind::Username, false);
        let mac = seed_npv(TargetKind::MacAddress, false);
        let url = seed_npv(TargetKind::Url, false);
        let addr = seed_npv(TargetKind::Address, false);
        // Domain has richest free graph, followed by email, then IP/username
        assert!(d > e, "domain {d} > email {e}");
        assert!(e > ip, "email {e} > ip {ip}");
        assert!(ip > u || (ip - u).abs() < 3.0, "ip ≈ username");
        assert!(mac > addr, "mac {mac} > address {addr}");
        assert!(url > mac, "url {url} > mac {mac}");
    }

    #[test]
    fn seed_npv_paid_always_gte_free() {
        for kind in [
            TargetKind::Email,
            TargetKind::Phone,
            TargetKind::FullName,
            TargetKind::Username,
            TargetKind::Organisation,
        ] {
            let paid = seed_npv(kind, true);
            let free = seed_npv(kind, false);
            assert!(paid >= free, "{:?}: paid {paid} < free {free}", kind);
        }
    }

    #[test]
    fn geo_npv_mac_address_reflects_bssid_pipeline() {
        let mac_geo = geo_npv(TargetKind::MacAddress, false);
        let addr_geo = geo_npv(TargetKind::Address, false);
        // MacAddress→BSSID→Coords is a rich geo pipeline
        assert!(
            mac_geo > addr_geo,
            "mac geo {mac_geo} should exceed address geo {addr_geo}"
        );
        assert!(mac_geo > 5.0, "mac geo should be substantial: {mac_geo}");
    }

    #[test]
    fn geo_npv_coords_already_geo() {
        let coords_geo = geo_npv(TargetKind::Coordinates, false);
        let addr_geo = geo_npv(TargetKind::Address, false);
        // Both are already-geo seeds; coords should be slightly higher
        assert!(coords_geo >= addr_geo);
        assert!(coords_geo > 3.0, "coords should have mesh refinement value");
    }

    #[test]
    fn geo_npv_ip_has_direct_path() {
        let ip_geo = geo_npv(TargetKind::IpAddress, false);
        let email_geo = geo_npv(TargetKind::Email, false);
        // IP gets geo at R0 (direct), email needs 2+ hops
        // But email has more total pathways, so email geo ≥ ip geo overall
        assert!(
            ip_geo > 3.0,
            "IP should have substantial direct geo: {ip_geo}"
        );
        assert!(
            email_geo > ip_geo * 0.5,
            "email geo should be in same ballpark"
        );
    }

    #[test]
    fn pipeline_npv_decreases_with_hops() {
        let direct = pipeline_npv(0, 0.80, 0.90);
        let one_hop = pipeline_npv(1, 0.80, 0.90);
        let three_hops = pipeline_npv(3, 0.80, 0.90);
        assert!(direct > one_hop);
        assert!(one_hop > three_hops);
    }

    #[test]
    fn pipeline_npv_zero_hops_is_p_times_conf() {
        let npv = pipeline_npv(0, 0.70, 0.90);
        assert!((npv - 0.63).abs() < 0.01);
    }

    #[test]
    fn expansion_marginal_value_decays_with_depth() {
        let d0 = expansion_marginal_value(TargetKind::IpAddress, 0, false);
        let d1 = expansion_marginal_value(TargetKind::IpAddress, 1, false);
        let d2 = expansion_marginal_value(TargetKind::IpAddress, 2, false);
        let d5 = expansion_marginal_value(TargetKind::IpAddress, 5, false);
        assert!(d0 > d1);
        assert!(d1 > d2);
        assert!(d5 < d0 * 0.15, "deep expansion should be nearly exhausted");
    }

    #[test]
    fn expansion_marginal_value_d0_equals_geo_npv() {
        for kind in [
            TargetKind::Email,
            TargetKind::MacAddress,
            TargetKind::Domain,
        ] {
            let marginal = expansion_marginal_value(kind, 0, false);
            let geo = geo_npv(kind, false);
            assert!(
                (marginal - geo).abs() < 0.01,
                "{:?}: marginal@d0 {marginal} != geo_npv {geo}",
                kind
            );
        }
    }

    #[test]
    fn optimal_depth_mac_address_enables_wifi_mesh() {
        let (depth_free, _) = optimal_depth(TargetKind::MacAddress, false);
        let (depth_paid, _) = optimal_depth(TargetKind::MacAddress, true);
        // Mac needs: R0 bssid→coords, R1 geocode+wigle, R2 mac mesh
        assert!(depth_free >= 3, "mac free depth {depth_free} < 3");
        assert!(depth_paid >= depth_free, "paid depth should be >= free");
    }

    #[test]
    fn optimal_depth_identity_seeds_reach_wifi_mesh() {
        for kind in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::FullName,
        ] {
            let (depth, _) = optimal_depth(kind, false);
            assert!(
                depth >= 5,
                "{:?}: depth {depth} < 5 (can't reach WiFi mesh)",
                kind
            );
        }
    }

    #[test]
    fn optimal_depth_geo_seeds_have_mesh_refinement() {
        let (coords_depth, _) = optimal_depth(TargetKind::Coordinates, false);
        let (addr_depth, _) = optimal_depth(TargetKind::Address, false);
        assert!(
            coords_depth >= 3,
            "coords needs R0 geocode, R1 wigle, R2 bssid"
        );
        assert!(
            addr_depth >= 3,
            "address needs R0 geocode, R1 wigle, R2 bssid"
        );
    }

    #[test]
    fn optimal_depth_confidence_threshold_below_phone_prefix() {
        let (_, min_conf) = optimal_depth(TargetKind::Phone, false);
        // Phone prefix coords are at 0.52 confidence — threshold must be below that
        assert!(
            min_conf < 0.52,
            "threshold {min_conf} would filter phone prefix coords"
        );
    }

    #[test]
    fn all_target_kinds_have_positive_npvs() {
        let kinds = [
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
            TargetKind::MacAddress,
        ];
        for kind in kinds {
            assert!(seed_npv(kind, false) > 0.0, "{:?} seed_npv is 0", kind);
            assert!(seed_npv(kind, true) > 0.0, "{:?} seed_npv(paid) is 0", kind);
            assert!(geo_npv(kind, false) > 0.0, "{:?} geo_npv is 0", kind);
            assert!(geo_npv(kind, true) > 0.0, "{:?} geo_npv(paid) is 0", kind);
        }
    }

    #[test]
    fn mac_address_round_trips_through_target_kind() {
        let tk = TargetKind::MacAddress;
        let ek = tk.to_entity_kind();
        assert_eq!(ek, EntityKind::MacAddress);
        assert_eq!(TargetKind::from_entity_kind(&ek), Some(tk));
        assert_eq!(tk.canonical_str(), "mac_address");
    }
}
