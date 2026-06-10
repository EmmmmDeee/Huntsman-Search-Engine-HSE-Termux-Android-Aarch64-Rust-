//! Scan request, target, status, and per-scan customisation options.

use serde::{Deserialize, Serialize};

use crate::core::entity::{EntityKind, unix_now};

mod classify;
// Re-exported pub(crate) so engine / audit / import keep using
// `crate::core::scan::is_mega_domain` etc.; `domain_expansion_factor` is bridged
// privately because the scoring submodule reaches it via `super::`.
use classify::domain_expansion_factor;
pub(crate) use classify::{is_mega_domain, is_noncentral_domain, is_wrong_identity_pivot};
// Reached only by the classification tests retained in this file.
#[cfg(test)]
use classify::{identity_norm, identity_overlaps, is_infra_domain};

mod detect;
use detect::{
    has_company_suffix, is_address_shaped, is_cidr_shaped, is_domain_shaped, is_mac_shaped,
    is_phone_shaped,
};

mod scoring;
// Re-exported so external callers keep using `crate::core::scan::expansion_weight`
// etc. unchanged after the expansion-economics model moved to `scoring`.
pub use scoring::{
    corroboration_prior, expansion_weight, expansion_weight_for_strategy, geo_npv, optimal_depth,
    predicted_marginal_yield,
};
// Internal scoring helpers reached only by the scoring tests retained in this file.
#[cfg(test)]
use scoring::{auto_min_expand_confidence, seed_marginal_yield};

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
    Cidr,
    Coordinates,
    Address,
    Organisation,
    AbnAcn,
    MacAddress,
    ApiKey,
    CryptoAddress,
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
            EntityKind::Cidr => Some(Self::Cidr),
            EntityKind::Coordinates => Some(Self::Coordinates),
            EntityKind::Address => Some(Self::Address),
            EntityKind::Url => Some(Self::Url),
            EntityKind::Organisation => Some(Self::Organisation),
            EntityKind::AbnAcn => Some(Self::AbnAcn),
            EntityKind::ApiKey => Some(Self::ApiKey),
            EntityKind::MacAddress => Some(Self::MacAddress),
            EntityKind::CryptoAddress => Some(Self::CryptoAddress),
            EntityKind::Credential
            | EntityKind::DeviceId
            | EntityKind::TrackingId
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
            Self::Cidr => EntityKind::Cidr,
            Self::Coordinates => EntityKind::Coordinates,
            Self::Address => EntityKind::Address,
            Self::Organisation => EntityKind::Organisation,
            Self::AbnAcn => EntityKind::AbnAcn,
            Self::ApiKey => EntityKind::ApiKey,
            Self::MacAddress => EntityKind::MacAddress,
            Self::CryptoAddress => EntityKind::CryptoAddress,
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
            Self::Cidr => "cidr",
            Self::Coordinates => "coordinates",
            Self::Address => "address",
            Self::Organisation => "organisation",
            Self::AbnAcn => "abn_acn",
            Self::ApiKey => "api_key",
            Self::MacAddress => "mac_address",
            Self::CryptoAddress => "crypto_address",
        }
    }

    /// Best-effort classification of a raw target value into a [`TargetKind`].
    /// Powers the **unified scan** path: the operator supplies only a value and
    /// the kind is inferred from its shape (`hse scan -v <value>`; a `ScanRequest`
    /// or `LiveRequest` with no `kind`).
    ///
    /// Ordered most-specific → least, so a value matching several shapes
    /// resolves to the most informative kind (e.g. `8.8.8.8` is a valid IP *and*
    /// dotted like a domain → `IpAddress`). Structured kinds are recognised by
    /// shape; free text falls back to `Organisation` (company suffix) →
    /// `Address` (street shape) → `FullName` (multiple words) → `Username`
    /// (single token). **Never fails** — the fallback is always a valid kind —
    /// so the caller always gets a target to run; [`Target::validate`] still
    /// gates obviously-bogus values downstream.
    ///
    /// `ApiKey` is intentionally NOT auto-detected: its shape overlaps with
    /// opaque usernames/tokens, and a false positive would route a benign value
    /// into the key-probe path — so an API-key scan must be requested explicitly
    /// (`--kind apikey`).
    pub fn detect(value: &str) -> Self {
        let v = value.trim();
        if v.is_empty() {
            // Lax default; `Target::validate` rejects the empty value anyway.
            return Self::Username;
        }
        let lower = v.to_ascii_lowercase();

        // 1. URL — explicit scheme.
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return Self::Url;
        }
        // 2. Email — one '@', non-empty local + dotted host, no whitespace.
        if !v.contains(char::is_whitespace)
            && let Some((local, host)) = v.split_once('@')
            && !local.is_empty()
            && !host.is_empty()
            && !host.contains('@')
            && host.contains('.')
        {
            return Self::Email;
        }
        // 3. IP address (v4/v6).
        if v.parse::<std::net::IpAddr>().is_ok() {
            return Self::IpAddress;
        }
        // 3b. CIDR network block (`a.b.c.d/n`, `2001:db8::/48`) — checked after a
        //     bare IP (which has no `/`) and before the domain/URL shapes.
        if is_cidr_shaped(v) {
            return Self::Cidr;
        }
        // 4. MAC / BSSID — six 2-hex octets separated by ':' or '-'.
        if is_mac_shaped(v) {
            return Self::MacAddress;
        }
        // 5. Coordinates — "lat,lon", both numeric and in range. Delegate to the
        //    canonical, range-validating parser so this classifier and the geo
        //    pipeline agree on exactly what counts as a coordinate pair.
        if crate::util::geohash::parse_coords(v).is_some() {
            return Self::Coordinates;
        }
        // 6. ASN — "AS" + digits.
        if let Some(rest) = lower.strip_prefix("as")
            && !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_digit())
        {
            return Self::Asn;
        }
        // 7. ABN / ACN — 11- or 9-digit registry numbers, checksum-validated so
        //    a same-length phone number can't masquerade as one.
        if v.chars().all(|c| c.is_ascii_digit() || c == ' ') {
            let digits = v.chars().filter(char::is_ascii_digit).count();
            if (digits == 11 && crate::util::abn::is_valid_abn(v))
                || (digits == 9 && crate::util::abn::is_valid_acn(v))
            {
                return Self::AbnAcn;
            }
        }
        // 8. Phone — '+' country code or a punctuated digit run, no letters.
        if is_phone_shaped(v) {
            return Self::Phone;
        }
        // 9. Domain — no whitespace/'@', a dot, valid labels, alpha TLD.
        if is_domain_shaped(v) {
            return Self::Domain;
        }
        // 9b. Cryptocurrency wallet address (bc1…/0x…/base58). Checked after the
        // dotted/numeric shapes (which it never matches) but before the free-text
        // fallback, so a pasted `1A1z…`/`bc1q…`/`0x…` is recognised rather than
        // mis-bucketed as a Username.
        if crate::core::crypto::classify_crypto_address(v).is_some() {
            return Self::CryptoAddress;
        }
        // 10. Free text → Organisation / Address / FullName / Username.
        if has_company_suffix(&lower) {
            return Self::Organisation;
        }
        if is_address_shaped(v) {
            return Self::Address;
        }
        if v.split_whitespace().count() >= 2 {
            return Self::FullName;
        }
        Self::Username
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
}

/// Strip shell/CSV quoting and stray surrounding punctuation a user (or a pasted
/// list) commonly leaves on a target value, e.g. `"Matthew Diegmann",` →
/// `Matthew Diegmann`. Applied only at the user-input boundary ([`Target::new`])
/// so module-discovered entity values are left untouched; kind-specific
/// normalisation (`entity::normalise`) runs afterwards.
///
/// Real cause this fixes: a `full_name` scan came in as `"\"Matthew Diegmann\""`
/// (literal quotes), which the `_` arm of `normalise` only whitespace-trimmed —
/// the quotes then leaked into name permutations and every derived artifact.
///
/// The strip is iterative so layered artifacts unwrap fully: a trailing comma
/// outside a quote pair (`"x",`) is removed first, exposing the quote pair.
fn sanitise_target_input(raw: &str) -> String {
    // ASCII + common Unicode quote pairs. A value bounded by a matching pair is
    // never legitimate for any target kind (emails, domains, names, …).
    const QUOTE_PAIRS: &[(char, char)] = &[
        ('"', '"'),
        ('\'', '\''),
        ('`', '`'),
        ('\u{201C}', '\u{201D}'), // “ ”
        ('\u{2018}', '\u{2019}'), // ‘ ’
    ];
    // Separators a list/CSV paste leaves dangling on an end. Never bound a target.
    let stray = |c: char| matches!(c, ',' | ';' | '|');

    let mut s = raw.trim();
    loop {
        let before = s;
        s = s.trim_matches(stray).trim();
        if let (Some(first), Some(last)) = (s.chars().next(), s.chars().last())
            && s.chars().count() >= 2
            && QUOTE_PAIRS.contains(&(first, last))
        {
            s = &s[first.len_utf8()..s.len() - last.len_utf8()];
        }
        if s == before {
            break;
        }
    }
    s.to_string()
}

/// Detect a [`TargetKind`] from a **raw**, user-supplied value — sanitising
/// surrounding quotes / stray separators first (exactly as [`Target::new`]
/// does), so a pasted `"https://x.com",` is classified by its *cleaned* form.
///
/// Every auto-detect entry point (CLI `--kind auto`, and `ScanRequest` /
/// `LiveRequest` with no `kind`) MUST go through this rather than calling
/// `TargetKind::detect` on the raw string: otherwise the detected kind is
/// computed from the dirty value while the scan runs on the sanitised value,
/// so a pasted target could be classed `Username` but stored as a URL and
/// routed through the wrong modules.
pub fn detect_kind(raw: &str) -> TargetKind {
    TargetKind::detect(&sanitise_target_input(raw))
}

impl Target {
    pub fn new(kind: TargetKind, value: impl Into<String>) -> Self {
        let raw: String = value.into();
        let cleaned = sanitise_target_input(&raw);
        let normalised = crate::core::entity::normalise(&kind.to_entity_kind(), &cleaned);
        Self {
            kind,
            value: normalised,
        }
    }

    /// Build a target by auto-detecting its [`TargetKind`] from the value — the
    /// **unified scan** entry point. Detection runs on the sanitised value (so
    /// quotes/stray punctuation don't skew it); sanitisation + normalisation
    /// then match [`Target::new`]. Returns the resolved kind alongside the
    /// target so callers can surface it (CLI message, `scan_id`, API response).
    pub fn detect(value: impl Into<String>) -> Self {
        let raw: String = value.into();
        let kind = detect_kind(&raw);
        Self::new(kind, raw)
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
                if crate::core::validation::is_placeholder_domain(host) {
                    return Err("email host is a reserved/placeholder (example) domain");
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
                if crate::core::validation::is_placeholder_domain(v) {
                    return Err("domain is a reserved/placeholder (example) domain");
                }
            }
            TargetKind::IpAddress => {
                v.parse::<std::net::IpAddr>()
                    .map_err(|_| "not a valid IPv4 or IPv6 address")?;
            }
            TargetKind::Cidr => {
                if !is_cidr_shaped(v) {
                    return Err("not a valid CIDR block (e.g. 192.0.2.0/24)");
                }
            }
            TargetKind::Asn => {
                let upper = v.to_uppercase();
                let digits = upper.strip_prefix("AS").unwrap_or(&upper);
                if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                    return Err("ASN must be digits, optionally prefixed by 'AS'");
                }
            }
            TargetKind::Phone => {
                let digits = crate::util::str_util::ascii_digits(v);
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
            TargetKind::AbnAcn => {
                // ACN = 9 digits, ABN = 11 (spaces/punctuation allowed and
                // ignored — matches abn_lookup's digit-count dispatch). Fail
                // fast on a non-registry value like a name, as the other
                // structured kinds do, instead of dispatching a guaranteed no-op.
                let digits = v.chars().filter(char::is_ascii_digit).count();
                if digits != 9 && digits != 11 {
                    return Err("ABN/ACN must be 9 digits (ACN) or 11 digits (ABN)");
                }
            }
            TargetKind::MacAddress => {
                // 6 hex octets, with or without `:` / `-` / `.` separators.
                let hex: String = v
                    .chars()
                    .filter(|c| !matches!(c, ':' | '-' | '.'))
                    .collect();
                if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("MAC address must be 6 hex octets (e.g. AA:BB:CC:DD:EE:FF)");
                }
            }
            TargetKind::CryptoAddress => {
                if crate::core::crypto::classify_crypto_address(v).is_none() {
                    return Err("not a recognised cryptocurrency address shape");
                }
            }
            TargetKind::Username
            | TargetKind::FullName
            | TargetKind::Address
            | TargetKind::Organisation => {}
        }

        // Never scan our own egress infrastructure: a host/IP configured as a
        // rotation proxy or DNS resolver is routed *through*, never investigated.
        // No-op unless HUNTSMAN_SEARCH_PROXY / HUNTSMAN_PROXY / HUNTSMAN_DNS_RESOLVERS
        // is set, so default behaviour is unchanged.
        let infra_host: Option<String> = match self.kind {
            TargetKind::Domain | TargetKind::IpAddress => Some(v.to_string()),
            TargetKind::Url => url::Url::parse(v)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string)),
            _ => None,
        };
        if let Some(h) = infra_host
            && crate::util::preflight::is_infrastructure_host(&h)
        {
            return Err(
                "target is configured network infrastructure (proxy / DNS resolver) — not scanned",
            );
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
    /// Modules that were skipped rather than run: gate-skips (excluded,
    /// disabled in config, not in the allowlist, filtered by `--free-only` /
    /// `--passive-only`, or a sensor that already ran on the seed round) plus
    /// modules that dispatched but cleanly opted out because a required
    /// (optional) API key is not configured. Distinct from `modules_errored`.
    #[serde(default)]
    pub modules_skipped: usize,
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
            modules_skipped: 0,
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
    /// Target kind. `None` (omitted in the request) triggers shape-based
    /// auto-detection via [`TargetKind::detect`] — the unified-scan path.
    /// An explicit kind is always honoured as-is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<TargetKind>,
    pub value: String,
    /// Per-scan options. Defaults to [`default_scan_options`] (product default
    /// depth 2) when omitted, so a bare `{"value": "..."}` request recurses two
    /// hops just like the CLI and web UI.
    #[serde(default = "default_scan_options")]
    pub options: ScanOptions,
}

impl ScanRequest {
    /// Resolve the request's [`TargetKind`]: the explicit kind if supplied,
    /// otherwise auto-detected from `value`. Single source of truth shared by
    /// the scan-create, batch and rerun paths so detection can't diverge.
    pub fn resolved_kind(&self) -> TargetKind {
        self.kind.unwrap_or_else(|| detect_kind(&self.value))
    }
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
    /// off an `matthewdiegmann` seed). The gate is the right default for a
    /// focused investigation, but it is by design conservative and can drop a
    /// genuine alias whose handle looks unrelated (a pseudonym, an initials
    /// handle, a married name). An operator who would rather over-collect and
    /// prune by hand sets this to `true` — every excluded alias is still logged
    /// as `identity_mismatch` when the gate is on, so the trade-off is visible
    /// either way.
    #[serde(default)]
    pub expand_all_identities: bool,
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
/// Two hops balances coverage (seed → directly-discovered entities → their
/// first-order pivots) against runtime on a phone. The library [`ScanOptions`]
/// default stays `0` (single round) so programmatic/API callers and the test
/// suite remain deterministic; this product default is applied at the CLI
/// boundary in `cli::scan`.
pub const DEFAULT_SCAN_DEPTH: u32 = 2;

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

/// Marginal-yield floor for the `--auto` depth curve, expressed as *new
/// graph-advancing entities per dispatched pivot*. A round whose predicted
/// marginal yield falls below this is dominated by re-confirmation rather than
/// discovery, so `--auto` does not schedule it. Tied to the engine's own
/// runtime adaptive-termination threshold so the planned depth and the live
/// `dE/dDispatch → 0` cutoff agree by construction.
pub const MARGINAL_YIELD_FLOOR: f64 = crate::core::roi::DEFAULT_MIN_MARGINAL_YIELD;

#[cfg(test)]
mod tests;
