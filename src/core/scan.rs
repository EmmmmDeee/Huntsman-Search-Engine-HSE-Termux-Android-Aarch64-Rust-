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
        // 4. MAC / BSSID — six 2-hex octets separated by ':' or '-'.
        if is_mac_shaped(v) {
            return Self::MacAddress;
        }
        // 5. Coordinates — "lat,lon", both numeric and in range.
        if let Some((a, b)) = v.split_once(',')
            && let (Ok(lat), Ok(lon)) = (a.trim().parse::<f64>(), b.trim().parse::<f64>())
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon)
        {
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

/// Six 2-hex-digit octets joined by ':' or '-' (`aa:bb:cc:dd:ee:ff`). A 6-group
/// colon form is not a valid IPv6 address (which needs 8 groups or `::`), so the
/// IP check ahead of this in [`TargetKind::detect`] never steals a real MAC.
fn is_mac_shaped(v: &str) -> bool {
    let sep = if v.contains(':') {
        ':'
    } else if v.contains('-') {
        '-'
    } else {
        return false;
    };
    let octets: Vec<&str> = v.split(sep).collect();
    octets.len() == 6
        && octets
            .iter()
            .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A dialable phone number: 7–15 digits with only phone punctuation
/// (`+ - space ( ) .`), and any `+` only as the leading character.
fn is_phone_shaped(v: &str) -> bool {
    let digits = v.chars().filter(char::is_ascii_digit).count();
    if !(7..=15).contains(&digits) {
        return false;
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')' | '.'))
    {
        return false;
    }
    // A '+' is allowed only once, and only as the leading character (the
    // international-dialling form); `+123+4567` is not a phone number.
    let plus = v.chars().filter(|&c| c == '+').count();
    plus == 0 || (plus == 1 && v.trim_start().starts_with('+'))
}

/// Domain-name shape: no whitespace/'@', at least one dot, only label chars
/// (`alnum . - _`), non-empty labels, and a TLD of ≥2 ASCII letters.
fn is_domain_shaped(v: &str) -> bool {
    if v.contains(char::is_whitespace) || v.contains('@') || !v.contains('.') {
        return false;
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return false;
    }
    let labels: Vec<&str> = v.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    match labels.last() {
        Some(tld) => tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()),
        None => false,
    }
}

/// `value` (already lowercased) ends with a recognised company-form suffix.
fn has_company_suffix(lower: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        " pty ltd",
        " pty. ltd.",
        " pty limited",
        " inc",
        " inc.",
        " llc",
        " l.l.c.",
        " ltd",
        " ltd.",
        " limited",
        " corp",
        " corp.",
        " corporation",
        " gmbh",
        " plc",
        " ag",
        " s.a.",
        " b.v.",
    ];
    SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Street-address shape: a leading house number, then a space and an alphabetic
/// word (`123 Main St`, `42 Wallaby Way, Sydney`). Requires the leading number
/// so it never swallows a bare name; coordinates/phones are matched earlier.
fn is_address_shaped(v: &str) -> bool {
    let house = v.bytes().take_while(u8::is_ascii_digit).count();
    if house == 0 {
        return false;
    }
    let rest = v[house..].trim_start();
    rest.chars().next().is_some_and(char::is_alphabetic) && v.contains(' ')
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
    /// Modules that cleanly opted out because a required (optional) API key is
    /// not configured — distinct from `modules_errored`.
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
    #[serde(default)]
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
            throttle_ms: 0,
            // Deliberately gentle (2, not the old 4): two concurrent network
            // modules paces dispatch so a deep/everything scan does not flood
            // the link or trip provider rate limits. Operators can raise it
            // with `--max-concurrent` when they know the network can take it.
            max_concurrent: 2,
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

/// Marginal-yield floor for the `--auto` depth curve, expressed as *new
/// graph-advancing entities per dispatched pivot*. A round whose predicted
/// marginal yield falls below this is dominated by re-confirmation rather than
/// discovery, so `--auto` does not schedule it. Tied to the engine's own
/// runtime adaptive-termination threshold so the planned depth and the live
/// `dE/dDispatch → 0` cutoff agree by construction.
pub const MARGINAL_YIELD_FLOOR: f64 = crate::core::roi::DEFAULT_MIN_MARGINAL_YIELD;

/// Expected marginal yield of the **first** expansion round (round 1) for a
/// seed of `kind` at the given API tier — `m₁` in the geometric yield model
/// `m(d) = m₁ · q^(d−1)` used by [`optimal_depth`]. Units: new graph-advancing
/// entities per dispatched pivot.
///
/// Anchored to the two live Termux scans in the validation transcript:
///   * a `FullName` seed surfaced 446 seed-round entities (oathnet 374,
///     name_intel 51, social_probe 3, qld 18) → a dense round-1 pivot pool;
///   * a `Username` seed surfaced 91 (username_search 65, social_probe 19,
///     oathnet 6, variants 1) → a sparser pool.
///
/// The ordering `FullName (2.9) > Username (2.4)` reproduces that 446 ≫ 91 gap.
/// Unobserved kinds are placed by their expandable-pivot fan-out: identity
/// seeds richest; terminal geo/registry seeds (Coordinates, AbnAcn, ApiKey)
/// sit near the 1.0 "one weak pivot" floor. Paid keys raise the ceiling
/// because OathNet/IntelX re-queries on round-1 discoveries keep the frontier
/// novel for an extra round instead of re-confirming.
fn seed_marginal_yield(kind: TargetKind, has_paid_keys: bool) -> f64 {
    let (paid, free) = match kind {
        // Identity seeds — richest expandable fan-out (emails → usernames →
        // domains → socials), and the only kinds the paid tier can keep novel
        // for a third round.
        TargetKind::Email => (3.2, 2.0),
        TargetKind::FullName => (2.9, 1.9),
        TargetKind::Username => (2.4, 1.6),
        TargetKind::Domain => (2.2, 1.7),
        // High-value geo pivots — one or two reliable hops to coordinates.
        TargetKind::Address => (1.9, 1.5),
        TargetKind::IpAddress => (1.6, 1.25),
        TargetKind::MacAddress => (1.4, 1.4),
        // Mid fan-out — a handful of corroborating leads per round.
        TargetKind::Phone => (1.6, 1.15),
        TargetKind::Asn => (1.6, 1.2),
        TargetKind::Organisation => (1.6, 1.2),
        TargetKind::Url => (1.55, 1.2),
        // Terminal / registry seeds — resolve and stop.
        TargetKind::AbnAcn => (1.3, 1.1),
        TargetKind::Coordinates => (1.2, 1.2),
        TargetKind::ApiKey => (1.1, 1.0),
    };
    if has_paid_keys { paid } else { free }
}

/// Per-round retention `q ∈ (0,1)` — the fraction of a round's marginal yield
/// carried into the next round before re-confirmation and frontier drift erode
/// it. Identity seeds retain most (each round still surfaces independent new
/// pivots); geo/terminal seeds collapse fast once the coordinate/address is
/// resolved. Combined with [`seed_marginal_yield`] this fixes the shape of the
/// decay curve [`optimal_depth`] integrates.
fn round_retention(kind: TargetKind) -> f64 {
    match kind {
        TargetKind::Email | TargetKind::FullName | TargetKind::Username | TargetKind::Domain => {
            0.60
        }
        TargetKind::Address | TargetKind::MacAddress => 0.55,
        TargetKind::IpAddress | TargetKind::Asn | TargetKind::Organisation => 0.52,
        TargetKind::Phone | TargetKind::Url => 0.50,
        TargetKind::AbnAcn => 0.45,
        TargetKind::Coordinates | TargetKind::ApiKey => 0.40,
    }
}

/// Predicted marginal yield of expansion `round` (1-indexed) for a seed of
/// `kind` — the geometric decay `m(round) = m₁ · q^(round−1)`. Exposed so the
/// depth choice in [`optimal_depth`] and its statistical invariants are
/// machine-checkable (see tests), and so callers can reason about the curve.
#[must_use]
pub fn predicted_marginal_yield(kind: TargetKind, has_paid_keys: bool, round: u32) -> f64 {
    let m1 = seed_marginal_yield(kind, has_paid_keys);
    let q = round_retention(kind);
    m1 * q.powi(i32::try_from(round.saturating_sub(1)).unwrap_or(0))
}

/// Confidence floor for `--auto` expansion, scaled with the scheduled depth.
/// Deeper auto-scans raise the bar — each extra round compounds false-positive
/// risk through `c_eff`, so a higher floor keeps expected precision roughly
/// constant across rounds; the paid tier starts marginally lower because its
/// leads arrive better-corroborated. Clamped to a sane `[0.40, 0.55]` band.
fn auto_min_expand_confidence(depth: u32, has_paid_keys: bool) -> f64 {
    let base = if has_paid_keys { 0.42 } else { 0.46 };
    (base + 0.03 * f64::from(depth.saturating_sub(1))).clamp(0.40, 0.55)
}

/// Statistically-grounded expansion depth for a seed and API tier, via a
/// geometric **yield-curve** model rather than hand-tuned per-kind constants.
///
/// The previous constants (4–5 per kind) were silently flattened by the
/// [`MAX_DEPTH`] = 3 clamp — every kind resolved to depth 3 — so depth carried
/// no signal. This model instead schedules the *largest round whose predicted
/// marginal yield still clears [`MARGINAL_YIELD_FLOOR`]*:
///
/// ```text
///   m(d) = m₁ · q^(d−1)                          (geometric decay of new/dispatch)
///   D*   = max{ d ∈ 1..=MAX_DEPTH : m(d) ≥ floor }    (≥ 1 — one round is cheap)
/// ```
///
/// where `m₁` = [`seed_marginal_yield`] (anchored to the live transcript:
/// FullName 446 vs Username 91 seed entities) and `q` = [`round_retention`].
/// This is the same `dE/dDispatch → 0` cutoff the engine enforces at runtime
/// via [`crate::core::roi::should_terminate_adaptive`]; computing it ahead of
/// time lets `--auto` stop one round *before* paying for a round the curve
/// already predicts is re-confirmation. Net effect: rich identity seeds earn
/// the full depth-3 budget with paid keys and depth 2 keyless, while terminal
/// seeds (Coordinates/AbnAcn/ApiKey) correctly resolve at depth 1 — the
/// differentiation the old constants intended but the clamp erased.
///
/// Returns `(depth, min_expand_confidence)`.
pub fn optimal_depth(kind: TargetKind, has_paid_keys: bool) -> (u32, f64) {
    // Walk the curve outward and keep the last round that clears the floor.
    // Floor at 1: a single expansion round is cheap and almost always pays,
    // and the runtime adaptive guard cuts it short anyway if it doesn't.
    let mut depth: u32 = 1;
    for round in 1..=MAX_DEPTH {
        // `- f64::EPSILON` admits a round whose predicted yield sits exactly on
        // the floor (e.g. Url paid R2) rather than letting FP error drop it.
        if predicted_marginal_yield(kind, has_paid_keys, round)
            >= MARGINAL_YIELD_FLOOR - f64::EPSILON
        {
            depth = round;
        } else {
            break;
        }
    }
    (depth, auto_min_expand_confidence(depth, has_paid_keys))
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

/// Coefficient on the corroboration prior. Larger than `c_eff`'s 0.15 because
/// ranking can be more assertive than a calibrated confidence — but small
/// enough that corroboration only *refines order within* a geo-proximity tier,
/// never overrides geo-convergence (an 8-source far entity scores ×1.52, still
/// under a 1-source IP's ×1.8 geo boost).
const CORROBORATION_PRIOR_COEFF: f64 = 0.25;

/// Non-saturating ranking multiplier rewarding independent cross-correlation.
///
/// `c_effective()` already folds corroboration in via `1 + 0.15·ln(sources)`,
/// but it is **clamped to 1.0** — so for confident pivots the corroboration
/// signal is erased: a c_eff=1.0 entity confirmed by six independent sources
/// ranks identically to a single-source one. Expansion ranking is exactly
/// where that signal matters most (a cross-corroborated lead is far likelier
/// to be genuine, so its dispatch is likelier to yield real children), so we
/// re-introduce it here as an *uncapped* factor on the expansion weight.
///
/// `1 + β·ln(source_count)` with `source_count ≥ 1`: a single source gives
/// `ln(1)=0 → 1.0` (neutral — no penalty vs today's behaviour), and each
/// additional independent source adds sharply diminishing weight. Uses the
/// distinct-source count (the honest cross-correlation measure), never the
/// inflatable `corroboration` magnitude.
#[must_use]
pub fn corroboration_prior(source_count: u32) -> f64 {
    let sources = f64::from(source_count.max(1));
    CORROBORATION_PRIOR_COEFF.mul_add(sources.ln(), 1.0)
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
    fn sanitise_strips_surrounding_quotes_and_stray_punctuation() {
        // The exact real failure: a full_name target arrived quoted.
        assert_eq!(
            sanitise_target_input("\"Matthew Diegmann\""),
            "Matthew Diegmann"
        );
        // Quote + trailing comma (CSV/list paste).
        assert_eq!(
            sanitise_target_input("\"Matthew Diegmann\","),
            "Matthew Diegmann"
        );
        assert_eq!(sanitise_target_input("'jdoe'"), "jdoe");
        assert_eq!(sanitise_target_input("  jdoe ;"), "jdoe");
        // Unicode smart quotes.
        assert_eq!(
            sanitise_target_input("\u{201C}Jane Roe\u{201D}"),
            "Jane Roe"
        );
        // Inner punctuation/quotes are preserved — only the bounding layer goes.
        assert_eq!(sanitise_target_input("a\"b"), "a\"b");
        assert_eq!(sanitise_target_input("o'brien"), "o'brien");
        // Idempotent on already-clean input; doesn't mangle structured kinds.
        assert_eq!(
            sanitise_target_input("matthewdiegmann@gmail.com"),
            "matthewdiegmann@gmail.com"
        );
        assert_eq!(sanitise_target_input(""), "");
    }

    #[test]
    fn target_new_sanitises_quoted_full_name() {
        // End-to-end through the user-input boundary: the quotes never reach
        // the stored value (and thus never reach name permutations).
        let t = Target::new(TargetKind::FullName, "\"Matthew Diegmann\"");
        assert_eq!(t.value, "Matthew Diegmann");
    }

    #[test]
    fn options_default_is_inert() {
        let o = ScanOptions::default();
        assert!(o.modules.is_none());
        assert_eq!(o.throttle_ms, 0);
        assert!(!o.free_only);
        assert!(!o.passive_only);
        assert_eq!(o.depth, 0);
        assert!((o.min_expand_confidence - 0.50).abs() < 1e-9);
        // Gentle by default (2, not 4) so deep/everything scans don't flood the
        // link or trip provider rate limits.
        assert_eq!(o.max_concurrent, 2);
    }

    #[test]
    fn clamp_depth_enforces_max_depth() {
        assert_eq!(MAX_DEPTH, 3);
        let over = ScanOptions {
            depth: 99,
            ..Default::default()
        };
        assert_eq!(
            over.clamp_depth().depth,
            MAX_DEPTH,
            "deep request is capped"
        );
        let under = ScanOptions {
            depth: 2,
            ..Default::default()
        };
        assert_eq!(under.clamp_depth().depth, 2, "in-range depth is untouched");
    }

    #[test]
    fn optimal_depth_never_exceeds_max_depth_and_is_at_least_one() {
        // Iterate the CANONICAL kind list so a newly-added TargetKind is forced
        // through the depth model (the exhaustive `match`es panic-free here).
        for &kind in crate::core::dependency::ALL_TARGET_KINDS {
            for paid in [true, false] {
                let (d, c) = optimal_depth(kind, paid);
                assert!(
                    (1..=MAX_DEPTH).contains(&d),
                    "{kind:?} paid={paid}: depth {d}"
                );
                assert!((0.40..=0.55).contains(&c), "{kind:?} paid={paid}: conf {c}");
            }
        }
    }

    #[test]
    fn optimal_depth_is_differentiated_not_pinned_at_ceiling() {
        // Regression guard for the old bug: the hand-tuned 4/5 constants were
        // all flattened to 3 by `.min(MAX_DEPTH)`, so depth carried no signal.
        // The yield model MUST spread depth across the [1, MAX_DEPTH] range.
        let depths: std::collections::BTreeSet<u32> = crate::core::dependency::ALL_TARGET_KINDS
            .iter()
            .flat_map(|&k| [optimal_depth(k, true).0, optimal_depth(k, false).0])
            .collect();
        assert!(
            depths.len() >= 3,
            "depth must be differentiated across kinds, saw only {depths:?}"
        );
        assert!(
            depths.contains(&1),
            "some terminal seed must resolve at depth 1"
        );
        assert!(
            depths.contains(&MAX_DEPTH),
            "some rich seed must reach MAX_DEPTH"
        );

        // Rich identity seeds with paid keys earn the full budget…
        for k in [
            TargetKind::Email,
            TargetKind::FullName,
            TargetKind::Username,
            TargetKind::Domain,
        ] {
            assert_eq!(
                optimal_depth(k, true).0,
                MAX_DEPTH,
                "{k:?} paid → MAX_DEPTH"
            );
            assert_eq!(optimal_depth(k, false).0, 2, "{k:?} keyless → 2");
        }
        // …terminal / registry seeds resolve in a single round.
        for k in [
            TargetKind::Coordinates,
            TargetKind::AbnAcn,
            TargetKind::ApiKey,
        ] {
            assert_eq!(optimal_depth(k, true).0, 1, "{k:?} is terminal");
            assert_eq!(optimal_depth(k, false).0, 1, "{k:?} is terminal");
        }
    }

    #[test]
    fn optimal_depth_paid_tier_is_never_shallower_than_free() {
        for &kind in crate::core::dependency::ALL_TARGET_KINDS {
            assert!(
                optimal_depth(kind, true).0 >= optimal_depth(kind, false).0,
                "{kind:?}: paid depth must be ≥ free depth"
            );
        }
    }

    #[test]
    fn optimal_depth_respects_the_marginal_yield_floor() {
        // The core statistical invariant: the chosen depth D is exactly the
        // cutoff of the yield curve — round D clears the floor, and round D+1
        // (if one exists below MAX_DEPTH) does not. This is what makes the
        // depth a *decision* rather than a constant.
        for &kind in crate::core::dependency::ALL_TARGET_KINDS {
            for paid in [true, false] {
                let (d, _) = optimal_depth(kind, paid);
                assert!(
                    predicted_marginal_yield(kind, paid, d) >= MARGINAL_YIELD_FLOOR - f64::EPSILON,
                    "{kind:?} paid={paid}: round {d} must clear the floor"
                );
                if d < MAX_DEPTH {
                    assert!(
                        predicted_marginal_yield(kind, paid, d + 1) < MARGINAL_YIELD_FLOOR,
                        "{kind:?} paid={paid}: round {} must fall below the floor",
                        d + 1
                    );
                }
            }
        }
    }

    #[test]
    fn predicted_marginal_yield_decays_monotonically_with_round() {
        // 0 < q < 1 and m₁ > 0 ⇒ each round is strictly less productive than
        // the last — the property the depth cutoff relies on.
        for &kind in crate::core::dependency::ALL_TARGET_KINDS {
            for paid in [true, false] {
                let mut prev = f64::INFINITY;
                for round in 1..=MAX_DEPTH + 1 {
                    let y = predicted_marginal_yield(kind, paid, round);
                    assert!(y > 0.0, "{kind:?}: yield must stay positive");
                    assert!(y < prev, "{kind:?} round {round}: yield must decay");
                    prev = y;
                }
            }
        }
    }

    #[test]
    fn seed_yield_ordering_matches_observed_transcript() {
        // Live transcript: FullName seed surfaced 446 entities, Username 91.
        // The model's round-1 yields must preserve that ≫ ordering, and the
        // richest identity seeds must out-yield terminal seeds.
        for paid in [true, false] {
            assert!(
                seed_marginal_yield(TargetKind::FullName, paid)
                    > seed_marginal_yield(TargetKind::Username, paid)
            );
            assert!(
                seed_marginal_yield(TargetKind::Email, paid)
                    >= seed_marginal_yield(TargetKind::FullName, paid)
            );
            assert!(
                seed_marginal_yield(TargetKind::Username, paid)
                    > seed_marginal_yield(TargetKind::ApiKey, paid)
            );
        }
    }

    #[test]
    fn auto_min_expand_confidence_rises_with_depth_within_band() {
        // Deeper scans are more selective; every value stays in [0.40, 0.55];
        // the paid tier starts no higher than the free tier at equal depth.
        for paid in [true, false] {
            let c1 = auto_min_expand_confidence(1, paid);
            let c2 = auto_min_expand_confidence(2, paid);
            let c3 = auto_min_expand_confidence(3, paid);
            assert!(
                c1 <= c2 && c2 <= c3,
                "confidence floor must rise with depth"
            );
            for c in [c1, c2, c3] {
                assert!((0.40..=0.55).contains(&c));
            }
        }
        for d in 1..=MAX_DEPTH {
            assert!(auto_min_expand_confidence(d, true) <= auto_min_expand_confidence(d, false));
        }
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
    fn corroboration_prior_is_neutral_at_one_source_and_grows_diminishingly() {
        // Single source must not penalise vs today's behaviour: exactly 1.0.
        assert!((corroboration_prior(1) - 1.0).abs() < 1e-12);
        // 0 is floored to 1 (defensive).
        assert!((corroboration_prior(0) - 1.0).abs() < 1e-12);
        // Strictly increasing with independent sources…
        assert!(corroboration_prior(2) > corroboration_prior(1));
        assert!(corroboration_prior(4) > corroboration_prior(2));
        assert!(corroboration_prior(8) > corroboration_prior(4));
        // …with diminishing returns (concave: each doubling adds a constant,
        // shrinking increment relative to the level).
        let d_1_2 = corroboration_prior(2) - corroboration_prior(1);
        let d_2_4 = corroboration_prior(4) - corroboration_prior(2);
        assert!((d_1_2 - d_2_4).abs() < 1e-9, "ln doubling steps are equal");
        assert!(corroboration_prior(4) - corroboration_prior(2) < d_1_2 * 1.0 + 1e-9);
    }

    #[test]
    fn corroboration_prior_refines_within_tier_never_overrides_geo() {
        // A heavily-corroborated FAR entity must still rank below a
        // single-source geo-proximate IP — corroboration refines order within
        // a geo tier, it does not invert the geo-convergence priority.
        let far_8src =
            expansion_weight(TargetKind::Organisation, 0.80, "x", false) * corroboration_prior(8);
        let ip_1src = expansion_weight(TargetKind::IpAddress, 0.80, "8.8.8.8", false)
            * corroboration_prior(1);
        assert!(
            ip_1src > far_8src,
            "geo-proximate IP ({ip_1src:.1}) must outrank corroborated org ({far_8src:.1})"
        );
        // But within the SAME kind, corroboration breaks the c_eff=1.0 tie.
        let a = expansion_weight(TargetKind::Email, 1.0, "a@x.com", true) * corroboration_prior(6);
        let b = expansion_weight(TargetKind::Email, 1.0, "b@x.com", true) * corroboration_prior(1);
        assert!(a > b, "6-source email must outrank 1-source at equal c_eff");
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
            kind: Some(TargetKind::Email),
            value: "x@y.com".into(),
            options: ScanOptions::default(),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"kind\":\"email\""));

        // Omitted kind → None → auto-detected; the field is skipped on the wire.
        let auto: ScanRequest = serde_json::from_str(r#"{"value":"x@y.com"}"#).unwrap();
        assert_eq!(auto.kind, None);
        assert_eq!(auto.resolved_kind(), TargetKind::Email);
        assert!(!serde_json::to_string(&auto).unwrap().contains("kind"));
    }

    // ── TargetKind::detect — unified-scan auto-detection ──────────────────────

    #[test]
    fn detect_classifies_structured_kinds() {
        use TargetKind::*;
        let cases = [
            ("https://example.com/page", Url),
            ("http://x.io", Url),
            ("alice@example.com", Email),
            ("8.8.8.8", IpAddress),
            ("2001:4860:4860::8888", IpAddress),
            ("aa:bb:cc:dd:ee:ff", MacAddress),
            ("AA-BB-CC-DD-EE-FF", MacAddress),
            ("-33.8688,151.2093", Coordinates),
            ("AS13335", Asn),
            ("as15169", Asn),
            ("51824753556", AbnAcn),    // valid ABN (ATO worked example)
            ("51 824 753 556", AbnAcn), // spaced ABN
            ("+61 400 123 456", Phone),
            ("(07) 3000 1234", Phone),
            ("example.com", Domain),
            ("sub.example.co.uk", Domain),
        ];
        for (value, want) in cases {
            assert_eq!(TargetKind::detect(value), want, "detect({value:?})");
        }
    }

    #[test]
    fn detect_classifies_free_text() {
        use TargetKind::*;
        assert_eq!(TargetKind::detect("jsmith"), Username);
        assert_eq!(TargetKind::detect("shinigami_jerome"), Username);
        assert_eq!(TargetKind::detect("Matthew Diegmann"), FullName);
        assert_eq!(TargetKind::detect("Acme Pty Ltd"), Organisation);
        assert_eq!(TargetKind::detect("Globex Corporation"), Organisation);
        assert_eq!(TargetKind::detect("123 Main St, Springfield"), Address);
    }

    #[test]
    fn detect_disambiguates_overlapping_shapes() {
        // Dotted-but-valid IP beats domain.
        assert_eq!(TargetKind::detect("8.8.8.8"), TargetKind::IpAddress);
        // 11 digits that are NOT a valid ABN fall through to phone.
        assert_eq!(TargetKind::detect("12345678901"), TargetKind::Phone);
        // A valid ABN of the same length is recognised as the registry id.
        assert_eq!(TargetKind::detect("51824753556"), TargetKind::AbnAcn);
        // '+' is valid only once and only leading: a stray internal '+' is not
        // a phone, but a normal international number still is.
        assert_ne!(TargetKind::detect("+123+4567"), TargetKind::Phone);
        assert_eq!(TargetKind::detect("+61400123456"), TargetKind::Phone);
    }

    #[test]
    fn detect_never_panics_on_junk() {
        let big = "x".repeat(2000);
        let junk = [
            "",
            "   ",
            "@",
            "a@b",
            "...",
            "::::::",
            "+",
            "AS",
            "9999",
            "🦀",
            "a b c d e f",
            "-",
            big.as_str(),
        ];
        for v in junk {
            let _ = TargetKind::detect(v); // must not panic
        }
    }

    #[test]
    fn detect_then_validate_round_trips_clean_values() {
        // A value detected from a clean input must pass Target::validate, so the
        // unified path never produces a target the engine would reject.
        // Real (non-placeholder) values: `validate` rejects reserved
        // documentation domains like example.com, so use live ones here.
        for v in [
            "alice@proton.me",
            "cloudflare.com",
            "8.8.8.8",
            "AS13335",
            "+61400123456",
            "Matthew Diegmann",
            "jsmith",
            "https://cloudflare.com/p",
        ] {
            let t = Target::detect(v);
            assert!(
                t.validate().is_ok(),
                "detect+validate failed for {v:?}: {t:?}"
            );
        }
    }

    #[test]
    fn target_detect_resolves_and_normalises() {
        let t = Target::detect("Alice@Example.Com");
        assert_eq!(t.kind, TargetKind::Email);
        assert_eq!(t.value, "alice@example.com"); // email normalisation lowercases
        // Quoted name: detection sees through the quotes; value is sanitised.
        let t2 = Target::detect("\"Matthew Diegmann\"");
        assert_eq!(t2.kind, TargetKind::FullName);
        assert_eq!(t2.value, "Matthew Diegmann");
    }

    #[test]
    fn auto_detect_sanitises_before_classifying() {
        // Regression (PR #102 review): the auto-detect paths must sanitise paste
        // artifacts (surrounding quotes + trailing separators) BEFORE
        // classifying, exactly as `Target::new` sanitises the stored value —
        // otherwise a pasted `"https://x.com",` is classed `Username` while the
        // stored value is a URL, routing the scan through the wrong modules.
        let dirty = "\"https://cloudflare.com\",";
        assert_eq!(detect_kind(dirty), TargetKind::Url);
        assert_eq!(Target::detect(dirty).kind, TargetKind::Url);
        // The shared helper is what every entry point uses:
        let req = ScanRequest {
            kind: None,
            value: dirty.to_string(),
            options: ScanOptions::default(),
        };
        assert_eq!(req.resolved_kind(), TargetKind::Url);
        // And the detected kind agrees with the value the target will store.
        assert_eq!(Target::detect(dirty).value, "https://cloudflare.com");
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
            Target::new(TargetKind::Domain, "cloudflare.com")
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
        // Reserved/placeholder domains are rejected at the seed boundary.
        assert!(
            Target::new(TargetKind::Domain, "example.com")
                .validate()
                .is_err(),
            "example.com is a reserved placeholder — must not be scannable"
        );
        assert!(
            Target::new(TargetKind::Email, "jordan@example.com")
                .validate()
                .is_err(),
            "placeholder email host must be rejected"
        );
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
