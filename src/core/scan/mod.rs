//! Scan request, target, status, and per-scan customisation options.

use serde::{Deserialize, Serialize};

use crate::core::entity::{EntityKind, unix_now};

mod classify;
// Re-exported pub(crate) so engine / audit / import keep using
// `crate::core::scan::is_mega_domain` etc.; `domain_expansion_factor` is bridged
// privately because the scoring submodule reaches it via `super::`.
use classify::domain_expansion_factor;
// `identity_norm` / `identity_overlaps` are the dictionary-free identity-matching
// primitives; `core::relation` reuses them to bind a subject to their identifiers
// and associates (rather than re-deriving a second, drift-prone copy).
pub(crate) use classify::{
    IDENTITY_OVERLAP_MIN, identity_norm, identity_overlaps, is_infra_domain, is_mega_domain,
    is_noncentral_domain, is_wrong_identity_pivot,
};

mod detect;
use detect::{
    has_company_suffix, is_address_shaped, is_cidr_shaped, is_domain_shaped, is_mac_shaped,
    is_phone_shaped, is_tracking_id_shaped,
};

mod scoring;

mod options;
pub(crate) use options::default_scan_options;
pub use options::{
    DEFAULT_MAX_ENTITIES, DEFAULT_MIN_EXPAND_CONFIDENCE, DEFAULT_SCAN_DEPTH, ExpansionStrategy,
    MAX_CONCURRENT, MAX_DEPTH, ScanOptions, THROTTLE_CEILING_MS, default_wall_for_depth,
};
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
    DeviceId,
    /// A WiFi network name (SSID). A unique SSID is a WiGLE SSID-search seed that
    /// geolocates where the network was observed.
    Ssid,
    /// Google Analytics / Google Tag Manager / GA4 tracking identifier.
    /// Pattern: `UA-XXXXXXX-X`, `GTM-XXXXXXX`, `G-XXXXXXXXXX`, `AW-XXXXXXXXX`.
    /// Emitted by `web_crawler`; queued back for cross-domain co-ownership search.
    TrackingId,
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
            EntityKind::DeviceId => Some(Self::DeviceId),
            EntityKind::Ssid => Some(Self::Ssid),
            EntityKind::TrackingId => Some(Self::TrackingId),
            EntityKind::Credential | EntityKind::Password | EntityKind::Other(_) => None,
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
            Self::DeviceId => EntityKind::DeviceId,
            Self::Ssid => EntityKind::Ssid,
            Self::TrackingId => EntityKind::TrackingId,
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
            Self::DeviceId => "device_id",
            Self::Ssid => "ssid",
            Self::TrackingId => "tracking_id",
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
        // `detect` runs on every classified candidate across the whole scan (via
        // `core::classifier::extract`/`classify`), so avoid allocating a full
        // lowercased copy of `value` just to run 3 ASCII-case-insensitive checks
        // below (the URL-scheme prefix, the ASN "as" prefix, and the company-suffix
        // match) — each compares directly against `v`'s bytes instead.
        let starts_with_ci = |prefix: &str| {
            let pb = prefix.as_bytes();
            v.len() >= pb.len() && v.as_bytes()[..pb.len()].eq_ignore_ascii_case(pb)
        };

        // 1. URL — explicit scheme.
        if starts_with_ci("http://") || starts_with_ci("https://") {
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
        // 5. Coordinates — a plain decimal "lat,lon" (the canonical, range-
        //    validating parser the geo pipeline shares), or any *self-evident*
        //    notation that carries an unambiguous marker: degrees-minutes-seconds
        //    with °/′/″ glyphs or N/S/E/W letters, a `geo:` URI, or a Plus Code.
        //    Handle-shaped notations (Maidenhead locators, bare space-separated
        //    decimals) are deliberately NOT auto-detected — they are accepted
        //    only via an explicit `--kind coordinates`, which normalises them.
        if crate::util::geohash::parse_coords(v).is_some()
            || crate::util::geo::coords::parse(v).is_some_and(|c| c.format.is_self_evident())
        {
            return Self::Coordinates;
        }
        // 6. ASN — "AS" + digits (case-insensitive prefix, matched without an
        // allocation; the two matched prefix bytes are each single-byte ASCII, so
        // `v[2..]` always lands on a char boundary).
        if v.len() > 2
            && v.as_bytes()[..2].eq_ignore_ascii_case(b"as")
            && v[2..].bytes().all(|b| b.is_ascii_digit())
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
        // 8. Cell tower ID: mcc-mnc-lac-cid (all-numeric, 4 hyphen segments, MCC in
        // 200-999). Checked BEFORE the phone shape because it is MORE SPECIFIC — a
        // generic dialable digit run (`is_phone_shaped`) would otherwise swallow a
        // `mcc-mnc-lac-cid` and leave this DeviceId branch dead for realistic inputs
        // (the detector's documented most-specific-first ordering).
        {
            let parts: Vec<&str> = v.split('-').collect();
            if parts.len() == 4
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
                && parts[0]
                    .parse::<u32>()
                    .is_ok_and(|mcc| (200..=999).contains(&mcc))
            {
                return Self::DeviceId;
            }
        }
        // 8b. Phone — '+' country code or a punctuated digit run, no letters.
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
        // 9d. Tracking ID — Google Analytics (UA-XXXXXXX-X / G-XXXXXXXXXX),
        //     Google Tag Manager (GTM-XXXXXXX), Google Ads (AW-XXXXXXXXX).
        //     Must be checked before the general Username fallback.
        if is_tracking_id_shaped(v) {
            return Self::TrackingId;
        }
        // 10. Free text → Organisation / Address / FullName / Username.
        if has_company_suffix(v) {
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

/// The radar sweep's sentinel target: `hse radar` / `POST /api/v1/radar` seed
/// every sweep with one of these two placeholder values because the local
/// sensor modules (`signal_radar`, `device_sensors`, `wifi_intel`, `cell_intel`,
/// `local_net`) scan the DEVICE's own surroundings and ignore the target value
/// entirely — a value is only present because `Target` requires one and the
/// sensors gate on `Coordinates`/`MacAddress` kind to dispatch. It is never a
/// real claimed location or a real device identity.
///
/// Single source of truth for both the RAW form `Target::new` is built with
/// (`radar_scan_spec` / `cli::radar::cmd_radar`) and the NORMALISED form that
/// results after `core::entity::normalise` rounds a coordinate to 6 decimal
/// places (what ends up persisted and what `AuditEntity`/`Store::radar_history`
/// compare against) — consolidating what were four independent hand-duplicated
/// copies of these literals (the CLI, the API's `radar_scan_spec`, the storage
/// layer's `radar_history` query, and its `test_support` mirror).
pub const RADAR_SENTINEL_COORD_RAW: &str = "0,0";
/// Post-normalisation form of [`RADAR_SENTINEL_COORD_RAW`] — what a persisted
/// `Coordinates` entity/target actually reads as.
pub const RADAR_SENTINEL_COORD_NORMALISED: &str = "0.000000,0.000000";
/// The MAC sentinel needs no normalisation (already lowercase, colon-separated,
/// all-zero), so raw and persisted forms are identical.
pub const RADAR_SENTINEL_MAC: &str = "00:00:00:00:00:00";

/// True if `(kind, value)` is the radar sweep's sentinel target/entity — in
/// either its raw (`Target::new` input) or normalised (persisted) form. Callers
/// that must not mistake the sentinel for a real claimed location/identity (the
/// self-audit's cross-source geo-divergence check, any future radar-aware
/// consumer) should gate on this rather than re-deriving the literal.
#[must_use]
pub fn is_radar_sentinel(kind: TargetKind, value: &str) -> bool {
    match kind {
        TargetKind::Coordinates => {
            value == RADAR_SENTINEL_COORD_RAW || value == RADAR_SENTINEL_COORD_NORMALISED
        }
        TargetKind::MacAddress => value == RADAR_SENTINEL_MAC,
        _ => false,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
}

/// Strip shell/CSV quoting and stray surrounding punctuation a user (or a pasted
/// list) commonly leaves on a target value, e.g. `"Jordan Avery",` →
/// `Jordan Avery`. Applied only at the user-input boundary ([`Target::new`])
/// so module-discovered entity values are left untouched; kind-specific
/// normalisation (`entity::normalise`) runs afterwards.
///
/// Real cause this fixes: a `full_name` scan came in as `"\"Jordan Avery\""`
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

    // Drop invisible/format characters (zero-width, bidi controls, soft hyphen,
    // word joiner, BOM) FIRST — BEFORE the quote/separator unwrap below, not after.
    // Two reasons: (1) two seeds a human reads as identical but that differ only by
    // such a char must deduplicate; (2) an invisible char sitting BETWEEN a
    // surrounding quote and the string edge (`\u{200b}"x"`, routine in rich-text /
    // chat copy-paste) makes the first/last char NOT the quote pair, so the unwrap
    // below skips it — leaving the quote ON the value (the exact leak this function
    // exists to prevent) AND breaking idempotence, because a re-sanitise of the
    // now-invisible-free value WOULD strip the quote. Stripping up front lets the
    // unwrap loop reach a true fixed point. `strip_invisible` borrows (no
    // allocation) for the common clean input.
    let stripped = crate::core::validation::strip_invisible(raw);
    let mut s = stripped.trim();
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
        // Reject only the clear homograph spoof: a value that mixes genuine
        // ASCII letters with ASCII-lookalike foreign-script letters (e.g. a
        // Cyrillic-`а` in `paypal.com`). A legitimate all-one-script non-ASCII
        // value has no ASCII letters to mix, so it is not flagged.
        if crate::core::validation::is_confusable_mixed_script(v) {
            return Err(HOMOGRAPH_REASON);
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
            TargetKind::DeviceId => {
                let parts: Vec<&str> = v.split('-').collect();
                if parts.len() != 4 {
                    return Err("DeviceId must be mcc-mnc-lac-cid (4 numeric segments)");
                }
                if !parts
                    .iter()
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
                {
                    return Err("DeviceId segments must be numeric");
                }
                let mcc: u32 = parts[0]
                    .parse()
                    .map_err(|_| "DeviceId MCC is not a number")?;
                if !(200..=999).contains(&mcc) {
                    return Err("DeviceId MCC must be in 200–999");
                }
            }
            TargetKind::TrackingId => {
                if !is_tracking_id_shaped(v) {
                    return Err("not a recognised tracking ID shape (UA-/GTM-/G-/AW-)");
                }
            }
            TargetKind::Ssid => {
                // An 802.11 SSID is at most 32 octets; otherwise free-form.
                if v.chars().count() > 32 {
                    return Err("SSID exceeds 32 characters");
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
        //
        // Domain/IpAddress: `v` is already the host string — borrow it directly
        // rather than cloning to `Option<String>` just to immediately deref back.
        // Url: host_str() borrows from the temporary `Url`, so we materialise it
        // as a String only for that uncommon branch.
        let url_host: String;
        let infra_host: Option<&str> = match self.kind {
            TargetKind::Domain | TargetKind::IpAddress => Some(v),
            TargetKind::Url => {
                url_host = url::Url::parse(v)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                    .unwrap_or_default();
                if url_host.is_empty() {
                    None
                } else {
                    Some(&url_host)
                }
            }
            _ => None,
        };
        if let Some(h) = infra_host
            && crate::util::preflight::is_infrastructure_host(h)
        {
            return Err(
                "target is configured network infrastructure (proxy / DNS resolver) — not scanned",
            );
        }
        Ok(())
    }

    /// Same rejection as [`Self::validate`], but the mixed-script-homograph
    /// case additionally names the ASCII skeleton the value normalizes to
    /// (e.g. `pаypal.com` → `paypal.com`) — the concrete, auditable detail an
    /// operator needs to see *why* a spoofed seed was refused, which
    /// `validate`'s `&'static str` return can't carry without an allocation.
    /// Every other rejection reuses `validate`'s message unchanged (zero-cost
    /// `Cow::Borrowed`). Matches on the shared `HOMOGRAPH_REASON` constant
    /// rather than a duplicated string literal, so the two can never drift.
    pub fn validate_verbose(&self) -> std::result::Result<(), std::borrow::Cow<'static, str>> {
        match self.validate() {
            Err(HOMOGRAPH_REASON) => Err(std::borrow::Cow::Owned(format!(
                "{HOMOGRAPH_REASON} — ascii skeleton: {}",
                crate::core::validation::skeleton(self.value.trim())
            ))),
            Err(msg) => Err(std::borrow::Cow::Borrowed(msg)),
            Ok(()) => Ok(()),
        }
    }
}

/// The mixed-script-homograph rejection message, single-sourced so
/// [`Target::validate`] and [`Target::validate_verbose`] can never drift.
const HOMOGRAPH_REASON: &str = "value contains a mixed-script homograph (possible spoof)";

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
    /// Modules whose result was served from the inter-scan entity cache
    /// instead of re-querying the provider. Counts as a run avoided, not
    /// as a skip: the data is fresh within the TTL.
    #[serde(default)]
    pub modules_cached: usize,
    #[serde(default)]
    pub options: ScanOptions,
}

impl Scan {
    /// The six module-accounting counts as one canonical human sentence:
    /// `"{run} run, {errored} errored, {timed_out} timed out, {skipped} skipped,
    /// {cached} cached, {deduped} deduped"`. Single-sourced so every renderer
    /// (the dossier, the debug-bundle header, any future one) surfaces the same
    /// counts in the same order and can never again disagree — the drift this
    /// prevents is exactly what once left the dossier showing only 3 of the 6.
    /// Callers prepend their own label/prefix.
    pub fn module_accounting_line(&self) -> String {
        format!(
            "{} run, {} errored, {} timed out, {} skipped, {} cached, {} deduped",
            self.modules_run,
            self.modules_errored,
            self.modules_timed_out,
            self.modules_skipped,
            self.modules_cached,
            self.modules_deduped
        )
    }

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
            modules_cached: 0,
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
    /// Per-scan options. Defaults to [`default_scan_options`] — the
    /// **comprehensive** product defaults (depth 3, expansion floor 0.20, entity
    /// cap 2500), matching `hse scan` — when omitted, so a bare
    /// `{"value": "..."}` request is as thorough as the CLI and web UI. The same
    /// values are the per-field serde defaults, so an `options` object that omits
    /// any of these fields behaves identically to omitting `options` entirely.
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

/// Marginal-yield floor for the `--auto` depth curve, expressed as *new
/// graph-advancing entities per dispatched pivot*. A round whose predicted
/// marginal yield falls below this is dominated by re-confirmation rather than
/// discovery, so `--auto` does not schedule it. Tied to the engine's own
/// runtime adaptive-termination threshold so the planned depth and the live
/// `dE/dDispatch → 0` cutoff agree by construction.
pub const MARGINAL_YIELD_FLOOR: f64 = crate::core::roi::DEFAULT_MIN_MARGINAL_YIELD;

#[cfg(test)]
mod tests;
