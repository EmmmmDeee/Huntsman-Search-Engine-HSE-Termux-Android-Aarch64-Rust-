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
    IDENTITY_OVERLAP_MIN, fold_name_text, handle_names_person, identity_norm, identity_overlaps,
    is_infra_domain, is_mega_domain, is_noncentral_domain, is_other_named_person,
    is_wrong_identity_pivot, person_names_compatible, person_surname, text_names_person,
};

mod detect;
use detect::{
    has_company_suffix, is_address_shaped, is_cidr_shaped, is_domain_shaped, is_mac_shaped,
    is_phone_shaped, is_tracking_id_shaped,
};

mod scoring;

mod options;
pub(crate) use options::default_scan_options;
mod runner;
pub use options::{
    DEFAULT_MAX_ENTITIES, DEFAULT_MIN_EXPAND_CONFIDENCE, DEFAULT_SCAN_DEPTH, ExpansionStrategy,
    MAX_CONCURRENT, MAX_DEPTH, MAX_SCAN_NAME_CHARS, ScanNameError, ScanOptions,
    THROTTLE_CEILING_MS, known_option_keys, nearest_option_key, unknown_option_keys,
};
pub use runner::ScanRunner;
// Re-exported so external callers keep using `crate::core::scan::expansion_weight`
// etc. unchanged after the expansion-economics model moved to `scoring`.
pub use scoring::{
    corroboration_prior, expansion_weight, expansion_weight_for_strategy, geo_npv, optimal_depth,
    predicted_marginal_yield,
};
// Internal scoring helpers reached only by the scoring tests retained in this file.
#[cfg(test)]
use scoring::{auto_min_expand_confidence, seed_marginal_yield};

/// **Subject claims.** The tags a module sets to assert that an entity IS the
/// scan subject (`seed`, `subject`) or that a register row's name EXACTLY
/// matched it (`exact-name-match`). Every consumer reads them as statements
/// about the scan's subject, so they are one list, defined once:
///
/// * the engine's `dispatch::rescope_subject_claims` strips them from what a
///   module returned for a pivot — a module cannot tell the seed from a pivot,
///   so its claim is re-scoped to what the engine knows (REQ-SUBJECT-SCOPE-001);
/// * [`crate::core::geo_family::subject_surname`] reads the family surname off
///   them, in this order (the operator's own seed first);
/// * the GEXF export labels only an identity node carrying one of them as the
///   Diamond `victim` vertex ([`crate::core::diamond::scoped_vertex_label`]).
///
/// Order is precedence: strongest claim first.
pub(crate) const SUBJECT_CLAIM_TAGS: &[&str] = &["seed", "subject", "exact-name-match"];

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
                if !crate::util::url_util::is_absolute_http_url(v) {
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

    /// Whether the scan has stopped for good — no further work will be
    /// dispatched and no further columns will be written to its row.
    ///
    /// This is the predicate that tells a reader whether the scan record's
    /// derived columns can be trusted. The `modules_*` counters in particular
    /// are written **once**, in `Engine::finalise_scan`, so on a `Pending` or
    /// `Running` row they still hold the zeros [`Scan::new`] seeded — see
    /// [`Scan::module_accounting_line`], which uses this to say so rather than
    /// let six zeros read as "nothing ran".
    #[must_use]
    pub fn is_terminal(self) -> bool {
        match self {
            Self::Pending | Self::Running => false,
            Self::Complete | Self::Failed | Self::Aborted => true,
        }
    }
}

/// Why a scan's expansion stopped.
///
/// # Why this is persisted rather than only emitted
///
/// The engine has always known this — [`crate::core::event::EventKind`]'s
/// `ExpansionStop` carries [`StopReason::label`] onto the live event stream.
/// But the reason was never written to the scan record, so every consumer that
/// reads a *finished* scan back from the store (`hse scan`'s table output,
/// `hse export`, `hse audit`, the dossier, the HTTP API) saw only
/// [`ScanStatus::Complete`] and could not tell a scan that genuinely exhausted
/// its candidates from one that was cut off partway by a budget.
///
/// That distinction is the difference between "there is no more evidence" and
/// "we stopped looking" — the single most consequential thing an OSINT scan can
/// get wrong, because an analyst reads the first as a negative finding. The
/// entities such a scan *did* produce are all genuine; the defect is the
/// silence about what was never reached. So the fix is disclosure, matching the
/// principle [`Scan::module_accounting_line`] already states: report the
/// shortfall, never fabricate the missing part.
///
/// [`StopReason::truncated`] is the predicate that separates the two benign
/// terminations (the search space was genuinely exhausted) from the two
/// truncating ones (a budget cut the search short).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The frontier emptied — every candidate above the expansion confidence
    /// floor was pursued. Not a truncation.
    NoMoreCandidates,
    /// `--depth` rounds all ran to completion. Not a truncation: the operator
    /// asked for exactly this much expansion and got it.
    DepthExhausted,
    /// `max_entities` reached — expansion stopped with candidates still queued.
    MaxEntities(usize),
    /// `max_wall_time_secs` exceeded — expansion stopped with candidates still
    /// queued.
    MaxWallTime(u64),
    /// Operator-initiated cancellation. Reported through
    /// [`ScanStatus::Aborted`] as well; carried here so the scan record names
    /// the same reason the event stream did.
    Cancelled,
}

impl StopReason {
    /// One human sentence naming the reason, single-sourced so the live
    /// `ExpansionStop` event, the persisted scan record and every renderer
    /// cannot drift.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::NoMoreCandidates => "no more high-confidence candidates".into(),
            Self::DepthExhausted => "maximum expansion depth reached".into(),
            Self::MaxEntities(n) => format!("max_entities={n} reached"),
            Self::MaxWallTime(s) => format!("max_wall_time_secs={s} exceeded"),
            Self::Cancelled => "cancelled by operator".into(),
        }
    }

    /// Whether the expansion was cut short with work still outstanding — i.e.
    /// whether absence of evidence in this scan may be an artefact of the
    /// budget rather than a finding.
    ///
    /// [`Self::Cancelled`] is deliberately **not** truncating here: an operator
    /// cancel is already surfaced by [`ScanStatus::Aborted`], which every
    /// disclosure path keys off separately, so counting it twice would attach
    /// two different warnings to one event.
    #[must_use]
    pub fn truncated(&self) -> bool {
        matches!(self, Self::MaxEntities(_) | Self::MaxWallTime(_))
    }
}

/// Where a scan's entities came from — the fact that decides how a shortfall
/// in its stored result can be rebuilt ([`Scan::completeness_caveat`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanOrigin {
    /// Collected by the engine from a live target: a re-run collects it again.
    #[default]
    Live,
    /// Persisted from a batch the operator already held — `hse import`,
    /// `hse ingest --auto-scan`, `hse investigate --auto-scan` or a web upload,
    /// every one written by `app::persist::ImportScanRow`. A re-run of it is a
    /// live scan of its label, which rebuilds nothing it stored.
    Import,
}

impl ScanOrigin {
    /// `true` for [`Self::Live`] — the default, omitted from the stored JSON
    /// so a live scan's row and wire form are unchanged.
    #[must_use]
    pub fn is_live(&self) -> bool {
        *self == Self::Live
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
    /// Module dispatches this scan that returned a result, an error or a
    /// timeout — that obtained an answer about their target, or failed trying.
    /// Disjoint from [`modules_skipped`](Self::modules_skipped): a module that
    /// dispatched and then opted out in-band (no key, not applicable) is a
    /// skip, not a run — including one that contacted a provider to learn it
    /// could not answer (hackertarget's "error invalid host", whois's IANA
    /// bootstrap), since it obtained no answer about the target
    /// (REQ-ENGINE-005). Includes `modules_errored` and `modules_timed_out`.
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
    /// Why this scan's expansion stopped, once it has. `None` on a scan that
    /// has not finished expanding, on a depth-0 scan (which runs no expansion),
    /// and on any scan record written before this field existed — hence
    /// `#[serde(default)]`: `Scan` round-trips through the `scans.data_json`
    /// column, so an older row deserialises with `None` and every consumer
    /// treats it exactly as it did before, with no schema migration.
    #[serde(default)]
    pub stop_reason: Option<StopReason>,
    /// The process running this scan, stamped when the scan is created and
    /// again when the engine starts it. Read back from the stored row, and
    /// never serialised anywhere else: `Store::upsert_scan` writes it into
    /// `data_json` itself, so no API response or export carries a process
    /// identity. See [`Scan::is_interrupted`].
    #[serde(default, skip_serializing)]
    pub runner: Option<ScanRunner>,
    /// Where this scan's entities came from. `#[serde(default)]` for the same
    /// reason as [`Self::stop_reason`]: a row written before the field existed
    /// reads [`ScanOrigin::Live`], the advice every row carried until then.
    #[serde(default, skip_serializing_if = "ScanOrigin::is_live")]
    pub origin: ScanOrigin,
}

impl Scan {
    /// Whether this `pending` or `running` scan has lost the process running
    /// it (REQ-SCANSTATUS-038). Nothing will finish it: its row reads as the
    /// dead process left it, and is never rewritten.
    ///
    /// `registry` is the calling process's own in-flight registry, when it
    /// has one (`hse serve` does). It is exact for the scans this process
    /// runs: each is registered before its row is written and stays
    /// registered until the engine's last write. A scan another process
    /// runs is interrupted when that process is gone ([`ScanRunner::is_alive`]).
    /// A caller with no registry (an export) takes a scan this process runs
    /// as live. A row with no runner predates this field, so only a registry
    /// can vouch for it.
    #[must_use]
    pub fn is_interrupted(&self, registry: Option<&std::collections::HashSet<String>>) -> bool {
        if !matches!(self.status, ScanStatus::Pending | ScanStatus::Running) {
            return false;
        }
        if registry.is_some_and(|r| r.contains(&self.id)) {
            return false;
        }
        match &self.runner {
            Some(r) if r.is_this_process() => registry.is_some(),
            Some(r) => !r.is_alive(),
            None => true,
        }
    }

    /// The six module-accounting counts as one canonical human sentence:
    /// `"{run} run, {errored} errored, {timed_out} timed out, {skipped} skipped,
    /// {cached} cached, {deduped} deduped"`. Single-sourced so every renderer
    /// (the dossier, the debug-bundle header, any future one) surfaces the same
    /// counts in the same order and can never again disagree — the drift this
    /// prevents is exactly what once left the dossier showing only 3 of the 6.
    /// Callers prepend their own label/prefix.
    ///
    /// # Non-terminal scans
    ///
    /// All six columns are written in exactly one place — `finalise_scan`, at
    /// the end of the run. The row inserted when the scan goes `Running`
    /// carries the zeros [`Scan::new`] seeded, and nothing updates them in
    /// between. So a dossier or debug bundle exported **mid-scan** read
    /// `0 run, 0 errored, 0 timed out, 0 skipped, 0 cached, 0 deduped` for a
    /// scan whose own event stream showed 60 modules done, 9 errored and 11
    /// skipped — six zeros that say "nothing ran" when plenty had.
    ///
    /// The counters are still genuinely unavailable before finalise (there is
    /// no cheaper truth to print — they live in the engine's in-memory
    /// `ModuleStats` until then), so the fix is disclosure, not fabrication:
    /// on a non-terminal scan the sentence states that the columns are not yet
    /// written. Renderers with the event stream to hand additionally show the
    /// live observed tally — see
    /// [`ModuleEventTally`](crate::core::event::ModuleEventTally).
    #[must_use]
    pub fn module_accounting_line(&self) -> String {
        let counts = format!(
            "{} run, {} errored, {} timed out, {} skipped, {} cached, {} deduped",
            self.modules_run,
            self.modules_errored,
            self.modules_timed_out,
            self.modules_skipped,
            self.modules_cached,
            self.modules_deduped
        );
        if self.status.is_terminal() {
            counts
        } else {
            format!(
                "{counts}  (NOT YET FINAL — this scan is {}; the counters are written once, at \
                 finalise, so they read as zeros until then)",
                self.status.as_str()
            )
        }
    }

    /// Whether this scan finished (`Complete` or `Aborted`) but its finalise
    /// did not store or compute everything: [`Self::error`] on such a row is
    /// written only by the finalise's [`FinaliseTally`]. The one reading both
    /// completion announcements carry — the `scan_complete` event's
    /// `finalise_incomplete` and the operator webhook's — so neither can call
    /// whole a scan its exports read partial (REQ-SCANSTATUS-015): a
    /// `Complete` one reads "partial, finalise-incomplete", an `Aborted` one
    /// "partial, aborted", and [`Self::completeness_caveat`] names the
    /// shortfall for both (REQ-SCANSTATUS-022). `false` on a `Failed` scan,
    /// whose `error` is its failure, and on a scan not yet finished.
    #[must_use]
    pub fn finalise_incomplete(&self) -> bool {
        matches!(self.status, ScanStatus::Complete | ScanStatus::Aborted) && self.error.is_some()
    }

    /// The operator-facing caveat this scan needs, or `None` when its results
    /// stand on their own as a complete answer.
    ///
    /// The single source for "how much of this scan should you trust", so the
    /// offline read paths (`hse export`, `audit`, `gap`, `diff`, `benchmark`),
    /// `hse scan`'s own output and the dossier cannot drift apart on it.
    /// `subject` names the scan the way the caller refers to it ("scan a1b2c3",
    /// "scan latest", "this scan") and opens the sentence.
    ///
    /// The four status arms reproduce the framing established when this
    /// distinction was first drawn, and are pinned by tests in
    /// `crate::app::runtime`: `Aborted` is deliberately NOT bucketed with
    /// `Failed`/`Pending`/`Running`, because those three can still change (a
    /// crash-recovered partial write, a scan not yet started, one actively
    /// being written) whereas a completed abort's data is as final as a
    /// `Complete` scan's — just shorter.
    ///
    /// The `Complete` arm is the one this gained when [`StopReason`] became
    /// part of the scan record: a scan whose expansion was cut off by
    /// `max_entities` / `max_wall_time_secs` reaches `Complete` like any other,
    /// but its silence about what it never reached is not a finding. Returns
    /// `None` for a benign stop reason and for `stop_reason: None` — including
    /// every row written before the field existed — so no warning is ever
    /// retro-fitted onto a scan on no evidence.
    ///
    /// The same arm also reads [`Scan::error`]: on a `Complete` scan it is
    /// written only by the finalise's [`FinaliseTally`] — writes the store
    /// refused, or a correlation pass that failed outright. That scan ran to
    /// completion, but its stored result is not what it produced, so it is
    /// caveated ahead of any truncation, in the order the export classifier
    /// (`app::export`'s `partial_export_reason`) uses. The `Aborted` arm reads
    /// it too: an abort's finalise still runs and still records its
    /// shortfall, which every live surface announced as partial, so the
    /// caveat names it rather than calling the scan's data final. The remedy
    /// each names follows the scan's origin and what failed (see
    /// `finalise_shortfall`).
    #[must_use]
    pub fn completeness_caveat(&self, subject: &str) -> Option<String> {
        match self.status {
            ScanStatus::Complete => {
                if let Some(err) = self.error.as_deref() {
                    return Some(format!(
                        "{subject} finished, but {}",
                        self.finalise_shortfall(err)
                    ));
                }
                let r = self.stop_reason?;
                r.truncated().then(|| {
                    format!(
                        "{subject} finished, but its expansion was TRUNCATED by a budget \
                         ({}) — it stopped with candidates still queued, so a result missing \
                         from this scan is not evidence that it does not exist; re-run with a \
                         higher --max-entities / --max-wall-time-secs to search further",
                        r.label()
                    )
                })
            }
            // An abort's finalise still runs, and its tally still writes
            // `error`: the same shortfall every live surface announced
            // (`finalise_incomplete`) is named here too, rather than calling
            // the scan's data final over it (REQ-SCANSTATUS-022).
            ScanStatus::Aborted => Some(match self.error.as_deref() {
                Some(err) => format!(
                    "{subject} was stopped early by the operator (aborted), and {}; no further \
                     data will arrive for this scan",
                    self.finalise_shortfall(err)
                ),
                None => format!(
                    "{subject} was stopped early by the operator (aborted) — entities from \
                     modules that completed before the stop are final; no further data will \
                     arrive for this scan"
                ),
            }),
            other => Some(format!(
                "{subject} is {status}, not complete — recovering its checkpointed \
                 (partial) entities; results may be incomplete",
                status = other.as_str()
            )),
        }
    }

    /// The clause [`Self::completeness_caveat`] gives a finished scan whose
    /// finalise did not complete: what `err` (its [`FinaliseTally::message`])
    /// means for every view of it, and the remedy that rebuilds it.
    ///
    /// What a refused write leaves is not always an absence: a live scan's
    /// checkpoints store its entities before the finalise, so an entity whose
    /// finalise write the store refused is still listed, as the checkpoint
    /// stored it, and a refused address-fold detach leaves the folded
    /// spelling listed beside its survivor. The clause says so rather than
    /// call every shortfall absent (REQ-SCANSTATUS-028).
    ///
    /// The remedy follows the scan's origin AND what failed. No shortfall on an
    /// import is rebuilt by a re-run: `/scans/{id}/rerun` starts a LIVE scan of
    /// the import's label (an email string read as a full name), which neither
    /// stores the relations the store refused nor re-correlates the imported
    /// entities (REQ-SCANSTATUS-017/020). Re-importing rebuilds a refused
    /// write, a pass that failed on a store read, or a pass a time budget cut
    /// short. A size skip recurs on the same data (and batches within the cap
    /// are each enriched on their own, so links between batches are never
    /// derived). A correlation pass that panicked recurs on the same data too
    /// (REQ-SCANSTATUS-021) — but only when it read the same data: the
    /// correlator reads the scan's stored entities AND relations, and every
    /// other clause an import can record beside a panic (a refused relation
    /// write, a derivation its budget cut) means the relations it read were
    /// incomplete. Then a re-import that stores the whole graph runs the pass
    /// over different data, which may finish or panic again, so the caveat
    /// does not claim either (REQ-SCANSTATUS-027). The skip clause identifies
    /// an import written before `origin` existed.
    fn finalise_shortfall(&self, err: &str) -> String {
        let import = self.origin == ScanOrigin::Import;
        let remedy = if FinaliseTally::records_import_enrichment_skip(err) {
            "re-running cannot rebuild it (a re-run is a live scan of the import's \
             label, and re-importing the same data hits the same cap) — importing \
             the data in smaller batches, each within the cap, enriches each batch \
             on its own; links between entities in different batches are not derived"
        } else if import && FinaliseTally::records_correlation_panic(err) {
            if FinaliseTally::records_only_correlation_panic(err) {
                "neither re-running nor re-importing can rebuild it: a re-run is a live scan \
                 of the import's label, and its correlation pass panicked on the imported \
                 data with its whole graph derived and stored, so a re-import of the same \
                 data runs the same pass over the same data and meets the same panic, unless \
                 a time budget stops it first, which leaves the correlations incomplete too"
            } else {
                "re-running cannot rebuild it (a re-run is a live scan of the import's label) \
                 — re-importing the data rebuilds the rest of it, and may or may not rebuild \
                 its correlations: its correlation pass panicked over the incomplete graph \
                 this import stored, so a re-import that stores the whole graph runs the pass \
                 over different data, which may finish or may panic again"
            }
        } else if import {
            "re-running cannot rebuild it (a re-run is a live scan of the import's \
             label) — re-import the data to rebuild it"
        } else {
            "re-run the scan to rebuild it"
        };
        format!(
            "its finalise did not complete ({err}) — what it did not store or compute is \
             absent from every view and export of it, or there only as the scan stored it \
             before its finalise (an entity whose finalise write was refused lacks the \
             finalise's enrichment; an address whose fold was refused is listed twice), so \
             that absence is not a finding; {remedy}"
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
            stop_reason: None,
            runner: Some(ScanRunner::current()),
            origin: ScanOrigin::Live,
        }
    }

    pub fn with_options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }
}

/// One kind of write a scan's finalise makes to the store, as counted by
/// [`FinaliseTally`]. Declaration order is the order the live finalise makes
/// them in, and the order [`FinaliseTally::message`] lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinaliseWrite {
    /// Detaching the observations of address spellings folded into their
    /// locality survivor. A refused detach leaves the folded spelling
    /// observed by the scan, so every export repeats the address the fold
    /// removed.
    AddressFolds,
    /// The scan's entities (the live engine's batch, or its per-entity
    /// fallback).
    Entities,
    /// The typed relation edges (the attribution graph).
    Relations,
    /// The correlator's findings, including the cross-scan AU-065/AU-066 ones.
    Correlations,
    /// The re-persist of identities a confirmed link strengthened
    /// (multipath / cross-scan corroboration). A refused write leaves the
    /// stored entity without the boost the scan computed.
    CorroborationBoosts,
}

impl FinaliseWrite {
    /// Every kind, in declaration order.
    const ALL: [Self; 5] = [
        Self::AddressFolds,
        Self::Entities,
        Self::Relations,
        Self::Correlations,
        Self::CorroborationBoosts,
    ];

    /// The plural noun [`FinaliseTally::message`] prints.
    fn label(self) -> &'static str {
        match self {
            Self::AddressFolds => "address folds",
            Self::Entities => "entities",
            Self::Relations => "relations",
            Self::Correlations => "correlations",
            Self::CorroborationBoosts => "corroboration boosts",
        }
    }

    /// Slot in [`FinaliseTally`]'s counters.
    fn index(self) -> usize {
        match self {
            Self::AddressFolds => 0,
            Self::Entities => 1,
            Self::Relations => 2,
            Self::Correlations => 3,
            Self::CorroborationBoosts => 4,
        }
    }
}

/// A finalise pass that COMPUTES part of what the scan's exports read, as
/// opposed to writing it — so a failure of the pass itself (a store read that
/// errored, a panic, a time budget that stopped it) leaves nothing to count as
/// a refused write, only a result that was never produced. Declaration order is the order the live finalise
/// runs them in, and the order [`FinaliseTally::message`] lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalisePass {
    /// An import's relation derivation and correlation, taken together: the
    /// import paths (`hse import` / `ingest --auto-scan` and the web upload)
    /// do not run them at all over a batch larger than their enrichment cap
    /// (`app::persist::PERSIST_ENRICH_MAX_ENTITIES`). A skip on purpose still
    /// leaves the scan's relations and correlations never produced, so its
    /// exports must not read it whole (REQ-SCANSTATUS-010).
    ImportEnrichment,
    /// The relation derivation (`core::relation::derive_all_within`), when its
    /// time budget stopped the pass chain before its last pass: every edge a
    /// later pass would have built is absent, and the correlator reads the
    /// thinner graph (REQ-SCANSTATUS-024).
    RelationDerivation,
    /// The authoritative correlator over the persisted scan.
    Correlation,
    /// The cross-scan route learning that fires AU-065 / AU-066.
    CrossScanRoutes,
    /// The multipath / cross-scan corroboration boosts.
    CorroborationBoosts,
}

impl FinalisePass {
    /// Every pass, in declaration order.
    const ALL: [Self; 5] = [
        Self::ImportEnrichment,
        Self::RelationDerivation,
        Self::Correlation,
        Self::CrossScanRoutes,
        Self::CorroborationBoosts,
    ];

    /// The name [`FinaliseTally::message`] prints.
    fn label(self) -> &'static str {
        match self {
            Self::ImportEnrichment => "relation and correlation pass",
            Self::RelationDerivation => "relation derivation",
            Self::Correlation => "correlation pass",
            Self::CrossScanRoutes => "cross-scan route pass",
            Self::CorroborationBoosts => "corroboration boost pass",
        }
    }

    /// Slot in [`FinaliseTally`]'s pass failures.
    fn index(self) -> usize {
        match self {
            Self::ImportEnrichment => 0,
            Self::RelationDerivation => 1,
            Self::Correlation => 2,
            Self::CrossScanRoutes => 3,
            Self::CorroborationBoosts => 4,
        }
    }
}

/// The reason the engine's `guarded_correlation_pass` gives for a correlation
/// pass that panicked. Fixed text, never the payload: a panic message can
/// carry a pointer, a thread id or other run-specific detail, and this reason
/// is written into [`Scan::error`], which a debug bundle must reproduce byte
/// for byte. The payload is still logged. Defined here, beside its reader
/// ([`FinaliseTally::records_correlation_panic`]).
pub(crate) const CORRELATION_PASS_PANICKED: &str = "panicked";

/// The reason [`FinaliseTally::import_enrichment_skipped`] opens with — the
/// word [`FinaliseTally::records_import_enrichment_skip`] reads it back by.
const IMPORT_ENRICHMENT_SKIP_REASON: &str = "skipped";

/// Everything a finalise did not complete: how many of each [`FinaliseWrite`]
/// it attempted and how many the store refused (with the first refusal's
/// error), and which [`FinalisePass`] failed outright — the single
/// authority for what a scan records in [`Scan::error`] when it runs to the
/// end but its stored result is not what it produced.
///
/// # Why this exists
///
/// Every export decides whether a scan is whole from the stored record alone
/// (`app::export`'s `partial_export_reason`, and [`Scan::completeness_caveat`]
/// for the read paths). The three paths that finalise a scan — the live
/// engine, `hse import` / `hse ingest --auto-scan` and the web upload — each
/// treated a relation or correlation that failed to persist as a log line, or
/// counted successes with `.is_ok()` and dropped the error. A pass that failed
/// outright — the correlator on a store read error or a panicking rule, the
/// cross-scan route learning or the boost pass on a failed read — produced
/// nothing and recorded nothing, and the live engine's address-fold detach and
/// corroboration-boost re-persist were logged only. The scan was
/// then written `Complete` with `error: None`, and every export of it read
/// "complete" while the graph or the findings were missing, a folded address
/// was repeated, or a computed boost was absent. Only the live engine's entity
/// shortfall reached `error`, and even that was not read by the export
/// classifier. Each of those sites now counts into one of these, and the
/// terminal write stores [`Self::message`].
///
/// # Determinism
///
/// The message is a pure function of the counts, the first error and the pass
/// failures' reasons — no timestamp, no map iteration order, and no panic
/// payload (see [`Self::pass_failed`]) — so a debug bundle that
/// prints it stays byte-identical across exports. "First" is the first failure
/// in the order the finalise makes its writes, each in the order its pass
/// writes them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FinaliseTally {
    /// `(failed, attempted)` per write kind, indexed by [`FinaliseWrite::index`].
    counts: [(usize, usize); 5],
    /// The first store error recorded, in finalise order.
    first_err: Option<String>,
    /// Why each [`FinalisePass`] produced nothing, when it failed outright,
    /// indexed by [`FinalisePass::index`].
    passes: [Option<String>; 5],
}

impl FinaliseTally {
    /// Record a batch of `attempted` writes of `kind`, `failed` of which did
    /// not persist; `first_err` is the first of those failures' errors. A later
    /// call never replaces an earlier error.
    pub fn add(
        &mut self,
        kind: FinaliseWrite,
        attempted: usize,
        failed: usize,
        first_err: Option<String>,
    ) {
        let slot = &mut self.counts[kind.index()];
        slot.0 += failed;
        slot.1 += attempted;
        if failed > 0 && self.first_err.is_none() {
            self.first_err = first_err;
        }
    }

    /// Record one write of `kind`, returning whether it persisted — so a
    /// persist site reads `if tally.record(kind, store.upsert_x(..)) { .. }`
    /// in place of the `.is_ok()` that used to drop the error.
    pub fn record<T, E: std::fmt::Display>(
        &mut self,
        kind: FinaliseWrite,
        outcome: std::result::Result<T, E>,
    ) -> bool {
        match outcome {
            Ok(_) => {
                self.add(kind, 1, 0, None);
                true
            }
            Err(e) => {
                self.add(kind, 1, 1, Some(e.to_string()));
                false
            }
        }
    }

    /// Record that `pass` produced nothing (or only part of its result)
    /// because it failed outright — a store read error or a panic — rather
    /// than because there was nothing to find. `reason` must be deterministic:
    /// the error's text, or a fixed word for a panic, never the panic payload
    /// (which can carry a pointer, a thread id or other run-specific text).
    /// The first reason per pass is kept.
    pub fn pass_failed(&mut self, pass: FinalisePass, reason: impl Into<String>) {
        let slot = &mut self.passes[pass.index()];
        if slot.is_none() {
            *slot = Some(reason.into());
        }
    }

    /// Record that an import skipped its relation and correlation pass
    /// ([`FinalisePass::ImportEnrichment`]) because its `entity_count`
    /// entities exceed the import enrichment cap `cap`. The one writer of
    /// that clause, beside its one reader
    /// ([`Self::records_import_enrichment_skip`]), so the scan's caveat can
    /// name the remedy a size skip needs.
    pub fn import_enrichment_skipped(&mut self, entity_count: usize, cap: usize) {
        self.pass_failed(
            FinalisePass::ImportEnrichment,
            format!(
                "{IMPORT_ENRICHMENT_SKIP_REASON} — {entity_count} entities exceed the \
                 {cap}-entity import enrichment cap"
            ),
        );
    }

    /// Record that the relation derivation's time budget stopped its pass
    /// chain after `last_pass` ([`FinalisePass::RelationDerivation`]): the
    /// scan keeps the edges built so far, but not the ones a later pass would
    /// have built. Fixed words around the pass's name, so the clause is a
    /// pure function of how far derivation got.
    pub fn derivation_cut(&mut self, last_pass: &str) {
        self.pass_failed(
            FinalisePass::RelationDerivation,
            format!("stopped at its time budget after the {last_pass} pass"),
        );
    }

    /// Record that the correlator's time budget stopped it after `ran` of its
    /// `total` rules ([`FinalisePass::Correlation`]): the scan keeps the
    /// firings of the rules that ran, but a finding a later rule would have
    /// made is absent for a reason other than the data (REQ-SCANSTATUS-026).
    /// Fixed words around the counts, so the clause is a pure function of how
    /// far the pass got — and never the panic clause, so
    /// [`Self::records_correlation_panic`] leaves it to the remedy of a pass
    /// a re-run or a re-import can finish.
    pub fn correlation_cut(&mut self, ran: usize, total: usize) {
        self.pass_failed(
            FinalisePass::Correlation,
            format!("stopped at its time budget after {ran} of its {total} rules"),
        );
    }

    /// Whether a stored [`Scan::error`] (a [`Self::message`]) records an
    /// import's relation and correlation pass skipped for size
    /// ([`Self::import_enrichment_skipped`]).
    #[must_use]
    pub fn records_import_enrichment_skip(error: &str) -> bool {
        let clause = format!(
            "{} failed: {IMPORT_ENRICHMENT_SKIP_REASON} — ",
            FinalisePass::ImportEnrichment.label()
        );
        error.split("; ").any(|c| c.starts_with(&clause))
    }

    /// The clause [`Self::message`] writes for a correlation pass that
    /// panicked ([`CORRELATION_PASS_PANICKED`]).
    fn correlation_panic_clause() -> String {
        format!(
            "{} failed: {CORRELATION_PASS_PANICKED}",
            FinalisePass::Correlation.label()
        )
    }

    /// Whether a stored [`Scan::error`] (a [`Self::message`]) records a
    /// correlation pass that panicked — a failure a re-run of the same
    /// deterministic pass over the same data repeats, unlike a store read that
    /// errored.
    #[must_use]
    pub fn records_correlation_panic(error: &str) -> bool {
        let clause = Self::correlation_panic_clause();
        error.split("; ").any(|c| c == clause)
    }

    /// Whether a stored [`Scan::error`] records a correlation pass that
    /// panicked and nothing else.
    #[must_use]
    pub fn records_only_correlation_panic(error: &str) -> bool {
        error == Self::correlation_panic_clause()
    }

    /// Why `pass` failed, if it did.
    #[must_use]
    pub fn pass_failure(&self, pass: FinalisePass) -> Option<&str> {
        self.passes[pass.index()].as_deref()
    }

    /// How many writes of `kind` failed.
    #[must_use]
    pub fn failed(&self, kind: FinaliseWrite) -> usize {
        self.counts[kind.index()].0
    }

    /// How many writes of `kind` were attempted.
    #[must_use]
    pub fn attempted(&self, kind: FinaliseWrite) -> usize {
        self.counts[kind.index()].1
    }

    /// How many writes of `kind` persisted — the count a caller's summary
    /// reports, so it can never disagree with the shortfall beside it.
    #[must_use]
    pub fn persisted(&self, kind: FinaliseWrite) -> usize {
        self.attempted(kind) - self.failed(kind)
    }

    /// The deterministic [`Scan::error`] text, or `None` when the finalise
    /// completed. Clauses, each present only when it applies, joined by
    /// `"; "`:
    ///
    /// * `"2/40 relations, 1/9 correlations failed to persist: <first error>"`
    ///   — only the kinds that lost a write, in finalise order. For an
    ///   entity-only shortfall this is word for word the message the live
    ///   engine wrote before the tally existed;
    /// * then one `"<pass> failed: <reason>"` per failed [`FinalisePass`], in
    ///   finalise order (`"correlation pass failed: panicked"`).
    #[must_use]
    pub fn message(&self) -> Option<String> {
        let parts: Vec<String> = FinaliseWrite::ALL
            .iter()
            .filter(|k| self.failed(**k) > 0)
            .map(|k| format!("{}/{} {}", self.failed(*k), self.attempted(*k), k.label()))
            .collect();
        let mut clauses: Vec<String> = Vec::with_capacity(1 + FinalisePass::ALL.len());
        if !parts.is_empty() {
            clauses.push(format!(
                "{} failed to persist: {}",
                parts.join(", "),
                self.first_err.as_deref().unwrap_or("unknown")
            ));
        }
        for pass in FinalisePass::ALL {
            if let Some(reason) = self.pass_failure(pass) {
                clauses.push(format!("{} failed: {reason}", pass.label()));
            }
        }
        (!clauses.is_empty()).then(|| clauses.join("; "))
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
    /// **comprehensive** product defaults (depth `DEFAULT_SCAN_DEPTH`, expansion floor 0.20, entity
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
