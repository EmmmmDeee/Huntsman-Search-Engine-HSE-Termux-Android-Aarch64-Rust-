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
    Asn,
    Coordinates,
    Address,
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
            EntityKind::Organisation
            | EntityKind::AbnAcn
            | EntityKind::MacAddress
            | EntityKind::DeviceId
            | EntityKind::Url
            | EntityKind::Credential
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
            Self::Asn => EntityKind::Asn,
            Self::Coordinates => EntityKind::Coordinates,
            Self::Address => EntityKind::Address,
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
            Self::Asn => "asn",
            Self::Coordinates => "coordinates",
            Self::Address => "address",
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
            value: value.into(),
        }
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
        if v.contains(['\n', '\r', '\0']) {
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
                let digits = v.strip_prefix("AS").unwrap_or(v);
                if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                    return Err("ASN must be digits, optionally prefixed by 'AS'");
                }
            }
            TargetKind::Phone => {
                let digits: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
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
            // Free-form text kinds: only the universal checks above apply.
            TargetKind::Username | TargetKind::FullName | TargetKind::Address => {}
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
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            modules: None,
            exclude_modules: Vec::new(),
            throttle_ms: 0,
            max_concurrent: 0,
            module_timeout_ms: None,
            min_confidence: None,
            free_only: false,
            passive_only: false,
            depth: 0,
            min_expand_confidence: default_min_expand_confidence(),
            max_entities: None,
            max_wall_time_secs: None,
        }
    }
}

fn default_min_expand_confidence() -> f64 {
    0.75
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
        assert!((o.min_expand_confidence - 0.75).abs() < 1e-9);
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
            TargetKind::Asn,
            TargetKind::Coordinates,
            TargetKind::Address,
        ] {
            let ek = tk.to_entity_kind();
            assert_eq!(TargetKind::from_entity_kind(&ek), Some(tk));
        }
    }

    #[test]
    fn unscannable_entity_kinds_return_none() {
        assert!(TargetKind::from_entity_kind(&EntityKind::Organisation).is_none());
        assert!(TargetKind::from_entity_kind(&EntityKind::MacAddress).is_none());
        assert!(TargetKind::from_entity_kind(&EntityKind::Credential).is_none());
        assert!(TargetKind::from_entity_kind(&EntityKind::Password).is_none());
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
        assert!(Target::new(TargetKind::Email, "noatsign").validate().is_err());
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
        assert!(Target::new(TargetKind::Domain, "single").validate().is_err()); // no dot
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
        assert!(
            Target::new(TargetKind::IpAddress, "::1")
                .validate()
                .is_ok()
        );
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
}
