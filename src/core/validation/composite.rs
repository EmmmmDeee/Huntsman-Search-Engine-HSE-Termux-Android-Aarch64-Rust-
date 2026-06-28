use std::net::IpAddr;

use super::{
    coordinates::validate_coordinates, domain::validate_domain_shape, email::validate_email_syntax,
    ip::is_bogus_ip, phone::validate_phone_e164, report::ValidationReport,
};

/// Apply every validator that is relevant to the given entity-kind
/// string and return the first failure (or `ok` if all pass).
///
/// The `kind` strings are the canonical snake_case identifiers a
/// [`crate::core::scan::TargetKind`] serialises to (its `canonical_str`):
/// `phone`, `email`, `domain`, `coordinates`, `ip_address`, `cidr`,
/// `mac_address`, `abn_acn`, `crypto_address`, `url`. Each of these has a
/// clear, cheap validity shape, and the checks here mirror exactly the
/// per-kind shape checks in [`crate::core::scan::Target::validate`] so the two
/// validation surfaces — entity-composite admission and API-boundary target
/// validation — cannot diverge on what a malformed value of that kind looks
/// like (a bogus IP/MAC/crypto/ABN is rejected by both).
///
/// Free-form kinds (`username`, `full_name`, `address`, `organisation`,
/// `api_key`, `ssid`, `asn`, `device_id`, `tracking_id`) and any unrecognised
/// kind string have no cheap structural shape to enforce here, so they return
/// [`ValidationReport::ok`]: callers wanting the stricter, kind-specific
/// admission gate for those should call the relevant validator directly.
pub fn validate_for_kind(kind: &str, value: &str) -> ValidationReport {
    match kind {
        "phone" => validate_phone_e164(value),
        "email" => validate_email_syntax(value),
        "domain" => validate_domain_shape(value),
        "coordinates" => validate_coordinates_str(value),
        "ip_address" => validate_ip_address(value),
        "cidr" => validate_cidr(value),
        "mac_address" => validate_mac_address(value),
        "abn_acn" => validate_abn_acn(value),
        "crypto_address" => validate_crypto_address(value),
        "url" => validate_url(value),
        _ => ValidationReport::ok(),
    }
}

/// Parse a `"lat,lon"` string and run the shared coordinate-bounds validator.
///
/// Parsing is explicit so a non-numeric component yields a distinct
/// `coord.parse` failure naming *which* component is at fault — mirroring
/// [`crate::core::scan::Target::validate`]'s separate "lat is not a number" /
/// "lon is not a number" messages — rather than feeding `NaN` to
/// [`validate_coordinates`] and surfacing a misleading "outside [-90, 90]".
fn validate_coordinates_str(value: &str) -> ValidationReport {
    let Some((lat_s, lon_s)) = value.split_once(',') else {
        return ValidationReport::fail("coord.shape", "expected 'lat,lon'");
    };
    let Ok(lat) = lat_s.trim().parse::<f64>() else {
        return ValidationReport::fail("coord.parse", "lat is not a number");
    };
    let Ok(lon) = lon_s.trim().parse::<f64>() else {
        return ValidationReport::fail("coord.parse", "lon is not a number");
    };
    validate_coordinates(lat, lon)
}

/// Reject a value that does not parse as an IPv4/IPv6 address, or that parses to
/// a documentation/reserved range no external source can resolve (the same
/// [`is_bogus_ip`] gate the entity-admission path uses).
fn validate_ip_address(value: &str) -> ValidationReport {
    if value.parse::<IpAddr>().is_err() {
        return ValidationReport::fail("ip.parse", "not a valid IPv4 or IPv6 address");
    }
    if is_bogus_ip(value) {
        return ValidationReport::fail(
            "ip.bogus",
            "documentation/reserved address (RFC5737/2544/etc.) — not a real host",
        );
    }
    ValidationReport::ok()
}

/// Reject a value that is not `IP/prefix` with a parseable address and a prefix
/// within the family width (≤32 for IPv4, ≤128 for IPv6). Same shape check as
/// [`crate::core::scan::Target::validate`]'s `Cidr` arm.
fn validate_cidr(value: &str) -> ValidationReport {
    let Some((ip, prefix)) = value.split_once('/') else {
        return ValidationReport::fail("cidr.shape", "expected 'IP/prefix' (e.g. 192.0.2.0/24)");
    };
    let Ok(addr) = ip.trim().parse::<IpAddr>() else {
        return ValidationReport::fail("cidr.parse", "network part is not a valid IP address");
    };
    let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
    match prefix.trim().parse::<u8>() {
        Ok(p) if p <= max => ValidationReport::ok(),
        _ => ValidationReport::fail(
            "cidr.prefix",
            "prefix length out of range for address family",
        ),
    }
}

/// Reject a value that is not six hex octets, with or without `:` / `-` / `.`
/// separators. Same digit accounting as
/// [`crate::core::scan::Target::validate`]'s `MacAddress` arm.
fn validate_mac_address(value: &str) -> ValidationReport {
    let hex: String = value
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return ValidationReport::fail(
            "mac.shape",
            "MAC address must be 6 hex octets (e.g. AA:BB:CC:DD:EE:FF)",
        );
    }
    ValidationReport::ok()
}

/// Reject a value whose digit count is neither 9 (ACN) nor 11 (ABN). Mirrors
/// [`crate::core::scan::Target::validate`]'s `AbnAcn` digit-count dispatch and
/// additionally verifies the registry checksum so a same-length phone number
/// can't masquerade as a valid ABN/ACN.
fn validate_abn_acn(value: &str) -> ValidationReport {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    match digits {
        11 => {
            if crate::util::abn::is_valid_abn(value) {
                ValidationReport::ok()
            } else {
                ValidationReport::fail("abn.checksum", "ABN fails the registry checksum")
            }
        }
        9 => {
            if crate::util::abn::is_valid_acn(value) {
                ValidationReport::ok()
            } else {
                ValidationReport::fail("acn.checksum", "ACN fails the registry checksum")
            }
        }
        _ => ValidationReport::fail(
            "abn.shape",
            "ABN/ACN must be 9 digits (ACN) or 11 digits (ABN)",
        ),
    }
}

/// Reject a value that does not classify as any recognised cryptocurrency
/// address shape, using the same [`crate::core::crypto::classify_crypto_address`]
/// classifier as [`crate::core::scan::Target::validate`]'s `CryptoAddress` arm.
fn validate_crypto_address(value: &str) -> ValidationReport {
    if crate::core::crypto::classify_crypto_address(value).is_some() {
        ValidationReport::ok()
    } else {
        ValidationReport::fail(
            "crypto.shape",
            "not a recognised cryptocurrency address shape",
        )
    }
}

/// Reject a value that is not an absolute `http`/`https` URL of plausible
/// length. Same prefix + minimum-length check as
/// [`crate::core::scan::Target::validate`]'s `Url` arm.
fn validate_url(value: &str) -> ValidationReport {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return ValidationReport::fail("url.scheme", "URL must start with http:// or https://");
    }
    if value.len() < 10 {
        return ValidationReport::fail("url.short", "URL too short");
    }
    ValidationReport::ok()
}
