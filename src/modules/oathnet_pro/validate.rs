//! Offline, shape-anchored validators for breach/stealer field values.
//!
//! Pure functions (no I/O, no module state) split out of the parent so the
//! extraction code stays readable. Each rejects a placeholder/sentinel or
//! malformed value, or classifies a leaked credential, before it becomes an
//! entity. Self-contained: every dependency is reached by an explicit path, so
//! the parent re-globs these validators via `use validate::*` without a
//! reciprocal `use super::*` here.

/// A syntactically valid, routable **public** IP: parses as v4/v6 and is not a
/// private/reserved/loopback range. A leaked private IP can't geolocate and is
/// noise for the `geolocation-lead` pivot, so it is dropped along with junk.
/// The definition is shared with `see_know` via `util::preflight` — re-exported
/// here so the extractors keep reaching it by bare name through `use super::*`.
pub(super) use crate::util::preflight::is_public_ip;

/// At least `n` ASCII digits — separates a real phone/number from a placeholder
/// sentinel that merely clears a raw character-length gate.
pub(super) fn has_min_digits(s: &str, n: usize) -> bool {
    s.chars().filter(char::is_ascii_digit).count() >= n
}

/// The structural email gate now lives in [`crate::util::extract::looks_like_email`]
/// — the single source shared by every breach/stealer parser. Re-exported here so
/// the extractors keep reaching it by bare name through `use super::*`.
pub(super) use crate::util::extract::looks_like_email;

/// True for OathNet's redacted-data sentinels — a free-text field whose "value"
/// is really a paywall marker, not the datum itself.
pub(super) fn is_redacted_sentinel(s: &str) -> bool {
    let u = s.to_ascii_uppercase();
    u.contains("UPGRADE_TO_SEE") || u.contains("REDACTED")
}

/// Objective, offline validation of a leaked bank-account number: normalise the
/// raw `iban` field (drop whitespace, upper-case) and defer to the single-sourced
/// [`crate::util::extract::iban_is_valid`], which pins the ISO 13616 `CCkk`
/// layout, the country's **registered length**, and the mod-97 checksum. A wrong
/// check digit, a wrong-length string for its country code, or a redacted
/// sentinel in the field all fail, so only a genuine account is emitted. (Was a
/// duplicated mod-97 implementation that — unlike the shared one — accepted any
/// mod-97-valid string of length 15..=34 regardless of the country's real IBAN
/// length.)
pub(super) fn iban_is_valid(raw: &str) -> bool {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    crate::util::extract::iban_is_valid(&s)
}

/// Identify a leaked password hash's algorithm and whether it is a **fast**
/// (unsalted, GPU-trivial) digest versus a **slow** adaptive KDF — the single
/// strongest signal for how exposed the leaked credential really is (a fast
/// MD5/SHA-1 is effectively plaintext; a bcrypt/argon2 digest is not). Pure,
/// shape-anchored classification, the same discipline the key detector applies:
/// prefixed `crypt(3)`/KDF formats by their `$id$` marker, bare digests by hex
/// length. Returns `(algorithm, fast)`, or `None` for an unrecognised shape.
///
/// Delegates to the shared [`crate::util::hashcat::identify_hash`] so every breach
/// provider (OathNet, SeekNow, DeHashed) classifies by one definition that can't
/// drift; the offline crack/salt corollaries live alongside it there.
pub(super) fn identify_password_hash(s: &str) -> Option<(&'static str, bool)> {
    crate::util::hashcat::identify_hash(s)
}
