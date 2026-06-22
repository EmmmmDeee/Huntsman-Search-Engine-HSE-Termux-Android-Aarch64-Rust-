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

/// ISO 7064 mod-97-10 IBAN validation. Strip whitespace, confirm the `CCkk……`
/// layout, move the first four characters to the end, map letters `A–Z → 10–35`,
/// and check the running remainder mod 97 equals 1. Objective, offline
/// validation of a leaked bank-account number: a wrong check digit — or a
/// redacted sentinel in the `iban` field — fails, so only a genuine account is
/// emitted.
pub(super) fn iban_is_valid(raw: &str) -> bool {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let b = s.as_bytes();
    if !(b[0].is_ascii_uppercase()
        && b[1].is_ascii_uppercase()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit())
    {
        return false;
    }
    // Rearranged string = s[4..] followed by s[..4]; fold its digit value mod 97.
    let mut remainder: u32 = 0;
    for c in s[4..].chars().chain(s[..4].chars()) {
        let val = if c.is_ascii_digit() {
            u32::from(c) - u32::from('0')
        } else if c.is_ascii_uppercase() {
            u32::from(c) - u32::from('A') + 10
        } else {
            return false;
        };
        remainder = if val >= 10 {
            (remainder * 100 + val) % 97
        } else {
            (remainder * 10 + val) % 97
        };
    }
    remainder == 1
}

/// Identify a leaked password hash's algorithm and whether it is a **fast**
/// (unsalted, GPU-trivial) digest versus a **slow** adaptive KDF — the single
/// strongest signal for how exposed the leaked credential really is (a fast
/// MD5/SHA-1 is effectively plaintext; a bcrypt/argon2 digest is not). Pure,
/// shape-anchored classification, the same discipline the key detector applies:
/// prefixed `crypt(3)`/KDF formats by their `$id$` marker, bare digests by hex
/// length. Returns `(algorithm, fast)`, or `None` for an unrecognised shape.
pub(super) fn identify_password_hash(s: &str) -> Option<(&'static str, bool)> {
    let h = s.trim();
    // Adaptive / salted KDF + crypt(3) formats — slow to crack by design.
    for (prefix, algo) in [
        ("$2a$", "bcrypt"),
        ("$2b$", "bcrypt"),
        ("$2y$", "bcrypt"),
        ("$2x$", "bcrypt"),
        ("$argon2", "argon2"),
        ("$6$", "sha512crypt"),
        ("$5$", "sha256crypt"),
        ("$1$", "md5crypt"),
        ("$P$", "phpass"),
        ("$H$", "phpass"),
        ("$7$", "scrypt"),
        ("$scrypt$", "scrypt"),
        ("$pbkdf2", "pbkdf2"),
        ("pbkdf2_", "pbkdf2"),
    ] {
        if h.starts_with(prefix) {
            return Some((algo, false));
        }
    }
    // MySQL 4.1+: `*` followed by 40 hex — a fast SHA1(SHA1(pw)).
    if let Some(rest) = h.strip_prefix('*')
        && rest.len() == 40
        && rest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Some(("mysql", true));
    }
    // Bare hex digest, optionally with an appended salt. 32 hex is MD5 (also
    // NTLM / LM at this length); the rest are the SHA-2 family by width. OathNet
    // packs the salt onto the digest — space-separated (`"2f43… _:=j…"`) or behind
    // a `,:` / `:` marker (`"b3dd…,:xpay"`) — so classify by the LEADING hex run's
    // length rather than demanding the whole string be hex. The remainder, if any,
    // must begin at a separator, so a token that merely *starts* with hex but is
    // really something else is not misread as a digest.
    let hex_len = h.bytes().take_while(u8::is_ascii_hexdigit).count();
    if hex_len > 0 {
        let rest = &h[hex_len..];
        if rest.is_empty() || rest.starts_with([' ', '\t', ':', ',', ';', '|']) {
            return match hex_len {
                32 => Some(("md5", true)),
                40 => Some(("sha1", true)),
                56 => Some(("sha224", true)),
                64 => Some(("sha256", true)),
                96 => Some(("sha384", true)),
                128 => Some(("sha512", true)),
                _ => None,
            };
        }
    }
    None
}
