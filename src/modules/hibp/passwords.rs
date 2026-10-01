//! Pwned Passwords range API helpers (api.pwnedpasswords.com).
//!
//! k-anonymity: only the first 5 hex characters of a password's SHA-1 or NTLM
//! hash are sent; the response lists `SUFFIX:COUNT` lines for every hash with
//! that prefix (35-char SHA-1 suffixes, 27-char NTLM suffixes). With the
//! `Add-Padding: true` header the response is padded to 800–1,000 lines with
//! entries whose count is 0, which "can be discarded once received"
//! (haveibeenpwned.com/API/v3, "Introducing padding").

use sha1::Digest;

/// Which hash the range is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordHashMode {
    /// SHA-1 of the UTF-8 password (the API default).
    Sha1,
    /// NTLM: MD4 of the UTF-16LE password (`?mode=ntlm`).
    Ntlm,
}

/// One `SUFFIX:COUNT` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeEntry {
    /// Upper-case hash suffix.
    pub suffix: String,
    /// Times seen in breaches.
    pub count: u64,
}

/// Parse a range body. With `drop_padding`, zero-count entries are removed.
/// Malformed lines are skipped.
pub fn parse_range(body: &str, drop_padding: bool) -> Vec<RangeEntry> {
    body.lines()
        .filter_map(|line| {
            let (s, c) = line.trim().split_once(':')?;
            let count = c.trim().parse::<u64>().ok()?;
            let suffix = s.trim();
            if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return None;
            }
            Some(RangeEntry {
                suffix: suffix.to_ascii_uppercase(),
                count,
            })
        })
        .filter(|e| !(drop_padding && e.count == 0))
        .collect()
}

/// Upper-case hex hash of `password` in `mode`.
pub fn hash_password(password: &str, mode: PasswordHashMode) -> String {
    match mode {
        PasswordHashMode::Sha1 => hex::encode_upper(sha1::Sha1::digest(password.as_bytes())),
        PasswordHashMode::Ntlm => {
            let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
            hex::encode_upper(super::md4::md4(&utf16))
        }
    }
}

/// The count for `suffix` in `entries` (0 when absent).
pub fn count_for(entries: &[RangeEntry], suffix: &str) -> u64 {
    entries
        .iter()
        .find(|e| e.suffix.eq_ignore_ascii_case(suffix))
        .map_or(0, |e| e.count)
}
