//! Canonical free-text identifier extraction.
//!
//! One definition of "what an email looks like in scraped or free text",
//! shared by every module that mines addresses out of HTML, search snippets,
//! breach blobs, or chat content. Before this module each carried its own
//! `Regex::new("…@…")` literal; consolidating removes drift and ensures a
//! single, testable source of truth.
//!
//! ## What [`EMAIL_RE`] matches
//!
//! Pragmatic, ASCII-only, scanner-grade — NOT an RFC 5322 validator:
//!
//! | part   | grammar                | notes                                  |
//! |--------|------------------------|----------------------------------------|
//! | local  | `[A-Za-z0-9._%+-]+`    | dotted + plus-tagged locals included   |
//! | `@`    | literal                |                                        |
//! | domain | `[A-Za-z0-9.-]+`       | ASCII labels; IDNs appear as punycode  |
//! | TLD    | `\.[A-Za-z]{2,}`       | ≥2 ASCII letters — rejects `.123`      |

use std::sync::LazyLock;

use regex::Regex;

/// Canonical free-text email matcher. Compiled once per process.
pub static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("constant email regex")
});

/// Canonical free-text `http(s)` URL matcher: a scheme then any run of
/// non-space, non-quote, non-angle-bracket, non-`)` characters. Scanner-grade —
/// it deliberately over-matches trailing sentence punctuation, so callers
/// `trim_end_matches(['.', ',', ')'])` the hit. Compiled once per process.
/// Replaces the identical bio/profile-URL literal that `reddit_user` and
/// `hacker_news` each carried.
pub static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s"'<>)]+"#).expect("constant url regex"));

/// Matches a 48-bit MAC address / WiFi BSSID in colon or hyphen form
/// (`aa:bb:cc:dd:ee:ff` / `AA-BB-CC-DD-EE-FF`). Word-boundary-anchored so a
/// 6-octet run is not carved out of a longer hex string. Rust's regex has no
/// backreferences, so the two separators are separate alternatives.
pub static MAC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b")
        .expect("constant mac regex")
});

/// Every email address in `text`, lowercased and de-duplicated with
/// first-occurrence order preserved.
#[must_use]
pub fn emails(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in EMAIL_RE.find_iter(text) {
        let addr = m.as_str().to_lowercase();
        if seen.insert(addr.clone()) {
            out.push(addr);
        }
    }
    out
}

/// Every plausible MAC address / WiFi BSSID in `text`, normalised to lowercase
/// colon form and de-duplicated. The all-zero and broadcast addresses are
/// dropped (never a real device/access-point). Pulls a victim's router BSSID
/// out of a stealer log or breach record so it can be geolocated by
/// [`crate::modules::mylnikov`] / `wigle`.
#[must_use]
pub fn macs(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in MAC_RE.find_iter(text) {
        let hex: String = m
            .as_str()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .flat_map(char::to_lowercase)
            .collect();
        if hex.len() != 12 || hex == "000000000000" || hex == "ffffffffffff" {
            continue;
        }
        let norm = format!(
            "{}:{}:{}:{}:{}:{}",
            &hex[0..2],
            &hex[2..4],
            &hex[4..6],
            &hex[6..8],
            &hex[8..10],
            &hex[10..12]
        );
        if seen.insert(norm.clone()) {
            out.push(norm);
        }
    }
    out
}

/// Loose structural check that `s` is shaped like a single email address: a
/// non-empty local part, an `@`, and a dotted host that neither starts nor ends
/// with a dot, with no embedded whitespace. Enough to reject the junk that breach
/// providers put in an `email` field — a bare username echoed back from the query
/// (`ali.kareem`, no `@`), a redacted sentinel (`UPGRADE_TO_SEE@x`), or a half
/// value (`user@`, `@host`) — without a full RFC 5322 parser. The single gate for
/// any module that turns a provider `email` *field* into an `Email` entity, so a
/// non-address never reaches the graph to pollute correlation. **Pure.**
///
/// ```
/// use huntsman_search_engine::util::extract::looks_like_email;
///
/// assert!(looks_like_email("ali.kareem95@gmail.com"));
/// assert!(!looks_like_email("ali.kareem")); // query echoed into the email field
/// assert!(!looks_like_email("user@"));      // no host
/// assert!(!looks_like_email("@example.com")); // no local part
/// ```
#[must_use]
pub fn looks_like_email(s: &str) -> bool {
    match s.split_once('@') {
        Some((local, host)) => {
            !local.is_empty()
                && host.contains('.')
                && !host.starts_with('.')
                && !host.ends_with('.')
                && !s.contains(char::is_whitespace)
        }
        None => false,
    }
}

/// What a breach/stealer **credential field** (`password`, `pass`,
/// `hashed_password`, …) actually holds. Providers are inconsistent: the slot
/// frequently carries a capture sentinel or an email rather than a secret, and
/// minting those as a `Password` both loses a real lead and forges false
/// reused-secret links. [`classify_credential_field`] is the one decision point
/// every credential parser shares, so that judgement lives in a single place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialField {
    /// A redaction / capture-failure placeholder (`[fail]`, `UPGRADE_TO_SEE…`) — drop.
    Sentinel,
    /// An email mis-stored in the credential slot — recover as an `Email` lead.
    Email,
    /// A genuine plaintext secret (the caller still applies its length/variety gate).
    Secret,
}

/// Classify a raw credential-field value into a [`CredentialField`]. Trims first;
/// an empty value is a [`Sentinel`](CredentialField::Sentinel). **Pure.**
#[must_use]
pub fn classify_credential_field(s: &str) -> CredentialField {
    let t = s.trim();
    if t.is_empty() || is_placeholder_secret(t) {
        CredentialField::Sentinel
    } else if looks_like_email(t) {
        CredentialField::Email
    } else {
        CredentialField::Secret
    }
}

/// True for a credential value that is a provider *placeholder*, not a real
/// secret: a redaction marker (`UPGRADE_TO_SEE…`, `REDACTED`) anywhere in the
/// value, or a **bracketed** stealer capture sentinel (`[fail]`, `[NOT_SAVED]`,
/// `<empty>`). The bracket requirement is deliberate — a genuine (if terrible)
/// password like `fail` or `null` must survive, so only the wrapped forms count.
/// **Pure.**
#[must_use]
pub fn is_placeholder_secret(s: &str) -> bool {
    let u = s.trim().to_ascii_uppercase();
    if u.contains("UPGRADE_TO_SEE") || u.contains("REDACTED") {
        return true;
    }
    let inner = u.trim_matches(|c| matches!(c, '[' | ']' | '<' | '>' | '(' | ')' | '{' | '}'));
    inner.len() != u.len()
        && matches!(
            inner,
            "FAIL"
                | "FAILED"
                | "NOT_SAVED"
                | "NOT SAVED"
                | "NOTSAVED"
                | "EMPTY"
                | "BLANK"
                | "NULL"
                | "NONE"
                | "N/A"
                | "NA"
                | "UNKNOWN"
                | "NOT_FOUND"
                | "NO_PASSWORD"
                | "NO PASSWORD"
                | "ERROR"
        )
}

/// Every plausibly-international phone number in `text`, normalised to `+<digits>`,
/// de-duplicated with first-occurrence order preserved.
///
/// Requires a leading `+` followed by a non-zero country digit and 10–15 total
/// digits (E.164 minimum; Niue +683 and Nauru +674 are the shortest real prefixes).
/// Separators (spaces, hyphens, parentheses) are stripped.
#[must_use]
pub fn phones(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    crate::util::phone::scan_phones(text, usize::MAX, |p| {
        if seen.insert(p.clone()) {
            out.push(p);
        }
    });
    out
}

const ASSET_EXTS: &[&str] = &[
    ".png", ".jpg", ".gif", ".css", ".js", ".svg", ".webp", ".ico", ".woff", ".woff2",
];

/// Web-script/page extensions that, when they appear in an email's *local* part,
/// mark it as a URL fragment glued to the `@` during HTML stripping rather than
/// a real mailbox (the real-scan bug `viewtopic.phprose.cl@onet.eu`).
const SCRIPT_EXTS: &[&str] = &[
    ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".cgi", ".cfm", ".phtml",
];

fn is_email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+')
}

fn is_domain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// Email addresses mined from a scraped page body (raw HTML/markup or SERP
/// snippet), lower-cased and de-duplicated. Drops asset references
/// (`logo@2x.png`, `font@x.woff2`) and web-script URL fragments
/// (`viewtopic.php…@…`), and requires a dotted domain of reasonable length.
#[must_use]
pub fn page_emails(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut i = 0;
    while i < len {
        if bytes[i] != b'@' || i == 0 || i + 1 >= len {
            i += 1;
            continue;
        }
        if !is_email_local_byte(bytes[i - 1]) || !bytes[i + 1].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let mut local_start = i;
        while local_start > 0 && is_email_local_byte(bytes[local_start - 1]) {
            local_start -= 1;
        }
        let mut domain_end = i + 1;
        while domain_end < len && is_domain_byte(bytes[domain_end]) {
            domain_end += 1;
        }
        while domain_end > i + 1 && bytes[domain_end - 1] == b'.' {
            domain_end -= 1;
        }
        let domain = &text[i + 1..domain_end];
        if local_start < i
            && domain.contains('.')
            && domain.len() > 3
            && domain_end - local_start <= 254
        {
            let email = text[local_start..domain_end].to_lowercase();
            // Local part (ASCII, so lowercasing preserves the `@` offset).
            let local_lower = &email[..i - local_start];
            let is_script_frag = SCRIPT_EXTS.iter().any(|ext| local_lower.contains(ext));
            let is_asset = ASSET_EXTS.iter().any(|ext| email.ends_with(ext))
                || email.contains("@2x.")
                || email.contains("@3x.");
            if !is_script_frag && !is_asset && seen.insert(email.clone()) {
                out.push(email);
            }
        }
        i = domain_end;
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
