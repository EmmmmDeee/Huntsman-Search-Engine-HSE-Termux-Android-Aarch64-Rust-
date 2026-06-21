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

/// Every plausibly-international phone number in `text`, normalised to `+<digits>`,
/// de-duplicated with first-occurrence order preserved.
///
/// Requires a leading `+` followed by a non-zero country digit and 7–15 total
/// digits (E.164 range). Separators (spaces, hyphens, parentheses) are stripped.
#[must_use]
pub fn phones(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' && i + 8 < bytes.len() && matches!(bytes[i + 1], b'1'..=b'9') {
            let start = i;
            i += 1;
            let mut digits = 0u32;
            while i < bytes.len() && matches!(bytes[i], b'0'..=b'9' | b'-' | b' ' | b'(' | b')') {
                if bytes[i].is_ascii_digit() {
                    digits += 1;
                }
                i += 1;
            }
            if (7..=15).contains(&digits) {
                let cleaned: String = text[start..i]
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '+')
                    .collect();
                if seen.insert(cleaned.clone()) {
                    out.push(cleaned);
                }
            }
        } else {
            i += 1;
        }
    }
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
