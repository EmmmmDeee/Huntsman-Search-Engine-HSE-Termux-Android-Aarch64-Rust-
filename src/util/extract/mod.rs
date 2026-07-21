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

/// Every HTTP(S) URL in `text`, with the trailing sentence punctuation that
/// [`URL_RE`] deliberately over-matches (`.`, `,`, `)`) trimmed, de-duplicated
/// on the trimmed value with first-occurrence order preserved. Mirrors
/// [`emails`]: scanner-grade extraction with **no cap**, so a bio or profile
/// that lists many links surfaces all of them rather than a silent first-N
/// sample. Single-sources the identical `URL_RE.find_iter(...).trim_end_matches(...)
/// + HashSet` loop the bio scanners each carried.
#[must_use]
pub fn urls(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in URL_RE.find_iter(text) {
        let link = m.as_str().trim_end_matches(['.', ',', ')']);
        if !link.is_empty() && seen.insert(link.to_string()) {
            out.push(link.to_string());
        }
    }
    out
}

/// Matches a labelled WiFi SSID line — `SSID: Home`, `WiFi Name = Office`,
/// `Wireless Network: …` — capturing the network name. SSIDs are arbitrary
/// strings, so only a *labelled* one can be recognised (never free-text).
pub static SSID_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^\s*(?:ssid|wifi(?:\s*name)?|wireless\s*network|network\s*name)\s*[:=]\s*(.+?)\s*$",
    )
    .expect("constant ssid regex")
});

/// Every labelled WiFi SSID in `text`, de-duplicated. Bounded to the 802.11
/// 1–32-octet length and stripped of obvious placeholders. Recovers a victim's
/// network names from a stealer log so a *unique* one can be geolocated by WiGLE.
#[must_use]
pub fn labeled_ssids(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for cap in SSID_LABEL_RE.captures_iter(text) {
        let ssid = cap.get(1).map_or("", |m| m.as_str()).trim();
        let n = ssid.chars().count();
        if (1..=32).contains(&n)
            && !ssid.eq_ignore_ascii_case("null")
            && !ssid.eq_ignore_ascii_case("n/a")
            && !ssid.eq_ignore_ascii_case("none")
            && seen.insert(ssid.to_string())
        {
            out.push(ssid.to_string());
        }
    }
    out
}

/// Matches an IBAN-shaped token: a 2-letter country code, 2 check digits, then
/// 10–30 alphanumerics (contiguous form, as breach dumps store it).
pub static IBAN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b").expect("constant iban regex")
});

/// Every checksum-valid IBAN (international bank account number) in `text`,
/// upper-cased and de-duplicated. Validated by the ISO 13616 mod-97 check, so a
/// random alphanumeric run that merely looks IBAN-shaped is rejected (~1-in-97
/// would otherwise slip through the shape alone). Recovers a victim's bank
/// account from a breach/stealer dump as a financial-intel finding.
#[must_use]
pub fn ibans(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in IBAN_RE.find_iter(text) {
        let iban: String = m
            .as_str()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .flat_map(char::to_uppercase)
            .collect();
        if iban_is_valid(&iban) && seen.insert(iban.clone()) {
            out.push(iban);
        }
    }
    out
}

/// Full ISO 13616 IBAN validity for an already-normalised candidate (uppercase,
/// no separators): the `CCkk` layout, the country's **registered length**, and
/// the mod-97 checksum — the single source of truth both the free-text scanner
/// ([`ibans`]) and the breach-field validator (`oathnet_pro`) share.
///
/// The registered-length gate is the precision the mod-97 check alone lacks: a
/// country's IBAN length is fixed by ISO 13616 (`GB` 22, `DE` 22, `FR` 27, …), so
/// a right-checksum but wrong-length string (which the old `len in 15..=34` range
/// admitted — roughly 1 in 97 of any wrong-length run with a real country prefix)
/// is not a genuine account. An **unregistered** country code falls back to the
/// spec's `15..=34` range rather than rejecting outright, so a future registry
/// addition is never a false negative. Pure.
#[must_use]
pub fn iban_is_valid(iban: &str) -> bool {
    let b = iban.as_bytes();
    // CCkk layout, then an all-alphanumeric BBAN.
    if b.len() < 5
        || !b[0].is_ascii_uppercase()
        || !b[1].is_ascii_uppercase()
        || !b[2].is_ascii_digit()
        || !b[3].is_ascii_digit()
        || !iban[4..]
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }
    match iban_country_length(&iban[..2]) {
        Some(len) if iban.len() != len => return false,
        None if !(15..=34).contains(&iban.len()) => return false,
        _ => {}
    }
    iban_mod97_valid(iban)
}

/// The registered total IBAN length for an ISO 13616 country code, or `None` for
/// a code not in the registry (the caller then falls back to the spec range). The
/// values are the published national IBAN lengths; a code absent here is treated
/// leniently, never rejected, so the table can grow without risking a real
/// account. Kept sorted by code for reviewability.
fn iban_country_length(cc: &str) -> Option<usize> {
    Some(match cc {
        "AD" => 24,
        "AE" => 23,
        "AL" => 28,
        "AT" => 20,
        "AZ" => 28,
        "BA" => 20,
        "BE" => 16,
        "BG" => 22,
        "BH" => 22,
        "BI" => 27,
        "BR" => 29,
        "BY" => 28,
        "CH" => 21,
        "CR" => 22,
        "CY" => 28,
        "CZ" => 24,
        "DE" => 22,
        "DK" => 18,
        "DO" => 28,
        "EE" => 20,
        "EG" => 29,
        "ES" => 24,
        "FI" => 18,
        "FO" => 18,
        "FR" => 27,
        "GB" => 22,
        "GE" => 22,
        "GI" => 23,
        "GL" => 18,
        "GR" => 27,
        "GT" => 28,
        "HR" => 21,
        "HU" => 28,
        "IE" => 22,
        "IL" => 23,
        "IQ" => 23,
        "IS" => 26,
        "IT" => 27,
        "JO" => 30,
        "KW" => 30,
        "KZ" => 20,
        "LB" => 28,
        "LC" => 32,
        "LI" => 21,
        "LT" => 20,
        "LU" => 20,
        "LV" => 21,
        "LY" => 25,
        "MC" => 27,
        "MD" => 24,
        "ME" => 22,
        "MK" => 19,
        "MN" => 20,
        "MR" => 27,
        "MT" => 31,
        "MU" => 30,
        "NL" => 18,
        "NO" => 15,
        "PK" => 24,
        "PL" => 28,
        "PS" => 29,
        "PT" => 25,
        "QA" => 29,
        "RO" => 24,
        "RS" => 22,
        "RU" => 33,
        "SA" => 24,
        "SC" => 31,
        "SD" => 18,
        "SE" => 24,
        "SI" => 19,
        "SK" => 24,
        "SM" => 27,
        "ST" => 25,
        "SV" => 28,
        "TL" => 23,
        "TN" => 24,
        "TR" => 26,
        "UA" => 29,
        "VA" => 22,
        "VG" => 24,
        "XK" => 20,
        _ => return None,
    })
}

/// ISO 13616 IBAN checksum: move the first four chars to the end, map letters
/// `A`–`Z` to `10`–`35`, and require the resulting decimal `mod 97 == 1`. Callers
/// go through [`iban_is_valid`], which first pins the layout and registered
/// length; this is the checksum step alone.
fn iban_mod97_valid(iban: &str) -> bool {
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        if let Some(d) = c.to_digit(10) {
            rem = (rem * 10 + d) % 97;
        } else if c.is_ascii_uppercase() {
            // A letter contributes two decimal digits (10..=35).
            rem = (rem * 100 + (c as u32 - 'A' as u32 + 10)) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

/// Every plausible MAC address / WiFi BSSID in `text`, normalised to lowercase
/// colon form and de-duplicated. The all-zero and broadcast addresses are
/// dropped (never a real device/access-point). Pulls a victim's router BSSID
/// out of a stealer log or breach record so it can be geolocated by
/// [`crate::modules::mylnikov`] / `wigle`.
#[must_use]
pub fn macs(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let is_sep = |b: u8| b == b':' || b == b'-';
    let is_hex = |b: u8| b.is_ascii_hexdigit();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in MAC_RE.find_iter(text) {
        // Reject a 6-octet window carved out of a LONGER colon/hyphen hex run
        // (an EUI-64 / longer identifier). The regex's `\b` treats the separator
        // after the 6th octet as a word boundary, so `aa:bb:cc:dd:ee:ff:00:11`
        // yields a spurious 48-bit `aa:bb:cc:dd:ee:ff`. A genuine standalone MAC
        // is never flanked by `<sep><hex><hex>`: another octet immediately after
        // (sep + 2 hex) or before (2 hex + sep) means this is a fragment of a
        // longer identifier, not an address. (MAC/EUI bytes are ASCII, so byte
        // indexing at the match edges is boundary-safe.)
        let (s, e) = (m.start(), m.end());
        let octet_after = e + 1 < bytes.len() && is_sep(bytes[e]) && is_hex(bytes[e + 1]);
        let octet_before =
            s >= 3 && is_sep(bytes[s - 1]) && is_hex(bytes[s - 2]) && is_hex(bytes[s - 3]);
        if octet_after || octet_before {
            continue;
        }
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
            !local.is_empty() && !s.contains(char::is_whitespace) && host_has_alpha_tld(host)
        }
        None => false,
    }
}

/// True if `host` ends in a valid alphabetic TLD: at least one dot, no empty
/// label (so no leading/trailing dot and no `..`), and a final label of ≥2 ASCII
/// letters. This is exactly the domain validity the canonical [`EMAIL_RE`]
/// (`…\.[A-Za-z]{2,}`) enforces, single-sourced here so the **non-regex**
/// admission paths — [`looks_like_email`] (the provider-field gate), [`page_emails`]
/// (the `util` HTML byte-scanner), and the `web_crawler` module's own page byte-scanner
/// (`crawl_util::extract_emails`) — cannot be more permissive than the free-text
/// scanner and admit an address the scanner would reject. Without it an IP-literal
/// host (`admin@10.0.0.1`), a numeric pseudo-TLD (`user@host.123`), a 1-char TLD
/// (`user@host.c`) or a double-dot host (`x@sub..example.com`) minted a bogus `Email`
/// entity that then poisoned correlation. Pure.
pub fn host_has_alpha_tld(host: &str) -> bool {
    // A second `@` in the host means the value is a double-`@` non-address
    // (`user@host@evil.com`) that `looks_like_email`/`page_emails` reach via a
    // first-`@` split; the canonical [`EMAIL_RE`] host class (`[A-Za-z0-9.-]+`)
    // admits no `@`, so rejecting it here keeps the non-regex paths from being
    // MORE permissive than the free-text scanner (the stated invariant).
    if host.contains('@') {
        return false;
    }
    if !host.contains('.') || host.split('.').any(str::is_empty) {
        return false;
    }
    host.rsplit('.')
        .next()
        .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
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
    // Match the canonical `EMAIL_RE` local class `[A-Za-z0-9._%+-]`, which includes
    // `%` — omitting it truncated a `%`-containing mailbox at the `%`, carving a
    // fabricated shorter address (`with%percent@x` → `percent@x`) the regex accepts
    // whole.
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'%')
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
            // Same alphabetic-TLD validity the free-text `EMAIL_RE` enforces, so
            // the scanner can't carve an IP-literal (`@10.0.0.1`) or numeric-TLD
            // (`@host.123`) pseudo-address out of a page body. Subsumes the old
            // `contains('.') && len > 3` gate.
            && host_has_alpha_tld(domain)
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
