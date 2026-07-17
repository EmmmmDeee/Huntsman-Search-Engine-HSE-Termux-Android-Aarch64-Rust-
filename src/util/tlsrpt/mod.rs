//! SMTP TLS Reporting — TLSRPT (RFC 8460) parsing.
//!
//! A TLSRPT policy is published as a TXT record at `_smtp._tls.{domain}` and
//! names where the domain wants SMTP-TLS failure reports delivered:
//!
//! ```text
//! v=TLSRPTv1; rua=mailto:sts-reports@example.com,https://tlsrpt.example.com/v1
//! ```
//!
//! The `rua=` destinations are the OSINT-valuable pivot — exactly like DMARC
//! `rua`/`ruf`: they reveal where the organisation receives mail-security
//! telemetry, often exposing an internal security-team inbox or a third-party
//! reporting service. Unlike DMARC (mailto-only), a TLSRPT `rua` entry may be a
//! `mailto:` address OR an `https:` collection endpoint (RFC 8460 §3), so both
//! forms are surfaced.
//!
//! Parsing is total and never panics. The version tag is matched
//! case-insensitively (RFC 8460 §3); a record without it is not a TLSRPT record.

/// True if `txt` is a TLSRPT record — `v=TLSRPTv1` matched case-insensitively
/// (RFC 8460 §3). Leading whitespace is tolerated (the record value may arrive
/// with surrounding spaces after TXT reassembly).
#[must_use]
pub fn is_tlsrpt(txt: &str) -> bool {
    let t = txt.trim_start();
    let b = t.as_bytes();
    b.len() >= 9 && b[..9].eq_ignore_ascii_case(b"v=TLSRPTv")
}

/// A parsed TLSRPT record — just its `rua=` report destinations, split into the
/// two URI schemes RFC 8460 permits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsRptRecord {
    /// `mailto:` report addresses (the `mailto:` prefix stripped).
    pub emails: Vec<String>,
    /// `http(s)://` report collection endpoints (full URL retained).
    pub urls: Vec<String>,
}

/// Parse a TLSRPT TXT record. Returns `None` when `txt` is not a TLSRPT record.
/// A record with a valid version but no usable `rua=` destination still parses
/// (to an empty [`TlsRptRecord`]) — the caller decides whether that is useful.
///
/// TLSRPT tag-value pairs are `;`-delimited (RFC 8460 §3); the `rua=` value is a
/// `,`-separated URI list. The first `rua=` wins (a duplicate tag is malformed;
/// take the leftmost, matching the DMARC convention).
#[must_use]
pub fn parse(txt: &str) -> Option<TlsRptRecord> {
    if !is_tlsrpt(txt) {
        return None;
    }
    let mut rec = TlsRptRecord::default();
    for field in txt.split(';') {
        let field = field.trim();
        let Some(list) = field
            .strip_prefix("rua=")
            .or_else(|| field.strip_prefix("RUA="))
        else {
            continue;
        };
        for uri in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(addr) = uri.strip_prefix("mailto:") {
                // An optional `!<size>` suffix is a DMARC-ism; TLSRPT does not
                // define one, but stripping it is harmless and defensive.
                let addr = addr.split('!').next().unwrap_or(addr).trim();
                if addr.contains('@') && addr.len() >= 5 {
                    rec.emails.push(addr.to_string());
                }
            } else if uri.starts_with("https://") || uri.starts_with("http://") {
                rec.urls.push(uri.to_string());
            }
        }
        // First rua= wins.
        break;
    }
    Some(rec)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
