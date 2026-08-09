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

/// Build the OSINT entities for a domain's TLSRPT record set: a report-address
/// `Email` per `mailto:` destination and a `Domain` lead per distinct
/// `http(s)://` reporting endpoint host.
///
/// This is the ONE implementation the two DNS transports share — the DoH
/// (`doh_resolver`) and hickory (`dns_intel`) paths both call it after doing
/// their own transport-specific TXT unquoting, so they emit a **byte-identical**
/// entity set from the same record (same confidence, tags, evidence, and gating)
/// rather than each carrying a hand-maintained copy that had already drifted:
/// the DoH copy stamped the report address at a bare `0.68` while the hickory
/// copy used [`crate::core::confidence::ATTRIBUTED`] (`0.72`), so the same
/// published address scored differently depending only on which transport
/// observed it. The named rung is canonical here.
///
/// Gating matches the modules' documented contract: a provider-infrastructure
/// mailbox (`sts-reports@google.com`) is dropped via
/// [`crate::util::domains::is_infrastructure_email`] rather than clustered as the
/// subject, and an endpoint host equal to `domain` (self-reporting) is not
/// re-emitted. A domain has at most one valid TLSRPT record, so the first that
/// parses wins. `src` is the calling module's name, stamped on the evidence.
///
/// `unquoted_txts` are the TXT record values with transport quoting already
/// removed (DoH multi-string reassembly vs. hickory's raw strings differ, so
/// each caller unquotes its own way). **Pure** — no network or I/O.
#[must_use]
pub fn report_entities(
    unquoted_txts: &[String],
    domain: &str,
    scan_id: &str,
    src: &'static str,
) -> Vec<crate::core::entity::Entity> {
    use crate::core::confidence;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let mut out = Vec::new();
    for txt in unquoted_txts {
        let Some(parsed) = parse(txt) else {
            continue;
        };
        for addr in &parsed.emails {
            if crate::util::domains::is_infrastructure_email(addr) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Email, addr, confidence::ATTRIBUTED, scan_id);
            e.tag("dns");
            e.tag("tlsrpt-report");
            e.add_evidence(
                Evidence::new(
                    src,
                    format!("TLSRPT (SMTP-TLS) report address for {domain}"),
                )
                .with_attr("record_type", "TLSRPT")
                .with_attr("parent_domain", domain),
            );
            out.push(e);
        }
        // One `Domain` lead per DISTINCT endpoint host: a `rua=` list may point
        // several report URLs at the same host (e.g. two paths on one collector),
        // and emitting the host once keeps the doc's "distinct host" contract and
        // avoids duplicate Domain entities skewing any pre-persist aggregation.
        let mut seen_hosts = std::collections::BTreeSet::new();
        for url in &parsed.urls {
            if let Some(host) = crate::util::url_util::host_from_url(url)
                && host.contains('.')
                && host != domain
                && seen_hosts.insert(host.clone())
            {
                let mut d =
                    Entity::new(EntityKind::Domain, &host, confidence::MEDIUM_SOLID, scan_id);
                d.tag("dns");
                d.tag("tlsrpt-report");
                d.add_evidence(
                    Evidence::new(
                        src,
                        format!("TLSRPT (SMTP-TLS) reporting endpoint host for {domain}"),
                    )
                    .with_attr("record_type", "TLSRPT")
                    .with_attr("rua", url.as_str()),
                );
                out.push(d);
            }
        }
        // A domain has at most one valid TLSRPT record; the first wins.
        break;
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
