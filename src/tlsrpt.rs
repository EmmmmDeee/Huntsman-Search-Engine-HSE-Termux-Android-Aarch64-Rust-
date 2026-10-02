//! TLSRPT (RFC 8460) parsing.

use crate::{domains, http};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsRptRecord {
    pub emails: Vec<String>,
    pub urls: Vec<String>,
}

#[must_use]
pub fn is_tlsrpt(txt: &str) -> bool {
    let trimmed = txt.trim_start();
    let bytes = trimmed.as_bytes();
    bytes.len() >= 9 && bytes[..9].eq_ignore_ascii_case(b"v=TLSRPTv")
}

#[must_use]
pub fn parse(txt: &str) -> Option<TlsRptRecord> {
    if !is_tlsrpt(txt) {
        return None;
    }
    let mut record = TlsRptRecord::default();
    for raw_field in txt.split(';') {
        let field = raw_field.trim();
        let list = field
            .strip_prefix("rua=")
            .or_else(|| field.strip_prefix("RUA="));
        let Some(list) = list else {
            continue;
        };
        for uri in list
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if let Some(addr) = uri.strip_prefix("mailto:") {
                let addr = addr.split('!').next().unwrap_or(addr).trim();
                if addr.contains('@') && addr.len() >= 5 {
                    record.emails.push(addr.to_string());
                }
            } else if http::parse_http_uri(uri).is_ok() {
                record.urls.push(uri.to_string());
            }
        }
        break;
    }
    Some(record)
}

#[must_use]
pub fn report_hosts(record: &TlsRptRecord, domain: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for url in &record.urls {
        if let Some(host) = host_of_absolute_http_url(url) {
            if host.contains('.') && host != domain && seen.insert(host.clone()) {
                out.push(host);
            }
        }
    }
    out.sort();
    out
}

fn host_of_absolute_http_url(url: &str) -> Option<String> {
    http::parse_http_uri(url).ok()?;
    domains::host_from_url(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mailto_and_https_rua() {
        let record = parse(
            "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://report.example.net/v1,mailto:sec@example.com",
        )
        .expect("TLSRPT record");
        assert_eq!(record.emails, vec!["tlsrpt@example.com", "sec@example.com"]);
        assert_eq!(record.urls, vec!["https://report.example.net/v1"]);
    }

    #[test]
    fn first_rua_wins_and_hosts_dedup() {
        let record = parse(
            "v=TLSRPTv1; rua=https://tlsrpt.example.net/a,https://tlsrpt.example.net/b,https://other.example.org/r; rua=mailto:ignored@example.com",
        )
        .expect("record");
        let hosts = report_hosts(&record, "fabrikam.example");
        assert_eq!(hosts, vec!["other.example.org", "tlsrpt.example.net"]);
    }

    #[test]
    fn rejects_non_tlsrpt() {
        assert!(!is_tlsrpt("v=spf1 -all"));
        assert!(parse("v=DMARC1; p=reject").is_none());
    }
}
