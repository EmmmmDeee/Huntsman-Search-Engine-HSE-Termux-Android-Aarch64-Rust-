//! TLSRPT (RFC 8460) parsing.

use crate::{http, value_syntax};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsRptRecord {
    pub emails: Vec<String>,
    pub urls: Vec<String>,
}

/// RFC 8460 version 1 requires the entire first version tag to be
/// `v=TLSRPTv1`. Unsupported versions must not be reported as policy.
#[must_use]
pub fn is_tlsrpt(txt: &str) -> bool {
    txt.trim_start()
        .split(';')
        .next()
        .is_some_and(|version| version.trim_end().eq_ignore_ascii_case("v=TLSRPTv1"))
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
        // A mailbox is read as DMARC reads its `rua`, so the two records agree on one.
        record.emails = value_syntax::parse_mailto_list(list);
        record.urls = list
            .split(',')
            .map(str::trim)
            .filter(|uri| !uri.starts_with("mailto:") && http::parse_http_uri(uri).is_ok())
            .map(str::to_string)
            .collect();
        break;
    }
    Some(record)
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
    fn first_rua_wins() {
        let record = parse(
            "v=TLSRPTv1; rua=https://tlsrpt.example.net/a,https://tlsrpt.example.net/b,https://other.example.org/r; rua=mailto:ignored@example.com",
        )
        .expect("record");
        assert_eq!(
            record.urls,
            [
                "https://tlsrpt.example.net/a",
                "https://tlsrpt.example.net/b",
                "https://other.example.org/r"
            ]
        );
        assert!(record.emails.is_empty(), "{:?}", record.emails);
    }

    #[test]
    fn mailto_entries_are_the_mailboxes_dmarc_reads() {
        let list = "mailto:a@b.example!10m, mailto:x, https://r.example/v1";
        let dmarc =
            crate::dmarc::parse(&format!("v=DMARC1; p=none; rua={list}")).expect("DMARC record");
        let record = parse(&format!("v=TLSRPTv1; rua={list}")).expect("TLSRPT record");
        assert_eq!(record.emails, ["a@b.example"]);
        assert_eq!(record.emails, dmarc.rua);
        assert_eq!(record.urls, ["https://r.example/v1"]);
    }

    #[test]
    fn version_tag_requires_exact_tlsrpt_v1() {
        for raw in [
            "v=TLSRPTv2; rua=mailto:reports@example.com",
            "v=TLSRPTv10; rua=mailto:reports@example.com",
            "v=TLSRPTv; rua=mailto:reports@example.com",
            "v=TLSRPTv1extra; rua=mailto:reports@example.com",
            "v=TLSRPTv1 rua=mailto:reports@example.com",
        ] {
            assert!(
                !is_tlsrpt(raw),
                "accepted unsupported TLSRPT version: {raw:?}"
            );
            assert!(
                parse(raw).is_none(),
                "parsed unsupported TLSRPT version: {raw:?}"
            );
        }
        for raw in [
            "v=TLSRPTv1",
            "v=TLSRPTv1; rua=mailto:reports@example.com",
            " v=tlsrptV1 ; rua=mailto:reports@example.com",
        ] {
            assert!(is_tlsrpt(raw), "refused supported TLSRPT version: {raw:?}");
            assert!(
                parse(raw).is_some(),
                "failed to parse TLSRPT record: {raw:?}"
            );
        }
    }

    #[test]
    fn rejects_non_tlsrpt() {
        assert!(!is_tlsrpt("v=spf1 -all"));
        assert!(parse("v=DMARC1; p=reject").is_none());
    }
}
