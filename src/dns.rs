//! DNS helpers rebuilt from `util/dns`.
//! DNS-over-HTTPS queries go through `fetch` over an injected transport so tests
//! use fakes and a challenge page is a wall, not a JSON parse error.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use serde::Deserialize;

use crate::{
    canonical,
    dmarc::{self, DmarcPolicy},
    domains,
    fetch::{FetchOptions, Fetched, fetch},
    http::{Request, Response, Transport, TransportConfig, append_query_param},
    source_outcome::SourceOutcomeKind,
    spf::{self, AllPolicy},
    textnorm::escape_controls,
    tlsrpt,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Mx,
    Ns,
    Soa,
    Txt,
}

impl RecordType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Soa => "SOA",
            Self::Txt => "TXT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveQuery {
    pub name: String,
    pub record_type: RecordType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverServer {
    pub provider: &'static str,
    pub ip: IpAddr,
    pub doh_url: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverPoolConfig {
    pub name_servers: Vec<ResolverServer>,
    pub timeout_secs: u64,
    pub attempts: u8,
    pub ipv4_then_ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveAnswer {
    pub server: ResolverServer,
    pub records: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveError {
    pub kind: ResolveErrorKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveErrorKind {
    Timeout,
    Upstream,
    Empty,
    BotWaf,
    RateLimited,
    Truncated,
}

impl ResolveErrorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Upstream => "upstream",
            Self::Empty => "empty",
            Self::BotWaf => "bot_waf",
            Self::RateLimited => "rate_limited",
            Self::Truncated => "truncated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAnswer {
    pub name: String,
    pub record_type: RecordType,
    pub answer: ResolveAnswer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryFailure {
    pub name: String,
    pub record_type: RecordType,
    pub error: ResolveError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDns {
    pub domain: String,
    pub answers: Vec<QueryAnswer>,
    pub failures: Vec<QueryFailure>,
    pub spf: Option<spf::SpfRecord>,
    pub dmarc: Option<dmarc::DmarcRecord>,
    pub tlsrpt: Option<tlsrpt::TlsRptRecord>,
}

#[derive(Debug, Deserialize, Default)]
struct DnsJsonResponse {
    #[serde(rename = "Status", default)]
    status: u32,
    #[serde(rename = "Answer", default)]
    answers: Vec<DnsJsonAnswer>,
}

#[derive(Debug, Deserialize, Default)]
struct DnsJsonAnswer {
    #[serde(default)]
    data: String,
}

#[must_use]
pub fn resolver_config() -> ResolverPoolConfig {
    ResolverPoolConfig {
        name_servers: vec![
            ResolverServer {
                provider: "Cloudflare",
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                doh_url: "https://cloudflare-dns.com/dns-query",
            },
            ResolverServer {
                provider: "Quad9",
                ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                doh_url: "https://dns.quad9.net/dns-query",
            },
            ResolverServer {
                provider: "Google",
                ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                doh_url: "https://dns.google/resolve",
            },
        ],
        timeout_secs: 2,
        attempts: 1,
        ipv4_then_ipv6: true,
    }
}

/// # Errors
/// Returns the last transport or response error observed across the resolver pool.
pub fn resolve_with_pool<T: Transport + ?Sized>(
    transport: &T,
    query: &ResolveQuery,
) -> Result<ResolveAnswer, ResolveError> {
    resolve_with_config(transport, query, &resolver_config())
}

/// # Errors
/// Returns a transport, HTTP, parse, or empty-answer error if no configured resolver
/// yields at least one record. A challenge page is [`ResolveErrorKind::BotWaf`],
/// never an invalid-JSON parse.
pub fn resolve_with_config<T: Transport + ?Sized>(
    transport: &T,
    query: &ResolveQuery,
    config: &ResolverPoolConfig,
) -> Result<ResolveAnswer, ResolveError> {
    let mut last_error = None;
    for server in &config.name_servers {
        let request = build_request(server, query, Duration::from_secs(config.timeout_secs));
        match fetch(
            transport,
            request,
            None,
            &FetchOptions::no_redirects(),
            "dns",
            0,
        ) {
            Err(error) => {
                last_error = Some(ResolveError {
                    kind: ResolveErrorKind::Upstream,
                    detail: error.to_string(),
                });
            }
            Ok(fetched) => match interpret_fetched(&fetched) {
                Ok(records) if !records.is_empty() => {
                    return Ok(ResolveAnswer {
                        server: server.clone(),
                        records,
                    });
                }
                Ok(_) => {
                    last_error = Some(ResolveError {
                        kind: ResolveErrorKind::Empty,
                        detail: "empty DNS answer".into(),
                    });
                }
                Err(error) => last_error = Some(error),
            },
        }
    }
    Err(last_error.unwrap_or(ResolveError {
        kind: ResolveErrorKind::Upstream,
        detail: "resolver pool is empty".into(),
    }))
}

fn build_request(server: &ResolverServer, query: &ResolveQuery, timeout: Duration) -> Request {
    let url = append_query_param(
        &append_query_param(server.doh_url, "name", &query.name),
        "type",
        query.record_type.as_str(),
    );
    Request::get(url)
        .header("accept", "application/dns-json")
        .with_timeout(timeout)
}

fn interpret_fetched(fetched: &Fetched) -> Result<Vec<String>, ResolveError> {
    match fetched.outcome.kind {
        SourceOutcomeKind::BotWaf => {
            return Err(ResolveError {
                kind: ResolveErrorKind::BotWaf,
                detail: fetched
                    .outcome
                    .detail
                    .clone()
                    .unwrap_or_else(|| "challenge page".into()),
            });
        }
        SourceOutcomeKind::RateLimited => {
            return Err(ResolveError {
                kind: ResolveErrorKind::RateLimited,
                detail: fetched
                    .outcome
                    .detail
                    .clone()
                    .unwrap_or_else(|| "rate limited".into()),
            });
        }
        SourceOutcomeKind::TtfbTimeout | SourceOutcomeKind::BodyTimeout => {
            return Err(ResolveError {
                kind: ResolveErrorKind::Timeout,
                detail: fetched
                    .outcome
                    .detail
                    .clone()
                    .unwrap_or_else(|| "timed out".into()),
            });
        }
        _ => {}
    }
    let Some(response) = &fetched.response else {
        return Err(ResolveError {
            kind: ResolveErrorKind::Upstream,
            detail: fetched
                .outcome
                .detail
                .clone()
                .unwrap_or_else(|| "no HTTP response".into()),
        });
    };
    if crate::classify::is_challenge(&response.text()) {
        return Err(ResolveError {
            kind: ResolveErrorKind::BotWaf,
            detail: "challenge page".into(),
        });
    }
    if response.truncated {
        return Err(ResolveError {
            kind: ResolveErrorKind::Truncated,
            detail: "truncated DNS response".into(),
        });
    }
    parse_response(response)
}

fn parse_response(response: &Response) -> Result<Vec<String>, ResolveError> {
    if response.status != 200 {
        return Err(ResolveError {
            kind: ResolveErrorKind::Upstream,
            detail: format!("http status {}", response.status),
        });
    }
    if response.truncated {
        return Err(ResolveError {
            kind: ResolveErrorKind::Upstream,
            detail: "truncated DNS response".into(),
        });
    }
    let parsed: DnsJsonResponse =
        crate::http::parse_json_body(response).map_err(|_| ResolveError {
            kind: ResolveErrorKind::Upstream,
            detail: "invalid DNS JSON".into(),
        })?;
    if parsed.status != 0 {
        return Err(ResolveError {
            kind: ResolveErrorKind::Empty,
            detail: format!("dns status {}", parsed.status),
        });
    }
    let records: Vec<String> = parsed
        .answers
        .into_iter()
        .filter_map(|answer| {
            let data = answer.data.trim();
            (!data.is_empty()).then(|| data.to_string())
        })
        .collect();
    if records.is_empty() {
        Err(ResolveError {
            kind: ResolveErrorKind::Empty,
            detail: "empty DNS answer".into(),
        })
    } else {
        Ok(records)
    }
}

#[must_use]
pub fn unescape_dns_label(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'\\' {
            out.push(bytes[cursor]);
            cursor += 1;
            continue;
        }
        if cursor + 3 < bytes.len() && bytes[cursor + 1..cursor + 4].iter().all(u8::is_ascii_digit)
        {
            let text = std::str::from_utf8(&bytes[cursor + 1..cursor + 4]).unwrap_or("");
            let parsed = text
                .parse::<u16>()
                .ok()
                .and_then(|value| u8::try_from(value).ok());
            if let Some(value) = parsed {
                out.push(value);
                cursor += 4;
                continue;
            }
        }
        if cursor + 1 < bytes.len() {
            out.push(bytes[cursor + 1]);
            cursor += 2;
        } else {
            cursor += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[must_use]
pub fn soa_rname_to_email(rname: &str) -> String {
    if rname.is_empty() || !rname.contains('.') {
        return String::new();
    }
    let bytes = rname.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = cursor.saturating_add(2);
            continue;
        }
        if bytes[cursor] == b'.' {
            let (local, rest) = rname.split_at(cursor);
            let domain = rest[1..].trim_end_matches('.');
            if local.is_empty() || domain.is_empty() {
                return String::new();
            }
            return format!("{}@{domain}", unescape_dns_label(local));
        }
        cursor += 1;
    }
    String::new()
}

/// Canonical DNS name for a domain, URL or email selector. Nothing is sent.
#[must_use]
pub fn query_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains("://") {
        return domains::host_from_url(raw).and_then(|host| canonical::canonical_domain(&host));
    }
    if raw.contains('@') {
        return canonical::canonical_email(raw)
            .and_then(|email| email.split_once('@').map(|(_, domain)| domain.to_string()));
    }
    canonical::canonical_domain(raw)
}

#[must_use]
pub fn transport_config() -> TransportConfig {
    TransportConfig {
        timeout: Duration::from_secs(resolver_config().timeout_secs),
        ..TransportConfig::default()
    }
}

fn planned_queries(domain: &str) -> [(String, RecordType); 7] {
    [
        (domain.to_string(), RecordType::A),
        (domain.to_string(), RecordType::Aaaa),
        (domain.to_string(), RecordType::Mx),
        (domain.to_string(), RecordType::Ns),
        (domain.to_string(), RecordType::Txt),
        (format!("_dmarc.{domain}"), RecordType::Txt),
        (format!("_smtp._tls.{domain}"), RecordType::Txt),
    ]
}

/// Decode DNS-over-HTTPS TXT presentation (`"v=spf1 -all"` or concatenated
/// `"hello" "world"`) into the stored character-string. Unquoted data is kept.
#[must_use]
pub fn decode_txt(data: &str) -> String {
    let trimmed = data.trim();
    if !trimmed.contains('"') {
        return trimmed.to_string();
    }
    let mut out = String::new();
    let bytes = trimmed.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
                    out.push(char::from(bytes[cursor + 1]));
                    cursor += 2;
                    continue;
                }
                if bytes[cursor] == b'"' {
                    cursor += 1;
                    break;
                }
                out.push(char::from(bytes[cursor]));
                cursor += 1;
            }
        } else if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        } else {
            out.push_str(&trimmed[cursor..]);
            break;
        }
    }
    out
}

/// Resolve apex A/AAAA/MX/NS/TXT plus `_dmarc` and `_smtp._tls` TXT, then parse
/// SPF/DMARC/TLSRPT from those answers. One record-type failure does not abort
/// the others. `None` means the selector is not a domain, URL or email.
pub fn lookup_domain<T: Transport + ?Sized>(transport: &T, raw: &str) -> Option<DomainDns> {
    lookup_domain_with_config(transport, raw, &resolver_config())
}

pub fn lookup_domain_with_config<T: Transport + ?Sized>(
    transport: &T,
    raw: &str,
    config: &ResolverPoolConfig,
) -> Option<DomainDns> {
    let domain = query_name(raw)?;
    let dmarc_name = format!("_dmarc.{domain}");
    let tls_name = format!("_smtp._tls.{domain}");
    let mut answers = Vec::new();
    let mut failures = Vec::new();
    let mut apex_txt = Vec::new();
    let mut dmarc_txt = Vec::new();
    let mut tlsrpt_txt = Vec::new();
    for (name, record_type) in planned_queries(&domain) {
        match resolve_with_config(
            transport,
            &ResolveQuery {
                name: name.clone(),
                record_type,
            },
            config,
        ) {
            Ok(mut answer) => {
                if record_type == RecordType::Txt {
                    answer.records = answer
                        .records
                        .into_iter()
                        .map(|record| decode_txt(&record))
                        .filter(|record| !record.is_empty())
                        .collect();
                    if answer.records.is_empty() {
                        failures.push(QueryFailure {
                            name,
                            record_type,
                            error: ResolveError {
                                kind: ResolveErrorKind::Empty,
                                detail: "empty DNS answer".into(),
                            },
                        });
                        continue;
                    }
                    if name == domain {
                        apex_txt.extend(answer.records.iter().cloned());
                    } else if name == dmarc_name {
                        dmarc_txt.extend(answer.records.iter().cloned());
                    } else if name == tls_name {
                        tlsrpt_txt.extend(answer.records.iter().cloned());
                    }
                }
                answers.push(QueryAnswer {
                    name,
                    record_type,
                    answer,
                });
            }
            Err(error) => failures.push(QueryFailure {
                name,
                record_type,
                error,
            }),
        }
    }
    Some(DomainDns {
        spf: apex_txt.iter().find_map(|txt| spf::parse(txt)),
        dmarc: dmarc_txt.iter().find_map(|txt| dmarc::parse(txt)),
        tlsrpt: tlsrpt_txt.iter().find_map(|txt| tlsrpt::parse(txt)),
        domain,
        answers,
        failures,
    })
}

fn spf_all_name(policy: AllPolicy) -> &'static str {
    match policy {
        AllPolicy::HardFail => "hardfail",
        AllPolicy::SoftFail => "softfail",
        AllPolicy::Neutral => "neutral",
        AllPolicy::Pass => "pass",
        AllPolicy::Redirect => "redirect",
        AllPolicy::ImplicitNeutral => "implicit-neutral",
    }
}

fn dmarc_policy_name(policy: DmarcPolicy) -> &'static str {
    match policy {
        DmarcPolicy::None => "none",
        DmarcPolicy::Quarantine => "quarantine",
        DmarcPolicy::Reject => "reject",
    }
}

impl DomainDns {
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("domain={}", escape_controls(&self.domain)));
        for answer in &self.answers {
            for record in &answer.answer.records {
                lines.push(format!(
                    "{}\t{}\t{}\t{}",
                    answer.record_type.as_str(),
                    escape_controls(&answer.name),
                    escape_controls(record),
                    answer.answer.server.provider,
                ));
            }
        }
        if let Some(spf) = &self.spf {
            lines.push(format!("spf_all={}", spf_all_name(spf.all_policy())));
            for issue in spf.issues() {
                lines.push(format!("spf_issue={}", issue.tag()));
            }
        }
        if let Some(dmarc) = &self.dmarc {
            match dmarc.policy {
                Some(policy) => {
                    lines.push(format!("dmarc_policy={}", dmarc_policy_name(policy)));
                }
                None => lines.push("dmarc_policy=missing".to_string()),
            }
            for issue in dmarc.issues() {
                lines.push(format!("dmarc_issue={}", issue.tag()));
            }
        }
        if let Some(tlsrpt) = &self.tlsrpt {
            if !tlsrpt.emails.is_empty() {
                lines.push(format!(
                    "tlsrpt_emails={}",
                    escape_controls(&tlsrpt.emails.join(","))
                ));
            }
            if !tlsrpt.urls.is_empty() {
                lines.push(format!(
                    "tlsrpt_urls={}",
                    escape_controls(&tlsrpt.urls.join(","))
                ));
            }
        }
        for failure in &self.failures {
            lines.push(format!(
                "failed\t{}\t{}\t{}\t{}",
                failure.record_type.as_str(),
                escape_controls(&failure.name),
                failure.error.kind.as_str(),
                escape_controls(&failure.error.detail),
            ));
        }
        lines.push(format!(
            "answers={} failed={}",
            self.answers.len(),
            self.failures.len()
        ));
        lines.join("\n") + "\n"
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use super::*;
    use crate::http::TransportFailure;

    struct FakeTransport {
        outcomes: RefCell<VecDeque<Result<Response, TransportFailure>>>,
        seen: RefCell<Vec<Request>>,
    }

    impl FakeTransport {
        fn new(outcomes: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                outcomes: RefCell::new(outcomes.into()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for FakeTransport {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.clone());
            self.outcomes.borrow_mut().pop_front().unwrap_or_else(|| {
                Err(TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "unexpected lookup".into(),
                    blocked: false,
                })
            })
        }
    }

    #[test]
    fn pool_spans_all_three_providers() {
        let config = resolver_config();
        let ips: Vec<IpAddr> = config.name_servers.iter().map(|server| server.ip).collect();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn pool_is_ipv4_only_and_prefers_cloudflare() {
        let config = resolver_config();
        assert!(config.name_servers.iter().all(|server| server.ip.is_ipv4()));
        assert_eq!(
            config.name_servers.first().map(|server| server.provider),
            Some("Cloudflare")
        );
        assert_eq!(config.timeout_secs, 2);
        assert_eq!(config.attempts, 1);
        assert!(config.ipv4_then_ipv6);
    }

    #[test]
    fn resolver_fails_over_to_next_provider() {
        let transport = FakeTransport::new(vec![
            Err(TransportFailure {
                kind: SourceOutcomeKind::TtfbTimeout,
                detail: "timed out".into(),
                blocked: false,
            }),
            Err(TransportFailure {
                kind: SourceOutcomeKind::Upstream5xx,
                detail: "servfail".into(),
                blocked: false,
            }),
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: br#"{"Status":0,"Answer":[{"data":"1.2.3.4"}]}"#.to_vec(),
                truncated: false,
            }),
        ]);
        let answer = resolve_with_pool(
            &transport,
            &ResolveQuery {
                name: "example.com".into(),
                record_type: RecordType::A,
            },
        )
        .expect("third provider succeeds");
        assert_eq!(answer.server.provider, "Google");
        assert_eq!(answer.records, ["1.2.3.4"]);
        let seen = transport.seen.borrow();
        assert!(seen[0].url.contains("cloudflare-dns.com"));
        assert!(seen[1].url.contains("dns.quad9.net"));
        assert!(seen[2].url.contains("dns.google"));
        assert_eq!(seen[0].header_value("accept"), Some("application/dns-json"));
        let timeout = seen[0].timeout.expect("DoH request is capped");
        assert!(timeout <= Duration::from_secs(2), "{timeout:?}");
        assert!(timeout >= Duration::from_millis(1500), "{timeout:?}");
    }

    #[test]
    fn resolver_returns_last_error_when_all_fail() {
        let transport = FakeTransport::new(vec![
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: br#"{"Status":0,"Answer":[]}"#.to_vec(),
                truncated: false,
            }),
            Err(TransportFailure {
                kind: SourceOutcomeKind::TtfbTimeout,
                detail: "timed out".into(),
                blocked: false,
            }),
            Err(TransportFailure {
                kind: SourceOutcomeKind::Upstream4xx,
                detail: "refused".into(),
                blocked: false,
            }),
        ]);
        let error = resolve_with_pool(
            &transport,
            &ResolveQuery {
                name: "example.com".into(),
                record_type: RecordType::Mx,
            },
        )
        .expect_err("all fail");
        assert_eq!(error.kind, ResolveErrorKind::Upstream);
        assert_eq!(error.detail, "refused");
    }

    #[test]
    fn label_and_soa_helpers_preserve_legacy_behavior() {
        assert_eq!(unescape_dns_label(r"hostmaster\.ops"), "hostmaster.ops");
        assert_eq!(unescape_dns_label(r"\038"), "&");
        assert_eq!(
            soa_rname_to_email(r"hostmaster\.ops.example.com."),
            "hostmaster.ops@example.com"
        );
        let email = soa_rname_to_email("invalid");
        assert!(email.is_empty(), "{email:?}");
    }

    fn challenge() -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: b"<html>checking your browser cloudflare</html>".to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn challenge_page_is_bot_waf_not_invalid_json_and_failsover() {
        let transport = FakeTransport::new(vec![
            Ok(challenge()),
            Err(TransportFailure {
                kind: SourceOutcomeKind::TtfbTimeout,
                detail: "timed out".into(),
                blocked: false,
            }),
            Ok(json_ok(&["1.2.3.4"])),
        ]);
        let answer = resolve_with_pool(
            &transport,
            &ResolveQuery {
                name: "example.com".into(),
                record_type: RecordType::A,
            },
        )
        .expect("third provider succeeds after a wall");
        assert_eq!(answer.server.provider, "Google");
        assert_eq!(answer.records, ["1.2.3.4"]);
    }

    #[test]
    fn truncated_body_is_truncated_not_a_partial_answer() {
        let transport = FakeTransport::new(vec![Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"Status":0,"Answer":[{"data":"1.2.3.4"}]}"#.to_vec(),
            truncated: true,
        })]);
        let error = resolve_with_config(
            &transport,
            &ResolveQuery {
                name: "example.com".into(),
                record_type: RecordType::A,
            },
            &one_server(),
        )
        .expect_err("truncated is not an answer");
        assert_eq!(error.kind, ResolveErrorKind::Truncated);
        assert_eq!(error.detail, "truncated DNS response");
    }

    #[test]
    fn rate_limit_is_not_an_empty_dns_answer() {
        let transport = FakeTransport::new(vec![Ok(Response {
            status: 429,
            headers: Vec::new(),
            body: b"retry later".to_vec(),
            truncated: false,
        })]);
        let error = resolve_with_config(
            &transport,
            &ResolveQuery {
                name: "example.com".into(),
                record_type: RecordType::A,
            },
            &one_server(),
        )
        .expect_err("429 is rate limited");
        assert_eq!(error.kind, ResolveErrorKind::RateLimited);
    }

    fn one_server() -> ResolverPoolConfig {
        ResolverPoolConfig {
            name_servers: vec![ResolverServer {
                provider: "Cloudflare",
                ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                doh_url: "https://cloudflare-dns.com/dns-query",
            }],
            timeout_secs: 2,
            attempts: 1,
            ipv4_then_ipv6: true,
        }
    }

    fn json_ok(records: &[&str]) -> Response {
        let answers = records
            .iter()
            .map(|data| format!(r#"{{"data":{}}}"#, serde_json::to_string(data).unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        Response {
            status: 200,
            headers: Vec::new(),
            body: format!(r#"{{"Status":0,"Answer":[{answers}]}}"#).into_bytes(),
            truncated: false,
        }
    }

    fn json_empty() -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"Status":0,"Answer":[]}"#.to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn query_name_accepts_domain_url_and_email_without_sending() {
        let transport = FakeTransport::new(vec![]);
        assert_eq!(query_name("Example.COM."), Some("example.com".into()));
        assert_eq!(
            query_name("https://WWW.Example.COM/path"),
            Some("www.example.com".into())
        );
        assert_eq!(
            query_name("Hostmaster@Example.COM"),
            Some("example.com".into())
        );
        assert_eq!(query_name("localhost"), None);
        assert_eq!(query_name(" "), None);
        let none = lookup_domain_with_config(&transport, "localhost", &one_server());
        assert!(none.is_none(), "{none:?}");
        let seen = transport.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn decode_txt_strips_presentation_quotes_and_concatenates() {
        assert_eq!(decode_txt(r#""v=spf1 -all""#), "v=spf1 -all");
        assert_eq!(decode_txt("v=spf1 -all"), "v=spf1 -all");
        assert_eq!(decode_txt(r#""hello" "world""#), "helloworld");
    }

    #[test]
    fn lookup_parses_mail_records_and_keeps_partial_failures() {
        let transport = FakeTransport::new(vec![
            Ok(json_ok(&["93.184.216.34"])),
            Ok(json_empty()),
            Ok(json_ok(&["10 mail.example.com."])),
            Ok(json_ok(&["a.iana-servers.net."])),
            Ok(json_ok(&[r#""v=spf1 -all""#])),
            Ok(json_ok(&[r#""v=DMARC1; p=reject""#])),
            Ok(json_ok(&["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"])),
        ]);
        let report = lookup_domain_with_config(&transport, "example.com", &one_server())
            .expect("valid domain");
        assert_eq!(report.domain, "example.com");
        assert_eq!(report.answers.len(), 6);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].record_type, RecordType::Aaaa);
        assert_eq!(
            report.spf.as_ref().map(spf::SpfRecord::all_policy),
            Some(AllPolicy::HardFail)
        );
        assert_eq!(
            report.dmarc.as_ref().and_then(|record| record.policy),
            Some(DmarcPolicy::Reject)
        );
        assert_eq!(
            report
                .tlsrpt
                .as_ref()
                .map(|record| record.emails.as_slice()),
            Some(["tlsrpt@example.com".to_string()].as_slice())
        );
        let rendered = report.render();
        assert!(rendered.contains("spf_all=hardfail"), "{rendered}");
        assert!(rendered.contains("dmarc_policy=reject"), "{rendered}");
        assert!(
            rendered.contains("tlsrpt_emails=tlsrpt@example.com"),
            "{rendered}"
        );
        assert!(
            rendered.contains("failed\tAAAA\texample.com\tempty"),
            "{rendered}"
        );
        assert!(rendered.contains("answers=6 failed=1"), "{rendered}");
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 7);
        assert!(seen[4].url.contains("name=example.com") && seen[4].url.contains("type=TXT"));
        assert!(seen[5].url.contains("name=_dmarc.example.com"));
        assert!(seen[6].url.contains("name=_smtp._tls.example.com"));
    }

    #[test]
    fn lookup_all_failures_are_explicit_not_a_clean_negative() {
        let transport = FakeTransport::new(vec![
            Ok(json_empty()),
            Ok(json_empty()),
            Ok(json_empty()),
            Ok(json_empty()),
            Ok(json_empty()),
            Ok(json_empty()),
            Ok(json_empty()),
        ]);
        let report = lookup_domain_with_config(&transport, "missing.example", &one_server())
            .expect("valid domain");
        let answers_empty = report.answers.is_empty();
        assert!(answers_empty, "{:?}", report.answers);
        assert_eq!(report.failures.len(), 7);
        assert!(report.spf.is_none());
        assert!(report.dmarc.is_none());
        assert!(report.tlsrpt.is_none());
        assert!(report.render().contains("answers=0 failed=7"));
    }
}
