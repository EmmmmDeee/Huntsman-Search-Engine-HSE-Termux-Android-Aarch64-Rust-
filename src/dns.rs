//! DNS helpers rebuilt from `util/dns`.
//! The network-facing resolver pool uses the shared HTTP transport so tests use fakes.

use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;

use crate::{
    http::{Request, Response, Transport, TransportFailure},
    source_outcome::SourceOutcomeKind,
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
pub fn resolve_with_pool<T: Transport>(
    transport: &T,
    query: &ResolveQuery,
) -> Result<ResolveAnswer, ResolveError> {
    resolve_with_config(transport, query, &resolver_config())
}

/// # Errors
/// Returns a transport, HTTP, parse, or empty-answer error if no configured resolver
/// yields at least one record.
pub fn resolve_with_config<T: Transport>(
    transport: &T,
    query: &ResolveQuery,
    config: &ResolverPoolConfig,
) -> Result<ResolveAnswer, ResolveError> {
    let mut last_error = None;
    for server in &config.name_servers {
        let request = build_request(server, query);
        match transport.send(&request) {
            Ok(response) => match parse_response(&response) {
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
            Err(failure) => last_error = Some(map_transport_failure(failure)),
        }
    }
    Err(last_error.unwrap_or(ResolveError {
        kind: ResolveErrorKind::Upstream,
        detail: "resolver pool is empty".into(),
    }))
}

fn build_request(server: &ResolverServer, query: &ResolveQuery) -> Request {
    Request::get(format!(
        "{}?name={}&type={}",
        server.doh_url,
        query.name,
        query.record_type.as_str()
    ))
    .header("accept", "application/dns-json")
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

fn map_transport_failure(failure: TransportFailure) -> ResolveError {
    let kind = match failure.kind {
        SourceOutcomeKind::TtfbTimeout | SourceOutcomeKind::BodyTimeout => {
            ResolveErrorKind::Timeout
        }
        _ => ResolveErrorKind::Upstream,
    };
    ResolveError {
        kind,
        detail: failure.detail,
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

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use super::*;

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
}
