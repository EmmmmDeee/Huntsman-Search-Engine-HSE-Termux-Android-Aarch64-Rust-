//! DNS helpers rebuilt from `util/dns`.
//! DNS-over-HTTPS queries go through `fetch` over an injected transport so tests
//! use fakes and a challenge page is a wall, not a JSON parse error.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// The module name of resolving a name or an address another source found, forward (A and
/// AAAA) or reverse (PTR), as Spiderfoot's `sfp_dnsresolve` does: on outcome rows and evidence.
pub const RESOLVE_SOURCE: &str = "dnsresolve";

/// Names or addresses resolved at once by [`ask_all`].
pub const ASK_WORKERS: usize = 8;
/// Names or addresses that may fail before the first answer, before [`ask_all`] stops asking: the
/// resolvers are unreachable, so every other one would fail the same way.
pub const ASK_FAILURES_BEFORE_ABORT: usize = 4;

/// `ask` for each item, [`ASK_WORKERS`] at a time, each answer at its item's index. Once
/// [`ASK_FAILURES_BEFORE_ABORT`] answers are `failed` before any other came back, no further item
/// is asked and those items' answers are `None`; so is the answer of a worker that panicked.
pub fn ask_all<I, R, F, B>(items: &[I], ask: F, failed: B) -> Vec<Option<R>>
where
    I: Sync,
    R: Send,
    F: Fn(&I) -> R + Sync,
    B: Fn(&R) -> bool + Sync,
{
    let next = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    let answered = AtomicUsize::new(0);
    let work = || {
        let mut mine = Vec::new();
        loop {
            if answered.load(Ordering::SeqCst) == 0
                && failures.load(Ordering::SeqCst) >= ASK_FAILURES_BEFORE_ABORT
            {
                break;
            }
            let index = next.fetch_add(1, Ordering::SeqCst);
            let Some(item) = items.get(index) else {
                break;
            };
            let result = ask(item);
            let counter = if failed(&result) {
                &failures
            } else {
                &answered
            };
            counter.fetch_add(1, Ordering::SeqCst);
            mine.push((index, result));
        }
        mine
    };
    let mut out: Vec<Option<R>> = items.iter().map(|_| None).collect();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..ASK_WORKERS.min(items.len()))
            .map(|_| scope.spawn(work))
            .collect();
        for worker in workers {
            for (index, result) in worker.join().unwrap_or_default() {
                out[index] = Some(result);
            }
        }
    });
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Mx,
    Ns,
    Soa,
    Txt,
    Ptr,
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
            Self::Ptr => "PTR",
        }
    }

    /// The IANA DNS record-type code carried in the `DoH` JSON `type` field of each answer.
    /// Used to drop answers of another type, such as a `CNAME` in the chain ahead of the
    /// record that was queried.
    #[must_use]
    pub const fn doh_code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Soa => 6,
            Self::Mx => 15,
            Self::Ptr => 12,
            Self::Txt => 16,
            Self::Aaaa => 28,
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

    /// The outcome kind of a query no resolver answered with this error. **Pure.**
    #[must_use]
    pub const fn outcome_kind(self) -> SourceOutcomeKind {
        match self {
            Self::Timeout => SourceOutcomeKind::TtfbTimeout,
            Self::RateLimited => SourceOutcomeKind::RateLimited,
            Self::BotWaf => SourceOutcomeKind::BotWaf,
            Self::Upstream | Self::Truncated | Self::Empty => SourceOutcomeKind::Inconclusive,
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

/// The DNS RCODE for a name that does not exist (RFC 1035 section 4.1.1).
const DNS_NXDOMAIN: u32 = 3;

/// A DNS JSON API answer. `Status` is the RCODE and every resolver sends it; a 200 JSON body
/// without one (a captive portal's, an API gateway's error) is not a DNS answer at all, so it
/// is `None` here rather than a default of NOERROR.
#[derive(Debug, Deserialize, Default)]
struct DnsJsonResponse {
    #[serde(rename = "Status")]
    status: Option<u32>,
    #[serde(rename = "Answer", default)]
    answers: Vec<DnsJsonAnswer>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DnsJsonAnswer {
    #[serde(rename = "type", default)]
    rtype: u16,
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
            // DNS.SB (xTom): unfiltered, no query logs, and it answers the DNS JSON API on
            // 443. Quad9 was here before, but its `/dns-query` speaks only RFC 8484 wire
            // format and answered every JSON query with HTTP 400, so that leg never resolved
            // anything (its JSON API sits on port 5053, which mobile networks and proxies
            // often block).
            ResolverServer {
                provider: "DNS.SB",
                ip: IpAddr::V4(Ipv4Addr::new(185, 222, 222, 222)),
                doh_url: "https://doh.dns.sb/dns-query",
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
/// never an invalid-JSON parse. A resolver that answers NXDOMAIN, or no record of the
/// queried type, ends the search with [`ResolveErrorKind::Empty`]: that answer comes from
/// the zone, so only a failed resolver hands the query to the next one.
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
            Ok(fetched) => match interpret_fetched(&fetched, query.record_type) {
                Ok(records) if !records.is_empty() => {
                    return Ok(ResolveAnswer {
                        server: server.clone(),
                        records,
                    });
                }
                // NXDOMAIN, or a name with no record of this type, is the zone's own answer:
                // every resolver gives it, so asking the next one only repeats the question
                // (and tells one more provider what is being looked up).
                Ok(_) => {
                    return Err(ResolveError {
                        kind: ResolveErrorKind::Empty,
                        detail: "empty DNS answer".into(),
                    });
                }
                Err(error) if error.kind == ResolveErrorKind::Empty => return Err(error),
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
        &append_query_param(
            &append_query_param(server.doh_url, "name", &query.name),
            "type",
            query.record_type.as_str(),
        ),
        "do",
        "1",
    );
    Request::get(url)
        .header("accept", "application/dns-json")
        .with_timeout(timeout)
}

fn interpret_fetched(
    fetched: &Fetched,
    record_type: RecordType,
) -> Result<Vec<String>, ResolveError> {
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
    if crate::classify::is_challenge(&response.text_view()) {
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
    parse_response(response, record_type)
}

fn parse_response(
    response: &Response,
    record_type: RecordType,
) -> Result<Vec<String>, ResolveError> {
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
    // A body with no RCODE is not a DNS answer, whatever else it holds: the next resolver is
    // asked rather than reading it as "no such record".
    let Some(status) = parsed.status else {
        return Err(ResolveError {
            kind: ResolveErrorKind::Upstream,
            detail: "not a DNS answer: no Status".into(),
        });
    };
    // RCODE 3 (NXDOMAIN) is authoritative: the name does not exist. Any other non-zero code
    // (SERVFAIL, REFUSED, a DNSSEC failure) is about this resolver, so the next one is asked.
    if status == DNS_NXDOMAIN {
        return Err(ResolveError {
            kind: ResolveErrorKind::Empty,
            detail: format!("dns status {status}"),
        });
    }
    if status != 0 {
        return Err(ResolveError {
            kind: ResolveErrorKind::Upstream,
            detail: format!("dns status {status}"),
        });
    }
    // Keep only answers of the queried record type. A DoH answer array may carry a CNAME
    // (or other) record ahead of the record that was asked for; its `data` is a different
    // kind of value (a host name, not an address or TXT string) and must not be reported
    // as the queried type.
    let want = record_type.doh_code();
    let records: Vec<String> = parsed
        .answers
        .into_iter()
        .filter(|answer| answer.rtype == want)
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

/// The labels a reverse name gives `ip`, without a zone: the four octets reversed (IPv4,
/// RFC 1035) or the 32 nibbles reversed (IPv6, RFC 3596). [`reverse_name`] puts them under
/// `in-addr.arpa` or `ip6.arpa`, and a DNS blocklist under its own zone. **Pure.**
#[must_use]
pub fn reversed_labels(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}")
        }
        IpAddr::V6(v6) => {
            let mut labels = String::with_capacity(63);
            for byte in v6.octets().iter().rev() {
                for nibble in [byte & 0x0f, byte >> 4] {
                    if !labels.is_empty() {
                        labels.push('.');
                    }
                    labels.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
                }
            }
            labels
        }
    }
}

/// The `in-addr.arpa` name (IPv4, RFC 1035) or nibble-format `ip6.arpa` name (IPv6, RFC 3596)
/// whose PTR records name `ip`. **Pure.**
#[must_use]
pub fn reverse_name(ip: IpAddr) -> String {
    let zone = match ip {
        IpAddr::V4(_) => "in-addr.arpa",
        IpAddr::V6(_) => "ip6.arpa",
    };
    format!("{}.{zone}", reversed_labels(ip))
}

/// The PTR records of `ip` over the `DoH` pool, as published (a trailing root dot kept).
///
/// # Errors
/// [`ResolveErrorKind::Empty`] when the zone has no PTR record for the address; any other kind
/// when no resolver answered.
pub fn lookup_ptr<T: Transport + ?Sized>(
    transport: &T,
    ip: IpAddr,
) -> Result<ResolveAnswer, ResolveError> {
    resolve_with_pool(
        transport,
        &ResolveQuery {
            name: reverse_name(ip),
            record_type: RecordType::Ptr,
        },
    )
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
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(185, 222, 222, 222))));
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
                body: br#"{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"#.to_vec(),
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
        assert!(seen[1].url.contains("doh.dns.sb"));
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
                body: br#"{"Status":2,"Answer":[]}"#.to_vec(),
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

    fn doh(body: &[u8]) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: body.to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn reverse_names_follow_rfc_1035_and_rfc_3596() {
        assert_eq!(
            reverse_name(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            "4.3.2.1.in-addr.arpa"
        );
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0x567, 0x89ab,
        ));
        assert_eq!(
            reverse_name(v6),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    /// A reverse name is its reversed labels under the family's zone, for an IPv4-mapped IPv6
    /// address too, which is named by its nibbles like any other IPv6 address.
    #[test]
    fn a_reverse_name_is_the_reversed_labels_under_the_family_zone() {
        let cases = [
            ("192.0.2.10", "10.2.0.192", "in-addr.arpa"),
            (
                "2001:db8::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
                "ip6.arpa",
            ),
            (
                "::ffff:1.2.3.4",
                "4.0.3.0.2.0.1.0.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
                "ip6.arpa",
            ),
        ];
        for (address, labels, zone) in cases {
            let ip: IpAddr = address.parse().expect("an address");
            assert_eq!(reversed_labels(ip), labels, "{address}");
            assert_eq!(reverse_name(ip), format!("{labels}.{zone}"), "{address}");
        }
    }

    /// A PTR lookup asks for the reverse name's PTR records and keeps only those, as published;
    /// a CNAME in the chain (RFC 2317 classless delegation) is not a PTR answer.
    #[test]
    fn a_ptr_lookup_asks_the_reverse_name_and_keeps_its_ptr_records() {
        let transport = FakeTransport::new(vec![Ok(doh(
            br#"{"Status":0,"Answer":[{"type":5,"data":"4.0-25.3.2.1.in-addr.arpa."},{"type":12,"data":"One.One.One.One."}]}"#,
        ))]);
        let answer = lookup_ptr(&transport, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(answer.records, ["One.One.One.One."]);
        let seen = transport.seen.borrow();
        assert!(
            seen[0].url.contains("name=1.1.1.1.in-addr.arpa"),
            "{}",
            seen[0].url
        );
        assert!(seen[0].url.contains("type=PTR"), "{}", seen[0].url);
    }

    /// NXDOMAIN and "no record of this type" come from the zone, so the first resolver's
    /// answer is final: asking DNS.SB and Google again only costs two more round trips and
    /// tells two more providers the name being looked up.
    #[test]
    fn an_authoritative_empty_answer_asks_one_resolver_only() {
        for body in [
            &br#"{"Status":3}"#[..],
            br#"{"Status":0,"Answer":[]}"#,
            br#"{"Status":0}"#,
            br#"{"Status":0,"Answer":[{"type":5,"data":"alias.example.net."}]}"#,
        ] {
            let transport = FakeTransport::new(vec![
                Ok(doh(body)),
                Ok(doh(
                    br#"{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"#,
                )),
            ]);
            let error = resolve_with_pool(
                &transport,
                &ResolveQuery {
                    name: "example.com".into(),
                    record_type: RecordType::A,
                },
            )
            .expect_err("the zone has no such record");
            assert_eq!(error.kind, ResolveErrorKind::Empty);
            assert_eq!(
                transport.seen.borrow().len(),
                1,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// SERVFAIL and REFUSED are about the resolver, not the zone, so the next one is asked;
    /// when every resolver answers so, the result is a resolver failure, not "no such record".
    #[test]
    fn a_resolver_failure_code_fails_over() {
        for status in [2, 5] {
            let transport = FakeTransport::new(vec![
                Ok(doh(format!(r#"{{"Status":{status}}}"#).as_bytes())),
                Ok(doh(
                    br#"{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"#,
                )),
            ]);
            let answer = resolve_with_pool(
                &transport,
                &ResolveQuery {
                    name: "example.com".into(),
                    record_type: RecordType::A,
                },
            )
            .expect("the second resolver answers");
            assert_eq!(answer.server.provider, "DNS.SB");
            assert_eq!(transport.seen.borrow().len(), 2);
        }
        let transport = FakeTransport::new(vec![Ok(doh(br#"{"Status":2}"#)); 3]);
        let error = resolve_with_pool(
            &transport,
            &ResolveQuery {
                name: "example.com".into(),
                record_type: RecordType::A,
            },
        )
        .expect_err("every resolver failed");
        assert_eq!(error.kind, ResolveErrorKind::Upstream);
        assert_eq!(error.detail, "dns status 2");
        assert_eq!(transport.seen.borrow().len(), 3);
    }

    /// A 200 JSON body with no `Status` is not a DNS answer (a captive portal's page, a
    /// gateway's error object), so it is the resolver's failure, never "no such record".
    #[test]
    fn a_body_without_a_status_is_a_resolver_failure_not_an_empty_answer() {
        for body in [
            &br#"{"error":"captive portal"}"#[..],
            b"{}",
            br#"{"Answer":[]}"#,
        ] {
            let transport = FakeTransport::new(vec![
                Ok(doh(body)),
                Ok(doh(
                    br#"{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"#,
                )),
            ]);
            let answer = resolve_with_pool(
                &transport,
                &ResolveQuery {
                    name: "example.com".into(),
                    record_type: RecordType::A,
                },
            )
            .expect("the second resolver answers");
            assert_eq!(answer.records, ["1.2.3.4"]);
            assert_eq!(
                transport.seen.borrow().len(),
                2,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let transport = FakeTransport::new(vec![Ok(doh(b"{}")); 3]);
        let error = resolve_with_pool(
            &transport,
            &ResolveQuery {
                name: "example.com".into(),
                record_type: RecordType::A,
            },
        )
        .expect_err("no resolver answered");
        assert_eq!(error.kind, ResolveErrorKind::Upstream);
        assert_eq!(error.detail, "not a DNS answer: no Status");
    }

    /// A domain with A and MX records but no AAAA, DMARC or TLS-RPT record: before, each of
    /// those three empty answers went to all three resolvers.
    #[test]
    fn a_typical_domain_costs_one_request_per_query() {
        let queries = planned_queries("example.com").len();
        let mut outcomes = Vec::new();
        for (name, record_type) in planned_queries("example.com") {
            outcomes.push(Ok(doh(match (name.as_str(), record_type) {
                ("example.com", RecordType::A) => {
                    br#"{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"#.as_slice()
                }
                ("example.com", RecordType::Mx) => {
                    br#"{"Status":0,"Answer":[{"type":15,"data":"10 mx.example.com."}]}"#
                }
                ("example.com", RecordType::Txt) => {
                    br#"{"Status":0,"Answer":[{"type":16,"data":"\"v=spf1 -all\""}]}"#
                }
                ("example.com", RecordType::Ns) => {
                    br#"{"Status":0,"Answer":[{"type":2,"data":"ns.example.com."}]}"#
                }
                _ => br#"{"Status":3}"#,
            })));
        }
        let transport = FakeTransport::new(outcomes);
        let dns = lookup_domain(&transport, "example.com").expect("a domain");
        assert_eq!(transport.seen.borrow().len(), queries);
        assert!(!dns.answers.is_empty());
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
            Ok(json_ok(RecordType::A, &["1.2.3.4"])),
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

    fn json_ok(rtype: RecordType, records: &[&str]) -> Response {
        let answers = records
            .iter()
            .map(|data| {
                format!(
                    r#"{{"type":{},"data":{}}}"#,
                    rtype.doh_code(),
                    serde_json::to_string(data).unwrap()
                )
            })
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
    fn a_cname_in_the_answer_chain_is_not_reported_as_the_queried_type() {
        // A real DoH answer array for a hosted _dmarc record: a CNAME (type 5) to the
        // provider, then the TXT (type 16) that was asked for. Only the TXT is a TXT value;
        // the CNAME target is a host name and must not be surfaced as a TXT record.
        let transport = FakeTransport::new(vec![Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"Status":0,"Answer":[{"type":5,"data":"ex._dmarc.provider.net."},{"type":16,"data":"v=DMARC1; p=reject"}]}"#.to_vec(),
            truncated: false,
        })]);
        let answer = resolve_with_config(
            &transport,
            &ResolveQuery {
                name: "_dmarc.example.com".into(),
                record_type: RecordType::Txt,
            },
            &one_server(),
        )
        .expect("the TXT answer is present");
        assert_eq!(
            answer.records,
            ["v=DMARC1; p=reject"],
            "the CNAME target must not be surfaced as a TXT record"
        );
    }

    #[test]
    fn an_answer_whose_only_record_is_a_cname_is_an_empty_result() {
        // An A query that returns only a CNAME (no terminal A) has no address to report,
        // so it is an empty answer, not the CNAME host name reported as an address.
        let transport = FakeTransport::new(vec![Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"Status":0,"Answer":[{"type":5,"data":"alias.example.net."}]}"#.to_vec(),
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
        .expect_err("a lone CNAME is not an A record");
        assert_eq!(error.kind, ResolveErrorKind::Empty);
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
            Ok(json_ok(RecordType::A, &["93.184.216.34"])),
            Ok(json_empty()),
            Ok(json_ok(RecordType::Mx, &["10 mail.example.com."])),
            Ok(json_ok(RecordType::Ns, &["a.iana-servers.net."])),
            Ok(json_ok(RecordType::Txt, &[r#""v=spf1 -all""#])),
            Ok(json_ok(RecordType::Txt, &[r#""v=DMARC1; p=reject""#])),
            Ok(json_ok(
                RecordType::Txt,
                &["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
            )),
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
