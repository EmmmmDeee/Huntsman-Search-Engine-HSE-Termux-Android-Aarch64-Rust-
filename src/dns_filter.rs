//! Filtering resolvers: whether the public resolvers that filter malware, phishing and adult
//! content block a name, as Spiderfoot's `sfp_adguard_dns`, `sfp_cleanbrowsing`,
//! `sfp_cloudflaredns`, `sfp_comodo`, `sfp_dns_for_family`, `sfp_opendns`, `sfp_quad9` and
//! `sfp_yandexdns` ask them.
//!
//! A filter blocks a name one of two ways: it answers its own block address (Cloudflare `0.0.0.0`,
//! an `OpenDNS` `146.112.61.x` address that names the category, Yandex `213.180.193.250`), or it
//! answers no address for a name the unfiltered resolvers resolve (Quad9, `CleanBrowsing`,
//! Comodo). An extended DNS error saying the answer was blocked, censored or filtered (RFC 8914)
//! is a block under either.
//!
//! A filter is asked over DNS-over-HTTPS in the RFC 8484 wire form (see [`crate::dns_wire`]) where
//! it serves that over HTTP/1.1, so nothing on the path answers for it. Comodo, which offers no
//! DNS-over-HTTPS, and Quad9, DNS for Family and Yandex, whose DNS-over-HTTPS needs HTTP/2, are
//! asked over UDP at their own servers, as Spiderfoot asks every filter; a network that answers
//! port 53 itself, as some carriers and sandboxes do, then answers for them.
//!
//! So before trusting a filter the lookup asks a name the filter is known to block, its test
//! point. A filter that does not block it, answers with an error or does not answer says so on its
//! row instead of "not blocked". Comodo has no known test point, so its answer is read only when
//! another filter asked over UDP blocked its test point, proving port 53 reaches the filters' own
//! servers, and its "not blocked" still says it is unverified. The test points are also how this module knows that `AdGuard`'s default filter and
//! DNS for Family now answer `0.0.0.0` for what they block, which Spiderfoot, still looking for
//! `94.140.14.35` and `159.69.10.249`, reads as not blocked. Every block is kept with the filter,
//! the resolver, the answer and its records, and any extended error; a threat filter's block is a
//! malicious verdict, a content filter's only a block. Each filter family is its own source.

use crate::clock;
use crate::dns::{self, DomainDns, RecordType, ResolveErrorKind, ResolveQuery};
use crate::dns_wire::{self, A, AAAA, Message, NOERROR, NXDOMAIN};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, TransportFailure};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::tags;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// How a filter is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolver {
    /// DNS-over-HTTPS at this URL, in the wire form.
    Doh(&'static str),
    /// Plain DNS over UDP to these servers, the second asked when the first does not answer.
    Udp([Ipv4Addr; 2]),
}

impl Resolver {
    /// The resolver as a row and a record name it: the URL without its scheme, or the server.
    #[must_use]
    pub fn endpoint(&self) -> String {
        match self {
            Self::Doh(url) => url.trim_start_matches("https://").to_owned(),
            Self::Udp(servers) => servers[0].to_string(),
        }
    }
}

/// How a filter says it blocks a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Any of these answers is a block, for the filter's own reason.
    Answers(&'static [&'static str]),
    /// Each of these answers is a block for its own reason, and whether that reason is a threat.
    Coded(&'static [(&'static str, &'static str, bool)]),
    /// No address, for a name the unfiltered resolvers resolve, is a block.
    NoAddress,
}

/// One filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filter {
    /// The source label: Spiderfoot's module name without `sfp_`.
    pub source: &'static str,
    /// What a block says, as Spiderfoot writes it.
    pub reason: &'static str,
    /// A block is a threat verdict (malware, phishing, botnets), not only a content category.
    pub threat: bool,
    pub resolver: Resolver,
    pub signal: Signal,
    /// A name the filter is known to block, asked before trusting it.
    pub test: Option<&'static str>,
}

/// The null answers filters give for what they block, IPv4 and IPv6.
const NULL: &[&str] = &["0.0.0.0", "::"];

/// Every filter asked, in order.
pub const FILTERS: &[Filter] = &[
    Filter {
        source: "adguard_dns",
        reason: "AdGuard - Default Filter",
        threat: false,
        resolver: Resolver::Doh("https://dns.adguard-dns.com/dns-query"),
        signal: Signal::Answers(&["94.140.14.35", "0.0.0.0", "::"]),
        test: Some("doubleclick.net"),
    },
    Filter {
        source: "adguard_dns",
        reason: "AdGuard - Family Filter",
        threat: false,
        resolver: Resolver::Doh("https://family.adguard-dns.com/dns-query"),
        signal: Signal::Answers(&["94.140.14.35", "0.0.0.0", "::"]),
        test: Some("exampleadultsite.com"),
    },
    Filter {
        source: "cleanbrowsing",
        reason: "CleanBrowsing DNS - Security",
        threat: true,
        resolver: Resolver::Doh("https://doh.cleanbrowsing.org/doh/security-filter/"),
        signal: Signal::NoAddress,
        test: Some("internetbadguys.com"),
    },
    Filter {
        source: "cleanbrowsing",
        reason: "CleanBrowsing DNS - Adult",
        threat: false,
        resolver: Resolver::Doh("https://doh.cleanbrowsing.org/doh/adult-filter/"),
        signal: Signal::NoAddress,
        test: Some("exampleadultsite.com"),
    },
    Filter {
        source: "cleanbrowsing",
        reason: "CleanBrowsing DNS - Family",
        threat: false,
        resolver: Resolver::Doh("https://doh.cleanbrowsing.org/doh/family-filter/"),
        signal: Signal::NoAddress,
        test: Some("exampleadultsite.com"),
    },
    Filter {
        source: "cloudflaredns",
        reason: "CloudFlare - Malware",
        threat: true,
        resolver: Resolver::Doh("https://security.cloudflare-dns.com/dns-query"),
        signal: Signal::Answers(NULL),
        test: Some("malware.testcategory.com"),
    },
    Filter {
        source: "cloudflaredns",
        reason: "CloudFlare - Family",
        threat: false,
        resolver: Resolver::Doh("https://family.cloudflare-dns.com/dns-query"),
        signal: Signal::Answers(NULL),
        test: Some("nudity.testcategory.com"),
    },
    Filter {
        source: "comodo",
        reason: "Comodo Secure DNS",
        threat: true,
        resolver: Resolver::Udp([Ipv4Addr::new(8, 26, 56, 26), Ipv4Addr::new(8, 20, 247, 20)]),
        signal: Signal::NoAddress,
        test: None,
    },
    Filter {
        source: "dns_for_family",
        reason: "DNS for Family",
        threat: false,
        resolver: Resolver::Udp([
            Ipv4Addr::new(94, 130, 180, 225),
            Ipv4Addr::new(78, 47, 64, 161),
        ]),
        signal: Signal::Answers(&["159.69.10.249", "0.0.0.0", "::"]),
        test: Some("exampleadultsite.com"),
    },
    Filter {
        source: "opendns",
        reason: "OpenDNS - Blocked",
        threat: false,
        resolver: Resolver::Doh("https://doh.familyshield.opendns.com/dns-query"),
        signal: Signal::Coded(&[
            ("146.112.61.105", "OpenDNS - Botnet", true),
            ("146.112.61.106", "OpenDNS - Adult", false),
            ("146.112.61.107", "OpenDNS - Malware", true),
            ("146.112.61.108", "OpenDNS - Phishing", true),
            ("146.112.61.109", "OpenDNS - Blocked", false),
            ("146.112.61.110", "OpenDNS - Malware", true),
        ]),
        test: Some("internetbadguys.com"),
    },
    Filter {
        source: "quad9",
        reason: "Quad9",
        threat: true,
        resolver: Resolver::Udp([Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)]),
        signal: Signal::NoAddress,
        test: Some("isitblocked.org"),
    },
    Filter {
        source: "yandexdns",
        reason: "Yandex - Blocked",
        threat: false,
        resolver: Resolver::Udp([Ipv4Addr::new(77, 88, 8, 7), Ipv4Addr::new(77, 88, 8, 3)]),
        signal: Signal::Coded(&[
            ("213.180.193.250", "Yandex - Infected", true),
            ("93.158.134.250", "Yandex - Adult", false),
        ]),
        test: Some("pornhub.com"),
    },
];

/// The longest one filter question may take.
const DOH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

/// The name is what was asked about: a block is the filter's own answer.
const BLOCKED_CONFIDENCE: f64 = 0.90;

/// What the unfiltered resolvers say about a name: what a filter's missing answer is read against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unfiltered {
    /// Its addresses: the IPv4 ones when it has any, else the IPv6 ones.
    Resolves(Vec<IpAddr>),
    /// No such name, or no address of either type.
    Nowhere,
    /// The unfiltered resolvers did not answer, and why.
    Unanswered(String),
}

impl Unfiltered {
    /// Ask the unfiltered resolvers (see [`dns::resolve_with_pool`]) for `name`'s IPv4 addresses,
    /// then its IPv6 ones.
    #[must_use]
    pub fn ask<T: Transport + ?Sized>(transport: &T, name: &str) -> Self {
        for record_type in [RecordType::A, RecordType::Aaaa] {
            let query = ResolveQuery {
                name: name.to_owned(),
                record_type,
            };
            match dns::resolve_with_pool(transport, &query) {
                Ok(answer) => {
                    return Self::Resolves(
                        answer
                            .records
                            .iter()
                            .filter_map(|r| r.parse().ok())
                            .collect(),
                    );
                }
                Err(error) if error.kind == ResolveErrorKind::Empty => {}
                Err(error) => return Self::Unanswered(error.detail),
            }
        }
        Self::Nowhere
    }

    /// What a domain lookup's own A and AAAA answers (see [`dns::lookup_domain`]) say, so the
    /// domain is not asked twice. **Pure.**
    #[must_use]
    pub fn from_records(records: &DomainDns) -> Self {
        let addresses = |wanted: RecordType| -> Vec<IpAddr> {
            records
                .answers
                .iter()
                .filter(|answer| answer.record_type == wanted)
                .flat_map(|answer| &answer.answer.records)
                .filter_map(|record| record.parse().ok())
                .collect()
        };
        for wanted in [RecordType::A, RecordType::Aaaa] {
            let found = addresses(wanted);
            if !found.is_empty() {
                return Self::Resolves(found);
            }
        }
        records
            .failures
            .iter()
            .find(|failure| {
                matches!(failure.record_type, RecordType::A | RecordType::Aaaa)
                    && failure.error.kind != ResolveErrorKind::Empty
            })
            .map_or(Self::Nowhere, |failure| {
                Self::Unanswered(failure.error.detail.clone())
            })
    }

    /// The record type the filters are asked for: AAAA for a name with only IPv6 addresses.
    fn kind(&self) -> u16 {
        match self {
            Self::Resolves(addresses)
                if !addresses.is_empty() && addresses.iter().all(IpAddr::is_ipv6) =>
            {
                AAAA
            }
            _ => A,
        }
    }
}

/// One block: what the filter answered and what that means.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Block {
    answer: String,
    reason: String,
    threat: bool,
    records: String,
    extended: Option<String>,
    /// For a block by no address, where the unfiltered resolvers resolve the name.
    elsewhere: Option<String>,
}

/// What one filter said.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Blocked(Block),
    /// Not blocked, with what it answered.
    NotBlocked(String),
    /// The filter cannot be trusted for this lookup: the kind of failure and why.
    Untrusted(SourceOutcomeKind, String),
}

/// What the filters say about `name`, whose unfiltered answer is `unfiltered`: each block as
/// evidence on it, and one row per source the transport's lookup asks.
#[must_use]
pub fn check<T: Transport + ?Sized + Sync>(
    transport: &T,
    name: &str,
    unfiltered: &Unfiltered,
    scan_id: &str,
    now_unix: u64,
) -> (Vec<Entity>, Vec<SourceExecutionOutcome>) {
    let kind = unfiltered.kind();
    let filters: Vec<&Filter> = FILTERS
        .iter()
        .filter(|filter| transport.runs_module(filter.source))
        .collect();
    let asked = dns::ask_all(
        &filters,
        |filter| ask(transport, filter, name, kind, unfiltered, now_unix),
        unreachable,
    );
    let mut verdicts: Vec<(&Filter, Verdict)> = filters
        .into_iter()
        .zip(asked)
        .map(|(filter, verdict)| {
            (
                filter,
                verdict.unwrap_or_else(|| {
                    Verdict::Untrusted(
                        SourceOutcomeKind::Inconclusive,
                        "not asked: the first filters asked could not be reached".to_owned(),
                    )
                }),
            )
        })
        .collect();
    let witness = udp_witness(&verdicts);
    if witness.is_none() {
        distrust_unwitnessed_udp(&mut verdicts);
    }
    let mut entities = Vec::new();
    for (filter, verdict) in &verdicts {
        if let Verdict::Blocked(block) = verdict {
            push_entity(
                &mut entities,
                EntityKind::Domain,
                name,
                BLOCKED_CONFIDENCE,
                scan_id,
                evidence(filter, block, scan_id),
                if block.threat {
                    &[tags::MALICIOUS]
                } else {
                    &[]
                },
            );
        }
    }
    (entities, rows(&verdicts, witness, now_unix))
}

/// The first filter asked over UDP that blocked its test point: proof that UDP port 53 reaches the
/// filters' own servers from this network. A network that answers port 53 itself, as some
/// carriers and sandboxes do, answers for every filter asked over UDP alike.
fn udp_witness<'a>(verdicts: &[(&'a Filter, Verdict)]) -> Option<&'a Filter> {
    verdicts
        .iter()
        .find(|(filter, verdict)| {
            matches!(filter.resolver, Resolver::Udp(_))
                && filter.test.is_some()
                && !matches!(verdict, Verdict::Untrusted(..))
        })
        .map(|(filter, _)| *filter)
}

/// With no witness that UDP reaches the filters, what a filter asked over UDP without a test point
/// of its own answered may be the network's answer, not the filter's: it is kept in the row and
/// not read as a verdict either way.
fn distrust_unwitnessed_udp(verdicts: &mut [(&Filter, Verdict)]) {
    for (filter, verdict) in verdicts {
        if filter.test.is_some() || !matches!(filter.resolver, Resolver::Udp(_)) {
            continue;
        }
        let said = match verdict {
            Verdict::Blocked(block) => format!("blocked ({})", block.answer),
            Verdict::NotBlocked(answer) => format!("not blocked ({answer})"),
            Verdict::Untrusted(..) => continue,
        };
        *verdict = Verdict::Untrusted(
            SourceOutcomeKind::Inconclusive,
            format!(
                "answered {said}, untrusted: no filter asked over UDP blocked its test point, so \
                 this network may answer port 53 itself"
            ),
        );
    }
}

/// Whether a verdict says the filter could not be reached at all, as when the network is down:
/// enough of those before any answer and the rest are not asked (see [`dns::ask_all`]).
fn unreachable(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Untrusted(kind, _) if kind.is_transport_failure())
}

fn evidence(filter: &Filter, block: &Block, scan_id: &str) -> Evidence {
    let endpoint = filter.resolver.endpoint();
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(filter.source, scan_id),
        format!(
            "Blocked by {} ({endpoint}): answered {}",
            block.reason, block.answer
        ),
    )
    .with_attr("dns_filter", block.reason.as_str())
    .with_attr(
        "dns_filter_threat",
        if block.threat { "true" } else { "false" },
    )
    .with_attr("dns_filter_resolver", endpoint.as_str())
    .with_attr("dns_filter_answer", block.answer.as_str());
    if block.threat {
        evidence = evidence.with_attr("blocklists", block.reason.as_str());
    }
    if !block.records.is_empty() {
        evidence = evidence.with_attr("dns_filter_records", block.records.as_str());
    }
    if let Some(extended) = &block.extended {
        evidence = evidence.with_attr("dns_filter_extended_error", extended.as_str());
    }
    if let Some(elsewhere) = &block.elsewhere {
        evidence = evidence.with_attr("dns_filter_resolves_elsewhere", elsewhere.as_str());
    }
    evidence
}

/// One row per source, joining what each of its filters said.
fn rows(
    verdicts: &[(&Filter, Verdict)],
    witness: Option<&Filter>,
    now_unix: u64,
) -> Vec<SourceExecutionOutcome> {
    let mut sources: Vec<&str> = verdicts.iter().map(|(filter, _)| filter.source).collect();
    sources.dedup();
    sources
        .into_iter()
        .map(|source| {
            let mine: Vec<&(&Filter, Verdict)> = verdicts
                .iter()
                .filter(|(filter, _)| filter.source == source)
                .collect();
            let detail = mine
                .iter()
                .map(|(filter, verdict)| {
                    let said = match verdict {
                        Verdict::Blocked(block) => {
                            format!("blocked as {} ({})", block.reason, block.answer)
                        }
                        Verdict::NotBlocked(answer) if filter.test.is_none() => match witness {
                            Some(witness) => format!(
                                "not blocked ({answer}); unverified, no known test point, though \
                                 UDP reaches the filters ({} blocked its test point)",
                                witness.source
                            ),
                            None => {
                                format!("not blocked ({answer}); unverified, no known test point")
                            }
                        },
                        Verdict::NotBlocked(answer) => format!("not blocked ({answer})"),
                        Verdict::Untrusted(_, why) => why.clone(),
                    };
                    format!("{}: {said}", filter.resolver.endpoint())
                })
                .collect::<Vec<_>>()
                .join("; ");
            let blocked = mine
                .iter()
                .filter(|(_, verdict)| matches!(verdict, Verdict::Blocked(_)))
                .count();
            // The source's row is refused only when every server under it was refused, so take the
            // first untrusted kind that was not a refusal, else the first.
            let untrusted_kinds = || {
                mine.iter().filter_map(|(_, verdict)| match verdict {
                    Verdict::Untrusted(kind, _) => Some(*kind),
                    _ => None,
                })
            };
            let untrusted = untrusted_kinds()
                .find(|kind| *kind != SourceOutcomeKind::RefusedBeforeSending)
                .or_else(|| untrusted_kinds().next());
            let answered = mine
                .iter()
                .any(|(_, verdict)| !matches!(verdict, Verdict::Untrusted(..)));
            match (blocked, untrusted) {
                (0, Some(kind)) if !answered => {
                    SourceExecutionOutcome::failed(source, now_unix, kind, None, &detail)
                }
                (0, _) => SourceExecutionOutcome::valid_zero(source, now_unix).with_detail(detail),
                (count, _) => {
                    SourceExecutionOutcome::success(source, now_unix, count).with_detail(detail)
                }
            }
        })
        .collect()
}

/// Ask `filter` about `name` with record type `kind`, after its test point.
fn ask<T: Transport + ?Sized>(
    transport: &T,
    filter: &Filter,
    name: &str,
    kind: u16,
    unfiltered: &Unfiltered,
    now_unix: u64,
) -> Verdict {
    if let Some(test) = filter.test {
        let known = Unfiltered::Resolves(Vec::new());
        match exchange(transport, filter, test, A, now_unix) {
            Err((kind, why)) => return Verdict::Untrusted(kind, why),
            Ok(message) => match read(filter, &message, &known) {
                Verdict::Blocked(_) => {}
                Verdict::NotBlocked(answer) => {
                    return Verdict::Untrusted(
                        SourceOutcomeKind::Inconclusive,
                        format!("did not block its test point {test} (answered {answer})"),
                    );
                }
                untrusted @ Verdict::Untrusted(..) => return untrusted,
            },
        }
    }
    match exchange(transport, filter, name, kind, now_unix) {
        Err((kind, why)) => Verdict::Untrusted(kind, why),
        Ok(message) => read(filter, &message, unfiltered),
    }
}

/// Why a filter could not be trusted: the kind of failure and why.
type Failure = (SourceOutcomeKind, String);

/// Send `filter` the question and read back its answer to that question.
fn exchange<T: Transport + ?Sized>(
    transport: &T,
    filter: &Filter,
    name: &str,
    kind: u16,
    now_unix: u64,
) -> Result<Message, Failure> {
    let drift = |why: String| (SourceOutcomeKind::ProtocolDrift, why);
    // RFC 8484 asks for id 0 over HTTPS, so answers cache; over UDP the id guards the answer.
    let id = match filter.resolver {
        Resolver::Doh(_) => 0,
        Resolver::Udp(_) => fresh_id(),
    };
    let query = dns_wire::query(id, name, kind)
        .map_err(|error| (SourceOutcomeKind::Inconclusive, error.to_string()))?;
    let body = match filter.resolver {
        Resolver::Doh(url) => doh(transport, filter, url, query, now_unix)?,
        Resolver::Udp(servers) => udp(transport, servers, &query)?,
    };
    let message =
        dns_wire::parse(&body).map_err(|error| drift(format!("not a DNS answer: {error}")))?;
    let same_question = message
        .question
        .as_ref()
        .is_some_and(|q| q.kind == kind && q.name.eq_ignore_ascii_case(name.trim_end_matches('.')));
    if message.id != id || !same_question {
        return Err(drift("answered another question".to_owned()));
    }
    if message.truncated {
        return Err((
            SourceOutcomeKind::Inconclusive,
            "its answer was truncated".to_owned(),
        ));
    }
    Ok(message)
}

fn doh<T: Transport + ?Sized>(
    transport: &T,
    filter: &Filter,
    url: &str,
    query: Vec<u8>,
    now_unix: u64,
) -> Result<Vec<u8>, Failure> {
    let request = Request::post(url, query)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .with_timeout(DOH_TIMEOUT);
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects(),
        filter.source,
        now_unix,
    )
    // `fetch` errors only before anything is sent (a blocked egress, an unsendable URL).
    .map_err(|error| (SourceOutcomeKind::RefusedBeforeSending, error.to_string()))?;
    match fetched.response {
        Some(response) if response.status == 200 && !response.truncated => Ok(response.body),
        Some(response) => Err((fetched.outcome.kind, format!("HTTP {}", response.status))),
        None => Err((
            fetched.outcome.kind,
            format!(
                "no answer ({})",
                fetched.outcome.detail.as_deref().unwrap_or("no response")
            ),
        )),
    }
}

fn udp<T: Transport + ?Sized>(
    transport: &T,
    servers: [Ipv4Addr; 2],
    query: &[u8],
) -> Result<Vec<u8>, Failure> {
    let mut last: Option<TransportFailure> = None;
    for server in servers {
        match transport.exchange_udp(SocketAddr::new(IpAddr::V4(server), 53), query) {
            Ok(body) => return Ok(body),
            // Keep the last unblocked failure over a blocked one: the filter is refused only when
            // every server asked was blocked before sending, so one server that answered the
            // socket (and then timed out or the like) means it was reachable.
            Err(failure) => {
                if !failure.blocked || last.as_ref().is_none_or(|kept| kept.blocked) {
                    last = Some(failure);
                }
            }
        }
    }
    Err(last.map_or_else(
        || (SourceOutcomeKind::ConnectFailure, "no server".to_owned()),
        |failure| {
            let kind = if failure.blocked {
                SourceOutcomeKind::RefusedBeforeSending
            } else {
                failure.kind
            };
            (kind, format!("no answer ({})", failure.detail))
        },
    ))
}

/// A query id for one UDP question: the clock's nanoseconds, folded. **Not secret:** the
/// connected socket already takes only the server's datagrams.
fn fresh_id() -> u16 {
    let nanos = clock::unix_subsec_nanos();
    u16::try_from((nanos ^ (nanos >> 16)) & 0xffff).unwrap_or_default()
}

/// What `message` from `filter` says about the name `unfiltered` describes. **Pure.**
fn read(filter: &Filter, message: &Message, unfiltered: &Unfiltered) -> Verdict {
    let addresses: Vec<String> = message
        .addresses()
        .iter()
        .map(ToString::to_string)
        .collect();
    let answer = if !addresses.is_empty() {
        addresses.join(", ")
    } else if message.rcode == NOERROR {
        "no address".to_owned()
    } else {
        dns_wire::rcode_name(message.rcode)
    };
    let withheld = message
        .extended_errors
        .iter()
        .any(dns_wire::ExtendedError::withheld);
    if !matches!(message.rcode, NOERROR | NXDOMAIN) && !withheld {
        return Verdict::Untrusted(
            SourceOutcomeKind::Inconclusive,
            format!("answered {answer}"),
        );
    }
    let block = |answer: &str, reason: &str, threat: bool, elsewhere: Option<String>| {
        Verdict::Blocked(Block {
            answer: answer.to_owned(),
            reason: reason.to_owned(),
            threat,
            records: message
                .answers
                .iter()
                .map(|r| {
                    format!(
                        "{} {} {}",
                        r.name,
                        dns_wire::type_name(r.kind),
                        r.data.presentation()
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
            extended: (!message.extended_errors.is_empty()).then(|| {
                message
                    .extended_errors
                    .iter()
                    .map(dns_wire::ExtendedError::describe)
                    .collect::<Vec<_>>()
                    .join("; ")
            }),
            elsewhere,
        })
    };
    let coded = match filter.signal {
        Signal::Answers(blocks) => addresses
            .iter()
            .find(|address| blocks.contains(&address.as_str()))
            .map(|address| (address.as_str(), filter.reason, filter.threat)),
        Signal::Coded(codes) => addresses.iter().find_map(|address| {
            codes
                .iter()
                .find(|(code, _, _)| code == address)
                .map(|(_, reason, threat)| (address.as_str(), *reason, *threat))
        }),
        Signal::NoAddress => None,
    };
    if let Some((address, reason, threat)) = coded {
        return block(address, reason, threat, None);
    }
    if withheld {
        return block(&answer, filter.reason, filter.threat, None);
    }
    if filter.signal != Signal::NoAddress || !addresses.is_empty() {
        return Verdict::NotBlocked(answer);
    }
    match unfiltered {
        Unfiltered::Resolves(elsewhere) => block(
            &answer,
            filter.reason,
            filter.threat,
            (!elsewhere.is_empty()).then(|| {
                elsewhere
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            }),
        ),
        Unfiltered::Nowhere => Verdict::NotBlocked(format!("{answer}; no resolver resolves it")),
        Unfiltered::Unanswered(why) => Verdict::Untrusted(
            SourceOutcomeKind::Inconclusive,
            format!(
                "answered {answer}, and the unfiltered resolvers did not answer to compare ({why})"
            ),
        ),
    }
}

#[cfg(test)]
mod tests;
