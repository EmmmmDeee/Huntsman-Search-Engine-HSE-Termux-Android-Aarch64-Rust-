//! DNS blocklists: whether an address or a domain is listed by Spamhaus, `SpamCop`, UCEPROTECT,
//! `DroneBL`, SORBS and SURBL, as Spiderfoot's `sfp_spamhaus`, `sfp_spamcop`, `sfp_uceprotect`,
//! `sfp_dronebl`, `sfp_sorbs` and `sfp_surbl` ask them, with Spamhaus's domain list (DBL) and
//! UCEPROTECT's third level beside them.
//!
//! A list is asked through the system resolver (see [`Transport::resolve`]): an IPv4 address as
//! its reversed octets under the zone (`2.0.0.127.zen.spamhaus.org`), an IPv6 address as its
//! reversed nibbles where the list takes IPv6, and a domain as itself. An answer in `127.0.0.0/8`
//! is a listing, and each list's codes say why. Before trusting a zone the lookup asks its RFC 5782
//! test points: the listed one (`127.0.0.2`, or the list's own test domain) must answer, and
//! `127.0.0.1` must not. A zone that does not answer its test point, refuses the resolver (Spamhaus
//! refuses public resolvers with `127.255.255.254`, SURBL with `127.0.0.1`), or lists everything is
//! reported as such on its row instead of as "not listed". Every listing is kept with the list,
//! the zone, the answer and the reason; each list is its own source, so an address on two lists is
//! two sources' verdicts.

use std::net::IpAddr;

use crate::dns::reversed_labels;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::{Transport, TransportFailure};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::tags;

/// What a zone is asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Takes {
    /// IPv4 addresses.
    Ipv4,
    /// IPv4 and IPv6 addresses.
    Addresses,
    /// Domains.
    Domains,
    /// IPv4 addresses and domains.
    Ipv4AndDomains,
}

/// How a zone's answers read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codes {
    /// Each answer address names one reason.
    Exact(&'static [(&'static str, &'static str)]),
    /// The last octet is a bit mask, each bit one reason (SURBL's `multi`).
    Bits(&'static [(u8, &'static str)]),
}

/// One blocklist zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Zone {
    /// The source label: Spiderfoot's module name without `sfp_`.
    pub source: &'static str,
    /// The list's name, as a reason starts.
    pub list: &'static str,
    pub zone: &'static str,
    pub takes: Takes,
    pub codes: Codes,
    /// Answers that refuse the question, with why.
    pub refusals: &'static [(&'static str, &'static str)],
    /// The domain the list documents as always listed, for a domain-only zone.
    pub test_domain: Option<&'static str>,
}

const SPAMHAUS_REFUSALS: &[(&str, &str)] = &[
    ("127.255.255.252", "Spamhaus rejected a malformed query"),
    (
        "127.255.255.254",
        "Spamhaus refuses queries through public or open resolvers",
    ),
    (
        "127.255.255.255",
        "Spamhaus refused the resolver for too many queries",
    ),
];

/// Every zone asked, in order.
pub const ZONES: &[Zone] = &[
    Zone {
        source: "spamhaus",
        list: "Spamhaus (Zen)",
        zone: "zen.spamhaus.org",
        takes: Takes::Addresses,
        codes: Codes::Exact(&[
            ("127.0.0.2", "Spammer"),
            ("127.0.0.3", "Spammer"),
            ("127.0.0.4", "Proxies, Trojans, etc."),
            ("127.0.0.5", "Proxies, Trojans, etc."),
            ("127.0.0.6", "Proxies, Trojans, etc."),
            ("127.0.0.7", "Proxies, Trojans, etc."),
            ("127.0.0.9", "Hijacked network (DROP)"),
            ("127.0.0.10", "Potential Spammer"),
            ("127.0.0.11", "Potential Spammer"),
        ]),
        refusals: SPAMHAUS_REFUSALS,
        test_domain: None,
    },
    Zone {
        source: "spamhaus",
        list: "Spamhaus (DBL)",
        zone: "dbl.spamhaus.org",
        takes: Takes::Domains,
        codes: Codes::Exact(&[
            ("127.0.1.2", "Spam domain"),
            ("127.0.1.4", "Phishing domain"),
            ("127.0.1.5", "Malware domain"),
            ("127.0.1.6", "Botnet command and control domain"),
            ("127.0.1.102", "Abused legitimate spam domain"),
            ("127.0.1.103", "Abused spammed redirector domain"),
            ("127.0.1.104", "Abused legitimate phishing domain"),
            ("127.0.1.105", "Abused legitimate malware domain"),
            (
                "127.0.1.106",
                "Abused legitimate botnet command and control domain",
            ),
        ]),
        refusals: SPAMHAUS_REFUSALS,
        test_domain: Some("dbltest.com"),
    },
    Zone {
        source: "spamcop",
        list: "SpamCop",
        zone: "bl.spamcop.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[("127.0.0.2", "Blacklist")]),
        refusals: &[],
        test_domain: None,
    },
    Zone {
        source: "uceprotect",
        list: "UCEPROTECT",
        zone: "dnsbl-1.uceprotect.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[("127.0.0.2", "Level 1 (high likelihood)")]),
        refusals: &[],
        test_domain: None,
    },
    Zone {
        source: "uceprotect",
        list: "UCEPROTECT",
        zone: "dnsbl-2.uceprotect.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[("127.0.0.2", "Level 2 (some false positives)")]),
        refusals: &[],
        test_domain: None,
    },
    Zone {
        source: "uceprotect",
        list: "UCEPROTECT",
        zone: "dnsbl-3.uceprotect.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[("127.0.0.2", "Level 3 (the address's AS)")]),
        refusals: &[],
        test_domain: None,
    },
    Zone {
        source: "dronebl",
        list: "dronebl.org",
        zone: "dnsbl.dronebl.org",
        takes: Takes::Addresses,
        codes: Codes::Exact(&[
            ("127.0.0.3", "IRC Drone"),
            ("127.0.0.5", "Bottler"),
            ("127.0.0.6", "Unknown spambot or drone"),
            ("127.0.0.7", "DDOS Drone"),
            ("127.0.0.8", "SOCKS Proxy"),
            ("127.0.0.9", "HTTP Proxy"),
            ("127.0.0.10", "ProxyChain"),
            ("127.0.0.11", "Web Page Proxy"),
            ("127.0.0.12", "Open DNS Resolver"),
            ("127.0.0.13", "Brute force attackers"),
            ("127.0.0.14", "Open Wingate Proxy"),
            ("127.0.0.15", "Compromised router / gateway"),
            ("127.0.0.16", "Autorooting worms"),
            (
                "127.0.0.17",
                "Automatically determined botnet IPs (experimental)",
            ),
            ("127.0.0.18", "Possibly compromised DNS/MX"),
            ("127.0.0.19", "Abused VPN Service"),
            ("127.0.0.255", "Unknown"),
        ]),
        refusals: &[],
        test_domain: None,
    },
    Zone {
        source: "sorbs",
        list: "SORBS",
        zone: "dnsbl.sorbs.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[
            ("127.0.0.2", "Open HTTP Proxy"),
            ("127.0.0.3", "Open SOCKS Proxy"),
            ("127.0.0.4", "Open Proxy"),
            ("127.0.0.5", "Open SMTP Relay"),
            ("127.0.0.6", "Spammer"),
            ("127.0.0.7", "Vulnerability exposed to spammers"),
            ("127.0.0.8", "Host ignored by SORBS"),
            ("127.0.0.9", "Hijacked host"),
            ("127.0.0.10", "Dynamic IP address range"),
            ("127.0.0.11", "Misconfigured A or MX record"),
            ("127.0.0.12", "Host does not send mail"),
            ("127.0.0.14", "Network does not contain servers"),
        ]),
        refusals: &[],
        test_domain: None,
    },
    Zone {
        source: "surbl",
        list: "SURBL",
        zone: "multi.surbl.org",
        takes: Takes::Ipv4AndDomains,
        codes: Codes::Bits(&[
            (8, "Phishing"),
            (16, "Malware"),
            (64, "Abuse"),
            (128, "Cracked site"),
        ]),
        refusals: &[(
            "127.0.0.1",
            "SURBL refused the resolver (public resolvers are blocked)",
        )],
        test_domain: Some("surbl-org-permanent-test-point.com"),
    },
];

/// What is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject<'a> {
    Address(IpAddr),
    Domain(&'a str),
}

impl Subject<'_> {
    fn asked_by(&self, zone: &Zone) -> bool {
        match self {
            Self::Address(IpAddr::V4(_)) => zone.takes != Takes::Domains,
            Self::Address(IpAddr::V6(_)) => zone.takes == Takes::Addresses,
            Self::Domain(_) => matches!(zone.takes, Takes::Domains | Takes::Ipv4AndDomains),
        }
    }

    /// The name asked under `zone`. **Pure.**
    fn query(&self, zone: &str) -> String {
        match self {
            Self::Address(address) => format!("{}.{zone}", reversed_labels(*address)),
            Self::Domain(domain) => format!("{domain}.{zone}"),
        }
    }

    fn value(&self) -> String {
        match self {
            Self::Address(address) => address.to_string(),
            Self::Domain(domain) => (*domain).to_owned(),
        }
    }
}

/// What one zone said.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Each answer address with its reason.
    Listed(Vec<(String, String)>),
    NotListed,
    /// The zone cannot be trusted for this lookup: the kind of failure and why.
    Untrusted(SourceOutcomeKind, String),
}

/// What the lists say about `subject`: its listings as evidence on it, and one row per list the
/// transport's lookup asks.
#[must_use]
pub fn check<T: Transport + ?Sized>(
    transport: &T,
    subject: Subject<'_>,
    scan_id: &str,
    now_unix: u64,
) -> (Vec<Entity>, Vec<SourceExecutionOutcome>) {
    let zones: Vec<&Zone> = ZONES
        .iter()
        .filter(|zone| subject.asked_by(zone) && transport.runs_module(zone.source))
        .collect();
    let verdicts: Vec<(&Zone, Verdict)> = zones
        .iter()
        .map(|zone| (*zone, ask(transport, zone, subject)))
        .collect();
    let mut entities = Vec::new();
    let value = subject.value();
    let kind = match subject {
        Subject::Address(_) => EntityKind::IpAddress,
        Subject::Domain(_) => EntityKind::Domain,
    };
    for (zone, verdict) in &verdicts {
        let Verdict::Listed(answers) = verdict else {
            continue;
        };
        for (answer, reason) in answers {
            let listing = format!("{} - {reason}", zone.list);
            let evidence = Evidence::new(
                EvidenceProvenance::for_scan(zone.source, scan_id),
                format!("Listed on {} ({}): {reason}", zone.list, zone.zone),
            )
            .with_attr("blocklists", listing.as_str())
            .with_attr("dnsbl", listing.as_str())
            .with_attr("dnsbl_zone", zone.zone)
            .with_attr("dnsbl_answer", answer.as_str());
            push_entity(
                &mut entities,
                kind.clone(),
                &value,
                LISTED_CONFIDENCE,
                scan_id,
                evidence,
                &[tags::MALICIOUS],
            );
        }
    }
    let outcomes = rows(&verdicts, now_unix);
    (entities, outcomes)
}

/// The subject is what was asked about: its listing is the list's own record.
const LISTED_CONFIDENCE: f64 = 0.90;

/// One row per source, joining what each of its zones said.
fn rows(verdicts: &[(&Zone, Verdict)], now_unix: u64) -> Vec<SourceExecutionOutcome> {
    let mut sources: Vec<&str> = verdicts.iter().map(|(zone, _)| zone.source).collect();
    sources.dedup();
    sources
        .into_iter()
        .map(|source| {
            let mine: Vec<&(&Zone, Verdict)> = verdicts
                .iter()
                .filter(|(zone, _)| zone.source == source)
                .collect();
            let detail = mine
                .iter()
                .map(|(zone, verdict)| match verdict {
                    Verdict::Listed(answers) => format!(
                        "{}: listed ({})",
                        zone.zone,
                        answers
                            .iter()
                            .map(|(answer, reason)| format!("{answer} {reason}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    Verdict::NotListed => format!("{}: not listed", zone.zone),
                    Verdict::Untrusted(_, why) => format!("{}: {why}", zone.zone),
                })
                .collect::<Vec<_>>()
                .join("; ");
            let listed = mine
                .iter()
                .map(|(_, verdict)| match verdict {
                    Verdict::Listed(answers) => answers.len(),
                    _ => 0,
                })
                .sum::<usize>();
            let untrusted = mine.iter().find_map(|(_, verdict)| match verdict {
                Verdict::Untrusted(kind, _) => Some(*kind),
                _ => None,
            });
            let answered = mine
                .iter()
                .any(|(_, verdict)| !matches!(verdict, Verdict::Untrusted(..)));
            match (listed, untrusted) {
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

/// Ask `zone` about `subject`, after its test points.
fn ask<T: Transport + ?Sized>(transport: &T, zone: &Zone, subject: Subject<'_>) -> Verdict {
    let positive = zone.test_domain.map_or_else(
        || format!("2.0.0.127.{}", zone.zone),
        |domain| format!("{domain}.{}", zone.zone),
    );
    match transport.resolve(&positive) {
        Err(failure) => return unreachable(&failure),
        Ok(answers) => {
            if let Some(why) = refusal(zone, &answers) {
                return Verdict::Untrusted(SourceOutcomeKind::EntitlementDenied, why);
            }
            if listed(zone, &answers).is_empty() {
                return Verdict::Untrusted(
                    SourceOutcomeKind::Inconclusive,
                    format!("did not list its test point {positive}"),
                );
            }
        }
    }
    if zone.test_domain.is_none() {
        let negative = format!("1.0.0.127.{}", zone.zone);
        if let Ok(answers) = transport.resolve(&negative) {
            if !listed(zone, &answers).is_empty() {
                return Verdict::Untrusted(
                    SourceOutcomeKind::Inconclusive,
                    "listed 127.0.0.1, which no list may: the resolver answers every name"
                        .to_owned(),
                );
            }
        }
    }
    match transport.resolve(&subject.query(zone.zone)) {
        Err(failure) => unreachable(&failure),
        Ok(answers) => {
            if let Some(why) = refusal(zone, &answers) {
                return Verdict::Untrusted(SourceOutcomeKind::EntitlementDenied, why);
            }
            let found = listed(zone, &answers);
            if found.is_empty() {
                Verdict::NotListed
            } else {
                Verdict::Listed(found)
            }
        }
    }
}

fn unreachable(failure: &TransportFailure) -> Verdict {
    Verdict::Untrusted(failure.kind, format!("no answer ({})", failure.detail))
}

/// Why `answers` refuse the question, if they do. **Pure.**
fn refusal(zone: &Zone, answers: &[IpAddr]) -> Option<String> {
    answers.iter().find_map(|answer| {
        let text = answer.to_string();
        zone.refusals
            .iter()
            .find(|(code, _)| *code == text)
            .map(|(_, why)| (*why).to_owned())
    })
}

/// Each listing answer with its reason; an answer outside `127.0.0.0/8` is not a listing, and a
/// code the list does not document is kept as itself. **Pure.**
fn listed(zone: &Zone, answers: &[IpAddr]) -> Vec<(String, String)> {
    answers
        .iter()
        .filter_map(|answer| match answer {
            IpAddr::V4(v4) if v4.octets()[0] == 127 => Some(*v4),
            _ => None,
        })
        .filter(|v4| {
            zone.refusals
                .iter()
                .all(|(code, _)| *code != v4.to_string())
        })
        .map(|v4| {
            let text = v4.to_string();
            let reason = match zone.codes {
                Codes::Exact(codes) => codes.iter().find(|(code, _)| *code == text).map_or_else(
                    || format!("undocumented answer {text}"),
                    |(_, why)| (*why).to_owned(),
                ),
                Codes::Bits(bits) => {
                    let mask = v4.octets()[3];
                    let named: Vec<&str> = bits
                        .iter()
                        .filter(|(bit, _)| mask & bit != 0)
                        .map(|(_, why)| *why)
                        .collect();
                    if named.is_empty() {
                        format!("undocumented answer {text}")
                    } else {
                        named.join(", ")
                    }
                }
            };
            (text, reason)
        })
        .collect()
}

#[cfg(test)]
mod tests;
