//! DNS blocklists: whether an address or a domain is listed by Spamhaus, `SpamCop`, UCEPROTECT,
//! `DroneBL` and SURBL, as Spiderfoot's `sfp_spamhaus`, `sfp_spamcop`, `sfp_uceprotect`,
//! `sfp_dronebl` and `sfp_surbl` ask them, with Spamhaus's domain list (DBL) and UCEPROTECT's third
//! level beside them. SORBS (`sfp_sorbs`) has shut down: its zone is kept, never asked, and its row
//! is `confirmed_dead`.
//!
//! Each answer code has a [`Class`]: only a record of the subject's own abuse marks it malicious. A
//! policy listing of its range (Spamhaus's PBL) and a listing of its network or AS (UCEPROTECT's
//! levels 2 and 3) are kept as blacklistings that say nothing the subject did.
//!
//! A list is asked through the system resolver (see [`Transport::resolve`]): an IPv4 address as
//! its reversed octets under the zone (`2.0.0.127.zen.spamhaus.org`), an IPv6 address as its
//! reversed nibbles where the list takes IPv6, and a domain as itself. An answer in `127.0.0.0/8`
//! is a listing, and each list's codes say why. Before trusting a zone the lookup asks its RFC 5782
//! test points: the listed one (`127.0.0.2`, or the list's own test domain) must answer, and
//! `127.0.0.1` must not. A zone that does not answer its test point, refuses the resolver (Spamhaus
//! refuses public resolvers with `127.255.255.254`, SURBL with `127.0.0.1`), or lists everything is
//! reported as such on its row instead of as "not listed". A list is "not listed" only when every
//! zone of it asked said so: UCEPROTECT's levels 2 and 3, which list an address's network and AS,
//! say nothing of level 1, so with level 1 unanswered its row is inconclusive (see
//! [`SourceExecutionOutcome::joined`]). Every listing is kept with the list, the zone, the answer
//! and the reason; each list is its own source, so an address on two lists is two sources'
//! verdicts.

use std::net::IpAddr;

use crate::dns::reversed_labels;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::{Transport, TransportFailure};
use crate::source_outcome::{EndpointAnswer, SourceExecutionOutcome, SourceOutcomeKind};
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

/// What a listing says of the subject itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The subject was seen sending spam, serving malware, running a proxy or a bot, or is a
    /// hijacked network: a record of the subject's own abuse, which marks it malicious.
    Abuse,
    /// The list's policy, not anything the subject did: Spamhaus's PBL lists the end-user ranges
    /// whose holders say they should not send mail directly, and SURBL's DM and CT bits name
    /// disposable-mail providers and mail click trackers, which have their honest uses.
    Policy,
    /// The subject's network or AS is listed, not the subject: UCEPROTECT's levels 2 and 3.
    Neighbourhood,
}

impl Class {
    /// The label a listing's evidence keeps (`dnsbl_class`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Abuse => "abuse",
            Self::Policy => "policy",
            Self::Neighbourhood => "neighbourhood",
        }
    }
}

/// How a zone's answers read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codes {
    /// Each answer address names one reason and what it says of the subject.
    Exact(&'static [(&'static str, &'static str, Class)]),
    /// The last octet is a bit mask, each bit one reason and what it says of the subject (SURBL's
    /// `multi`). An answer is abuse when any of its bits is.
    Bits(&'static [(u8, &'static str, Class)]),
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
    /// Why the list is no longer asked, for one that has shut down: nothing is sent to it, and
    /// its row says so as `confirmed_dead`.
    pub retired: Option<&'static str>,
}

/// Spamhaus's refusal codes for its DBL: its zen ones, and DBL's own answer to a question about an
/// IP address, which it does not list.
const SPAMHAUS_DBL_REFUSALS: &[(&str, &str)] = &[
    ("127.0.1.255", "Spamhaus DBL refuses IP-address queries"),
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

/// Every zone, in the order they are asked; a retired zone is never asked.
pub const ZONES: &[Zone] = &[
    Zone {
        source: "spamhaus",
        list: "Spamhaus (Zen)",
        zone: "zen.spamhaus.org",
        takes: Takes::Addresses,
        codes: Codes::Exact(&[
            ("127.0.0.2", "Spammer", Class::Abuse),
            ("127.0.0.3", "Spammer", Class::Abuse),
            ("127.0.0.4", "Proxies, Trojans, etc.", Class::Abuse),
            ("127.0.0.5", "Proxies, Trojans, etc.", Class::Abuse),
            ("127.0.0.6", "Proxies, Trojans, etc.", Class::Abuse),
            ("127.0.0.7", "Proxies, Trojans, etc.", Class::Abuse),
            ("127.0.0.9", "Hijacked network (DROP)", Class::Abuse),
            (
                "127.0.0.10",
                "Policy Block List (end-user range)",
                Class::Policy,
            ),
            (
                "127.0.0.11",
                "Policy Block List (end-user range)",
                Class::Policy,
            ),
        ]),
        refusals: SPAMHAUS_REFUSALS,
        test_domain: None,
        retired: None,
    },
    Zone {
        source: "spamhaus",
        list: "Spamhaus (DBL)",
        zone: "dbl.spamhaus.org",
        takes: Takes::Domains,
        codes: Codes::Exact(&[
            ("127.0.1.2", "Spam domain", Class::Abuse),
            ("127.0.1.4", "Phishing domain", Class::Abuse),
            ("127.0.1.5", "Malware domain", Class::Abuse),
            (
                "127.0.1.6",
                "Botnet command and control domain",
                Class::Abuse,
            ),
            ("127.0.1.102", "Abused legitimate spam domain", Class::Abuse),
            (
                "127.0.1.103",
                "Abused spammed redirector domain",
                Class::Abuse,
            ),
            (
                "127.0.1.104",
                "Abused legitimate phishing domain",
                Class::Abuse,
            ),
            (
                "127.0.1.105",
                "Abused legitimate malware domain",
                Class::Abuse,
            ),
            (
                "127.0.1.106",
                "Abused legitimate botnet command and control domain",
                Class::Abuse,
            ),
        ]),
        refusals: SPAMHAUS_DBL_REFUSALS,
        test_domain: Some("dbltest.com"),
        retired: None,
    },
    Zone {
        source: "spamcop",
        list: "SpamCop",
        zone: "bl.spamcop.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[("127.0.0.2", "Blacklist", Class::Abuse)]),
        refusals: &[],
        test_domain: None,
        retired: None,
    },
    Zone {
        source: "uceprotect",
        list: "UCEPROTECT",
        zone: "dnsbl-1.uceprotect.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[("127.0.0.2", "Level 1 (high likelihood)", Class::Abuse)]),
        refusals: &[],
        test_domain: None,
        retired: None,
    },
    Zone {
        source: "uceprotect",
        list: "UCEPROTECT",
        zone: "dnsbl-2.uceprotect.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[(
            "127.0.0.2",
            "Level 2 (the address's network)",
            Class::Neighbourhood,
        )]),
        refusals: &[],
        test_domain: None,
        retired: None,
    },
    Zone {
        source: "uceprotect",
        list: "UCEPROTECT",
        zone: "dnsbl-3.uceprotect.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[(
            "127.0.0.2",
            "Level 3 (the address's AS)",
            Class::Neighbourhood,
        )]),
        refusals: &[],
        test_domain: None,
        retired: None,
    },
    Zone {
        source: "dronebl",
        list: "dronebl.org",
        zone: "dnsbl.dronebl.org",
        takes: Takes::Addresses,
        codes: Codes::Exact(&[
            ("127.0.0.3", "IRC Drone", Class::Abuse),
            ("127.0.0.5", "Bottler", Class::Abuse),
            ("127.0.0.6", "Unknown spambot or drone", Class::Abuse),
            ("127.0.0.7", "DDOS Drone", Class::Abuse),
            ("127.0.0.8", "SOCKS Proxy", Class::Abuse),
            ("127.0.0.9", "HTTP Proxy", Class::Abuse),
            ("127.0.0.10", "ProxyChain", Class::Abuse),
            ("127.0.0.11", "Web Page Proxy", Class::Abuse),
            ("127.0.0.12", "Open DNS Resolver", Class::Abuse),
            ("127.0.0.13", "Brute force attackers", Class::Abuse),
            ("127.0.0.14", "Open Wingate Proxy", Class::Abuse),
            ("127.0.0.15", "Compromised router / gateway", Class::Abuse),
            ("127.0.0.16", "Autorooting worms", Class::Abuse),
            (
                "127.0.0.17",
                "Automatically determined botnet IPs (experimental)",
                Class::Abuse,
            ),
            ("127.0.0.18", "Possibly compromised DNS/MX", Class::Abuse),
            ("127.0.0.19", "Abused VPN Service", Class::Abuse),
            ("127.0.0.255", "Unknown", Class::Abuse),
        ]),
        refusals: &[],
        test_domain: None,
        retired: None,
    },
    Zone {
        source: "sorbs",
        list: "SORBS",
        zone: "dnsbl.sorbs.net",
        takes: Takes::Ipv4,
        codes: Codes::Exact(&[
            ("127.0.0.2", "Open HTTP Proxy", Class::Abuse),
            ("127.0.0.3", "Open SOCKS Proxy", Class::Abuse),
            ("127.0.0.4", "Open Proxy", Class::Abuse),
            ("127.0.0.5", "Open SMTP Relay", Class::Abuse),
            ("127.0.0.6", "Spammer", Class::Abuse),
            (
                "127.0.0.7",
                "Vulnerability exposed to spammers",
                Class::Abuse,
            ),
            ("127.0.0.8", "Host ignored by SORBS", Class::Abuse),
            ("127.0.0.9", "Hijacked host", Class::Abuse),
            ("127.0.0.10", "Dynamic IP address range", Class::Abuse),
            ("127.0.0.11", "Misconfigured A or MX record", Class::Abuse),
            ("127.0.0.12", "Host does not send mail", Class::Abuse),
            (
                "127.0.0.14",
                "Network does not contain servers",
                Class::Abuse,
            ),
        ]),
        refusals: &[],
        test_domain: None,
        retired: Some(
            "SORBS has shut down: sorbs.net no longer resolves (NXDOMAIN at the .net servers, checked 2026-10-31), so dnsbl.sorbs.net is not asked",
        ),
    },
    Zone {
        source: "surbl",
        list: "SURBL",
        zone: "multi.surbl.org",
        takes: Takes::Ipv4AndDomains,
        codes: Codes::Bits(&[
            (4, "Disposable mail provider", Class::Policy),
            (8, "Phishing", Class::Abuse),
            (16, "Malware", Class::Abuse),
            (32, "Mail click tracker", Class::Policy),
            (64, "Abuse", Class::Abuse),
            (128, "Cracked site", Class::Abuse),
        ]),
        refusals: &[(
            "127.0.0.1",
            "SURBL refused the resolver (public resolvers are blocked)",
        )],
        test_domain: Some("surbl-org-permanent-test-point.com"),
        retired: None,
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
    /// Each answer address with its reason and what it says of the subject.
    Listed(Vec<(String, String, Class)>),
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
    let (retired, zones): (Vec<&Zone>, Vec<&Zone>) =
        zones.into_iter().partition(|zone| zone.retired.is_some());
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
        for (answer, reason, class) in answers {
            let listing = format!("{} - {reason}", zone.list);
            let evidence = Evidence::new(
                EvidenceProvenance::for_scan(zone.source, scan_id),
                format!("Listed on {} ({}): {reason}", zone.list, zone.zone),
            )
            .with_attr("blocklists", listing.as_str())
            .with_attr("dnsbl", listing.as_str())
            .with_attr("dnsbl_zone", zone.zone)
            .with_attr("dnsbl_answer", answer.as_str())
            .with_attr(LISTING_CLASS, class.as_str());
            // Only a record of the subject's own abuse marks it malicious: a policy listing of its
            // range, or a listing of its network or AS, says nothing the subject did.
            let tags: &[&str] = match class {
                Class::Abuse => &[tags::MALICIOUS],
                Class::Policy | Class::Neighbourhood => &[],
            };
            push_entity(
                &mut entities,
                kind.clone(),
                &value,
                LISTED_CONFIDENCE,
                scan_id,
                evidence,
                tags,
            );
        }
    }
    let mut outcomes = rows(&verdicts, now_unix);
    outcomes.extend(retired.iter().filter_map(|zone| {
        zone.retired.map(|why| {
            SourceExecutionOutcome::failed(
                zone.source,
                now_unix,
                SourceOutcomeKind::ConfirmedDead,
                None,
                format!("{}: {why}", zone.zone),
            )
        })
    }));
    (entities, outcomes)
}

/// The subject is what was asked about: its listing is the list's own record.
const LISTED_CONFIDENCE: f64 = 0.90;

/// The evidence attribute naming a listing's [`Class`]: `abuse`, `policy` or `neighbourhood`.
pub const LISTING_CLASS: &str = "dnsbl_class";

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
                            .map(|(answer, reason, _)| format!("{answer} {reason}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    Verdict::NotListed => format!("{}: not listed", zone.zone),
                    Verdict::Untrusted(_, why) => format!("{}: {why}", zone.zone),
                })
                .collect::<Vec<_>>()
                .join("; ");
            let answers: Vec<EndpointAnswer> = mine
                .iter()
                .map(|(_, verdict)| match verdict {
                    Verdict::Listed(answers) => EndpointAnswer::Found(answers.len()),
                    Verdict::NotListed => EndpointAnswer::Absent,
                    Verdict::Untrusted(kind, _) => EndpointAnswer::Failed(*kind),
                })
                .collect();
            SourceExecutionOutcome::joined(source, now_unix, &answers, detail)
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
    let query = subject.query(zone.zone);
    if !crate::dns_wire::askable_name(&query) {
        return Verdict::Untrusted(
            SourceOutcomeKind::Inconclusive,
            format!("{query} cannot be asked: a DNS name is at most 253 bytes, each label 1 to 63"),
        );
    }
    match transport.resolve(&query) {
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

/// Each listing answer with its reason and class; an answer outside `127.0.0.0/8` is not a
/// listing, and a code the list does not document is kept as itself, as abuse: the list listed
/// the subject. **Pure.**
fn listed(zone: &Zone, answers: &[IpAddr]) -> Vec<(String, String, Class)> {
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
            let (reason, class) = match zone.codes {
                Codes::Exact(codes) => codes.iter().find(|(code, _, _)| *code == text).map_or_else(
                    || (format!("undocumented answer {text}"), Class::Abuse),
                    |(_, why, class)| ((*why).to_owned(), *class),
                ),
                Codes::Bits(bits) => {
                    let mask = v4.octets()[3];
                    let named: Vec<&(u8, &str, Class)> =
                        bits.iter().filter(|(bit, _, _)| mask & bit != 0).collect();
                    let reason = if named.is_empty() {
                        format!("undocumented answer {text}")
                    } else {
                        named
                            .iter()
                            .map(|(_, why, _)| *why)
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    // An answer naming no documented bit reads as abuse, as an undocumented exact
                    // answer does; one naming only policy bits marks nothing malicious.
                    let class = if !named.is_empty()
                        && named.iter().all(|(_, _, class)| *class != Class::Abuse)
                    {
                        Class::Policy
                    } else {
                        Class::Abuse
                    };
                    (reason, class)
                }
            };
            (text, reason, class)
        })
        .collect()
}

#[cfg(test)]
mod tests;
