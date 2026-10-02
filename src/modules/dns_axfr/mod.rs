//! DNS zone transfer (AXFR) — attempt to pull entire DNS zone from
//! permissive nameservers.
//!
//! Many legacy nameservers still permit unauthenticated AXFR. When
//! successful, this parses the subdomains carried in the server's first
//! response message — often the bulk of a small zone's inventory, though a
//! very large zone split across multiple messages is not fully pulled. Most
//! modern nameservers reject AXFR from unauthorised sources (which is the
//! expected/correct outcome for production zones).
//!
//! Implementation: raw TCP to port 53 with an AXFR query built via
//! hickory-resolver's DNS wire format.

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "dns_axfr";

/// Cap on answer records parsed from a single AXFR response message. A very
/// large zone advertises more records in `ANCOUNT` than this parser walks (and
/// AXFR itself may span multiple TCP messages this module only reads the
/// first of), so the zone's TRUE record count can exceed what is actually
/// turned into `Domain` subdomain entities.
const MAX_ANSWER_RECORDS: usize = 500;

pub struct DnsAxfr;

#[async_trait]
impl Module for DnsAxfr {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "DNS zone-transfer (AXFR) probe — attempts a full AXFR to enumerate every subdomain in one sweep"
    }

    fn priority(&self) -> u8 {
        60
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // DNS zone-transfer attempt against the target's OWN authoritative
        // nameserver — ATT&CK DNS (T1590.002). A successful AXFR dumps every
        // record in the zone, exposing the victim's internal network layout
        // → T1590.004 Network Topology. This is also an active,
        // target-touching probe testing for an exploitable AXFR-open
        // misconfiguration (tagged VULNERABLE on success) — ATT&CK Active
        // Scanning: Vulnerability Scanning (T1595.002), mirroring
        // subdomain_takeover's identical reasoning for its own active probe.
        &["T1590.002", "T1590.004", "T1595.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let domain = target.value.clone();

        if domain.is_empty() || !domain.contains('.') {
            return Ok(result);
        }

        use hickory_resolver::proto::rr::RData;

        let resolver = crate::util::dns::shared_resolver();
        let ns_records = match resolver.ns_lookup(&domain).await {
            Ok(ns) => ns,
            // The zone authoritatively said "no NS records" — NXDOMAIN, or NOERROR with no
            // answers. There is genuinely nothing to attempt a transfer against, so an empty
            // result is the true answer. `is_no_records_found()` is exactly this and nothing
            // more: hickory maps SERVFAIL/REFUSED/FORMERR to `ResponseCode(..)`, never to
            // `NoRecordsFound`, so a failing resolver cannot slip through dressed as a clean
            // result (same idiom as `dns_intel::resolve`'s DNSBL sweep).
            Err(e) if e.is_no_records_found() => return Ok(result),
            // SERVFAIL, REFUSED, timeout, no route. Nothing was established about this domain.
            //
            // This module is an EXPOSURE check — an open AXFR hands an attacker the entire zone —
            // so the direction of a wrong answer matters more here than almost anywhere else in
            // the engine. Returning `Ok(empty)` reported "no zone-transfer exposure found" for a
            // domain whose nameservers were never even enumerated, and the engine reads that as a
            // clean no-data outcome: the operator sees a negative security finding produced by a
            // resolver outage. Fail closed so the check is recorded as not performed.
            Err(e) => {
                return Err(crate::core::error::Error::module(
                    SRC,
                    format!(
                        "NS lookup for {domain} failed, so no zone transfer was attempted: {e}"
                    ),
                ));
            }
        };

        let ns_hosts: Vec<String> = ns_records
            .answers()
            .iter()
            .filter_map(|r| {
                if let RData::NS(ns) = &r.data {
                    Some(ns.0.to_ascii().trim_end_matches('.').to_string())
                } else {
                    None
                }
            })
            .take(3)
            .collect();

        // Nameservers that answered the AXFR request (permitted or refused),
        // those that could not be reached (no address, connect / read failure)
        // and those deliberately not probed (private addresses) are counted
        // apart: only an answer establishes anything about the zone.
        let mut answered = 0usize;
        let mut unreached: Vec<String> = Vec::new();
        let mut not_probed = 0usize;
        for ns_host in &ns_hosts {
            let ns_ip = match resolver.lookup_ip(ns_host.as_str()).await {
                Ok(ips) => {
                    let ip: Option<std::net::IpAddr> =
                        ips.as_lookup()
                            .answers()
                            .iter()
                            .find_map(|r| match &r.data {
                                RData::A(a) => Some(std::net::IpAddr::V4(a.0)),
                                RData::AAAA(aaaa) => Some(std::net::IpAddr::V6(aaaa.0)),
                                _ => None,
                            });
                    match ip {
                        // SSRF guard: a scanned domain's NS record is attacker-
                        // controllable and can point at a private/reserved IP
                        // (127.0.0.1, 169.254.169.254, RFC1918). This raw-socket
                        // AXFR path bypasses reqwest's `SsrfResolver`, so refuse
                        // the transfer explicitly — otherwise the tool becomes an
                        // internal port-53 prober for whoever controls the zone.
                        Some(addr) if crate::util::preflight::is_private_addr(addr) => {
                            not_probed += 1;
                            continue;
                        }
                        Some(addr) => addr.to_string(),
                        None => {
                            unreached.push(format!("{ns_host}: no address record"));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    unreached.push(format!("{ns_host}: {e}"));
                    continue;
                }
            };

            match attempt_axfr(&ns_ip, &domain).await {
                Ok(msg) if !msg.records.is_empty() => {
                    let records = &msg.records;
                    result.extend(records.iter().map(|record| {
                        let mut e = Entity::new(
                            EntityKind::Domain,
                            record,
                            confidence::HIGH_PLUSPLUS,
                            &ctx.scan_id,
                        );
                        e.tag("subdomain");
                        e.tag("axfr");
                        e.add_evidence(
                            Evidence::new(SRC, format!("Zone transfer from {ns_host}"))
                                .with_attr("nameserver", ns_host)
                                .with_attr("method", "AXFR"),
                        );
                        e
                    }));

                    let mut zone_e = Entity::new(
                        EntityKind::Domain,
                        &domain,
                        confidence::VERY_HIGH_PLUSPLUS,
                        &ctx.scan_id,
                    );
                    zone_e.tag("axfr-permitted");
                    zone_e.tag(crate::core::tags::VULNERABLE);
                    zone_e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!(
                                "Zone transfer permitted by {ns_host} — {} records exposed",
                                records.len()
                            ),
                        )
                        .with_attr("nameserver", ns_host)
                        .with_attr("record_count", records.len().to_string()),
                    );
                    // A large zone can advertise more answer records than this
                    // single-message parser walks, or span multiple AXFR
                    // messages this module only reads the first of — signal
                    // when the emitted subdomains are a partial zone inventory.
                    mark_axfr_truncation(&mut result, &mut zone_e, &msg);
                    result.push(zone_e);
                    break;
                }
                // The server answered — a refusal (rcode) or an empty transfer.
                Ok(_) => answered += 1,
                Err(e) => unreached.push(format!("{ns_host} ({ns_ip}): {e}")),
            }
        }

        if !result.is_empty() {
            return Ok(result);
        }
        sweep_verdict(&domain, ns_hosts.len(), answered, &unreached, not_probed)
    }
}

/// The verdict of a sweep that found no open transfer. **Pure.** "No
/// zone-transfer exposure" is established only by nameservers that ANSWERED
/// (refused, or served nothing); a nameserver that could not be reached —
/// TCP/53 filtered, a connect or read timeout, an unresolvable glue name —
/// leaves the question open for it, so the sweep is the module's error naming
/// it (backlog #10: the resolver-outage stage already failed closed; this
/// stage still read a fully unreachable set as the clean negative its own
/// comment forbids). A zone whose nameservers were all skipped as private
/// addresses, or that lists none, is not applicable — nothing was probed.
fn sweep_verdict(
    domain: &str,
    ns_count: usize,
    answered: usize,
    unreached: &[String],
    not_probed: usize,
) -> Result<ModuleResult> {
    if !unreached.is_empty() {
        return Err(crate::core::error::Error::module(
            SRC,
            format!(
                "AXFR against {domain}: {} of {ns_count} nameserver(s) could not be reached, so no zone-transfer verdict was established for them ({answered} answered): {}",
                unreached.len(),
                unreached.join("; ")
            ),
        ));
    }
    if answered == 0 {
        return Err(crate::core::error::Error::skipped(
            crate::core::event::SkipClass::NotApplicable,
            if ns_count == 0 {
                format!("{domain} lists no nameservers: nothing to transfer from")
            } else {
                format!(
                    "every nameserver of {domain} resolves to a private/reserved address ({not_probed} skipped): AXFR is not attempted against internal hosts"
                )
            },
        ));
    }
    Ok(ModuleResult::new())
}

/// True when `name` is a genuine subdomain of `zone` under the SAME identity
/// `Entity::new` will actually construct it under — i.e. canonicalised (not
/// just lower-cased) before the label-boundary check. **Pure**, so this
/// classification is unit-testable without a live zone transfer.
///
/// A zone transfer that includes a "www" A/CNAME record (near-universal DNS
/// practice) is a proper subdomain of the raw zone by string shape alone,
/// even though `Entity::new` strips the "www." label and collapses it onto
/// the exposed zone's own apex uid — the SAME entity `process()` separately
/// tags `axfr-permitted`/`tags::VULNERABLE` at
/// `confidence::VERY_HIGH_PLUSPLUS`. An unrelated `subdomain` tag surviving
/// onto that entity via `Entity::merge`'s tag-union would muddy what should
/// be an unambiguous exposed-zone-apex finding.
fn is_canonical_subdomain_of_zone(name: &str, zone: &str) -> bool {
    let canonical = crate::core::entity::normalise(&crate::core::entity::EntityKind::Domain, name);
    let canonical_zone =
        crate::core::entity::normalise(&crate::core::entity::EntityKind::Domain, zone);
    crate::util::domains::is_proper_subdomain_of(&canonical, &canonical_zone)
}

/// What one AXFR response message held.
#[derive(Debug, Default, PartialEq, Eq)]
struct AxfrMessage {
    /// The in-zone subdomains parsed from it, deduplicated.
    records: Vec<String>,
    /// The server-advertised `ANCOUNT`: the answer records this message holds.
    ancount: usize,
    /// SOA records among the answers actually walked. An AXFR opens with the
    /// zone's SOA and closes with the same SOA (RFC 5936 §2.2), so a transfer
    /// the first message carries whole shows two; fewer means the zone goes
    /// on in messages this module does not read.
    soa_seen: usize,
}

/// Attempt a zone transfer: send the query and read the FIRST response
/// message, which [`parse_axfr_message`] decodes.
async fn attempt_axfr(ns_ip: &str, domain: &str) -> std::io::Result<AxfrMessage> {
    let addr = format!("{ns_ip}:53");
    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .map_err(|_| std::io::Error::other("connect timeout"))??;

    let query = build_axfr_query(domain);

    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&query).await?;
    stream.flush().await?;

    let mut buf = vec![0u8; 65535];

    let read = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > buf.len() || msg_len < 12 {
            return Err(std::io::Error::other("invalid response length"));
        }
        stream.read_exact(&mut buf[..msg_len]).await?;
        Ok(msg_len)
    })
    .await
    .map_err(|_| std::io::Error::other("read timeout"))??;

    Ok(parse_axfr_message(&buf[..read], domain))
}

/// DNS `TYPE` of a start-of-authority record.
const TYPE_SOA: u16 = 6;

/// Decode one AXFR response message. **Pure.** A refusal (non-zero rcode) or
/// an empty answer decodes as the default: no records, `ancount` 0.
fn parse_axfr_message(msg: &[u8], domain: &str) -> AxfrMessage {
    let mut out = AxfrMessage::default();
    let read = msg.len();
    if read < 12 {
        return out;
    }
    let rcode = msg[3] & 0x0F;
    if rcode != 0 {
        return out;
    }

    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if ancount == 0 {
        return out;
    }
    out.ancount = ancount;

    // Parse answer records for domain names (simplified parser)
    let mut pos = 12;
    // Skip question section
    if pos < read {
        while pos < read && msg[pos] != 0 {
            let label_len = msg[pos] as usize;
            if label_len >= 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + label_len;
        }
        if pos < read && msg[pos] == 0 {
            pos += 1;
        }
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer records. Collect only true subdomains of the zone (via the
    // shared label-boundary helper), so a hostile or buggy server can't slip an
    // out-of-zone name (`evilexample.com`) past a bare `ends_with(domain)`, and
    // case differences between the queried name and the returned record don't
    // drop legitimate records. See [`is_canonical_subdomain_of_zone`] for why
    // this must canonicalise, not just lower-case.
    let zone = domain.to_lowercase();
    for _ in 0..ancount.min(MAX_ANSWER_RECORDS) {
        if pos + 12 > read {
            break;
        }
        let name = extract_name(msg, pos);
        // Skip name
        while pos < read {
            let b = msg[pos];
            if b == 0 {
                pos += 1;
                break;
            }
            if b >= 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + b as usize;
        }
        if pos + 10 > read {
            break;
        }
        if u16::from_be_bytes([msg[pos], msg[pos + 1]]) == TYPE_SOA {
            out.soa_seen += 1;
        }
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10 + rdlength;

        if let Some(name) = name {
            let lower = name.to_lowercase();
            if is_canonical_subdomain_of_zone(&lower, &zone) && !out.records.contains(&lower) {
                out.records.push(lower);
            }
        }
    }

    out
}

/// Declare a transfer this module read only part of — to the coverage layer
/// and on the zone entity. **Pure** (no network/IO). No-op for a transfer the
/// first message carried whole.
///
/// Two ways the emitted subdomains are a PARTIAL zone inventory:
/// - the message advertised more answer records (`ANCOUNT`) than this parser
///   walks ([`MAX_ANSWER_RECORDS`]); or
/// - the zone's closing SOA never arrived: AXFR opens and closes with the
///   zone's SOA (RFC 5936 §2.2), so a first message without both is followed
///   by more, which this module does not read. The previous check saw only the
///   first cause, while this function's own caller described both — so a large
///   zone split across messages, the ordinary shape of one, was reported
///   complete.
fn mark_axfr_truncation(result: &mut ModuleResult, zone_entity: &mut Entity, msg: &AxfrMessage) {
    let note = if msg.ancount > MAX_ANSWER_RECORDS {
        result.mark_truncated(
            MAX_ANSWER_RECORDS,
            Some(msg.ancount),
            &format!("the parser's cap of {MAX_ANSWER_RECORDS} answer records per message"),
        );
        format!(
            "AXFR response advertised {} answer record(s); only the first {MAX_ANSWER_RECORDS} were parsed",
            msg.ancount
        )
    } else if msg.soa_seen < 2 {
        result.mark_truncated(
            msg.ancount,
            None,
            "the first AXFR message: the zone's closing SOA had not arrived, so the transfer continues in messages this module does not read",
        );
        format!(
            "AXFR response's first message carried {} answer record(s) without the zone's closing SOA; the rest of the transfer was not read",
            msg.ancount
        )
    } else {
        return;
    };
    zone_entity.tag("truncated");
    zone_entity.add_evidence(
        Evidence::new(SRC, note)
            .with_attr("total_dns_records", msg.ancount.to_string())
            .with_attr("dns_records_capped", "true"),
    );
}

fn build_axfr_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    // Header: ID=0x1234, QR=0, OPCODE=0, RD=1
    pkt.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // QNAME
    for label in domain.split('.') {
        // DNS labels are ≤63 bytes by spec (target is validated upstream); cap
        // the length prefix so an over-long label can never wrap the `u8`.
        pkt.push(label.len().min(255) as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    // QTYPE=AXFR(252), QCLASS=IN(1)
    pkt.extend_from_slice(&[0x00, 0xFC, 0x00, 0x01]);
    pkt
}

fn extract_name(buf: &[u8], mut pos: usize) -> Option<String> {
    let mut name = String::new();
    let mut jumps = 0;
    loop {
        if pos >= buf.len() || jumps > 10 {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            break;
        }
        if len >= 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let offset = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            pos = offset;
            jumps += 1;
            continue;
        }
        if pos + 1 + len > buf.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&buf[pos + 1..pos + 1 + len]));
        pos += 1 + len;
    }
    if name.is_empty() { None } else { Some(name) }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
