//! DNS zone transfer (AXFR) — attempt to pull entire DNS zone from
//! permissive nameservers.
//!
//! Many legacy nameservers still permit unauthenticated AXFR. When
//! successful, this yields every DNS record in the zone — a complete
//! subdomain inventory in one query. Most modern nameservers reject
//! AXFR from unauthorised sources (which is the expected/correct
//! outcome for production zones).
//!
//! Implementation: raw TCP to port 53 with an AXFR query built via
//! hickory-resolver's DNS wire format.

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "dns_axfr";

pub struct DnsAxfr;

#[async_trait]
impl Module for DnsAxfr {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Attempt DNS zone transfer (AXFR) for complete subdomain enumeration"
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
            Err(_) => return Ok(result),
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
                        Some(addr) => addr.to_string(),
                        None => continue,
                    }
                }
                Err(_) => continue,
            };

            match attempt_axfr(&ns_ip, &domain).await {
                Ok(records) if !records.is_empty() => {
                    for record in &records {
                        let mut e = Entity::new(EntityKind::Domain, record, 0.80, &ctx.scan_id);
                        e.tag("subdomain");
                        e.tag("axfr");
                        e.add_evidence(
                            Evidence::new(SRC, format!("Zone transfer from {ns_host}"))
                                .with_attr("nameserver", ns_host)
                                .with_attr("method", "AXFR"),
                        );
                        result.push(e);
                    }

                    let mut zone_e = Entity::new(EntityKind::Domain, &domain, 0.95, &ctx.scan_id);
                    zone_e.tag("axfr-permitted");
                    zone_e.tag("vulnerable");
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
                    result.push(zone_e);
                    break;
                }
                _ => continue,
            }
        }

        Ok(result)
    }
}

async fn attempt_axfr(ns_ip: &str, domain: &str) -> std::io::Result<Vec<String>> {
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

    let mut records = Vec::new();
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

    let rcode = buf[3] & 0x0F;
    if rcode != 0 {
        return Ok(records);
    }

    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return Ok(records);
    }

    // Parse answer records for domain names (simplified parser)
    let mut pos = 12;
    // Skip question section
    if pos < read {
        while pos < read && buf[pos] != 0 {
            let label_len = buf[pos] as usize;
            if label_len >= 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + label_len;
        }
        if pos < read && buf[pos] == 0 {
            pos += 1;
        }
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer records
    for _ in 0..ancount.min(500) {
        if pos + 12 > read {
            break;
        }
        let name = extract_name(&buf[..read], pos);
        // Skip name
        while pos < read {
            let b = buf[pos];
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
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10 + rdlength;

        if let Some(name) = name {
            let lower = name.to_lowercase();
            if lower.ends_with(domain) && lower != *domain && !records.contains(&lower) {
                records.push(lower);
            }
        }
    }

    Ok(records)
}

fn build_axfr_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    // Header: ID=0x1234, QR=0, OPCODE=0, RD=1
    pkt.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // QNAME
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
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
    use super::*;

    #[test]
    fn build_axfr_query_valid() {
        let q = build_axfr_query("example.com");
        assert!(q.len() > 12);
        // QTYPE should be 252 (AXFR)
        let qtype_pos = q.len() - 4;
        assert_eq!(q[qtype_pos], 0x00);
        assert_eq!(q[qtype_pos + 1], 0xFC); // 252
    }

    #[test]
    fn extract_name_simple() {
        let buf = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let name = extract_name(&buf, 0).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn extract_name_empty_returns_none() {
        let buf = [0u8];
        assert!(extract_name(&buf, 0).is_none());
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = DnsAxfr;
        assert_eq!(m.name(), "dns_axfr");
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
