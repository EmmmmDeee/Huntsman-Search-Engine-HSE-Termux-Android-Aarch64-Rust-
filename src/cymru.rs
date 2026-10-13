//! Team Cymru IP-to-ASN mapping over DNS, queried through the `DoH` pool in [`crate::dns`].
//!
//! Keyless. `{reversed-ip}.origin.asn.cymru.com` (or `origin6` with IPv6 nibbles) answers TXT
//! `ASN [ASN...] | PREFIX | CC | REGISTRY | ALLOCATED`, one record per covering announced prefix;
//! `AS{n}.asn.cymru.com` answers `ASN | CC | REGISTRY | ALLOCATED | AS-NAME`. A record that does
//! not have that exact shape is dropped, never guessed at.

use std::net::IpAddr;

use crate::dns::{
    self, RecordType, ResolveError, ResolveErrorKind, ResolveQuery, resolve_with_pool,
};
use crate::http::Transport;

/// One announced prefix covering an address, with every origin AS that announces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub asns: Vec<u32>,
    /// Canonical CIDR (`192.0.2.0/24`).
    pub prefix: String,
    pub country: String,
    pub registry: String,
    pub allocated: String,
}

/// Registration details of one autonomous system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsInfo {
    pub asn: u32,
    pub country: String,
    pub registry: String,
    pub allocated: String,
    pub name: String,
}

/// The origin query name for `ip`.
#[must_use]
pub fn origin_name(ip: IpAddr) -> String {
    let reverse = dns::reverse_name(ip);
    match ip {
        IpAddr::V4(_) => format!(
            "{}.origin.asn.cymru.com",
            reverse.trim_end_matches(".in-addr.arpa")
        ),
        IpAddr::V6(_) => format!(
            "{}.origin6.asn.cymru.com",
            reverse.trim_end_matches(".ip6.arpa")
        ),
    }
}

fn fields(txt: &str) -> Vec<String> {
    dns::decode_txt(txt)
        .split('|')
        .map(|field| field.trim().to_owned())
        .collect()
}

/// `a.b.c.d/n` or `v6/n` as its network address and length (`192.0.2.5/24` is
/// `192.0.2.0/24`); `None` for anything else.
#[must_use]
pub fn parse_prefix(raw: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = raw.trim().split_once('/')?;
    let ip: IpAddr = addr.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    match ip {
        IpAddr::V4(v4) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            Some((IpAddr::V4((u32::from(v4) & mask).into()), bits))
        }
        IpAddr::V6(v6) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            Some((IpAddr::V6((u128::from(v6) & mask).into()), bits))
        }
        _ => None,
    }
}

/// [`parse_prefix`] rendered as CIDR text.
#[must_use]
pub fn canonical_prefix(raw: &str) -> Option<String> {
    parse_prefix(raw).map(|(network, bits)| format!("{network}/{bits}"))
}

fn asn(raw: &str) -> Option<u32> {
    raw.parse::<u32>().ok().filter(|asn| *asn != 0)
}

#[must_use]
pub fn parse_origin(txt: &str) -> Option<Origin> {
    let [asns, prefix, country, registry, allocated] = <[String; 5]>::try_from(fields(txt)).ok()?;
    let asns: Vec<u32> = asns
        .split_whitespace()
        .map(asn)
        .collect::<Option<Vec<_>>>()?;
    if asns.is_empty() {
        return None;
    }
    Some(Origin {
        asns,
        prefix: canonical_prefix(&prefix)?,
        country,
        registry,
        allocated,
    })
}

#[must_use]
pub fn parse_as(txt: &str) -> Option<AsInfo> {
    let [number, country, registry, allocated, name] = <[String; 5]>::try_from(fields(txt)).ok()?;
    Some(AsInfo {
        asn: asn(&number)?,
        country,
        registry,
        allocated,
        name,
    })
}

/// Records for `name`/TXT; an empty answer or NXDOMAIN is a definitive zero.
fn txt_records<T: Transport + ?Sized>(
    transport: &T,
    name: String,
) -> Result<Vec<String>, ResolveError> {
    let query = ResolveQuery {
        name,
        record_type: RecordType::Txt,
    };
    match resolve_with_pool(transport, &query) {
        Ok(answer) => Ok(answer.records),
        Err(error) if error.kind == ResolveErrorKind::Empty => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// Every announced prefix covering `ip`, most specific first. No announcement is `Ok(vec![])`.
///
/// # Errors
/// The resolver failure when no `DoH` server gave a definitive answer.
pub fn lookup_origin<T: Transport + ?Sized>(
    transport: &T,
    ip: IpAddr,
) -> Result<Vec<Origin>, ResolveError> {
    let mut origins: Vec<Origin> = txt_records(transport, origin_name(ip))?
        .iter()
        .filter_map(|record| parse_origin(record))
        .collect();
    origins.sort_by_key(|origin| {
        std::cmp::Reverse(
            origin
                .prefix
                .rsplit_once('/')
                .and_then(|(_, bits)| bits.parse::<u8>().ok())
                .unwrap_or(0),
        )
    });
    origins.dedup();
    Ok(origins)
}

/// Registration details of `asn`; `Ok(None)` when Team Cymru has no record of it.
///
/// # Errors
/// The resolver failure when no `DoH` server gave a definitive answer.
pub fn lookup_as<T: Transport + ?Sized>(
    transport: &T,
    asn: u32,
) -> Result<Option<AsInfo>, ResolveError> {
    Ok(txt_records(transport, format!("AS{asn}.asn.cymru.com"))?
        .iter()
        .filter_map(|record| parse_as(record))
        .find(|info| info.asn == asn))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;

    struct Fake {
        responses: RefCell<VecDeque<Response>>,
        urls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(bodies: &[&str]) -> Self {
            Self {
                responses: RefCell::new(
                    bodies
                        .iter()
                        .map(|body| Response {
                            status: 200,
                            headers: Vec::new(),
                            body: body.as_bytes().to_vec(),
                            truncated: false,
                        })
                        .collect(),
                ),
                urls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.urls.borrow_mut().push(request.url.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "no more responses".into(),
                    blocked: false,
                })
        }
    }

    #[test]
    fn origin_names_follow_the_cymru_zones() {
        assert_eq!(
            origin_name(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            "1.1.1.1.origin.asn.cymru.com"
        );
        let v6: IpAddr = "2606:4700::1111"
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let name = origin_name(v6);
        assert!(name.ends_with(".6.0.6.2.origin6.asn.cymru.com"), "{name}");
        assert_eq!(name.matches('.').count(), 32 + 3);
    }

    #[test]
    fn records_parse_strictly() {
        assert_eq!(
            parse_origin("\"13335 209242 | 1.1.1.0/24 | AU | apnic | 2011-08-11\""),
            Some(Origin {
                asns: vec![13335, 209_242],
                prefix: "1.1.1.0/24".into(),
                country: "AU".into(),
                registry: "apnic".into(),
                allocated: "2011-08-11".into(),
            })
        );
        assert_eq!(
            parse_as("\"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US\"").map(|i| i.name),
            Some("CLOUDFLARENET, US".to_string())
        );
        for bad in [
            "13335 | 1.1.1.0/24 | AU | apnic",
            "x | 1.1.1.0/24 | AU | apnic | 2011",
            "13335 | 1.1.1.0/33 | AU | apnic | 2011",
            "0 | 1.1.1.0/24 | AU | apnic | 2011",
            " | 1.1.1.0/24 | AU | apnic | 2011",
        ] {
            assert_eq!(parse_origin(bad), None, "{bad}");
        }
        assert_eq!(parse_as("AS13335 | US | arin | 2010 | X"), None);
    }

    /// `DoH` bodies recorded from Cloudflare's resolver on 2026-10-13.
    #[test]
    fn recorded_live_answers_parse() {
        let origin = Fake::new(&[
            r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"1.1.1.1.origin.asn.cymru.com","type":16}],"Answer":[{"name":"1.1.1.1.origin.asn.cymru.com","type":16,"TTL":14175,"data":"\"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11\""}]}"#,
        ]);
        let found = lookup_origin(&origin, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            found.map(|o| o
                .into_iter()
                .map(|o| (o.asns, o.prefix))
                .collect::<Vec<_>>()),
            Ok(vec![(vec![13335], "1.1.1.0/24".to_string())])
        );
        let asn = Fake::new(&[
            r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"AS13335.asn.cymru.com","type":16}],"Answer":[{"name":"AS13335.asn.cymru.com","type":16,"TTL":77301,"data":"\"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US\""}]}"#,
        ]);
        assert_eq!(
            lookup_as(&asn, 13335).map(|info| info.map(|i| i.name)),
            Ok(Some("CLOUDFLARENET - Cloudflare, Inc., US".to_string()))
        );
    }

    #[test]
    fn prefixes_are_masked_to_their_network() {
        assert_eq!(
            canonical_prefix("192.0.2.77/24").as_deref(),
            Some("192.0.2.0/24")
        );
        assert_eq!(canonical_prefix("10.1.2.3/0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(
            canonical_prefix("10.1.2.3/32").as_deref(),
            Some("10.1.2.3/32")
        );
        assert_eq!(
            canonical_prefix("2001:db8:aaaa::1/32").as_deref(),
            Some("2001:db8::/32")
        );
        assert_eq!(canonical_prefix("::/0").as_deref(), Some("::/0"));
        for bad in [
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.0",
            "x/8",
            "192.0.2.0/-1",
        ] {
            assert_eq!(canonical_prefix(bad), None, "{bad}");
        }
    }

    #[test]
    fn origin_lookup_orders_most_specific_first_and_drops_malformed_records() {
        let fake = Fake::new(&[
            r#"{"Status":0,"Answer":[{"type":16,"data":"\"64500 | 192.0.0.0/16 | US | arin | 1990\""},{"type":16,"data":"\"junk\""},{"type":16,"data":"\"64501 | 192.0.2.0/24 | AU | apnic | 2001\""}]}"#,
        ]);
        let origins = lookup_origin(&fake, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        let prefixes: Option<Vec<String>> = origins
            .ok()
            .map(|o| o.into_iter().map(|o| o.prefix).collect());
        assert_eq!(
            prefixes,
            Some(vec!["192.0.2.0/24".to_string(), "192.0.0.0/16".to_string()])
        );
        let urls = fake.urls.borrow();
        assert!(
            urls[0].contains("name=9.2.0.192.origin.asn.cymru.com"),
            "{}",
            urls[0]
        );
        assert!(urls[0].contains("type=TXT"), "{}", urls[0]);
    }

    #[test]
    fn unannounced_space_is_a_zero_but_servfail_is_an_error() {
        let nx = Fake::new(&[r#"{"Status":3}"#, r#"{"Status":3}"#, r#"{"Status":3}"#]);
        assert_eq!(
            lookup_origin(&nx, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Ok(Vec::new())
        );
        let servfail = Fake::new(&[r#"{"Status":2}"#, r#"{"Status":2}"#, r#"{"Status":2}"#]);
        assert!(lookup_as(&servfail, 64500).is_err());
    }
}
