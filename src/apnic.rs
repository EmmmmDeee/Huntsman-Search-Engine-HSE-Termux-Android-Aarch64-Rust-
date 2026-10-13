//! APNIC enrichment: IP block ownership and network allocation data for Australian infrastructure.
//!
//! Queries the APNIC (Asia-Pacific Network Information Centre) WHOIS service to enrich IP addresses
//! with network allocation, ASN, organization, and administrative contact information. Useful for
//! identifying IP ownership, infrastructure provider, and network routing patterns.
//!
//! A pass over one IP address runs under the caller's [`Deadline`]: the request is capped at what
//! is left of it (never more than [`APNIC_TIMEOUT`]), and a request that would start after the
//! budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one APNIC query, recomputed against the budget before sending.
pub const APNIC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct ApnicRecord {
    pub ip_address: String,
    pub netname: Option<String>,
    pub origin: Option<String>,     // ASN (e.g., AS1234)
    pub organization: Option<String>, // Org name
    pub country: Option<String>,     // Country code (AU for Australia)
    pub admin_contact: Option<String>,
    pub tech_contact: Option<String>,
}

impl ApnicRecord {
    #[must_use]
    pub fn is_australian(&self) -> bool {
        self.country
            .as_ref()
            .is_some_and(|c| c.to_uppercase() == "AU")
    }
}

/// Parse APNIC WHOIS response for network allocation and ASN data.
fn parse_apnic_response(ip: &str, body: &str) -> Option<ApnicRecord> {
    if body.is_empty() || body.contains("% No Found") {
        return None;
    }

    let mut record = ApnicRecord {
        ip_address: ip.to_owned(),
        netname: None,
        origin: None,
        organization: None,
        country: None,
        admin_contact: None,
        tech_contact: None,
    };

    for line in body.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("netname:") {
            record.netname = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("origin:") {
            record.origin = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("org-name:") || lower.starts_with("organisation:") {
            record.organization = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("country:") {
            record.country = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("admin-c:") {
            record.admin_contact = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("tech-c:") {
            record.tech_contact = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        }
    }

    Some(record)
}

/// Query APNIC WHOIS for one IP address with `cap` as the request timeout.
///
/// `Some(record)` when the APNIC server responded (even if fields are sparse), `None` when
/// no response was obtained.
#[must_use]
pub fn query<T: Transport + ?Sized>(
    transport: &T,
    ip: &str,
    cap: Duration,
) -> Option<ApnicRecord> {
    let whois_url = format!("http://whois.apnic.net/whois?query={ip}");
    let request = Request::get(&whois_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_apnic_response(ip, &body)
}

/// Query APNIC WHOIS for an IP address within `deadline`.
///
/// Returns the network allocation record or None if the budget was spent or no response was obtained.
pub fn query_ip<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    ip: &str,
) -> Option<ApnicRecord> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(APNIC_TIMEOUT);
    query(transport, ip, cap)
}

/// Convert an APNIC record into evidence for inclusion in an entity.
#[must_use]
pub fn record_to_evidence(record: &ApnicRecord) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("apnic_whois");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("ip_address".to_owned(), record.ip_address.clone());

    if let Some(netname) = &record.netname {
        attributes.insert("netname".to_owned(), netname.clone());
    }
    if let Some(origin) = &record.origin {
        attributes.insert("asn".to_owned(), origin.clone());
    }
    if let Some(org) = &record.organization {
        attributes.insert("organization".to_owned(), org.clone());
    }
    if let Some(country) = &record.country {
        attributes.insert("country".to_owned(), country.clone());
    }
    if let Some(admin) = &record.admin_contact {
        attributes.insert("admin_contact".to_owned(), admin.clone());
    }
    if let Some(tech) = &record.tech_contact {
        attributes.insert("tech_contact".to_owned(), tech.clone());
    }

    let summary = format!(
        "IP {} owned by {} ({})",
        record.ip_address,
        record.organization.as_deref().unwrap_or("unknown"),
        record.country.as_deref().unwrap_or("unknown")
    );
    let mut evidence = Evidence::new(provenance, summary);
    evidence.attributes = attributes;
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadline::FakeClock;
    use crate::http::Response;

    struct MockApnicServer {
        response_body: String,
    }

    impl MockApnicServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn australian_ip() -> Self {
            Self::new(
                "inetnum: 203.0.113.0 - 203.0.113.255\n\
                 netname: AU-ISP-NET\n\
                 origin: AS1234\n\
                 org-name: Australian Internet Service Provider\n\
                 country: AU\n\
                 admin-c: CONTACT1\n\
                 tech-c: CONTACT2\n",
            )
        }

        fn non_au_ip() -> Self {
            Self::new(
                "inetnum: 1.0.0.0 - 1.0.0.255\n\
                 netname: US-ISP-NET\n\
                 origin: AS1111\n\
                 org-name: US Internet Service Provider\n\
                 country: US\n",
            )
        }

        fn no_match() -> Self {
            Self::new("% No Found\n")
        }
    }

    impl crate::http::Transport for MockApnicServer {
        fn send(&self, _request: &crate::http::Request) -> Result<Response, crate::http::TransportFailure> {
            Ok(Response {
                status: 200,
                headers: vec![],
                body: self.response_body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    #[test]
    fn australian_ip_parsing() {
        let server = MockApnicServer::australian_ip();
        let record = query(&server, "203.0.113.100", APNIC_TIMEOUT).expect("parsed");
        assert_eq!(record.ip_address, "203.0.113.100");
        assert_eq!(record.netname, Some("AU-ISP-NET".to_owned()));
        assert_eq!(record.origin, Some("AS1234".to_owned()));
        assert_eq!(
            record.organization,
            Some("Australian Internet Service Provider".to_owned())
        );
        assert_eq!(record.country, Some("AU".to_owned()));
        assert!(record.is_australian());
    }

    #[test]
    fn non_au_ip_parsing() {
        let server = MockApnicServer::non_au_ip();
        let record = query(&server, "1.0.0.100", APNIC_TIMEOUT).expect("parsed");
        assert!(!record.is_australian());
        assert_eq!(record.country, Some("US".to_owned()));
    }

    #[test]
    fn no_match_returns_none() {
        let server = MockApnicServer::no_match();
        let result = query(&server, "10.0.0.1", APNIC_TIMEOUT);
        assert_eq!(result, None);
    }

    #[test]
    fn record_to_evidence_contains_attributes() {
        let record = ApnicRecord {
            ip_address: "203.0.113.100".to_owned(),
            netname: Some("AU-ISP-NET".to_owned()),
            origin: Some("AS1234".to_owned()),
            organization: Some("Australian ISP".to_owned()),
            country: Some("AU".to_owned()),
            admin_contact: Some("ADMIN1".to_owned()),
            tech_contact: Some("TECH1".to_owned()),
        };
        let evidence = record_to_evidence(&record);
        assert_eq!(
            evidence.attributes.get("ip_address").map(String::as_str),
            Some("203.0.113.100")
        );
        assert_eq!(
            evidence.attributes.get("asn").map(String::as_str),
            Some("AS1234")
        );
        assert_eq!(
            evidence.attributes.get("country").map(String::as_str),
            Some("AU")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockApnicServer::australian_ip();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_ip(&server, &deadline, "203.0.113.100");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn expired_budget_skips_request() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockApnicServer::australian_ip();
        assert_eq!(query_ip(&server, &deadline, "203.0.113.100"), None);
    }
}
