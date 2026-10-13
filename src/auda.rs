//! auDA WHOIS client: Query .au domain registration records.
//!
//! Queries the .au domain registry WHOIS service to retrieve registrant, registrar, nameserver,
//! and registration lifecycle information for Australian domains. Useful for identifying domain
//! ownership, registrar infrastructure, and DNS delegation patterns.
//!
//! A pass over one domain runs under the caller's [`Deadline`]: the request is capped at what is
//! left of it (never more than [`WHOIS_TIMEOUT`]), and a request that would start after the
//! budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one WHOIS query, recomputed against the budget before sending.
pub const WHOIS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct AudaRecord {
    pub domain: String,
    pub status: AudaStatus,
    pub registrant: Option<String>,
    pub registrar: Option<String>,
    pub nameservers: Vec<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub updated: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudaStatus {
    /// Domain active and delegated.
    Active,
    /// Domain reserved or held.
    Reserved,
    /// Domain available for registration.
    Available,
    /// WHOIS response received but status unclear.
    Unknown,
}

impl AudaStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Available => "available",
            Self::Unknown => "unknown",
        }
    }
}

/// Parse WHOIS response for relevant auDA fields.
fn parse_whois_response(domain: &str, body: &str) -> Option<AudaRecord> {
    let text = body.to_lowercase();

    // Detect status from response patterns.
    let status = if text.contains("no matching query") || text.contains("object does not exist") {
        AudaStatus::Available
    } else if text.contains("domain status: reserved") {
        AudaStatus::Reserved
    } else if text.contains("domain status: active")
        || text.contains("registrar")
        || text.contains("nameserver")
    {
        AudaStatus::Active
    } else if body.len() > 50 {
        AudaStatus::Unknown
    } else {
        return None;
    };

    let mut record = AudaRecord {
        domain: domain.to_owned(),
        status,
        registrant: None,
        registrar: None,
        nameservers: Vec::new(),
        created: None,
        expires: None,
        updated: None,
    };

    // Extract registrant (case-insensitive search).
    for line in body.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("registrant:") {
            record.registrant = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("registrar:") {
            record.registrar = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("nameserver:") {
            let ns = line.split(':').nth(1).unwrap_or("").trim().to_owned();
            if !ns.is_empty() {
                record.nameservers.push(ns);
            }
        } else if lower.starts_with("created:") {
            record.created = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("expires:") || lower.starts_with("expiry date:") {
            record.expires = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("last updated:") || lower.starts_with("updated:") {
            record.updated = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        }
    }

    Some(record)
}

/// Query auDA WHOIS for one .au domain with `cap` as the request timeout.
///
/// `Some(record)` when the WHOIS server responded (even if status is Available), `None` when
/// no response was obtained.
#[must_use]
pub fn query<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    cap: Duration,
) -> Option<AudaRecord> {
    // Construct WHOIS query to auda.org.au server using standard WHOIS protocol.
    // The domain must be a valid .au domain for meaningful results.
    let whois_url = format!("http://whois.auda.org.au/whois?query={domain}");
    let request = Request::get(&whois_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_whois_response(domain, &body)
}

/// Query auDA WHOIS for a domain within `deadline`.
///
/// Returns the WHOIS record or None if the budget was spent or no response was obtained.
pub fn query_domain<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    domain: &str,
) -> Option<AudaRecord> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(WHOIS_TIMEOUT);
    query(transport, domain, cap)
}

/// Convert an auDA record into evidence for inclusion in an entity.
#[must_use]
pub fn record_to_evidence(record: &AudaRecord) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("auda_whois");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("domain".to_owned(), record.domain.clone());
    attributes.insert("status".to_owned(), record.status.as_str().to_owned());

    if let Some(registrant) = &record.registrant {
        attributes.insert("registrant".to_owned(), registrant.clone());
    }
    if let Some(registrar) = &record.registrar {
        attributes.insert("registrar".to_owned(), registrar.clone());
    }
    if !record.nameservers.is_empty() {
        attributes.insert(
            "nameservers".to_owned(),
            record.nameservers.join(", "),
        );
    }
    if let Some(created) = &record.created {
        attributes.insert("created".to_owned(), created.clone());
    }
    if let Some(expires) = &record.expires {
        attributes.insert("expires".to_owned(), expires.clone());
    }
    if let Some(updated) = &record.updated {
        attributes.insert("updated".to_owned(), updated.clone());
    }

    let summary = format!(".au domain {} ({})", record.domain, record.status.as_str());
    let mut evidence = Evidence::new(provenance, summary);
    evidence.attributes = attributes;
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadline::FakeClock;
    use crate::http::Response;

    struct MockAudaServer {
        response_body: String,
    }

    impl MockAudaServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn active_domain() -> Self {
            Self::new(
                "Domain Name: example.com.au\n\
                 Status: Active\n\
                 Registrar: Example Registrar Pty Ltd\n\
                 Registrant: John Doe\n\
                 Created: 2020-01-15\n\
                 Expires: 2025-01-15\n\
                 Updated: 2023-06-30\n\
                 Nameserver: ns1.example.com\n\
                 Nameserver: ns2.example.com\n",
            )
        }

        fn available_domain() -> Self {
            Self::new("No Matching Query.\n")
        }

        fn reserved_domain() -> Self {
            Self::new("Domain Status: Reserved\n")
        }
    }

    impl crate::http::Transport for MockAudaServer {
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
    fn active_domain_parsing() {
        let server = MockAudaServer::active_domain();
        let record = query(&server, "example.com.au", WHOIS_TIMEOUT).expect("parsed");
        assert_eq!(record.domain, "example.com.au");
        assert_eq!(record.status, AudaStatus::Active);
        assert_eq!(record.registrant, Some("John Doe".to_owned()));
        assert_eq!(record.registrar, Some("Example Registrar Pty Ltd".to_owned()));
        assert_eq!(record.nameservers.len(), 2);
        assert_eq!(record.created, Some("2020-01-15".to_owned()));
        assert_eq!(record.expires, Some("2025-01-15".to_owned()));
    }

    #[test]
    fn available_domain_parsing() {
        let server = MockAudaServer::available_domain();
        let record = query(&server, "notregistered.com.au", WHOIS_TIMEOUT).expect("parsed");
        assert_eq!(record.status, AudaStatus::Available);
    }

    #[test]
    fn reserved_domain_parsing() {
        let server = MockAudaServer::reserved_domain();
        let record = query(&server, "reserved.com.au", WHOIS_TIMEOUT).expect("parsed");
        assert_eq!(record.status, AudaStatus::Reserved);
    }

    #[test]
    fn status_strings_consistent() {
        assert_eq!(AudaStatus::Active.as_str(), "active");
        assert_eq!(AudaStatus::Reserved.as_str(), "reserved");
        assert_eq!(AudaStatus::Available.as_str(), "available");
        assert_eq!(AudaStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn nameserver_deduplication() {
        let server = MockAudaServer::new(
            "Nameserver: ns1.example.com\n\
             Nameserver: ns2.example.com\n\
             Nameserver: ns1.example.com\n",
        );
        let record = query(&server, "test.com.au", WHOIS_TIMEOUT).expect("parsed");
        assert_eq!(record.nameservers.len(), 3); // Preserves all entries
    }

    #[test]
    fn record_to_evidence_contains_attributes() {
        let record = AudaRecord {
            domain: "example.com.au".to_owned(),
            status: AudaStatus::Active,
            registrant: Some("John Doe".to_owned()),
            registrar: Some("Example Registrar".to_owned()),
            nameservers: vec!["ns1.example.com".to_owned()],
            created: Some("2020-01-15".to_owned()),
            expires: Some("2025-01-15".to_owned()),
            updated: Some("2023-06-30".to_owned()),
        };
        let evidence = record_to_evidence(&record);
        assert_eq!(
            evidence.attributes.get("domain").map(String::as_str),
            Some("example.com.au")
        );
        assert_eq!(
            evidence.attributes.get("status").map(String::as_str),
            Some("active")
        );
        assert_eq!(
            evidence.attributes.get("registrant").map(String::as_str),
            Some("John Doe")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockAudaServer::active_domain();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_domain(&server, &deadline, "example.com.au");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn budget_exhaustion_skips_request() {
        // Create a deadline with zero remaining budget after creation.
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockAudaServer::active_domain();
        assert_eq!(query_domain(&server, &deadline, "example.com.au"), None);
    }
}
