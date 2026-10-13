//! ASIC company data: Australian Securities and Investments Commission business registration.
//!
//! Queries the ASIC (Australian Securities and Investments Commission) registry to retrieve
//! company registration details, business status, directors, ACN (Australian Company Number),
//! and registration dates. Useful for correlating domain registrants with registered Australian
//! businesses and verifying company legitimacy.
//!
//! A pass over one company query runs under the caller's [`Deadline`]: the request is capped at
//! what is left of it (never more than [`ASIC_TIMEOUT`]), and a request that would start after
//! the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one ASIC query, recomputed against the budget before sending.
pub const ASIC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct AsicCompany {
    pub query: String,                 // Original search query (name or ACN)
    pub acn: Option<String>,            // Australian Company Number
    pub name: Option<String>,           // Company name
    pub status: AsicCompanyStatus,     // Active, Cancelled, In Liquidation, etc.
    pub registration_date: Option<String>,
    pub type_: Option<String>,         // Proprietary/Public Company, Cooperative, etc.
    pub registered_office: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsicCompanyStatus {
    /// Company is active and registered.
    Active,
    /// Company registration cancelled.
    Cancelled,
    /// Company in administration or liquidation.
    InAdministration,
    /// Status could not be determined.
    Unknown,
}

impl AsicCompanyStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Cancelled => "cancelled",
            Self::InAdministration => "in_administration",
            Self::Unknown => "unknown",
        }
    }
}

/// Parse ASIC response for company registration details.
fn parse_asic_response(query: &str, body: &str) -> Option<AsicCompany> {
    if body.is_empty() || body.contains("No results found") {
        return None;
    }

    let text = body.to_lowercase();
    let status = if text.contains("cancelled") {
        AsicCompanyStatus::Cancelled
    } else if text.contains("in liquidation") || text.contains("administration") {
        AsicCompanyStatus::InAdministration
    } else if text.contains("active") || body.contains("ACN") {
        AsicCompanyStatus::Active
    } else {
        AsicCompanyStatus::Unknown
    };

    let mut company = AsicCompany {
        query: query.to_owned(),
        acn: None,
        name: None,
        status,
        registration_date: None,
        type_: None,
        registered_office: None,
    };

    for line in body.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("acn:") || lower.starts_with("acn ") {
            company.acn = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("company name:") || lower.starts_with("name:") {
            company.name = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("registration date:") || lower.starts_with("registered:") {
            company.registration_date = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("company type:") || lower.starts_with("type:") {
            company.type_ = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("registered office:") || lower.starts_with("address:") {
            company.registered_office = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        }
    }

    Some(company)
}

/// Query ASIC for company registration by name or ACN with `cap` as the request timeout.
///
/// `Some(company)` when the ASIC server responded (even if status is Unknown), `None` when
/// no response was obtained.
#[must_use]
pub fn query<T: Transport + ?Sized>(
    transport: &T,
    search_term: &str,
    cap: Duration,
) -> Option<AsicCompany> {
    let asic_url = format!("http://connectonline.asic.gov.au/RegistrySearch?query={search_term}");
    let request = Request::get(&asic_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_asic_response(search_term, &body)
}

/// Query ASIC for company registration within `deadline`.
///
/// Returns the company record or None if the budget was spent or no response was obtained.
pub fn query_company<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    search_term: &str,
) -> Option<AsicCompany> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(ASIC_TIMEOUT);
    query(transport, search_term, cap)
}

/// Convert an ASIC company record into evidence for inclusion in an entity.
#[must_use]
pub fn company_to_evidence(company: &AsicCompany) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("asic_company");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("query".to_owned(), company.query.clone());

    if let Some(acn) = &company.acn {
        attributes.insert("acn".to_owned(), acn.clone());
    }
    if let Some(name) = &company.name {
        attributes.insert("company_name".to_owned(), name.clone());
    }
    attributes.insert("status".to_owned(), company.status.as_str().to_owned());

    if let Some(reg_date) = &company.registration_date {
        attributes.insert("registration_date".to_owned(), reg_date.clone());
    }
    if let Some(type_) = &company.type_ {
        attributes.insert("company_type".to_owned(), type_.clone());
    }
    if let Some(office) = &company.registered_office {
        attributes.insert("registered_office".to_owned(), office.clone());
    }

    let summary = format!(
        "ASIC company {} ({})",
        company.name.as_deref().unwrap_or(&company.query),
        company.status.as_str()
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

    struct MockAsicServer {
        response_body: String,
    }

    impl MockAsicServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn active_company() -> Self {
            Self::new(
                "ACN: 123456789\n\
                 Company Name: Example Pty Ltd\n\
                 Status: Active\n\
                 Company Type: Proprietary Company\n\
                 Registration Date: 01-01-2010\n\
                 Registered Office: 123 Test Street, Sydney NSW 2000\n",
            )
        }

        fn cancelled_company() -> Self {
            Self::new(
                "ACN: 987654321\n\
                 Company Name: Old Company Pty Ltd\n\
                 Status: Cancelled\n\
                 Registration Date: 01-01-2005\n",
            )
        }

        fn no_match() -> Self {
            Self::new("No results found\n")
        }
    }

    impl crate::http::Transport for MockAsicServer {
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
    fn active_company_parsing() {
        let server = MockAsicServer::active_company();
        let company = query(&server, "Example Pty Ltd", ASIC_TIMEOUT).expect("parsed");
        assert_eq!(company.query, "Example Pty Ltd");
        assert_eq!(company.acn, Some("123456789".to_owned()));
        assert_eq!(company.name, Some("Example Pty Ltd".to_owned()));
        assert_eq!(company.status, AsicCompanyStatus::Active);
        assert_eq!(company.type_, Some("Proprietary Company".to_owned()));
    }

    #[test]
    fn cancelled_company_parsing() {
        let server = MockAsicServer::cancelled_company();
        let company = query(&server, "Old Company Pty Ltd", ASIC_TIMEOUT).expect("parsed");
        assert_eq!(company.status, AsicCompanyStatus::Cancelled);
    }

    #[test]
    fn no_match_returns_none() {
        let server = MockAsicServer::no_match();
        let result = query(&server, "Nonexistent Corp", ASIC_TIMEOUT);
        assert_eq!(result, None);
    }

    #[test]
    fn status_strings_consistent() {
        assert_eq!(AsicCompanyStatus::Active.as_str(), "active");
        assert_eq!(AsicCompanyStatus::Cancelled.as_str(), "cancelled");
        assert_eq!(AsicCompanyStatus::InAdministration.as_str(), "in_administration");
        assert_eq!(AsicCompanyStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn company_to_evidence_contains_attributes() {
        let company = AsicCompany {
            query: "Example Pty Ltd".to_owned(),
            acn: Some("123456789".to_owned()),
            name: Some("Example Pty Ltd".to_owned()),
            status: AsicCompanyStatus::Active,
            registration_date: Some("01-01-2010".to_owned()),
            type_: Some("Proprietary Company".to_owned()),
            registered_office: Some("123 Test Street, Sydney NSW 2000".to_owned()),
        };
        let evidence = company_to_evidence(&company);
        assert_eq!(
            evidence.attributes.get("acn").map(String::as_str),
            Some("123456789")
        );
        assert_eq!(
            evidence.attributes.get("company_name").map(String::as_str),
            Some("Example Pty Ltd")
        );
        assert_eq!(
            evidence.attributes.get("status").map(String::as_str),
            Some("active")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockAsicServer::active_company();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_company(&server, &deadline, "Example Pty Ltd");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn expired_budget_skips_request() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockAsicServer::active_company();
        assert_eq!(query_company(&server, &deadline, "Example Pty Ltd"), None);
    }
}
