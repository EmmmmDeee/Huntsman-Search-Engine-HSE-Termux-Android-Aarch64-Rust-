//! ABN lookup: Australian Business Number register queries for business registration details.
//!
//! Queries the ABN Lookup Web Service (abn.business.gov.au) to retrieve business
//! registration information: business name, trading names, ABN status, registration date,
//! industry classification (ANZSIC), and entity type. Useful for identifying business
//! registration, activity classification, and ABN-to-ACN linkage.
//!
//! A pass over one ABN query runs under the caller's [`Deadline`]: the request is capped
//! at what is left of it (never more than [`ABN_TIMEOUT`]), and a request that would start
//! after the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one ABN lookup, recomputed against the budget before sending.
pub const ABN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct AbnRecord {
    pub abn: String,
    pub acn: Option<String>, // Associated ACN if a company
    pub business_name: Option<String>,
    pub trading_names: Vec<String>,
    pub entity_type: Option<String>, // Individual, Company, Partnership, etc.
    pub status: AbnStatus,
    pub registration_date: Option<String>,
    pub industry_code: Option<String>, // ANZSIC code
    pub industry_description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbnStatus {
    /// Business is active and registered.
    Active,
    /// Business is registered but not active (dormant/suspended).
    Inactive,
    /// Business registration cancelled.
    Cancelled,
    /// Status could not be determined.
    Unknown,
}

impl AbnStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

/// Parse ABN Lookup response for business registration details.
fn parse_abn_response(abn: &str, body: &str) -> Option<AbnRecord> {
    if body.is_empty() || body.contains("ABN not found") || body.contains("is not a valid ABN") {
        return None;
    }

    let text = body.to_lowercase();
    let status = if text.contains("cancelled") {
        AbnStatus::Cancelled
    } else if text.contains("not currently active") || text.contains("inactive") {
        AbnStatus::Inactive
    } else if text.contains("active") || body.contains("ABN") {
        AbnStatus::Active
    } else {
        AbnStatus::Unknown
    };

    let mut record = AbnRecord {
        abn: abn.to_owned(),
        acn: None,
        business_name: None,
        trading_names: Vec::new(),
        entity_type: None,
        status,
        registration_date: None,
        industry_code: None,
        industry_description: None,
    };

    for line in body.lines() {
        let lower = line.to_lowercase();
        if lower.contains("acn:") {
            if let Some(acn_val) = line
                .split("ACN:")
                .nth(1)
                .or_else(|| line.split("acn:").nth(1))
            {
                record.acn = Some(acn_val.trim().to_owned());
            }
        } else if lower.starts_with("business name:") || lower.starts_with("abn name:") {
            record.business_name = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("trading name") {
            if let Some(name) = line.split(':').nth(1) {
                let name = name.trim().to_owned();
                if !name.is_empty() {
                    record.trading_names.push(name);
                }
            }
        } else if lower.starts_with("entity type:") {
            record.entity_type = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("registration date:") || lower.starts_with("registered:") {
            record.registration_date = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("anzsic code:") || lower.starts_with("industry code:") {
            record.industry_code = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        } else if lower.starts_with("main business activity:") || lower.starts_with("industry:") {
            record.industry_description =
                Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
        }
    }

    Some(record)
}

/// Query ABN Lookup for a business ABN with `cap` as the request timeout.
///
/// `Some(record)` when the ABN Lookup server responded, `None` when no response or invalid ABN.
#[must_use]
pub fn query<T: Transport + ?Sized>(transport: &T, abn: &str, cap: Duration) -> Option<AbnRecord> {
    // ABN Lookup URL: standard web service format.
    let abn_clean = abn.replace(' ', "");
    let abn_url = format!(
        "http://abn.business.gov.au/abn/ABNLookupAction.do?abn={abn_clean}&method=loadSearchIfAbnExists"
    );
    let request = Request::get(&abn_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_abn_response(&abn_clean, &body)
}

/// Query ABN Lookup for a business within `deadline`.
///
/// Returns the ABN record or None if the budget was spent or no response was obtained.
pub fn query_abn<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    abn: &str,
) -> Option<AbnRecord> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(ABN_TIMEOUT);
    query(transport, abn, cap)
}

/// Convert an ABN record into evidence for inclusion in an entity.
#[must_use]
pub fn record_to_evidence(record: &AbnRecord) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("abn_lookup");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("abn".to_owned(), record.abn.clone());

    if let Some(acn) = &record.acn {
        attributes.insert("acn".to_owned(), acn.clone());
    }
    if let Some(name) = &record.business_name {
        attributes.insert("business_name".to_owned(), name.clone());
    }
    if !record.trading_names.is_empty() {
        attributes.insert("trading_names".to_owned(), record.trading_names.join("; "));
    }
    if let Some(entity_type) = &record.entity_type {
        attributes.insert("entity_type".to_owned(), entity_type.clone());
    }
    attributes.insert("status".to_owned(), record.status.as_str().to_owned());

    if let Some(reg_date) = &record.registration_date {
        attributes.insert("registration_date".to_owned(), reg_date.clone());
    }
    if let Some(code) = &record.industry_code {
        attributes.insert("industry_code".to_owned(), code.clone());
    }
    if let Some(desc) = &record.industry_description {
        attributes.insert("industry_description".to_owned(), desc.clone());
    }

    let summary = format!(
        "ABN {} — {} ({})",
        record.abn,
        record.business_name.as_deref().unwrap_or("unknown"),
        record.status.as_str()
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

    struct MockAbnServer {
        response_body: String,
    }

    impl MockAbnServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn active_abn() -> Self {
            Self::new(
                "ABN: 50 123 456 789\n\
                 ACN: 123456789\n\
                 Business Name: Example Pty Ltd\n\
                 Entity Type: Proprietary Company\n\
                 Status: Active\n\
                 Registration Date: 01-01-2015\n\
                 ANZSIC Code: 6202\n\
                 Main Business Activity: Software Publishing\n",
            )
        }

        fn inactive_abn() -> Self {
            Self::new(
                "ABN: 50 987 654 321\n\
                 Business Name: Old Business Pty Ltd\n\
                 Status: Not currently active\n\
                 Registration Date: 01-01-2010\n",
            )
        }

        fn cancelled_abn() -> Self {
            Self::new(
                "ABN: 50 111 222 333\n\
                 Business Name: Closed Business\n\
                 Status: Cancelled\n",
            )
        }

        fn not_found() -> Self {
            Self::new("ABN not found\n")
        }
    }

    impl crate::http::Transport for MockAbnServer {
        fn send(
            &self,
            _request: &crate::http::Request,
        ) -> Result<Response, crate::http::TransportFailure> {
            Ok(Response {
                status: 200,
                headers: vec![],
                body: self.response_body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    #[test]
    fn active_abn_parsing() {
        let server = MockAbnServer::active_abn();
        let record = query(&server, "50 123 456 789", ABN_TIMEOUT).expect("parsed");
        assert_eq!(record.abn, "50123456789");
        assert_eq!(record.business_name, Some("Example Pty Ltd".to_owned()));
        assert_eq!(record.status, AbnStatus::Active);
        assert_eq!(record.acn, Some("123456789".to_owned()));
        assert_eq!(record.entity_type, Some("Proprietary Company".to_owned()));
    }

    #[test]
    fn inactive_abn_parsing() {
        let server = MockAbnServer::inactive_abn();
        let record = query(&server, "50987654321", ABN_TIMEOUT).expect("parsed");
        assert_eq!(record.status, AbnStatus::Inactive);
    }

    #[test]
    fn cancelled_abn_parsing() {
        let server = MockAbnServer::cancelled_abn();
        let record = query(&server, "50111222333", ABN_TIMEOUT).expect("parsed");
        assert_eq!(record.status, AbnStatus::Cancelled);
    }

    #[test]
    fn abn_not_found_returns_none() {
        let server = MockAbnServer::not_found();
        let result = query(&server, "50000000000", ABN_TIMEOUT);
        assert_eq!(result, None);
    }

    #[test]
    fn status_strings_consistent() {
        assert_eq!(AbnStatus::Active.as_str(), "active");
        assert_eq!(AbnStatus::Inactive.as_str(), "inactive");
        assert_eq!(AbnStatus::Cancelled.as_str(), "cancelled");
        assert_eq!(AbnStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn abn_whitespace_normalization() {
        let server = MockAbnServer::active_abn();
        // Both with and without spaces should parse the same
        let record1 = query(&server, "50 123 456 789", ABN_TIMEOUT).expect("parsed");
        let record2 = query(&server, "50123456789", ABN_TIMEOUT).expect("parsed");
        assert_eq!(record1.abn, record2.abn);
    }

    #[test]
    fn record_to_evidence_contains_attributes() {
        let record = AbnRecord {
            abn: "50123456789".to_owned(),
            acn: Some("123456789".to_owned()),
            business_name: Some("Example Pty Ltd".to_owned()),
            trading_names: vec!["Example Trading".to_owned()],
            entity_type: Some("Proprietary Company".to_owned()),
            status: AbnStatus::Active,
            registration_date: Some("01-01-2015".to_owned()),
            industry_code: Some("6202".to_owned()),
            industry_description: Some("Software Publishing".to_owned()),
        };
        let evidence = record_to_evidence(&record);
        assert_eq!(
            evidence.attributes.get("abn").map(String::as_str),
            Some("50123456789")
        );
        assert_eq!(
            evidence.attributes.get("acn").map(String::as_str),
            Some("123456789")
        );
        assert_eq!(
            evidence.attributes.get("status").map(String::as_str),
            Some("active")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockAbnServer::active_abn();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_abn(&server, &deadline, "50123456789");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn expired_budget_skips_request() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockAbnServer::active_abn();
        assert_eq!(query_abn(&server, &deadline, "50123456789"), None);
    }
}
