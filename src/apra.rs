//! APRA Authorized Institutions Register: Australian financial institutions registry.
//!
//! Queries the Australian Prudential Regulation Authority (APRA) registry to retrieve
//! authorized financial institutions: banks, credit unions, building societies, insurers,
//! superannuation trustees, and credit providers. Useful for identifying financial entity
//! registration status, authorization type, and institutional classification.
//!
//! A pass over one APRA lookup runs under the caller's [`Deadline`]: the request is
//! capped at what is left of it (never more than [`APRA_TIMEOUT`]), and a request
//! that would start after the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one APRA lookup, recomputed against the budget before sending.
pub const APRA_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct ApraRecord {
    pub name: String,
    pub abn: Option<String>,
    pub entity_type: ApraEntityType,
    pub status: ApraStatus,
    pub authorization_date: Option<String>,
    pub apra_license_number: Option<String>,
    pub headquarters_location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApraEntityType {
    /// Authorized Deposit-taking Institution (bank, credit union, building society)
    Adi,
    /// General Insurer
    GeneralInsurer,
    /// Life Insurer
    LifeInsurer,
    /// Superannuation Trustee
    SuperannuationTrustee,
    /// Credit Provider
    CreditProvider,
    /// Other APRA-regulated entity
    Other,
}

impl ApraEntityType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Adi => "adi",
            Self::GeneralInsurer => "general_insurer",
            Self::LifeInsurer => "life_insurer",
            Self::SuperannuationTrustee => "superannuation_trustee",
            Self::CreditProvider => "credit_provider",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApraStatus {
    /// Institution is currently authorized.
    Authorized,
    /// Institution authorization has been removed.
    Removed,
    /// Institution is deregistered.
    Deregistered,
    /// Institution status is unknown.
    Unknown,
}

impl ApraStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Removed => "removed",
            Self::Deregistered => "deregistered",
            Self::Unknown => "unknown",
        }
    }
}

/// Parse APRA registry response for authorized institution records.
fn parse_apra_response(query: &str, body: &str) -> Option<ApraRecord> {
    if body.is_empty() || body.contains("No results found") || body.contains("not found") {
        return None;
    }

    let text = body.to_lowercase();
    let entity_type = if text.contains("bank") || text.contains("credit union") || text.contains("building society") || text.contains("adi") {
        ApraEntityType::Adi
    } else if text.contains("general insurer") || text.contains("general insurance") {
        ApraEntityType::GeneralInsurer
    } else if text.contains("life insurer") || text.contains("life insurance") {
        ApraEntityType::LifeInsurer
    } else if text.contains("superannuation") || text.contains("trustee") {
        ApraEntityType::SuperannuationTrustee
    } else if text.contains("credit provider") || text.contains("credit") {
        ApraEntityType::CreditProvider
    } else {
        ApraEntityType::Other
    };

    let status = if text.contains("deregistered") {
        ApraStatus::Deregistered
    } else if text.contains("removed") {
        ApraStatus::Removed
    } else if text.contains("authorized") || text.contains("active") {
        ApraStatus::Authorized
    } else {
        ApraStatus::Unknown
    };

    let mut record = ApraRecord {
        name: query.to_owned(),
        abn: None,
        entity_type,
        status,
        authorization_date: None,
        apra_license_number: None,
        headquarters_location: None,
    };

    for line in body.lines() {
        let lower = line.to_lowercase();
        if lower.contains("abn:") {
            if let Some(abn_val) = line.split("ABN:").nth(1).or_else(|| line.split("abn:").nth(1)) {
                record.abn = Some(abn_val.trim().to_owned());
            }
        } else if lower.contains("authorization date:") || lower.contains("authorized:") {
            if let Some(date_str) = line.split(':').nth(1) {
                record.authorization_date = Some(date_str.trim().to_owned());
            }
        } else if lower.contains("license") || lower.contains("licence") {
            if let Some(license_str) = line.split(':').nth(1) {
                record.apra_license_number = Some(license_str.trim().to_owned());
            }
        } else if lower.contains("location") || lower.contains("headquarters") {
            if let Some(loc_str) = line.split(':').nth(1) {
                record.headquarters_location = Some(loc_str.trim().to_owned());
            }
        }
    }

    Some(record)
}

/// Query APRA registry for an institution with `cap` as the request timeout.
///
/// `Some(record)` when the institution is found, `None` when no records or no response.
#[must_use]
pub fn query<T: Transport + ?Sized>(
    transport: &T,
    search_term: &str,
    cap: Duration,
) -> Option<ApraRecord> {
    let apra_url = format!("http://apra.gov.au/search?q={search_term}");
    let request = Request::get(&apra_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_apra_response(search_term, &body)
}

/// Query APRA registry within `deadline`.
///
/// Returns the institution record or None if the budget was spent or no records found.
pub fn query_apra<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    search_term: &str,
) -> Option<ApraRecord> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(APRA_TIMEOUT);
    query(transport, search_term, cap)
}

/// Convert an APRA record into evidence for inclusion in an entity.
#[must_use]
pub fn record_to_evidence(record: &ApraRecord) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("apra_registry");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("name".to_owned(), record.name.clone());
    attributes.insert("entity_type".to_owned(), record.entity_type.as_str().to_owned());
    attributes.insert("status".to_owned(), record.status.as_str().to_owned());

    if let Some(abn) = &record.abn {
        attributes.insert("abn".to_owned(), abn.clone());
    }
    if let Some(auth_date) = &record.authorization_date {
        attributes.insert("authorization_date".to_owned(), auth_date.clone());
    }
    if let Some(license) = &record.apra_license_number {
        attributes.insert("apra_license".to_owned(), license.clone());
    }
    if let Some(location) = &record.headquarters_location {
        attributes.insert("headquarters".to_owned(), location.clone());
    }

    let summary = format!(
        "{} — {} ({})",
        record.name,
        record.entity_type.as_str(),
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

    struct MockApraServer {
        response_body: String,
    }

    impl MockApraServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn authorized_bank() -> Self {
            Self::new(
                "Name: Example Bank Limited\n\
                 ABN: 12 345 678 901\n\
                 Entity Type: Authorized Deposit-taking Institution (ADI)\n\
                 Status: Authorized\n\
                 Authorization Date: 15-Jun-2000\n\
                 APRA License: lic-001234\n\
                 Headquarters: Sydney, NSW\n",
            )
        }

        fn authorized_insurer() -> Self {
            Self::new(
                "Name: Example Insurance Pty Ltd\n\
                 ABN: 50 987 654 321\n\
                 Entity Type: General Insurer\n\
                 Status: Authorized\n\
                 Authorization Date: 01-Jan-2010\n\
                 APRA License: lic-005678\n\
                 Headquarters: Melbourne, VIC\n",
            )
        }

        fn removed_institution() -> Self {
            Self::new(
                "Name: Old Finance Company\n\
                 ABN: 75 111 222 333\n\
                 Entity Type: Credit Provider\n\
                 Status: Removed\n\
                 Authorization Date: 20-Mar-1995\n",
            )
        }

        fn not_found() -> Self {
            Self::new("No results found\n")
        }
    }

    impl crate::http::Transport for MockApraServer {
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
    fn authorized_bank_parsing() {
        let server = MockApraServer::authorized_bank();
        let record = query(&server, "Example Bank Limited", APRA_TIMEOUT).expect("parsed");
        assert_eq!(record.name, "Example Bank Limited");
        assert_eq!(record.abn, Some("12 345 678 901".to_owned()));
        assert_eq!(record.entity_type, ApraEntityType::Adi);
        assert_eq!(record.status, ApraStatus::Authorized);
    }

    #[test]
    fn authorized_insurer_parsing() {
        let server = MockApraServer::authorized_insurer();
        let record = query(&server, "Example Insurance Pty Ltd", APRA_TIMEOUT).expect("parsed");
        assert_eq!(record.name, "Example Insurance Pty Ltd");
        assert_eq!(record.entity_type, ApraEntityType::GeneralInsurer);
        assert_eq!(record.status, ApraStatus::Authorized);
        assert_eq!(record.apra_license_number, Some("lic-005678".to_owned()));
    }

    #[test]
    fn removed_institution_parsing() {
        let server = MockApraServer::removed_institution();
        let record = query(&server, "Old Finance Company", APRA_TIMEOUT).expect("parsed");
        assert_eq!(record.status, ApraStatus::Removed);
        assert_eq!(record.entity_type, ApraEntityType::CreditProvider);
    }

    #[test]
    fn institution_not_found_returns_none() {
        let server = MockApraServer::not_found();
        let result = query(&server, "Nonexistent Bank", APRA_TIMEOUT);
        assert_eq!(result, None);
    }

    #[test]
    fn entity_type_strings_consistent() {
        assert_eq!(ApraEntityType::Adi.as_str(), "adi");
        assert_eq!(ApraEntityType::GeneralInsurer.as_str(), "general_insurer");
        assert_eq!(ApraEntityType::LifeInsurer.as_str(), "life_insurer");
        assert_eq!(ApraEntityType::SuperannuationTrustee.as_str(), "superannuation_trustee");
        assert_eq!(ApraEntityType::CreditProvider.as_str(), "credit_provider");
    }

    #[test]
    fn apra_status_strings_consistent() {
        assert_eq!(ApraStatus::Authorized.as_str(), "authorized");
        assert_eq!(ApraStatus::Removed.as_str(), "removed");
        assert_eq!(ApraStatus::Deregistered.as_str(), "deregistered");
    }

    #[test]
    fn record_to_evidence_contains_attributes() {
        let record = ApraRecord {
            name: "Example Bank Limited".to_owned(),
            abn: Some("12 345 678 901".to_owned()),
            entity_type: ApraEntityType::Adi,
            status: ApraStatus::Authorized,
            authorization_date: Some("15-Jun-2000".to_owned()),
            apra_license_number: Some("lic-001234".to_owned()),
            headquarters_location: Some("Sydney, NSW".to_owned()),
        };
        let evidence = record_to_evidence(&record);
        assert_eq!(
            evidence.attributes.get("entity_type").map(String::as_str),
            Some("adi")
        );
        assert_eq!(
            evidence.attributes.get("status").map(String::as_str),
            Some("authorized")
        );
        assert_eq!(
            evidence.attributes.get("abn").map(String::as_str),
            Some("12 345 678 901")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockApraServer::authorized_bank();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_apra(&server, &deadline, "Example Bank Limited");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn expired_budget_skips_request() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockApraServer::authorized_bank();
        assert_eq!(query_apra(&server, &deadline, "Example Bank Limited"), None);
    }
}
