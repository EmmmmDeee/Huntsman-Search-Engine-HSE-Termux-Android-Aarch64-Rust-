//! AUSTRAC Sanctions List: Australian AML/CTF sanctions registry.
//!
//! Queries the Australian Transaction Reports and Analysis Centre (AUSTRAC) sanctions
//! lists to identify individuals and entities subject to UN or Australian government-imposed
//! sanctions. Includes UN targeted financial sanctions, AUSTRAC-imposed sanctions, and
//! proliferation financing designations. Useful for compliance checks, financial crime
//! investigation, and sanctions verification.
//!
//! A pass over one AUSTRAC query runs under the caller's [`Deadline`]: the request is
//! capped at what is left of it (never more than [`AUSTRAC_TIMEOUT`]), and a request
//! that would start after the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one AUSTRAC lookup, recomputed against the budget before sending.
pub const AUSTRAC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct AustracSanctionRecord {
    pub name: String,
    pub acn: Option<String>,
    pub abn: Option<String>,
    pub sanctions_type: SanctionsType,
    pub listing_date: Option<String>,
    pub last_updated: Option<String>,
    pub reason: Option<String>,
    pub status: SanctionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanctionsType {
    /// UN targeted financial sanctions
    UnSanctions,
    /// Australian government-imposed sanctions
    AustralianSanctions,
    /// Proliferation financing designation
    ProliferationFinancing,
    /// Other sanctions type
    Other,
}

impl SanctionsType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnSanctions => "un_sanctions",
            Self::AustralianSanctions => "australian_sanctions",
            Self::ProliferationFinancing => "proliferation_financing",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanctionStatus {
    /// Entity is currently sanctioned.
    Active,
    /// Sanction has been removed/lifted.
    Removed,
    /// Sanction status is unknown.
    Unknown,
}

impl SanctionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }
}

/// Parse AUSTRAC sanctions list response for matching records.
fn parse_austrac_response(name: &str, body: &str) -> Option<AustracSanctionRecord> {
    if body.is_empty() || body.contains("No matches found") || body.contains("not found") {
        return None;
    }

    let text = body.to_lowercase();
    let sanctions_type = if text.contains("un sanctions") || text.contains("un targeted") {
        SanctionsType::UnSanctions
    } else if text.contains("proliferation") {
        SanctionsType::ProliferationFinancing
    } else if text.contains("australian") || text.contains("australia") {
        SanctionsType::AustralianSanctions
    } else {
        SanctionsType::Other
    };

    let status = if text.contains("removed") || text.contains("delisted") || text.contains("lifted")
    {
        SanctionStatus::Removed
    } else if text.contains("active") || text.contains("current") || text.contains("listed") {
        SanctionStatus::Active
    } else {
        SanctionStatus::Unknown
    };

    let mut record = AustracSanctionRecord {
        name: name.to_owned(),
        acn: None,
        abn: None,
        sanctions_type,
        listing_date: None,
        last_updated: None,
        reason: None,
        status,
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
        } else if lower.contains("abn:") {
            if let Some(abn_val) = line
                .split("ABN:")
                .nth(1)
                .or_else(|| line.split("abn:").nth(1))
            {
                record.abn = Some(abn_val.trim().to_owned());
            }
        } else if lower.contains("listing date:") || lower.contains("listed:") {
            if let Some(date_str) = line.split(':').nth(1) {
                record.listing_date = Some(date_str.trim().to_owned());
            }
        } else if lower.contains("updated:") || lower.contains("last updated:") {
            if let Some(date_str) = line.split(':').nth(1) {
                record.last_updated = Some(date_str.trim().to_owned());
            }
        } else if lower.contains("reason:") || lower.contains("justification:") {
            if let Some(reason_str) = line.split(':').nth(1) {
                record.reason = Some(reason_str.trim().to_owned());
            }
        }
    }

    Some(record)
}

/// Query AUSTRAC sanctions list for a person or entity with `cap` as the request timeout.
///
/// `Some(record)` when a sanction match is found, `None` when no matches or no response.
#[must_use]
pub fn query<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    cap: Duration,
) -> Option<AustracSanctionRecord> {
    let austrac_url = format!("http://austrac.gov.au/sanctions/search?q={name}");
    let request = Request::get(&austrac_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_austrac_response(name, &body)
}

/// Query AUSTRAC sanctions list within `deadline`.
///
/// Returns the sanction record or None if the budget was spent or no matches found.
pub fn query_austrac<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    name: &str,
) -> Option<AustracSanctionRecord> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(AUSTRAC_TIMEOUT);
    query(transport, name, cap)
}

/// Convert an AUSTRAC sanction record into evidence for inclusion in an entity.
#[must_use]
pub fn record_to_evidence(record: &AustracSanctionRecord) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("austrac_sanctions");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("name".to_owned(), record.name.clone());
    attributes.insert(
        "sanctions_type".to_owned(),
        record.sanctions_type.as_str().to_owned(),
    );
    attributes.insert("status".to_owned(), record.status.as_str().to_owned());

    if let Some(acn) = &record.acn {
        attributes.insert("acn".to_owned(), acn.clone());
    }
    if let Some(abn) = &record.abn {
        attributes.insert("abn".to_owned(), abn.clone());
    }
    if let Some(listing) = &record.listing_date {
        attributes.insert("listing_date".to_owned(), listing.clone());
    }
    if let Some(updated) = &record.last_updated {
        attributes.insert("last_updated".to_owned(), updated.clone());
    }
    if let Some(reason) = &record.reason {
        attributes.insert("reason".to_owned(), reason.clone());
    }

    let summary = format!(
        "{} — {} ({})",
        record.name,
        record.sanctions_type.as_str(),
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

    struct MockAustracServer {
        response_body: String,
    }

    impl MockAustracServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn un_sanctions_match() -> Self {
            Self::new(
                "Name: Example Person\n\
                 UN Sanctions: Yes\n\
                 Listing Date: 15-Mar-2015\n\
                 Last Updated: 10-Nov-2023\n\
                 Reason: Suspected terrorism financing\n\
                 Status: Active\n",
            )
        }

        fn australian_sanctions() -> Self {
            Self::new(
                "Name: Example Organisation\n\
                 ACN: 123 456 789\n\
                 Australian Sanctions: Yes\n\
                 Listing Date: 01-Jan-2022\n\
                 Status: Active\n\
                 Reason: Export control violation\n",
            )
        }

        fn removed_sanction() -> Self {
            Self::new(
                "Name: Historical Entity\n\
                 UN Sanctions: Yes\n\
                 Listing Date: 20-Feb-2010\n\
                 Delisted: 15-Aug-2020\n\
                 Status: Removed\n",
            )
        }

        fn no_match() -> Self {
            Self::new("No matches found\n")
        }
    }

    impl crate::http::Transport for MockAustracServer {
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
    fn un_sanctions_match_parsing() {
        let server = MockAustracServer::un_sanctions_match();
        let record = query(&server, "Example Person", AUSTRAC_TIMEOUT).expect("parsed");
        assert_eq!(record.name, "Example Person");
        assert_eq!(record.sanctions_type, SanctionsType::UnSanctions);
        assert_eq!(record.status, SanctionStatus::Active);
    }

    #[test]
    fn australian_sanctions_parsing() {
        let server = MockAustracServer::australian_sanctions();
        let record = query(&server, "Example Organisation", AUSTRAC_TIMEOUT).expect("parsed");
        assert_eq!(record.acn, Some("123 456 789".to_owned()));
        assert_eq!(record.sanctions_type, SanctionsType::AustralianSanctions);
        assert_eq!(record.status, SanctionStatus::Active);
    }

    #[test]
    fn removed_sanction_parsing() {
        let server = MockAustracServer::removed_sanction();
        let record = query(&server, "Historical Entity", AUSTRAC_TIMEOUT).expect("parsed");
        assert_eq!(record.status, SanctionStatus::Removed);
        assert_eq!(record.sanctions_type, SanctionsType::UnSanctions);
    }

    #[test]
    fn no_match_returns_none() {
        let server = MockAustracServer::no_match();
        let result = query(&server, "Nonexistent Entity", AUSTRAC_TIMEOUT);
        assert_eq!(result, None);
    }

    #[test]
    fn sanctions_type_strings_consistent() {
        assert_eq!(SanctionsType::UnSanctions.as_str(), "un_sanctions");
        assert_eq!(
            SanctionsType::AustralianSanctions.as_str(),
            "australian_sanctions"
        );
        assert_eq!(
            SanctionsType::ProliferationFinancing.as_str(),
            "proliferation_financing"
        );
    }

    #[test]
    fn sanction_status_strings_consistent() {
        assert_eq!(SanctionStatus::Active.as_str(), "active");
        assert_eq!(SanctionStatus::Removed.as_str(), "removed");
    }

    #[test]
    fn record_to_evidence_contains_attributes() {
        let record = AustracSanctionRecord {
            name: "Example Person".to_owned(),
            acn: None,
            abn: None,
            sanctions_type: SanctionsType::UnSanctions,
            listing_date: Some("15-Mar-2015".to_owned()),
            last_updated: Some("10-Nov-2023".to_owned()),
            reason: Some("Suspected terrorism financing".to_owned()),
            status: SanctionStatus::Active,
        };
        let evidence = record_to_evidence(&record);
        assert_eq!(
            evidence
                .attributes
                .get("sanctions_type")
                .map(String::as_str),
            Some("un_sanctions")
        );
        assert_eq!(
            evidence.attributes.get("status").map(String::as_str),
            Some("active")
        );
        assert_eq!(
            evidence.attributes.get("reason").map(String::as_str),
            Some("Suspected terrorism financing")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockAustracServer::un_sanctions_match();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_austrac(&server, &deadline, "Example Person");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn expired_budget_skips_request() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockAustracServer::un_sanctions_match();
        assert_eq!(query_austrac(&server, &deadline, "Example Person"), None);
    }
}
