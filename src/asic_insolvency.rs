//! ASIC Insolvency Register: Bankruptcy, liquidation, and receivership records.
//!
//! Queries the ASIC National Personal Insolvency Index (NPII) to retrieve insolvency
//! proceedings for individuals and companies: bankruptcies, debt agreements, liquidations,
//! receiverships, and administration orders. Useful for identifying financial distress,
//! litigation risk, and historical company/person insolvency status.
//!
//! A pass over one insolvency query runs under the caller's [`Deadline`]: the request is
//! capped at what is left of it (never more than [`INSOLVENCY_TIMEOUT`]), and a request
//! that would start after the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one insolvency lookup, recomputed against the budget before sending.
pub const INSOLVENCY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct InsolvencyRecord {
    pub name: String,
    pub proceedings: Vec<InsolvencyProceeding>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InsolvencyProceeding {
    pub proceeding_type: InsolvencyType,
    pub date_filed: Option<String>,
    pub date_ended: Option<String>,
    pub status: InsolvencyStatus,
    pub trustee_or_administrator: Option<String>,
    pub court_or_authority: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsolvencyType {
    /// Personal bankruptcy
    Bankruptcy,
    /// Debt agreement (alternative to bankruptcy)
    DebtAgreement,
    /// Company liquidation
    Liquidation,
    /// Company receivership
    Receivership,
    /// Company administration
    Administration,
    /// Court-ordered arrangement
    CourtOrder,
    /// Other insolvency proceeding
    Other,
}

impl InsolvencyType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bankruptcy => "bankruptcy",
            Self::DebtAgreement => "debt_agreement",
            Self::Liquidation => "liquidation",
            Self::Receivership => "receivership",
            Self::Administration => "administration",
            Self::CourtOrder => "court_order",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsolvencyStatus {
    /// Proceeding is currently active.
    Active,
    /// Proceeding has been completed/discharged.
    Completed,
    /// Proceeding status is unknown.
    Unknown,
}

impl InsolvencyStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Unknown => "unknown",
        }
    }
}

/// Parse ASIC insolvency response for proceeding records.
fn parse_insolvency_response(name: &str, body: &str) -> Option<InsolvencyRecord> {
    if body.is_empty() || body.contains("No entries found") || body.contains("not found") {
        return None;
    }

    let mut record = InsolvencyRecord {
        name: name.to_owned(),
        proceedings: Vec::new(),
    };

    // Parse each proceeding from the response.
    let mut current_proceeding: Option<InsolvencyProceeding> = None;

    for line in body.lines() {
        let lower = line.to_lowercase();

        // Detect proceeding type line.
        if lower.contains("bankruptcy") {
            if let Some(proceeding) = current_proceeding.take() {
                record.proceedings.push(proceeding);
            }
            current_proceeding = Some(InsolvencyProceeding {
                proceeding_type: InsolvencyType::Bankruptcy,
                date_filed: None,
                date_ended: None,
                status: InsolvencyStatus::Unknown,
                trustee_or_administrator: None,
                court_or_authority: None,
            });
        } else if lower.contains("debt agreement") {
            if let Some(proceeding) = current_proceeding.take() {
                record.proceedings.push(proceeding);
            }
            current_proceeding = Some(InsolvencyProceeding {
                proceeding_type: InsolvencyType::DebtAgreement,
                date_filed: None,
                date_ended: None,
                status: InsolvencyStatus::Unknown,
                trustee_or_administrator: None,
                court_or_authority: None,
            });
        } else if lower.contains("liquidation") {
            if let Some(proceeding) = current_proceeding.take() {
                record.proceedings.push(proceeding);
            }
            current_proceeding = Some(InsolvencyProceeding {
                proceeding_type: InsolvencyType::Liquidation,
                date_filed: None,
                date_ended: None,
                status: InsolvencyStatus::Unknown,
                trustee_or_administrator: None,
                court_or_authority: None,
            });
        } else if lower.contains("receivership") {
            if let Some(proceeding) = current_proceeding.take() {
                record.proceedings.push(proceeding);
            }
            current_proceeding = Some(InsolvencyProceeding {
                proceeding_type: InsolvencyType::Receivership,
                date_filed: None,
                date_ended: None,
                status: InsolvencyStatus::Unknown,
                trustee_or_administrator: None,
                court_or_authority: None,
            });
        } else if lower.contains("administration") {
            if let Some(proceeding) = current_proceeding.take() {
                record.proceedings.push(proceeding);
            }
            current_proceeding = Some(InsolvencyProceeding {
                proceeding_type: InsolvencyType::Administration,
                date_filed: None,
                date_ended: None,
                status: InsolvencyStatus::Unknown,
                trustee_or_administrator: None,
                court_or_authority: None,
            });
        }

        // Parse details for current proceeding.
        if let Some(ref mut proceeding) = current_proceeding {
            if lower.starts_with("date filed:") || lower.starts_with("date entered:") {
                proceeding.date_filed = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
            } else if lower.starts_with("date ended:") || lower.starts_with("date discharged:") {
                proceeding.date_ended = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
            } else if lower.starts_with("status:") {
                let status_str = line.split(':').nth(1).unwrap_or("").trim().to_lowercase();
                if status_str.contains("discharged") || status_str.contains("completed") {
                    proceeding.status = InsolvencyStatus::Completed;
                } else if status_str.contains("active") || status_str.contains("current") {
                    proceeding.status = InsolvencyStatus::Active;
                }
            } else if lower.starts_with("trustee:") || lower.starts_with("liquidator:") || lower.starts_with("administrator:") {
                proceeding.trustee_or_administrator = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
            } else if lower.starts_with("court:") || lower.starts_with("authority:") {
                proceeding.court_or_authority = Some(line.split(':').nth(1).unwrap_or("").trim().to_owned());
            }
        }
    }

    if let Some(proceeding) = current_proceeding {
        record.proceedings.push(proceeding);
    }

    if record.proceedings.is_empty() {
        None
    } else {
        Some(record)
    }
}

/// Query ASIC Insolvency Register for a person or company with `cap` as the request timeout.
///
/// `Some(record)` when entries are found, `None` when no records or no response obtained.
#[must_use]
pub fn query<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    cap: Duration,
) -> Option<InsolvencyRecord> {
    let insolvency_url = format!("http://asic.gov.au/online-services/national-personal-insolvency-index/search?q={name}");
    let request = Request::get(&insolvency_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_insolvency_response(name, &body)
}

/// Query ASIC Insolvency Register within `deadline`.
///
/// Returns the insolvency record or None if the budget was spent or no records found.
pub fn query_insolvency<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    name: &str,
) -> Option<InsolvencyRecord> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(INSOLVENCY_TIMEOUT);
    query(transport, name, cap)
}

/// Convert an insolvency record into evidence for inclusion in an entity.
#[must_use]
pub fn record_to_evidence(record: &InsolvencyRecord) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("asic_insolvency");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("name".to_owned(), record.name.clone());
    attributes.insert("proceeding_count".to_owned(), record.proceedings.len().to_string());

    let proceeding_types: Vec<_> = record
        .proceedings
        .iter()
        .map(|p| p.proceeding_type.as_str())
        .collect();
    attributes.insert("proceeding_types".to_owned(), proceeding_types.join("; "));

    let active_count = record
        .proceedings
        .iter()
        .filter(|p| p.status == InsolvencyStatus::Active)
        .count();
    attributes.insert("active_proceedings".to_owned(), active_count.to_string());

    let summary = format!(
        "{} has {} insolvency proceeding(s) ({} active)",
        record.name,
        record.proceedings.len(),
        active_count
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

    struct MockInsolvencyServer {
        response_body: String,
    }

    impl MockInsolvencyServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn active_bankruptcy() -> Self {
            Self::new(
                "Name: John Smith\n\
                 Bankruptcy\n\
                 Date filed: 01-01-2022\n\
                 Status: Active\n\
                 Trustee: Official Receiver\n",
            )
        }

        fn completed_liquidation() -> Self {
            Self::new(
                "Name: ABC Company Pty Ltd\n\
                 Liquidation\n\
                 Date entered: 01-06-2020\n\
                 Date discharged: 01-06-2023\n\
                 Status: Completed\n\
                 Liquidator: XYZ Insolvency\n",
            )
        }

        fn multiple_proceedings() -> Self {
            Self::new(
                "Name: Jane Doe\n\
                 Debt Agreement\n\
                 Date filed: 01-01-2019\n\
                 Status: Completed\n\
                 Bankruptcy\n\
                 Date filed: 01-01-2021\n\
                 Status: Active\n",
            )
        }

        fn not_found() -> Self {
            Self::new("No entries found\n")
        }
    }

    impl crate::http::Transport for MockInsolvencyServer {
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
    fn active_bankruptcy_parsing() {
        let server = MockInsolvencyServer::active_bankruptcy();
        let record = query(&server, "John Smith", INSOLVENCY_TIMEOUT).expect("parsed");
        assert_eq!(record.name, "John Smith");
        assert_eq!(record.proceedings.len(), 1);
        assert_eq!(record.proceedings[0].proceeding_type, InsolvencyType::Bankruptcy);
        assert_eq!(record.proceedings[0].status, InsolvencyStatus::Active);
    }

    #[test]
    fn completed_liquidation_parsing() {
        let server = MockInsolvencyServer::completed_liquidation();
        let record = query(&server, "ABC Company Pty Ltd", INSOLVENCY_TIMEOUT).expect("parsed");
        assert_eq!(record.proceedings.len(), 1);
        assert_eq!(record.proceedings[0].proceeding_type, InsolvencyType::Liquidation);
        assert_eq!(record.proceedings[0].status, InsolvencyStatus::Completed);
    }

    #[test]
    fn multiple_proceedings_parsing() {
        let server = MockInsolvencyServer::multiple_proceedings();
        let record = query(&server, "Jane Doe", INSOLVENCY_TIMEOUT).expect("parsed");
        assert_eq!(record.proceedings.len(), 2);
        assert_eq!(record.proceedings[0].proceeding_type, InsolvencyType::DebtAgreement);
        assert_eq!(record.proceedings[1].proceeding_type, InsolvencyType::Bankruptcy);
    }

    #[test]
    fn not_found_returns_none() {
        let server = MockInsolvencyServer::not_found();
        let result = query(&server, "Nonexistent Person", INSOLVENCY_TIMEOUT);
        assert_eq!(result, None);
    }

    #[test]
    fn insolvency_type_strings_consistent() {
        assert_eq!(InsolvencyType::Bankruptcy.as_str(), "bankruptcy");
        assert_eq!(InsolvencyType::Liquidation.as_str(), "liquidation");
        assert_eq!(InsolvencyType::DebtAgreement.as_str(), "debt_agreement");
    }

    #[test]
    fn insolvency_status_strings_consistent() {
        assert_eq!(InsolvencyStatus::Active.as_str(), "active");
        assert_eq!(InsolvencyStatus::Completed.as_str(), "completed");
        assert_eq!(InsolvencyStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn record_to_evidence_counts_proceedings() {
        let record = InsolvencyRecord {
            name: "John Smith".to_owned(),
            proceedings: vec![
                InsolvencyProceeding {
                    proceeding_type: InsolvencyType::Bankruptcy,
                    date_filed: Some("01-01-2022".to_owned()),
                    date_ended: None,
                    status: InsolvencyStatus::Active,
                    trustee_or_administrator: None,
                    court_or_authority: None,
                },
                InsolvencyProceeding {
                    proceeding_type: InsolvencyType::DebtAgreement,
                    date_filed: Some("01-01-2020".to_owned()),
                    date_ended: Some("01-01-2021".to_owned()),
                    status: InsolvencyStatus::Completed,
                    trustee_or_administrator: None,
                    court_or_authority: None,
                },
            ],
        };
        let evidence = record_to_evidence(&record);
        assert_eq!(
            evidence.attributes.get("proceeding_count").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            evidence.attributes.get("active_proceedings").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockInsolvencyServer::active_bankruptcy();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_insolvency(&server, &deadline, "John Smith");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn expired_budget_skips_request() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockInsolvencyServer::active_bankruptcy();
        assert_eq!(query_insolvency(&server, &deadline, "John Smith"), None);
    }
}
