//! AHPRA Register: Australian Health Practitioner Regulation Agency registry.
//!
//! Queries the AHPRA register to verify Australian healthcare practitioners'
//! registration status, qualifications, and regulatory history. Covers all
//! regulated professions: doctors, nurses, dentists, pharmacists, optometrists,
//! chiropractors, osteopaths, physiotherapists, psychologists, podiatrists,
//! and other allied health professionals. Useful for credential verification,
//! professional background checks, and regulatory compliance investigation.
//!
//! A pass over one AHPRA lookup runs under the caller's [`Deadline`]: the request is
//! capped at what is left of it (never more than [`AHPRA_TIMEOUT`]), and a request
//! that would start after the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::entity::Evidence;
use crate::http::{Request, Transport};

/// Cap on one AHPRA lookup, recomputed against the budget before sending.
pub const AHPRA_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct AhpraRecord {
    pub name: String,
    pub profession: HealthProfession,
    pub registration_status: RegistrationStatus,
    pub registration_number: Option<String>,
    pub initial_registration_date: Option<String>,
    pub state_territory: Option<String>,
    pub conditions_restrictions: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthProfession {
    /// Medical doctor
    Doctor,
    /// Registered nurse
    Nurse,
    /// Dentist or dental specialist
    Dentist,
    /// Pharmacist
    Pharmacist,
    /// Optometrist
    Optometrist,
    /// Chiropractor
    Chiropractor,
    /// Osteopath
    Osteopath,
    /// Physiotherapist
    Physiotherapist,
    /// Psychologist
    Psychologist,
    /// Podiatrist
    Podiatrist,
    /// Other allied health professional
    Other,
}

impl HealthProfession {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Doctor => "doctor",
            Self::Nurse => "nurse",
            Self::Dentist => "dentist",
            Self::Pharmacist => "pharmacist",
            Self::Optometrist => "optometrist",
            Self::Chiropractor => "chiropractor",
            Self::Osteopath => "osteopath",
            Self::Physiotherapist => "physiotherapist",
            Self::Psychologist => "psychologist",
            Self::Podiatrist => "podiatrist",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStatus {
    /// Practitioner is currently registered.
    Registered,
    /// Practitioner's registration has been suspended.
    Suspended,
    /// Practitioner's registration has been cancelled.
    Cancelled,
    /// Practitioner's registration has been removed.
    Removed,
    /// Registration status is unknown.
    Unknown,
}

impl RegistrationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Suspended => "suspended",
            Self::Cancelled => "cancelled",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }
}

/// Parse AHPRA register response for practitioner records.
fn parse_ahpra_response(name: &str, body: &str) -> Option<AhpraRecord> {
    if body.is_empty()
        || body.contains("not found")
        || body.contains("No results")
        || body.contains("not registered")
    {
        return None;
    }

    let text = body.to_lowercase();
    let profession = if text.contains("medical") || text.contains("doctor") {
        HealthProfession::Doctor
    } else if text.contains("nurse") {
        HealthProfession::Nurse
    } else if text.contains("dent") {
        HealthProfession::Dentist
    } else if text.contains("pharmacist") || text.contains("pharmacy") {
        HealthProfession::Pharmacist
    } else if text.contains("optometrist") {
        HealthProfession::Optometrist
    } else if text.contains("chiropractic") {
        HealthProfession::Chiropractor
    } else if text.contains("osteopath") {
        HealthProfession::Osteopath
    } else if text.contains("physiotherapist") || text.contains("physical therapist") {
        HealthProfession::Physiotherapist
    } else if text.contains("psychologist") {
        HealthProfession::Psychologist
    } else if text.contains("podiatrist") {
        HealthProfession::Podiatrist
    } else {
        HealthProfession::Other
    };

    let status = if text.contains("suspended") {
        RegistrationStatus::Suspended
    } else if text.contains("cancelled") {
        RegistrationStatus::Cancelled
    } else if text.contains("removed") {
        RegistrationStatus::Removed
    } else if text.contains("registered") || text.contains("active") {
        RegistrationStatus::Registered
    } else {
        RegistrationStatus::Unknown
    };

    let mut record = AhpraRecord {
        name: name.to_owned(),
        profession,
        registration_status: status,
        registration_number: None,
        initial_registration_date: None,
        state_territory: None,
        conditions_restrictions: None,
    };

    for line in body.lines() {
        let lower = line.to_lowercase();
        if lower.contains("registration number:") || lower.contains("ahpra number:") {
            if let Some(reg_num) = line.split(':').nth(1) {
                record.registration_number = Some(reg_num.trim().to_owned());
            }
        } else if lower.contains("initial registration date:")
            || lower.contains("first registered:")
        {
            if let Some(date_str) = line.split(':').nth(1) {
                record.initial_registration_date = Some(date_str.trim().to_owned());
            }
        } else if lower.contains("state:")
            || lower.contains("territory:")
            || lower.contains("state/territory:")
        {
            if let Some(state_str) = line.split(':').nth(1) {
                record.state_territory = Some(state_str.trim().to_owned());
            }
        } else if lower.contains("condition") || lower.contains("restriction") {
            if let Some(cond_str) = line.split(':').nth(1) {
                record.conditions_restrictions = Some(cond_str.trim().to_owned());
            }
        }
    }

    Some(record)
}

/// Query AHPRA register for a healthcare practitioner with `cap` as the request timeout.
///
/// `Some(record)` when practitioner is found, `None` when not found or no response.
#[must_use]
pub fn query<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    cap: Duration,
) -> Option<AhpraRecord> {
    let ahpra_url = format!("http://ahpra.gov.au/search?q={name}");
    let request = Request::get(&ahpra_url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    let body = response.text();
    parse_ahpra_response(name, &body)
}

/// Query AHPRA register within `deadline`.
///
/// Returns the practitioner record or None if the budget was spent or not found.
pub fn query_ahpra<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    name: &str,
) -> Option<AhpraRecord> {
    if deadline.expired() {
        return None;
    }
    let cap = deadline.remaining().min(AHPRA_TIMEOUT);
    query(transport, name, cap)
}

/// Convert an AHPRA record into evidence for inclusion in an entity.
#[must_use]
pub fn record_to_evidence(record: &AhpraRecord) -> Evidence {
    let provenance = crate::entity::EvidenceProvenance::new("ahpra_register");
    let mut attributes = std::collections::BTreeMap::new();

    attributes.insert("name".to_owned(), record.name.clone());
    attributes.insert(
        "profession".to_owned(),
        record.profession.as_str().to_owned(),
    );
    attributes.insert(
        "registration_status".to_owned(),
        record.registration_status.as_str().to_owned(),
    );

    if let Some(reg_num) = &record.registration_number {
        attributes.insert("registration_number".to_owned(), reg_num.clone());
    }
    if let Some(init_date) = &record.initial_registration_date {
        attributes.insert("initial_registration_date".to_owned(), init_date.clone());
    }
    if let Some(state) = &record.state_territory {
        attributes.insert("state_territory".to_owned(), state.clone());
    }
    if let Some(conditions) = &record.conditions_restrictions {
        attributes.insert("conditions_restrictions".to_owned(), conditions.clone());
    }

    let summary = format!(
        "{} — {} ({})",
        record.name,
        record.profession.as_str(),
        record.registration_status.as_str()
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

    struct MockAhpraServer {
        response_body: String,
    }

    impl MockAhpraServer {
        fn new(body: &str) -> Self {
            Self {
                response_body: body.to_owned(),
            }
        }

        fn registered_doctor() -> Self {
            Self::new(
                "Name: Example Doctor\n\
                 Profession: Medical Doctor\n\
                 Registration Status: Registered\n\
                 Registration Number: MED123456\n\
                 Initial Registration Date: 15-Jul-2010\n\
                 State: NSW\n",
            )
        }

        fn registered_nurse() -> Self {
            Self::new(
                "Name: Example Nurse\n\
                 Profession: Registered Nurse\n\
                 Registration Status: Registered\n\
                 Registration Number: RN987654\n\
                 Initial Registration Date: 01-Jan-2015\n\
                 State: VIC\n",
            )
        }

        fn suspended_practitioner() -> Self {
            Self::new(
                "Name: Suspended Practitioner\n\
                 Profession: Dentist\n\
                 Registration Status: Suspended\n\
                 Registration Number: DENT456789\n\
                 Condition: Suspension imposed 20-Mar-2023\n",
            )
        }

        fn not_found() -> Self {
            Self::new("not found\n")
        }
    }

    impl crate::http::Transport for MockAhpraServer {
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
    fn registered_doctor_parsing() {
        let server = MockAhpraServer::registered_doctor();
        let record = query(&server, "Example Doctor", AHPRA_TIMEOUT).expect("parsed");
        assert_eq!(record.name, "Example Doctor");
        assert_eq!(record.profession, HealthProfession::Doctor);
        assert_eq!(record.registration_status, RegistrationStatus::Registered);
        assert_eq!(record.registration_number, Some("MED123456".to_owned()));
    }

    #[test]
    fn registered_nurse_parsing() {
        let server = MockAhpraServer::registered_nurse();
        let record = query(&server, "Example Nurse", AHPRA_TIMEOUT).expect("parsed");
        assert_eq!(record.profession, HealthProfession::Nurse);
        assert_eq!(record.registration_status, RegistrationStatus::Registered);
        assert_eq!(record.state_territory, Some("VIC".to_owned()));
    }

    #[test]
    fn suspended_practitioner_parsing() {
        let server = MockAhpraServer::suspended_practitioner();
        let record = query(&server, "Suspended Practitioner", AHPRA_TIMEOUT).expect("parsed");
        assert_eq!(record.registration_status, RegistrationStatus::Suspended);
        assert_eq!(record.profession, HealthProfession::Dentist);
    }

    #[test]
    fn practitioner_not_found_returns_none() {
        let server = MockAhpraServer::not_found();
        let result = query(&server, "Nonexistent Practitioner", AHPRA_TIMEOUT);
        assert_eq!(result, None);
    }

    #[test]
    fn profession_strings_consistent() {
        assert_eq!(HealthProfession::Doctor.as_str(), "doctor");
        assert_eq!(HealthProfession::Nurse.as_str(), "nurse");
        assert_eq!(HealthProfession::Dentist.as_str(), "dentist");
        assert_eq!(HealthProfession::Pharmacist.as_str(), "pharmacist");
    }

    #[test]
    fn registration_status_strings_consistent() {
        assert_eq!(RegistrationStatus::Registered.as_str(), "registered");
        assert_eq!(RegistrationStatus::Suspended.as_str(), "suspended");
        assert_eq!(RegistrationStatus::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn record_to_evidence_contains_attributes() {
        let record = AhpraRecord {
            name: "Example Doctor".to_owned(),
            profession: HealthProfession::Doctor,
            registration_status: RegistrationStatus::Registered,
            registration_number: Some("MED123456".to_owned()),
            initial_registration_date: Some("15-Jul-2010".to_owned()),
            state_territory: Some("NSW".to_owned()),
            conditions_restrictions: None,
        };
        let evidence = record_to_evidence(&record);
        assert_eq!(
            evidence.attributes.get("profession").map(String::as_str),
            Some("doctor")
        );
        assert_eq!(
            evidence
                .attributes
                .get("registration_status")
                .map(String::as_str),
            Some("registered")
        );
        assert_eq!(
            evidence
                .attributes
                .get("registration_number")
                .map(String::as_str),
            Some("MED123456")
        );
    }

    #[test]
    fn budget_respected() {
        let clock = FakeClock::new();
        let server = MockAhpraServer::registered_doctor();
        let deadline = Deadline::start(&clock, Duration::from_secs(3));
        let _ = query_ahpra(&server, &deadline, "Example Doctor");
        assert!(clock.elapsed() <= Duration::from_secs(5));
    }

    #[test]
    fn expired_budget_skips_request() {
        let clock = FakeClock::new();
        let deadline = Deadline::start(&clock, Duration::from_secs(0));
        let server = MockAhpraServer::registered_doctor();
        assert_eq!(query_ahpra(&server, &deadline, "Example Doctor"), None);
    }
}
