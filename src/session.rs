//! Session document. Full terminate refuses missing recover, candidate,
//! falsification, or verification. Partial terminate still requires residual text.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::stage::{EvidenceLevel, Status};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub title: String,
    pub created_utc: String,
    pub updated_utc: String,
    pub recover: Recover,
    pub candidates: Vec<Candidate>,
    pub falsifications: Vec<FalsifyRecord>,
    pub executions: Vec<ExecuteRecord>,
    pub verifications: Vec<VerifyRecord>,
    pub termination: Option<Termination>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recover {
    pub objective: String,
    pub required_outcome: String,
    pub constraints: String,
    pub success_criteria: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub statement: String,
    pub alternatives: Vec<String>,
    pub reverse_observation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsifyRecord {
    pub attack: String,
    pub test: String,
    pub result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteRecord {
    pub action: String,
    pub observed: String,
    pub component: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRecord {
    pub claim: String,
    pub status: Status,
    pub evidence_level: EvidenceLevel,
    pub does_not_show: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Termination {
    pub partial: bool,
    pub residual_uncertainty: String,
    pub ledger_tip: String,
    pub at_utc: String,
}

impl Session {
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        let now = utc_now();
        Self {
            id: generate_id(),
            title: title.into(),
            created_utc: now.clone(),
            updated_utc: now,
            recover: Recover::default(),
            candidates: Vec::new(),
            falsifications: Vec::new(),
            executions: Vec::new(),
            verifications: Vec::new(),
            termination: None,
        }
    }

    pub fn apply_recover(
        &mut self,
        objective: &str,
        required_outcome: &str,
        constraints: &str,
        success_criteria: &str,
    ) {
        objective.clone_into(&mut self.recover.objective);
        required_outcome.clone_into(&mut self.recover.required_outcome);
        constraints.clone_into(&mut self.recover.constraints);
        success_criteria.clone_into(&mut self.recover.success_criteria);
        self.touch();
    }

    /// # Errors
    /// `Error::MissingField` when a required text field is blank.
    pub fn add_candidate(&mut self, candidate: Candidate) -> Result<(), Error> {
        require_text("candidate", &candidate.statement)?;
        self.candidates.push(candidate);
        self.touch();
        Ok(())
    }

    /// # Errors
    /// `Error::MissingField` when a required text field is blank.
    pub fn add_falsify(&mut self, record: FalsifyRecord) -> Result<(), Error> {
        require_text("attack", &record.attack)?;
        self.falsifications.push(record);
        self.touch();
        Ok(())
    }

    /// # Errors
    /// `Error::MissingField` when a required text field is blank.
    pub fn add_execute(&mut self, record: ExecuteRecord) -> Result<(), Error> {
        require_text("action", &record.action)?;
        require_text("component", &record.component)?;
        self.executions.push(record);
        self.touch();
        Ok(())
    }

    /// # Errors
    /// `Error::MissingField` when a required text field is blank.
    pub fn add_verify(&mut self, record: VerifyRecord) -> Result<(), Error> {
        require_text("claim", &record.claim)?;
        require_text("does_not_show", &record.does_not_show)?;
        self.verifications.push(record);
        self.touch();
        Ok(())
    }

    #[must_use]
    pub fn terminate_gaps(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.recover.objective.trim().is_empty() {
            gaps.push("recover.objective");
        }
        if self.recover.required_outcome.trim().is_empty() {
            gaps.push("recover.required_outcome");
        }
        if self.recover.constraints.trim().is_empty() {
            gaps.push("recover.constraints");
        }
        if self.recover.success_criteria.trim().is_empty() {
            gaps.push("recover.success_criteria");
        }
        if self.candidates.is_empty() {
            gaps.push("candidates");
        }
        if self.falsifications.is_empty() {
            gaps.push("falsifications");
        }
        if self.verifications.is_empty() {
            gaps.push("verifications");
        }
        gaps
    }

    /// Close the session. Full terminate needs every RCVF section and a ledger tip.
    ///
    /// # Errors
    /// `Error::MissingField` for blank residual; `Error::TerminateRefused` for gaps or a non-hash tip. A partial close may leave the tip empty.
    pub fn terminate(
        &mut self,
        residual: String,
        partial: bool,
        ledger_tip: &str,
    ) -> Result<(), Error> {
        require_text("residual_uncertainty", &residual)?;
        if !partial {
            let gaps = self.terminate_gaps();
            if !gaps.is_empty() {
                return Err(Error::TerminateRefused(format!(
                    "missing {}",
                    gaps.join(", ")
                )));
            }
            if !tip_is_hash(ledger_tip) {
                return Err(Error::TerminateRefused(
                    "ledger tip is not a chain hash".into(),
                ));
            }
        } else if !ledger_tip.is_empty() && !tip_is_hash(ledger_tip) {
            return Err(Error::TerminateRefused(
                "ledger tip is neither empty nor a chain hash".into(),
            ));
        }
        self.termination = Some(Termination {
            partial,
            residual_uncertainty: residual,
            ledger_tip: ledger_tip.to_owned(),
            at_utc: utc_now(),
        });
        self.touch();
        Ok(())
    }

    #[must_use]
    pub fn bound_to(&self, tip: &str) -> bool {
        self.termination
            .as_ref()
            .is_some_and(|t| t.ledger_tip == tip)
    }

    fn touch(&mut self) {
        self.updated_utc = utc_now();
    }
}

fn require_text(name: &str, value: &str) -> Result<(), Error> {
    if value.trim().is_empty() {
        Err(Error::MissingField(name.to_owned()))
    } else {
        Ok(())
    }
}

/// Ledger hashes are lowercase hex. An uppercase tip could never satisfy `bound_to`.
fn tip_is_hash(tip: &str) -> bool {
    tip.len() == 64 && tip.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn generate_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut id = String::new();
    let _ = write!(id, "{nanos:x}-{:x}", std::process::id());
    id
}

fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        i32::try_from(y).unwrap_or(0),
        u32::try_from(m).unwrap_or(0),
        u32::try_from(d).unwrap_or(0),
    )
}

#[must_use]
pub fn valid_session_id(id: &str) -> bool {
    (1..=80).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Session {
        let mut s = Session::new("t");
        s.apply_recover("o", "r", "c", "s");
        s.add_candidate(Candidate {
            statement: "x".into(),
            alternatives: vec![],
            reverse_observation: "y".into(),
        })
        .unwrap();
        s.add_falsify(FalsifyRecord {
            attack: "a".into(),
            test: "t".into(),
            result: "r".into(),
        })
        .unwrap();
        s.add_verify(VerifyRecord {
            claim: "c".into(),
            status: Status::Verified,
            evidence_level: EvidenceLevel::DirectObservation,
            does_not_show: "d".into(),
        })
        .unwrap();
        s
    }

    #[test]
    fn uppercase_or_short_tip_is_refused() {
        let mut s = complete();
        assert!(s.terminate("r".into(), false, &"AB".repeat(32)).is_err());
        assert!(s.terminate("r".into(), false, &"ab".repeat(31)).is_err());
        assert!(s.termination.is_none());
        s.terminate("r".into(), false, &"ab".repeat(32)).unwrap();
        assert!(s.bound_to(&"ab".repeat(32)));
    }

    #[test]
    fn partial_terminate_never_binds_a_non_hash_tip() {
        let mut s = Session::new("p");
        assert!(s.terminate("r".into(), true, "not-a-hash").is_err());
        assert!(s.termination.is_none());
        s.terminate("r".into(), true, "").unwrap();
        assert!(!s.bound_to("not-a-hash"));
        s.terminate("r".into(), true, &"ab".repeat(32)).unwrap();
        assert!(s.bound_to(&"ab".repeat(32)));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}
