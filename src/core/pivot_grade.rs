//! Pivot strength for a people-finding hop.
//!
//! An anchor is only as strong as the weakest A or B hop back to the fragment.
//! C or D is a hypothesis, not a finding.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PivotGrade {
    D = 0,
    C = 1,
    B = 2,
    A = 3,
}

impl PivotGrade {
    pub fn as_str(self) -> &'static str {
        match self {
            PivotGrade::A => "A",
            PivotGrade::B => "B",
            PivotGrade::C => "C",
            PivotGrade::D => "D",
        }
    }

    pub fn is_finding(self) -> bool {
        self >= PivotGrade::B
    }
}

/// Grade one hop from the kind of link, not from a shared name or place.
pub fn grade_hop(kind: &str) -> PivotGrade {
    match kind {
        "distinctive-password" | "session-cookie" | "hwid" | "phone-anchor" => PivotGrade::A,
        "common-password" | "rare-username" | "stealer-account-list" => PivotGrade::B,
        "common-username" | "email-pattern" | "handle-link" => PivotGrade::C,
        _ => PivotGrade::D,
    }
}

/// The chain is as strong as its weakest hop. An empty chain is not a finding.
pub fn weakest(grades: &[PivotGrade]) -> Option<PivotGrade> {
    grades.iter().copied().min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_match_is_not_a_finding() {
        assert_eq!(grade_hop("shared-name"), PivotGrade::D);
        assert!(!grade_hop("shared-name").is_finding());
    }

    #[test]
    fn the_chain_follows_the_weakest_hop() {
        let chain = [
            grade_hop("phone-anchor"),
            grade_hop("common-username"),
        ];
        assert_eq!(weakest(&chain), Some(PivotGrade::C));
        assert!(!weakest(&chain).unwrap().is_finding());
    }
}
