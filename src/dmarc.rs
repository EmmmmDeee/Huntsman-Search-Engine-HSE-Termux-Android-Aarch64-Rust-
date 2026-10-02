//! DMARC (RFC 7489) parsing and analysis.

/// True if `txt` starts with `v=DMARC1` (ASCII-case-insensitive).
#[must_use]
pub fn is_dmarc(txt: &str) -> bool {
    let bytes = txt.as_bytes();
    bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"v=DMARC1")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

impl DmarcPolicy {
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::None => "dmarc:none",
            Self::Quarantine => "dmarc:quarantine",
            Self::Reject => "dmarc:reject",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "quarantine" => Some(Self::Quarantine),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    Relaxed,
    Strict,
}

impl AlignmentMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "r" => Some(Self::Relaxed),
            "s" => Some(Self::Strict),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcIssue {
    NoEnforcement,
    PartialCoverage(u8),
    SubdomainUnprotected,
    NoAggregateReports,
    MissingPolicy,
}

impl DmarcIssue {
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoEnforcement => "dmarc:no-enforcement",
            Self::PartialCoverage(_) => "dmarc:partial-coverage",
            Self::SubdomainUnprotected => "dmarc:subdomain-unprotected",
            Self::NoAggregateReports => "dmarc:no-aggregate-reports",
            Self::MissingPolicy => "dmarc:missing-policy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    pub policy: Option<DmarcPolicy>,
    pub sp: Option<DmarcPolicy>,
    pub pct: u8,
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: Option<String>,
    pub ri: u32,
    pub rf: Option<String>,
}

impl Default for DmarcRecord {
    fn default() -> Self {
        Self {
            policy: None,
            sp: None,
            pct: 100,
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            rua: Vec::new(),
            ruf: Vec::new(),
            fo: None,
            ri: 86_400,
            rf: None,
        }
    }
}

#[must_use]
pub fn parse(txt: &str) -> Option<DmarcRecord> {
    if !is_dmarc(txt) {
        return None;
    }

    let mut rec = DmarcRecord::default();
    let mut seen = std::collections::BTreeSet::new();

    for raw_tag in txt.split(';') {
        let tag = raw_tag.trim();
        if tag.is_empty() {
            continue;
        }
        let Some((name_raw, value)) = tag.split_once('=') else {
            continue;
        };
        let name = name_raw.trim().to_ascii_lowercase();
        match name.as_str() {
            "v" => {
                seen.insert(name);
            }
            "p" => {
                if seen.contains("p") {
                    continue;
                }
                if let Some(policy) = DmarcPolicy::parse(value) {
                    rec.policy = Some(policy);
                    seen.insert(name);
                }
            }
            "sp" => {
                if seen.contains("sp") {
                    continue;
                }
                if let Some(policy) = DmarcPolicy::parse(value) {
                    rec.sp = Some(policy);
                    seen.insert(name);
                }
            }
            "pct" => {
                if seen.contains("pct") {
                    continue;
                }
                if let Ok(pct) = value.trim().parse::<u8>() {
                    if pct <= 100 {
                        rec.pct = pct;
                        seen.insert(name);
                    }
                }
            }
            "adkim" => {
                if seen.contains("adkim") {
                    continue;
                }
                if let Some(mode) = AlignmentMode::parse(value) {
                    rec.adkim = mode;
                    seen.insert(name);
                }
            }
            "aspf" => {
                if seen.contains("aspf") {
                    continue;
                }
                if let Some(mode) = AlignmentMode::parse(value) {
                    rec.aspf = mode;
                    seen.insert(name);
                }
            }
            "rua" => {
                if seen.insert(name) {
                    rec.rua = parse_mailto_list(value);
                }
            }
            "ruf" => {
                if seen.insert(name) {
                    rec.ruf = parse_mailto_list(value);
                }
            }
            "fo" => {
                if seen.insert(name) {
                    rec.fo = Some(value.trim().to_string());
                }
            }
            "ri" => {
                if seen.contains("ri") {
                    continue;
                }
                if let Ok(ri) = value.trim().parse::<u32>() {
                    rec.ri = ri;
                    seen.insert(name);
                }
            }
            "rf" if !seen.contains("rf") => {
                rec.rf = Some(value.trim().to_string());
                seen.insert(name);
            }
            _ => {}
        }
    }

    Some(rec)
}

fn parse_mailto_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let addr = trimmed.strip_prefix("mailto:")?;
            let addr = addr.split('!').next().unwrap_or(addr).trim();
            if addr.contains('@') && addr.len() >= 5 {
                Some(addr.to_string())
            } else {
                None
            }
        })
        .collect()
}

impl DmarcRecord {
    #[must_use]
    pub fn issues(&self) -> Vec<DmarcIssue> {
        let mut issues = Vec::new();
        match self.policy {
            None => issues.push(DmarcIssue::MissingPolicy),
            Some(DmarcPolicy::None) => {
                issues.push(DmarcIssue::NoEnforcement);
                if self
                    .sp
                    .is_none_or(|policy| matches!(policy, DmarcPolicy::None))
                {
                    issues.push(DmarcIssue::SubdomainUnprotected);
                }
            }
            Some(DmarcPolicy::Quarantine | DmarcPolicy::Reject) => {
                if self.sp == Some(DmarcPolicy::None) {
                    issues.push(DmarcIssue::SubdomainUnprotected);
                }
            }
        }
        if self.pct < 100 {
            issues.push(DmarcIssue::PartialCoverage(self.pct));
        }
        if self.rua.is_empty() {
            issues.push(DmarcIssue::NoAggregateReports);
        }
        issues
    }

    #[must_use]
    pub fn report_addresses(&self) -> Vec<&str> {
        let mut addresses: Vec<&str> = self
            .rua
            .iter()
            .chain(self.ruf.iter())
            .map(String::as_str)
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_reports_dmarc() {
        let record = parse(
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:agg@example.com!10m; ruf=mailto:dmarc@example.com; pct=75; adkim=s; aspf=s",
        )
        .expect("DMARC record");
        assert_eq!(record.policy, Some(DmarcPolicy::Reject));
        assert_eq!(record.pct, 75);
        assert_eq!(record.adkim, AlignmentMode::Strict);
        assert_eq!(record.aspf, AlignmentMode::Strict);
        assert_eq!(
            record.report_addresses(),
            vec!["agg@example.com", "dmarc@example.com"]
        );
        assert!(record.issues().contains(&DmarcIssue::PartialCoverage(75)));
    }

    #[test]
    fn flags_missing_policy_and_non_enforcement() {
        let missing = parse("v=DMARC1; rua=mailto:a@b.com").expect("record");
        assert!(missing.issues().contains(&DmarcIssue::MissingPolicy));

        let none = parse("v=DMARC1; p=none").expect("record");
        assert!(none.issues().contains(&DmarcIssue::NoEnforcement));
        assert!(none.issues().contains(&DmarcIssue::SubdomainUnprotected));
        assert!(none.issues().contains(&DmarcIssue::NoAggregateReports));
    }

    #[test]
    fn first_duplicate_tag_wins() {
        let record = parse("v=DMARC1; p=reject; p=none; pct=120; pct=90").expect("record");
        assert_eq!(record.policy, Some(DmarcPolicy::Reject));
        assert_eq!(
            record.pct, 90,
            "first invalid pct is ignored; first valid duplicate wins"
        );
    }

    #[test]
    fn recognises_only_dmarc_records() {
        assert!(is_dmarc("v=DMARC1; p=reject"));
        assert!(!is_dmarc("v=spf1 -all"));
        assert!(parse("v=spf1 -all").is_none());
    }
}
