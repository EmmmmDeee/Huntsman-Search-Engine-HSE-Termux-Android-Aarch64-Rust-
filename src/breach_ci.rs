//! Offline breach-search candidate planning and operator-evidence CI ranking.
//! This module never fetches leaks, consumes API credits, or promotes a fuzzy
//! selector into proof of identity. Existing keyed clients remain the only
//! permitted network execution paths.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::dehashed::{Field, Purpose, QueryError, Selector};
use crate::username_variants;

pub const USAGE: &str = concat!(
    "breach-ci plan email|username|domain VALUE --purpose own-account|authorized-engagement|incident-response|security-research\n",
    "breach-ci rank FILE.json\n",
    "Plan bounded exact provider checks plus conditional public OSINT pivots offline. ",
    "Rank analyst-supplied non-secret evidence metadata by heuristic Confidence Index (0-100). ",
    "No network activity, breach records, credential values or automatic identity attribution."
);

const MAX_FINDINGS: usize = 128;
const MAX_ORIGINS: usize = 8;
const MAX_OPAQUE_ID: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCheck {
    pub priority: u8,
    pub provider: &'static str,
    pub field: &'static str,
    pub selector: String,
    pub match_basis: &'static str,
    pub credential_requirement: &'static str,
    pub confidence_index: Option<u8>,
    pub state: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsintPivot {
    pub priority: u8,
    pub capability: &'static str,
    pub prerequisite: &'static str,
    pub evidentiary_limit: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub purpose: &'static str,
    pub field: &'static str,
    pub candidate_count: usize,
    pub checks: Vec<SourceCheck>,
    pub osint_pivots: Vec<OsintPivot>,
    pub evidence_status: &'static str,
    pub ci_policy: &'static str,
}

fn push_check(
    checks: &mut Vec<SourceCheck>,
    priority: u8,
    provider: &'static str,
    field: &'static str,
    selector: &str,
    match_basis: &'static str,
    credential_requirement: &'static str,
) {
    checks.push(SourceCheck {
        priority,
        provider,
        field,
        selector: selector.to_owned(),
        match_basis,
        credential_requirement,
        confidence_index: None,
        state: "not_queried",
    });
}

/// Produce a bounded query plan, reusing DeHashed's validated selectors and
/// existing deterministic username variants. No provider calls are performed.
///
/// # Errors
/// Rejects a selector that violates the exact-match provider contract.
pub fn plan(field: Field, value: &str, purpose: Purpose) -> Result<Plan, QueryError> {
    let exact = Selector::new(field, value)?;
    let mut checks = Vec::new();
    let mut candidates = BTreeSet::new();
    candidates.insert(exact.value().to_owned());

    let pivots = match field {
        Field::Email => {
            push_check(&mut checks, 100, "HIBP", "email", value, "exact", "API key + subscription");
            push_check(&mut checks, 95, "XposedOrNot", "email", value, "exact", "public, availability unverified");
            push_check(&mut checks, 90, "DeHashed", "email", value, "exact", "own API key and credits");
            push_check(&mut checks, 80, "OathNet", "email", value, "exact", "own API key and entitlement");
            push_check(&mut checks, 70, "stolen.tax", "email", value, "exact", "own API key and entitlement");
            vec![
                OsintPivot {
                    priority: 95,
                    capability: "HIBP breach catalogue and incident metadata",
                    prerequisite: "exact account-breach hit",
                    evidentiary_limit: "a breached account does not establish its present controller",
                },
                OsintPivot {
                    priority: 90,
                    capability: "DNS/MX, RDAP and certificate transparency",
                    prerequisite: "validated email domain and authorised scope",
                    evidentiary_limit: "infrastructure records do not prove mailbox ownership",
                },
                OsintPivot {
                    priority: 65,
                    capability: "public account profile attribution",
                    prerequisite: "a separately observed profile URL or username",
                    evidentiary_limit: "matching handles alone cannot confirm a person",
                },
            ]
        }
        Field::Username => {
            push_check(&mut checks, 100, "DeHashed", "username", value, "exact", "own API key and credits");
            for candidate in username_variants::variants(value) {
                if Selector::new(Field::Username, &candidate).is_ok()
                    && candidates.insert(candidate.clone())
                {
                    push_check(
                        &mut checks,
                        55,
                        "DeHashed",
                        "username",
                        &candidate,
                        "fuzzy_candidate_exact_query",
                        "own API key and credits; explicit review before use",
                    );
                }
            }
            vec![
                OsintPivot {
                    priority: 95,
                    capability: "public profile exact-handle checks",
                    prerequisite: "a valid handle observed in a breach record",
                    evidentiary_limit: "an account name match is not person identity",
                },
                OsintPivot {
                    priority: 80,
                    capability: "archived public profile metadata",
                    prerequisite: "a source-backed public account URL",
                    evidentiary_limit: "historical pages may be stale or controlled by others",
                },
                OsintPivot {
                    priority: 60,
                    capability: "domain, certificate and DNS correlation",
                    prerequisite: "a distinct verified domain identifier",
                    evidentiary_limit: "fuzzy handles must never become DNS or ownership claims",
                },
            ]
        }
        Field::Domain => {
            push_check(&mut checks, 100, "DeHashed", "domain", value, "exact", "own API key and credits");
            push_check(
                &mut checks, 80, "HIBP", "domain", value,
                "verified_domain_only", "verified domain control and eligible HIBP plan",
            );
            vec![
                OsintPivot {
                    priority: 100,
                    capability: "DNS/MX and certificate transparency",
                    prerequisite: "validated domain",
                    evidentiary_limit: "DNS and CT cannot establish account exposure or person identity",
                },
                OsintPivot {
                    priority: 90,
                    capability: "RDAP and registration history",
                    prerequisite: "validated domain",
                    evidentiary_limit: "registrar privacy and historic registration limit attribution",
                },
                OsintPivot {
                    priority: 70,
                    capability: "Wayback, Common Crawl and public passive DNS",
                    prerequisite: "observed URLs or hostnames",
                    evidentiary_limit: "mirrors and archives do not supply independent breach proof",
                },
            ]
        }
    };
    checks.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.provider.cmp(b.provider))
            .then_with(|| a.selector.cmp(&b.selector))
    });
    Ok(Plan {
        purpose: purpose.as_str(),
        field: field.as_str(),
        candidate_count: candidates.len(),
        checks,
        osint_pivots: pivots,
        evidence_status: "not_queried",
        ci_policy: "CI is undefined until source observations exist; priority is investigative utility, not confidence or match probability",
    })
}

/// Operator-provided, non-secret metadata about one purported finding. Origin
/// identifiers must name ORIGINAL dataset lineages, not mirrored websites or
/// collector labels. This input assertion cannot authenticate those lineages.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingInput {
    pub id: String,
    pub exact_identifier: bool,
    pub fuzzy_match: bool,
    pub primary_record: bool,
    pub original_dataset_ids: Vec<String>,
    pub temporal_consistency: bool,
    pub contradicted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RankedFinding {
    pub id: String,
    pub confidence_index: u8,
    pub confidence_type: &'static str,
    pub distinct_claimed_origins: usize,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ranking {
    pub findings: Vec<RankedFinding>,
    pub scoring_contract: &'static str,
    pub provenance_status: &'static str,
}

fn opaque_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_OPAQUE_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Conservatively rank evidence metadata. This is an *uncalibrated heuristic*,
/// never a probability, and never upgrades the entity evidence state.
///
/// # Errors
/// Rejects unbounded inputs, duplicated IDs, identifiers that may embed PII,
/// or missing provenance. Source-root independence remains operator-asserted.
pub fn rank(inputs: Vec<FindingInput>) -> Result<Ranking, &'static str> {
    if inputs.len() > MAX_FINDINGS {
        return Err("too many findings");
    }
    let mut seen = BTreeSet::new();
    let mut findings = Vec::with_capacity(inputs.len());
    for finding in inputs {
        if !opaque_id(&finding.id) || !seen.insert(finding.id.clone()) {
            return Err("finding ids must be unique opaque ASCII tokens of 1..=64 bytes");
        }
        if finding.original_dataset_ids.is_empty()
            || finding.original_dataset_ids.len() > MAX_ORIGINS
            || !finding.original_dataset_ids.iter().all(|s| opaque_id(s))
        {
            return Err("each finding needs 1..=8 valid original dataset identifiers");
        }
        let origins = finding.original_dataset_ids.iter().collect::<BTreeSet<_>>().len();
        let mut ci: u8 = if finding.exact_identifier && !finding.fuzzy_match {
            35
        } else {
            12
        };
        ci += if finding.primary_record { 22 } else { 8 };
        ci += ((origins.saturating_sub(1)).min(3) as u8) * 9;
        if finding.temporal_consistency {
            ci += 10;
        }
        if finding.contradicted {
            ci = ci.saturating_sub(30).min(39);
        }
        if finding.fuzzy_match || !finding.exact_identifier {
            ci = ci.min(55);
        }
        if !finding.primary_record {
            ci = ci.min(70);
        }
        findings.push(RankedFinding {
            id: finding.id,
            confidence_index: ci,
            confidence_type: "uncalibrated_evidence_quality_heuristic",
            distinct_claimed_origins: origins,
            status: if finding.contradicted { "conflicted" } else { "requires_independent_verification" },
        });
    }
    findings.sort_by(|a, b| {
        b.confidence_index
            .cmp(&a.confidence_index)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(Ranking {
        findings,
        scoring_contract: "exact identifier 35 vs fuzzy 12; primary record 22 vs derivative 8; independently attested additional dataset roots +9 each (up to 3); temporal fit +10; conflict penalty -30 and CI cap 39; fuzzy CI cap 55; secondary-only cap 70",
        provenance_status: "operator_asserted_not_independently_verified; mirrored providers sharing one original dataset must use one origin ID",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_variants_are_bounded_and_never_presented_as_hits() {
        let plan = plan(
            Field::Username, "John.Doe", Purpose::AuthorizedEngagement,
        ).unwrap();
        assert!(plan.candidate_count <= username_variants::MAX_VARIANTS + 1);
        assert_eq!(plan.checks[0].selector, "John.Doe");
        assert_eq!(plan.checks[0].match_basis, "exact");
        assert!(plan.checks.iter().all(|step| step.confidence_index.is_none()));
        assert!(plan.checks.iter().all(|step| step.state == "not_queried"));
        assert!(plan.checks.iter().any(|step| step.selector == "john_doe"));
        assert!(!plan.checks.iter().any(|step| step.selector.contains('*')));
    }

    #[test]
    fn email_never_fuzzes_mailbox_and_domain_never_enumerates_people() {
        let email = plan(Field::Email, "alice@example.org", Purpose::OwnAccount).unwrap();
        assert_eq!(email.candidate_count, 1);
        assert!(email.checks.iter().all(|step| step.selector == "alice@example.org"));
        let domain = plan(Field::Domain, "example.org", Purpose::AuthorizedEngagement).unwrap();
        assert_eq!(domain.candidate_count, 1);
        assert!(domain.checks.iter().all(|step| step.selector == "example.org"));
        assert!(Selector::new(Field::Email, "a*@example.org").is_err());
    }

    #[test]
    fn ranking_deduplicates_origins_and_sorts_by_ci() {
        let high = FindingInput {
            id: "case-high".into(),
            exact_identifier: true,
            fuzzy_match: false,
            primary_record: true,
            original_dataset_ids: vec!["original-a".into(), "original-b".into(), "original-a".into()],
            temporal_consistency: true,
            contradicted: false,
        };
        let low = FindingInput {
            id: "case-low".into(),
            exact_identifier: false,
            fuzzy_match: true,
            primary_record: false,
            original_dataset_ids: vec!["original-a".into()],
            temporal_consistency: false,
            contradicted: false,
        };
        let report = rank(vec![low, high]).unwrap();
        assert_eq!(report.findings[0].id, "case-high");
        assert_eq!(report.findings[0].distinct_claimed_origins, 2);
        assert!(report.findings[1].confidence_index <= 55);
    }

    #[test]
    fn conflicting_and_fuzzy_claims_cannot_score_as_verified() {
        let mut entry = FindingInput {
            id: "candidate".into(),
            exact_identifier: true,
            fuzzy_match: false,
            primary_record: true,
            original_dataset_ids: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            temporal_consistency: true,
            contradicted: true,
        };
        assert!(rank(vec![entry.clone()]).unwrap().findings[0].confidence_index <= 39);
        entry.contradicted = false;
        entry.fuzzy_match = true;
        assert!(rank(vec![entry]).unwrap().findings[0].confidence_index <= 55);
    }

    #[test]
    fn rejects_duplicate_ids_pii_ids_and_missing_origin() {
        let base = FindingInput {
            id: "one".into(),
            exact_identifier: true,
            fuzzy_match: false,
            primary_record: true,
            original_dataset_ids: vec!["corpus".into()],
            temporal_consistency: false,
            contradicted: false,
        };
        assert!(rank(vec![base.clone(), base.clone()]).is_err());
        let mut bad = base.clone();
        bad.id = "person@example.org".into();
        assert!(rank(vec![bad]).is_err());
        let mut bad = base;
        bad.original_dataset_ids.clear();
        assert!(rank(vec![bad]).is_err());
    }
}
