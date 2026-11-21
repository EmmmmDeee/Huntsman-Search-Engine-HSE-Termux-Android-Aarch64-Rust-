//! Offline breach-search candidate planning and operator-evidence CI ranking.
//! This module never fetches leaks, consumes API credits, or promotes a fuzzy
//! selector into proof of identity. Existing keyed clients remain the only
//! permitted network execution paths.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::dehashed::{Field, Purpose, QueryError, Selector};
use crate::username_variants;
use crate::people_discovery;

pub const USAGE: &str = concat!(
    "breach-ci plan email|username|domain|name VALUE --purpose own-account|authorized-engagement|incident-response|security-research\n",
    "breach-ci names FILE.txt --purpose own-account|authorized-engagement|incident-response\n",
    "breach-ci rank FILE.json\n",
    "Plan bounded exact provider checks plus conditional public OSINT pivots offline. ",
    "Rank analyst-supplied non-secret evidence metadata by heuristic Confidence Index (0-100). ",
    "No network activity, breach records, credential values or automatic identity attribution."
);

pub const MAX_FULL_NAMES: usize = 128;
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

/// ASCII case-insensitive Levenshtein distance, without heap allocation.
/// Callers have already validated both username lengths (at most 64 bytes).
fn username_distance(left: &str, right: &str) -> usize {
    let a = left.as_bytes();
    let b = right.as_bytes();
    if a.len() > 64 || b.len() > 64 {
        return 65;
    }
    let mut previous = [0_usize; 65];
    let mut current = [0_usize; 65];
    for (index, slot) in previous.iter_mut().take(b.len() + 1).enumerate() {
        *slot = index;
    }
    for (i, &left_byte) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, &right_byte) in b.iter().enumerate() {
            let substitution = usize::from(
                left_byte.to_ascii_lowercase() != right_byte.to_ascii_lowercase(),
            );
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + substitution);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

/// Produce a bounded query plan, reusing DeHashed's validated selectors and
/// existing deterministic username variants. No provider calls are performed.
///
/// # Errors
/// Rejects a selector that violates the exact-match provider contract.
#[allow(clippy::too_many_lines)] // bounded source decision matrix stays explicit and auditable
pub fn plan(field: Field, value: &str, purpose: Purpose) -> Result<Plan, QueryError> {
    if purpose == Purpose::SecurityResearch && field != Field::Domain {
        return Err(QueryError::Invalid(
            "security-research cannot plan breach lookups for private-account selectors",
        ));
    }
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
                    let penalty = match username_distance(value, &candidate) {
                        0 => 0,
                        1 => 6,
                        2 => 12,
                        3 => 18,
                        _ => 24,
                    };
                    push_check(
                        &mut checks,
                        55 - penalty,
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

/// One deterministic, locally validated name-only candidate batch.
/// A returned person-name match is a lead, never an identity or breach match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameBatch {
    pub name_count: usize,
    pub duplicate_names: usize,
    pub plans: Vec<Plan>,
    pub evidence_status: &'static str,
    pub provenance_policy: &'static str,
}

/// Validate one full personal name using the same rules as people-discover.
/// No person identifier, account, email, or breach hit is inferred from it.
///
/// # Errors
/// Refuses unsafe, incomplete or out-of-scope personal-name selectors.
pub fn plan_full_name(name: &str, purpose: Purpose) -> Result<Plan, &'static str> {
    if purpose == Purpose::SecurityResearch {
        return Err("a full personal name requires own-account, authorised engagement or incident-response purpose");
    }
    people_discovery::checked_name(name)
        .map_err(|_| "invalid full name: use two or more alphabetic name tokens, at most 120 bytes")?;
    let display = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut checks = Vec::with_capacity(4);
    for (priority, provider, basis, requirement) in [
        (100, "people-discover", "full_name_public_index_lead", "keyless; sends full name to public search indexes only upon separate execution"),
        (90, "people", "full_name_public_register_lead", "keyless; actual name match requires validation against original records"),
        (75, "Open Library", "full_name_bibliography_lead", "keyless; author names are not unique identifiers"),
        (60, "public archives", "full_name_historical_lead", "separate opt-in public research; archived records can be stale"),
    ] {
        push_check(&mut checks, priority, provider, "full_name", &display, basis, requirement);
    }
    Ok(Plan {
        purpose: purpose.as_str(),
        field: "full_name",
        candidate_count: 1,
        checks,
        osint_pivots: vec![
            OsintPivot {
                priority: 100,
                capability: "public full-name source records and jurisdiction/timeframe disambiguation",
                prerequisite: "public source containing the complete submitted name",
                evidentiary_limit: "a common name or indexed profile cannot establish the same individual",
            },
            OsintPivot {
                priority: 90,
                capability: "independent official records with explicit entity identifiers",
                prerequisite: "original records with grounded jurisdiction and temporal context",
                evidentiary_limit: "multiple records or mirrored indexes may describe different namesakes",
            },
            OsintPivot {
                priority: 70,
                capability: "existing exact-selector breach checks and corroborating public OSINT",
                prerequisite: "an independently verified, authorised email, username or controlled domain",
                evidentiary_limit: "never derive email addresses, handles, breach affiliation or identity solely from a full name",
            },
        ],
        evidence_status: "not_queried",
        ci_policy: "no CI for name-only leads; name similarity is not identity; exact breach selectors require independently justified authorisation",
    })
}

/// Produce plans for every unique valid full name in a bounded local file.
/// Blank lines and comments are ignored; duplicate canonical names collapse.
/// No query is made and no evidence is promoted.
///
/// # Errors
/// Fails closed on any invalid name or more than 128 distinct names.
pub fn plan_full_names(input: &str, purpose: Purpose) -> Result<NameBatch, &'static str> {
    let mut seen = BTreeSet::new();
    let mut plans = Vec::new();
    let mut duplicate_names = 0;
    for line in input.lines() {
        let name = line.trim();
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        let canonical = people_discovery::checked_name(line)
            .map_err(|_| "name-list contains an invalid full personal name")?;
        if !seen.insert(canonical) {
            duplicate_names += 1;
            continue;
        }
        if plans.len() == MAX_FULL_NAMES {
            return Err("name-list exceeds 128 unique full names");
        }
        plans.push(plan_full_name(line, purpose)?);
    }
    if plans.is_empty() {
        return Err("name-list contains no valid full names");
    }
    Ok(NameBatch {
        name_count: plans.len(),
        duplicate_names,
        plans,
        evidence_status: "not_queried",
        provenance_policy: "operator-supplied names only; no namesake merge, data breach search or independent identity confirmation",
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
        ci += match origins.saturating_sub(1).min(3) {
            0 => 0,
            1 => 9,
            2 => 18,
            _ => 27,
        };
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
    fn full_name_plans_preserve_complete_names_without_breach_attribution() {
        let plan = plan_full_name("Anne Marie O'Neill", Purpose::AuthorizedEngagement);
        assert!(plan.is_ok(), "validity depends on shared name checker");
        let plan = plan.unwrap();
        assert_eq!(plan.field, "full_name");
        assert_eq!(plan.candidate_count, 1);
        assert_eq!(plan.checks[0].selector, "Anne Marie O'Neill");
        assert!(plan.checks.iter().all(|check| check.state == "not_queried"));
        assert!(plan.checks.iter().all(|check| check.confidence_index.is_none()));
        assert!(!plan.checks.iter().any(|check| check.provider == "DeHashed"));
    }

    #[test]
    fn name_batch_keeps_all_unique_full_names_and_counts_duplicates() {
        let batch = plan_full_names(
            "# reviewed scope\nJohn Albert Stephens\nJane Mary Smith\njohn albert stephens\n\n",
            Purpose::AuthorizedEngagement,
        )
        .unwrap();
        assert_eq!(batch.name_count, 2);
        assert_eq!(batch.duplicate_names, 1);
        assert_eq!(batch.plans[0].checks[0].selector, "John Albert Stephens");
        assert_eq!(batch.plans[1].checks[0].selector, "Jane Mary Smith");
    }

    #[test]
    fn name_batch_rejects_invalid_and_unsafe_name_inputs() {
        assert!(plan_full_names("John Smith\nJane\n", Purpose::AuthorizedEngagement).is_err());
        assert!(plan_full_names("John Smith\nJane\tSmith\n", Purpose::AuthorizedEngagement).is_err());
        assert!(plan_full_names("John Smith\n", Purpose::SecurityResearch).is_err());
        assert!(plan_full_names("# empty\n", Purpose::AuthorizedEngagement).is_err());
        let huge = (0..=MAX_FULL_NAMES)
            .map(|i| format!("Person{i} Example"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan_full_names(&huge, Purpose::AuthorizedEngagement).is_err());
    }

    #[test]
    fn fuzzy_username_edit_distance_is_bounded_and_case_insensitive() {
        assert_eq!(username_distance("John.Doe", "john.doe"), 0);
        assert_eq!(username_distance("John.Doe", "john_doe"), 1);
        assert_eq!(username_distance("John.Doe", "johndoe"), 1);
        assert_eq!(username_distance("abc", "xyz"), 3);
        assert_eq!(username_distance(&"x".repeat(65), "x"), 65);
    }

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
    fn research_purpose_cannot_target_private_account_identifiers() {
        assert!(plan(Field::Email, "alice@example.org", Purpose::SecurityResearch).is_err());
        assert!(plan(Field::Username, "alice", Purpose::SecurityResearch).is_err());
        assert!(plan(Field::Domain, "example.org", Purpose::SecurityResearch).is_ok());
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
