//! Hugging Face account lookup for a username selector. Keyless -- the public user overview the
//! Hub serves at `https://huggingface.co/api/users/{username}/overview`.
//!
//! One handle resolves to the Hugging Face account. The overview names its account in `user`, and
//! the account is confirmed only when that is the queried handle ignoring ASCII case. A handle in
//! a case other than the account's own is answered with a `307` redirect, which the no-redirects
//! fetch reports as unresolved, never as a found or absent account. A `404` read as a plain
//! upstream 4xx is the clean "no such account" answer; a body that is not the account document is
//! schema or semantic drift. An organisation handle is answered as a missing user, so it is a
//! clean zero for this leg.
//!
//! The account keeps its public profile `Url`, join date, bio and model, dataset, space, paper and
//! follower counts as verbatim evidence. Its self-declared full name (two or more words) is a
//! `Person` candidate, and each organisation it publicly belongs to an `Organisation` candidate
//! tagged `membership`. Each is a lead to review, never proof of who controls the account.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::nonblank;

pub const SRC: &str = "huggingface_user";
const API_BASE: &str = "https://huggingface.co";

/// Hub handles are 1-96 characters: an ASCII letter, digit, hyphen, underscore or dot.
const MAX_HANDLE_LEN: usize = 96;
/// At most this many organisation memberships become entities; the rest stay a count.
const MAX_ORGS: usize = 25;

/// Confirmed-on-Hugging-Face handle: a single-source, keyless account-existence lead.
const USERNAME_CONF: f64 = 0.80;
/// The public profile page.
const PROFILE_URL_CONF: f64 = 0.74;
/// A self-declared name: a candidate lead.
const SELF_REPORTED_CONF: f64 = 0.55;
/// A public organisation membership: a candidate affiliation, never an employment claim.
const MEMBERSHIP_CONF: f64 = 0.55;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Overview {
    #[serde(default)]
    user: String,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    fullname: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    is_pro: Option<bool>,
    #[serde(default)]
    num_models: Option<u64>,
    #[serde(default)]
    num_datasets: Option<u64>,
    #[serde(default)]
    num_spaces: Option<u64>,
    #[serde(default)]
    num_papers: Option<u64>,
    #[serde(default)]
    num_followers: Option<u64>,
    #[serde(default)]
    orgs: Vec<Org>,
}

#[derive(Debug, Deserialize)]
struct Org {
    #[serde(default)]
    name: String,
    #[serde(default)]
    fullname: Option<String>,
}

/// Whether `handle` is a shape the Hub keys an account on. **Pure.**
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_HANDLE_LEN
        && !handle.starts_with(['.', '-'])
        && !handle.contains("..")
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The overview API URL. **Pure.**
#[must_use]
pub fn overview_url(handle: &str) -> String {
    format!(
        "{API_BASE}/api/users/{}/overview",
        percent_encode_unreserved(handle)
    )
}

/// The public profile page a human reads for a handle. **Pure.**
fn profile_url(handle: &str) -> String {
    format!("{API_BASE}/{}", percent_encode_unreserved(handle))
}

/// Look up one Hugging Face account, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the account URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let handle = username.trim().trim_start_matches('@');
    if !valid_handle(handle) {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a valid Hugging Face handle",
        )));
    }
    let fetched = fetch(
        transport,
        Request::get_json(overview_url(handle)),
        None,
        &FetchOptions::no_redirects().paced(),
        SRC,
        now_unix,
    )?;
    let (overview, status) = match interpret_overview(&fetched, handle, now_unix) {
        Ok(found) => found,
        Err(outcome) => return Ok(miss(outcome)),
    };
    let mut entities = build_entities(&overview, scan_id);
    merge_by_uid(&mut entities);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(status),
        entities,
    })
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// The confirmed account and response status; `Err` is the outcome of a response that named no
/// such account or a different one. **Pure.**
fn interpret_overview(
    fetched: &Fetched,
    handle: &str,
    now_unix: u64,
) -> Result<(Overview, u16), SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(
                SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(response.status)
            );
        }
    }
    let response = whole_response(fetched, "Hugging Face user")?;
    answer(fetched, "Hugging Face user")?;
    let overview: Overview = decode_json(response, SRC, now_unix, "Hugging Face user")?;
    if overview.user.trim().is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Hugging Face payload carried no user",
        ));
    }
    if !overview.user.trim().eq_ignore_ascii_case(handle) {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "Hugging Face returned a different account than the queried handle",
        ));
    }
    Ok((overview, response.status))
}

fn count(value: Option<u64>) -> Option<String> {
    value.map(|n| n.to_string())
}

fn overview_evidence(overview: &Overview, scan_id: &str) -> Evidence {
    let login = overview.user.trim();
    let models = count(overview.num_models);
    let datasets = count(overview.num_datasets);
    let spaces = count(overview.num_spaces);
    let papers = count(overview.num_papers);
    let followers = count(overview.num_followers);
    let orgs = overview.orgs.len().to_string();
    let pro = overview
        .is_pro
        .map(|pro| if pro { "true" } else { "false" });
    Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "Hugging Face account {login}: a public machine-learning hub account, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Hugging Face Hub")
    .with_attr("profile_url", profile_url(login))
    .with_attr("organisation_count", orgs)
    .with_optional_attrs([
        ("account_type", nonblank(overview.kind.as_deref())),
        ("created_at", nonblank(overview.created_at.as_deref())),
        ("fullname", nonblank(overview.fullname.as_deref())),
        ("details", nonblank(overview.details.as_deref())),
        ("is_pro", pro),
        ("models", models.as_deref()),
        ("datasets", datasets.as_deref()),
        ("spaces", spaces.as_deref()),
        ("papers", papers.as_deref()),
        ("followers", followers.as_deref()),
    ])
}

/// Build the report entities from the confirmed account. **Pure.**
fn build_entities(overview: &Overview, scan_id: &str) -> Vec<Entity> {
    let login = overview.user.trim();
    let evidence = overview_evidence(overview, scan_id);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Username,
        login,
        USERNAME_CONF,
        scan_id,
        evidence.clone(),
        &["huggingface", "code"],
    );
    push_entity(
        &mut entities,
        EntityKind::Url,
        &profile_url(login),
        PROFILE_URL_CONF,
        scan_id,
        evidence.clone(),
        &["huggingface", "code"],
    );
    if let Some(name) =
        nonblank(overview.fullname.as_deref()).filter(|n| n.split_whitespace().count() >= 2)
    {
        push_entity(
            &mut entities,
            EntityKind::Person,
            name,
            SELF_REPORTED_CONF,
            scan_id,
            evidence.clone(),
            &["huggingface", "self-reported"],
        );
    }
    for org in overview
        .orgs
        .iter()
        .filter(|org| valid_handle(org.name.trim()))
        .take(MAX_ORGS)
    {
        let label = nonblank(org.fullname.as_deref()).unwrap_or_else(|| org.name.trim());
        let org_evidence = Evidence::new(
            EvidenceProvenance::for_scan(SRC, scan_id),
            format!(
                "Hugging Face organisation {} lists {login} as a public member: a candidate affiliation, not an employment or control claim",
                org.name.trim()
            ),
        )
        .with_attr("dataset", "Hugging Face Hub")
        .with_attr("member", login)
        .with_attr("organisation_handle", org.name.trim())
        .with_attr("organisation_url", profile_url(org.name.trim()));
        push_entity(
            &mut entities,
            EntityKind::Organisation,
            label,
            MEMBERSHIP_CONF,
            scan_id,
            org_evidence,
            &["huggingface", "membership"],
        );
    }
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    /// Trimmed from `huggingface.co/api/users/julien-c/overview` on 2026-11-04.
    const JULIEN: &str = r#"{"_id":"5dd96eb166059660ed1ee413","isPro":true,"fullname":"Julien Chaumond","numModels":53,"numDatasets":26,"numSpaces":49,"numPapers":8,"numFollowers":5229,"orgs":[{"id":"5e67bd5b1009063689407478","name":"huggingface","fullname":"Hugging Face"},{"id":"63878a485c68cf2713b9f0af","name":"ph-snps","fullname":"ph-snps"},{"id":"x","name":"../bad"}],"user":"julien-c","type":"user","details":"<3 ML/AI for everyone","createdAt":"2019-11-23T17:38:57.000Z"}"#;

    fn report_of(body: &str, handle: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, handle, "scan-hf", 1).expect("lookup runs")
    }

    fn tagged(report: &Report, kind: &EntityKind, value: &str, tag: &str) -> bool {
        report
            .entities
            .iter()
            .any(|e| e.kind == *kind && e.raw_value == value && e.has_tag(tag))
    }

    #[test]
    fn valid_handle_accepts_hub_handles_only() {
        assert!(valid_handle("julien-c"));
        assert!(valid_handle("Ada.Lovelace_1"));
        assert!(!valid_handle(""));
        assert!(!valid_handle("-lead"));
        assert!(!valid_handle(".lead"));
        assert!(!valid_handle("a..b"));
        assert!(!valid_handle("../bad"));
        assert!(!valid_handle("has space"));
        assert!(!valid_handle(&"x".repeat(97)));
    }

    #[test]
    fn the_urls_carry_the_handle() {
        assert_eq!(
            overview_url("julien-c"),
            "https://huggingface.co/api/users/julien-c/overview"
        );
        assert_eq!(profile_url("julien-c"), "https://huggingface.co/julien-c");
    }

    #[test]
    fn a_confirmed_account_emits_username_person_and_memberships() {
        let report = report_of(JULIEN, "julien-c");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(tagged(
            &report,
            &EntityKind::Username,
            "julien-c",
            "huggingface"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Url,
            "https://huggingface.co/julien-c",
            "code"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Person,
            "Julien Chaumond",
            "self-reported"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Organisation,
            "Hugging Face",
            "membership"
        ));
        assert!(tagged(
            &report,
            &EntityKind::Organisation,
            "ph-snps",
            "membership"
        ));
        // A malformed organisation handle is never an entity.
        assert_eq!(
            report
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Organisation)
                .count(),
            2
        );
        let attr = |key: &str| {
            report
                .entities
                .iter()
                .find(|e| e.kind == EntityKind::Username)
                .and_then(|e| e.evidence.first())
                .and_then(|ev| ev.attributes.get(key))
                .cloned()
        };
        assert_eq!(attr("models").as_deref(), Some("53"));
        assert_eq!(
            attr("created_at").as_deref(),
            Some("2019-11-23T17:38:57.000Z")
        );
        assert_eq!(attr("organisation_count").as_deref(), Some("3"));
    }

    #[test]
    fn an_unknown_account_is_a_clean_negative() {
        let transport =
            OneResponse::with_headers(404, &[], r#"{"error":"This user does not exist"}"#);
        let report = lookup(&transport, "zz-nobody", "scan-hf", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_case_redirect_is_never_a_found_or_absent_account() {
        let transport =
            OneResponse::with_headers(307, &[("location", "/api/users/julien-c/overview")], "");
        let report = lookup(&transport, "Julien-C", "scan-hf", 1).expect("lookup runs");
        assert!(report.entities.is_empty());
        assert_ne!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_ne!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_payload_for_a_different_account_is_semantic_drift() {
        let report = report_of(r#"{"user":"someone-else"}"#, "julien-c");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn a_payload_without_a_user_is_schema_drift() {
        let report = report_of(r#"{"numModels":1}"#, "julien-c");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }
}
