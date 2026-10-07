//! End-to-end front-end for `huntsman-recon username`.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::bluesky_user;
use crate::canonical::canonical_handle;
use crate::entity::{self, Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::evidence_ancestry::EvidenceNodeId;
use crate::github_user;
use crate::http::Transport;
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{Lineage, Observation, ObservedLineage, UpstreamKind, resolve_with_lineage};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::username_variants::{VARIANT_CONFIDENCE, variants};
use crate::validation::{ValueKind, is_placeholder_entity};

pub const USERNAME_USAGE: &str = "usage: huntsman-recon username HANDLE [--save FILE]";
pub const USERNAME_HELP: &str = "\
username HANDLE [--save FILE]
Derive deterministic handle variants and query keyless public GitHub and Bluesky profiles. --save FILE writes an unverified ledger that verify can reload.";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameArgs {
    pub username: String,
    pub save: Option<PathBuf>,
}

impl UsernameArgs {
    /// # Errors
    /// Invalid/missing handle, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut positional = Vec::new();
        let mut save = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--save" => {
                    if save.is_some() {
                        return Err(Error::Invalid("only one --save".into()));
                    }
                    let path = it
                        .next()
                        .cloned()
                        .ok_or_else(|| Error::Invalid("--save needs a value".into()))?;
                    if path.is_empty() || path.starts_with("--") {
                        return Err(Error::Invalid("--save needs a file path".into()));
                    }
                    save = Some(PathBuf::from(path));
                }
                flag if flag.starts_with("--") => {
                    return Err(Error::Invalid(format!("unknown option {flag}")));
                }
                value => positional.push(value.to_owned()),
            }
        }
        if positional.len() != 1 {
            return Err(Error::Invalid("username needs exactly one HANDLE".into()));
        }
        let username = selector(&positional[0])?;
        Ok(Self { username, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UsernameRun {
    Printed { text: String, report: Report },
    Failed(String),
}

/// Run deterministic variants and the two keyless public-profile collectors.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, username: &str, now_unix: u64) -> UsernameRun {
    let username = match selector(username) {
        Ok(username) => username,
        Err(error) => return UsernameRun::Failed(error.to_string()),
    };
    let scan_id = entity::scan_id("username", &username);
    let mut report = Report {
        entities: derived_entities(&username, &scan_id),
        outcomes: Vec::new(),
    };

    collect_github(transport, &username, &scan_id, now_unix, &mut report);
    collect_bluesky(transport, &username, &scan_id, now_unix, &mut report);
    merge_by_uid(&mut report.entities);

    match render(&report) {
        Ok(text) => UsernameRun::Printed { text, report },
        Err(message) => UsernameRun::Failed(message),
    }
}

fn selector(raw: &str) -> Result<String, Error> {
    let value = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::Invalid("invalid username selector".into()));
    }
    let canonical = canonical_handle(&value)
        .ok_or_else(|| Error::Invalid("invalid username selector".into()))?;
    if is_placeholder_entity(&ValueKind::Username, &canonical) {
        return Err(Error::Invalid("placeholder username selector".into()));
    }
    Ok(value)
}

fn derived_entities(username: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    let mut seed = Entity::new(EntityKind::Username, username, 0.99, scan_id);
    seed.tag("seed");
    seed.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        "operator-supplied username selector",
    ));
    entities.push(seed);

    for variant in variants(username) {
        let mut entity = Entity::new(EntityKind::Username, &variant, VARIANT_CONFIDENCE, scan_id);
        entity.tag("derived");
        entity.tag("variant");
        entity.tag("candidate");
        entity.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan("username_variants", scan_id),
                format!("Handle normalization variant of '{username}'"),
            )
            .with_attr("source_username", username)
            .with_attr("derivation", "handle_variant")
            .inferred(),
        );
        entities.push(entity);
    }
    entities
}

fn collect_github<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) {
    match github_user::lookup(transport, username, scan_id, now_unix) {
        Ok(found) => {
            report.entities.extend(found.entities);
            report.outcomes.push(found.outcome);
        }
        Err(error) => report
            .outcomes
            .push(error_outcome(github_user::SRC, now_unix, &error)),
    }
}

fn collect_bluesky<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) {
    match bluesky_user::lookup(transport, username, scan_id, now_unix) {
        Ok(found) => {
            report.entities.extend(found.entities);
            report.outcomes.push(found.outcome);
        }
        Err(error) => report
            .outcomes
            .push(error_outcome(bluesky_user::SRC, now_unix, &error)),
    }
}

fn error_outcome(module: &str, now_unix: u64, error: &Error) -> SourceExecutionOutcome {
    SourceExecutionOutcome {
        module: module.into(),
        kind: SourceOutcomeKind::Inconclusive,
        observed_at_unix: now_unix,
        http_status: None,
        found: None,
        retry_after_secs: None,
        detail: Some(error.to_string()),
    }
}

fn render(report: &Report) -> Result<String, String> {
    let mut out = format!("entities={}\n", report.entities.len());
    for entity in &report.entities {
        writeln!(
            out,
            "{}\t{}\t{:.2}\t{}",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        )
        .map_err(|error| error.to_string())?;
    }
    for outcome in &report.outcomes {
        let found = outcome
            .found
            .map_or_else(|| "none".to_owned(), |count| count.to_string());
        let kind = serde_json::to_value(outcome.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".into());
        writeln!(out, "{}\t{kind}\tfound={found}", outcome.module)
            .map_err(|error| error.to_string())?;
    }
    append_lineage(report, &mut out)?;
    Ok(out)
}

fn append_lineage(report: &Report, out: &mut String) -> Result<(), String> {
    let observations = observations(report);
    if observations.is_empty() {
        return Ok(());
    }
    let resolution = resolve_with_lineage(observations, Vec::new(), AutoMergePolicy::default())
        .map_err(|error| error.to_string())?;
    writeln!(out, "lineage={}", resolution.observations.len())
        .map_err(|error| error.to_string())?;
    for item in &resolution.observations {
        writeln!(out, "{}", lineage_line(item)).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn observations(report: &Report) -> Vec<Observation> {
    report
        .entities
        .iter()
        .enumerate()
        .flat_map(|(entity_index, entity)| {
            entity
                .evidence
                .iter()
                .enumerate()
                .map(move |(evidence_index, evidence)| Observation {
                    id: EvidenceNodeId(format!("{}:{entity_index}:{evidence_index}", entity.uid)),
                    evidence: evidence.clone(),
                })
        })
        .collect()
}

fn lineage_line(item: &ObservedLineage) -> String {
    let id = &item.observation.id.0;
    match &item.lineage {
        Lineage::Upstream { kind, family, .. } => {
            format!("{id}\t{}\t{family}", upstream_kind_label(*kind))
        }
        Lineage::Unattributed => format!("{id}\tunattributed"),
        Lineage::Ambiguous { field, values } => {
            format!("{id}\tambiguous\t{field}\t{}", values.join(";"))
        }
    }
}

const fn upstream_kind_label(kind: UpstreamKind) -> &'static str {
    match kind {
        UpstreamKind::Dataset => "dataset",
        UpstreamKind::Registry => "registry",
        UpstreamKind::Source => "source",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::http::{Request, Response, TransportFailure};

    struct Fake {
        replies: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn new(replies: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }

    fn response(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn parses_handle_and_save() {
        let parsed =
            UsernameArgs::parse(&["@Jane.Doe".into(), "--save".into(), "out.json".into()]).unwrap();
        assert_eq!(parsed.username, "jane.doe");
        assert_eq!(parsed.save, Some(PathBuf::from("out.json")));
    }

    #[test]
    fn rejects_path_and_placeholder_selectors() {
        assert!(UsernameArgs::parse(&["../root".into()]).is_err());
        assert!(UsernameArgs::parse(&["username".into()]).is_err());
    }

    #[test]
    fn run_combines_variants_github_and_bluesky() {
        let github = r#"{
          "login":"jane-doe",
          "id":7,
          "html_url":"https://github.com/jane-doe",
          "name":"Jane Citizen",
          "email":"jane@example.org"
        }"#;
        let bluesky = r#"{
          "handle":"jane-doe.bsky.social",
          "displayName":"Jane Citizen",
          "did":"did:plc:oky5czdrnfjpqslsw2a5iclo"
        }"#;
        let fake = Fake::new(vec![Ok(response(200, github)), Ok(response(200, bluesky))]);
        match run(&fake, "jane-doe", 1) {
            UsernameRun::Printed { text, report } => {
                assert!(text.contains("github_user\tsuccess"), "{text}");
                assert!(text.contains("bluesky_user\tsuccess"), "{text}");
                assert!(text.contains("lineage="), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.kind == EntityKind::Email)
                );
            }
            other @ UsernameRun::Failed(_) => panic!("{other:?}"),
        }
    }

    #[test]
    fn one_clean_miss_does_not_erase_the_other_source() {
        let bluesky = r#"{"handle":"nobody.bsky.social"}"#;
        let fake = Fake::new(vec![Ok(response(404, "")), Ok(response(200, bluesky))]);
        match run(&fake, "nobody", 1) {
            UsernameRun::Printed { report, .. } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
                assert_eq!(report.outcomes[1].kind, SourceOutcomeKind::Success);
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.has_tag("bluesky"))
                );
            }
            other @ UsernameRun::Failed(_) => panic!("{other:?}"),
        }
    }
}
