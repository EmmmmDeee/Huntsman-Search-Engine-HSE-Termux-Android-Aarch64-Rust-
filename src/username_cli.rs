//! End-to-end front-end for `huntsman-recon username`.
//!
//! The command preserves the operator-supplied handle, derives bounded legacy
//! variants locally, queries public GitHub and Bluesky profile APIs through the
//! shared transport, and renders provenance lineage.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::bluesky_user;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::error::Error;
use crate::evidence_ancestry::EvidenceNodeId;
use crate::github_user;
use crate::http::Transport;
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{Lineage, Observation, ObservedLineage, UpstreamKind, resolve_with_lineage};
use crate::source_outcome::SourceExecutionOutcome;
use crate::uid;
use crate::username_variants;

pub const USERNAME_USAGE: &str = "usage: huntsman-recon username HANDLE [--save FILE]";
pub const USERNAME_HELP: &str = "\
username HANDLE [--save FILE]
Derive bounded handle variants and query public GitHub and Bluesky profiles. --save FILE writes an unverified ledger that verify can reload.";

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
    /// Invalid/missing handle, repeated `--save`, or unknown option.
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
        let username = normalize_selector(&positional[0])
            .ok_or_else(|| Error::Invalid("invalid username handle".into()))?;
        Ok(Self { username, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UsernameRun {
    Printed { text: String, report: Report },
    Failed(String),
}

#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, username: &str, now_unix: u64) -> UsernameRun {
    let Some(username) = normalize_selector(username) else {
        return UsernameRun::Failed("invalid username handle".into());
    };
    let scan_id = uid::scan_id("username", &username);
    let mut report = Report {
        entities: seed_and_variants(&username, &scan_id),
        outcomes: Vec::new(),
    };

    match github_user::lookup(transport, &username, &scan_id, now_unix) {
        Ok(got) => {
            report.entities.extend(got.entities);
            report.outcomes.push(got.outcome);
        }
        Err(err) => return UsernameRun::Failed(err.to_string()),
    }

    match bluesky_user::lookup(transport, &username, &scan_id, now_unix) {
        Ok(got) => {
            report.entities.extend(got.entities);
            report.outcomes.push(got.outcome);
        }
        Err(err) => return UsernameRun::Failed(err.to_string()),
    }

    dedupe_exact(&mut report.entities);
    match render(&report) {
        Ok(text) => UsernameRun::Printed { text, report },
        Err(err) => UsernameRun::Failed(err),
    }
}

fn normalize_selector(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('@').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        || value.starts_with(['.', '_', '-'])
        || value.ends_with(['.', '_', '-'])
    {
        return None;
    }
    Some(value)
}

fn seed_and_variants(username: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    let mut seed = Entity::new(EntityKind::Username, username, 0.99, scan_id);
    seed.tag("seed");
    seed.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        "operator-supplied username selector",
    ));
    entities.push(seed);
    entities.extend(username_variants::entities(username, scan_id));
    entities
}

fn dedupe_exact(entities: &mut Vec<Entity>) {
    let mut seen = BTreeSet::new();
    entities.retain(|entity| {
        seen.insert((
            entity.kind.clone(),
            entity.raw_value.trim().to_ascii_lowercase(),
            entity
                .evidence
                .first()
                .map(|e| e.provenance.source.clone())
                .unwrap_or_default(),
        ))
    });
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
        .map_err(|err| err.to_string())?;
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
            .map_err(|err| err.to_string())?;
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
        .map_err(|err| err.to_string())?;
    writeln!(out, "lineage={}", resolution.observations.len()).map_err(|err| err.to_string())?;
    for item in &resolution.observations {
        writeln!(out, "{}", lineage_line(item)).map_err(|err| err.to_string())?;
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
    use crate::source_outcome::SourceOutcomeKind;

    struct Fake {
        responses: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn new(responses: Vec<Response>) -> Self {
            Self {
                responses: RefCell::new(responses.into_iter().map(Ok).collect()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }

    fn response(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn parse_accepts_at_handle_and_save() {
        let parsed = UsernameArgs::parse(&[
            "@Jane_Doe".into(),
            "--save".into(),
            "out.json".into(),
        ])
        .unwrap();
        assert_eq!(parsed.username, "jane_doe");
        assert_eq!(parsed.save, Some(PathBuf::from("out.json")));
    }

    #[test]
    fn variant_expansion_matches_legacy_examples() {
        let variants = username_variants::variants("john.doe");
        assert_eq!(variants, vec!["john-doe", "john_doe", "johndoe"]);
        assert!(username_variants::variants("jdoe1990").contains(&"jdoe".to_owned()));
        assert!(
            username_variants::variants("the_real_jdoe").contains(&"jdoe".to_owned())
        );
    }

    #[test]
    fn run_combines_github_bluesky_and_variants() {
        let github = response(
            200,
            r#"{"login":"john-doe","name":"John Doe","html_url":"https://github.com/john-doe"}"#,
        );
        let bluesky = response(
            200,
            r#"{"handle":"john-doe.bsky.social","displayName":"John Doe"}"#,
        );
        match run(&Fake::new(vec![github, bluesky]), "john-doe", 1) {
            UsernameRun::Printed { text, report } => {
                assert!(text.contains("github_user\tsuccess"), "{text}");
                assert!(text.contains("bluesky_user\tsuccess"), "{text}");
                assert!(text.contains("lineage="), "{text}");
                assert_eq!(report.outcomes.len(), 2);
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.kind == EntityKind::Person)
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn dual_miss_keeps_seed_and_reports_two_valid_zeros() {
        match run(
            &Fake::new(vec![response(404, ""), response(400, "{}")]),
            "nobody",
            1,
        ) {
            UsernameRun::Printed { report, .. } => {
                assert_eq!(report.outcomes.len(), 2);
                assert!(
                    report
                        .outcomes
                        .iter()
                        .all(|outcome| outcome.kind == SourceOutcomeKind::ValidZero)
                );
                assert!(report.entities.iter().any(|entity| entity.tags.contains(&"seed".into())));
            }
            other => panic!("{other:?}"),
        }
    }
}
