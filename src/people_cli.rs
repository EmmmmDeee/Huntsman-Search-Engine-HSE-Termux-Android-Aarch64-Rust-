//! Collection front-end for `huntsman-recon people`.
//!
//! Lookup runs [`crate::asic_persons`], [`crate::asic_director`], [`crate::au_people`]
//! and [`crate::au_electoral`] over one injected [`crate::http::Transport`]. One
//! source's [`Error::Invalid`] or `BotWaf` does not abort the others. Evidence is
//! fed through [`crate::lineage::resolve_with_lineage`]. Tests inject fakes; live
//! sources are not run here. Saving a ledger is L7 ([`crate::people_save`]); this
//! module only parses `--save`.

use std::fmt::Write;
use std::path::PathBuf;

use crate::asic_director;
use crate::asic_persons;
use crate::au_electoral;
use crate::au_people;
use crate::entity::Entity;
use crate::error::Error;
use crate::evidence_ancestry::EvidenceNodeId;
use crate::http::Transport;
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{Lineage, Observation, ObservedLineage, UpstreamKind, resolve_with_lineage};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::uid;

pub const PEOPLE_USAGE: &str = "usage: huntsman-recon people NAME [--save FILE]";
pub const PEOPLE_HELP: &str = "\
people NAME [--save FILE]
Look up NAME on keyless ASIC people registers, ASIC Connect, True People Search AU, and NSW/VIC/QLD electoral rolls. Fewer than two alphabetic tokens makes no request. One source failure does not abort the others. --save FILE writes an unverified ledger that verify can reload; skip does not write.";

/// Merged entities and outcomes from every people source that ran.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}
/// Parsed `people` arguments. The name is the positional tokens joined with spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeopleArgs {
    pub name: String,
    pub save: Option<PathBuf>,
}

impl PeopleArgs {
    /// # Errors
    /// [`Error::Invalid`] when NAME is missing, `--save` has no path, `--save` is
    /// repeated, or an unknown option is present.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut name_parts = Vec::new();
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
                positional => name_parts.push(positional.to_owned()),
            }
        }
        if name_parts.is_empty() {
            return Err(Error::Invalid("missing NAME".into()));
        }
        Ok(Self {
            name: name_parts.join(" "),
            save,
        })
    }
}

/// Result of one `people` invocation, before the binary maps it to an exit code.
#[derive(Debug, Clone, PartialEq)]
pub enum PeopleRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

/// Look up `name` over `transport` and render entities, outcomes, and lineage.
/// A single-token name prints the skip line and makes no request.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, name: &str, now_unix: u64) -> PeopleRun {
    if name_tokens(name).len() < 2 {
        return PeopleRun::Printed {
            text: "people: skipped (need two alphabetic tokens)\n".into(),
            report: Report::default(),
        };
    }

    let scan_id = uid::scan_id("person", name);
    let mut report = Report::default();
    let mut network = None;
    let mut failed = None;

    collect(
        "asic_persons",
        asic_persons::lookup(transport, name, &scan_id, now_unix),
        now_unix,
        &mut report,
        &mut network,
        &mut failed,
    );
    collect(
        "asic_director",
        asic_director::lookup(transport, name, &scan_id, now_unix),
        now_unix,
        &mut report,
        &mut network,
        &mut failed,
    );
    collect(
        "au_people",
        au_people::lookup(transport, name, &scan_id, now_unix),
        now_unix,
        &mut report,
        &mut network,
        &mut failed,
    );
    collect(
        "au_electoral",
        au_electoral::lookup(transport, name, &scan_id, now_unix),
        now_unix,
        &mut report,
        &mut network,
        &mut failed,
    );

    merge_by_uid(&mut report.entities);
    if !usable(&report) {
        if let Some(msg) = network {
            return PeopleRun::Network(msg);
        }
        if let Some(msg) = failed {
            return PeopleRun::Failed(msg);
        }
        return PeopleRun::Failed("nothing collected".into());
    }

    match render(&report) {
        Ok(text) => PeopleRun::Printed { text, report },
        Err(msg) => PeopleRun::Failed(msg),
    }
}

fn collect<R>(
    module: &'static str,
    result: Result<R, Error>,
    now_unix: u64,
    report: &mut Report,
    network: &mut Option<String>,
    failed: &mut Option<String>,
) where
    R: IntoCollected,
{
    match result {
        Ok(got) => {
            let got = got.into_collected();
            report.entities.extend(got.entities);
            report.outcomes.extend(got.outcomes);
        }
        Err(Error::Network(msg)) => {
            network.get_or_insert(msg.clone());
            report.outcomes.push(failure_outcome(
                module,
                now_unix,
                SourceOutcomeKind::ConnectFailure,
                msg,
            ));
        }
        Err(Error::Invalid(msg)) => {
            failed.get_or_insert(msg.clone());
            report.outcomes.push(failure_outcome(
                module,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                msg,
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            failed.get_or_insert(msg.clone());
            report.outcomes.push(failure_outcome(
                module,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                msg,
            ));
        }
    }
}

trait IntoCollected {
    fn into_collected(self) -> Report;
}

impl IntoCollected for asic_persons::Report {
    fn into_collected(self) -> Report {
        Report {
            entities: self.entities,
            outcomes: self.outcomes,
        }
    }
}

impl IntoCollected for asic_director::Report {
    fn into_collected(self) -> Report {
        Report {
            entities: self.entities,
            outcomes: self.outcomes,
        }
    }
}

impl IntoCollected for au_people::Report {
    fn into_collected(self) -> Report {
        Report {
            entities: self.entities,
            outcomes: self.outcomes,
        }
    }
}

impl IntoCollected for au_electoral::Report {
    fn into_collected(self) -> Report {
        Report {
            entities: self.entities,
            outcomes: self.outcomes,
        }
    }
}

fn failure_outcome(
    module: &'static str,
    now_unix: u64,
    kind: SourceOutcomeKind,
    detail: String,
) -> SourceExecutionOutcome {
    let mut outcome = SourceExecutionOutcome::success(module, now_unix, 0);
    outcome.kind = kind;
    outcome.found = None;
    outcome.detail = Some(detail);
    outcome
}

fn usable(report: &Report) -> bool {
    !report.entities.is_empty()
        || report
            .outcomes
            .iter()
            .any(|outcome| outcome.kind.is_accepted())
}

fn name_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphabetic())
        .filter(|token| token.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn merge_by_uid(entities: &mut Vec<Entity>) {
    let mut merged: Vec<Entity> = Vec::new();
    for entity in entities.drain(..) {
        if let Some(existing) = merged.iter_mut().find(|seen| seen.uid == entity.uid) {
            existing.absorb(entity);
        } else {
            merged.push(entity);
        }
    }
    *entities = merged;
}

fn render(report: &Report) -> Result<String, String> {
    let mut out = format!("entities={}\n", report.entities.len());
    for entity in &report.entities {
        let _ = writeln!(
            out,
            "{}\t{}\t{:.2}\t{}",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        );
    }
    for outcome in &report.outcomes {
        let found = outcome
            .found
            .map_or_else(|| "none".to_owned(), |n| n.to_string());
        let kind = serde_json::to_value(outcome.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let _ = writeln!(out, "{}\t{kind}\tfound={found}", outcome.module);
    }

    let observations = observations(report);
    if observations.is_empty() {
        return Ok(out);
    }
    let resolution = resolve_with_lineage(observations, Vec::new(), AutoMergePolicy::default())
        .map_err(|e| e.to_string())?;
    let _ = writeln!(out, "lineage={}", resolution.observations.len());
    for item in &resolution.observations {
        let _ = writeln!(out, "{}", lineage_line(item));
    }
    Ok(out)
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
    use std::collections::HashMap;

    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;

    const BANNED_RES: &str = "741da9e3-7e0c-458e-830c-c518698e1788";
    const ADVISER_RES: &str = "91d80440-5787-46fc-99de-0c1d93e6cc9f";
    const CREDIT_RES: &str = "999d9e92-df2c-4d6d-b580-321dcd205292";
    const BANNED: &str = r##"{
  "BD_PER_NAME":"ABBOTT, BILL","BD_PER_TYPE":"Banned Securities",
  "BD_PER_START_DT":"29/03/1994","BD_PER_END_DT":"29/03/1999",
  "BD_PER_DOC_NUM":"#004289112","BD_PER_ADD_LOCAL":"TEMPLESTOWE LOWER",
  "BD_PER_ADD_STATE":"VIC","BD_PER_ADD_PCODE":"3107","BD_PER_COMMENTS":"No comment made"}"##;

    struct Fake {
        by_id: RefCell<HashMap<String, Result<Response, TransportFailure>>>,
        html: RefCell<Vec<(String, Response)>>,
        seen: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(script: HashMap<String, Result<Response, TransportFailure>>) -> Self {
            Self {
                by_id: RefCell::new(script),
                html: RefCell::default(),
                seen: RefCell::default(),
            }
        }

        fn html(self, needle: &str, response: Response) -> Self {
            self.html.borrow_mut().push((needle.to_owned(), response));
            self
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.url.clone());
            if let Some(id) = request
                .url
                .split("resource_id=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
            {
                return self
                    .by_id
                    .borrow_mut()
                    .remove(id)
                    .unwrap_or_else(|| panic!("unexpected resource {id}"));
            }
            let html = self.html.borrow();
            if let Some((_, response)) =
                html.iter().find(|(needle, _)| request.url.contains(needle))
            {
                return Ok(Response {
                    status: response.status,
                    headers: response.headers.clone(),
                    body: response.body.clone(),
                    truncated: response.truncated,
                });
            }
            Ok(html_ok(""))
        }
    }

    struct BlockAll;

    impl Transport for BlockAll {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: format!("egress-policy: {}", request.url),
                blocked: true,
            })
        }
    }

    fn json_ok(body: &str) -> Response {
        Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn html_ok(body: &str) -> Response {
        Response {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn challenge() -> Response {
        Response {
            status: 403,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"<html>just a moment cloudflare</html>".to_vec(),
            truncated: false,
        }
    }

    const PEOPLE_SOURCE_REQUESTS: usize = 8;

    fn empty_script() -> HashMap<String, Result<Response, TransportFailure>> {
        let empty = json_ok(r#"{"success":true,"result":{"records":[]}}"#);
        HashMap::from([
            (BANNED_RES.into(), Ok(empty.clone())),
            (ADVISER_RES.into(), Ok(empty.clone())),
            (CREDIT_RES.into(), Ok(empty)),
        ])
    }

    #[test]
    fn missing_name_is_invalid() {
        assert!(matches!(
            PeopleArgs::parse(&[]),
            Err(Error::Invalid(msg)) if msg == "missing NAME"
        ));
    }

    #[test]
    fn parse_joins_name_and_accepts_save() {
        let parsed = PeopleArgs::parse(&[
            "Bill".into(),
            "--save".into(),
            "out.json".into(),
            "Abbott".into(),
        ])
        .unwrap();
        assert_eq!(parsed.name, "Bill Abbott");
        assert_eq!(
            parsed.save.as_deref(),
            Some(PathBuf::from("out.json").as_path())
        );
    }

    #[test]
    fn parse_rejects_unknown_option_and_bare_save() {
        assert!(PeopleArgs::parse(&["Bill".into(), "--depth".into()]).is_err());
        assert!(PeopleArgs::parse(&["--save".into()]).is_err());
        assert!(PeopleArgs::parse(&["--save".into(), "--save".into(), "x".into()]).is_err());
    }

    #[test]
    fn single_token_prints_skip_and_makes_no_request() {
        let fake = Fake::new(HashMap::new());
        match run(&fake, "Madonna", 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.contains("skipped"), "{text}");
                assert!(!text.contains("lineage="), "{text}");
                let entities = &report.entities;
                assert!(entities.is_empty(), "{entities:?}");
                let outcomes = &report.outcomes;
                assert!(outcomes.is_empty(), "{outcomes:?}");
            }
            other => panic!("{other:?}"),
        }
        let seen = fake.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn scripted_hit_prints_entities_and_dataset_lineage() {
        let mut script = empty_script();
        script.insert(
            BANNED_RES.into(),
            Ok(json_ok(&format!(
                r#"{{"success":true,"result":{{"records":[{BANNED}]}}}}"#
            ))),
        );
        let fake = Fake::new(script);
        match run(&fake, "Bill Abbott", 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.contains("Bill Abbott"), "{text}");
                assert!(text.contains("asic_persons.banned"), "{text}");
                assert!(
                    text.contains("dataset\tasic banned & disqualified persons"),
                    "person evidence must count as the banned dataset family: {text}"
                );
                assert!(!report.entities.is_empty(), "{report:?}");
                assert_eq!(fake.seen.borrow().len(), PEOPLE_SOURCE_REQUESTS);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn joined_args_are_the_lookup_name() {
        let fake = Fake::new(empty_script());
        let parsed = PeopleArgs::parse(&["Jane".into(), "Citizen".into()]).unwrap();
        match run(&fake, &parsed.name, 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.starts_with("entities=0\n"), "{text}");
                assert!(text.contains("asic_persons.banned\tvalid_zero"), "{text}");
                assert!(text.contains("asic_director\tvalid_zero"), "{text}");
                assert!(text.contains("au_people\tvalid_zero"), "{text}");
                assert!(text.contains("au_electoral.nsw\tvalid_zero"), "{text}");
                assert!(!text.contains("lineage="), "{text}");
                let entities = &report.entities;
                assert!(entities.is_empty(), "{entities:?}");
                assert_eq!(report.outcomes.len(), PEOPLE_SOURCE_REQUESTS);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.seen.borrow().len(), PEOPLE_SOURCE_REQUESTS);
    }

    #[test]
    fn valid_zero_report_saves_and_reloads() {
        let fake = Fake::new(empty_script());
        match run(&fake, "Jane Citizen", 1) {
            PeopleRun::Printed { report, .. } => {
                let dir = std::env::temp_dir()
                    .join(format!("huntsman-people-cli-save-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("people.json");
                let entries =
                    crate::lookup_save::save(&path, &report.entities, &report.outcomes, crate::lookup_save::PEOPLE_POLICY).unwrap();
                assert_eq!(entries.len(), PEOPLE_SOURCE_REQUESTS);
                let loaded = crate::ledger::load_chain(&path).unwrap();
                assert_eq!(loaded, entries);
                let admitted = crate::ledger::admitted(&loaded);
                assert!(admitted.is_empty(), "{admitted:?}");
                let _ = std::fs::remove_dir_all(&dir);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn director_challenge_does_not_abort_asic_valid_zero() {
        let fake = Fake::new(empty_script()).html("connectonline.asic.gov.au", challenge());
        match run(&fake, "Jane Citizen", 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.contains("asic_persons.banned\tvalid_zero"), "{text}");
                assert!(
                    text.contains("asic_director\tinconclusive")
                        || text.contains("asic_director\tbot_waf"),
                    "director WAF must be recorded without aborting: {text}"
                );
                assert!(
                    report
                        .outcomes
                        .iter()
                        .any(|o| o.module == "asic_persons.banned" && o.kind.is_accepted()),
                    "{report:?}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn electoral_outage_does_not_abort_other_sources() {
        let fake = Fake::new(empty_script())
            .html("elections.nsw.gov.au", challenge())
            .html("vec.vic.gov.au", challenge())
            .html("ecq.qld.gov.au", challenge());
        match run(&fake, "Jane Citizen", 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.contains("asic_persons.banned\tvalid_zero"), "{text}");
                assert!(text.contains("au_electoral"), "{text}");
                assert!(
                    report
                        .outcomes
                        .iter()
                        .any(|o| o.module.starts_with("asic_persons") && o.kind.is_accepted()),
                    "{report:?}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn all_sources_blocked_is_network() {
        match run(&BlockAll, "Jane Citizen", 1) {
            PeopleRun::Network(msg) => assert!(msg.contains("egress-policy"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }
}
