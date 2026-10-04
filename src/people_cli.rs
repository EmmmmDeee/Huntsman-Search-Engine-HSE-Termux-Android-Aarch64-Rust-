//! Collection front-end for `huntsman-recon people`.
//!
//! Lookup stays in [`crate::asic_persons`]. This module parses the name, runs that
//! lookup over an injected [`crate::http::Transport`], and feeds each evidence item
//! through [`crate::lineage::resolve_with_lineage`]. Tests inject fakes; live CKAN
//! is not run here.

use crate::asic_persons::{self, Report};
use crate::error::Error;
use crate::evidence_ancestry::EvidenceNodeId;
use crate::http::Transport;
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{Lineage, Observation, ObservedLineage, UpstreamKind, resolve_with_lineage};
use crate::uid;

pub const PEOPLE_USAGE: &str = "usage: huntsman-recon people NAME";
pub const PEOPLE_HELP: &str = "\
people NAME
Look up NAME on keyless ASIC people registers (data.gov.au CKAN). Fewer than two alphabetic tokens makes no request.";

/// Result of one `people` invocation, before the binary maps it to an exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeopleRun {
    Usage,
    Printed(String),
    Network(String),
    Failed(String),
}

/// Parse `args` as NAME, look up over `transport`, and render entities, outcomes,
/// and lineage. An empty argument list is usage. A single-token name prints the
/// skip line and makes no request.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, args: &[String], now_unix: u64) -> PeopleRun {
    if args.is_empty() {
        return PeopleRun::Usage;
    }
    let name = args.join(" ");
    let scan_id = uid::scan_id("person", &name);
    match asic_persons::lookup(transport, &name, &scan_id, now_unix) {
        Ok(report) => match render(&report) {
            Ok(text) => PeopleRun::Printed(text),
            Err(msg) => PeopleRun::Failed(msg),
        },
        Err(Error::Network(msg)) => PeopleRun::Network(msg),
        Err(e) => PeopleRun::Failed(e.to_string()),
    }
}

fn render(report: &Report) -> Result<String, String> {
    let no_entities = report.entities.is_empty();
    let no_outcomes = report.outcomes.is_empty();
    if no_entities && no_outcomes {
        return Ok("asic_persons: skipped (need two alphabetic tokens)\n".into());
    }

    let mut out = format!("entities={}\n", report.entities.len());
    for entity in &report.entities {
        out.push_str(&format!(
            "{}\t{}\t{:.2}\t{}\n",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        ));
    }
    for outcome in &report.outcomes {
        let found = outcome
            .found
            .map_or_else(|| "none".to_owned(), |n| n.to_string());
        let kind = serde_json::to_value(outcome.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        out.push_str(&format!("{}\t{kind}\tfound={found}\n", outcome.module));
    }

    let observations = observations(report);
    if observations.is_empty() {
        return Ok(out);
    }
    let resolution = resolve_with_lineage(observations, Vec::new(), AutoMergePolicy::default())
        .map_err(|e| e.to_string())?;
    out.push_str(&format!("lineage={}\n", resolution.observations.len()));
    for item in &resolution.observations {
        out.push_str(&format!("{}\n", lineage_line(item)));
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
        seen: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(script: HashMap<String, Result<Response, TransportFailure>>) -> Self {
            Self {
                by_id: RefCell::new(script),
                seen: RefCell::default(),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.url.clone());
            let id = request
                .url
                .split("resource_id=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
                .expect("CKAN resource_id");
            self.by_id
                .borrow_mut()
                .remove(id)
                .unwrap_or_else(|| panic!("unexpected resource {id}"))
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

    fn empty_script() -> HashMap<String, Result<Response, TransportFailure>> {
        let empty = json_ok(r#"{"success":true,"result":{"records":[]}}"#);
        HashMap::from([
            (BANNED_RES.into(), Ok(empty.clone())),
            (ADVISER_RES.into(), Ok(empty.clone())),
            (CREDIT_RES.into(), Ok(empty)),
        ])
    }

    #[test]
    fn missing_name_is_usage() {
        let fake = Fake::new(HashMap::new());
        assert_eq!(run(&fake, &[], 1), PeopleRun::Usage);
        assert!(fake.seen.borrow().is_empty());
    }

    #[test]
    fn single_token_prints_skip_and_makes_no_request() {
        let fake = Fake::new(HashMap::new());
        match run(&fake, &["Madonna".into()], 1) {
            PeopleRun::Printed(text) => {
                assert!(text.contains("skipped"), "{text}");
                assert!(!text.contains("lineage="), "{text}");
            }
            other => panic!("{other:?}"),
        }
        assert!(fake.seen.borrow().is_empty());
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
        match run(&fake, &["Bill".into(), "Abbott".into()], 1) {
            PeopleRun::Printed(text) => {
                assert!(text.contains("Bill Abbott"), "{text}");
                assert!(text.contains("asic_persons.banned"), "{text}");
                assert!(
                    text.contains("dataset\tasic banned & disqualified persons"),
                    "person evidence must count as the banned dataset family: {text}"
                );
                assert_eq!(fake.seen.borrow().len(), 3);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn joined_args_are_the_lookup_name() {
        let fake = Fake::new(empty_script());
        match run(&fake, &["Jane".into(), "Citizen".into()], 1) {
            PeopleRun::Printed(text) => {
                assert!(text.starts_with("entities=0\n"), "{text}");
                assert!(text.contains("asic_persons.banned\tvalid_zero"), "{text}");
                assert!(!text.contains("lineage="), "{text}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.seen.borrow().len(), 3);
    }
}
