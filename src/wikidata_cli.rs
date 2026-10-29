//! End-to-end front-end for `huntsman-recon wikidata`: one query resolved to a Wikidata item and
//! read for its structured record, keyless. A knowledge-base item is a candidate to review, never
//! a confirmed real-world identity; its published website, location and external profiles ride
//! out as pivot entities so the rest of the engine can follow them. The item is a person only when
//! Wikidata says it is a human, an organisation only on a known organisation type, and otherwise
//! an entity of unstated type -- a classification is never assumed from the absence of evidence.

use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};
use crate::wikidata;

pub const WIKIDATA_USAGE: &str = "usage: huntsman-recon wikidata QUERY";
pub const WIKIDATA_HELP: &str = "\
wikidata QUERY
Look up one Wikidata item for QUERY: a Q-number (Q42), or free text resolved to its top matching item. The item is a person when Wikidata says it is a human, an organisation when it is a known organisation type, and otherwise an entity of unstated type (never assumed to be an organisation); every statement Wikidata holds for it is kept as evidence. Its official website becomes a domain, a coordinate location a point the geocoder can reverse, and external identifiers (GitHub, X, VIAF, ORCID, IMDb, ...) profile URLs and usernames, so one lookup seeds the others. Keyless, from Wikidata's public search and REST APIs. A knowledge-base record is a candidate to review, not a confirmed identity. Makes network requests.";

/// The longest query taken, in bytes. A longer one is not a label a knowledge base would match.
const MAX_WIKIDATA_QUERY_BYTES: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WikidataArgs {
    pub query: String,
}

impl WikidataArgs {
    /// # Errors
    /// [`Error::Invalid`] for no query, [`Error::InvalidValue`] for one that is empty, too long or
    /// holds a control character.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        if args.is_empty() {
            return Err(Error::Invalid("wikidata needs a query".into()));
        }
        Ok(Self {
            query: canonical_query(&args.join(" "))?,
        })
    }
}

/// `raw` as the query is looked up: trimmed, non-empty, at most [`MAX_WIKIDATA_QUERY_BYTES`] bytes, with no
/// control character.
///
/// # Errors
/// [`Error::InvalidValue`] for a query that is empty, too long, or holds a control character.
pub fn canonical_query(raw: &str) -> Result<String, Error> {
    let query = raw.trim();
    if query.is_empty() {
        return Err(Error::invalid_value("the query is empty"));
    }
    if query.len() > MAX_WIKIDATA_QUERY_BYTES {
        return Err(Error::invalid_value(format!(
            "the query is longer than {MAX_WIKIDATA_QUERY_BYTES} bytes"
        )));
    }
    if query.chars().any(char::is_control) {
        return Err(Error::invalid_value("the query holds a control character"));
    }
    Ok(query.to_owned())
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

pub type WikidataRun = SourceRun<Report>;

/// Look up `query` on Wikidata, the leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, query: &str, now_unix: u64) -> WikidataRun {
    let query = match canonical_query(query) {
        Ok(query) => query,
        Err(error) => return WikidataRun::Failed(error.to_string()),
    };
    let scan_id = crate::entity::scan_id("wikidata", &query);
    let mut report = Report::default();

    if transport.runs_module(wikidata::SOURCE) {
        match wikidata::lookup(transport, &query, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return WikidataRun::Network(error.to_string()),
        }
    }
    merge_by_uid(&mut report.entities);

    if !report
        .outcomes
        .iter()
        .any(|outcome| outcome.kind.is_accepted())
    {
        return WikidataRun::Failed(format!("no source answered for {query:?}"));
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => WikidataRun::Printed { text, report },
        Err(message) => WikidataRun::Failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    const ITEM: &str = r#"{"type":"item","id":"Q000","labels":{"en":"Jane Example"},"statements":{"P31":[{"value":{"type":"value","content":"Q5"}}],"P856":[{"value":{"type":"value","content":"https://jane.example/"}}]}}"#;

    #[test]
    fn joins_and_trims_a_multi_word_query() {
        let parsed = WikidataArgs::parse(&["  Douglas".into(), "Adams  ".into()]).unwrap();
        assert_eq!(parsed.query, "Douglas Adams");
    }

    #[test]
    fn rejects_missing_empty_long_and_control_queries() {
        assert!(WikidataArgs::parse(&[]).is_err());
        assert!(WikidataArgs::parse(&["   ".into()]).is_err());
        assert!(WikidataArgs::parse(&["x".repeat(MAX_WIKIDATA_QUERY_BYTES + 1)]).is_err());
        assert!(WikidataArgs::parse(&["bad\nquery".into()]).is_err());
    }

    #[test]
    fn run_prints_the_item_and_its_website_pivot() {
        match run(&OneResponse::json(200, ITEM), "Q000", 1) {
            WikidataRun::Printed { text, report } => {
                assert!(text.contains("wikidata\tsuccess"), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|e| e.raw_value == "Jane Example")
                );
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|e| e.raw_value == "jane.example")
                );
            }
            WikidataRun::Network(why) | WikidataRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn free_text_resolves_through_search_then_the_item() {
        let search = r#"{"search":[{"id":"Q000","label":"Jane Example"}]}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(search)), Ok(json_ok(ITEM))]);
        match run(&transport, "Jane Example", 1) {
            WikidataRun::Printed { report, .. } => {
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|e| e.raw_value == "Jane Example")
                );
            }
            WikidataRun::Network(why) | WikidataRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn a_search_with_no_hit_prints_nothing_found() {
        match run(
            &OneResponse::json(200, r#"{"search":[]}"#),
            "nobody here at all",
            1,
        ) {
            WikidataRun::Printed { report, .. } => {
                assert!(report.entities.is_empty());
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
            }
            WikidataRun::Network(why) | WikidataRun::Failed(why) => panic!("{why}"),
        }
    }
}
