//! End-to-end front-end for `huntsman-recon gleif`: one query -- an LEI, or a company name resolved
//! to its top matching record -- looked up on the keyless GLEIF public register. A register record
//! is a candidate to review, never a confirmed real-world identity; its legal and headquarters
//! addresses and an Australian local registration number ride out as pivot entities so the geocoder
//! and the ASIC director correlation can follow them.

use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::gleif;
use crate::http::Transport;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const GLEIF_USAGE: &str = "usage: huntsman-recon gleif LEI|NAME";
pub const GLEIF_HELP: &str = "\
gleif LEI|NAME
Look up one legal entity on GLEIF for LEI|NAME: a 20-character Legal Entity Identifier (5493001KJTIIGC8Y1R12), or free text resolved to its top matching register record. The registered legal name is an organisation (a candidate, never a confirmed identity); its legal and headquarters addresses are points the geocoder can reverse, and an Australian entity's local registration number becomes a checksum-validated ACN that feeds the ASIC director correlation. A record is accepted only when the response envelope's LEI is exactly the one requested; an unknown LEI or an empty search is a clean zero. Keyless, from GLEIF's public API. A register record is a candidate to review, not a confirmed identity. Makes network requests.";

/// The longest query taken, in bytes. A longer one is neither an LEI nor a name a register matches.
const MAX_GLEIF_QUERY_BYTES: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GleifArgs {
    pub query: String,
}

impl GleifArgs {
    /// # Errors
    /// [`Error::Invalid`] for no query, [`Error::InvalidValue`] for one that is empty, too long or
    /// holds a control character.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        if args.is_empty() {
            return Err(Error::Invalid("gleif needs an LEI or a name".into()));
        }
        Ok(Self {
            query: canonical_query(&args.join(" "))?,
        })
    }
}

/// `raw` as the query is looked up: trimmed, non-empty, at most [`MAX_GLEIF_QUERY_BYTES`] bytes, with
/// no control character.
///
/// # Errors
/// [`Error::InvalidValue`] for a query that is empty, too long, or holds a control character.
pub fn canonical_query(raw: &str) -> Result<String, Error> {
    let query = raw.trim();
    if query.is_empty() {
        return Err(Error::invalid_value("the query is empty"));
    }
    if query.len() > MAX_GLEIF_QUERY_BYTES {
        return Err(Error::invalid_value(format!(
            "the query is longer than {MAX_GLEIF_QUERY_BYTES} bytes"
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

pub type GleifRun = SourceRun<Report>;

/// Look up `query` on GLEIF, the leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, query: &str, now_unix: u64) -> GleifRun {
    let query = match canonical_query(query) {
        Ok(query) => query,
        Err(error) => return GleifRun::Failed(error.to_string()),
    };
    let scan_id = crate::entity::scan_id("gleif", &query);
    let mut report = Report::default();

    if transport.runs_module(gleif::SOURCE) {
        match gleif::lookup(transport, &query, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return GleifRun::Network(error.to_string()),
        }
    }
    merge_by_uid(&mut report.entities);

    if !report
        .outcomes
        .iter()
        .any(|outcome| outcome.kind.is_accepted())
    {
        return GleifRun::Failed(format!("no source answered for {query:?}"));
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => GleifRun::Printed { text, report },
        Err(message) => GleifRun::Failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityKind;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    const RECORD: &str = r#"{"data":{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12","entity":{"legalName":{"name":"Example Holdings Pty Ltd"},"jurisdiction":"AU","registeredAs":"004085616","legalAddress":{"addressLines":["1 Collins St"],"city":"Melbourne","region":"AU-VIC","country":"AU","postalCode":"3000"}}}}}"#;

    #[test]
    fn joins_and_trims_a_multi_word_query() {
        let parsed = GleifArgs::parse(&["  Example".into(), "Holdings  ".into()]).unwrap();
        assert_eq!(parsed.query, "Example Holdings");
    }

    #[test]
    fn rejects_missing_empty_long_and_control_queries() {
        assert!(GleifArgs::parse(&[]).is_err());
        assert!(GleifArgs::parse(&["   ".into()]).is_err());
        assert!(GleifArgs::parse(&["x".repeat(MAX_GLEIF_QUERY_BYTES + 1)]).is_err());
        assert!(GleifArgs::parse(&["bad\nquery".into()]).is_err());
    }

    #[test]
    fn run_prints_the_entity_and_its_pivots() {
        match run(&OneResponse::json(200, RECORD), "5493001KJTIIGC8Y1R12", 1) {
            GleifRun::Printed { text, report } => {
                assert!(text.contains("gleif_lei\tsuccess"), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|e| e.kind == EntityKind::Organisation
                            && e.raw_value == "Example Holdings Pty Ltd")
                );
                assert!(report.entities.iter().any(|e| e.kind == EntityKind::AbnAcn));
            }
            GleifRun::Network(why) | GleifRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn free_text_resolves_through_search_then_the_record() {
        let search = r#"{"data":[{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12"}}]}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(search)), Ok(json_ok(RECORD))]);
        match run(&transport, "Example Holdings", 1) {
            GleifRun::Printed { report, .. } => {
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|e| e.raw_value == "Example Holdings Pty Ltd")
                );
            }
            GleifRun::Network(why) | GleifRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn a_search_with_no_hit_prints_nothing_found() {
        match run(
            &OneResponse::json(200, r#"{"data":[]}"#),
            "nobody here at all",
            1,
        ) {
            GleifRun::Printed { report, .. } => {
                assert!(report.entities.is_empty());
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
            }
            GleifRun::Network(why) | GleifRun::Failed(why) => panic!("{why}"),
        }
    }
}
