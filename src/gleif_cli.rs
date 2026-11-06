//! End-to-end front-end for `huntsman-recon gleif`: one query -- an LEI, or a company name resolved
//! to its top matching record -- looked up on the keyless GLEIF public register. A register record
//! is a candidate to review, never a confirmed real-world identity; its legal and headquarters
//! addresses and an Australian local registration number ride out as pivot entities so the geocoder
//! and the ASIC director correlation can follow them.

use crate::error::Error;
use crate::gleif;
use crate::http::Transport;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const GLEIF_USAGE: &str =
    "usage: huntsman-recon gleif [--country CC] [--jurisdiction CC[-SUB]] LEI|NAME";
pub const GLEIF_HELP: &str = "\
gleif [--country CC] [--jurisdiction CC[-SUB]] LEI|NAME
Look up one legal entity on GLEIF for LEI|NAME: a 20-character Legal Entity Identifier (5493001KJTIIGC8Y1R12), or free text resolved to its top matching register record. --country CC narrows a name search to entities whose legal address is in that ISO 3166-1 country, and --jurisdiction to entities registered in that country or ISO 3166-2 subdivision: --jurisdiction AE-DU searches Dubai-registered entities (GLEIF records many Dubai entities under the federal AE jurisdiction, which --country AE reaches). Names may be written in Arabic as GLEIF holds them. An LEI already names one record, so neither narrows it. The registered legal name is an organisation (a candidate, never a confirmed identity); its legal and headquarters addresses are points the geocoder can reverse, and an Australian entity's local registration number becomes a checksum-validated ACN that feeds the ASIC director correlation. A record is accepted only when the response envelope's LEI is exactly the one requested; an unknown LEI or an empty search is a clean zero. Keyless, from GLEIF's public API. A register record is a candidate to review, not a confirmed identity. Makes network requests.";

/// The longest query taken, in bytes. A longer one is neither an LEI nor a name a register matches.
const MAX_GLEIF_QUERY_BYTES: usize = 300;

/// A scope flag: the part of the scope it fills and the parser of its ISO code.
type CodeFlag<'a> = (&'a mut Option<String>, fn(&str) -> Option<String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GleifArgs {
    pub query: String,
    /// Where a name search looks; empty for an LEI.
    pub scope: gleif::Scope,
}

impl GleifArgs {
    /// # Errors
    /// [`Error::Invalid`] for no query, a repeated or valueless flag, or a scope given with an LEI;
    /// [`Error::InvalidValue`] for a query that is empty, too long or holds a control character,
    /// or a country or jurisdiction code that is not ISO shaped.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut scope = gleif::Scope::default();
        let mut words = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let (slot, read): CodeFlag<'_> = match arg.as_str() {
                "--country" => (&mut scope.country, gleif::country_code),
                "--jurisdiction" => (&mut scope.jurisdiction, gleif::jurisdiction_code),
                _ => {
                    words.push(arg.as_str());
                    continue;
                }
            };
            if slot.is_some() {
                return Err(Error::Invalid(format!("{arg} is given twice")));
            }
            let value = args
                .next()
                .ok_or_else(|| Error::Invalid(format!("{arg} needs a code")))?;
            *slot = Some(read(value).ok_or_else(|| {
                Error::invalid_value(format!(
                    "{arg} takes an ISO code such as AE or AE-DU, not {value:?}"
                ))
            })?);
        }
        if words.is_empty() {
            return Err(Error::Invalid("gleif needs an LEI or a name".into()));
        }
        let query = canonical_query(&words.join(" "))?;
        if !scope.is_empty() && gleif::as_lei(&query).is_some() {
            return Err(Error::Invalid(
                "--country and --jurisdiction narrow a name search; an LEI already names one record"
                    .into(),
            ));
        }
        Ok(Self { query, scope })
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

/// What the lookup found: its entities and each source's row.
pub type Report = crate::lookup_report::LookupReport;

pub type GleifRun = SourceRun<Report>;

/// Look up `query` on GLEIF, the leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, query: &str, now_unix: u64) -> GleifRun {
    run_within(transport, query, &gleif::Scope::default(), now_unix)
}

/// [`run`] with a name search narrowed to `scope`.
#[must_use]
pub fn run_within<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scope: &gleif::Scope,
    now_unix: u64,
) -> GleifRun {
    let query = match canonical_query(query) {
        Ok(query) => query,
        Err(error) => return GleifRun::Failed(error.to_string()),
    };
    // A scoped search is its own scan: the same name searched in Dubai and worldwide differs.
    let scan_key = match (&scope.country, &scope.jurisdiction) {
        (None, None) => query.clone(),
        (country, jurisdiction) => format!(
            "{query}\u{1f}{}\u{1f}{}",
            country.as_deref().unwrap_or_default(),
            jurisdiction.as_deref().unwrap_or_default()
        ),
    };
    let scan_id = crate::entity::scan_id("gleif", &scan_key);
    let mut report = Report::default();

    if transport.runs_module(gleif::SOURCE) {
        match gleif::lookup_within(transport, &query, scope, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => report.outcomes.push(SourceExecutionOutcome::of_leg_error(
                gleif::SOURCE,
                now_unix,
                &error,
            )),
        }
    }
    lookup_report::finish(report, &format!("no source answered for {query:?}"))
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
    fn a_dubai_scoped_name_search_asks_gleif_for_dubai_registered_entities() {
        let parsed = GleifArgs::parse(&[
            "--jurisdiction".into(),
            "ae-du".into(),
            "Example".into(),
            "Holdings".into(),
        ])
        .unwrap();
        assert_eq!(parsed.query, "Example Holdings");
        assert_eq!(parsed.scope.jurisdiction.as_deref(), Some("AE-DU"));
        let search = r#"{"data":[{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12"}}]}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(search)), Ok(json_ok(RECORD))]);
        let GleifRun::Printed { report, .. } =
            run_within(&transport, &parsed.query, &parsed.scope, 1)
        else {
            panic!("a scoped search prints");
        };
        assert!(!report.entities.is_empty());
        let asked = transport.seen.borrow()[0].url.clone();
        assert!(
            asked.ends_with("&filter%5Bentity.jurisdiction%5D=AE-DU"),
            "{asked}"
        );
        // The same name searched in Dubai and worldwide are two scans.
        let worldwide = ScriptedTransport::new(vec![Ok(json_ok(search)), Ok(json_ok(RECORD))]);
        let GleifRun::Printed {
            report: everywhere, ..
        } = run(&worldwide, "Example Holdings", 1)
        else {
            panic!("an unscoped search prints");
        };
        assert_ne!(report.entities[0].scan_id, everywhere.entities[0].scan_id);
    }

    #[test]
    fn a_scope_needs_an_iso_code_once_and_a_name_not_an_lei() {
        let parse = |args: &[&str]| {
            GleifArgs::parse(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
        };
        let both = parse(&["--country", "ae", "--jurisdiction", "AE-DU", "Emirates"]).unwrap();
        assert_eq!(both.scope.country.as_deref(), Some("AE"));
        for refused in [
            &["--jurisdiction", "AE-DU", "5493001KJTIIGC8Y1R12"][..],
            &["--country", "AE", "--country", "AU", "Emirates"],
            &["--country", "ARE", "Emirates"],
            &["--jurisdiction", "AE-DUBAI", "Emirates"],
            &["Emirates", "--country"],
            &["--country", "AE"],
        ] {
            assert!(parse(refused).is_err(), "{refused:?}");
        }
        // An LEI on its own is still fetched as it is.
        assert!(parse(&["5493001KJTIIGC8Y1R12"]).unwrap().scope.is_empty());
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
