//! End-to-end front-end for `huntsman-recon company`: one organisation query -- a name, a nine-digit
//! ACN or an eleven-digit ABN -- looked up on ASIC's keyless organisation registers (companies,
//! business names, banned and disqualified organisations) and, for a name, on the GLEIF legal-entity
//! register. Every record is a register entry to review, never a confirmed identity.

use crate::asic_orgs::{self, Query};
use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::gleif;
use crate::http::Transport;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const COMPANY_USAGE: &str = "usage: huntsman-recon company NAME|ACN|ABN";
pub const COMPANY_HELP: &str = "\
company NAME|ACN|ABN
Look up one Australian organisation by NAME, a nine-digit ACN or an eleven-digit ABN (spaces allowed; the number must pass its checksum). Searches ASIC's Company Dataset (every registered company, its current and former names, ACN, ABN, type, class, status and registration dates), the Business Names register (each trading name with the ABN of the entity that holds it) and the Banned and Disqualified Organisations register, all keyless on data.gov.au; a NAME is also looked up on the GLEIF legal-entity register. A name matches only a record holding every word of the query, and a number matches only a record holding exactly that number. A register entry is a candidate to review, not a confirmed identity. Makes network requests.";

/// The longest query taken, in bytes.
const MAX_COMPANY_QUERY_BYTES: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyArgs {
    pub query: Query,
}

impl CompanyArgs {
    /// # Errors
    /// [`Error::Invalid`] for no query, [`Error::InvalidValue`] for one that is empty, too long, holds
    /// a control character, or is a number that is neither a valid ACN nor a valid ABN.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        if args.is_empty() {
            return Err(Error::Invalid("company needs a NAME, ACN or ABN".into()));
        }
        let raw = args.join(" ");
        if raw.len() > MAX_COMPANY_QUERY_BYTES {
            return Err(Error::invalid_value(format!(
                "the query is longer than {MAX_COMPANY_QUERY_BYTES} bytes"
            )));
        }
        if raw.chars().any(char::is_control) {
            return Err(Error::invalid_value("the query holds a control character"));
        }
        let query = Query::parse(&raw).ok_or_else(|| {
            Error::invalid_value("the query is empty, or a number that is not a valid ACN or ABN")
        })?;
        Ok(Self { query })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

pub type CompanyRun = SourceRun<Report>;

/// Look up `query`, each leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, query: &Query, now_unix: u64) -> CompanyRun {
    let text = match query {
        Query::Acn(id) | Query::Abn(id) | Query::Name(id) => id.as_str(),
    };
    let scan_id = crate::entity::scan_id("company", text);
    let mut report = Report::default();

    if transport.runs_module(asic_orgs::SRC) {
        match asic_orgs::lookup(transport, query, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.extend(found.outcomes);
            }
            Err(Error::Network(why)) => return CompanyRun::Network(why),
            Err(error) => report.outcomes.push(SourceExecutionOutcome::inconclusive(
                asic_orgs::SRC,
                now_unix,
                error.to_string(),
            )),
        }
    }
    // GLEIF searches legal names; it cannot be asked an ACN or ABN.
    if matches!(query, Query::Name(_)) && transport.runs_module(gleif::SOURCE) {
        match gleif::lookup(transport, text, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return CompanyRun::Network(error.to_string()),
        }
    }
    merge_by_uid(&mut report.entities);

    if let Some(run) = crate::source_outcome::none_accepted(
        &report.outcomes,
        &format!("no source answered for {text:?}"),
    ) {
        return run;
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => CompanyRun::Printed { text, report },
        Err(message) => CompanyRun::Failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_classify_names_and_checksummed_numbers() {
        let parse = |s: &str| CompanyArgs::parse(&[s.to_owned()]);
        assert_eq!(parse("Monaka").unwrap().query, Query::Name("Monaka".into()));
        assert_eq!(
            parse("000 000 019").unwrap().query,
            Query::Acn("000000019".into())
        );
        assert!(parse("000000018").is_err(), "bad checksum");
        assert!(parse("bad\nquery").is_err());
        assert!(CompanyArgs::parse(&[]).is_err());
        assert!(parse(&"x".repeat(MAX_COMPANY_QUERY_BYTES + 1)).is_err());
    }
}
