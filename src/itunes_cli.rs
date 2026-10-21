//! End-to-end front-end for `huntsman-recon itunes`: one keyword searched across the App Store,
//! Spiderfoot's `apple_itunes` leg, keyless. Each app found is a candidate for review, never a
//! confirmed link to the keyword's owner.

use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::itunes;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const ITUNES_USAGE: &str = "usage: huntsman-recon itunes KEYWORD";
pub const ITUNES_HELP: &str = "\
itunes KEYWORD
Search the Apple App Store for one keyword: the apps whose name, seller or description match, one Url entity per app with its seller, bundle identifier, genre and release date. Keyless, from Apple's public iTunes Search API, US storefront, software only, at most 25 apps. A match is a candidate to review, not a confirmed link to the keyword's owner. Makes network requests.";

/// The longest keyword a search takes, in bytes. A longer one is not a name a store would match.
const MAX_KEYWORD_BYTES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItunesArgs {
    pub keyword: String,
}

impl ItunesArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] for a keyword
    /// that is empty, too long, or holds a control character.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let [raw] = args else {
            return Err(Error::Invalid("itunes needs exactly one keyword".into()));
        };
        Ok(Self {
            keyword: canonical_keyword(raw)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

pub type ItunesRun = SourceRun<Report>;

/// `raw` as the search keys on: trimmed, non-empty, at most [`MAX_KEYWORD_BYTES`] bytes, with no
/// control character.
///
/// # Errors
/// [`Error::InvalidValue`] for a keyword that is empty, too long, or holds a control character.
pub fn canonical_keyword(raw: &str) -> Result<String, Error> {
    let keyword = raw.trim();
    if keyword.is_empty() {
        return Err(Error::invalid_value("the keyword is empty"));
    }
    if keyword.len() > MAX_KEYWORD_BYTES {
        return Err(Error::invalid_value(format!(
            "the keyword is longer than {MAX_KEYWORD_BYTES} bytes"
        )));
    }
    if keyword.chars().any(char::is_control) {
        return Err(Error::invalid_value(
            "the keyword holds a control character",
        ));
    }
    Ok(keyword.to_owned())
}

/// Search the App Store for `keyword`, the iTunes leg only when the transport's lookup asks its
/// module ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, keyword: &str, now_unix: u64) -> ItunesRun {
    let keyword = match canonical_keyword(keyword) {
        Ok(keyword) => keyword,
        Err(error) => return ItunesRun::Failed(error.to_string()),
    };
    let scan_id = crate::entity::scan_id("itunes", &keyword);
    let mut report = Report::default();

    if transport.runs_module(itunes::SOURCE) {
        match itunes::lookup(transport, &keyword, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return ItunesRun::Network(error.to_string()),
        }
    }
    merge_by_uid(&mut report.entities);

    if !report
        .outcomes
        .iter()
        .any(|outcome| outcome.kind.is_accepted())
    {
        return ItunesRun::Failed(format!("no source answered for {keyword:?}"));
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => ItunesRun::Printed { text, report },
        Err(message) => ItunesRun::Failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::OneResponse;

    #[test]
    fn parses_one_trimmed_keyword() {
        let parsed = ItunesArgs::parse(&["  Example Co  ".into()]).unwrap();
        assert_eq!(parsed.keyword, "Example Co");
    }

    #[test]
    fn rejects_missing_extra_empty_long_and_control_keywords() {
        assert!(ItunesArgs::parse(&[]).is_err());
        assert!(ItunesArgs::parse(&["a".into(), "b".into()]).is_err());
        assert!(ItunesArgs::parse(&["   ".into()]).is_err());
        assert!(ItunesArgs::parse(&["x".repeat(MAX_KEYWORD_BYTES + 1)]).is_err());
        assert!(ItunesArgs::parse(&["bad\nkeyword".into()]).is_err());
    }

    #[test]
    fn run_prints_the_app_it_found() {
        let body = r#"{"resultCount":1,"results":[{"trackId":1,"trackName":"Example Trail App","sellerName":"Example Seller Ltd","trackViewUrl":"https://apps.apple.com/us/app/example-trail-app/id1"}]}"#;
        match run(&OneResponse::json(200, body), "Example Co", 1) {
            ItunesRun::Printed { text, report } => {
                assert!(text.contains("apple_itunes\tsuccess"), "{text}");
                assert_eq!(report.entities.len(), 1);
            }
            ItunesRun::Network(why) | ItunesRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn an_empty_search_still_prints_its_clean_negative() {
        match run(
            &OneResponse::json(200, r#"{"resultCount":0,"results":[]}"#),
            "nothing-here",
            1,
        ) {
            ItunesRun::Printed { report, .. } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
            }
            ItunesRun::Network(why) | ItunesRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn an_invalid_keyword_fails_without_network() {
        match run(&OneResponse::json(200, "{}"), "", 1) {
            ItunesRun::Failed(_) => {}
            other => panic!(
                "expected a failure, got {}",
                matches!(other, ItunesRun::Printed { .. })
            ),
        }
    }
}
