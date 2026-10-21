//! End-to-end front-end for `huntsman-recon geocode`: one query turned into coordinates and an
//! address through OpenStreetMap's keyless Nominatim service (see [`crate::nominatim`]).
//!
//! The query is read as a point when it is `lat,lon` and as free text otherwise, so one command
//! both forward-geocodes a place or address and reverse-geocodes a point. Keyless.

use crate::canonical::canonical_coordinates;
use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_report;
use crate::nominatim;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const GEOCODE_USAGE: &str = "usage: huntsman-recon geocode PLACE-OR-ADDRESS | geocode LAT,LON";
pub const GEOCODE_HELP: &str = "\
geocode QUERY
Geocode one query through OpenStreetMap's Nominatim, keyless. A `lat,lon` point is reverse-geocoded to the address at that spot; any other text is a place name or street address, forward-geocoded to the coordinates and address of each match (at most ten). Each match becomes a coordinates entity for its point and an address entity for its written address, with every field Nominatim returns -- each separate address component included -- kept as evidence. Makes network requests; Nominatim asks for no more than one a second.";

/// The longest query a geocode takes, in bytes. A longer string is not an address a gazetteer
/// would match.
const MAX_QUERY_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeocodeArgs {
    pub query: String,
}

impl GeocodeArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] for a query
    /// that is empty, too long, or holds a control character.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let [raw] = args else {
            return Err(Error::Invalid("geocode needs exactly one query".into()));
        };
        Ok(Self {
            query: canonical_query(raw)?,
        })
    }
}

/// `raw` as the geocode keys on: trimmed, non-empty, at most [`MAX_QUERY_BYTES`] bytes, with no
/// control character.
///
/// # Errors
/// [`Error::InvalidValue`] for a query that is empty, too long, or holds a control character.
pub fn canonical_query(raw: &str) -> Result<String, Error> {
    let query = raw.trim();
    if query.is_empty() {
        return Err(Error::invalid_value("the query is empty"));
    }
    if query.len() > MAX_QUERY_BYTES {
        return Err(Error::invalid_value(format!(
            "the query is longer than {MAX_QUERY_BYTES} bytes"
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

pub type GeocodeRun = SourceRun<Report>;

/// A `lat,lon` point, when `query` is one. **Pure.**
fn as_point(query: &str) -> Option<(f64, f64)> {
    let canonical = canonical_coordinates(query)?;
    let (lat, lon) = canonical.split_once(',')?;
    Some((lat.parse().ok()?, lon.parse().ok()?))
}

/// Geocode `query`, the Nominatim leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]). A `lat,lon` query is reverse-geocoded; any other is forward.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, query: &str, now_unix: u64) -> GeocodeRun {
    let query = match canonical_query(query) {
        Ok(query) => query,
        Err(error) => return GeocodeRun::Failed(error.to_string()),
    };
    let scan_id = crate::entity::scan_id("geocode", &query);
    let mut report = Report::default();

    if transport.runs_module(nominatim::SOURCE) {
        let found = match as_point(&query) {
            Some((lat, lon)) => nominatim::reverse(transport, lat, lon, &scan_id, now_unix),
            None => nominatim::forward(transport, &query, &scan_id, now_unix),
        };
        match found {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => return GeocodeRun::Network(error.to_string()),
        }
    }
    merge_by_uid(&mut report.entities);

    if !report
        .outcomes
        .iter()
        .any(|outcome| outcome.kind.is_accepted())
    {
        return GeocodeRun::Failed(format!("no source answered for {query:?}"));
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => GeocodeRun::Printed { text, report },
        Err(message) => GeocodeRun::Failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::OneResponse;

    const PLACE: &str = r#"{"osm_type":"way","osm_id":1,"lat":"48.8584","lon":"2.2945","category":"tourism","type":"attraction","place_rank":30,"importance":0.5,"addresstype":"tourism","name":"Eiffel Tower","display_name":"Eiffel Tower, Paris, France","address":{"tourism":"Eiffel Tower","city":"Paris","country":"France","country_code":"fr"}}"#;

    #[test]
    fn parses_one_trimmed_query() {
        let parsed = GeocodeArgs::parse(&["  Eiffel Tower  ".into()]).unwrap();
        assert_eq!(parsed.query, "Eiffel Tower");
    }

    #[test]
    fn rejects_missing_extra_empty_long_and_control_queries() {
        assert!(GeocodeArgs::parse(&[]).is_err());
        assert!(GeocodeArgs::parse(&["a".into(), "b".into()]).is_err());
        assert!(GeocodeArgs::parse(&["   ".into()]).is_err());
        assert!(GeocodeArgs::parse(&["x".repeat(MAX_QUERY_BYTES + 1)]).is_err());
        assert!(GeocodeArgs::parse(&["bad\nquery".into()]).is_err());
    }

    #[test]
    fn a_free_text_query_is_forward_geocoded() {
        match run(
            &OneResponse::json(200, &format!("[{PLACE}]")),
            "Eiffel Tower",
            1,
        ) {
            GeocodeRun::Printed { text, report } => {
                assert!(text.contains("nominatim\tsuccess"), "{text}");
                assert!(!report.entities.is_empty());
            }
            GeocodeRun::Network(why) | GeocodeRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn a_lat_lon_query_is_reverse_geocoded() {
        match run(&OneResponse::json(200, PLACE), "48.8584, 2.2945", 1) {
            GeocodeRun::Printed { report, .. } => {
                assert!(report.outcomes[0].kind.is_accepted());
            }
            GeocodeRun::Network(why) | GeocodeRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn an_empty_result_still_prints_its_clean_negative() {
        match run(&OneResponse::json(200, "[]"), "nowhere-zzzz", 1) {
            GeocodeRun::Printed { report, .. } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
            }
            GeocodeRun::Network(why) | GeocodeRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn an_invalid_query_fails_without_network() {
        match run(&OneResponse::json(200, "[]"), "", 1) {
            GeocodeRun::Failed(_) => {}
            _ => panic!("expected a failure"),
        }
    }
}
