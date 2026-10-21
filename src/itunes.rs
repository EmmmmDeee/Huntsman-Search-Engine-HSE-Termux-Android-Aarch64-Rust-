//! Keyless App Store search over Apple's public iTunes Search API.
//!
//! One lookup is one GET to the iTunes Search API for a keyword, restricted to software in the US
//! storefront. Each app it returns becomes a `Url` entity for its App Store page, with the app's
//! name, seller, bundle identifier, genre and release date kept as evidence. A keyword match is
//! not a confirmed ownership link, so the confidence is deliberately modest: the evidence names
//! the search term that produced each app. This is the source Spiderfoot's `sfp_apple_itunes`
//! reaches, keyless.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SOURCE: &str = "apple_itunes";
const HOST: &str = "https://itunes.apple.com/search";

/// Most apps one search keeps. The API allows more; a keyword this broad is not a finding.
const RESULT_LIMIT: usize = 25;

/// Confidence that an app returned for a keyword belongs to the keyword's subject. A keyword
/// match is a candidate for review, never a confirmed link.
const KEYWORD_CONFIDENCE: f64 = 0.5;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Deserialize)]
struct Search {
    #[serde(default)]
    results: Vec<App>,
}

#[derive(Debug, Deserialize)]
struct App {
    #[serde(default, rename = "trackId")]
    track_id: Option<u64>,
    #[serde(default, rename = "trackName")]
    track_name: Option<String>,
    #[serde(default, rename = "sellerName")]
    seller_name: Option<String>,
    #[serde(default, rename = "bundleId")]
    bundle_id: Option<String>,
    #[serde(default, rename = "trackViewUrl")]
    track_view_url: Option<String>,
    #[serde(default, rename = "primaryGenreName")]
    primary_genre_name: Option<String>,
    #[serde(default, rename = "currentVersionReleaseDate")]
    release_date: Option<String>,
}

/// The request URL for one keyword. **Pure.**
#[must_use]
pub fn url(term: &str) -> String {
    format!(
        "{HOST}?term={}&entity=software&country=us&limit={RESULT_LIMIT}",
        percent_encode_unreserved(term)
    )
}

/// Search the App Store for one keyword.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    term: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let fetched = fetch(
        transport,
        Request::get(url(term))
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;

    let Some(response) = fetched.response else {
        return Ok(Report {
            entities: Vec::new(),
            outcome: fetched.outcome,
        });
    };
    Ok(interpret(&response, term, scan_id, now_unix))
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// Turn one fetched response into a report. **Pure.**
fn interpret(response: &Response, term: &str, scan_id: &str, now_unix: u64) -> Report {
    if response.truncated {
        return miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "truncated iTunes Search response",
        ));
    }

    let body = response.text();
    let classified = classify_fetch(response.status, &body);
    if classified != SourceOutcomeKind::Inconclusive {
        return miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            classified,
            Some(response.status),
            "iTunes Search answered with a refusal or a wall, not a result set",
        ));
    }

    let search: Search = match serde_json::from_slice(&response.body) {
        Ok(search) => search,
        Err(error) => {
            return miss(SourceExecutionOutcome::failed(
                SOURCE,
                now_unix,
                SourceOutcomeKind::ParserDrift,
                Some(response.status),
                format!("iTunes Search JSON: {error}"),
            ));
        }
    };

    decode(&search, term, scan_id, now_unix, response.status)
}

/// Build the report from a parsed search. **Pure.**
fn decode(search: &Search, term: &str, scan_id: &str, now_unix: u64, status: u16) -> Report {
    let mut entities = Vec::new();
    for app in search.results.iter().take(RESULT_LIMIT) {
        let Some(page) = app
            .track_view_url
            .as_deref()
            .map(str::trim)
            .filter(|value| value.starts_with("https://"))
        else {
            continue;
        };
        let name = app.track_name.as_deref().unwrap_or("").trim();
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            format!("App Store app for the keyword {term:?}: {name}"),
        )
        .with_attr("dataset", "iTunes Search API, software, US storefront")
        .with_attr("keyword", term)
        .with_attr("track_name", name);
        for (attr, value) in [
            ("seller_name", app.seller_name.as_deref()),
            ("bundle_id", app.bundle_id.as_deref()),
            ("primary_genre", app.primary_genre_name.as_deref()),
            ("release_date", app.release_date.as_deref()),
        ] {
            if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
                evidence = evidence.with_attr(attr, value);
            }
        }
        if let Some(track_id) = app.track_id {
            evidence = evidence.with_attr("track_id", track_id.to_string());
        }
        push_entity(
            &mut entities,
            EntityKind::Url,
            page,
            KEYWORD_CONFIDENCE,
            scan_id,
            evidence,
            &["itunes", crate::tags::APP_STORE_ENTRY, "keyword-match"],
        );
    }
    merge_by_uid(&mut entities);

    let outcome = if entities.is_empty() {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(status)
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, entities.len()).with_http_status(status)
    };
    Report { entities, outcome }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    /// Fictional records with the API's field names; no real app or seller data is committed.
    const SEARCH: &str = r#"{"resultCount":2,"results":[
        {"trackId":1,"trackName":"Example Trail App","sellerName":"Example Seller Ltd",
         "bundleId":"com.example.trail","trackViewUrl":"https://apps.apple.com/us/app/example-trail-app/id1",
         "primaryGenreName":"Utilities","currentVersionReleaseDate":"2026-01-02T03:04:05Z"},
        {"trackId":2,"trackName":"No Page App","sellerName":"Example Seller Ltd",
         "trackViewUrl":"http://insecure.example/app"}
    ]}"#;

    #[test]
    fn the_url_carries_the_keyword_once_and_is_software_in_the_us() {
        assert_eq!(
            url("Example Co"),
            "https://itunes.apple.com/search?term=Example%20Co&entity=software&country=us&limit=25"
        );
    }

    #[test]
    fn each_app_page_becomes_a_url_entity_with_its_seller_and_bundle() {
        match lookup(
            &OneResponse::json(200, SEARCH),
            "Example Co",
            "scan-itunes",
            1,
        ) {
            Ok(report) => {
                assert_eq!(report.entities.len(), 1, "a non-https page is dropped");
                let app = &report.entities[0];
                assert_eq!(app.kind, EntityKind::Url);
                assert_eq!(
                    app.raw_value,
                    "https://apps.apple.com/us/app/example-trail-app/id1"
                );
                assert!((app.confidence - KEYWORD_CONFIDENCE).abs() < f64::EPSILON);
                assert!(report.outcome.kind.is_accepted());
            }
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn an_empty_result_set_is_a_clean_negative() {
        match lookup(
            &OneResponse::json(200, r#"{"resultCount":0,"results":[]}"#),
            "nothing-here",
            "scan-itunes",
            1,
        ) {
            Ok(report) => {
                assert!(report.entities.is_empty());
                assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
            }
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn a_refusal_is_not_read_as_a_zero() {
        match lookup(
            &OneResponse::json(403, "forbidden"),
            "Example Co",
            "scan-itunes",
            1,
        ) {
            Ok(report) => {
                assert!(report.entities.is_empty());
                assert!(!report.outcome.kind.is_accepted(), "{:?}", report.outcome);
            }
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn a_body_that_is_not_a_search_document_is_drift_not_a_zero() {
        match lookup(
            &OneResponse::json(200, "<html>not json</html>"),
            "Example Co",
            "scan-itunes",
            1,
        ) {
            Ok(report) => {
                assert!(report.entities.is_empty());
                assert!(!report.outcome.kind.is_accepted());
            }
            Err(error) => panic!("{error}"),
        }
    }
}
