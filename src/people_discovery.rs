//! Bounded, source-scoped public people discovery over Huntsman's existing search transport.
//!
//! Search-index URLs are *candidate leads* only. Even matching full names, domains,
//! and repeats across engines do not establish that one person owns any account.
//! The existing `people` command remains the authority for structured registers.
use std::collections::BTreeMap;

use serde::Serialize;

use crate::canonical::canonical_name;
use crate::error::Error;
use crate::http::{Transport, parse_http_uri};
use crate::people_cli;
use crate::source_outcome::SourceExecutionOutcome;
use crate::web_query;

pub const MAX_DISCOVERY_NAME_BYTES: usize = 120;
pub const MAX_CANDIDATES: usize = 80;
pub const PEOPLE_DISCOVER_USAGE: &str =
    "usage: huntsman-recon people-discover [--region au|us] FULL NAME...";
pub const PEOPLE_DISCOVER_HELP: &str = "people-discover [--region au|us] FULL NAME...\nRun four bounded, keyless public-index searches using the actual Rust Bing, Brave and Mojeek collectors. Cross-source discovery covers public professional profiles (LinkedIn), development footprints (GitHub), research identifiers (ORCID) and jurisdiction-specific official pages (ASIC for AU, SEC for US). This is separate from the existing people lookup, which collects structured records. Returns JSON with the exact index URLs, admitted domains, per-engine typed outcomes, discarded out-of-scope links and explicit truncation. Every hit is an UNVERIFIED LEAD: matching names, URL occurrence and multiple indexes do not prove identity, employment or control. No breach lookup, location tracing, private API, or automatic recursive expansion.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    Au,
    Us,
}

impl Region {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "au" => Some(Self::Au),
            "us" => Some(Self::Us),
            _ => None,
        }
    }

    const fn official_domain(self) -> &'static str {
        match self {
            Self::Au => "asic.gov.au",
            Self::Us => "sec.gov",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub url: String,
    /// Source-scoped search contexts which returned this exact URL.
    pub facets: Vec<&'static str>,
    /// Indexes which first reported this URL in each matching facet.
    /// Index repetition does not mean independent evidence corroboration.
    pub reported_by: Vec<String>,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchFacet {
    pub id: &'static str,
    pub accepted_host: &'static str,
    pub query: String,
    pub index_hits: usize,
    pub discarded_out_of_scope: usize,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub subject: String,
    pub region: Region,
    pub facets: Vec<SearchFacet>,
    pub candidates: Vec<Candidate>,
    pub truncated: bool,
    pub attribution: &'static str,
    pub discovery_completeness: &'static str,
}

fn checked_name(raw: &str) -> Result<String, Error> {
    // Check the *original bytes* before canonical_name collapses whitespace.
    // Otherwise a newline, tab or NUL can disappear and be accepted as a
    // legitimate name, despite the command's safety and input contract.
    if raw.len() > MAX_DISCOVERY_NAME_BYTES
        || raw
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '<' | '>'))
    {
        return Err(Error::Invalid(
            "people-discover requires a bounded full name (two alphabetic tokens), without quotes, controls or HTML delimiters".into(),
        ));
    }
    let name = canonical_name(raw);
    if !people_cli::is_name(&name) {
        return Err(Error::Invalid(
            "people-discover requires a bounded full name (two alphabetic tokens), without quotes, controls or HTML delimiters".into(),
        ));
    }
    Ok(name)
}

fn is_accepted_host(url: &str, domain: &str) -> bool {
    if !url.starts_with("https://") {
        return false;
    }
    let Ok(parsed) = parse_http_uri(url) else {
        return false;
    };
    let Some(host) = parsed.host() else {
        return false;
    };
    host.eq_ignore_ascii_case(domain)
        || host
            .to_ascii_lowercase()
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Public-source discovery without changing canonical record ownership or promoting
/// index URLs into verified person records.
///
/// # Errors
/// Invalid names and network boundary errors propagate. Each search engine's
/// transport, WAF, zero-yield and parser failures remain per-facet typed outcomes.
pub fn discover<T: Transport + ?Sized>(
    transport: &T,
    raw_name: &str,
    region: Region,
    now_unix: u64,
) -> Result<Report, Error> {
    let name = checked_name(raw_name)?;
    let sources = [
        ("professional_profile", "linkedin.com"),
        ("software_footprint", "github.com"),
        ("research_identifier", "orcid.org"),
        ("official_registry", region.official_domain()),
    ];
    let mut facets = Vec::with_capacity(sources.len());
    let mut candidates = BTreeMap::<String, Candidate>::new();
    let mut truncated = false;

    for (facet, host) in sources {
        let query = format!("\"{name}\" site:{host}");
        // Owns the network requests and classification: no second search
        // parser, scraping workaround, or provider-availability guess.
        let (response, index_sightings) =
            web_query::search_with_provenance(transport, &query, now_unix)?;
        let mut discarded = 0;
        let index_hits = index_sightings.len();
        for hit in index_sightings {
            if !is_accepted_host(&hit.url, host) {
                discarded += 1;
                continue;
            }
            if !candidates.contains_key(&hit.url) && candidates.len() == MAX_CANDIDATES {
                truncated = true;
                continue;
            }
            let candidate = candidates
                .entry(hit.url.clone())
                .or_insert_with(|| Candidate {
                    url: hit.url,
                    facets: Vec::new(),
                    reported_by: Vec::new(),
                    status: "unverified_search_index_lead",
                });
            if !candidate.facets.contains(&facet) {
                candidate.facets.push(facet);
            }
            if !candidate.reported_by.contains(&hit.engine) {
                candidate.reported_by.push(hit.engine);
            }
        }
        facets.push(SearchFacet {
            id: facet,
            accepted_host: host,
            query,
            index_hits,
            discarded_out_of_scope: discarded,
            outcomes: response.outcomes,
        });
    }

    Ok(Report {
        subject: name,
        region,
        facets,
        candidates: candidates.into_values().collect(),
        truncated,
        attribution: "none_established; indexed_page_is_not_proof_of_person_or_account",
        discovery_completeness: "unknown_beyond_four_index_queries",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;

    struct Fixture {
        seen: RefCell<Vec<String>>,
        denied: bool,
    }

    impl Transport for Fixture {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.url.clone());
            if self.denied {
                return Err(TransportFailure {
                    kind: SourceOutcomeKind::TlsFailure,
                    detail: "offline test".into(),
                    blocked: false,
                });
            }
            let body = concat!(
                "<html><a href='https://linkedin.com/in/jane-example'>profile</a>",
                "<a href='https://github.com/jane-example'>code</a>",
                "<a href='https://orcid.org/0000-0001-1111-1111'>research</a>",
                "<a href='https://asic.gov.au/register/candidate'>register</a>",
                "<a href='https://sec.gov/archives/candidate'>US</a>",
                "<a href='https://github.com.evil.example/false'>impersonation</a></html>"
            );
            Ok(Response {
                status: 200,
                headers: vec![("content-type".into(), "text/html".into())],
                body: body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    #[test]
    fn four_existing_index_fanouts_are_scoped_and_never_attributed() {
        let fixture = Fixture {
            seen: RefCell::new(Vec::new()),
            denied: false,
        };
        let report = discover(&fixture, "Clara Ashwell", Region::Au, 100).unwrap();
        assert!(fixture.seen.borrow().len() >= 12);
        assert_eq!(report.facets.len(), 4);
        assert_eq!(report.candidates.len(), 4);
        assert!(
            report
                .candidates
                .iter()
                .all(|c| c.status == "unverified_search_index_lead")
        );
        assert!(report.candidates.iter().all(|c| c.reported_by.len() == 3));
        assert!(
            report
                .facets
                .iter()
                .all(|f| f.index_hits >= 4 && f.discarded_out_of_scope > 0)
        );
        assert!(
            !report
                .candidates
                .iter()
                .any(|c| c.url.contains("evil.example"))
        );
        assert_eq!(
            report.attribution,
            "none_established; indexed_page_is_not_proof_of_person_or_account"
        );
        assert!(!report.truncated);
    }

    #[test]
    fn regional_official_source_selection_reuses_all_other_facets() {
        let au = Fixture {
            seen: RefCell::new(Vec::new()),
            denied: false,
        };
        let us = Fixture {
            seen: RefCell::new(Vec::new()),
            denied: false,
        };
        let au_report = discover(&au, "Jane Example", Region::Au, 1).unwrap();
        let us_report = discover(&us, "Alyssa Example", Region::Us, 3600).unwrap();
        assert_eq!(au_report.facets[3].accepted_host, "asic.gov.au");
        assert_eq!(us_report.facets[3].accepted_host, "sec.gov");
        assert_eq!(us_report.candidates.len(), 4);
        assert!(
            !us_report
                .candidates
                .iter()
                .any(|c| c.url.contains("asic.gov.au"))
        );
        assert_eq!(
            au_report.facets[..3]
                .iter()
                .map(|f| f.accepted_host)
                .collect::<Vec<_>>(),
            us_report.facets[..3]
                .iter()
                .map(|f| f.accepted_host)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rejects_unsafe_or_single_token_names_before_any_request() {
        let fixture = Fixture {
            seen: RefCell::new(Vec::new()),
            denied: false,
        };
        for bad in [
            "A",
            "Ada",
            "A Example",
            "Jane \"Example\"",
            "Jane\nExample",
            "Jane\tExample",
            "Jane\rExample",
            "Jane\u{0}Example",
            "Jane <Example>",
            &"X".repeat(130),
        ] {
            assert!(discover(&fixture, bad, Region::Au, 1).is_err(), "{bad:?}");
        }
        assert!(fixture.seen.borrow().is_empty());
        assert!(!is_accepted_host(
            "https://github.com.evil.example/x",
            "github.com"
        ));
        assert!(!is_accepted_host("http://github.com/x", "github.com"));
    }

    #[test]
    fn unavailable_sources_do_not_claim_zero_results_are_confirmed() {
        let fixture = Fixture {
            seen: RefCell::new(Vec::new()),
            denied: true,
        };
        let report = discover(&fixture, "Daphne Example", Region::Au, 7200).unwrap();
        assert!(report.candidates.is_empty());
        assert_eq!(report.facets.len(), 4);
        assert!(
            report
                .facets
                .iter()
                .flat_map(|f| &f.outcomes)
                .all(|o| !o.kind.is_accepted())
        );
        assert!(fixture.seen.borrow().len() >= 12);
    }
}
