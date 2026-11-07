//! Keyless entity intelligence over Wikidata, the public structured knowledge base.
//!
//! One lookup resolves a free-text query to a Wikidata item (its `wbsearchentities` top match) or
//! takes a `Q`-number directly, then reads that item's statements from the keyless REST API
//! (`/w/rest.php/wikibase/v1/entities/items/{QID}`). The item becomes a [`EntityKind::Person`] when
//! it is an instance of human (`P31 = Q5`), an [`EntityKind::Organisation`] only when it is an
//! instance of a known organisation type, and otherwise [`EntityKind::Other`]: an organisation is
//! asserted on positive type evidence, never assumed as a default. A 200 response that is not the
//! item document asked for -- an array, a different id, or a non-item envelope -- is source-schema
//! drift, never a positive entity. Statement-level JSON (including rank, qualifiers and
//! references) is retained within explicit per-statement and per-item bounds; omissions are
//! counted. Deprecated or qualified statements remain evidence, but cannot seed live pivots.
//!
//! A curated set of statements also becomes its own pivot entity, so a Wikidata lookup seeds the
//! rest of the engine: the official website (`P856`) is a [`EntityKind::Domain`], a coordinate
//! location (`P625`) is a [`EntityKind::Coordinates`] the geocoder can reverse, and external
//! identifiers (GitHub, X, VIAF, ORCID, `IMDb`, ...) are [`EntityKind::Url`] and
//! [`EntityKind::Username`] pivots. A knowledge-base record is a candidate for review, never a
//! confirmed real-world identity: the confidence is deliberately modest and every summary says so.
//!
//! The REST origin is switchable via `HUNTSMAN_WIKIDATA_BASE_URL` without recompiling; absent, the
//! public `www.wikidata.org` endpoint is used, reached through the guarded, paced fetch boundary.

use serde::Deserialize;
use serde_json::Value;

use crate::entity::{EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{
    FetchOptions, Fetched, answer, decode_json, fetch, mediawiki_api_error, whole_response,
};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "wikidata";
const PUBLIC_BASE: &str = "https://www.wikidata.org";
/// HTTPS origin for an operator-managed Wikibase-compatible service. When absent, the public
/// Wikidata endpoint is used.
pub const BASE_URL_ENV: &str = crate::environment::WIKIDATA_BASE_URL_ENV;

/// Confidence that a knowledge-base item is the subject the query meant. A label match, even an
/// exact `Q`-number, is a candidate for review, never a confirmed identity.
const ITEM_CONFIDENCE: f64 = 0.6;
/// Confidence of a pivot (website, coordinate, external profile) Wikidata publishes for the item.
const PIVOT_CONFIDENCE: f64 = 0.55;
/// Most search candidates considered when resolving free text: only the top match is taken, but a
/// broader result set still says the query was ambiguous.
const SEARCH_LIMIT: usize = 5;
/// Maximum number of source statements retained as evidence; overflow is reported.
const MAX_CLAIM_VALUES: usize = 1_000;
/// Maximum bytes of serialized JSON preserved for any one statement. Oversized statements are
/// explicitly counted instead of being silently represented as complete.
const MAX_STATEMENT_JSON_BYTES: usize = 4_096;

/// A curated property: its `P`-number, the attribute name its value is kept under, and how a pivot
/// entity is built from it. Every statement is still kept as a raw `claim:P…` attribute; these
/// add a friendly name and, where set, a pivot that seeds other lookups.
struct Property {
    pid: &'static str,
    attr: &'static str,
    pivot: Pivot,
}

/// How a curated property's value becomes a pivot entity, if at all.
#[derive(Clone, Copy)]
enum Pivot {
    /// Not a pivot: kept only as a named attribute.
    None,
    /// An official website string value becomes a [`EntityKind::Domain`].
    Website,
    /// A globe-coordinate value becomes a [`EntityKind::Coordinates`].
    Coordinate,
    /// An external identifier whose value fills `{}` in this URL template, becoming a
    /// [`EntityKind::Url`]; when `handle` is set the bare value is also a [`EntityKind::Username`].
    External { url: &'static str, handle: bool },
}

/// The curated properties, in the order their attributes are recorded.
const PROPERTIES: &[Property] = &[
    Property {
        pid: "P856",
        attr: "official_website",
        pivot: Pivot::Website,
    },
    Property {
        pid: "P625",
        attr: "coordinate_location",
        pivot: Pivot::Coordinate,
    },
    Property {
        pid: "P17",
        attr: "country",
        pivot: Pivot::None,
    },
    Property {
        pid: "P571",
        attr: "inception",
        pivot: Pivot::None,
    },
    Property {
        pid: "P569",
        attr: "date_of_birth",
        pivot: Pivot::None,
    },
    Property {
        pid: "P570",
        attr: "date_of_death",
        pivot: Pivot::None,
    },
    Property {
        pid: "P159",
        attr: "headquarters",
        pivot: Pivot::None,
    },
    Property {
        pid: "P2002",
        attr: "x_username",
        pivot: Pivot::External {
            url: "https://x.com/{}",
            handle: true,
        },
    },
    Property {
        pid: "P2003",
        attr: "instagram_username",
        pivot: Pivot::External {
            url: "https://www.instagram.com/{}",
            handle: true,
        },
    },
    Property {
        pid: "P2013",
        attr: "facebook_id",
        pivot: Pivot::External {
            url: "https://www.facebook.com/{}",
            handle: false,
        },
    },
    Property {
        pid: "P2037",
        attr: "github_username",
        pivot: Pivot::External {
            url: "https://github.com/{}",
            handle: true,
        },
    },
    Property {
        pid: "P6634",
        attr: "linkedin_personal_id",
        pivot: Pivot::External {
            url: "https://www.linkedin.com/in/{}/",
            handle: false,
        },
    },
    Property {
        pid: "P11892",
        attr: "threads_username",
        pivot: Pivot::External {
            url: "https://www.threads.net/@{}",
            handle: true,
        },
    },
    Property {
        pid: "P7085",
        attr: "tiktok_username",
        pivot: Pivot::External {
            url: "https://www.tiktok.com/@{}",
            handle: true,
        },
    },
    Property {
        pid: "P12361",
        attr: "bluesky_handle",
        pivot: Pivot::External {
            url: "https://bsky.app/profile/{}",
            handle: true,
        },
    },
    Property {
        pid: "P4265",
        attr: "reddit_username",
        pivot: Pivot::External {
            url: "https://www.reddit.com/user/{}",
            handle: true,
        },
    },
    Property {
        pid: "P2397",
        attr: "youtube_channel_id",
        pivot: Pivot::External {
            url: "https://www.youtube.com/channel/{}",
            handle: false,
        },
    },
    Property {
        pid: "P345",
        attr: "imdb_id",
        pivot: Pivot::External {
            url: "https://www.imdb.com/name/{}/",
            handle: false,
        },
    },
    Property {
        pid: "P214",
        attr: "viaf_id",
        pivot: Pivot::External {
            url: "https://viaf.org/viaf/{}/",
            handle: false,
        },
    },
    Property {
        pid: "P496",
        attr: "orcid_id",
        pivot: Pivot::External {
            url: "https://orcid.org/{}",
            handle: false,
        },
    },
    Property {
        pid: "P1278",
        attr: "legal_entity_identifier",
        pivot: Pivot::None,
    },
];

/// The property whose value classifies the item: instance of (`P31`). A human (`Q5`) is a person;
/// a known organisation type is an organisation; anything else is [`EntityKind::Other`].
const INSTANCE_OF: &str = "P31";
const HUMAN: &str = "Q5";

/// `P31` values that positively evidence an organisation. The REST item endpoint returns an item's
/// own `instance_of` statements but not the subclass-of (`P279`) graph, so classification matches
/// against this curated set of common organisation types rather than walking the hierarchy. An
/// item whose `instance_of` is none of these -- a place, a work, a taxon, an event, or a record
/// with no `P31` at all -- is [`EntityKind::Other`], never defaulted to an organisation. Each QID
/// is verified against Wikidata; the comment is its English label.
const ORGANISATION_TYPES: &[&str] = &[
    "Q43229",   // organization
    "Q4830453", // business
    "Q783794",  // company
    "Q891723",  // public company
    "Q6881511", // enterprise
    "Q163740",  // nonprofit organization
    "Q79913",   // non-governmental organization
    "Q7278",    // political party
    "Q3918",    // university
    "Q2385804", // educational institution
    "Q327333",  // government agency
    "Q484652",  // international organization
    "Q157031",  // foundation
    "Q43702",   // federation
];

pub type Report = crate::lookup_report::SourceReport;

fn configured_base() -> Result<String, Error> {
    crate::canonical::configured_https_origin(
        crate::environment::wikidata_base_url(),
        PUBLIC_BASE,
        BASE_URL_ENV,
    )
    .map_err(Error::Invalid)
}

/// Whether `query` is a bare Wikidata item id (`Q` followed by digits), case-insensitively.
#[must_use]
pub fn is_qid(query: &str) -> bool {
    let mut chars = query.chars();
    matches!(chars.next(), Some('Q' | 'q')) && {
        let rest: &str = chars.as_str();
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
    }
}

/// The `wbsearchentities` URL that resolves free text to candidate items. **Pure.**
#[must_use]
pub fn search_url(base: &str, term: &str) -> String {
    format!(
        "{base}/w/api.php?action=wbsearchentities&search={}&language=en&uselang=en&format=json&limit={SEARCH_LIMIT}",
        percent_encode_unreserved(term)
    )
}

/// The REST URL for one item's full record. **Pure.**
#[must_use]
pub fn item_url(base: &str, qid: &str) -> String {
    format!(
        "{base}/w/rest.php/wikibase/v1/entities/items/{}",
        percent_encode_unreserved(qid)
    )
}

/// The public page a human reads for an item. **Pure.**
fn concept_uri(qid: &str) -> String {
    format!("https://www.wikidata.org/wiki/{qid}")
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    /// Present (any shape) when the Action API did not run the search.
    #[serde(default)]
    error: Option<Value>,
    /// The hits of a search that ran, an explicit empty list when nothing matched. A response
    /// without it says nothing about whether anything matched.
    #[serde(default)]
    search: Option<Vec<SearchHit>>,
}

#[derive(Debug, Deserialize)]
struct SearchHit {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

fn request(url: String) -> Request {
    Request::get_json(url)
}

/// Look up one Wikidata item for `query`: a `Q`-number, or free text resolved to its top match.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL, or [`Error::Invalid`]
/// when `HUNTSMAN_WIKIDATA_BASE_URL` is set to something that is not a bare HTTPS origin.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let base = configured_base()?;
    let (qid, search_label) = if is_qid(query) {
        (query.to_ascii_uppercase(), None)
    } else {
        match resolve(transport, &base, query, now_unix)? {
            Resolved::Item { qid, label } => (qid, label),
            Resolved::None(outcome) => return Ok(Report::miss(outcome)),
        }
    };

    let fetched = fetch(
        transport,
        request(item_url(&base, &qid)),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    let mut report = interpret(&fetched, &qid, search_label.as_deref(), scan_id, now_unix)
        .unwrap_or_else(Report::miss);
    label_claims(transport, &base, &qid, &mut report, now_unix);
    classify_positions(transport, &base, &qid, &mut report, now_unix);
    Ok(report)
}

/// Position held (`P39`): the offices and roles an item records.
const POSITION_HELD: &str = "P39";
/// End time (`P582`): a position statement carrying it is a former one.
const END_TIME: &str = "P582";
/// The most positions one item's classification looks up.
const MAX_POSITIONS: usize = 20;
/// `P31` types that make a position a public office: public office (`Q294414`) and elective
/// office (`Q17279032`). The generic "position" (`Q4164871`) is not one: Wikidata gives it to a
/// company's "president" and "director" as well as to heads of state.
const PUBLIC_OFFICE_TYPES: &[&str] = &["Q294414", "Q17279032"];
/// `P279` classes a public office is a subclass of: head of state (`Q48352`), head of
/// government (`Q2285706`), minister (`Q83307`), prime minister (`Q14212`), emir (`Q166382`),
/// member of parliament (`Q486839`), legislator (`Q4175034`) and mayor (`Q30185`).
const PUBLIC_OFFICE_CLASSES: &[&str] = &[
    "Q48352", "Q2285706", "Q83307", "Q14212", "Q166382", "Q486839", "Q4175034", "Q30185",
];

/// One held position read from a kept `P39` statement: its item and whether it has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldPosition {
    qid: String,
    former: bool,
}

/// The positions the item's kept `P39` statements name, deprecated ones left out, at most
/// [`MAX_POSITIONS`], each once. **Pure.**
fn held_positions(evidence: &Evidence) -> Vec<HeldPosition> {
    let mut held: Vec<HeldPosition> = Vec::new();
    for statement in evidence.attr_values("statement_json") {
        let Some(json) = statement
            .strip_prefix(POSITION_HELD)
            .and_then(|rest| rest.strip_prefix('='))
        else {
            continue;
        };
        let Ok(statement) = serde_json::from_str::<Value>(json) else {
            continue;
        };
        if !eligible_rank(&statement) {
            continue;
        }
        let Some(position) = statement
            .get("value")
            .and_then(|v| v.get("content"))
            .and_then(Value::as_str)
            .filter(|id| is_qid(id) && id.starts_with('Q'))
        else {
            continue;
        };
        let former = statement
            .get("qualifiers")
            .and_then(Value::as_array)
            .is_some_and(|qualifiers| {
                qualifiers.iter().any(|q| {
                    q.get("property")
                        .and_then(|p| p.get("id"))
                        .and_then(Value::as_str)
                        == Some(END_TIME)
                })
            });
        if let Some(known) = held.iter_mut().find(|h| h.qid == position) {
            // A position held once and ended, then held again, is current if any holding is.
            known.former &= former;
        } else if held.len() < MAX_POSITIONS {
            held.push(HeldPosition {
                qid: position.to_owned(),
                former,
            });
        }
    }
    held
}

/// The item ids a `wbgetentities` claim list names under `pid`. **Pure.**
fn claim_targets<'a>(entity: &'a Value, pid: &str) -> Vec<&'a str> {
    entity
        .get("claims")
        .and_then(|claims| claims.get(pid))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|claim| {
            claim
                .get("mainsnak")?
                .get("datavalue")?
                .get("value")?
                .get("id")?
                .as_str()
        })
        .collect()
}

/// Whether a position's own record types it as a public office. **Pure.**
fn is_public_office(position: &Value) -> bool {
    claim_targets(position, "P31")
        .iter()
        .any(|t| PUBLIC_OFFICE_TYPES.contains(t))
        || claim_targets(position, "P279")
            .iter()
            .any(|c| PUBLIC_OFFICE_CLASSES.contains(c))
}

/// The `wbgetentities` URL that reads the claims of the positions in `ids`. **Pure.**
#[must_use]
pub fn positions_url(base: &str, ids: &[String]) -> String {
    format!(
        "{base}/w/api.php?action=wbgetentities&ids={}&props=claims&format=json",
        percent_encode_unreserved(&ids.join("|"))
    )
}

/// Classify the positions the item holds (`P39`) with one bounded request for their records: a
/// position typed as a public office makes the person politically exposed, current or former, and
/// the person entity is tagged `politically-exposed`. Positions are only ever recorded as found:
/// none typed as public offices is said as such, never as "not exposed", and a failed request only
/// records why, never changing the findings or the outcome.
fn classify_positions<T: Transport + ?Sized>(
    transport: &T,
    base: &str,
    qid: &str,
    report: &mut Report,
    now_unix: u64,
) {
    let Some(evidence) = item_evidence(report, qid) else {
        return;
    };
    let held = held_positions(evidence);
    if held.is_empty() {
        return;
    }
    let ids: Vec<String> = held.iter().map(|h| h.qid.clone()).collect();
    let records = fetch(
        transport,
        request(positions_url(base, &ids)),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )
    .map_err(|error| error.to_string())
    .and_then(|fetched| {
        let response = whole_response(&fetched, "Wikidata positions").map_err(why)?;
        answer(&fetched, "Wikidata positions").map_err(why)?;
        decode_json::<Value>(response, SOURCE, now_unix, "Wikidata positions").map_err(why)
    });
    let mut updated = std::mem::replace(
        evidence,
        Evidence::new(EvidenceProvenance::for_scan(SOURCE, ""), String::new()),
    );
    let mut exposed = false;
    match records {
        Ok(body) => {
            let entities = body.get("entities");
            let mut offices = 0usize;
            for position in &held {
                let Some(record) = entities.and_then(|e| e.get(&position.qid)) else {
                    continue;
                };
                if is_public_office(record) {
                    offices += 1;
                    updated = updated.with_attr(
                        "public_office",
                        format!(
                            "{} ({})",
                            position.qid,
                            if position.former { "former" } else { "current" }
                        ),
                    );
                }
            }
            if offices > 0 {
                exposed = true;
                updated = updated.with_attr(
                    "politically_exposed",
                    format!(
                        "yes: {offices} of {} positions held (P39) are typed as public offices; review before relying on it",
                        held.len()
                    ),
                );
            } else {
                updated = updated.with_attr(
                    "public_office_checked",
                    format!(
                        "{} positions held (P39), none typed as a public office",
                        held.len()
                    ),
                );
            }
        }
        Err(reason) => {
            updated = updated.with_attr("public_office_unavailable", reason);
        }
    }
    *evidence = updated;
    if exposed {
        if let Some(entity) = report.entities.iter_mut().find(|entity| {
            entity.evidence.iter().any(|ev| {
                ev.attr_values("qid").any(|q| q == qid) && ev.attributes.contains_key("claim")
            })
        }) {
            entity.tag("politically-exposed");
        }
    }
}

/// The most ids one `wbgetentities` request names (the Action API's own limit).
const MAX_LABEL_IDS: usize = 50;

/// The `wbgetentities` URL that names the properties and items in `ids`. **Pure.**
#[must_use]
pub fn labels_url(base: &str, ids: &[String]) -> String {
    format!(
        "{base}/w/api.php?action=wbgetentities&ids={}&props=labels&languages=en&languagefallback=1&format=json",
        percent_encode_unreserved(&ids.join("|"))
    )
}

/// Whether `id` is a property id (`P` and digits). **Pure.**
fn is_pid(id: &str) -> bool {
    id.strip_prefix('P')
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// The property and item ids an item's `claim` attributes name, each once, at most
/// [`MAX_LABEL_IDS`]: every claim's property, then its item value, in claim order, so a bounded
/// request names whole claims rather than only properties. **Pure.**
fn claim_ids(evidence: &Evidence) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for claim in evidence.attr_values("claim") {
        let Some((pid, value)) = claim.split_once('=') else {
            continue;
        };
        for id in [pid, value] {
            let nameable = is_pid(id) || (id.starts_with('Q') && is_qid(id));
            if nameable && ids.len() < MAX_LABEL_IDS && !ids.iter().any(|known| known == id) {
                ids.push(id.to_owned());
            }
        }
    }
    ids
}

/// `id=label` for every entity in a `wbgetentities` response that carries a label. **Pure.**
fn labels_from(response: &Value, ids: &[String]) -> Vec<String> {
    let Some(entities) = response.get("entities").and_then(Value::as_object) else {
        return Vec::new();
    };
    ids.iter()
        .filter_map(|id| {
            let labels = entities.get(id)?.get("labels")?.as_object()?;
            let label = labels
                .get("en")
                .or_else(|| labels.values().next())?
                .get("value")?
                .as_str()?
                .trim();
            (!label.is_empty()).then(|| format!("{id}={label}"))
        })
        .collect()
}

/// Why a labels response could not be read: its outcome's kind and detail. **Pure.**
fn why(outcome: SourceExecutionOutcome) -> String {
    format!("{:?}: {}", outcome.kind, outcome.detail.unwrap_or_default())
}

/// Name the properties and items the item's claims cite, with one bounded request. Readable
/// labels are presentation: a failed lookup leaves the claims as they were, records why in
/// `claim_labels_unavailable`, and never changes the report's outcome or entities.
/// The item's own evidence record in `report`: the one that carries its `qid` and its claims.
fn item_evidence<'a>(report: &'a mut Report, qid: &str) -> Option<&'a mut Evidence> {
    report
        .entities
        .iter_mut()
        .flat_map(|entity| entity.evidence.iter_mut())
        .find(|evidence| {
            evidence.attr_values("qid").any(|q| q == qid)
                && evidence.attributes.contains_key("claim")
        })
}

fn label_claims<T: Transport + ?Sized>(
    transport: &T,
    base: &str,
    qid: &str,
    report: &mut Report,
    now_unix: u64,
) {
    let Some(evidence) = item_evidence(report, qid) else {
        return;
    };
    let ids = claim_ids(evidence);
    if ids.is_empty() {
        return;
    }
    let labelled = fetch(
        transport,
        request(labels_url(base, &ids)),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )
    .map_err(|error| error.to_string())
    .and_then(|fetched| {
        let response = whole_response(&fetched, "Wikidata labels").map_err(why)?;
        answer(&fetched, "Wikidata labels").map_err(why)?;
        let body: Value =
            decode_json(response, SOURCE, now_unix, "Wikidata labels").map_err(why)?;
        Ok(labels_from(&body, &ids))
    });
    let mut updated = std::mem::replace(
        evidence,
        Evidence::new(EvidenceProvenance::for_scan(SOURCE, ""), String::new()),
    );
    match labelled {
        Ok(labels) if !labels.is_empty() => {
            for label in labels {
                updated = updated.with_attr("claim_label", label);
            }
        }
        Ok(_) => updated = updated.with_attr("claim_labels_unavailable", "no labels returned"),
        Err(reason) => updated = updated.with_attr("claim_labels_unavailable", reason),
    }
    *evidence = updated;
}

enum Resolved {
    Item { qid: String, label: Option<String> },
    None(SourceExecutionOutcome),
}

/// Resolve free text to its top item through `wbsearchentities`.
fn resolve<T: Transport + ?Sized>(
    transport: &T,
    base: &str,
    term: &str,
    now_unix: u64,
) -> Result<Resolved, Error> {
    let fetched = fetch(
        transport,
        request(search_url(base, term)),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    let response = match whole_response(&fetched, "Wikidata search") {
        Ok(response) => response,
        Err(outcome) => return Ok(Resolved::None(outcome)),
    };
    if let Err(outcome) = answer(&fetched, "Wikidata search") {
        return Ok(Resolved::None(outcome));
    }
    let search: SearchResponse = match decode_json(response, SOURCE, now_unix, "Wikidata search") {
        Ok(search) => search,
        Err(outcome) => return Ok(Resolved::None(outcome)),
    };
    // An error envelope comes with HTTP 200: the search did not run, so it found nothing only in
    // the sense that it was never asked.
    if let Some(error) = search.error {
        return Ok(Resolved::None(mediawiki_api_error(
            &error,
            SOURCE,
            response.status,
            now_unix,
            "Wikidata search",
        )));
    }
    let Some(hits) = search.search else {
        return Ok(Resolved::None(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "Wikidata search response omitted search",
        )));
    };
    if hits.is_empty() {
        return Ok(Resolved::None(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status),
        ));
    }
    let hits: Vec<SearchHit> = hits
        .into_iter()
        .filter(|hit| !hit.id.trim().is_empty())
        .collect();
    // Namesakes: several items carry exactly the searched label. The search's ranking does not
    // say which one is the subject, so none is attributed; the candidates are named for a
    // follow-up lookup by Q-number.
    let exact: Vec<&SearchHit> = hits
        .iter()
        .filter(|hit| {
            hit.label
                .as_deref()
                .is_some_and(|label| label.trim().eq_ignore_ascii_case(term.trim()))
        })
        .collect();
    if exact.len() > 1 {
        let candidates: Vec<String> = exact
            .iter()
            .map(|hit| match hit.description.as_deref() {
                Some(description) => format!("{} ({description})", hit.id),
                None => hit.id.clone(),
            })
            .collect();
        return Ok(Resolved::None(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            Some(response.status),
            format!(
                "{} Wikidata items are labelled \"{}\": {}; none is attributed, look one up by its Q-number",
                exact.len(),
                term.trim(),
                candidates.join(", ")
            ),
        )));
    }
    // One exact-label hit is the item, wherever the search ranked it.
    if let [only] = exact.as_slice() {
        return Ok(Resolved::Item {
            qid: only.id.clone(),
            label: only.label.clone().or_else(|| only.description.clone()),
        });
    }
    // Hits that name no item matched something the search cannot say: no clean negative.
    match hits.into_iter().next() {
        Some(hit) => Ok(Resolved::Item {
            qid: hit.id,
            label: hit.label.or(hit.description),
        }),
        None => Ok(Resolved::None(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "Wikidata search hits carried no item id",
        ))),
    }
}

/// Turn one fetched item response into a report; `Err` is the outcome of a response that was not a
/// readable item document for the requested `qid`. **Pure.**
fn interpret(
    fetched: &Fetched,
    qid: &str,
    search_label: Option<&str>,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "Wikidata item")?;
    answer(fetched, "Wikidata item")?;
    let item: Value = decode_json(response, SOURCE, now_unix, "Wikidata item")?;
    if !is_item_for(&item, qid) {
        return Err(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            format!(
                "Wikidata item response is not item {qid}: a 200 that is not an item envelope, or \
                 carries a different id, is not evidence for {qid}"
            ),
        ));
    }
    Ok(decode(
        &item,
        qid,
        search_label,
        scan_id,
        now_unix,
        response.status,
    ))
}

/// Whether `item` is the REST item document asked for: a JSON object whose `type` is `"item"` and
/// whose `id` is `qid` (case-insensitively). A 200 response is not proof on its own -- an array, a
/// non-item envelope, a missing id, or a different item's id would otherwise be attributed to the
/// requested `qid` and fabricate a finding -- so a mismatch is schema drift, never a positive
/// entity. **Pure.**
fn is_item_for(item: &Value, qid: &str) -> bool {
    item.get("type").and_then(Value::as_str) == Some("item")
        && item
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.eq_ignore_ascii_case(qid))
}

/// The best value of a `{lang: "text"}` map for an English-reading operator: English or an
/// English variant, then the language-neutral `mul` label, then any value, else `None`. Wikidata's
/// REST item endpoint sometimes omits `en`, so the fallbacks keep a readable name. **Pure.**
fn best_language(map: Option<&Value>) -> Option<String> {
    let map = map?.as_object()?;
    ["en", "en-gb", "en-ca", "en-us", "mul", "simple"]
        .iter()
        .find_map(|lang| map.get(*lang).and_then(Value::as_str))
        .or_else(|| map.values().find_map(Value::as_str))
        .map(str::to_owned)
}

/// The English aliases of an item, each as a plain string. **Pure.**
fn aliases(item: &Value) -> Vec<String> {
    let Some(list) = item
        .get("aliases")
        .and_then(|a| a.get("en"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|entry| {
            entry
                .as_str()
                .or_else(|| entry.get("value").and_then(Value::as_str))
        })
        .map(str::to_owned)
        .collect()
}

/// One statement value's content rendered as text, for whichever datatype it carries: a string, a
/// `lat,lon` coordinate, a timestamp, an item reference, a quantity or a monolingual text.
/// `None` for a `novalue`/`somevalue` snak or an unreadable shape. **Pure.**
fn rendered_value(value: &Value) -> Option<String> {
    if value.get("type").and_then(Value::as_str) == Some("novalue") {
        return None;
    }
    let content = value.get("content")?;
    if let Some(text) = content.as_str() {
        return Some(text.to_owned());
    }
    if let (Some(lat), Some(lon)) = (
        content.get("latitude").and_then(Value::as_f64),
        content.get("longitude").and_then(Value::as_f64),
    ) {
        return Some(format!("{lat},{lon}"));
    }
    if let Some(time) = content.get("time").and_then(Value::as_str) {
        return Some(time.to_owned());
    }
    if let Some(amount) = content.get("amount").and_then(Value::as_str) {
        return Some(amount.to_owned());
    }
    if let Some(text) = content.get("text").and_then(Value::as_str) {
        return Some(text.to_owned());
    }
    None
}

/// A statement may generate a current-looking entity only when it is not deprecated and carries
/// no qualifiers, or, for an account identifier, only ones that describe the account
/// ([`eligible_for_account_pivot`]). Qualifiers can
/// restrict time, jurisdiction, or applicability; an uninterpreted one suppresses the pivot rather
/// than presenting the value as current. **Pure.**
fn eligible_rank(statement: &Value) -> bool {
    matches!(
        statement.get("rank").and_then(Value::as_str),
        None | Some("normal" | "preferred")
    )
}

fn eligible_for_pivot(statement: &Value) -> bool {
    eligible_rank(statement) && qualifiers_all(statement, |_, _| false)
}

/// An external account identifier (an [`Pivot::External`] property) may pivot with qualifiers
/// that only describe the account ([`describes_without_restricting`]); Wikidata records a public
/// figure's social handles with follower counts, so the strict rule would drop every one. **Pure.**
fn eligible_for_account_pivot(statement: &Value) -> bool {
    eligible_rank(statement) && qualifiers_all(statement, describes_without_restricting)
}

/// Qualifiers that describe a still-current account without limiting when or where the
/// statement holds: statement is subject of (`P805`), a follower count (`P3744`) and the time it
/// was counted (`P585`), the account's start (`P580`, with no end time), the X numeric user id
/// (`P6552`), and `P1552` only when it says "verified account" (`Q28378282`). An end time, a
/// jurisdiction, a reason for deprecation or any other qualifier still suppresses the pivot.
/// **Pure.**
fn describes_without_restricting(pid: &str, value: &Value) -> bool {
    match pid {
        "P805" | "P3744" | "P585" | "P580" | "P6552" => true,
        "P1552" => value.get("content").and_then(Value::as_str) == Some("Q28378282"),
        _ => false,
    }
}

/// P805 (statement is subject of) is non-restrictive. Wikibase REST v1 exposes qualifiers
/// as an array of `{property:{id}, value}` objects; older/other envelopes use a PID map.
/// Both forms permit only P805 for P31 classification, never temporal or unknown qualifiers.
fn eligible_for_classification(statement: &Value) -> bool {
    eligible_rank(statement) && qualifiers_all(statement, |pid, _| pid == "P805")
}

/// Whether every qualifier of `statement` is a real value that `allowed` accepts; a statement
/// with no qualifiers passes, an unreadable qualifier shape fails. **Pure.**
fn qualifiers_all(statement: &Value, allowed: impl Fn(&str, &Value) -> bool) -> bool {
    let is_value = |value: &Value| value.get("type").and_then(Value::as_str) == Some("value");
    statement
        .get("qualifiers")
        .is_none_or(|qualifiers| match qualifiers {
            Value::Object(entries) => entries.iter().all(|(pid, values)| {
                values.as_array().is_some_and(|items| {
                    !items.is_empty()
                        && items.iter().all(|item| {
                            let value = item.get("value").unwrap_or(item);
                            allowed(pid, value)
                        })
                })
            }),
            Value::Array(entries) => entries.iter().all(|entry| {
                let pid = entry
                    .get("property")
                    .and_then(|property| property.get("id"))
                    .and_then(Value::as_str);
                let value = entry.get("value");
                match (pid, value) {
                    (Some(pid), Some(value)) => is_value(value) && allowed(pid, value),
                    _ => false,
                }
            }),
            _ => false,
        })
}

/// Share the bounded value decoder while retaining property-specific eligibility.
fn values_filtered(
    statements: Option<&serde_json::Map<String, Value>>,
    pid: &str,
    eligible: fn(&Value) -> bool,
) -> Vec<String> {
    statements
        .and_then(|map| map.get(pid))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|statement| eligible(statement))
                .filter_map(|st| rendered_value(st.get("value")?))
                .take(MAX_CLAIM_VALUES)
                .collect()
        })
        .unwrap_or_default()
}

/// Only unqualified, non-deprecated values seed friendly attributes and automatic pivots.
fn values(statements: Option<&serde_json::Map<String, Value>>, property: &Property) -> Vec<String> {
    let eligible = match property.pivot {
        Pivot::External { .. } => eligible_for_account_pivot,
        _ => eligible_for_pivot,
    };
    values_filtered(statements, property.pid, eligible)
}

/// Classify an item from current P31 values, including non-restrictive P805 annotations.
fn instance_types(statements: Option<&serde_json::Map<String, Value>>) -> Vec<String> {
    values_filtered(statements, INSTANCE_OF, eligible_for_classification)
}

/// Preserve bounded source statement envelopes and compatible rendered claim values, explicitly
/// counting omitted or oversized statements. This is evidence, not an automatic pivot. **Pure.**
fn attach_statement_evidence(
    mut evidence: Evidence,
    statements: Option<&serde_json::Map<String, Value>>,
) -> Evidence {
    // Retain the statement envelope, not merely value.content: rank, ID, qualifiers and
    // references distinguish deprecated/historical claims from current observations. Preserve
    // the legacy `claim` attribute for consumers that already read it. Count all omissions.
    let mut retained = 0usize;
    let mut dropped = 0usize;
    let mut oversized = 0usize;
    if let Some(statements) = statements {
        for (pid, entries) in statements {
            if let Some(entries) = entries.as_array() {
                for statement in entries {
                    if retained >= MAX_CLAIM_VALUES {
                        dropped += 1;
                        continue;
                    }
                    let json = statement.to_string();
                    if json.len() <= MAX_STATEMENT_JSON_BYTES {
                        evidence = evidence.with_attr("statement_json", format!("{pid}={json}"));
                    } else {
                        oversized += 1;
                        evidence = evidence
                            .with_attr("statement_oversize", format!("{pid}:{} bytes", json.len()));
                    }
                    if let Some(value) = statement.get("value").and_then(rendered_value) {
                        evidence = evidence.with_attr("claim", format!("{pid}={value}"));
                    }
                    retained += 1;
                }
            } else {
                evidence =
                    evidence.with_attr("statement_schema_warning", format!("{pid}: not an array"));
            }
        }
    }
    evidence = evidence.with_attr("statements_retained", retained.to_string());
    if dropped > 0 {
        evidence = evidence.with_attr("statements_not_shown", dropped.to_string());
    }
    if oversized > 0 {
        evidence = evidence.with_attr("statements_oversized", oversized.to_string());
    }

    evidence
}

/// Build the report from a parsed item. **Pure.**
fn decode(
    item: &Value,
    qid: &str,
    search_label: Option<&str>,
    scan_id: &str,
    now_unix: u64,
    status: u16,
) -> Report {
    let statements = item.get("statements").and_then(Value::as_object);
    let instance_of = instance_types(statements);
    let label = search_label
        .map(str::to_owned)
        .or_else(|| best_language(item.get("labels")))
        .unwrap_or_else(|| qid.to_owned());
    let description = best_language(item.get("descriptions"));

    let kind = classify(&instance_of);
    let what = match &kind {
        EntityKind::Person => "person",
        EntityKind::Organisation => "organisation",
        _ => "subject of an unstated type",
    };
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!(
            "Wikidata item {qid} ({label}): a public knowledge-base record for a {what}, a candidate to review, not a confirmed identity"
        ),
    )
    .with_attr("dataset", "Wikidata")
    .with_attr("qid", qid)
    .with_attr("concept_uri", concept_uri(qid))
    .with_optional_attrs([
        ("description", description.as_deref()),
        ("instance_of", (!instance_of.is_empty()).then_some(instance_of.join(", ")).as_deref()),
    ]);
    for alias in aliases(item) {
        evidence = evidence.with_attr("alias", alias);
    }

    // Every curated property keeps a friendly, named attribute.
    let mut pivots: Vec<(EntityKind, String, String)> = Vec::new();
    for property in PROPERTIES {
        let found = values(statements, property);
        for value in &found {
            evidence = evidence.with_attr(property.attr, value.clone());
            collect_pivots(property, value, &label, qid, &mut pivots);
        }
    }

    evidence = attach_statement_evidence(evidence, statements);

    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        kind,
        &label,
        ITEM_CONFIDENCE,
        scan_id,
        evidence,
        &["wikidata", "knowledge-base"],
    );

    for (pivot_kind, value, note) in pivots {
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            format!("{note} published by Wikidata for item {qid} ({label}); a lead, not confirmed ownership"),
        )
        .with_attr("dataset", "Wikidata")
        .with_attr("qid", qid);
        push_entity(
            &mut entities,
            pivot_kind,
            &value,
            PIVOT_CONFIDENCE,
            scan_id,
            evidence,
            &["wikidata"],
        );
    }
    merge_by_uid(&mut entities);

    let outcome =
        SourceExecutionOutcome::success(SOURCE, now_unix, entities.len()).with_http_status(status);
    Report { entities, outcome }
}

/// Classify an item from its `instance_of` (`P31`) values: a human (`Q5`) is an
/// [`EntityKind::Person`]; an instance of a known organisation type ([`ORGANISATION_TYPES`]) is an
/// [`EntityKind::Organisation`]; everything else -- a place, a work, a taxon, a record with no
/// `P31` -- is [`EntityKind::Other`]. An organisation is asserted only on positive type evidence,
/// never as a fallback, so the engine never invents an organisational classification. **Pure.**
fn classify(instance_of: &[String]) -> EntityKind {
    if instance_of.iter().any(|q| q == HUMAN) {
        EntityKind::Person
    } else if instance_of
        .iter()
        .any(|q| ORGANISATION_TYPES.contains(&q.as_str()))
    {
        EntityKind::Organisation
    } else {
        EntityKind::Other
    }
}

/// Add the pivot entity (or entities) a curated property's value seeds. **Pure.**
fn collect_pivots(
    property: &Property,
    value: &str,
    label: &str,
    qid: &str,
    pivots: &mut Vec<(EntityKind, String, String)>,
) {
    match property.pivot {
        Pivot::None => {}
        Pivot::Website => {
            if let Some((kind, host)) = crate::entity::link_host(value) {
                pivots.push((kind, host, "Official website".to_owned()));
            }
        }
        Pivot::Coordinate => {
            if let Some(point) = crate::canonical::canonical_coordinates(value) {
                pivots.push((
                    EntityKind::Coordinates,
                    point,
                    "Coordinate location".to_owned(),
                ));
            }
        }
        Pivot::External { url, handle } => {
            let trimmed = value.trim().trim_start_matches('@');
            if trimmed.is_empty() {
                return;
            }
            pivots.push((
                EntityKind::Url,
                url.replace("{}", &percent_encode_unreserved(trimmed)),
                format!("{} profile", property.attr),
            ));
            if handle {
                pivots.push((
                    EntityKind::Username,
                    trimmed.to_owned(),
                    format!("{} handle", property.attr),
                ));
            }
        }
    }
    let _ = (label, qid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::source_outcome::SourceOutcomeKind;

    /// A fictional person item with the REST v1 shapes: an entity-ref P31, a string website, a
    /// globe-coordinate, a timestamp and external identifiers.
    const PERSON_ITEM: &str = r#"{
      "type":"item","id":"Q000",
      "labels":{"en":"Jane Example"},
      "descriptions":{"en":"fictional test subject"},
      "aliases":{"en":["J. Example","Janey"]},
      "statements":{
        "P31":[{"value":{"type":"value","content":"Q5"}}],
        "P856":[{"value":{"type":"value","content":"https://jane.example/"}}],
        "P625":[{"value":{"type":"value","content":{"latitude":48.8584,"longitude":2.2945,"precision":0.0001}}}],
        "P569":[{"value":{"type":"value","content":{"time":"+1970-01-02T00:00:00Z","precision":11}}}],
        "P2037":[{"value":{"type":"value","content":"janeexample"}}],
        "P214":[{"value":{"type":"value","content":"999999"}}],
        "P999":[{"value":{"type":"value","content":"uncurated value"}}],
        "P777":[{"value":{"type":"somevalue"}}]
      }
    }"#;

    /// The labels the Action API returns for the ids the person item's claims cite.
    const LABELS: &str = r#"{"entities":{
      "P31":{"labels":{"en":{"language":"en","value":"instance of"}}},
      "P856":{"labels":{"en":{"language":"en","value":"official website"}}},
      "Q5":{"labels":{"en":{"language":"en","value":"human"}}},
      "P999":{"missing":""}
    },"success":1}"#;

    /// The item, then the one labels request its claims prompt (a connect failure when the
    /// script is spent, which only marks the labels unavailable).
    fn report_of(body: &str, query: &str) -> Report {
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(crate::test_support::json_ok(body)),
            Ok(crate::test_support::json_ok(LABELS)),
        ]);
        match lookup(&transport, query, "scan-wd", 1) {
            Ok(report) => report,
            Err(error) => panic!("{error}"),
        }
    }

    fn item_evidence(report: &Report) -> &Evidence {
        report
            .entities
            .iter()
            .flat_map(|e| &e.evidence)
            .find(|ev| ev.attributes.contains_key("claim"))
            .expect("item evidence")
    }

    #[test]
    fn claims_name_their_properties_and_items_with_one_bounded_request() {
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(crate::test_support::json_ok(PERSON_ITEM)),
            Ok(crate::test_support::json_ok(LABELS)),
        ]);
        let report = lookup(&transport, "Q000", "scan-wd", 1).expect("lookup");
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 2, "item then one labels request");
        assert!(
            seen[1].url.contains("action=wbgetentities"),
            "{}",
            seen[1].url
        );
        assert!(
            seen[1].url.contains("P31%7CQ5"),
            "claim then its value: {}",
            seen[1].url
        );
        let labels: Vec<&str> = item_evidence(&report).attr_values("claim_label").collect();
        assert!(labels.contains(&"P31=instance of"), "{labels:?}");
        assert!(labels.contains(&"Q5=human"), "{labels:?}");
        assert!(!labels.iter().any(|l| l.starts_with("P999")), "{labels:?}");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn a_failed_labels_request_never_changes_the_findings() {
        let transport = crate::test_support::ScriptedTransport::new(vec![Ok(
            crate::test_support::json_ok(PERSON_ITEM),
        )]);
        let unlabelled = lookup(&transport, "Q000", "scan-wd", 1).expect("lookup");
        let labelled = report_of(PERSON_ITEM, "Q000");
        assert_eq!(unlabelled.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(unlabelled.entities.len(), labelled.entities.len());
        let evidence = item_evidence(&unlabelled);
        assert!(evidence.attributes.contains_key("claim_labels_unavailable"));
        assert!(!evidence.attributes.contains_key("claim_label"));
    }

    #[test]
    fn claim_ids_name_whole_claims_each_once_and_bounded() {
        let mut evidence = Evidence::new(EvidenceProvenance::for_scan(SOURCE, "s"), "x");
        for n in 0..60 {
            evidence = evidence.with_attr("claim", format!("P{n}=Q{n}"));
        }
        evidence = evidence
            .with_attr("claim", "P0=Q0")
            .with_attr("claim", "P1=plain text")
            .with_attr("claim", "bad");
        let ids = claim_ids(&evidence);
        assert_eq!(ids.len(), MAX_LABEL_IDS);
        assert_eq!(
            &ids[..4],
            ["P0", "Q0", "P1", "Q1"],
            "each claim whole, in order"
        );
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
    }

    fn entity<'a>(report: &'a Report, kind: &EntityKind, value: &str) -> &'a Entity {
        report
            .entities
            .iter()
            .find(|e| e.kind == *kind && e.raw_value == value)
            .unwrap_or_else(|| panic!("no {kind:?} {value} in {:#?}", report.entities))
    }

    #[test]
    fn is_qid_accepts_only_q_then_digits() {
        assert!(is_qid("Q42"));
        assert!(is_qid("q42"));
        assert!(!is_qid("Q"));
        assert!(!is_qid("Q4a"));
        assert!(!is_qid("42"));
        assert!(!is_qid("Douglas Adams"));
    }

    #[test]
    fn the_urls_carry_the_term_and_qid_once() {
        assert_eq!(
            search_url(PUBLIC_BASE, "Douglas Adams"),
            "https://www.wikidata.org/w/api.php?action=wbsearchentities&search=Douglas%20Adams&language=en&uselang=en&format=json&limit=5"
        );
        assert_eq!(
            item_url(PUBLIC_BASE, "Q42"),
            "https://www.wikidata.org/w/rest.php/wikibase/v1/entities/items/Q42"
        );
    }

    #[test]
    fn a_human_item_is_a_person_with_website_coordinate_and_handle_pivots() {
        let report = report_of(PERSON_ITEM, "Q000");
        let person = entity(&report, &EntityKind::Person, "Jane Example");
        assert!((person.confidence - ITEM_CONFIDENCE).abs() < f64::EPSILON);
        let ev = &person.evidence[0];
        assert_eq!(ev.attributes.get("qid").map(String::as_str), Some("Q000"));
        assert_eq!(
            ev.attributes.get("official_website").map(String::as_str),
            Some("https://jane.example/")
        );
        assert_eq!(
            ev.attributes.get("github_username").map(String::as_str),
            Some("janeexample")
        );
        // Aliases and the coordinate are kept.
        assert_eq!(
            ev.attr_values("alias").collect::<Vec<_>>(),
            ["J. Example", "Janey"]
        );
        assert_eq!(
            ev.attributes.get("coordinate_location").map(String::as_str),
            Some("48.8584,2.2945")
        );
        // Pivots that seed other lookups.
        entity(&report, &EntityKind::Domain, "jane.example");
        entity(&report, &EntityKind::Coordinates, "48.858400,2.294500");
        entity(&report, &EntityKind::Url, "https://github.com/janeexample");
        entity(&report, &EntityKind::Username, "janeexample");
        entity(&report, &EntityKind::Url, "https://viaf.org/viaf/999999/");
        assert!(report.outcome.kind.is_accepted());
    }

    #[test]
    fn every_statement_is_kept_even_an_uncurated_one() {
        let report = report_of(PERSON_ITEM, "Q000");
        let claims: Vec<&str> = report.entities[0].evidence[0]
            .attr_values("claim")
            .collect();
        assert!(claims.contains(&"P999=uncurated value"), "{claims:?}");
        assert!(claims.contains(&"P856=https://jane.example/"), "{claims:?}");
        // A somevalue snak carries no content and is not rendered.
        assert!(!claims.iter().any(|c| c.starts_with("P777=")), "{claims:?}");
    }

    #[test]
    fn deprecated_and_qualified_websites_remain_evidence_without_becoming_pivots() {
        let item = r#"{"type":"item","id":"Q8","labels":{"en":"Example"},"statements":{
          "P856":[
            {"id":"Q8$old","rank":"deprecated","value":{"type":"value","content":"https://old.example/"},"qualifiers":{"P582":[{"value":{"type":"value","content":{"time":"+2001-01-01T00:00:00Z"}}}]},"references":[{"parts":{"P854":[{"value":{"type":"value","content":"https://source.example/"}}]}}]},
            {"id":"Q8$qualified","rank":"normal","value":{"type":"value","content":"https://dated.example/"},"qualifiers":{"P580":[{"value":{"type":"value","content":{"time":"+1990-01-01T00:00:00Z"}}}]}},
            {"id":"Q8$current","rank":"preferred","value":{"type":"value","content":"https://current.example/"}}
          ],"P777":[{"id":"Q8$unknown","rank":"normal","value":{"type":"somevalue"}}]
        }}"#;
        let report = report_of(item, "Q8");
        let subject = entity(&report, &EntityKind::Other, "Example");
        let ev = &subject.evidence[0];
        let statements: Vec<&str> = ev.attr_values("statement_json").collect();
        assert_eq!(statements.len(), 4);
        assert!(statements.iter().any(|s| s.contains("Q8$old")
            && s.contains("deprecated")
            && s.contains("qualifiers")
            && s.contains("references")));
        assert!(
            statements
                .iter()
                .any(|s| s.contains("Q8$qualified") && s.contains("P580"))
        );
        assert!(
            statements
                .iter()
                .any(|s| s.contains("Q8$unknown") && s.contains("somevalue"))
        );
        assert_eq!(
            ev.attributes.get("statements_retained").map(String::as_str),
            Some("4")
        );
        entity(&report, &EntityKind::Domain, "current.example");
        assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Domain
            && (e.raw_value == "old.example" || e.raw_value == "dated.example")));
        assert_eq!(
            ev.attributes.get("official_website").map(String::as_str),
            Some("https://current.example/")
        );
    }

    #[test]
    fn a_known_organisation_type_is_an_organisation() {
        // Q4830453 is "business": positive organisation type evidence.
        let org = r#"{"type":"item","id":"Q1","labels":{"en":"Example Org"},"statements":{"P31":[{"value":{"type":"value","content":"Q4830453"}}]}}"#;
        let report = report_of(org, "Q1");
        entity(&report, &EntityKind::Organisation, "Example Org");
    }

    #[test]
    fn a_non_organisation_type_or_missing_instance_of_is_other_never_an_organisation() {
        // A place (Q515 city), a work (Q11424 film), a taxon (Q16521) and a record with no P31 at
        // all must never be defaulted to an organisation: each is EntityKind::Other. Classifying
        // any of these as an organisation would fabricate a classification Wikidata did not state.
        let cases = [
            (
                "a city",
                "Q2",
                r#"{"type":"item","id":"Q2","labels":{"en":"Example City"},"statements":{"P31":[{"value":{"type":"value","content":"Q515"}}]}}"#,
                "Example City",
            ),
            (
                "a film",
                "Q3",
                r#"{"type":"item","id":"Q3","labels":{"en":"Example Film"},"statements":{"P31":[{"value":{"type":"value","content":"Q11424"}}]}}"#,
                "Example Film",
            ),
            (
                "a taxon",
                "Q4",
                r#"{"type":"item","id":"Q4","labels":{"en":"Examplaceae"},"statements":{"P31":[{"value":{"type":"value","content":"Q16521"}}]}}"#,
                "Examplaceae",
            ),
            (
                "no instance_of",
                "Q6",
                r#"{"type":"item","id":"Q6","labels":{"en":"Untyped Record"},"statements":{}}"#,
                "Untyped Record",
            ),
        ];
        for (what, qid, body, name) in cases {
            let report = report_of(body, qid);
            entity(&report, &EntityKind::Other, name);
            assert!(
                !report
                    .entities
                    .iter()
                    .any(|e| matches!(e.kind, EntityKind::Organisation | EntityKind::Person)),
                "{what}: fabricated a person/organisation classification in {:#?}",
                report.entities
            );
        }
    }

    #[test]
    fn free_text_resolves_through_search_then_reads_the_item() {
        let search =
            r#"{"search":[{"id":"Q000","label":"Jane Example","description":"fictional"}]}"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(crate::test_support::json_ok(search)),
            Ok(crate::test_support::json_ok(PERSON_ITEM)),
        ]);
        match lookup(&transport, "Jane Example", "scan-wd", 1) {
            Ok(report) => {
                entity(&report, &EntityKind::Person, "Jane Example");
            }
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn a_search_with_no_hit_is_a_clean_negative() {
        let report = report_of(r#"{"search":[]}"#, "no such subject anywhere");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    /// The Action API answers a search it did not run with HTTP 200 and an error envelope, so a
    /// lagged, rate-limited or failing search, or a reply with no hit list at all, is never read as
    /// "no Wikidata item".
    #[test]
    fn a_search_the_api_did_not_run_is_never_a_clean_negative() {
        for (body, kind) in [
            (
                r#"{"error":{"code":"cirrussearch-too-busy-error","info":"Search is currently too busy. Please try again later."}}"#,
                SourceOutcomeKind::RateLimited,
            ),
            (
                r#"{"error":{"code":"cirrussearch-backend-error","info":"We could not complete your search"}}"#,
                SourceOutcomeKind::Inconclusive,
            ),
            (
                r#"{"error":{"code":"ratelimited","info":"slow down"}}"#,
                SourceOutcomeKind::RateLimited,
            ),
            (
                r#"{"search":[{"label":"Jane Example","description":"x"}]}"#,
                SourceOutcomeKind::SchemaDrift,
            ),
            (
                r#"{"error":{"code":"internal_api_error_DBQueryError","info":"x"},"search":[]}"#,
                SourceOutcomeKind::Inconclusive,
            ),
            (
                r#"{"searchinfo":{"search":"x"}}"#,
                SourceOutcomeKind::ParserDrift,
            ),
        ] {
            let report = report_of(body, "a subject the search never ran for");
            assert!(report.entities.is_empty(), "{body}");
            assert_eq!(report.outcome.kind, kind, "{body}: {:?}", report.outcome);
        }
        // A code that is not shaped like an API code is not carried into the diagnostic.
        let report = report_of(
            r#"{"error":{"code":"<script>alert(1)</script>"}}"#,
            "a subject the search never ran for",
        );
        assert_eq!(
            report.outcome.detail.as_deref(),
            Some("Wikidata search API error: unknown")
        );
    }

    #[test]
    fn a_refusal_is_not_read_as_a_zero() {
        let report = report_of("forbidden", "Q000");
        assert!(report.entities.is_empty());
        assert!(!report.outcome.kind.is_accepted(), "{:?}", report.outcome);
    }

    #[test]
    fn a_body_that_is_not_the_item_asked_for_is_schema_drift_not_an_entity() {
        // A 200 response that is readable JSON but not the requested item document seeds no entity
        // and is never accepted: attributing a mismatched or malformed envelope to the requested
        // qid would fabricate a finding. Each is source-schema drift.
        let mismatched = [
            ("an array", "[1,2,3]"),
            ("a non-item envelope", r#"{"type":"property","id":"Q000"}"#),
            ("a missing id", r#"{"type":"item","labels":{"en":"No Id"}}"#),
            (
                "a different item's id",
                r#"{"type":"item","id":"Q999","labels":{"en":"Someone Else"},"statements":{"P31":[{"value":{"type":"value","content":"Q5"}}]}}"#,
            ),
            (
                "no type field",
                r#"{"id":"Q000","labels":{"en":"Untyped"}}"#,
            ),
        ];
        for (what, body) in mismatched {
            let report = report_of(body, "Q000");
            assert!(
                report.entities.is_empty(),
                "{what}: fabricated {:#?}",
                report.entities
            );
            assert_eq!(
                report.outcome.kind,
                SourceOutcomeKind::SchemaDrift,
                "{what}"
            );
            assert!(!report.outcome.kind.is_accepted(), "{what}");
        }
    }

    #[test]
    fn a_matching_item_envelope_is_the_one_shape_that_is_accepted() {
        // type "item" plus the requested id (matched case-insensitively) reads as an entity.
        let report = report_of(
            r#"{"type":"item","id":"q000","labels":{"en":"Jane Example"},"statements":{"P31":[{"value":{"type":"value","content":"Q5"}}]}}"#,
            "Q000",
        );
        entity(&report, &EntityKind::Person, "Jane Example");
        assert!(report.outcome.kind.is_accepted());
    }
    #[test]
    fn nonrestrictive_p805_type_annotation_preserves_person_and_evidence() {
        let item = r#"{
          "type":"item","id":"Q42","labels":{"en":"Douglas Adams"},
          "statements":{
            "P31":[{"rank":"normal","value":{"type":"value","content":"Q5"},
                    "qualifiers":[{"property":{"id":"P805","data_type":"wikibase-item"},
                                   "value":{"type":"value","content":"Q42395533"}}]}],
            "P856":[{"rank":"normal","value":{"type":"value","content":"https://dated.example/"},
                     "qualifiers":[{"property":{"id":"P805"},
                                    "value":{"type":"value","content":"Q1"}}]},
                    {"rank":"normal","value":{"type":"value","content":"https://live.example/"},
                     "qualifiers":[]}]
          }
        }"#;
        let report = report_of(item, "Q42");
        let person = entity(&report, &EntityKind::Person, "Douglas Adams");
        assert_eq!(
            person.evidence[0]
                .attributes
                .get("instance_of")
                .map(String::as_str),
            Some("Q5")
        );
        assert!(
            person.evidence[0]
                .attr_values("statement_json")
                .any(|s| s.contains("P805"))
        );
        entity(&report, &EntityKind::Domain, "live.example");
        assert!(
            !report
                .entities
                .iter()
                .any(|e| { e.kind == EntityKind::Domain && e.raw_value == "dated.example" })
        );
    }

    #[test]
    fn restrictive_or_deprecated_p31_statements_do_not_classify() {
        let cases = [
            serde_json::json!({
                "rank":"deprecated","value":{"type":"value","content":"Q5"}
            }),
            serde_json::json!({
                "rank":"normal","value":{"type":"value","content":"Q5"},
                "qualifiers":{"P580":[{"value":{"type":"value","content":"+1990-01-01"}}]}
            }),
            serde_json::json!({
                "rank":"normal","value":{"type":"value","content":"Q5"},
                "qualifiers":[{"property":{"id":"P580","data_type":"time"},
                               "value":{"type":"value","content":"+1990-01-01"}}]
            }),
            serde_json::json!({
                "rank":"normal","value":{"type":"value","content":"Q5"},
                "qualifiers":{
                    "P805":[{"value":{"type":"value","content":"Q42395533"}}],
                    "P582":[{"value":{"type":"value","content":"+2000-01-01"}}]
                }
            }),
        ];
        for statement in cases {
            let mut item = serde_json::json!({
                "type":"item","id":"Q43","labels":{"en":"Example Subject"},
                "statements":{"P31":[]}
            });
            item["statements"]["P31"] = serde_json::json!([statement]);
            let report = decode(&item, "Q43", None, "scan-wd", 1, 200);
            entity(&report, &EntityKind::Other, "Example Subject");
            assert!(!report.entities.iter().any(|e| e.kind == EntityKind::Person));
        }
    }
    #[test]
    fn p805_qualifier_map_remains_supported_and_malformed_qualifiers_are_rejected() {
        let old = serde_json::json!({
            "rank":"normal","value":{"type":"value","content":"Q5"},
            "qualifiers":{"P805":[{"value":{"type":"value","content":"Q1"}}]}
        });
        assert!(eligible_for_classification(&old));
        let invalid = serde_json::json!({
            "rank":"normal","value":{"type":"value","content":"Q5"},
            "qualifiers":[{"property":{"id":"P805"}}]
        });
        assert!(!eligible_for_classification(&invalid));
        let empty = serde_json::json!({
            "rank":"normal","value":{"type":"value","content":"https://example.com/"},
            "qualifiers":[]
        });
        assert!(eligible_for_pivot(&empty));
    }

    /// An X handle as Wikidata publishes it for a public figure: follower counts with the time
    /// each was counted, the account's start, its numeric id and "verified account".
    fn handle_with(extra: &[serde_json::Value]) -> serde_json::Value {
        let q = |pid: &str, content: serde_json::Value| serde_json::json!({"property":{"id":pid},"value":{"type":"value","content":content}});
        let mut qualifiers = vec![
            q("P3744", serde_json::json!({"amount":"+9135405","unit":"1"})),
            q(
                "P585",
                serde_json::json!({"time":"+2023-01-01T00:00:00Z","precision":11}),
            ),
            q(
                "P580",
                serde_json::json!({"time":"+2009-06-03T00:00:00Z","precision":11}),
            ),
            q("P6552", serde_json::json!("12345")),
            q("P1552", serde_json::json!("Q28378282")),
        ];
        qualifiers.extend(extra.iter().cloned());
        serde_json::json!({
            "rank":"normal","value":{"type":"value","content":"ExampleHandle"},
            "qualifiers":qualifiers
        })
    }

    #[test]
    fn descriptive_qualifiers_keep_a_handle_pivot_and_restrictive_ones_suppress_it() {
        assert!(eligible_for_account_pivot(&handle_with(&[])));
        let q = |pid: &str, content: serde_json::Value| serde_json::json!({"property":{"id":pid},"value":{"type":"value","content":content}});
        let ended = q(
            "P582",
            serde_json::json!({"time":"+2020-01-01T00:00:00Z","precision":11}),
        );
        assert!(
            !eligible_for_account_pivot(&handle_with(&[ended])),
            "an end time"
        );
        let other = q("P1552", serde_json::json!("Q1"));
        assert!(
            !eligible_for_account_pivot(&handle_with(&[other])),
            "another characteristic"
        );
        let unknown = q("P9999", serde_json::json!("x"));
        assert!(
            !eligible_for_account_pivot(&handle_with(&[unknown])),
            "an uninterpreted qualifier"
        );
        let novalue = serde_json::json!({"property":{"id":"P3744"},"value":{"type":"novalue"}});
        assert!(
            !eligible_for_account_pivot(&handle_with(&[novalue])),
            "a non-value qualifier"
        );
        // A website keeps the strict rule, and classification still accepts P805 alone.
        assert!(!eligible_for_pivot(&handle_with(&[])));
        let mut typed = handle_with(&[]);
        typed["value"]["content"] = serde_json::json!("Q5");
        assert!(!eligible_for_classification(&typed));
    }

    #[test]
    fn a_verified_handle_with_follower_counts_becomes_a_pivot() {
        let mut item = serde_json::json!({
            "type":"item","id":"Q44","labels":{"en":"Example Ruler"},
            "statements":{"P31":[{"value":{"type":"value","content":"Q5"}}]}
        });
        item["statements"]["P2002"] = serde_json::json!([handle_with(&[])]);
        let report = decode(&item, "Q44", None, "scan-wd", 1, 200);
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.raw_value == "ExampleHandle"),
            "{:?}",
            report
                .entities
                .iter()
                .map(|e| &e.raw_value)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn namesakes_are_inconclusive_and_never_attributed() {
        let search = r#"{"search":[
          {"id":"Q127511658","label":"Andrew Forrest"},
          {"id":"Q504773","label":"Andrew Forrest","description":"Australian mining businessman"},
          {"id":"Q50548887","label":"Andrew F. Hugall","description":"biologist"},
          {"id":"Q93245974","label":"andrew forrest","description":"Deserter from British Army"}
        ]}"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![Ok(
            crate::test_support::json_ok(search),
        )]);
        let report = lookup(&transport, "Andrew Forrest", "scan-wd", 1).expect("lookup");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
        let detail = report.outcome.detail.clone().unwrap_or_default();
        assert!(detail.starts_with("3 Wikidata items"), "{detail}");
        assert!(
            detail.contains("Q504773 (Australian mining businessman)"),
            "{detail}"
        );
        assert!(!detail.contains("Q50548887"), "{detail}");
        assert_eq!(transport.seen.borrow().len(), 1, "no item is fetched");
    }

    #[test]
    fn the_one_exact_label_is_the_item_wherever_it_ranks() {
        let search = r#"{"search":[
          {"id":"Q50548887","label":"Andrew F. Hugall","description":"biologist"},
          {"id":"Q000","label":"Jane Example"}
        ]}"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(crate::test_support::json_ok(search)),
            Ok(crate::test_support::json_ok(PERSON_ITEM)),
        ]);
        let report = lookup(&transport, "Jane Example", "scan-wd", 1).expect("lookup");
        assert!(transport.seen.borrow()[1].url.ends_with("/items/Q000"));
        entity(&report, &EntityKind::Person, "Jane Example");
    }

    #[test]
    fn linkedin_threads_and_other_account_ids_become_pivots() {
        let item = r#"{"type":"item","id":"Q45","labels":{"en":"Example Executive"},
          "statements":{
            "P31":[{"value":{"type":"value","content":"Q5"}}],
            "P6634":[{"rank":"normal","value":{"type":"value","content":"example-exec"}}],
            "P11892":[{"rank":"normal","value":{"type":"value","content":"exampleexec"}}],
            "P7085":[{"rank":"normal","value":{"type":"value","content":"exampletok"}}],
            "P12361":[{"rank":"normal","value":{"type":"value","content":"example.bsky.social"}}],
            "P4265":[{"rank":"normal","value":{"type":"value","content":"exampleredditor"}}],
            "P2397":[{"rank":"normal","value":{"type":"value","content":"UCabc123"}}]
          }}"#;
        let report = report_of(item, "Q45");
        for url in [
            "https://www.linkedin.com/in/example-exec/",
            "https://www.threads.net/@exampleexec",
            "https://www.tiktok.com/@exampletok",
            "https://bsky.app/profile/example.bsky.social",
            "https://www.reddit.com/user/exampleredditor",
            "https://www.youtube.com/channel/UCabc123",
        ] {
            assert!(
                report
                    .entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Url && e.raw_value == url),
                "{url}"
            );
        }
        for handle in [
            "exampleexec",
            "exampletok",
            "example.bsky.social",
            "exampleredditor",
        ] {
            assert!(
                report
                    .entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Username && e.raw_value == handle),
                "{handle}"
            );
        }
        // A LinkedIn slug and a YouTube channel id are not cross-site usernames.
        assert!(
            !report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username
                    && (e.raw_value == "example-exec" || e.raw_value == "UCabc123"))
        );
    }

    /// An item holding a current public office (typed directly), a former one (subclass of head
    /// of state, ended by P582) and a corporate role, as the live records type them.
    const OFFICE_HOLDER: &str = r#"{"type":"item","id":"Q46","labels":{"en":"Example Ruler"},
      "statements":{
        "P31":[{"value":{"type":"value","content":"Q5"}}],
        "P39":[
          {"id":"Q46$a","rank":"normal","value":{"type":"value","content":"Q110964267"},"qualifiers":[]},
          {"id":"Q46$b","rank":"normal","value":{"type":"value","content":"Q955006"},
           "qualifiers":[{"property":{"id":"P582"},"value":{"type":"value","content":{"time":"+2020-01-01T00:00:00Z"}}}]},
          {"id":"Q46$c","rank":"normal","value":{"type":"value","content":"Q484876"},"qualifiers":[]},
          {"id":"Q46$d","rank":"deprecated","value":{"type":"value","content":"Q30101519"},"qualifiers":[]}
        ]}}"#;
    const POSITIONS: &str = r#"{"entities":{
      "Q110964267":{"claims":{"P31":[{"mainsnak":{"datavalue":{"value":{"id":"Q294414"}}}}]}},
      "Q955006":{"claims":{"P31":[{"mainsnak":{"datavalue":{"value":{"id":"Q4164871"}}}}],
                           "P279":[{"mainsnak":{"datavalue":{"value":{"id":"Q48352"}}}}]}},
      "Q484876":{"claims":{"P31":[{"mainsnak":{"datavalue":{"value":{"id":"Q28640"}}}}]}}
    },"success":1}"#;

    #[test]
    fn a_public_office_held_marks_the_person_politically_exposed_current_and_former() {
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(crate::test_support::json_ok(OFFICE_HOLDER)),
            Ok(crate::test_support::json_ok(LABELS)),
            Ok(crate::test_support::json_ok(POSITIONS)),
        ]);
        let report = lookup(&transport, "Q46", "scan-wd", 1).expect("lookup");
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 3, "item, labels, then one positions request");
        assert!(seen[2].url.contains("props=claims"), "{}", seen[2].url);
        assert!(
            !seen[2].url.contains("Q30101519"),
            "a deprecated position is not looked up"
        );
        let person = entity(&report, &EntityKind::Person, "Example Ruler");
        assert!(person.tags.iter().any(|t| t == "politically-exposed"));
        let evidence = item_evidence_of(&report);
        let offices: Vec<&str> = evidence.attr_values("public_office").collect();
        assert_eq!(offices, ["Q110964267 (current)", "Q955006 (former)"]);
        assert!(evidence.attributes["politically_exposed"].starts_with("yes: 2 of 3"));
    }

    #[test]
    fn a_corporate_role_alone_is_never_a_public_office_and_a_failure_changes_nothing() {
        let ceo = r#"{"type":"item","id":"Q47","labels":{"en":"Example Executive"},
          "statements":{"P31":[{"value":{"type":"value","content":"Q5"}}],
          "P39":[{"rank":"normal","value":{"type":"value","content":"Q484876"},"qualifiers":[]}]}}"#;
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(crate::test_support::json_ok(ceo)),
            Ok(crate::test_support::json_ok(LABELS)),
            Ok(crate::test_support::json_ok(POSITIONS)),
        ]);
        let report = lookup(&transport, "Q47", "scan-wd", 1).expect("lookup");
        let person = entity(&report, &EntityKind::Person, "Example Executive");
        assert!(!person.tags.iter().any(|t| t == "politically-exposed"));
        let evidence = item_evidence_of(&report);
        assert!(!evidence.attributes.contains_key("politically_exposed"));
        assert_eq!(
            evidence
                .attributes
                .get("public_office_checked")
                .map(String::as_str),
            Some("1 positions held (P39), none typed as a public office")
        );

        // The positions request fails: the findings stand, the reason is kept, nothing is claimed.
        let transport = crate::test_support::ScriptedTransport::new(vec![
            Ok(crate::test_support::json_ok(OFFICE_HOLDER)),
            Ok(crate::test_support::json_ok(LABELS)),
        ]);
        let report = lookup(&transport, "Q46", "scan-wd", 1).expect("lookup");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let person = entity(&report, &EntityKind::Person, "Example Ruler");
        assert!(!person.tags.iter().any(|t| t == "politically-exposed"));
        let evidence = item_evidence_of(&report);
        assert!(
            evidence
                .attributes
                .contains_key("public_office_unavailable")
        );
        assert!(!evidence.attributes.contains_key("public_office_checked"));
    }

    fn item_evidence_of(report: &Report) -> &Evidence {
        report
            .entities
            .iter()
            .flat_map(|e| &e.evidence)
            .find(|ev| ev.attributes.contains_key("claim"))
            .expect("item evidence")
    }
}
