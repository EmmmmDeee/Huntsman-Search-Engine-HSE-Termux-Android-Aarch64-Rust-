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

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport, percent_encode_unreserved};
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

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn configured_base() -> Result<String, Error> {
    match crate::environment::wikidata_base_url() {
        Ok(Some(base)) if valid_base(&base) => Ok(base),
        Ok(None) => Ok(PUBLIC_BASE.to_owned()),
        Ok(Some(_)) | Err(_) => Err(Error::Invalid(format!(
            "{BASE_URL_ENV} must be an HTTPS origin with a qualified hostname and no path, userinfo, query or fragment"
        ))),
    }
}

/// Reject userinfo, query, fragments, paths and non-HTTPS schemes before the guarded transport
/// sees a replacement endpoint. DNS-based public-egress checks still apply to resolved addresses.
fn valid_base(base: &str) -> bool {
    let Some(authority) = base.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty() || authority.len() > 253 || authority.contains(['/', '?', '#', '@']) {
        return false;
    }
    let host = authority.split(':').next().unwrap_or(authority);
    host.rsplit_once('.').is_some_and(|(_, suffix)| {
        suffix.len() >= 2 && suffix.bytes().all(|c| c.is_ascii_alphabetic())
    })
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
    #[serde(default)]
    search: Vec<SearchHit>,
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
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
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
            Resolved::None(outcome) => return Ok(miss(outcome)),
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
    Ok(interpret(&fetched, &qid, search_label.as_deref(), scan_id, now_unix).unwrap_or_else(miss))
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
    match search
        .search
        .into_iter()
        .find(|hit| !hit.id.trim().is_empty())
    {
        Some(hit) => Ok(Resolved::Item {
            qid: hit.id,
            label: hit.label.or(hit.description),
        }),
        None => Ok(Resolved::None(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status),
        )),
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
/// no qualifiers. Qualifiers can restrict time, jurisdiction, or applicability; without interpreting
/// them, suppressing the pivot is safer than presenting it as current. **Pure.**
fn eligible_for_pivot(statement: &Value) -> bool {
    matches!(
        statement.get("rank").and_then(Value::as_str),
        None | Some("normal" | "preferred")
    ) && statement.get("qualifiers").is_none_or(|qualifiers| {
        qualifiers
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    })
}

/// Only unqualified, non-deprecated values are used for classification, friendly current-value
/// attributes and automatic pivots. The complete bounded statement record is kept separately.
fn values(statements: Option<&serde_json::Map<String, Value>>, pid: &str) -> Vec<String> {
    statements
        .and_then(|map| map.get(pid))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter(|statement| eligible_for_pivot(statement))
                .filter_map(|st| rendered_value(st.get("value")?))
                .take(MAX_CLAIM_VALUES)
                .collect()
        })
        .unwrap_or_default()
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
    let instance_of = values(statements, INSTANCE_OF);
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
        let found = values(statements, property.pid);
        for value in &found {
            evidence = evidence.with_attr(property.attr, value.clone());
            collect_pivots(property, value, &label, qid, &mut pivots);
        }
    }

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
            let host = crate::value_syntax::host_only(value);
            if let Some(domain) = crate::canonical::canonical_domain(host) {
                pivots.push((EntityKind::Domain, domain, "Official website".to_owned()));
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
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::OneResponse;

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

    fn report_of(body: &str, query: &str) -> Report {
        match lookup(&OneResponse::json(200, body), query, "scan-wd", 1) {
            Ok(report) => report,
            Err(error) => panic!("{error}"),
        }
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
}
