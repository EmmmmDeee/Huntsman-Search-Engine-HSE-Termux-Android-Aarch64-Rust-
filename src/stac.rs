//! Keyless satellite-imagery catalogue discovery through a public STAC API.
//!
//! One bounded POST to Element 84's Earth Search (`/v1/search`, the `SpatioTemporal` Asset
//! Catalog item search over AWS open data) asks which Sentinel-2 and Landsat scenes cover a
//! point in the last [`WINDOW_DAYS`] days, newest first, at most [`MAX_ITEMS`]. Each scene
//! becomes a URL entity for its catalogue record carrying its collection, platform,
//! acquisition time, cloud cover, scene footprint and, when https, its thumbnail. An
//! investigator uses it to know what imagery exists of a place and when it was taken, to check a
//! photo's claimed date against a clear-sky pass, or to find the scene to examine. A scene is
//! a catalogue record: it is not an interpretation of what the imagery shows, its acquisition
//! time is when the satellite passed, not when it was published, and its footprint is an area
//! of tens of kilometres, not a point. Nothing is downloaded beyond the catalogue answer.

use serde_json::{Value, json};

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "stac";
const SEARCH: &str = "https://earth-search.aws.element84.com/v1/search";
/// The only origin a catalogue record or thumbnail link may name to become evidence.
const RECORD_PREFIX: &str = "https://earth-search.aws.element84.com/v1/collections/";
/// The collections searched: Sentinel-2 surface reflectance and Landsat Collection 2 Level-2.
pub const COLLECTIONS: [&str; 2] = ["sentinel-2-l2a", "landsat-c2-l2"];
/// The most scenes asked for and kept.
pub const MAX_ITEMS: usize = 10;
/// How far back the search reaches.
pub const WINDOW_DAYS: u64 = 90;
/// The largest catalogue answer read; a scene record is about 20 KiB.
const MAX_SEARCH_BYTES: usize = 1024 * 1024;
/// Confidence of a scene record the catalogue returned for the point.
const SCENE_CONFIDENCE: f64 = 0.9;

/// What a scene never establishes.
pub const SCENE_LIMIT: &str = "A catalogue record of a satellite pass: it does not say what the imagery shows, its acquisition time is not a publication time, and its footprint is an area of tens of kilometres, not the point searched.";

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// The item-search body for a point over the last [`WINDOW_DAYS`] days ending at `now_unix`.
/// A `GeoJSON` position is longitude first (RFC 7946). **Pure.**
#[must_use]
pub fn search_body(lat: f64, lon: f64, now_unix: u64) -> Value {
    let to = crate::timefmt::format_unix(i64::try_from(now_unix).unwrap_or(i64::MAX));
    let from = crate::timefmt::format_unix(
        i64::try_from(now_unix.saturating_sub(WINDOW_DAYS * 86_400)).unwrap_or(0),
    );
    json!({
        "collections": COLLECTIONS,
        "intersects": {"type": "Point", "coordinates": [lon, lat]},
        "datetime": format!("{from}/{to}"),
        "limit": MAX_ITEMS,
        "sortby": [{"field": "properties.datetime", "direction": "desc"}],
    })
}

/// Search the catalogue for scenes covering `lat`,`lon`.
///
/// # Errors
/// A network-boundary error when the guarded fetch refuses the URL.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    lat: f64,
    lon: f64,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let body = search_body(lat, lon, now_unix).to_string().into_bytes();
    let fetched = fetch(
        transport,
        Request::post(SEARCH, body)
            .header("content-type", "application/json")
            .header("accept", "application/geo+json, application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    Ok(
        interpret(&fetched, scan_id, now_unix).unwrap_or_else(|outcome| Report {
            entities: Vec::new(),
            outcome,
        }),
    )
}

fn failed(
    kind: SourceOutcomeKind,
    now_unix: u64,
    status: u16,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(SOURCE, now_unix, kind, Some(status), detail)
}

fn interpret(
    fetched: &Fetched,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "STAC search")?;
    answer(fetched, "STAC search")?;
    if response.body.len() > MAX_SEARCH_BYTES {
        return Err(failed(
            SourceOutcomeKind::ParserDrift,
            now_unix,
            response.status,
            "STAC search answer exceeds 1 MiB",
        ));
    }
    let document: Value = decode_json(response, SOURCE, now_unix, "STAC search")?;
    parse(&document, scan_id, now_unix, response.status)
}

/// A finite number from a JSON value.
fn number(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| n.is_finite())
}

/// A scene footprint `[west, south, east, north]` within WGS 84 bounds. **Pure.**
fn footprint(feature: &Value) -> Option<[f64; 4]> {
    let bbox = feature.get("bbox")?.as_array()?;
    if bbox.len() != 4 {
        return None;
    }
    let [west, south, east, north] = [
        number(&bbox[0])?,
        number(&bbox[1])?,
        number(&bbox[2])?,
        number(&bbox[3])?,
    ];
    let lon = -180.0..=180.0;
    let lat = -90.0..=90.0;
    (lon.contains(&west)
        && lon.contains(&east)
        && lat.contains(&south)
        && lat.contains(&north)
        && south <= north)
        .then_some([west, south, east, north])
}

/// The scenes of one search answer. A document that is not a feature collection is schema
/// drift; a feature without an id, collection, acquisition time, footprint or a catalogue
/// record link is skipped and counted. **Pure.**
fn parse(
    document: &Value,
    scan_id: &str,
    now_unix: u64,
    status: u16,
) -> Result<Report, SourceExecutionOutcome> {
    let (Some("FeatureCollection"), Some(Value::Array(features))) = (
        document.get("type").and_then(Value::as_str),
        document.get("features"),
    ) else {
        return Err(failed(
            SourceOutcomeKind::SchemaDrift,
            now_unix,
            status,
            "STAC search answer is not a GeoJSON FeatureCollection",
        ));
    };
    let mut entities = Vec::new();
    let mut skipped = 0usize;
    for feature in features.iter().take(MAX_ITEMS) {
        if !scene(feature, scan_id, &mut entities) {
            skipped += 1;
        }
    }
    merge_by_uid(&mut entities);
    let matched = document.get("numberMatched").and_then(Value::as_u64);
    let mut outcome = if entities.is_empty() && skipped == 0 {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
    } else if entities.is_empty() {
        failed(
            SourceOutcomeKind::SemanticDrift,
            now_unix,
            status,
            "STAC search returned scenes but none had a usable record",
        )
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, entities.len())
    }
    .with_http_status(status);
    let mut notes = Vec::new();
    if let Some(matched) = matched.filter(|matched| *matched > entities.len() as u64) {
        notes.push(format!(
            "{matched} scenes matched in the last {WINDOW_DAYS} days; the newest {} are kept",
            entities.len()
        ));
    }
    if skipped != 0 {
        notes.push(format!(
            "{skipped} scene(s) lacked a usable record and were skipped"
        ));
    }
    if !notes.is_empty() {
        outcome = outcome.with_detail(notes.join("; "));
    }
    Ok(Report { entities, outcome })
}

/// A trimmed, non-empty string value.
fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// One scene as a URL entity for its catalogue record; false when it is unusable.
fn scene(feature: &Value, scan_id: &str, entities: &mut Vec<Entity>) -> bool {
    let properties = feature.get("properties");
    let (Some(id), Some(collection), Some(acquired), Some(bbox)) = (
        text(feature.get("id")),
        text(feature.get("collection")),
        text(properties.and_then(|p| p.get("datetime"))),
        footprint(feature),
    ) else {
        return false;
    };
    let record = feature
        .get("links")
        .and_then(Value::as_array)
        .and_then(|links| {
            links
                .iter()
                .find(|link| link.get("rel").and_then(Value::as_str) == Some("self"))
        })
        .and_then(|link| text(link.get("href")))
        .filter(|href| href.starts_with(RECORD_PREFIX) && !href.contains(char::is_whitespace));
    let Some(record) = record else {
        return false;
    };
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!("{collection} scene {id} acquired {acquired} covers the point; {SCENE_LIMIT}"),
    )
    .with_attr("dataset", "Earth Search STAC (AWS open data)")
    .with_attr("collection", collection)
    .with_attr("scene_id", id)
    .with_attr("acquired_utc", acquired)
    .with_attr(
        "footprint_bbox",
        format!("{},{},{},{}", bbox[0], bbox[1], bbox[2], bbox[3]),
    );
    if let Some(platform) = text(properties.and_then(|p| p.get("platform"))) {
        evidence = evidence.with_attr("platform", platform);
    }
    if let Some(cloud) = properties
        .and_then(|p| p.get("eo:cloud_cover"))
        .and_then(number)
    {
        evidence = evidence.with_attr("cloud_cover_percent", format!("{cloud:.1}"));
    }
    if let Some(thumbnail) = feature
        .pointer("/assets/thumbnail/href")
        .and_then(Value::as_str)
        .filter(|href| href.starts_with("https://") && !href.contains(char::is_whitespace))
    {
        evidence = evidence.with_attr("thumbnail_url", thumbnail);
    }
    push_entity(
        entities,
        EntityKind::Url,
        record,
        SCENE_CONFIDENCE,
        scan_id,
        evidence,
        &[SOURCE, "satellite_scene"],
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ScriptedTransport;

    const NOW: u64 = 1_793_145_600; // 2026-10-28T00:00:00Z

    fn feature(id: &str, datetime: &str, cloud: f64) -> String {
        format!(
            r#"{{"type":"Feature","id":"{id}","collection":"sentinel-2-l2a","bbox":[150.82,-34.42,151.98,-33.42],
            "properties":{{"datetime":"{datetime}","eo:cloud_cover":{cloud},"platform":"sentinel-2a"}},
            "links":[{{"rel":"self","href":"https://earth-search.aws.element84.com/v1/collections/sentinel-2-l2a/items/{id}"}},{{"rel":"collection","href":"https://earth-search.aws.element84.com/v1/collections/sentinel-2-l2a"}}],
            "assets":{{"thumbnail":{{"href":"https://sentinel-cogs.s3.us-west-2.amazonaws.com/{id}/thumbnail.jpg"}}}}}}"#
        )
    }

    fn collection(features: &[String], matched: u64) -> String {
        format!(
            r#"{{"type":"FeatureCollection","numberMatched":{matched},"numberReturned":{},"features":[{}]}}"#,
            features.len(),
            features.join(",")
        )
    }

    #[test]
    fn the_search_asks_both_collections_for_the_point_lon_first_newest_first() {
        let body = search_body(-33.8688, 151.2093, NOW);
        assert_eq!(
            body["intersects"]["coordinates"],
            json!([151.2093, -33.8688])
        );
        assert_eq!(body["collections"], json!(COLLECTIONS));
        assert_eq!(
            body["datetime"],
            "2026-07-30T00:00:00Z/2026-10-28T00:00:00Z"
        );
        assert_eq!(body["limit"], MAX_ITEMS);
        assert_eq!(body["sortby"][0]["direction"], "desc");
    }

    #[test]
    fn each_scene_becomes_a_catalogue_record_with_its_pass_and_footprint() {
        let answer = collection(
            &[
                feature(
                    "S2A_56HLH_20261027_0_L2A",
                    "2026-10-27T00:06:14.773000Z",
                    39.512_399,
                ),
                feature(
                    "S2C_56HLH_20261025_0_L2A",
                    "2026-10-25T00:06:07.192000Z",
                    7.8,
                ),
            ],
            63,
        );
        let transport = ScriptedTransport::new(vec![Ok(crate::test_support::json_ok(&answer))]);
        let report = search(&transport, -33.8688, 151.2093, "scan", NOW).unwrap();
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].url, SEARCH);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(report.entities.len(), 2);
        let scene = &report.entities[0];
        assert_eq!(scene.kind, EntityKind::Url);
        assert!(scene.value.starts_with(RECORD_PREFIX), "{}", scene.value);
        assert!(scene.has_tag("satellite_scene"));
        let attr = |key: &str| {
            scene.evidence[0]
                .attributes
                .get(key)
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(attr("acquired_utc"), "2026-10-27T00:06:14.773000Z");
        assert_eq!(attr("cloud_cover_percent"), "39.5");
        assert_eq!(attr("platform"), "sentinel-2a");
        assert_eq!(attr("footprint_bbox"), "150.82,-34.42,151.98,-33.42");
        assert!(attr("thumbnail_url").starts_with("https://"));
        assert!(scene.evidence[0].summary.contains("not the point searched"));
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("63 scenes matched")),
            "{:?}",
            report.outcome.detail
        );
    }

    #[test]
    fn unusable_scenes_are_skipped_and_foreign_links_never_become_evidence() {
        let foreign = feature("X", "2026-10-01T00:00:00Z", 1.0).replace(
            "https://earth-search.aws.element84.com/v1/collections/sentinel-2-l2a/items/X",
            "https://evil.example/x",
        );
        let bad_bbox = feature("Y", "2026-10-01T00:00:00Z", 1.0)
            .replace("[150.82,-34.42,151.98,-33.42]", "[0,95,1,96]");
        // South above north is not an area; west above east is legal (antimeridian).
        let inverted = feature("V", "2026-10-01T00:00:00Z", 1.0).replace(
            "[150.82,-34.42,151.98,-33.42]",
            "[150.82,-33.42,151.98,-34.42]",
        );
        let no_time = feature("Z", "", 1.0);
        let good = feature("G", "2026-10-02T00:00:00Z", 1.0);
        let answer = collection(&[foreign, bad_bbox, inverted, no_time, good], 5);
        let report = parse(&serde_json::from_str(&answer).unwrap(), "scan", NOW, 200).unwrap();
        assert_eq!(report.entities.len(), 1);
        assert!(!format!("{report:?}").contains("evil.example"));
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("4 scene(s) lacked")),
            "{:?}",
            report.outcome.detail
        );
    }

    #[test]
    fn an_empty_window_is_a_valid_zero_and_another_document_is_drift() {
        let empty = parse(
            &serde_json::from_str(&collection(&[], 0)).unwrap(),
            "scan",
            NOW,
            200,
        )
        .unwrap();
        assert_eq!(empty.outcome.kind, SourceOutcomeKind::ValidZero);
        let drift = parse(&json!({"type": "Feature"}), "scan", NOW, 200).unwrap_err();
        assert_eq!(drift.kind, SourceOutcomeKind::SchemaDrift);
    }
}
