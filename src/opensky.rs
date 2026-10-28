//! Keyless public aircraft observations around a point through the `OpenSky` Network.
//!
//! One bounded, anonymous GET to `OpenSky`'s `/api/states/all` asks for the state vectors its
//! receivers last reported inside a box of [`HALF_SPAN_DEG`] degrees each side of a point (one
//! square degree or less, the cheapest query: one of the 400 credits an anonymous address gets
//! a day). Each aircraft with a reported position becomes a device-identifier entity for its
//! ICAO 24-bit transponder address, nearest first, at most [`MAX_AIRCRAFT`], carrying its
//! callsign, the registration country `OpenSky` infers from the address, the position and the
//! time it was reported, altitude, ground state, speed, track, vertical rate, squawk, how the
//! position was obtained and its distance from the point.
//!
//! An investigator uses it to know what was flying over or parked near a place at a moment: to
//! check a photo or a claim against the traffic overhead, or to find the transponder to follow.
//! A transponder address identifies an airframe's transponder, not anyone aboard; a state vector
//! is what receivers reported at its own time, not where the aircraft is now; and an aircraft
//! seen near a point is not evidence it had anything to do with it. `OpenSky`'s data is for
//! non-commercial research and education under its terms of use.

use std::fmt::Write as _;

use serde_json::Value;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "opensky";
const STATES: &str = "https://opensky-network.org/api/states/all";
/// Degrees of latitude and longitude searched each side of the point: a box of at most one
/// square degree, which `OpenSky` charges one credit.
pub const HALF_SPAN_DEG: f64 = 0.5;
/// The most aircraft kept, nearest first.
pub const MAX_AIRCRAFT: usize = 50;
/// The largest answer read; a state vector is about 150 bytes.
const MAX_STATES_BYTES: usize = 512 * 1024;
/// Confidence that the receivers reported this transponder at this position and time.
const STATE_CONFIDENCE: f64 = 0.85;
/// The fields of a state vector before the optional aircraft category.
const STATE_FIELDS: usize = 17;

/// What an aircraft observation never establishes.
pub const AIRCRAFT_LIMIT: &str = "A state vector OpenSky's receivers reported at its stated time: the transponder address identifies an airframe, not anyone aboard, the position is not where the aircraft is now, and being near the point is not involvement with it. OpenSky data is for non-commercial research and education.";

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// The query box `[lamin, lomin, lamax, lomax]` around a point, clamped to WGS 84 bounds; a box
/// at a pole or the antimeridian is cut short rather than wrapped. **Pure.**
#[must_use]
pub fn bounding_box(lat: f64, lon: f64) -> [f64; 4] {
    [
        (lat - HALF_SPAN_DEG).max(-90.0),
        (lon - HALF_SPAN_DEG).max(-180.0),
        (lat + HALF_SPAN_DEG).min(90.0),
        (lon + HALF_SPAN_DEG).min(180.0),
    ]
}

/// The anonymous query URL for the box around a point. **Pure.**
#[must_use]
pub fn url(lat: f64, lon: f64) -> String {
    let [south, west, north, east] = bounding_box(lat, lon);
    let mut url = STATES.to_owned();
    for (name, value) in [
        ("lamin", south),
        ("lomin", west),
        ("lamax", north),
        ("lomax", east),
    ] {
        url = append_query_param(&url, name, &format!("{value:.4}"));
    }
    url
}

/// Ask `OpenSky` which aircraft its receivers last reported around `lat`,`lon`.
///
/// # Errors
/// A network-boundary error when the guarded fetch refuses the URL.
pub fn observe<T: Transport + ?Sized>(
    transport: &T,
    lat: f64,
    lon: f64,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let fetched = fetch(
        transport,
        Request::get(url(lat, lon))
            .header("accept", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    Ok(
        interpret(&fetched, (lat, lon), scan_id, now_unix).unwrap_or_else(|outcome| Report {
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
    point: (f64, f64),
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "OpenSky states")?;
    answer(fetched, "OpenSky states")?;
    if response.body.len() > MAX_STATES_BYTES {
        return Err(failed(
            SourceOutcomeKind::ParserDrift,
            now_unix,
            response.status,
            "OpenSky states answer exceeds 512 KiB",
        ));
    }
    let document: Value = decode_json(response, SOURCE, now_unix, "OpenSky states")?;
    parse(&document, point, scan_id, now_unix, response.status)
}

/// One aircraft's reported state, validated.
#[derive(Debug, Clone, PartialEq)]
struct State {
    icao24: String,
    callsign: Option<String>,
    country: Option<String>,
    position_unix: i64,
    last_contact_unix: i64,
    lat: f64,
    lon: f64,
    baro_altitude_m: Option<f64>,
    geo_altitude_m: Option<f64>,
    on_ground: Option<bool>,
    velocity_m_s: Option<f64>,
    track_deg: Option<f64>,
    vertical_rate_m_s: Option<f64>,
    squawk: Option<String>,
    position_source: Option<&'static str>,
    distance_m: f64,
}

/// A finite number, or `None` for null or anything else.
fn number(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| n.is_finite())
}

/// A non-empty trimmed string.
fn text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Whether `address` is an ICAO 24-bit address as `OpenSky` writes it: six lowercase hex digits.
fn icao24(address: &str) -> bool {
    address.len() == 6
        && address
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One state-vector row as a [`State`], or `None` when it lacks a valid address, a reported
/// position inside WGS 84 bounds or its timestamps. **Pure.**
fn state(row: &Value, point: (f64, f64)) -> Option<State> {
    let row = row.as_array().filter(|row| row.len() >= STATE_FIELDS)?;
    let address = row[0].as_str().filter(|address| icao24(address))?;
    let (lat, lon) = (number(&row[6])?, number(&row[5])?);
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    let position_unix = row[3].as_i64().filter(|t| *t > 0)?;
    let last_contact_unix = row[4].as_i64().filter(|t| *t > 0)?;
    Some(State {
        icao24: address.to_owned(),
        callsign: text(&row[1]),
        country: text(&row[2]),
        position_unix,
        last_contact_unix,
        lat,
        lon,
        baro_altitude_m: number(&row[7]),
        geo_altitude_m: number(&row[13]),
        on_ground: row[8].as_bool(),
        velocity_m_s: number(&row[9]),
        track_deg: number(&row[10]),
        vertical_rate_m_s: number(&row[11]),
        squawk: text(&row[14])
            .filter(|code| code.len() == 4 && code.bytes().all(|b| (b'0'..=b'7').contains(&b))),
        position_source: match row[16].as_u64() {
            Some(0) => Some("ADS-B"),
            Some(1) => Some("ASTERIX"),
            Some(2) => Some("MLAT"),
            Some(3) => Some("FLARM"),
            _ => None,
        },
        distance_m: crate::geohash::haversine_km(point.0, point.1, lat, lon) * 1000.0,
    })
}

/// The aircraft of one answer, nearest the point first. A document without a `states` field
/// is schema drift; `states: null` is the documented answer for no aircraft, a valid zero; a
/// row without a usable address, position or time is skipped and counted. **Pure.**
fn parse(
    document: &Value,
    point: (f64, f64),
    scan_id: &str,
    now_unix: u64,
    status: u16,
) -> Result<Report, SourceExecutionOutcome> {
    let (Some(answered), Some(vectors)) = (
        document.get("time").and_then(Value::as_i64),
        document.get("states"),
    ) else {
        return Err(failed(
            SourceOutcomeKind::SchemaDrift,
            now_unix,
            status,
            "OpenSky answer lacks its time or states",
        ));
    };
    let rows: &[Value] = match vectors {
        Value::Null => &[],
        Value::Array(rows) => rows,
        _ => {
            return Err(failed(
                SourceOutcomeKind::SchemaDrift,
                now_unix,
                status,
                "OpenSky states is not an array",
            ));
        }
    };
    let mut aircraft: Vec<State> = rows.iter().filter_map(|row| state(row, point)).collect();
    let skipped = rows.len() - aircraft.len();
    aircraft.sort_by(|a, b| {
        a.distance_m
            .total_cmp(&b.distance_m)
            .then_with(|| a.icao24.cmp(&b.icao24))
    });
    let seen = aircraft.len();
    aircraft.truncate(MAX_AIRCRAFT);
    if aircraft.is_empty() {
        let mut outcome =
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(status);
        if skipped != 0 {
            outcome = outcome.with_detail(format!(
                "{skipped} state vector(s) lacked an address, position or time"
            ));
        }
        return Ok(Report {
            entities: Vec::new(),
            outcome,
        });
    }
    let mut entities = Vec::new();
    for state in &aircraft {
        push_entity(
            &mut entities,
            EntityKind::DeviceId,
            &format!("icao24:{}", state.icao24),
            STATE_CONFIDENCE,
            scan_id,
            evidence(state, answered, scan_id),
            &[SOURCE, "aircraft"],
        );
    }
    merge_by_uid(&mut entities);
    let mut detail =
        format!("{seen} aircraft reported within {HALF_SPAN_DEG} degrees of the point");
    if seen > MAX_AIRCRAFT {
        let _ = write!(detail, "; the nearest {MAX_AIRCRAFT} kept");
    }
    if skipped != 0 {
        let _ = write!(
            detail,
            "; {skipped} state vector(s) lacked an address, position or time"
        );
    }
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SOURCE, now_unix, entities.len())
            .with_http_status(status)
            .with_detail(detail),
        entities,
    })
}

/// The evidence for one aircraft: everything the receivers reported, with its own times.
fn evidence(state: &State, answered: i64, scan_id: &str) -> Evidence {
    let utc = crate::timefmt::format_unix;
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!(
            "transponder {} reported {:.1} km from the point at {} by OpenSky receivers{}. {AIRCRAFT_LIMIT}",
            state.icao24,
            state.distance_m / 1000.0,
            utc(state.position_unix),
            state
                .callsign
                .as_deref()
                .map(|callsign| format!(" as {callsign}"))
                .unwrap_or_default()
        ),
    )
    .with_attr("dataset", "OpenSky Network state vectors")
    .with_attr("icao24", &state.icao24)
    .with_attr("position_time_utc", utc(state.position_unix))
    .with_attr("last_contact_utc", utc(state.last_contact_unix))
    .with_attr("answer_time_utc", utc(answered))
    .with_attr("latitude", format!("{:.5}", state.lat))
    .with_attr("longitude", format!("{:.5}", state.lon))
    .with_attr("distance_from_point_m", format!("{:.0}", state.distance_m))
    .with_attr("limit", AIRCRAFT_LIMIT);
    let optional = [
        ("on_ground", state.on_ground.map(|v| v.to_string())),
        ("callsign", state.callsign.clone()),
        ("registration_country_inferred", state.country.clone()),
        (
            "baro_altitude_m",
            state.baro_altitude_m.map(|v| format!("{v:.0}")),
        ),
        (
            "geo_altitude_m",
            state.geo_altitude_m.map(|v| format!("{v:.0}")),
        ),
        (
            "velocity_m_s",
            state.velocity_m_s.map(|v| format!("{v:.1}")),
        ),
        ("true_track_deg", state.track_deg.map(|v| format!("{v:.1}"))),
        (
            "vertical_rate_m_s",
            state.vertical_rate_m_s.map(|v| format!("{v:.1}")),
        ),
        ("squawk", state.squawk.clone()),
        ("position_source", state.position_source.map(str::to_owned)),
    ];
    for (name, value) in optional {
        if let Some(value) = value {
            evidence = evidence.with_attr(name, value);
        }
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::ScriptedTransport;

    const NOW: u64 = 1_793_213_400;
    /// A point at the centre of a fictional test box.
    const POINT: (f64, f64) = (-33.9, 151.2);

    fn row(address: &str, lat: f64, lon: f64, callsign: &str) -> String {
        format!(
            r#"["{address}","{callsign}","Australia",1793213394,1793213395,{lon},{lat},403.86,false,64.75,107.57,0,null,487.68,"0366",false,0]"#
        )
    }

    fn answer_of(rows: &[String]) -> String {
        format!(r#"{{"time":1793213400,"states":[{}]}}"#, rows.join(","))
    }

    fn ok(body: &str) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn the_box_is_one_square_degree_clamped_at_the_poles_and_antimeridian() {
        assert_eq!(bounding_box(-33.9, 151.2), [-34.4, 150.7, -33.4, 151.7]);
        assert_eq!(bounding_box(89.8, 179.9), [89.3, 179.4, 90.0, 180.0]);
        assert_eq!(bounding_box(-89.9, -179.8), [-90.0, -180.0, -89.4, -179.3]);
        let url = url(-33.9, 151.2);
        assert!(url.starts_with(STATES), "{url}");
        for part in [
            "lamin=-34.4000",
            "lomin=150.7000",
            "lamax=-33.4000",
            "lomax=151.7000",
        ] {
            assert!(url.contains(part), "{url}");
        }
    }

    #[test]
    fn aircraft_are_nearest_first_with_their_own_times_and_the_limit_stated() {
        let body = answer_of(&[
            row("7c3b43", -33.8154, 151.0697, "LZP     "),
            row("7cf495", -33.9010, 151.2010, "        "),
        ]);
        let report = parse(
            &serde_json::from_str(&body).unwrap(),
            POINT,
            "scan",
            NOW,
            200,
        )
        .unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let values: Vec<&str> = report.entities.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(values, ["icao24:7cf495", "icao24:7c3b43"]);
        let far = &report.entities[1];
        assert_eq!(far.kind, EntityKind::DeviceId);
        assert!(far.has_tag("aircraft") && far.has_tag(SOURCE));
        let ev = &far.evidence[0];
        let attr = |name: &str| ev.attr_values(name).next().unwrap_or_default().to_owned();
        assert_eq!(attr("callsign"), "LZP");
        assert_eq!(attr("position_time_utc"), "2026-10-28T18:49:54Z");
        assert_eq!(attr("squawk"), "0366");
        assert_eq!(attr("position_source"), "ADS-B");
        assert_eq!(attr("registration_country_inferred"), "Australia");
        assert!(ev.summary.contains("not anyone aboard"));
        // A blank callsign is absent, not an empty value.
        assert!(
            report.entities[0].evidence[0]
                .attr_values("callsign")
                .next()
                .is_none()
        );
    }

    #[test]
    fn rows_without_address_position_or_time_are_skipped_and_null_states_is_a_valid_zero() {
        let body = answer_of(&[
            row("7c3b43", -33.8, 151.0, "A"),
            row("7C3B4X", -33.8, 151.0, "B"),
            row("7c3b44", -33.8, 151.0, "C").replace("151,-33.8", "null,null"),
            r#"["7c3b45","D","Australia",null,1793213395,151.0,-33.8,1,false,1,1,0,null,1,null,false,0]"#.to_owned(),
            r#"["7c3b46","E"]"#.to_owned(),
            row("7c3b47", -95.0, 151.0, "F"),
        ]);
        let report = parse(
            &serde_json::from_str(&body).unwrap(),
            POINT,
            "scan",
            NOW,
            200,
        )
        .unwrap();
        assert_eq!(report.entities.len(), 1, "{:?}", report.entities);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("5 state vector(s) lacked")),
            "{:?}",
            report.outcome.detail
        );
        let empty = parse(
            &serde_json::from_str(r#"{"time":1793213400,"states":null}"#).unwrap(),
            POINT,
            "scan",
            NOW,
            200,
        )
        .unwrap();
        assert_eq!(empty.outcome.kind, SourceOutcomeKind::ValidZero);
        for drift in [r#"{"states":[]}"#, r#"{"time":1,"states":{}}"#, r"[]"] {
            assert!(
                parse(
                    &serde_json::from_str(drift).unwrap(),
                    POINT,
                    "scan",
                    NOW,
                    200
                )
                .is_err(),
                "{drift}"
            );
        }
    }

    #[test]
    fn at_most_fifty_aircraft_are_kept_and_the_rest_are_counted() {
        let rows: Vec<String> = (0..60)
            .map(|i| {
                row(
                    &format!("7c{i:04x}"),
                    -33.9 + f64::from(i) * 0.001,
                    151.2,
                    "X",
                )
            })
            .collect();
        let report = parse(
            &serde_json::from_str(&answer_of(&rows)).unwrap(),
            POINT,
            "scan",
            NOW,
            200,
        )
        .unwrap();
        assert_eq!(report.entities.len(), MAX_AIRCRAFT);
        assert_eq!(report.entities[0].value, "icao24:7c0000");
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("60 aircraft") && d.contains("nearest 50 kept")),
            "{:?}",
            report.outcome.detail
        );
    }

    #[test]
    fn unknown_ground_state_is_not_misreported_as_airborne() {
        let original = row("7c3b43", -33.81, 151.07, "LZP");
        let unknown = original.replace(",false,64.75,", ",null,64.75,");
        assert_ne!(original, unknown);
        let report = parse(
            &serde_json::from_str(&answer_of(&[unknown])).unwrap(),
            POINT,
            "scan",
            NOW,
            200,
        )
        .unwrap();
        assert_eq!(report.entities.len(), 1);
        assert!(
            report.entities[0].evidence[0]
                .attr_values("on_ground")
                .next()
                .is_none(),
            "unknown is not a reported false"
        );
        let known = parse(
            &serde_json::from_str(&answer_of(&[original])).unwrap(),
            POINT,
            "scan",
            NOW,
            200,
        )
        .unwrap();
        assert_eq!(
            known.entities[0].evidence[0].attr_values("on_ground").next(),
            Some("false")
        );
    }

    #[test]
    fn one_anonymous_get_to_the_states_endpoint() {
        let transport = ScriptedTransport::new(vec![Ok(ok(&answer_of(&[row(
            "7c3b43", -33.81, 151.07, "LZP",
        )])))]);
        let report = observe(&transport, POINT.0, POINT.1, "scan", NOW).unwrap();
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let seen = transport.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].url, url(POINT.0, POINT.1));
        assert!(seen[0].header_value("authorization").is_none());
    }
}
