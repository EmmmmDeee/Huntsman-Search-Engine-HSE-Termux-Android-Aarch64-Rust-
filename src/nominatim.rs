//! Keyless geocoding over OpenStreetMap's public Nominatim service.
//!
//! One lookup is one GET to Nominatim: a forward search turns a place name or street address into
//! the coordinates and full address of each match, and a reverse search turns a `lat,lon` point
//! into the address at that spot. Every match becomes a [`EntityKind::Coordinates`] entity for its
//! point and an [`EntityKind::Address`] entity for its written address, cross-referenced, and every
//! field Nominatim returns -- each separate address component included -- is kept as evidence, so no
//! part of the answer is dropped. This is the free, keyless geocoder; the keyed `WiGLE` leg carries
//! its own reverse-geocoded address for a network sighting, and this one needs no key.
//!
//! Public Nominatim allows at most one HTTP request per second across an application.
//! A bounded in-process cache avoids repeat queries, a shared lock serialises live
//! requests with a full second after each attempt, and the circuit breaker handles failures.
//! The HTTPS origin is switchable via HUNTSMAN_NOMINATIM_BASE_URL without recompiling.
//! Multi-process and multi-device traffic is NOT coordinated: aggregate use of OSMF's
//! public endpoint requires a single gateway or a separately operated service.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::canonical::canonical_coordinates;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, fetch, json_error_detail};
use crate::http::{DEFAULT_USER_AGENT, Request, Response, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const SOURCE: &str = "nominatim";
const PUBLIC_BASE: &str = "https://nominatim.openstreetmap.org";
/// HTTPS origin for an operator-managed Nominatim-compatible service.
/// When absent, the public OSMF endpoint is used subject to its usage policy.
pub const BASE_URL_ENV: &str = "HUNTSMAN_NOMINATIM_BASE_URL";

/// Reject userinfo, query, fragments, paths, non-HTTPS schemes and unqualified
/// hostnames before the guarded transport sees a replacement endpoint.
/// This does not replace DNS-based public-egress checks on resolved addresses.
fn valid_base(base: &str) -> bool {
    let Some(authority) = base.strip_prefix("https://") else {
        return false;
    };
    if authority.len() > 253 || authority.is_empty() {
        return false;
    }
    let (hostname, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if port.is_some_and(|port| {
        port.is_empty()
            || port.len() > 5
            || !port.bytes().all(|c| c.is_ascii_digit())
            || !port.parse::<u16>().is_ok_and(|number| number != 0)
    }) {
        return false;
    }
    if hostname.len() > 253 || !hostname.contains('.') || hostname.ends_with('.') {
        return false;
    }
    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }) && hostname.rsplit_once('.').is_some_and(|(_, suffix)| {
        suffix.len() >= 2 && suffix.bytes().all(|c| c.is_ascii_alphabetic())
    })
}

fn configured_base() -> Result<String, Error> {
    match std::env::var(BASE_URL_ENV) {
        Ok(base) if valid_base(&base) => Ok(base),
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => Err(Error::Invalid(format!(
            "{BASE_URL_ENV} must be an HTTPS origin with a qualified hostname and no path, userinfo, query or fragment"
        ))),
        Err(std::env::VarError::NotPresent) => Ok(PUBLIC_BASE.to_owned()),
    }
}

fn search_url_at(base: &str, query: &str) -> String {
    format!(
        "{base}/search?q={}&format=jsonv2&addressdetails=1&limit={RESULT_LIMIT}",
        percent_encode_unreserved(query)
    )
}

fn reverse_url_at(base: &str, lat: f64, lon: f64) -> String {
    format!("{base}/reverse?lat={lat}&lon={lon}&format=jsonv2&addressdetails=1")
}

/// Most matches one forward search keeps. Nominatim's own default is ten; a place that matches
/// more than this is too broad to be a finding.
const RESULT_LIMIT: usize = 10;
/// Hard cap on the verbatim provider response retained on each evidence record.
/// Reject oversized results rather than silently discarding source fields.
const MAX_NOMINATIM_RAW_JSON_BYTES: usize = 64 * 1024;

/// One immutable, bounded observation shared by all entities produced from
/// the same provider response.
struct RawObservation<'a> {
    body: &'a str,
    recorded_at_unix: u64,
}

const CACHE_LIMIT: usize = 64;
const MAX_CACHE_BODY: usize = MAX_NOMINATIM_RAW_JSON_BYTES;
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MIN_REQUEST_GAP: Duration = Duration::from_secs(1);

struct CachedResponse {
    response: Response,
    received: Instant,
    observed_at_unix: u64,
}

struct NominatimState {
    last_attempt_finished: Option<Instant>,
    cache: BTreeMap<String, CachedResponse>,
}

// One shared admission point for forward and reverse queries in this process.
// In particular, different callers must not create parallel public-service requests.
static NOMINATIM_STATE: Mutex<NominatimState> = Mutex::new(NominatimState {
    last_attempt_finished: None,
    cache: BTreeMap::new(),
});

/// Confidence that a geocoded match is the place the query meant. The service matched the query,
/// so the point is a sound candidate, but a name can match more than one place: modest, not
/// certain. Nominatim's own `importance` and `place_rank` ride along as evidence.
const GEOCODE_CONFIDENCE: f64 = 0.75;

/// Whether `query` is a `lat,lon` point (a reverse lookup) or free text (a forward lookup).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Forward,
    Reverse,
}

impl Mode {
    #[must_use]
    const fn tag(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Reverse => "reverse",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// One Nominatim place. `address` is kept as an open map so every component the service names --
/// however it is keyed -- is preserved without this struct having to enumerate them.
#[derive(Debug, Clone, Deserialize)]
struct Place {
    #[serde(default)]
    lat: Option<String>,
    #[serde(default)]
    lon: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    addresstype: Option<String>,
    #[serde(default, rename = "place_rank")]
    rank: Option<u64>,
    #[serde(default)]
    importance: Option<f64>,
    #[serde(default)]
    osm_type: Option<String>,
    #[serde(default)]
    osm_id: Option<u64>,
    #[serde(default)]
    boundingbox: Option<Vec<String>>,
    #[serde(default)]
    address: BTreeMap<String, String>,
}

/// A reverse answer is either one place or Nominatim's `{"error": "..."}` when nothing is near the
/// point. The untagged enum tries the error shape first; a real place has no `error` key.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Reverse {
    Error { error: String },
    Found(Box<Place>),
}

/// The forward search URL for `query`. **Pure.**
#[must_use]
pub fn search_url(query: &str) -> String {
    search_url_at(PUBLIC_BASE, query)
}

/// The reverse search URL for a `lat,lon` point. **Pure.**
#[must_use]
pub fn reverse_url(lat: f64, lon: f64) -> String {
    reverse_url_at(PUBLIC_BASE, lat, lon)
}

/// Forward-geocode `query`: a place name or address into coordinates and an address.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the URL.
pub fn forward<T: Transport + ?Sized>(
    transport: &T,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    // A direct Rust caller may bypass the CLI's query checks. Refuse invalid
    // input before it consumes a public-service rate slot or reaches the wire.
    if query.trim().is_empty() || query.len() > 512 || query.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "Nominatim query must be non-empty, at most 512 bytes and contain no controls".into(),
        ));
    }
    let origin = configured_base()?;
    let url = search_url_at(&origin, query);
    let (response, outcome, cached) = get(transport, &url, now_unix)?;
    let Some(response) = response else {
        return Ok(miss(outcome));
    };
    let mut report = interpret_forward(&response, query, scan_id, outcome.observed_at_unix);
    annotate_origin(&mut report, &origin);
    if cached {
        report.outcome = report
            .outcome
            .with_detail("in-process cached Nominatim response");
    }
    Ok(report)
}

/// Reverse-geocode a `lat,lon` point into the address at that spot.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the URL.
pub fn reverse<T: Transport + ?Sized>(
    transport: &T,
    lat: f64,
    lon: f64,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    if !lat.is_finite()
        || !lon.is_finite()
        || !(-90.0..=90.0).contains(&lat)
        || !(-180.0..=180.0).contains(&lon)
    {
        return Err(Error::Invalid(
            "invalid Nominatim latitude or longitude".into(),
        ));
    }
    let origin = configured_base()?;
    let url = reverse_url_at(&origin, lat, lon);
    let (response, outcome, cached) = get(transport, &url, now_unix)?;
    let Some(response) = response else {
        return Ok(miss(outcome));
    };
    let mut report = interpret_reverse(&response, lat, lon, scan_id, outcome.observed_at_unix);
    annotate_origin(&mut report, &origin);
    if cached {
        report.outcome = report
            .outcome
            .with_detail("in-process cached Nominatim response");
    }
    Ok(report)
}

/// Preserve which HTTPS Nominatim origin actually supplied this observation. The
/// source module name alone cannot distinguish operator-selected endpoints.
fn annotate_origin(report: &mut Report, origin: &str) {
    for entity in &mut report.entities {
        for evidence in &mut entity.evidence {
            evidence
                .attributes
                .insert("nominatim_endpoint_origin".into(), origin.to_owned());
        }
    }
}

/// Cache only a complete, successful document of the shape this endpoint expects.
fn cacheable(url: &str, response: &Response) -> bool {
    if response.status != 200 || response.truncated || response.body.len() > MAX_CACHE_BODY {
        return false;
    }
    // Full URLs are used as cache keys, preventing one operator endpoint from
    // supplying evidence for another. Parse only the known response shapes.
    let endpoint = url.split_once('?').map_or(url, |(path, _)| path);
    if endpoint.ends_with("/search") {
        serde_json::from_slice::<Vec<Place>>(&response.body).is_ok()
    } else if endpoint.ends_with("/reverse") {
        serde_json::from_slice::<Reverse>(&response.body).is_ok()
    } else {
        false
    }
}

fn insert_cache(state: &mut NominatimState, url: &str, response: Response, observed: u64) {
    // Keep phone memory bounded, including when every query is distinct.
    if state.cache.len() >= CACHE_LIMIT {
        if let Some(oldest) = state
            .cache
            .iter()
            .min_by_key(|(_, entry)| entry.received)
            .map(|(key, _)| key.clone())
        {
            state.cache.remove(&oldest);
        }
    }
    state.cache.insert(
        url.to_owned(),
        CachedResponse {
            response,
            received: Instant::now(),
            observed_at_unix: observed,
        },
    );
}

/// One guarded GET through the process-wide Nominatim cache and rate gate.
/// Waiting occurs under the lock, so concurrent forward and reverse calls cannot
/// overlap or burst. A circuit breaker remains a separate failure-control mechanism.
fn get<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
    now_unix: u64,
) -> Result<(Option<Response>, SourceExecutionOutcome, bool), Error> {
    get_with_state(&NOMINATIM_STATE, transport, url, now_unix, !cfg!(test))
}

/// Execute a guarded lookup with an explicitly provided cache and rate state.
///
/// Normal application calls use one process-global state. Unit tests isolate
/// fixture responses by disabling caching on the global path, and exercise
/// caching through a dedicated state rather than transport identity heuristics.
fn get_with_state<T: Transport + ?Sized>(
    state: &Mutex<NominatimState>,
    transport: &T,
    url: &str,
    now_unix: u64,
    cache_enabled: bool,
) -> Result<(Option<Response>, SourceExecutionOutcome, bool), Error> {
    let cache_key = url.to_owned();
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(entry) = state
        .cache
        .get(&cache_key)
        .filter(|_| cache_enabled)
        .filter(|entry| entry.received.elapsed() < CACHE_TTL)
    {
        return Ok((
            Some(entry.response.clone()),
            SourceExecutionOutcome::inconclusive(
                SOURCE,
                entry.observed_at_unix,
                "response came from the in-process Nominatim cache",
            ),
            true,
        ));
    }
    if let Some(finished) = state.last_attempt_finished {
        let delay = MIN_REQUEST_GAP.saturating_sub(finished.elapsed());
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }
    let result = fetch(
        transport,
        Request::get(url.to_owned())
            .header("accept", "application/json")
            .header("user-agent", DEFAULT_USER_AGENT),
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    );
    // Even refused or failed attempts consume the pacing slot; never create a burst.
    state.last_attempt_finished = Some(Instant::now());
    let fetched = result?;
    if let Some(response) = fetched
        .response
        .as_ref()
        .filter(|response| cache_enabled && cacheable(url, response))
    {
        insert_cache(
            &mut state,
            &cache_key,
            response.clone(),
            fetched.outcome.observed_at_unix,
        );
    }
    Ok((fetched.response, fetched.outcome, false))
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// A response that is a refusal or a wall rather than a result; `None` when it is a clean body to
/// parse. **Pure.**
fn refusal(response: &Response, now_unix: u64) -> Option<Report> {
    if response.truncated {
        return Some(miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "truncated Nominatim response",
        )));
    }
    if response.body.len() > MAX_NOMINATIM_RAW_JSON_BYTES {
        return Some(miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            "Nominatim response exceeds bounded raw-evidence limit",
        )));
    }
    let classified = classify_fetch(response.status, &response.text());
    if classified != SourceOutcomeKind::Inconclusive {
        return Some(miss(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            classified,
            Some(response.status),
            "Nominatim answered with a refusal or a wall, not a result",
        )));
    }
    None
}

/// Turn one forward-search response into a report. **Pure.**
fn interpret_forward(response: &Response, query: &str, scan_id: &str, now_unix: u64) -> Report {
    if let Some(report) = refusal(response, now_unix) {
        return report;
    }
    let raw_json = match std::str::from_utf8(&response.body) {
        Ok(body) => body,
        Err(error) => return drift(response.status, now_unix, &error.to_string()),
    };
    let places: Vec<Place> = match serde_json::from_slice(&response.body) {
        Ok(places) => places,
        Err(error) => return drift(response.status, now_unix, &json_error_detail(&error)),
    };
    decode(
        &places,
        Mode::Forward,
        query,
        scan_id,
        now_unix,
        response.status,
        raw_json,
    )
}

/// Turn one reverse-search response into a report. **Pure.**
fn interpret_reverse(
    response: &Response,
    lat: f64,
    lon: f64,
    scan_id: &str,
    now_unix: u64,
) -> Report {
    if let Some(report) = refusal(response, now_unix) {
        return report;
    }
    let query = format!("{lat},{lon}");
    let raw_json = match std::str::from_utf8(&response.body) {
        Ok(body) => body,
        Err(error) => return drift(response.status, now_unix, &error.to_string()),
    };
    match serde_json::from_slice::<Reverse>(&response.body) {
        Ok(Reverse::Found(place)) => decode(
            &[*place],
            Mode::Reverse,
            &query,
            scan_id,
            now_unix,
            response.status,
            raw_json,
        ),
        Ok(Reverse::Error { error }) => miss(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                .with_http_status(response.status)
                .with_detail(format!("Nominatim: {}", error.trim())),
        ),
        Err(error) => drift(response.status, now_unix, &json_error_detail(&error)),
    }
}

fn drift(status: u16, now_unix: u64, detail: &str) -> Report {
    miss(SourceExecutionOutcome::failed(
        SOURCE,
        now_unix,
        SourceOutcomeKind::ParserDrift,
        Some(status),
        format!("Nominatim JSON: {detail}"),
    ))
}

/// Build the report from parsed places. Each place yields a `Coordinates` entity for its point and
/// an `Address` entity for its written address, both carrying every field as evidence. **Pure.**
fn decode(
    places: &[Place],
    mode: Mode,
    query: &str,
    scan_id: &str,
    now_unix: u64,
    status: u16,
    raw_json: &str,
) -> Report {
    let mut entities = Vec::new();
    let observation = RawObservation {
        body: raw_json,
        recorded_at_unix: now_unix,
    };
    for (candidate_index, place) in places.iter().take(RESULT_LIMIT).enumerate() {
        place_entities(
            &mut entities,
            place,
            mode,
            query,
            scan_id,
            &observation,
            candidate_index,
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

/// The coordinates and address entities for one place. **Pure.**
fn place_entities(
    entities: &mut Vec<Entity>,
    place: &Place,
    mode: Mode,
    query: &str,
    scan_id: &str,
    observation: &RawObservation<'_>,
    candidate_index: usize,
) {
    let coordinates = point(place);
    let display = place
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    // Shared evidence: the query that produced the place and every field Nominatim named.
    let describe = |summary: String| -> Evidence {
        let mut provenance = EvidenceProvenance::for_scan(SOURCE, scan_id);
        provenance.recorded_at_unix = observation.recorded_at_unix;
        let mut evidence = Evidence::new(provenance, summary)
            .with_attr("dataset", "OpenStreetMap Nominatim")
            .with_attr("source_attribution", "© OpenStreetMap contributors")
            .with_attr("source_license", "ODbL 1.0")
            .with_attr("mode", mode.tag())
            .with_attr("query", query)
            // Preserve the exact UTF-8 bytes of this bounded JSON response, not a
            // reconstructed struct (which would drop unknown provider fields).
            .with_attr("nominatim_raw_response_json", observation.body)
            // A forward response may have several places: identify which one
            // yielded this entity without reassigning any provider property.
            .with_attr("nominatim_candidate_index", candidate_index.to_string());
        for (attr, value) in [
            ("display_name", display),
            ("name", opt(place.name.as_deref())),
            ("category", opt(place.category.as_deref())),
            ("place_type", opt(place.kind.as_deref())),
            ("addresstype", opt(place.addresstype.as_deref())),
            ("osm_type", opt(place.osm_type.as_deref())),
        ] {
            if let Some(value) = value {
                evidence = evidence.with_attr(attr, value);
            }
        }
        if let Some(id) = place.osm_id {
            evidence = evidence.with_attr("osm_id", id.to_string());
        }
        if let Some(rank) = place.rank {
            evidence = evidence.with_attr("place_rank", rank.to_string());
        }
        if let Some(importance) = place.importance {
            evidence = evidence.with_attr("importance", format!("{importance:.6}"));
        }
        if let Some(bbox) = place.boundingbox.as_ref().filter(|b| !b.is_empty()) {
            evidence = evidence.with_attr("boundingbox", bbox.join(","));
        }
        if let Some(coordinates) = coordinates.as_deref() {
            evidence = evidence.with_attr("coordinates", coordinates);
        }
        // Every address component, however keyed, so no part of the answer is dropped.
        for (key, value) in &place.address {
            let value = value.trim();
            if !value.is_empty() {
                evidence = evidence.with_attr(format!("address_{key}"), value);
            }
        }
        evidence
    };

    if let Some(coordinates) = coordinates.as_deref() {
        let summary = display.map_or_else(
            || format!("geocoded point for {query:?}"),
            |name| format!("geocoded point for {query:?}: {name}"),
        );
        push_entity(
            entities,
            EntityKind::Coordinates,
            coordinates,
            GEOCODE_CONFIDENCE,
            scan_id,
            describe(summary),
            &[SOURCE, "geocode", mode.tag()],
        );
    }

    if let Some(display) = display {
        let summary = coordinates.as_deref().map_or_else(
            || format!("geocoded address for {query:?}"),
            |point| format!("geocoded address at {point} for {query:?}"),
        );
        push_entity(
            entities,
            EntityKind::Address,
            display,
            GEOCODE_CONFIDENCE,
            scan_id,
            describe(summary),
            &[SOURCE, "geocode", mode.tag()],
        );
    }
}

/// The canonical `lat,lon` point of a place, when both are present and valid. **Pure.**
fn point(place: &Place) -> Option<String> {
    let lat = place.lat.as_deref()?.trim();
    let lon = place.lon.as_deref()?.trim();
    canonical_coordinates(&format!("{lat},{lon}"))
}

fn opt(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests;
