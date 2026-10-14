//! `WiGLE` network search: the keyed leg of `network`.
//!
//! One lookup is one `GET https://api.wigle.net/api/v2/network/search` with the operator's
//! `WiGLE` API name and API token sent as HTTP Basic credentials, bound to [`KEY_ORIGIN`] by
//! [`crate::fetch`]. Redirects are not followed, so the credentials cannot be sent anywhere else.
//! The endpoint, parameters and field names are those of `WiGLE`'s published Swagger document
//! (`https://api.wigle.net/swagger.json`, `NetSearchResponse` and `WiFiNetwork`).
//!
//! The selector decides the query: a BSSID searches `netid`, an SSID searches `ssid` (exact
//! match), and a coordinate pair searches a box of [`AREA_DELTA_DEGREES`] around it, nearest
//! network first. Each network becomes an [`RfSighting`] from [`RfSource::WigleApi`] with what
//! `WiGLE` records about it: its trilaterated position, encryption, channel, first and last
//! sighting, and the reverse-geocoded street address `WiGLE` gives the position.
//!
//! The lookup reads one page of [`PAGE_SIZE`] networks. When `WiGLE` reports more, the answer is
//! marked partial, never complete. A credential refusal, the daily query limit, a
//! `success: false` envelope, and a body that is not the envelope are errors, never a zero: a
//! zero is only a successful envelope with no results. Each lookup spends one of the account's
//! daily queries.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use crate::http::{Request, Response, Transport, TransportConfig, percent_encode_component};
use crate::keys::{Keys, Secret};
use crate::redact::scrub_secrets;
use crate::rf::{RadioKind, RfSighting, RfSource, canonical_network_id, is_mac};
use crate::scan_route::NetworkSelector;
use crate::source_outcome::SourceOutcomeKind;

/// Source label of this leg in outcomes, evidence and saved ledgers.
pub const SOURCE: &str = "wigle";
/// The slot holding the `WiGLE` API name (the Basic-auth user).
pub const USER_SLOT: &str = crate::environment::WIGLE_USER_ENV;
/// The slot holding the `WiGLE` API token (the Basic-auth password).
pub const TOKEN_SLOT: &str = crate::environment::WIGLE_TOKEN_ENV;
/// The `WiFi` network search endpoint.
pub const API_URL: &str = "https://api.wigle.net/api/v2/network/search";
/// The only origin the credentials are ever sent to.
pub const KEY_ORIGIN: &str = "https://api.wigle.net:443";
/// Networks read per lookup. `WiGLE` pages API searches at 100.
pub const PAGE_SIZE: u32 = 100;
/// Half the side of the box searched around a coordinate pair, in degrees (about 220 m of
/// latitude).
pub const AREA_DELTA_DEGREES: f64 = 0.002;
/// Ceiling for the one request.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Longest provider text kept, in characters: an SSID is at most 32 bytes, an address field
/// a short line.
const TEXT_MAX_CHARS: usize = 120;

/// Why a lookup gave no answer. No variant carries a credential, the selector or a body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WigleError {
    #[error("wigle: no API credentials configured (set {USER_SLOT} and {TOKEN_SLOT})")]
    MissingKey,
    #[error("wigle: request refused before sending: {0}")]
    Refused(String),
    #[error("wigle: no response ({0:?})")]
    Transport(SourceOutcomeKind),
    #[error("wigle: bad request (HTTP 400)")]
    BadRequest,
    #[error(
        "wigle: unauthorised (HTTP 401): the credentials were rejected; {USER_SLOT} must be the \
         API Name and {TOKEN_SLOT} the API Token from https://wigle.net/account, not the encoded \
         value"
    )]
    Unauthorized,
    #[error("wigle: the account is not entitled to this query (HTTP {0})")]
    Forbidden(u16),
    #[error("wigle: query failed (HTTP 410)")]
    QueryFailed,
    #[error("wigle: daily query limit reached (HTTP 429){}", describe_retry(*.retry_after))]
    RateLimited { retry_after: Option<u64> },
    #[error("wigle: server error (HTTP {0})")]
    Server(u16),
    #[error("wigle: unexpected HTTP {0}")]
    Unexpected(u16),
    #[error("wigle: response is not an API answer ({0:?})")]
    NotAnAnswer(SourceOutcomeKind),
    #[error("wigle: {0}")]
    Decode(String),
    #[error("wigle: success=false: {0}")]
    Provider(String),
}

fn describe_retry(retry_after: Option<u64>) -> String {
    retry_after.map_or_else(String::new, |secs| format!(", retry after {secs}s"))
}

impl WigleError {
    /// The outcome a failed lookup records.
    #[must_use]
    pub const fn outcome_kind(&self) -> SourceOutcomeKind {
        match self {
            Self::MissingKey => SourceOutcomeKind::AuthRequired,
            Self::Unauthorized => SourceOutcomeKind::AuthRejected,
            Self::Forbidden(_) => SourceOutcomeKind::EntitlementDenied,
            Self::RateLimited { .. } => SourceOutcomeKind::RateLimited,
            Self::BadRequest | Self::QueryFailed | Self::Unexpected(_) => {
                SourceOutcomeKind::Upstream4xx
            }
            Self::Server(_) => SourceOutcomeKind::Upstream5xx,
            Self::Transport(kind) | Self::NotAnAnswer(kind) => *kind,
            Self::Decode(_) => SourceOutcomeKind::SchemaDrift,
            Self::Refused(_) | Self::Provider(_) => SourceOutcomeKind::Inconclusive,
        }
    }

    /// The HTTP status behind the failure, when there was one.
    #[must_use]
    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::QueryFailed => Some(410),
            Self::RateLimited { .. } => Some(429),
            Self::Forbidden(status) | Self::Server(status) | Self::Unexpected(status) => {
                Some(*status)
            }
            _ => None,
        }
    }
}

/// One `WiFi` network as `WiGLE` records it.
#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    /// The BSSID (lower case), SSID, encryption, trilaterated position and last sighting.
    pub sighting: RfSighting,
    pub first_seen: Option<String>,
    pub last_updated: Option<String>,
    pub channel: Option<i64>,
    pub frequency_mhz: Option<i64>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub road: Option<String>,
    pub house_number: Option<String>,
    pub postal_code: Option<String>,
}

impl Network {
    /// The BSSID, lower case.
    #[must_use]
    pub fn bssid(&self) -> &str {
        &self.sighting.network_id
    }

    /// The SSID, when the network broadcasts one.
    #[must_use]
    pub fn ssid(&self) -> Option<&str> {
        self.sighting.name.as_deref()
    }

    /// The trilaterated position, when it is a real coordinate.
    #[must_use]
    pub fn position(&self) -> Option<(f64, f64)> {
        if !self.sighting.has_usable_position() {
            return None;
        }
        self.sighting.latitude.zip(self.sighting.longitude)
    }

    /// The street address `WiGLE` gives the position, most specific part first, or `None`.
    #[must_use]
    pub fn address(&self) -> Option<String> {
        let street = match (&self.house_number, &self.road) {
            (Some(number), Some(road)) => Some(format!("{number} {road}")),
            (None, Some(road)) => Some(road.clone()),
            _ => None,
        };
        let parts: Vec<String> = [
            street,
            self.city.clone(),
            self.region.clone(),
            self.postal_code.clone(),
            self.country.clone(),
        ]
        .into_iter()
        .flatten()
        .collect();
        (!parts.is_empty()).then(|| parts.join(", "))
    }
}

/// One decoded search page.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Search {
    /// One entry per distinct BSSID, in `WiGLE`'s order.
    pub networks: Vec<Network>,
    /// Results on this page, before dropping rows without a BSSID or repeating one.
    pub results: usize,
    /// Rows whose `netid` is not a BSSID. Counted, never kept.
    pub unusable: usize,
    /// Matching networks `WiGLE` reports in all.
    pub total: Option<u64>,
}

impl Search {
    /// Why this page is not the whole answer, or `None` when it is.
    #[must_use]
    pub fn truncation(&self) -> Option<String> {
        let total = self.total?;
        (total > self.results as u64).then(|| {
            format!(
                "partial: read the first {} of {total} matching networks; absence of a network \
                 here is not evidence of absence",
                self.results
            )
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    success: Option<bool>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    total_results: Option<u64>,
    #[serde(default)]
    results: Option<Vec<Map<String, Value>>>,
}

/// Transport settings for `WiGLE`: the [`TIMEOUT`] ceiling.
#[must_use]
pub fn transport_config() -> TransportConfig {
    TransportConfig {
        timeout: TIMEOUT,
        ..TransportConfig::default()
    }
}

/// Both credential slots hold a value. A half-configured account is not configured.
#[must_use]
pub fn configured(keys: &Keys) -> bool {
    keys.get(USER_SLOT).is_some() && keys.get(TOKEN_SLOT).is_some()
}

/// The request URL for `selector`. **Pure.**
#[must_use]
pub fn search_url(selector: &NetworkSelector) -> String {
    let query = match selector {
        NetworkSelector::Bssid(bssid) => {
            format!(
                "netid={}",
                percent_encode_component(&bssid.to_ascii_uppercase())
            )
        }
        NetworkSelector::Ssid(ssid) => format!("ssid={}", percent_encode_component(ssid)),
        NetworkSelector::Area { lat, lon } => {
            let d = AREA_DELTA_DEGREES;
            format!(
                "latrange1={:.6}&latrange2={:.6}&longrange1={:.6}&longrange2={:.6}\
                 &closestLat={lat:.6}&closestLong={lon:.6}",
                (lat - d).max(-90.0),
                (lat + d).min(90.0),
                (lon - d).max(-180.0),
                (lon + d).min(180.0),
            )
        }
    };
    format!("{API_URL}?{query}&resultsPerPage={PAGE_SIZE}")
}

/// Search `WiGLE` for the networks `selector` names, with the credentials in `keys`.
///
/// # Errors
/// [`WigleError::MissingKey`] before any request when either slot is empty; otherwise the
/// refusal, status, envelope or decode failure that stopped the lookup.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    selector: &NetworkSelector,
    now_unix: u64,
) -> Result<Search, WigleError> {
    let (Some(user), Some(token)) = (keys.get(USER_SLOT), keys.get(TOKEN_SLOT)) else {
        return Err(WigleError::MissingKey);
    };
    if user.expose().contains(':') {
        return Err(WigleError::Refused(format!(
            "{USER_SLOT} must be the API Name alone; a ':' cannot be sent as a Basic-auth user"
        )));
    }
    let pair = Secret::new(format!("{}:{}", user.expose(), token.expose()))
        .map_err(|e| WigleError::Refused(e.to_string()))?;
    let secrets = [user.expose(), token.expose(), pair.expose()];
    let credential = credential(pair.clone(), now_unix)?;
    let request = Request::get(search_url(selector))
        .header("Accept", "application/json")
        .with_timeout(TIMEOUT);
    let fetched = fetch(
        transport,
        request,
        Some(&credential),
        &FetchOptions::no_redirects(),
        SOURCE,
        now_unix,
    )
    .map_err(|e| WigleError::Refused(scrub_secrets(&e.to_string(), &secrets)))?;
    let Some(response) = fetched.response else {
        return Err(WigleError::Transport(fetched.outcome.kind));
    };
    status_error(&response)?;
    if fetched.outcome.kind != SourceOutcomeKind::Inconclusive {
        return Err(WigleError::NotAnAnswer(fetched.outcome.kind));
    }
    if response.truncated {
        return Err(WigleError::Decode("response exceeds the body limit".into()));
    }
    decode(&response.body, &secrets)
}

fn credential(secret: Secret, now_unix: u64) -> Result<Credential, WigleError> {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "wigle.net".into(),
        credential_slot: TOKEN_SLOT.into(),
        approved_at_unix: now_unix,
        approval_provenance: format!("operator configured {USER_SLOT} and {TOKEN_SLOT}"),
    })
    .map_err(|e| WigleError::Refused(e.to_string()))?;
    Credential::new(authority, secret, AuthStyle::Basic)
        .map(|c| c.only_for_origin(KEY_ORIGIN))
        .map_err(|e| WigleError::Refused(e.to_string()))
}

/// The error a non-2xx status means. The status decides first.
fn status_error(response: &Response) -> Result<(), WigleError> {
    match response.status {
        200..=299 => Ok(()),
        400 => Err(WigleError::BadRequest),
        401 => Err(WigleError::Unauthorized),
        status @ (402 | 403) => Err(WigleError::Forbidden(status)),
        410 => Err(WigleError::QueryFailed),
        429 => Err(WigleError::RateLimited {
            retry_after: response
                .header_value("retry-after")
                .and_then(|v| v.trim().parse::<u64>().ok()),
        }),
        status @ 500..=599 => Err(WigleError::Server(status)),
        status => Err(WigleError::Unexpected(status)),
    }
}

/// One response body as a search page, with every secret in `secrets` scrubbed from any
/// provider text kept. **Pure.**
///
/// # Errors
/// [`WigleError::Provider`] for a `success: false` envelope, [`WigleError::Decode`] for a body
/// that is not the envelope or has no `results` array.
pub fn decode(body: &[u8], secrets: &[&str]) -> Result<Search, WigleError> {
    let envelope: Envelope = serde_json::from_slice(body).map_err(|e| decode_error(&e))?;
    if envelope.success == Some(false) {
        let message = envelope.message.as_deref().unwrap_or("no message");
        return Err(WigleError::Provider(clean(message, secrets)));
    }
    let rows = envelope
        .results
        .ok_or_else(|| WigleError::Decode("envelope has no results".into()))?;
    let mut search = Search {
        results: rows.len(),
        total: envelope.total_results,
        ..Search::default()
    };
    let mut seen = BTreeSet::new();
    for row in &rows {
        let Some(network) = network(row, secrets) else {
            search.unusable += 1;
            continue;
        };
        if seen.insert(network.bssid().to_owned()) {
            search.networks.push(network);
        }
    }
    Ok(search)
}

/// One result row as a [`Network`], or `None` when its `netid` is not a BSSID. **Pure.**
fn network(row: &Map<String, Value>, secrets: &[&str]) -> Option<Network> {
    let bssid = canonical_network_id(&text(row, "netid", secrets)?);
    if !is_mac(&bssid) {
        return None;
    }
    let mut sighting = RfSighting::new(&bssid, RadioKind::Wifi, RfSource::WigleApi);
    sighting.name = text(row, "ssid", secrets);
    sighting.encryption = text(row, "encryption", secrets);
    sighting.raw_type = text(row, "type", secrets);
    sighting.latitude = row.get("trilat").and_then(Value::as_f64);
    sighting.longitude = row.get("trilong").and_then(Value::as_f64);
    sighting.observed_at = text(row, "lasttime", secrets);
    sighting.observed_epoch = sighting
        .observed_at
        .as_deref()
        .and_then(crate::rf::parse_iso8601_epoch);
    Some(Network {
        sighting,
        first_seen: text(row, "firsttime", secrets),
        last_updated: text(row, "lastupdt", secrets),
        channel: row
            .get("channel")
            .and_then(Value::as_i64)
            .filter(|c| *c > 0),
        frequency_mhz: row
            .get("frequency")
            .and_then(Value::as_i64)
            .filter(|f| *f > 0),
        country: text(row, "country", secrets),
        region: text(row, "region", secrets),
        city: text(row, "city", secrets),
        road: text(row, "road", secrets),
        house_number: text(row, "housenumber", secrets),
        postal_code: text(row, "postalcode", secrets),
    })
}

/// A non-blank string field, cleaned. **Pure.**
fn text(row: &Map<String, Value>, key: &str, secrets: &[&str]) -> Option<String> {
    let value = row.get(key)?.as_str()?.trim();
    (!value.is_empty() && !value.eq_ignore_ascii_case("null")).then(|| clean(value, secrets))
}

/// Provider text as a report may show it: secrets scrubbed first, then at most
/// [`TEXT_MAX_CHARS`] characters, control characters replaced. **Pure.**
fn clean(value: &str, secrets: &[&str]) -> String {
    scrub_secrets(value, secrets)
        .chars()
        .take(TEXT_MAX_CHARS)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// A body that is not the envelope: the error's category and position, never serde's message,
/// which can quote the body. **Pure.**
fn decode_error(e: &serde_json::Error) -> WigleError {
    let category = match e.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    WigleError::Decode(format!(
        "unexpected response shape: {category} error at line {} column {}",
        e.line(),
        e.column()
    ))
}

#[cfg(test)]
mod tests;
