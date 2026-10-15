//! `RIPEstat` `prefix-overview`: keyless routing context for one IP, from any registry region.
//!
//! One lookup is one `GET https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}`.
//! It answers with the announced prefix that covers the address, the origin AS numbers and their
//! holders, and the registry block. `status` must be `ok`; an address no AS announces is a valid
//! zero, not an error.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::keys::Keys;

pub const SOURCE: &str = "ripestat";
pub const API: Api = Api {
    source: SOURCE,
    provider: "stat.ripe.net",
    origin: "https://stat.ripe.net:443",
    key: None,
};
/// Most origin AS numbers kept for one prefix.
pub const MAX_ASNS: usize = 8;

/// One origin AS of the covering prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub asn: u32,
    pub holder: Option<String>,
}

/// The routing context of one address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Routing {
    /// The covering prefix as `RIPEstat` gives it.
    pub prefix: Option<String>,
    pub announced: bool,
    pub origins: Vec<Origin>,
    /// The registry block's description, e.g. `APNIC (Status: ALLOCATED)`.
    pub block: Option<String>,
}

#[derive(Deserialize)]
struct Envelope {
    status: String,
    data: Option<Data>,
}

#[derive(Deserialize)]
struct Data {
    #[serde(default)]
    announced: bool,
    #[serde(default)]
    asns: Vec<Asn>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    block: Option<Block>,
}

#[derive(Deserialize)]
struct Asn {
    asn: u32,
    #[serde(default)]
    holder: Option<String>,
}

#[derive(Deserialize)]
struct Block {
    #[serde(default)]
    desc: Option<String>,
}

/// The request URL for `ip`. **Pure.**
#[must_use]
pub fn url(ip: &str) -> String {
    format!(
        "https://stat.ripe.net/data/prefix-overview/data.json?resource={}",
        percent_encode_component(ip)
    )
}

/// Look `ip` up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    ip: &str,
    now_unix: u64,
) -> Result<Routing, LegError> {
    match api_leg::get(transport, &API, &Keys::default(), &url(ip), now_unix)? {
        Answer::Body(body) => decode(&body),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One answer body as routing context. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the envelope, has no data, or whose status is
/// not `ok`.
pub fn decode(body: &[u8]) -> Result<Routing, LegError> {
    let envelope: Envelope = api_leg::decode(body)?;
    if envelope.status != "ok" {
        return Err(LegError::Decode(format!(
            "status is {}",
            api_leg::clean(Some(&envelope.status)).unwrap_or_default()
        )));
    }
    let data = envelope
        .data
        .ok_or_else(|| LegError::Decode("envelope has no data".into()))?;
    let mut origins: Vec<Origin> = data
        .asns
        .into_iter()
        .map(|a| Origin {
            asn: a.asn,
            holder: api_leg::clean(a.holder.as_deref()),
        })
        .collect();
    origins.sort_by_key(|o| o.asn);
    origins.dedup_by_key(|o| o.asn);
    origins.truncate(MAX_ASNS);
    Ok(Routing {
        prefix: api_leg::clean(data.resource.as_deref()),
        announced: data.announced,
        origins,
        block: api_leg::clean(data.block.and_then(|b| b.desc).as_deref()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from `RIPEstat` for `1.1.1.1` on 2026-10-14 (envelope fields trimmed).
    const RECORDED: &str = r#"{"messages":[["warning","Given resource is not announced but result has been aligned to first-level less-specific (1.1.1.0/24)."]],"status":"ok","status_code":200,"data":{"is_less_specific":true,"announced":true,"asns":[{"asn":13335,"holder":"CLOUDFLARENET - Cloudflare, Inc."}],"related_prefixes":[],"resource":"1.1.1.0/24","type":"prefix","block":{"resource":"1.0.0.0/8","desc":"APNIC (Status: ALLOCATED)","name":"IANA IPv4 Address Space Registry"}}}"#;
    /// Recorded for the unannounced `192.0.2.1` on 2026-10-14 (trimmed).
    const UNANNOUNCED: &str = r#"{"status":"ok","data":{"announced":false,"asns":[],"resource":"192.0.2.1","block":{"desc":"Documentation (TEST-NET-1)"}}}"#;

    #[test]
    fn a_recorded_answer_names_the_prefix_and_its_origin_as() {
        let routing = decode(RECORDED.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(routing.prefix.as_deref(), Some("1.1.1.0/24"));
        assert!(routing.announced);
        assert_eq!(
            routing.origins,
            [Origin {
                asn: 13335,
                holder: Some("CLOUDFLARENET - Cloudflare, Inc.".into())
            }]
        );
        assert_eq!(routing.block.as_deref(), Some("APNIC (Status: ALLOCATED)"));
    }

    #[test]
    fn an_unannounced_address_has_no_origin() {
        let routing = decode(UNANNOUNCED.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert!(!routing.announced);
        assert!(routing.origins.is_empty());
    }

    #[test]
    fn a_status_other_than_ok_is_an_error() {
        assert!(decode(br#"{"status":"error","data":null}"#).is_err());
        assert!(decode(br#"{"status":"ok"}"#).is_err());
    }

    #[test]
    fn the_address_is_percent_encoded() {
        assert_eq!(
            url("2001:db8::1"),
            "https://stat.ripe.net/data/prefix-overview/data.json?resource=2001%3Adb8%3A%3A1"
        );
    }
}
