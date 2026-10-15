//! `RIPEstat` `prefix-overview`: keyless routing context for one IP, from any registry region.
//!
//! One lookup is one `GET https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}`.
//! It answers with the announced prefix that covers the address, the origin AS numbers and their
//! holders, the related prefixes, and the registry block. `status` must be `ok`. Everything is
//! kept: every origin AS, every related and `see_also` prefix, the block's resource, name and
//! description, `RIPEstat`'s messages, and the whole answer as JSON. An address no AS announces and
//! no registry block covers is a valid zero, not an error.

use serde::Deserialize;
use serde_json::Value;

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
    /// The registry block itself, e.g. `1.0.0.0/8`.
    pub block_resource: Option<String>,
    /// The registry the block is listed in, e.g. `IANA IPv4 Address Space Registry`.
    pub block_name: Option<String>,
    /// Whether the prefix is the first less-specific one covering the address, not the address.
    pub less_specific: bool,
    /// Every related prefix, as `RIPEstat` lists it.
    pub related: Vec<String>,
    /// Every `see_also` resource with its relation, e.g. `less-specific 8.0.0.0/9`.
    pub see_also: Vec<String>,
    /// `RIPEstat`'s messages, e.g. `warning: Given resource is not announced …`.
    pub messages: Vec<String>,
    /// The whole answer as JSON.
    pub raw: String,
}

impl Routing {
    /// Whether the answer says anything about the address. **Pure.**
    #[must_use]
    pub fn says_anything(&self) -> bool {
        !self.origins.is_empty()
            || self.block.is_some()
            || self.block_resource.is_some()
            || !self.related.is_empty()
    }
}

#[derive(Deserialize)]
struct Envelope {
    status: String,
    data: Option<Data>,
    #[serde(default)]
    messages: Vec<Vec<Value>>,
    #[serde(default)]
    see_also: Vec<SeeAlso>,
}

#[derive(Deserialize)]
struct Data {
    #[serde(default)]
    announced: bool,
    #[serde(default)]
    is_less_specific: bool,
    #[serde(default)]
    asns: Vec<Asn>,
    #[serde(default)]
    related_prefixes: Vec<Value>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    block: Option<Block>,
}

#[derive(Deserialize)]
struct SeeAlso {
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    resource: Option<String>,
}

#[derive(Deserialize)]
struct Asn {
    asn: u32,
    #[serde(default)]
    holder: Option<String>,
}

#[derive(Default, Deserialize)]
struct Block {
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    desc: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// One related prefix as text: `RIPEstat` lists a bare prefix, or an object with the prefix,
/// its origin AS, the AS name and the relationship. **Pure.**
fn related(value: &Value) -> Option<String> {
    match value {
        Value::String(prefix) => api_leg::clean(Some(prefix)),
        Value::Object(fields) => {
            let parts: Vec<String> = ["prefix", "origin_asn", "asn_name", "relationship"]
                .into_iter()
                .filter_map(|key| match fields.get(key)? {
                    Value::String(s) => api_leg::clean(Some(s)),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

/// Text joined from the parts of one `RIPEstat` message, e.g. `warning: …`. **Pure.**
fn message(parts: &[Value]) -> Option<String> {
    let parts: Vec<&str> = parts.iter().filter_map(Value::as_str).collect();
    match parts.as_slice() {
        [] => None,
        [text] => api_leg::clean(Some(text)),
        [level, rest @ ..] => api_leg::clean(Some(&format!("{level}: {}", rest.join(" ")))),
    }
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
    let raw: Value = api_leg::decode(body)?;
    let envelope = Envelope::deserialize(&raw)
        .map_err(|e| LegError::Decode(format!("unexpected response shape: {e}")))?;
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
    let block = data.block.unwrap_or_default();
    Ok(Routing {
        prefix: api_leg::clean(data.resource.as_deref()),
        announced: data.announced,
        origins,
        block: api_leg::clean(block.desc.as_deref()),
        block_resource: api_leg::clean(block.resource.as_deref()),
        block_name: api_leg::clean(block.name.as_deref()),
        less_specific: data.is_less_specific,
        related: data.related_prefixes.iter().filter_map(related).collect(),
        see_also: envelope
            .see_also
            .iter()
            .filter_map(|s| {
                let text = [s.relation.as_deref(), s.resource.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                api_leg::clean(Some(&text))
            })
            .collect(),
        messages: envelope
            .messages
            .iter()
            .filter_map(|m| message(m))
            .collect(),
        raw: raw.to_string(),
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

    /// Recorded from `RIPEstat` for `8.8.8.8` on 2026-10-15 (envelope bookkeeping trimmed).
    const ALIGNED: &str = r#"{"messages":[["warning","Given resource is not announced but result has been aligned to first-level less-specific (8.8.8.0/24)."]],"see_also":[{"relation":"less-specific","resource":"8.0.0.0/9"},{"relation":"less-specific","resource":"8.0.0.0/12"}],"status":"ok","status_code":200,"data":{"is_less_specific":true,"announced":true,"asns":[{"asn":15169,"holder":"GOOGLE - Google LLC"}],"related_prefixes":["8.0.0.0/9","8.0.0.0/12"],"resource":"8.8.8.0/24","type":"prefix","block":{"resource":"8.0.0.0/8","desc":"Administered by ARIN","name":"IANA IPv4 Address Space Registry"},"actual_num_related":2,"query_time":"2026-10-15T08:00:00","num_filtered_out":0}}"#;

    #[test]
    fn everything_ripestat_says_is_kept() {
        let routing = decode(ALIGNED.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(routing.related, ["8.0.0.0/9", "8.0.0.0/12"]);
        assert_eq!(
            routing.see_also,
            ["less-specific 8.0.0.0/9", "less-specific 8.0.0.0/12"]
        );
        assert_eq!(
            routing.messages,
            [
                "warning: Given resource is not announced but result has been aligned to first-level less-specific (8.8.8.0/24)."
            ]
        );
        assert_eq!(routing.block_resource.as_deref(), Some("8.0.0.0/8"));
        assert_eq!(
            routing.block_name.as_deref(),
            Some("IANA IPv4 Address Space Registry")
        );
        assert!(routing.less_specific);
        let raw: Value = serde_json::from_str(&routing.raw).unwrap_or_default();
        assert_eq!(raw["data"]["actual_num_related"], 2);
    }

    #[test]
    fn every_origin_as_and_an_object_shaped_related_prefix_are_kept() {
        let asns: Vec<String> = (1..=12)
            .map(|n| format!(r#"{{"asn":{},"holder":"Holder {n}"}}"#, 64_500 + n))
            .collect();
        let body = format!(
            r#"{{"status":"ok","data":{{"announced":true,"asns":[{}],"related_prefixes":[{{"prefix":"192.0.2.0/25","origin_asn":64501,"asn_name":"Holder 1","relationship":"Overlap - More Specific"}}],"resource":"192.0.2.0/24"}}}}"#,
            asns.join(",")
        );
        let routing = decode(body.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(routing.origins.len(), 12);
        assert_eq!(
            routing.related,
            ["192.0.2.0/25 64501 Holder 1 Overlap - More Specific"]
        );
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
