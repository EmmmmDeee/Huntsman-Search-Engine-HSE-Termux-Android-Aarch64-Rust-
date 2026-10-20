//! `RIPEstat`: keyless routing context from any registry region.
//!
//! For an address or block, `GET https://stat.ripe.net/data/prefix-overview/data.json?resource=`
//! answers with the announced prefix that covers it, every origin AS number and its holder, the
//! related prefixes, and the registry block. Everything is kept: every origin AS, every related and
//! `see_also` prefix, the block's resource, name and description, `RIPEstat`'s messages, and the
//! whole answer as JSON. For an AS number, as Spiderfoot's `sfp_ripe` reads it, `as-overview` names
//! its holder and registry block, `announced-prefixes` lists every prefix it announces with the
//! windows it was seen, and `asn-neighbours` every AS adjacent to it in BGP paths. `status` must
//! be `ok`; an address no AS announces and no registry block covers is a valid zero, not an error.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::entity::Evidence;
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
    /// Whether the answer says anything about the address or block. **Pure.**
    #[must_use]
    pub fn says_anything(&self) -> bool {
        !self.origins.is_empty()
            || self.block.is_some()
            || self.block_resource.is_some()
            || !self.related.is_empty()
    }

    /// Every origin AS of the covering prefix, written `AS13335`. **Pure.**
    #[must_use]
    pub fn origin_asns(&self) -> Vec<String> {
        self.origins
            .iter()
            .map(|origin| format!("AS{}", origin.asn))
            .collect()
    }

    /// The summary of the record on the address or block: the AS numbers that announce the
    /// covering prefix, or the registry block when none does. **Pure.**
    #[must_use]
    pub fn summary(&self) -> String {
        let asns = self.origin_asns();
        if asns.is_empty() {
            format!(
                "Not announced; registry block {}",
                self.block_resource
                    .as_deref()
                    .or(self.block.as_deref())
                    .unwrap_or("unnamed")
            )
        } else {
            format!("Announced by {}", asns.join(", "))
        }
    }

    /// `evidence` holding everything the answer says about the address or block: the covering
    /// prefix, whether it is announced and whether it is a less-specific one, every origin AS,
    /// related and `see_also` prefix, the registry block's resource, description and registry,
    /// `RIPEstat`'s messages, and the whole answer as `raw_answer`. Every lookup that reads
    /// `prefix-overview` records it this way. **Pure.**
    #[must_use]
    pub fn describe(&self, evidence: Evidence) -> Evidence {
        let lists = [
            ("origin_asns", self.origin_asns().join(",")),
            ("related_prefixes", self.related.join(",")),
            ("see_also", self.see_also.join(",")),
            ("messages", self.messages.join("; ")),
        ];
        let mut evidence = evidence.with_optional_attrs([
            ("prefix", self.prefix.as_deref()),
            ("registry_block", self.block.as_deref()),
            ("block_resource", self.block_resource.as_deref()),
            ("block_registry", self.block_name.as_deref()),
            (
                "announced",
                Some(if self.announced { "true" } else { "false" }),
            ),
            ("less_specific", self.less_specific.then_some("true")),
        ]);
        for (key, value) in lists {
            if !value.is_empty() {
                evidence = evidence.with_attr(key, value);
            }
        }
        evidence.with_attr("raw_answer", &self.raw)
    }
}

#[derive(Deserialize)]
struct Envelope<D> {
    status: String,
    data: Option<D>,
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
    let envelope = Envelope::<Data>::deserialize(&raw)
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

/// The data of an `ok` envelope. **Pure.**
fn unwrap<D: DeserializeOwned>(body: &[u8]) -> Result<D, LegError> {
    let envelope: Envelope<D> = api_leg::decode(body)?;
    if envelope.status != "ok" {
        return Err(LegError::Decode(format!(
            "status is {}",
            api_leg::clean(Some(&envelope.status)).unwrap_or_default()
        )));
    }
    envelope
        .data
        .ok_or_else(|| LegError::Decode("envelope has no data".into()))
}

/// The `RIPEstat` data call `call` for `AS{asn}`. **Pure.**
#[must_use]
pub fn as_url(call: &str, asn: u32) -> String {
    format!("https://stat.ripe.net/data/{call}/data.json?resource=AS{asn}")
}

fn as_call<T: Transport + ?Sized>(
    transport: &T,
    call: &str,
    asn: u32,
    now_unix: u64,
) -> Result<Vec<u8>, LegError> {
    match api_leg::get(
        transport,
        &API,
        &Keys::default(),
        &as_url(call, asn),
        now_unix,
    )? {
        Answer::Body(body) => Ok(body),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// An AS number's holder and the registry block it was assigned from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsOverview {
    pub holder: Option<String>,
    pub announced: bool,
    /// The registry block's range, e.g. `13312-15359`.
    pub block: Option<String>,
    /// e.g. `Assigned by ARIN`.
    pub block_desc: Option<String>,
    pub block_name: Option<String>,
}

#[derive(Deserialize)]
struct OverviewData {
    #[serde(default)]
    holder: Option<String>,
    #[serde(default)]
    announced: bool,
    #[serde(default)]
    block: Option<AsBlock>,
}

#[derive(Deserialize)]
struct AsBlock {
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    desc: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// `as-overview` for `asn`.
///
/// # Errors
/// The [`LegError`] that stopped the call.
pub fn as_overview<T: Transport + ?Sized>(
    transport: &T,
    asn: u32,
    now_unix: u64,
) -> Result<AsOverview, LegError> {
    decode_overview(&as_call(transport, "as-overview", asn, now_unix)?)
}

/// One `as-overview` body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not an `ok` envelope with data.
pub fn decode_overview(body: &[u8]) -> Result<AsOverview, LegError> {
    let data: OverviewData = unwrap(body)?;
    let block = data.block.unwrap_or(AsBlock {
        resource: None,
        desc: None,
        name: None,
    });
    Ok(AsOverview {
        holder: api_leg::clean(data.holder.as_deref()),
        announced: data.announced,
        block: api_leg::clean(block.resource.as_deref()),
        block_desc: api_leg::clean(block.desc.as_deref()),
        block_name: api_leg::clean(block.name.as_deref()),
    })
}

/// One prefix an AS announces, and each window collectors saw it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announced {
    pub prefix: String,
    /// `(start, end)`, as published.
    pub timelines: Vec<(String, String)>,
}

/// Every prefix an AS announces over the query window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Prefixes {
    pub prefixes: Vec<Announced>,
    pub query_start: Option<String>,
    pub query_end: Option<String>,
}

#[derive(Deserialize)]
struct PrefixesData {
    #[serde(default)]
    prefixes: Vec<PrefixRow>,
    #[serde(default)]
    query_starttime: Option<String>,
    #[serde(default)]
    query_endtime: Option<String>,
}

#[derive(Deserialize)]
struct PrefixRow {
    prefix: String,
    #[serde(default)]
    timelines: Vec<Timeline>,
}

#[derive(Deserialize)]
struct Timeline {
    #[serde(default)]
    starttime: Option<String>,
    #[serde(default)]
    endtime: Option<String>,
}

/// `announced-prefixes` for `asn`.
///
/// # Errors
/// The [`LegError`] that stopped the call.
pub fn announced_prefixes<T: Transport + ?Sized>(
    transport: &T,
    asn: u32,
    now_unix: u64,
) -> Result<Prefixes, LegError> {
    decode_prefixes(&as_call(transport, "announced-prefixes", asn, now_unix)?)
}

/// One `announced-prefixes` body, every prefix kept in published order. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not an `ok` envelope with data.
pub fn decode_prefixes(body: &[u8]) -> Result<Prefixes, LegError> {
    let data: PrefixesData = unwrap(body)?;
    Ok(Prefixes {
        prefixes: data
            .prefixes
            .into_iter()
            .filter_map(|row| {
                Some(Announced {
                    prefix: api_leg::clean(Some(&row.prefix))?,
                    timelines: row
                        .timelines
                        .into_iter()
                        .map(|window| {
                            (
                                window.starttime.unwrap_or_default(),
                                window.endtime.unwrap_or_default(),
                            )
                        })
                        .collect(),
                })
            })
            .collect(),
        query_start: data.query_starttime,
        query_end: data.query_endtime,
    })
}

/// One AS adjacent to the queried one in the BGP paths `RIPEstat`'s collectors saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    pub asn: u32,
    /// `left` (nearer the collector in the path, an upstream or peer), `right` (downstream) or
    /// `uncertain`.
    pub relation: String,
    /// How many collector peers saw the adjacency.
    pub power: u64,
    pub v4_peers: u64,
    pub v6_peers: u64,
}

/// Every neighbour of an AS on the query day.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Neighbours {
    pub neighbours: Vec<Neighbour>,
    pub query_start: Option<String>,
}

#[derive(Deserialize)]
struct NeighboursData {
    #[serde(default)]
    neighbours: Vec<NeighbourRow>,
    #[serde(default)]
    query_starttime: Option<String>,
}

#[derive(Deserialize)]
struct NeighbourRow {
    asn: u32,
    #[serde(default, rename = "type")]
    relation: Option<String>,
    #[serde(default)]
    power: u64,
    #[serde(default)]
    v4_peers: u64,
    #[serde(default)]
    v6_peers: u64,
}

/// `asn-neighbours` for `asn`.
///
/// # Errors
/// The [`LegError`] that stopped the call.
pub fn neighbours<T: Transport + ?Sized>(
    transport: &T,
    asn: u32,
    now_unix: u64,
) -> Result<Neighbours, LegError> {
    decode_neighbours(&as_call(transport, "asn-neighbours", asn, now_unix)?)
}

/// One `asn-neighbours` body, every row kept in published order. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not an `ok` envelope with data.
pub fn decode_neighbours(body: &[u8]) -> Result<Neighbours, LegError> {
    let data: NeighboursData = unwrap(body)?;
    Ok(Neighbours {
        neighbours: data
            .neighbours
            .into_iter()
            .map(|row| Neighbour {
                asn: row.asn,
                relation: api_leg::clean(row.relation.as_deref())
                    .unwrap_or_else(|| "uncertain".into()),
                power: row.power,
                v4_peers: row.v4_peers,
                v6_peers: row.v6_peers,
            })
            .collect(),
        query_start: data.query_starttime,
    })
}

#[cfg(test)]
pub(crate) mod tests {
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

    /// Recorded from `RIPEstat` for `AS13335` on 2026-10-15 (envelope fields trimmed).
    pub(crate) const OVERVIEW: &str = r#"{"status":"ok","data":{"type":"as","resource":"13335","block":{"resource":"13312-15359","desc":"Assigned by ARIN","name":"IANA 16-bit Autonomous System (AS) Numbers Registry"},"holder":"CLOUDFLARENET - Cloudflare, Inc.","announced":true}}"#;
    /// Two of `AS13335`'s 5,773 prefixes, recorded 2026-10-15; the second was withdrawn and
    /// announced again.
    pub(crate) const PREFIXES: &str = r#"{"status":"ok","data":{"prefixes":[{"prefix":"2400:cb00:618::/48","timelines":[{"starttime":"2026-10-01T08:00:00","endtime":"2026-10-15T08:00:00"}]},{"prefix":"104.28.238.0/24","timelines":[{"starttime":"2026-10-01T08:00:00","endtime":"2026-10-03T00:00:00"},{"starttime":"2026-10-07T16:00:00","endtime":"2026-10-15T08:00:00"}]}],"query_starttime":"2026-10-01T08:00:00","query_endtime":"2026-10-15T08:00:00","resource":"13335"}}"#;
    /// Three of `AS13335`'s neighbours, recorded 2026-10-15.
    pub(crate) const NEIGHBOURS: &str = r#"{"status":"ok","data":{"resource":"13335","query_starttime":"2026-10-15T00:00:00","neighbour_counts":{"left":1,"right":1,"unique":3,"uncertain":1},"neighbours":[{"asn":10094,"type":"left","power":257,"v4_peers":328,"v6_peers":0},{"asn":13414,"type":"right","power":12,"v4_peers":40,"v6_peers":31},{"asn":6939,"type":"uncertain","power":3,"v4_peers":3,"v6_peers":0}]}}"#;

    #[test]
    fn an_as_overview_names_its_holder_and_registry_block() {
        let overview = decode_overview(OVERVIEW.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            overview,
            AsOverview {
                holder: Some("CLOUDFLARENET - Cloudflare, Inc.".into()),
                announced: true,
                block: Some("13312-15359".into()),
                block_desc: Some("Assigned by ARIN".into()),
                block_name: Some("IANA 16-bit Autonomous System (AS) Numbers Registry".into()),
            }
        );
    }

    #[test]
    fn every_announced_prefix_keeps_every_window_it_was_seen() {
        let found = decode_prefixes(PREFIXES.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(found.prefixes.len(), 2);
        assert_eq!(found.prefixes[1].prefix, "104.28.238.0/24");
        assert_eq!(
            found.prefixes[1].timelines,
            [
                ("2026-10-01T08:00:00".into(), "2026-10-03T00:00:00".into()),
                ("2026-10-07T16:00:00".into(), "2026-10-15T08:00:00".into())
            ]
        );
        assert_eq!(found.query_end.as_deref(), Some("2026-10-15T08:00:00"));
    }

    #[test]
    fn every_neighbour_keeps_its_side_and_how_widely_it_was_seen() {
        let found = decode_neighbours(NEIGHBOURS.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            found.neighbours[1],
            Neighbour {
                asn: 13414,
                relation: "right".into(),
                power: 12,
                v4_peers: 40,
                v6_peers: 31
            }
        );
        assert_eq!(found.neighbours.len(), 3);
        assert_eq!(
            as_url("asn-neighbours", 13335),
            "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS13335"
        );
    }

    #[test]
    fn every_origin_of_a_prefix_is_kept() {
        let origins: Vec<String> = (1..=12)
            .map(|asn| format!(r#"{{"asn":{asn},"holder":"H{asn}"}}"#))
            .collect();
        let body = format!(
            r#"{{"status":"ok","data":{{"announced":true,"asns":[{}],"resource":"1.1.1.0/24"}}}}"#,
            origins.join(",")
        );
        let routing = decode(body.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(routing.origins.len(), 12);
    }

    #[test]
    fn the_address_is_percent_encoded() {
        assert_eq!(
            url("2001:db8::1"),
            "https://stat.ripe.net/data/prefix-overview/data.json?resource=2001%3Adb8%3A%3A1"
        );
    }
}
