//! `PeeringDB` network enrichment for an autonomous system. Keyless -- the public `PeeringDB` API
//! (`GET /api/net?asn=N` for the network record, then `GET /api/netixlan?net_id=<id>` for its
//! public Internet-exchange presence).
//!
//! `PeeringDB` is the operator-maintained registry of networks, exchanges and facilities. For an AS
//! this source adds what RDAP and `RIPEstat` do not: the operator's self-published profile -- its
//! organisation name (an [`EntityKind::Organisation`] candidate, never a confirmed identity), its
//! website (an [`EntityKind::Domain`] pivot), peering policy, traffic level, IRR AS-SET and prefix
//! counts -- and its public Internet-exchange presence, each peering address an
//! [`EntityKind::IpAddress`] pivot carrying the exchange name and port speed. The AS profile folds
//! onto the [`EntityKind::Asn`] entity the RDAP and `RIPEstat` legs also emit, so one AS scan
//! corroborates its holder across registries, and the peering addresses pivot straight into an IP
//! lookup.
//!
//! Evidence integrity is fail-closed, mirroring the merged `gleif`/`wikidata` hardening: a network
//! is accepted only when the `net` response's `asn` is exactly the requested number -- a mismatched
//! or malformed envelope is schema drift, never a positive entity; a 404 or an empty `data` array
//! is a clean zero (most networks simply have no `PeeringDB` record). Every published field is kept
//! verbatim as evidence; nothing is redacted. Secondary exchange rows must match the requested
//! ASN and, when supplied, the selected network ID before any IP pivots are emitted. A peering
//! address is minted only when it canonicalises as an IP, so malformed addresses are not pivots.
//!
//! Network facility-presence (`netfac`) records add bounded, operator-published facility
//! associations without asserting facility ownership or physical device location. Public points
//! of contact (`poc`) remain a separate, deliberately unimplemented follow-up.

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::Deserialize;

use crate::canonical::canonical_ip;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{DEFAULT_USER_AGENT, Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "peeringdb";
const PUBLIC_BASE: &str = "https://www.peeringdb.com/api";
const DATASET: &str = "PeeringDB";

/// The operator organisation and the AS profile: a self-published registry record, a candidate.
const NET_CONF: f64 = 0.65;
/// A peering address the operator published at a public exchange.
const PEER_IP_CONF: f64 = 0.80;
/// A self-published network/facility association, not proof of ownership or device location.
const FACILITY_CONF: f64 = 0.55;
/// Bound secondary response processing and avoid silently accepting incomplete large listings.
const MAX_FACILITY_ROWS: usize = 100;

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// The list envelope every `PeeringDB` endpoint returns: `{"data": [...], "meta": {...}}`. A missing
/// `data` is schema drift, not an observed empty registry.
#[derive(Debug, Deserialize)]
struct Envelope<T> {
    data: Option<Vec<T>>,
}

/// The `net` record. Only the fields kept as evidence or used for gating are modelled; unknown
/// fields are ignored by serde.
#[derive(Debug, Deserialize)]
struct Net {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    aka: Option<String>,
    #[serde(default)]
    website: Option<String>,
    #[serde(default)]
    irr_as_set: Option<String>,
    #[serde(default)]
    info_type: Option<String>,
    #[serde(default)]
    info_traffic: Option<String>,
    #[serde(default)]
    info_ratio: Option<String>,
    #[serde(default)]
    info_scope: Option<String>,
    #[serde(default)]
    info_prefixes4: Option<u64>,
    #[serde(default)]
    info_prefixes6: Option<u64>,
    #[serde(default)]
    policy_general: Option<String>,
    #[serde(default)]
    policy_url: Option<String>,
    #[serde(default)]
    ix_count: Option<u64>,
    #[serde(default)]
    fac_count: Option<u64>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    updated: Option<String>,
}

/// One `netixlan` record: the network's presence at one Internet exchange LAN.
#[derive(Debug, Deserialize)]
struct NetIxLan {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    net_id: Option<u64>,
    #[serde(default)]
    speed: Option<u64>,
    #[serde(default)]
    ipaddr4: Option<String>,
    #[serde(default)]
    ipaddr6: Option<String>,
    #[serde(default)]
    is_rs_peer: Option<bool>,
    #[serde(default)]
    operational: Option<bool>,
}

/// A network's presence at a public facility. The network ID is mandatory for attribution;
/// the facility ID is the stable identity key. The optional local ASN is a consistency check.
#[derive(Debug, Deserialize)]
struct NetFac {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    net_id: Option<u64>,
    #[serde(default)]
    fac_id: Option<u64>,
    #[serde(default)]
    local_asn: Option<u32>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    updated: Option<String>,
}

/// The `/api/net?asn=N` URL. `asn` is a `u32`, so the query needs no escaping. **Pure.**
#[must_use]
pub fn net_url(asn: u32) -> String {
    format!("{PUBLIC_BASE}/net?asn={asn}")
}

/// The `/api/netixlan?net_id=<id>` URL, filtered so the response stays small (an unfiltered
/// `netixlan` list runs to many megabytes). `net_id` is a `u64`, so it needs no escaping. **Pure.**
#[must_use]
pub fn netixlan_url(net_id: u64) -> String {
    format!("{PUBLIC_BASE}/netixlan?net_id={net_id}")
}

/// The filtered network/facility association endpoint. No unbounded registry-wide query.
#[must_use]
pub fn netfac_url(net_id: u64) -> String {
    format!("{PUBLIC_BASE}/netfac?net_id={net_id}")
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", DEFAULT_USER_AGENT)
}

fn options() -> FetchOptions {
    FetchOptions::no_redirects().paced()
}

/// Look up one AS on `PeeringDB`: its network profile, and -- when the profile reports exchange
/// presence -- the peering addresses from its `netixlan` records.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch of the primary `net` record refuses the
/// URL. A failure of the secondary `netixlan` fetch does not abort the leg: the network profile is
/// still reported and the failure is noted in the outcome detail.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    asn: u32,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let fetched = fetch(
        transport,
        request(net_url(asn)),
        None,
        &options(),
        SOURCE,
        now_unix,
    )?;
    let status = fetched.response.as_ref().map(|response| response.status);
    let net = match interpret_net(&fetched, asn, now_unix) {
        Ok(net) => net,
        Err(outcome) => return Ok(miss(outcome)),
    };

    let mut entities = Vec::new();
    build_net_entities(&net, asn, scan_id, &mut entities);
    let mut detail = net_summary(&net, asn);

    if net.ix_count.unwrap_or(0) > 0 {
        if let Some(net_id) = net.id {
            match ixlan_entities(transport, net_id, asn, scan_id, now_unix) {
                Ok((peering, records)) => {
                    let _ = write!(
                        detail,
                        "; netixlan: {records} exchange records, {} peering address(es)",
                        peering.len()
                    );
                    entities.extend(peering);
                }
                Err(reason) => {
                    let _ = write!(detail, "; netixlan unavailable: {reason}");
                }
            }
        }
    }

    if net.fac_count.unwrap_or(0) > 0 {
        if net.fac_count.unwrap_or(0) > MAX_FACILITY_ROWS as u64 {
            let _ = write!(
                detail,
                "; netfac skipped: facility count exceeds bounded {MAX_FACILITY_ROWS}-record limit"
            );
        } else if let Some(net_id) = net.id {
            match facility_entities(
                transport,
                net_id,
                asn,
                usize::try_from(net.fac_count.unwrap_or(0)).unwrap_or(MAX_FACILITY_ROWS + 1),
                scan_id,
                now_unix,
            ) {
                Ok((facilities, records)) => {
                    let _ = write!(detail, "; netfac: {records} facility presence record(s)");
                    entities.extend(facilities);
                }
                Err(reason) => {
                    let _ = write!(detail, "; netfac unavailable: {reason}");
                }
            }
        } else {
            let _ = write!(detail, "; netfac unavailable: network ID missing");
        }
    }

    merge_by_uid(&mut entities);
    let mut outcome =
        SourceExecutionOutcome::success(SOURCE, now_unix, entities.len()).with_detail(detail);
    if let Some(status) = status {
        outcome = outcome.with_http_status(status);
    }
    Ok(Report { entities, outcome })
}

/// A report that found nothing, carrying only its outcome. **Pure.**
fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

/// The confirmed `net` record, or the outcome of a lookup that named nothing usable. A 404 or an
/// empty `data` array is a clean zero; a 200 whose record is for a different ASN, or a malformed
/// envelope, is schema drift -- never attributed to the requested AS. **Pure.**
fn interpret_net(
    fetched: &Fetched,
    asn: u32,
    now_unix: u64,
) -> Result<Net, SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx {
            return Err(SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
                .with_http_status(response.status));
        }
    }
    let response = whole_response(fetched, "PeeringDB net")?;
    answer(fetched, "PeeringDB net")?;
    let envelope: Envelope<Net> = decode_json(response, SOURCE, now_unix, "PeeringDB net")?;
    let Some(data) = envelope.data else {
        return Err(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "PeeringDB net response lacked the required data array",
        ));
    };
    // The ASN query is expected to select one network. Never silently take the
    // first row of an ambiguous response: a later row may contradict attribution.
    if data.len() > 1 {
        return Err(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "PeeringDB net response contained multiple records for one ASN",
        ));
    }
    let Some(net) = data.into_iter().next() else {
        return Err(
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status)
        );
    };
    if net.asn != Some(asn) {
        return Err(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "PeeringDB net record was for a different ASN than requested",
        ));
    }
    Ok(net)
}

/// The network profile as entities: the AS itself (so the profile folds onto the RDAP/`RIPEstat` AS
/// entity), the operator organisation, and the official website as a `Domain` pivot. **Pure.**
fn build_net_entities(net: &Net, asn: u32, scan_id: &str, entities: &mut Vec<Entity>) {
    let evidence = net_evidence(net, asn, scan_id);

    let mut as_entity = Entity::new(EntityKind::Asn, format!("AS{asn}"), NET_CONF, scan_id);
    as_entity.tag(SOURCE);
    as_entity.tag("peeringdb");
    as_entity.add_evidence(evidence.clone());
    entities.push(as_entity);

    if let Some(name) = trimmed(net.name.as_deref()) {
        let mut org = Entity::new(EntityKind::Organisation, name, NET_CONF, scan_id);
        org.tag(SOURCE);
        org.tag("peeringdb");
        org.add_evidence(evidence.clone().with_attr("asn", format!("AS{asn}")));
        entities.push(org);
    }

    if let Some(website) = trimmed(net.website.as_deref()) {
        if let Some((kind, host)) = crate::domains::link_host(website) {
            let mut entity = Entity::new(kind, host, NET_CONF, scan_id);
            entity.tag(SOURCE);
            entity.tag("peeringdb");
            entity.tag("peeringdb-website");
            entity.add_evidence(evidence.clone().with_attr("official_website", website));
            entities.push(entity);
        }
    }
}

/// The shared evidence for the network profile: every published field kept verbatim (no redaction),
/// labelled as a candidate operator record, never a confirmed identity. **Pure.**
fn net_evidence(net: &Net, asn: u32, scan_id: &str) -> Evidence {
    let name = trimmed(net.name.as_deref());
    let summary = name.map_or_else(
        || format!("PeeringDB network AS{asn}: an operator-published registry profile, a candidate to review"),
        |name| format!("PeeringDB network {name} (AS{asn}): an operator-published registry profile, a candidate to review, not a confirmed identity"),
    );
    Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
        .with_attr("dataset", DATASET)
        .with_attr("asn", format!("AS{asn}"))
        .with_attr("ix_count", net.ix_count.unwrap_or(0).to_string())
        .with_attr("fac_count", net.fac_count.unwrap_or(0).to_string())
        .with_optional_attrs([
            ("name", name),
            ("aka", trimmed(net.aka.as_deref())),
            ("website", trimmed(net.website.as_deref())),
            ("irr_as_set", trimmed(net.irr_as_set.as_deref())),
            ("info_type", trimmed(net.info_type.as_deref())),
            ("info_traffic", trimmed(net.info_traffic.as_deref())),
            ("info_ratio", trimmed(net.info_ratio.as_deref())),
            ("info_scope", trimmed(net.info_scope.as_deref())),
            ("policy_general", trimmed(net.policy_general.as_deref())),
            ("policy_url", trimmed(net.policy_url.as_deref())),
            ("notes", trimmed(net.notes.as_deref())),
            ("created", trimmed(net.created.as_deref())),
            ("updated", trimmed(net.updated.as_deref())),
        ])
        .with_attr(
            "info_prefixes4",
            net.info_prefixes4.unwrap_or(0).to_string(),
        )
        .with_attr(
            "info_prefixes6",
            net.info_prefixes6.unwrap_or(0).to_string(),
        )
}

/// A one-line summary of the profile for the outcome detail. **Pure.**
fn net_summary(net: &Net, asn: u32) -> String {
    let who = trimmed(net.name.as_deref()).unwrap_or("network");
    format!(
        "net: AS{asn} {who}, {} IXP / {} facility records published",
        net.ix_count.unwrap_or(0),
        net.fac_count.unwrap_or(0)
    )
}

/// Fetch and interpret the network's `netixlan` records, returning the peering-address entities and
/// how many exchange records were read. A failure is returned as a human reason so the caller can
/// note it without aborting the whole leg.
fn ixlan_entities<T: Transport + ?Sized>(
    transport: &T,
    net_id: u64,
    expected_asn: u32,
    scan_id: &str,
    now_unix: u64,
) -> Result<(Vec<Entity>, usize), String> {
    let fetched = fetch(
        transport,
        request(netixlan_url(net_id)),
        None,
        &options(),
        SOURCE,
        now_unix,
    )
    .map_err(|error| error.to_string())?;
    let response = whole_response(&fetched, "PeeringDB netixlan")
        .map_err(|_| "no usable response".to_owned())?;
    answer(&fetched, "PeeringDB netixlan").map_err(|_| "not an answer".to_owned())?;
    let envelope: Envelope<NetIxLan> =
        decode_json(response, SOURCE, now_unix, "PeeringDB netixlan")
            .map_err(|_| "unreadable netixlan body".to_owned())?;
    let records = envelope
        .data
        .ok_or_else(|| "netixlan schema drift: missing data array".to_owned())?;
    // The URL filter is not an attribution guarantee. Fail the whole secondary leg
    // rather than emitting any IP when a row contradicts the selected AS/network.
    if records.iter().any(|record| {
        record.asn != Some(expected_asn)
            || record.net_id.is_some_and(|record_id| record_id != net_id)
    }) {
        return Err("netixlan schema drift: missing/foreign ASN or foreign network ID".to_owned());
    }
    let count = records.len();
    let mut entities = Vec::new();
    for record in &records {
        add_peering_ips(record, scan_id, &mut entities);
    }
    Ok((entities, count))
}

/// Each canonical peering address of one exchange record as an `IpAddress` pivot, with the exchange
/// name, port speed and peering flags kept verbatim as evidence. A value that does not canonicalise
/// as an IP is skipped (fail-closed), never minted as a fabricated address. **Pure.**
fn add_peering_ips(record: &NetIxLan, scan_id: &str, entities: &mut Vec<Entity>) {
    let exchange = trimmed(record.name.as_deref());
    for raw in [record.ipaddr4.as_deref(), record.ipaddr6.as_deref()]
        .into_iter()
        .flatten()
    {
        let Some(ip) = canonical_ip(raw.trim()) else {
            continue;
        };
        let summary = exchange.map_or_else(
            || "PeeringDB peering address".to_owned(),
            |exchange| format!("PeeringDB peering address at {exchange}"),
        );
        let mut evidence = Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
            .with_attr("dataset", DATASET)
            .with_optional_attrs([("exchange", exchange)]);
        if let Some(asn) = record.asn {
            evidence = evidence.with_attr("asn", format!("AS{asn}"));
        }
        if let Some(speed) = record.speed {
            evidence = evidence.with_attr("speed_mbps", speed.to_string());
        }
        if let Some(is_rs_peer) = record.is_rs_peer {
            evidence = evidence.with_attr("route_server_peer", is_rs_peer.to_string());
        }
        if let Some(operational) = record.operational {
            evidence = evidence.with_attr("operational", operational.to_string());
        }
        let mut entity = Entity::new(EntityKind::IpAddress, ip, PEER_IP_CONF, scan_id);
        entity.tag(SOURCE);
        entity.tag("peeringdb");
        entity.tag("peeringdb-peering-ip");
        entity.add_evidence(evidence);
        entities.push(entity);
    }
}

/// Fetch a bounded network/facility presence list. Reject the entire secondary leg if any
/// record contradicts the requested network or ASN, or if the response exceeds the cap.
/// A failed secondary request never discards the independently observed AS profile.
fn facility_entities<T: Transport + ?Sized>(
    transport: &T,
    net_id: u64,
    expected_asn: u32,
    expected_count: usize,
    scan_id: &str,
    now_unix: u64,
) -> Result<(Vec<Entity>, usize), String> {
    let fetched = fetch(
        transport,
        request(netfac_url(net_id)),
        None,
        &options(),
        SOURCE,
        now_unix,
    )
    .map_err(|error| error.to_string())?;
    let response = whole_response(&fetched, "PeeringDB netfac")
        .map_err(|_| "no usable response".to_owned())?;
    answer(&fetched, "PeeringDB netfac").map_err(|_| "not an answer".to_owned())?;
    let envelope: Envelope<NetFac> = decode_json(response, SOURCE, now_unix, "PeeringDB netfac")
        .map_err(|_| "unreadable netfac body".to_owned())?;
    let records = envelope
        .data
        .ok_or_else(|| "netfac schema drift: missing data array".to_owned())?;
    if records.len() > MAX_FACILITY_ROWS {
        return Err("netfac response exceeded bounded record limit".to_owned());
    }
    if records.len() != expected_count {
        return Err("netfac response count differs from network facility count".to_owned());
    }
    if records.iter().any(|record| {
        record.net_id != Some(net_id)
            || record.fac_id.is_none_or(|id| id == 0)
            || record.local_asn.is_some_and(|asn| asn != expected_asn)
            || record
                .status
                .as_deref()
                .is_some_and(|status| status != "ok")
    }) {
        return Err(
            "netfac schema drift: foreign network, invalid facility, or foreign local ASN"
                .to_owned(),
        );
    }
    let mut seen = HashSet::new();
    if records
        .iter()
        .any(|record| !seen.insert(record.fac_id.expect("validated facility ID")))
    {
        return Err("netfac schema drift: duplicate facility ID".to_owned());
    }
    let count = records.len();
    let mut entities = Vec::with_capacity(count);
    for record in &records {
        let fac_id = record.fac_id.expect("validated facility ID");
        let name = trimmed(record.name.as_deref());
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, scan_id),
            "PeeringDB self-published network/facility presence; not facility ownership or device geolocation",
        )
        .with_attr("dataset", DATASET)
        .with_attr("asn", format!("AS{expected_asn}"))
        .with_attr("network_id", net_id.to_string())
        .with_attr("facility_id", fac_id.to_string())
        .with_attr("attribution", "network presence only; no facility ownership or device location")
        .with_optional_attrs([
            ("facility_name", name),
            ("city", trimmed(record.city.as_deref())),
            ("country", trimmed(record.country.as_deref())),
            ("status", trimmed(record.status.as_deref())),
            ("created", trimmed(record.created.as_deref())),
            ("updated", trimmed(record.updated.as_deref())),
        ]);
        if let Some(record_id) = record.id {
            evidence = evidence.with_attr("presence_record_id", record_id.to_string());
        }
        if let Some(local_asn) = record.local_asn {
            evidence = evidence.with_attr("local_asn", local_asn.to_string());
        }
        // Other is a non-dispatchable stable registry key, not an Address/Coordinates pivot.
        let mut entity = Entity::new(
            EntityKind::Other,
            format!("peeringdb:facility:{fac_id}"),
            FACILITY_CONF,
            scan_id,
        );
        entity.tag(SOURCE);
        entity.tag("peeringdb");
        entity.tag("peeringdb-facility-presence");
        entity.add_evidence(evidence);
        entities.push(entity);
    }
    Ok((entities, count))
}

/// `value` trimmed, when it is present and not blank. **Pure.**
fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::{ScriptedTransport, json_ok};

    // A realistic PeeringDB `net` envelope for AS3333 (RIPE NCC), trimmed to the modelled fields.
    const NET: &str = r#"{"data":[{
        "id":5104,"asn":3333,"name":"RIPE NCC","aka":"Réseaux IP Européens NCC",
        "website":"http://www.ripe.net","irr_as_set":"AS-RIPENCC","info_type":"Non-Profit",
        "info_traffic":"1-5Gbps","info_ratio":"Balanced","info_scope":"Global",
        "info_prefixes4":30,"info_prefixes6":20,"policy_general":"Selective",
        "policy_url":"","ix_count":2,"fac_count":0,"notes":"",
        "created":"2012-11-09T06:06:08Z","updated":"2025-10-21T05:51:32Z"
    }],"meta":{}}"#;

    // Two exchange records: an IPv4+IPv6 peering at NL-ix, and an IPv6-only peering at AMS-IX.
    const NETIXLAN: &str = r#"{"data":[
        {"name":"NL-ix: Main","asn":3333,"speed":10000,"ipaddr4":"193.239.117.25","ipaddr6":"2001:7f8:13::a500:3333:1","is_rs_peer":true,"operational":true},
        {"name":"AMS-IX","asn":3333,"speed":100000,"ipaddr4":null,"ipaddr6":"2001:7f8:1::a500:3333:1","is_rs_peer":false,"operational":true}
    ],"meta":{}}"#;

    fn report_of(responses: Vec<Result<Response, crate::http::TransportFailure>>) -> Report {
        let transport = ScriptedTransport::new(responses);
        lookup(&transport, 3333, "scan-peeringdb", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|entity| entity.kind == *kind && entity.raw_value == value)
    }

    fn as_attr<'a>(report: &'a Report, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Asn)
            .and_then(|entity| entity.evidence.first())
            .and_then(|evidence| evidence.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn a_confirmed_net_emits_as_org_and_website_with_fields_verbatim() {
        let report = report_of(vec![Ok(json_ok(NET)), Ok(json_ok(NETIXLAN))]);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Asn, "AS3333"));
        assert!(has(&report, &EntityKind::Organisation, "RIPE NCC"));
        // The operator organisation is a modest candidate, never a confirmed identity: its
        // confidence is the source constant and well below a confirmed-identity level, so a
        // calibration regression toward 1.0 is caught.
        let org = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Organisation && e.raw_value == "RIPE NCC")
            .expect("the operator organisation is an entity");
        assert!(
            (org.confidence - NET_CONF).abs() < f64::EPSILON && org.confidence < 0.9,
            "operator org must stay a candidate, not a confirmed identity: {}",
            org.confidence
        );
        // The official website becomes a Domain pivot the domain lookup can take.
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.raw_value.ends_with("ripe.net")),
            "{:#?}",
            report.entities
        );
        // Every published field is kept verbatim as evidence on the AS entity.
        assert_eq!(as_attr(&report, "irr_as_set"), Some("AS-RIPENCC"));
        assert_eq!(as_attr(&report, "info_type"), Some("Non-Profit"));
        assert_eq!(as_attr(&report, "info_traffic"), Some("1-5Gbps"));
        assert_eq!(as_attr(&report, "policy_general"), Some("Selective"));
        assert_eq!(as_attr(&report, "info_prefixes4"), Some("30"));
        assert_eq!(as_attr(&report, "ix_count"), Some("2"));
    }

    #[test]
    fn netixlan_peering_addresses_become_ip_pivots() {
        let report = report_of(vec![Ok(json_ok(NET)), Ok(json_ok(NETIXLAN))]);
        // The IPv4 peering address is a canonical IpAddress pivot.
        assert!(has(&report, &EntityKind::IpAddress, "193.239.117.25"));
        // Both exchange records' IPv6 addresses surface too (three peering addresses in all).
        let ips = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::IpAddress)
            .count();
        assert_eq!(ips, 3, "{:#?}", report.entities);
        // The exchange name and port speed are kept as evidence on the peering address.
        let peering = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress && e.raw_value == "193.239.117.25")
            .expect("the v4 peering address is an entity");
        let evidence = peering.evidence.first().expect("peering evidence");
        assert_eq!(
            evidence.attributes.get("exchange").map(String::as_str),
            Some("NL-ix: Main")
        );
        assert_eq!(
            evidence.attributes.get("speed_mbps").map(String::as_str),
            Some("10000")
        );
        // The route-server and operational flags are kept as evidence too.
        assert_eq!(
            evidence
                .attributes
                .get("route_server_peer")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            evidence.attributes.get("operational").map(String::as_str),
            Some("true")
        );
        // A peering address is a lead pivot, never a confirmed identity: its confidence is the
        // source constant and stays below a confirmed-identity level.
        assert!(
            (peering.confidence - PEER_IP_CONF).abs() < f64::EPSILON && peering.confidence < 0.9,
            "peering address must stay a lead pivot: {}",
            peering.confidence
        );
        // The success detail names the netixlan work, so dropping it is caught.
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("peering address(es)"),
            "netixlan success detail: {:?}",
            report.outcome.detail
        );
    }

    #[test]
    fn netixlan_requires_matching_asn_and_network_id_before_emitting_any_ips() {
        // Reject a foreign ASN, missing ASN, contradictory network ID, and a mixed
        // response where an otherwise valid row precedes a foreign one. In all
        // cases preserve the verified network profile, but withhold every IP pivot.
        for body in [
            r#"{"data":[{"asn":9999,"net_id":5104,"ipaddr4":"203.0.113.77"}]}"#,
            r#"{"data":[{"net_id":5104,"ipaddr4":"203.0.113.77"}]}"#,
            r#"{"data":[{"asn":3333,"net_id":42,"ipaddr4":"203.0.113.77"}]}"#,
            r#"{"data":[{"asn":3333,"net_id":5104,"ipaddr4":"193.239.117.25"},{"asn":9999,"net_id":5104,"ipaddr4":"203.0.113.77"}]}"#,
            r#"{"meta":{}}"#,
        ] {
            let report = report_of(vec![Ok(json_ok(NET)), Ok(json_ok(body))]);
            assert!(has(&report, &EntityKind::Asn, "AS3333"));
            assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
            assert!(
                !report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::IpAddress),
                "a contradictory netixlan response must not emit any IP: {:#?}",
                report.entities
            );
            assert!(
                report
                    .outcome
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("netixlan unavailable"),
                "schema drift must be visible in outcome detail: {:?}",
                report.outcome.detail
            );
        }

        let valid = r#"{"data":[{"asn":3333,"net_id":5104,"ipaddr4":"193.239.117.25"}]}"#;
        let report = report_of(vec![Ok(json_ok(NET)), Ok(json_ok(valid))]);
        assert!(has(&report, &EntityKind::IpAddress, "193.239.117.25"));
    }

    #[test]
    fn a_malformed_peering_address_is_skipped_not_minted() {
        let bad = r#"{"data":[{"name":"Bad IX","asn":3333,"ipaddr4":"not-an-ip","ipaddr6":"also::bad::nope"}],"meta":{}}"#;
        let report = report_of(vec![Ok(json_ok(NET)), Ok(json_ok(bad))]);
        assert!(
            !report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::IpAddress),
            "a value that does not canonicalise as an IP must not be minted: {:#?}",
            report.entities
        );
        // The network profile still stands.
        assert!(has(&report, &EntityKind::Asn, "AS3333"));
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn a_record_for_a_different_asn_is_schema_drift() {
        let other = r#"{"data":[{"id":1,"asn":15169,"name":"Someone Else"}],"meta":{}}"#;
        let report = report_of(vec![Ok(json_ok(other))]);
        assert!(report.entities.is_empty(), "{:#?}", report.entities);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn a_multi_record_net_response_is_schema_drift_not_attribution() {
        // PeeringDB's ASN-filtered primary response must identify exactly one network.
        // Previously a valid first record hid contradictory or duplicate later rows.
        for body in [
            r#"{"data":[{"id":5104,"asn":3333,"name":"RIPE NCC"},{"id":9,"asn":9999,"name":"Foreign"}]}"#,
            r#"{"data":[{"id":9,"asn":9999,"name":"Foreign"},{"id":5104,"asn":3333,"name":"RIPE NCC"}]}"#,
            r#"{"data":[{"id":5104,"asn":3333,"name":"RIPE NCC"},{"id":99,"asn":3333,"name":"Conflicting duplicate"}]}"#,
        ] {
            let report = report_of(vec![Ok(json_ok(body))]);
            assert!(
                report.entities.is_empty(),
                "an ambiguous primary envelope must not mint entities: {:#?}",
                report.entities
            );
            assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
        }
    }

    #[test]
    fn an_unknown_as_404_is_a_clean_zero() {
        let not_found = Response {
            status: 404,
            headers: Vec::new(),
            body: br#"{"data":[],"meta":{"error":"Entity not found"}}"#.to_vec(),
            truncated: false,
        };
        let report = report_of(vec![Ok(not_found)]);
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn an_empty_data_array_is_a_clean_zero() {
        let report = report_of(vec![Ok(json_ok(r#"{"data":[],"meta":{}}"#))]);
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_missing_data_array_is_schema_drift() {
        let report = report_of(vec![Ok(json_ok(r#"{"meta":{"error":"boom"}}"#))]);
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn ix_count_zero_skips_the_netixlan_fetch() {
        // fac_count and ix_count are both 0 here, so only the net record is fetched.
        let no_ix = r#"{"data":[{"id":5104,"asn":3333,"name":"RIPE NCC","ix_count":0,"fac_count":0}],"meta":{}}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(no_ix))]);
        let report = lookup(&transport, 3333, "scan-peeringdb", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(
            transport.seen.borrow().len(),
            1,
            "a zero ix_count must not trigger a netixlan request"
        );
        assert!(
            !report
                .outcome
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("netixlan"),
            "no netixlan work should be reported: {:?}",
            report.outcome.detail
        );
    }

    #[test]
    fn a_netixlan_failure_keeps_the_net_profile() {
        // The net record is good; the netixlan fetch fails (exhausted script -> ConnectFailure).
        let transport = ScriptedTransport::new(vec![Ok(json_ok(NET))]);
        let report = lookup(&transport, 3333, "scan-peeringdb", 1).expect("runs");
        // The profile still stands and the leg is a success, with the sub-failure noted.
        assert!(has(&report, &EntityKind::Asn, "AS3333"));
        assert!(has(&report, &EntityKind::Organisation, "RIPE NCC"));
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("netixlan unavailable"),
            "a netixlan failure must be noted without aborting: {:?}",
            report.outcome.detail
        );
    }

    #[test]
    fn network_facility_presence_is_attributed_without_location_or_ownership_claims() {
        let net =
            r#"{"data":[{"id":5104,"asn":3333,"name":"RIPE NCC","ix_count":0,"fac_count":2}]}"#;
        let facilities = r#"{"data":[
            {"net_id":5104,"fac_id":44,"local_asn":3333,"name":"Facility Alpha","city":"Amsterdam","country":"NL"},
            {"net_id":5104,"fac_id":45,"name":"Facility Beta","city":"Frankfurt","country":"DE"}
        ]}"#;
        let report = report_of(vec![Ok(json_ok(net)), Ok(json_ok(facilities))]);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Other, "peeringdb:facility:44"));
        assert!(has(&report, &EntityKind::Other, "peeringdb:facility:45"));
        assert!(
            !report
                .entities
                .iter()
                .any(|e| matches!(e.kind, EntityKind::Address | EntityKind::Coordinates))
        );
        let facility = report
            .entities
            .iter()
            .find(|e| e.raw_value == "peeringdb:facility:44")
            .expect("facility");
        assert!(facility.confidence < 0.9);
        let evidence = facility.evidence.first().expect("facility evidence");
        assert_eq!(
            evidence.attributes.get("city").map(String::as_str),
            Some("Amsterdam")
        );
        assert_eq!(
            evidence.attributes.get("local_asn").map(String::as_str),
            Some("3333")
        );
        assert!(evidence.summary.contains("not facility ownership"));
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("2 facility presence")
        );
    }

    #[test]
    fn netfac_rejects_misattribution_and_malformed_envelopes_atomically() {
        let net = r#"{"data":[{"id":5104,"asn":3333,"fac_count":1}]}"#;
        for body in [
            r#"{"data":[{"net_id":999,"fac_id":44,"name":"Foreign"}]}"#,
            r#"{"data":[{"fac_id":44,"name":"Missing network"}]}"#,
            r#"{"data":[{"net_id":5104,"name":"Missing facility"}]}"#,
            r#"{"data":[{"net_id":5104,"fac_id":0}]}"#,
            r#"{"data":[{"net_id":5104,"fac_id":44,"local_asn":9999}]}"#,
            r#"{"data":[{"net_id":5104,"fac_id":44},{"net_id":999,"fac_id":45}]}"#,
            r#"{"data":[{"net_id":5104,"fac_id":44,"status":"deleted"}]}"#,
            r#"{"meta":{}}"#,
        ] {
            let report = report_of(vec![Ok(json_ok(net)), Ok(json_ok(body))]);
            assert!(has(&report, &EntityKind::Asn, "AS3333"));
            assert!(
                !report
                    .entities
                    .iter()
                    .any(|e| e.raw_value.starts_with("peeringdb:facility:"))
            );
            assert!(
                report
                    .outcome
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("netfac unavailable")
            );
        }
    }

    #[test]
    fn netfac_requires_complete_nonduplicated_facility_presence() {
        let net = r#"{"data":[{"id":5104,"asn":3333,"fac_count":2}]}"#;
        for body in [
            r#"{"data":[{"net_id":5104,"fac_id":44}]}"#,
            r#"{"data":[{"net_id":5104,"fac_id":44},{"net_id":5104,"fac_id":44}]}"#,
        ] {
            let report = report_of(vec![Ok(json_ok(net)), Ok(json_ok(body))]);
            assert!(has(&report, &EntityKind::Asn, "AS3333"));
            assert!(
                !report
                    .entities
                    .iter()
                    .any(|e| e.raw_value.starts_with("peeringdb:facility:"))
            );
            assert!(
                report
                    .outcome
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("netfac unavailable")
            );
        }
    }

    #[test]
    fn netfac_is_bounded_and_secondary_failure_preserves_profile() {
        let too_many = r#"{"data":[{"id":5104,"asn":3333,"fac_count":101}]}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(too_many))]);
        let report = lookup(&transport, 3333, "scan-peeringdb", 1).expect("runs");
        assert_eq!(transport.seen.borrow().len(), 1);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("netfac skipped")
        );
        let net = r#"{"data":[{"id":5104,"asn":3333,"fac_count":1}]}"#;
        let report = report_of(vec![Ok(json_ok(net))]);
        assert!(has(&report, &EntityKind::Asn, "AS3333"));
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("netfac unavailable")
        );
    }

    #[test]
    fn the_urls_filter_by_asn_and_net_id() {
        assert_eq!(net_url(3333), "https://www.peeringdb.com/api/net?asn=3333");
        assert_eq!(
            netixlan_url(5104),
            "https://www.peeringdb.com/api/netixlan?net_id=5104"
        );
        assert_eq!(
            netfac_url(5104),
            "https://www.peeringdb.com/api/netfac?net_id=5104"
        );
    }
}
