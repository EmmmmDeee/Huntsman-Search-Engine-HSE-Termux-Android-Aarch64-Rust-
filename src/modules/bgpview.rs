//! BGPView — ASN prefix enumeration and IP-to-ASN mapping.
//!
//! Queries the free `bgpview.io` API (no key) for two pivots:
//! - **ASN** → the prefixes it announces (`/asn/{n}/prefixes`) → `IpAddress`
//!   entities (the network blocks), each carrying the owning org name.
//! - **IP** → its PTR records and the prefix/ASN it sits in (`/ip/{ip}`) →
//!   `Domain` (reverse DNS) + `Asn` entities, the latter carrying the announced
//!   CIDR block as context.
//!
//! The response → entity mapping lives in the pure [`asn_prefix_entities`] /
//! [`ip_entities`] so it is unit-tested without a live API; `process` owns only
//! URL construction and transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "bgpview";

/// Output caps, keeping a single ASN/IP lookup bounded.
const MAX_ANNOUNCED_PREFIXES: usize = 20;
const MAX_PTR_RECORDS: usize = 3;
const MAX_IP_PREFIXES: usize = 3;

pub struct BgpView;

#[async_trait]
impl Module for BgpView {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "BGPView ASN prefix enumeration and IP-to-ASN mapping"
    }
    fn priority(&self) -> u8 {
        35
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Asn | TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain, EntityKind::Asn];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::Asn => {
                // Normalise `AS13335` / `as13335` / `13335` → `13335`.
                let asn = target.value.trim().to_uppercase();
                let asn_num = asn.strip_prefix("AS").unwrap_or(&asn);
                let url = format!("https://api.bgpview.io/asn/{asn_num}/prefixes");
                let resp: BgpPrefixResponse =
                    crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;
                if let Some(data) = resp.data {
                    for e in asn_prefix_entities(&data, asn_num, &ctx.scan_id) {
                        result.push(e);
                    }
                }
            }
            TargetKind::IpAddress => {
                let ip = target.value.trim();
                let url = format!("https://api.bgpview.io/ip/{ip}");
                let resp: BgpIpResponse =
                    crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;
                if let Some(data) = resp.data {
                    for e in ip_entities(&data, ip, &ctx.scan_id) {
                        result.push(e);
                    }
                }
            }
            _ => {}
        }

        Ok(result)
    }
}

use crate::util::str_util::nonempty;

/// `IpAddress` entities for the prefixes an ASN announces (the network blocks it
/// owns), each tagged `bgp-prefix` and carrying the owning org name when known.
fn asn_prefix_entities(data: &BgpPrefixData, asn_num: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for prefix in data.ipv4_prefixes.iter().take(MAX_ANNOUNCED_PREFIXES) {
        let cidr = prefix.prefix.trim();
        if cidr.is_empty() {
            continue;
        }
        let mut e = Entity::new(EntityKind::IpAddress, cidr, 0.70, scan_id);
        e.tag("bgp-prefix");
        let mut ev = Evidence::new(SRC, format!("AS{asn_num} announces {cidr}"))
            .with_attr("asn", asn_num)
            .with_attr("prefix", cidr);
        if let Some(name) = nonempty(&prefix.name) {
            ev = ev.with_attr("name", name);
        }
        e.add_evidence(ev);
        out.push(e);
    }
    out
}

/// `Domain` (reverse-DNS PTR) + `Asn` entities for an IP. The `Asn` entity now
/// carries the announced **CIDR block** the IP sits in (`prefix`) — previously
/// parsed and discarded — which is the actionable network-ownership datum.
fn ip_entities(data: &BgpIpData, ip: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    let mut seen_ptr = std::collections::HashSet::new();
    for ptr in data.ptr_record.iter().take(MAX_PTR_RECORDS) {
        // PTRs are often trailing-dot FQDNs; normalise and require a real label.
        let host = ptr.trim().trim_end_matches('.').to_lowercase();
        if host.contains('.') && seen_ptr.insert(host.clone()) {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.65, scan_id);
            e.tag("ptr");
            e.add_evidence(Evidence::new(SRC, format!("PTR record for {ip}")));
            out.push(e);
        }
    }

    for prefix in data.prefixes.iter().take(MAX_IP_PREFIXES) {
        let Some(asn) = prefix.asn.as_ref() else {
            continue;
        };
        let asn_label = format!("AS{}", asn.asn);
        let mut e = Entity::new(EntityKind::Asn, &asn_label, 0.80, scan_id);
        let name = nonempty(&asn.name).unwrap_or("");
        let mut ev = Evidence::new(SRC, format!("{ip} in AS{} ({name})", asn.asn))
            .with_attr("asn", asn.asn.to_string());
        if let Some(name) = nonempty(&asn.name) {
            ev = ev.with_attr("name", name);
        }
        // The announced CIDR block the IP belongs to — the key network datum.
        if let Some(cidr) = nonempty(&prefix.prefix) {
            ev = ev.with_attr("prefix", cidr);
            e.tag(format!("prefix:{cidr}"));
        }
        e.add_evidence(ev);
        out.push(e);
    }

    out
}

#[derive(Deserialize)]
struct BgpPrefixResponse {
    data: Option<BgpPrefixData>,
}

#[derive(Deserialize)]
struct BgpPrefixData {
    #[serde(default)]
    ipv4_prefixes: Vec<BgpPrefix>,
}

#[derive(Deserialize)]
struct BgpPrefix {
    prefix: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct BgpIpResponse {
    data: Option<BgpIpData>,
}

#[derive(Deserialize)]
struct BgpIpData {
    #[serde(default)]
    ptr_record: Vec<String>,
    #[serde(default)]
    prefixes: Vec<BgpIpPrefix>,
}

#[derive(Deserialize)]
struct BgpIpPrefix {
    #[serde(default)]
    prefix: Option<String>,
    asn: Option<BgpAsn>,
}

#[derive(Deserialize)]
struct BgpAsn {
    asn: u64,
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Deserialisation ─────────────────────────────────────────────────
    #[test]
    fn deserialize_prefix_response() {
        let json = r#"{"data":{"ipv4_prefixes":[{"prefix":"1.0.0.0/24","name":"APNIC"}]}}"#;
        let r: BgpPrefixResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.data.unwrap().ipv4_prefixes[0].prefix, "1.0.0.0/24");
    }

    #[test]
    fn deserialize_ip_response() {
        let json = r#"{"data":{"ptr_record":["dns.google"],"prefixes":[{"prefix":"8.8.8.0/24","asn":{"asn":15169,"name":"GOOGLE"}}]}}"#;
        let r: BgpIpResponse = serde_json::from_str(json).unwrap();
        let d = r.data.unwrap();
        assert_eq!(d.ptr_record[0], "dns.google");
        assert_eq!(d.prefixes[0].asn.as_ref().unwrap().asn, 15169);
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = BgpView;
        assert!(m.accepts(&Target::new(TargetKind::Asn, "AS13335")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    // ── ASN → announced prefixes ────────────────────────────────────────
    #[test]
    fn asn_prefix_entities_map_blocks_with_org_name() {
        let data: BgpPrefixData = serde_json::from_str(
            r#"{"ipv4_prefixes":[
                {"prefix":"104.16.0.0/13","name":"CLOUDFLARENET"},
                {"prefix":"1.1.1.0/24"},
                {"prefix":"  "}
            ]}"#,
        )
        .unwrap();
        let es = asn_prefix_entities(&data, "13335", "s");
        // The blank prefix is skipped.
        assert_eq!(es.len(), 2);
        assert!(
            es.iter()
                .all(|e| e.kind == EntityKind::IpAddress && e.has_tag("bgp-prefix"))
        );
        let cf = &es[0];
        assert_eq!(cf.value, "104.16.0.0/13");
        let ev = &cf.evidence[0];
        assert_eq!(ev.attributes.get("asn").map(String::as_str), Some("13335"));
        assert_eq!(
            ev.attributes.get("prefix").map(String::as_str),
            Some("104.16.0.0/13")
        );
        assert_eq!(
            ev.attributes.get("name").map(String::as_str),
            Some("CLOUDFLARENET")
        );
        // No name → no empty `name` attr (the old code wrote "").
        assert!(!es[1].evidence[0].attributes.contains_key("name"));
    }

    #[test]
    fn asn_prefix_entities_respect_the_cap() {
        let prefixes: Vec<_> = (0..30)
            .map(|i| format!(r#"{{"prefix":"10.{i}.0.0/24"}}"#))
            .collect();
        let data: BgpPrefixData =
            serde_json::from_str(&format!(r#"{{"ipv4_prefixes":[{}]}}"#, prefixes.join(",")))
                .unwrap();
        assert_eq!(
            asn_prefix_entities(&data, "1", "s").len(),
            MAX_ANNOUNCED_PREFIXES
        );
    }

    // ── IP → PTR + ASN, now WITH the announced CIDR ─────────────────────
    #[test]
    fn ip_entities_map_ptr_and_asn_with_prefix() {
        let data: BgpIpData = serde_json::from_str(
            r#"{
                "ptr_record":["dns.google.","DNS.GOOGLE.","not-a-host"],
                "prefixes":[{"prefix":"8.8.8.0/24","asn":{"asn":15169,"name":"GOOGLE"}}]
            }"#,
        )
        .unwrap();
        let es = ip_entities(&data, "8.8.8.8", "s");

        // PTRs: trailing dot stripped, lowercased, deduped, non-host dropped.
        let domains: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Domain).collect();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].value, "dns.google");
        assert!(domains[0].has_tag("ptr"));

        // ASN entity carries the announced CIDR (the field the old code dropped).
        let asn: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Asn).collect();
        assert_eq!(asn.len(), 1);
        assert_eq!(asn[0].value, "AS15169");
        let ev = &asn[0].evidence[0];
        assert_eq!(
            ev.attributes.get("prefix").map(String::as_str),
            Some("8.8.8.0/24")
        );
        assert_eq!(
            ev.attributes.get("name").map(String::as_str),
            Some("GOOGLE")
        );
        assert!(asn[0].has_tag("prefix:8.8.8.0/24"));
    }

    #[test]
    fn ip_entities_skip_prefix_without_asn() {
        let data: BgpIpData =
            serde_json::from_str(r#"{"ptr_record":[],"prefixes":[{"prefix":"1.0.0.0/24"}]}"#)
                .unwrap();
        assert!(ip_entities(&data, "1.1.1.1", "s").is_empty());
    }

    #[test]
    fn ip_entities_empty_data_yields_nothing() {
        let data: BgpIpData = serde_json::from_str("{}").unwrap();
        assert!(ip_entities(&data, "9.9.9.9", "s").is_empty());
    }
}
