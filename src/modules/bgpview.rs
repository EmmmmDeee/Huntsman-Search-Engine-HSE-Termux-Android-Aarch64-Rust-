//! BGPView — ASN prefix enumeration and IP-to-ASN mapping.
//!
//! Queries the free bgpview.io API for ASN details, announced prefixes,
//! and peer relationships. No API key required.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "bgpview";

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
                let asn = target.value.trim().to_uppercase();
                let asn_num = asn.strip_prefix("AS").unwrap_or(&asn);
                let url = format!("https://api.bgpview.io/asn/{asn_num}/prefixes");
                let resp: BgpPrefixResponse =
                    crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;

                if let Some(data) = resp.data {
                    for prefix in data.ipv4_prefixes.iter().take(20) {
                        let mut e =
                            Entity::new(EntityKind::IpAddress, &prefix.prefix, 0.70, &ctx.scan_id);
                        e.tag("bgp-prefix");
                        e.add_evidence(
                            Evidence::new(SRC, format!("AS{asn_num} announces {}", prefix.prefix))
                                .with_attr("asn", asn_num)
                                .with_attr("prefix", &prefix.prefix)
                                .with_attr("name", prefix.name.as_deref().unwrap_or("")),
                        );
                        result.push(e);
                    }
                }
            }
            TargetKind::IpAddress => {
                let url = format!("https://api.bgpview.io/ip/{}", target.value.trim());
                let resp: BgpIpResponse =
                    crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;

                if let Some(data) = resp.data {
                    for ptr in data.ptr_record.iter().take(3) {
                        if ptr.contains('.') && !ptr.is_empty() {
                            let mut e = Entity::new(EntityKind::Domain, ptr, 0.65, &ctx.scan_id);
                            e.tag("ptr");
                            e.add_evidence(Evidence::new(
                                SRC,
                                format!("PTR record for {}", target.value),
                            ));
                            result.push(e);
                        }
                    }
                    for prefix in data.prefixes.iter().take(3) {
                        if let Some(ref asn) = prefix.asn {
                            let asn_label = format!("AS{}", asn.asn);
                            let mut e =
                                Entity::new(EntityKind::Asn, &asn_label, 0.80, &ctx.scan_id);
                            e.add_evidence(
                                Evidence::new(
                                    SRC,
                                    format!(
                                        "{} in AS{} ({})",
                                        target.value,
                                        asn.asn,
                                        asn.name.as_deref().unwrap_or("")
                                    ),
                                )
                                .with_attr("asn", asn.asn.to_string())
                                .with_attr("name", asn.name.as_deref().unwrap_or("")),
                            );
                            result.push(e);
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(result)
    }
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

#[allow(dead_code)]
#[derive(Deserialize)]
struct BgpPrefix {
    prefix: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct BgpIpResponse {
    data: Option<BgpIpData>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct BgpIpData {
    #[serde(default)]
    ptr_record: Vec<String>,
    #[serde(default)]
    prefixes: Vec<BgpIpPrefix>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct BgpIpPrefix {
    prefix: Option<String>,
    asn: Option<BgpAsn>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct BgpAsn {
    asn: u64,
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
