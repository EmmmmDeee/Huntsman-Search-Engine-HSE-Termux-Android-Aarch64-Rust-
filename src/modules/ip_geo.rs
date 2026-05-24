//! ip-api.com IP geolocation. Free tier (HTTP only), 45 req/min limit.
//!
//! Yields a Coordinates entity (when lat/lon present) and an Organisation
//! entity (when org/ASN present).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

pub struct IpGeo;

#[derive(Deserialize)]
struct IpApiResp {
    status: String,
    country: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
}

#[async_trait]
impl Module for IpGeo {
    fn name(&self) -> &'static str {
        "ip_geo"
    }

    fn priority(&self) -> u8 {
        28
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // ip-api.com free tier is HTTP only — HTTPS requires paid plan.
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,country,regionName,city,lat,lon,org,as",
            target.value
        );

        // ip-api.com free tier rate-limits at 45 req/min and returns
        // HTTP 429 with a JSON body when exceeded. `fetch_json` surfaces
        // the body as a `module_error`, keeping rate-limit conditions
        // visible (previous silent-empty behaviour hid them).
        let data: IpApiResp = fetch_json(&ctx.http, "ip_geo", &url).await?;

        if data.status != "success" {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        if let (Some(lat), Some(lon)) = (data.lat, data.lon) {
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.70, &ctx.scan_id);
            e.tag("geoint");
            e.add_evidence(
                Evidence::new("ip_geo", format!("IP geolocation for {}", target.value))
                    .with_attr("country", data.country.as_deref().unwrap_or("-"))
                    .with_attr("region", data.region_name.as_deref().unwrap_or("-"))
                    .with_attr("city", data.city.as_deref().unwrap_or("-"))
                    .with_attr("source", "ip-api.com"),
            );
            result.push(e);
        }

        if let Some(org) = &data.org {
            let mut e = Entity::new(EntityKind::Organisation, org, 0.65, &ctx.scan_id);
            e.add_evidence(
                Evidence::new("ip_geo", format!("IP org for {}", target.value))
                    .with_attr("asn", data.asn.as_deref().unwrap_or("-")),
            );
            result.push(e);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = IpGeo;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
