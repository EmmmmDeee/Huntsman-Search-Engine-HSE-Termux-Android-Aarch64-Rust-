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
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
    #[serde(default)]
    mobile: Option<bool>,
    #[serde(default)]
    proxy: Option<bool>,
    #[serde(default)]
    hosting: Option<bool>,
}

#[async_trait]
impl Module for IpGeo {
    fn name(&self) -> &'static str {
        "ip_geo"
    }

    fn description(&self) -> &'static str {
        "IP geolocation, ISP, proxy and hosting detection"
    }

    fn priority(&self) -> u8 {
        28
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting",
            target.value
        );

        let data: IpApiResp = fetch_json(&ctx.http, "ip_geo", &url).await?;

        if data.status != "success" {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        if let (Some(lat), Some(lon)) = (data.lat, data.lon) {
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.70, &ctx.scan_id);
            e.tag("geoint");
            if let Some(cc) = data.country_code.as_deref() {
                e.tag(format!("country:{}", cc.to_uppercase()));
            }
            e.tag_opt(data.proxy, "proxy");
            e.tag_opt(data.hosting, "hosting");
            e.tag_opt(data.mobile, "mobile");
            e.add_evidence(
                Evidence::new("ip_geo", format!("IP geolocation for {}", target.value))
                    .with_attr("country", data.country.as_deref().unwrap_or("-"))
                    .with_attr("region", data.region_name.as_deref().unwrap_or("-"))
                    .with_attr("city", data.city.as_deref().unwrap_or("-"))
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string())
                    .with_attr("source", "ip-api.com")
                    .with_opt_attr("country_code", data.country_code.as_deref())
                    .with_opt_attr("zip", data.zip.as_deref())
                    .with_opt_attr("timezone", data.timezone.as_deref())
                    .with_opt_attr("isp", data.isp.as_deref())
                    .with_opt_attr("asn", data.asn.as_deref())
                    .with_opt_attr("is_proxy", data.proxy.map(|v| v.to_string()))
                    .with_opt_attr("is_hosting", data.hosting.map(|v| v.to_string()))
                    .with_opt_attr("is_mobile", data.mobile.map(|v| v.to_string())),
            );
            result.push(e);
        }

        if let Some(org) = &data.org {
            let mut e = Entity::new(EntityKind::Organisation, org, 0.65, &ctx.scan_id);
            e.add_evidence(
                Evidence::new("ip_geo", format!("IP org for {}", target.value))
                    .with_attr("asn", data.asn.as_deref().unwrap_or("-"))
                    .with_opt_attr("isp", data.isp.as_deref())
                    .with_opt_attr("country_code", data.country_code.as_deref()),
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
