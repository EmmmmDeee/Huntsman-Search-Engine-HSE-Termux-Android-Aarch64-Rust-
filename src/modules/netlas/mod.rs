//! Netlas host intelligence. Key-gated; requires HUNTSMAN_NETLAS_KEY.
//!
//! Endpoint: `GET https://app.netlas.io/api/responses/?q=ip:{t}&fields=*`
//! Auth: X-API-Key header.
//!
//! Key differentiator: extracts emails from SSL certs and HTTP bodies →
//! direct BFS pivot to breach stack. Also surfaces open ports, JARM
//! fingerprint, CVEs, technologies, and ISP/geolocation.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "netlas";
const KEY_ENV: &str = "HUNTSMAN_NETLAS_KEY";

pub struct Netlas;

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasResp {
    count: Option<u64>,
    items: Vec<NetlasItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasItem {
    data: Option<NetlasData>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasData {
    ip: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    jarm: Option<String>,
    geo: Option<NetlasGeo>,
    isp: Option<String>,
    whois: Option<NetlasWhois>,
    certificate: Option<NetlasCert>,
    http: Option<NetlasHttp>,
    cve: Option<Vec<NetlasCve>>,
    technologies: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasGeo {
    country: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasWhois {
    net: Option<NetlasWhoisNet>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasWhoisNet {
    emails: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasCert {
    subject: Option<NetlasCertSubject>,
    issuer: Option<NetlasCertIssuer>,
    domains: Option<Vec<String>>,
    emails: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasCertSubject {
    common_name: Option<String>,
    organization: Option<Vec<String>>,
    email: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasCertIssuer {
    common_name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasHttp {
    emails: Option<Vec<String>>,
    title: Option<String>,
    status_code: Option<u16>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NetlasCve {
    name: Option<String>,
}

pub(super) fn netlas_query(target: &Target) -> String {
    let val = crate::util::http::urlencode(target.value.trim());
    match target.kind {
        TargetKind::IpAddress => format!("ip:{val}"),
        TargetKind::Domain => format!("host:{val}"),
        TargetKind::Email => format!("certificate.subject.email:{val}"),
        _ => format!("ip:{val}"),
    }
}

#[async_trait]
impl Module for Netlas {
    fn name(&self) -> &'static str {
        "netlas"
    }

    fn description(&self) -> &'static str {
        "Netlas host intelligence: open ports, JARM, SSL-cert email extraction, CVEs, ISP"
    }

    fn priority(&self) -> u8 {
        79
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::IpAddress | TargetKind::Domain | TargetKind::Email
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Email,
            EntityKind::Domain,
            EntityKind::Organisation,
            EntityKind::Coordinates,
            EntityKind::Address,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let query = netlas_query(target);
        let url = format!("https://app.netlas.io/api/responses/?q={query}&fields=*");

        let resp = ctx
            .http
            .get(&url)
            .header("X-API-Key", key)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        if !status.is_success() {
            crate::util::http::note_keyed_error(status.as_u16(), SRC, key, ctx);
            return Ok(ModuleResult::new());
        }

        let body: NetlasResp = crate::util::http::json_decode(SRC, resp).await?;
        let mut result = ModuleResult::new();

        let mut all_emails: Vec<String> = Vec::new();
        let mut port_list: Vec<String> = Vec::new();
        let mut jarm_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut cve_list: Vec<String> = Vec::new();
        let mut tech_list: Vec<String> = Vec::new();
        let mut isp_val: Option<String> = None;
        let mut geo_val: Option<(f64, f64, String, String)> = None;
        let mut ssl_cn: Option<String> = None;
        let mut ip_val: Option<String> = None;

        for item in &body.items {
            let Some(data) = &item.data else { continue };

            if let Some(ip) = &data.ip
                && ip_val.is_none()
            {
                ip_val = Some(ip.clone());
            }
            if let Some(p) = data.port {
                let proto = data.protocol.as_deref().unwrap_or("tcp");
                port_list.push(format!("{p}/{proto}"));
            }
            if let Some(j) = data.jarm.as_deref().filter(|s| !s.is_empty()) {
                jarm_seen.insert(j.to_string());
            }
            if let Some(isp) = data.isp.as_deref().filter(|s| !s.is_empty())
                && isp_val.is_none()
            {
                isp_val = Some(isp.to_string());
            }
            if let Some(geo) = &data.geo
                && geo_val.is_none()
                && let (Some(lat), Some(lon)) = (geo.latitude, geo.longitude)
                && (lat.abs() > 0.001 || lon.abs() > 0.001)
            {
                geo_val = Some((
                    lat,
                    lon,
                    geo.country.clone().unwrap_or_default(),
                    geo.city.clone().unwrap_or_default(),
                ));
            }
            if let Some(cert) = &data.certificate {
                if let Some(subj) = &cert.subject {
                    if let Some(cn) = subj.common_name.as_deref().filter(|s| !s.is_empty())
                        && ssl_cn.is_none()
                    {
                        ssl_cn = Some(cn.to_string());
                    }
                    if let Some(emails) = &subj.email {
                        all_emails.extend(emails.iter().cloned());
                    }
                }
                if let Some(emails) = &cert.emails {
                    all_emails.extend(emails.iter().cloned());
                }
            }
            if let Some(http_data) = &data.http
                && let Some(emails) = &http_data.emails
            {
                all_emails.extend(emails.iter().cloned());
            }
            if let Some(whois) = &data.whois
                && let Some(net) = &whois.net
                && let Some(emails) = &net.emails
            {
                all_emails.extend(emails.iter().cloned());
            }
            if let Some(cves) = &data.cve {
                for cve in cves.iter().take(5) {
                    if let Some(n) = &cve.name {
                        cve_list.push(n.clone());
                    }
                }
            }
            if let Some(techs) = &data.technologies {
                tech_list.extend(techs.iter().cloned());
            }
        }

        if body.items.is_empty() {
            return Ok(result);
        }

        // Emit IP entity.
        let ip_str = ip_val.as_deref().unwrap_or(target.value.trim());
        let mut ip_entity = Entity::new(EntityKind::IpAddress, ip_str, 0.85, &ctx.scan_id);
        ip_entity.tag("netlas");
        port_list.sort();
        port_list.dedup();
        let mut ev = Evidence::new(SRC, format!("Netlas intelligence for {ip_str}"))
            .with_attr("port_count", port_list.len().to_string());
        if !port_list.is_empty() {
            ev = ev.with_attr(
                "open_ports",
                port_list
                    .iter()
                    .take(20)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(j) = jarm_seen.iter().next() {
            ev = ev.with_attr("jarm_fingerprint", j);
        }
        if let Some(cn) = ssl_cn.as_deref() {
            ev = ev.with_attr("ssl_cn", cn);
        }
        if !cve_list.is_empty() {
            ev = ev.with_attr(
                "cves",
                cve_list
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if !tech_list.is_empty() {
            tech_list.sort();
            tech_list.dedup();
            ev = ev.with_attr(
                "technologies",
                tech_list
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(isp) = &isp_val {
            ev = ev.with_attr("isp", isp);
        }
        ip_entity.add_evidence(ev);
        result.push(ip_entity);

        // ISP → Organisation entity.
        if let Some(isp) = isp_val.as_deref().filter(|s| s.len() >= 3) {
            let mut org = Entity::new(EntityKind::Organisation, isp, 0.60, &ctx.scan_id);
            org.tag("netlas");
            org.tag("isp");
            org.add_evidence(
                Evidence::new(SRC, format!("ISP for {ip_str}: {isp}"))
                    .with_attr("source", "netlas"),
            );
            result.push(org);
        }

        // Geolocation → Coordinates + Address.
        if let Some((lat, lon, country, city)) = geo_val {
            let coord_str = format!("{lat:.6},{lon:.6}");
            let mut geo_e = Entity::new(EntityKind::Coordinates, &coord_str, 0.60, &ctx.scan_id);
            geo_e.tag("netlas");
            geo_e.tag("geoint");
            if !country.is_empty() {
                geo_e.tag(format!(
                    "country:{}",
                    country.to_uppercase().replace(' ', "")
                ));
            }
            geo_e.add_evidence(
                Evidence::new(SRC, format!("Netlas geolocation for {ip_str}"))
                    .with_attr("latitude", lat.to_string())
                    .with_attr("longitude", lon.to_string())
                    .with_attr("country", &country)
                    .with_attr("city", &city),
            );
            result.push(geo_e);

            if !city.is_empty() && !country.is_empty() {
                let addr_str = format!("{city}, {country}");
                let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.55, &ctx.scan_id);
                addr.tag("netlas");
                addr.add_evidence(Evidence::new(SRC, format!("Netlas location for {ip_str}")));
                result.push(addr);
            }
        }

        // Extracted emails → Email entities for BFS.
        all_emails.sort();
        all_emails.dedup();
        for email in all_emails.iter().take(10) {
            let email = email.to_lowercase();
            if email.contains('@') {
                let mut e = Entity::new(EntityKind::Email, &email, 0.65, &ctx.scan_id);
                e.tag("netlas");
                e.tag("ssl-extracted");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Email extracted from SSL/HTTP data for {ip_str}"),
                    )
                    .with_attr("emails_extracted", &email),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}
