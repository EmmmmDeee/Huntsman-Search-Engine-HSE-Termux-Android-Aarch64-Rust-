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

/// Build the Netlas search expression for a target, picking the right field
/// per kind: an IP queries `ip:`, a domain `host:`, and an email
/// `certificate.subject.email:` (the cert-pivot that makes this module a
/// bridge from infrastructure back to identity). Unknown kinds fall back to
/// `ip:`. The value is URL-encoded so a stray character can't corrupt the
/// query string. Pure — unit-testable without a key or network.
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

        // 401/403/429 → note_keyed_error + Err; 404 → clean miss; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: NetlasResp = crate::util::http::json_decode(SRC, resp).await?;
        Ok(build_entities(&body, target.value.trim(), &ctx.scan_id))
    }
}

/// Map a decoded Netlas response to entities. **Pure** (no network/IO): the
/// network shell owns auth/transport, this owns the response→entity mapping
/// (unit-testable without a key). Accumulates host facts across `body.items`,
/// then emits the IP entity — carrying the port/JARM/SSL/CVE/tech/ISP evidence
/// plus the previously-dropped `ssl_issuer` (issuing CA), `http_title` and
/// `http_status` — the ISP and cert-subject Organisations, the geo
/// Coordinates/Address, the SAN Domains, and the SSL/HTTP-extracted Emails.
/// `target_value` is the queried value used as the IP fallback; an empty item
/// set yields an empty result.
fn build_entities(body: &NetlasResp, target_value: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    let mut all_emails: Vec<String> = Vec::new();
    let mut all_cert_domains: Vec<String> = Vec::new();
    let mut cert_orgs: Vec<String> = Vec::new();
    let mut port_list: Vec<String> = Vec::new();
    // BTreeSet, not HashSet: a host can expose several JARM fingerprints (one per
    // TLS service), but only ONE is emitted as `jarm_fingerprint`. `HashSet`
    // iteration order is randomised per process, so `.iter().next()` picked a
    // different fingerprint between otherwise-identical runs — breaking the
    // byte-identical-output guarantee. Ordered set → the lexicographically
    // smallest fingerprint, deterministically.
    let mut jarm_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cve_list: Vec<String> = Vec::new();
    let mut tech_list: Vec<String> = Vec::new();
    let mut isp_val: Option<String> = None;
    let mut geo_val: Option<(f64, f64, String, String)> = None;
    let mut ssl_cn: Option<String> = None;
    let mut ip_val: Option<String> = None;
    let mut ssl_issuer: Option<String> = None;
    let mut http_title: Option<String> = None;
    let mut http_status: Option<u16> = None;

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
                // OV/EV certificates carry the verified organisation name in
                // the Subject O field — a confirmed legal entity name.
                if let Some(orgs) = &subj.organization {
                    cert_orgs.extend(orgs.iter().filter(|o| !o.is_empty()).cloned());
                }
            }
            if let Some(emails) = &cert.emails {
                all_emails.extend(emails.iter().cloned());
            }
            if let Some(doms) = &cert.domains {
                all_cert_domains.extend(doms.iter().cloned());
            }
            // Issuing CA common name — the certificate authority that signed
            // the cert. Fetched via fields=* but previously dropped.
            if ssl_issuer.is_none()
                && let Some(iss) = cert
                    .issuer
                    .as_ref()
                    .and_then(|i| i.common_name.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            {
                ssl_issuer = Some(iss.to_string());
            }
        }
        if let Some(http_data) = &data.http {
            if let Some(emails) = &http_data.emails {
                all_emails.extend(emails.iter().cloned());
            }
            // HTTP <title> (often the owning org/product) and status code —
            // decoded via fields=* but previously dropped.
            if http_title.is_none()
                && let Some(t) = http_data
                    .title
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            {
                http_title = Some(t.to_string());
            }
            if http_status.is_none() {
                http_status = http_data.status_code;
            }
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
        return result;
    }

    // Emit IP entity.
    let ip_str = ip_val.as_deref().unwrap_or(target_value);
    let mut ip_entity = Entity::new(EntityKind::IpAddress, ip_str, 0.85, scan_id);
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
    // Deterministic: the smallest fingerprint of the ordered set (see `jarm_seen`).
    if let Some(j) = jarm_seen.iter().next() {
        ev = ev.with_attr("jarm_fingerprint", j);
    }
    if let Some(cn) = ssl_cn.as_deref() {
        ev = ev.with_attr("ssl_cn", cn);
    }
    if let Some(iss) = ssl_issuer.as_deref() {
        ev = ev.with_attr("ssl_issuer", iss);
    }
    if let Some(t) = http_title.as_deref() {
        ev = ev.with_attr("http_title", t);
    }
    if let Some(code) = http_status {
        ev = ev.with_attr("http_status", code.to_string());
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
    let isp_lc = isp_val
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    if let Some(isp) = isp_val.as_deref().filter(|s| s.len() >= 3) {
        let mut org = Entity::new(EntityKind::Organisation, isp, 0.60, scan_id);
        org.tag("netlas");
        org.tag("isp");
        org.add_evidence(
            Evidence::new(SRC, format!("ISP for {ip_str}: {isp}")).with_attr("source", "netlas"),
        );
        result.push(org);
    }

    // SSL Subject O field → Organisation entity (OV/EV certs only).
    // Deduplicate and skip values that match the ISP already emitted. Emit EVERY
    // unique cert Subject O: each is a confirmed legal-entity attribution pivot,
    // and a shared-hosting IP can present certs from several distinct
    // organisations — a silent `.take(3)` dropped real ones, inconsistent with
    // the uncapped SAN-domain / extracted-email loops below.
    cert_orgs.sort();
    cert_orgs.dedup();
    for cert_org in &cert_orgs {
        let org_lc = cert_org.trim().to_ascii_lowercase();
        if org_lc.len() < 3 || isp_lc.as_deref() == Some(&org_lc) {
            continue;
        }
        let mut oe = Entity::new(EntityKind::Organisation, cert_org.trim(), 0.70, scan_id);
        oe.tag("netlas");
        oe.tag("ssl-subject-org");
        oe.add_evidence(
            Evidence::new(
                SRC,
                format!("SSL/TLS certificate Subject O for {ip_str}: {cert_org}"),
            )
            .with_attr("ip", ip_str)
            .with_attr("cert_org", cert_org.as_str()),
        );
        result.push(oe);
    }

    // Geolocation → Coordinates + Address.
    if let Some((lat, lon, country, city)) = geo_val {
        let coord_str = format!("{lat:.6},{lon:.6}");
        let mut geo_e = Entity::new(EntityKind::Coordinates, &coord_str, 0.60, scan_id);
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
            let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.55, scan_id);
            addr.tag("netlas");
            addr.add_evidence(Evidence::new(SRC, format!("Netlas location for {ip_str}")));
            result.push(addr);
        }
    }

    // SSL/TLS SAN domains → Domain entities for BFS. Emit EVERY unique SAN domain:
    // a multi-SAN / wildcard / shared-hosting certificate lists 50-100+ domains, and
    // the BFS frontier budget is owned by the engine/scan orchestrator (max depth /
    // frontier cap), not this leaf module — so a silent `.take(20)` here would drop
    // real expansion pivots the host's certificate genuinely exposes.
    all_cert_domains.sort();
    all_cert_domains.dedup();
    for dom in &all_cert_domains {
        let dom = dom.trim().trim_start_matches('*').trim_start_matches('.');
        if dom.len() >= 4 && dom.contains('.') && !dom.contains(char::is_whitespace) {
            let mut de = Entity::new(EntityKind::Domain, dom, 0.70, scan_id);
            de.tag("netlas");
            de.tag("ssl-san");
            de.add_evidence(
                Evidence::new(SRC, format!("SSL/TLS SAN domain for {ip_str}"))
                    .with_attr("ip", ip_str),
            );
            result.push(de);
        }
    }

    // Extracted emails → Email entities for BFS. Emit EVERY unique email: per the
    // module docstring these are its "key differentiator … direct BFS pivot to breach
    // stack", so a silent `.take(10)` drops real breach-stack pivots a cert/WHOIS
    // record exposes (registrant/admin/tech/abuse contacts on a busy host).
    all_emails.sort();
    all_emails.dedup();
    for email in &all_emails {
        let email = email.to_lowercase();
        if crate::util::extract::looks_like_email(&email) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.65, scan_id);
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

    result
}
