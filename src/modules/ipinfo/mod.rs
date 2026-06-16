//! ipinfo.io — free IP intelligence (no key for basic queries).
//!
//! Endpoint: `GET https://ipinfo.io/{ip}/json`
//! Auth: None for basic tier (50K/month); paid tiers expose `privacy`,
//! `abuse`, and `domains` sub-objects.
//!
//! Returns city, region, country, org, ASN, hostname, timezone, postal,
//! anycast flag, and (paid) privacy/abuse/domains blocks.
//! Richer than ip-api.com for organisation + hostname data.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "ipinfo";

/// Privacy sub-object returned by ipinfo.io paid tier.
#[derive(Deserialize, Default)]
struct IpPrivacy {
    #[serde(default)]
    vpn: bool,
    #[serde(default)]
    proxy: bool,
    #[serde(default)]
    tor: bool,
    #[serde(default)]
    relay: bool,
    #[serde(default)]
    hosting: bool,
    #[serde(default)]
    service: Option<String>,
}

/// Abuse-contact sub-object returned by ipinfo.io paid tier.
#[derive(Deserialize, Default)]
struct IpAbuse {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    phone: Option<String>,
}

/// Domains sub-object returned by ipinfo.io paid tier.
#[derive(Deserialize, Default)]
struct IpDomains {
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    domains: Vec<String>,
}

#[derive(Deserialize)]
struct IpInfoResp {
    // The echoed `ip` field is intentionally not deserialized — the queried IP
    // is already known from the target, so serde simply ignores it.
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    loc: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    postal: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    anycast: bool,
    #[serde(default)]
    privacy: Option<IpPrivacy>,
    #[serde(default)]
    abuse: Option<IpAbuse>,
    #[serde(default)]
    domains: Option<IpDomains>,
}

/// Map an ipinfo.io record to its entities. **Pure** (no network/IO).
///
/// Yields up to several entity types:
/// - `Coordinates` from a real (non-null-island) `loc`
/// - `Address` from city/region/country
/// - `Organisation` plus the leading `Asn` parsed from the `org` string
///   (`"AS15169 Google LLC"`)
/// - PTR `Domain` from a dotted `hostname`
/// - Additional `Domain` entities from the paid `domains` block
///
/// Privacy flags (`vpn`, `proxy`, `tor`, `relay`, `hosting`) are surfaced as
/// tags on the `Organisation`/`Asn` entities and as evidence attributes.
/// Abuse-contact fields are surfaced as evidence attributes on the
/// `Organisation` entity. Each entity is independent; absent/blank fields are
/// skipped.
fn build_entities(ip: &str, data: &IpInfoResp, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    // Shared trust gate: an IP whose geolocation is infrastructure (a
    // CDN/anycast edge) is not the subject's, so skip its findings rather than
    // pollute identity-location correlation. The `anycast` flag from ipinfo
    // also signals this directly.
    if data.anycast {
        tracing::debug!(
            module = SRC,
            %ip,
            "skipping IP-geo — anycast flag set (location is infrastructure, not subject)"
        );
        return out;
    }
    if let Some(reason) = crate::core::validation::untrusted_ip_geo_reason(ip) {
        tracing::debug!(
            module = SRC,
            %ip,
            reason,
            "skipping IP-geo — location is the infrastructure, not the subject"
        );
        return out;
    }

    if let Some(loc) = &data.loc {
        let mut parts = loc.split(',');
        if let (Some(lat_s), Some(lon_s)) = (parts.next(), parts.next())
            && let (Ok(lat), Ok(lon)) = (lat_s.trim().parse::<f64>(), lon_s.trim().parse::<f64>())
            // Confidence recalibrated 0.68 → 0.58 — see ip_geo.rs.
            && let Some(mut ce) = crate::util::geo::coarse_provider_coords(lat, lon, 0.58, scan_id)
        {
            ce.tag("ipinfo");
            if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                ce.tag(format!("au-state:{state}"));
                ce.tag("country:AU");
            }
            let mut ev = Evidence::new(SRC, format!("IP geo for {ip}"));
            for (key, val) in [
                ("city", data.city.as_deref()),
                ("region", data.region.as_deref()),
                ("country", data.country.as_deref()),
                ("postal", data.postal.as_deref()),
                ("timezone", data.timezone.as_deref()),
            ] {
                if let Some(v) = val {
                    ev = ev.with_attr(key, v);
                }
            }
            ce.add_evidence(ev);
            out.push(ce);
        }
    }

    let city = data.city.as_deref().unwrap_or("");
    let region = data.region.as_deref().unwrap_or("");
    let country = data.country.as_deref().unwrap_or("");
    if !city.is_empty() {
        let addr = if !region.is_empty() {
            format!("{city}, {region}, {country}")
        } else {
            format!("{city}, {country}")
        };
        let mut ae = Entity::new(EntityKind::Address, &addr, 0.60, scan_id);
        ae.tag("ipinfo");
        let mut ev = Evidence::new(SRC, format!("Address for {ip}"));
        if let Some(p) = data.postal.as_deref() {
            ev = ev.with_attr("postal", p);
        }
        if let Some(tz) = data.timezone.as_deref() {
            ev = ev.with_attr("timezone", tz);
        }
        ae.add_evidence(ev);
        out.push(ae);
    }

    // Privacy flags — collected once, applied to Org/ASN entities below.
    let privacy_tags: Vec<&'static str> = data
        .privacy
        .as_ref()
        .map(|p| {
            let mut tags: Vec<&'static str> = Vec::new();
            if p.vpn {
                tags.push("vpn");
            }
            if p.proxy {
                tags.push("proxy");
            }
            if p.tor {
                tags.push("tor");
            }
            if p.relay {
                tags.push("relay");
            }
            if p.hosting {
                tags.push("hosting");
            }
            tags
        })
        .unwrap_or_default();

    if let Some(org) = &data.org
        && !org.is_empty()
    {
        let mut oe = Entity::new(EntityKind::Organisation, org, 0.65, scan_id);
        oe.tag("ipinfo");
        for t in &privacy_tags {
            oe.tag(*t);
        }

        let mut ev = Evidence::new(SRC, format!("Org for {ip}"));
        // Surface privacy flags as attributes.
        if let Some(p) = &data.privacy {
            ev = ev
                .with_attr("vpn", p.vpn.to_string())
                .with_attr("proxy", p.proxy.to_string())
                .with_attr("tor", p.tor.to_string())
                .with_attr("relay", p.relay.to_string())
                .with_attr("hosting", p.hosting.to_string());
            if let Some(svc) = p.service.as_deref() {
                ev = ev.with_attr("privacy_service", svc);
            }
        }
        // Surface abuse contact fields.
        if let Some(ab) = &data.abuse {
            for (key, val) in [
                ("abuse_name", ab.name.as_deref()),
                ("abuse_email", ab.email.as_deref()),
                ("abuse_phone", ab.phone.as_deref()),
                ("abuse_address", ab.address.as_deref()),
                ("abuse_country", ab.country.as_deref()),
                ("abuse_network", ab.network.as_deref()),
            ] {
                if let Some(v) = val {
                    ev = ev.with_attr(key, v);
                }
            }
        }
        oe.add_evidence(ev);
        out.push(oe);

        if let Some(asn) = org.split_whitespace().next()
            && asn.starts_with("AS")
        {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, scan_id);
            ae.tag("ipinfo");
            for t in &privacy_tags {
                ae.tag(*t);
            }
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
            out.push(ae);
        }
    }

    if let Some(hostname) = &data.hostname
        && !hostname.is_empty()
        && hostname.contains('.')
    {
        let mut de = Entity::new(EntityKind::Domain, hostname, 0.70, scan_id);
        de.tag("ipinfo");
        de.tag(tags::PTR);
        de.add_evidence(Evidence::new(SRC, format!("Hostname for {ip}")));
        out.push(de);
    }

    // Paid `domains` block: additional domains hosted on this IP.
    if let Some(dom_block) = &data.domains {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        // Insert the PTR hostname so we don't duplicate it.
        if let Some(h) = data.hostname.as_deref() {
            seen.insert(h);
        }
        let total = dom_block.total.unwrap_or(0);
        for d in &dom_block.domains {
            let d = d.trim();
            if d.is_empty() || !d.contains('.') || !seen.insert(d) {
                continue;
            }
            let mut de = Entity::new(EntityKind::Domain, d, 0.65, scan_id);
            de.tag("ipinfo");
            de.tag("hosted-domain");
            de.add_evidence(
                Evidence::new(SRC, format!("Domain hosted on {ip} per ipinfo.io"))
                    .with_attr("ip", ip)
                    .with_attr("total_domains", total.to_string()),
            );
            out.push(de);
        }
    }

    out
}

pub struct IpInfo;

#[async_trait]
impl Module for IpInfo {
    fn name(&self) -> &'static str {
        "ipinfo"
    }
    fn description(&self) -> &'static str {
        "IP intelligence via ipinfo.io (free tier + paid privacy/abuse/domains)"
    }
    fn priority(&self) -> u8 {
        25
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Infrastructure default (T1590.005 + T1596.005) covers IP info but
        // ipinfo.io is a passive geolocation API, not a scan database (T1596.005).
        // It maps IPs to physical coordinates + address (T1591.001) and identifies
        // the ISP/ASN operator as an Organisation (T1591.002).
        &["T1590.005", "T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Domain,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();

        let url = format!("https://ipinfo.io/{ip}/json");
        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(6))
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: IpInfoResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(ip, &data, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
