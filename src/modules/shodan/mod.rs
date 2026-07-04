//! Shodan — combined free InternetDB + paid host-API module.
//!
//! **Free path (always):**
//! `GET https://internetdb.shodan.io/{ip}` — open ports, CVEs, CPEs,
//! hostnames, tags for any public IPv4. No credentials needed.
//!
//! **Paid path (when `HUNTSMAN_SHODAN_KEY` is set):**
//! `GET https://api.shodan.io/shodan/host/{ip}?key={KEY}` — detailed
//! service-scan data, org/ISP/ASN/OS, and PTR hostnames.
//!
//! Both paths run for every IP address target; entities are merged.
//!
//! Key: hardcoded (`oss`/free plan) for zero-config, overridden by
//! `HUNTSMAN_SHODAN_KEY`. Single source of truth: `util::keys`.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

pub(super) const KEY_ENV: &str = "HUNTSMAN_SHODAN_KEY";
// Embedded fallback: single source of truth lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::SHODAN_DEFAULT_KEY;

/// Resolve the Shodan API key: the operator's own key when configured,
/// otherwise the embedded `oss`-plan default. Mirrors `hibp::resolve_key`.
pub(super) fn resolve_key(ctx_key: Option<&str>) -> &str {
    crate::util::keys::resolve_or_default(ctx_key, HARDCODED_KEY)
}

// ── Paid API response ────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct HostResp {
    #[serde(default)]
    pub(super) hostnames: Vec<String>,
    #[serde(default)]
    pub(super) ports: Vec<u32>,
    #[serde(default)]
    pub(super) vulns: Vec<String>,
    #[serde(default)]
    pub(super) last_update: Option<String>,
    #[serde(default)]
    pub(super) org: Option<String>,
    #[serde(default)]
    pub(super) isp: Option<String>,
    #[serde(default)]
    pub(super) asn: Option<String>,
    #[serde(default)]
    pub(super) country_name: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
    #[serde(default)]
    pub(super) os: Option<String>,
    // Precise host geolocation the paid API returns (city/datacenter level) —
    // far sharper than the country-centroid the module used to fall back to.
    #[serde(default)]
    pub(super) latitude: Option<f64>,
    #[serde(default)]
    pub(super) longitude: Option<f64>,
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) region_code: Option<String>,
}

// ── Free InternetDB response ─────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct InternetDbResp {
    #[serde(default)]
    pub(super) ip: Option<String>,
    #[serde(default)]
    pub(super) ports: Vec<u16>,
    #[serde(default)]
    pub(super) hostnames: Vec<String>,
    #[serde(default)]
    pub(super) cpes: Vec<String>,
    #[serde(default)]
    pub(super) vulns: Vec<String>,
    #[serde(default)]
    pub(super) tags: Vec<String>,
}

// ── Module impl ──────────────────────────────────────────────────────

pub(super) const SRC: &str = "shodan";

pub struct Shodan;

#[async_trait]
impl Module for Shodan {
    fn name(&self) -> &'static str {
        "shodan"
    }
    fn description(&self) -> &'static str {
        "Shodan host intelligence — free InternetDB plus paid API when keyed"
    }
    fn priority(&self) -> u8 {
        105
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        // Shodan IS a scan database (T1596.005) and gathers IP address info
        // (T1590.005) — both covered by the Infrastructure default. But it
        // also maps hosts to their country-level Address (T1591.001 Physical
        // Locations) and identifies the ASN operator as an Organisation
        // (T1591.002 Business Relationships) — both absent from the default.
        &["T1590.005", "T1591.001", "T1591.002", "T1596.005"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        // Free + paid Shodan paths emit IP host context: domains (PTR/SAN
        // hostnames), ASN labels, plus the dominant ISP/org as Organisation
        // and the host's country as Address. Neither endpoint returns a URL
        // field, so Url is not listed.
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::IpAddress,
        ];
        KINDS
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // `resolve_key` always yields a real key (the operator's own, else the
        // embedded `oss`-plan default). Free InternetDB runs FIRST and
        // unconditionally: it carries CPEs/tags the paid path lacks, and it is
        // the fallback when the shared `oss` key is rate-limited or exhausted.
        // The paid host lookup then augments with org/ISP/ASN/OS/country; its
        // outcome is routed through `finalize` so a key error (401/403/429) —
        // already recorded upstream by `keyed_ok_or_404` — does NOT discard the
        // InternetDB data already gathered.
        let key = resolve_key(ctx.key_opt(KEY_ENV));
        self.query_internetdb(ip, ctx, &mut result).await;
        let paid = self.query_paid(ip, key, ctx, &mut result).await;
        finalize(paid, result)
    }
}

/// Combine the best-effort paid host-lookup outcome with the already-gathered
/// (free InternetDB) `result`. The paid path is best-effort: a key error
/// (401/403/429) is recorded upstream by `keyed_ok_or_404`, and must NOT
/// discard the free data already collected — so it is swallowed here rather
/// than aborting the whole module. Pure, so the "free data survives a paid
/// failure" invariant is unit-testable without a network round-trip.
fn finalize(paid: Result<()>, result: ModuleResult) -> Result<ModuleResult> {
    if let Err(e) = paid {
        tracing::debug!(
            target: "huntsman::shodan",
            error = %e,
            "shodan paid host lookup failed; free InternetDB data retained"
        );
    }
    Ok(result)
}

impl Shodan {
    /// Query the free InternetDB endpoint. Errors are swallowed so the
    /// paid path can still proceed.
    async fn query_internetdb(&self, ip: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
        let resp = match ctx
            .http
            .get(format!("https://internetdb.shodan.io/{}", urlencode(ip)))
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(target: "huntsman::shodan", ip, error = %e, "internetdb fetch failed");
                return;
            }
        };

        let status = resp.status();
        if status.as_u16() == 404 || !status.is_success() {
            tracing::debug!(
                target: "huntsman::shodan",
                ip,
                status = status.as_u16(),
                "internetdb returned no usable data (404 / non-success)"
            );
            return;
        }

        let body: InternetDbResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(target: "huntsman::shodan", ip, error = %e, "internetdb parse failed");
                return;
            }
        };

        if body.ports.is_empty()
            && body.vulns.is_empty()
            && body.hostnames.is_empty()
            && body.cpes.is_empty()
            && body.tags.is_empty()
        {
            return;
        }

        // Enrich the originating IP with port/vuln summary.
        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.92, &ctx.scan_id);
        entity.tag("shodan-internetdb");
        if !body.vulns.is_empty() {
            entity.tag(crate::core::tags::VULNERABLE);
        }

        // Full-fidelity policy: surface EVERY open port of the target host.
        let mut ports_sorted: Vec<u16> = body.ports.clone();
        ports_sorted.sort_unstable();
        ports_sorted.dedup();
        let ports_csv = ports_sorted
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut ev = Evidence::new(
            SRC,
            format!(
                "Shodan InternetDB: {} port(s), {} CVE(s), {} hostname(s)",
                body.ports.len(),
                body.vulns.len(),
                body.hostnames.len()
            ),
        )
        .with_attr("ports", ports_csv)
        .with_attr("port_count", body.ports.len().to_string());

        if !body.vulns.is_empty() {
            let v: Vec<&str> = body.vulns.iter().map(std::string::String::as_str).collect();
            ev = ev
                .with_attr("vulns", v.join(","))
                .with_attr("vuln_count", body.vulns.len().to_string());
        }
        if !body.cpes.is_empty() {
            let c: Vec<&str> = body.cpes.iter().map(std::string::String::as_str).collect();
            ev = ev.with_attr("cpes", c.join(","));
        }
        if !body.tags.is_empty() {
            ev = ev.with_attr("tags", body.tags.join(","));
            body.tags
                .iter()
                .for_each(|t| entity.tag(format!("shodan:{t}")));
        }
        if let Some(canonical_ip) = body.ip.as_deref() {
            ev = ev.with_attr("ip", canonical_ip);
        }
        entity.add_evidence(ev);
        result.push(entity);

        // Emit Domain entities for observed PTR / SAN hostnames — all of them
        // (full-fidelity policy: every discovered hostname becomes an entity).
        result.extend(
            body.hostnames
                .iter()
                .map(|host| host.trim().trim_end_matches('.'))
                .filter(|host| {
                    !host.is_empty()
                        && host.parse::<std::net::IpAddr>().is_err()
                        && host.contains('.')
                        && !host.contains(char::is_whitespace)
                })
                .map(|host| {
                    let mut d = Entity::new(EntityKind::Domain, host, 0.80, &ctx.scan_id);
                    d.tag("shodan-internetdb");
                    d.tag("ptr");
                    d.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Hostname associated with {ip} per Shodan InternetDB"),
                        )
                        .with_attr("ip", ip),
                    );
                    d
                }),
        );
    }

    /// Query the paid Shodan host API.
    async fn query_paid(
        &self,
        ip: &str,
        key: &str,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let url = format!(
            "https://api.shodan.io/shodan/host/{}?key={}",
            urlencode(ip),
            urlencode(key),
        );
        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        // 404 → host not in Shodan (clean miss); 401/403/429 → note_keyed_error + Err;
        // other non-2xx → Err via http_status_error.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(());
        };
        let body: HostResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut entity = target_entity(ip, &ctx.scan_id);
        entity.tag("shodan");
        if !body.vulns.is_empty() {
            entity.tag(crate::core::tags::VULNERABLE);
        }
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }
        if let Some(os) = body.os.as_deref() {
            entity.tag(format!("os:{os}"));
        }

        let mut ev = [
            ("org", body.org.as_deref()),
            ("isp", body.isp.as_deref()),
            ("asn", body.asn.as_deref()),
            ("country", body.country_name.as_deref()),
            ("country_code", body.country_code.as_deref()),
            ("os", body.os.as_deref()),
            ("last_update", body.last_update.as_deref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("Shodan host record for {ip}")),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        if !body.ports.is_empty() {
            let mut ports = body.ports.clone();
            ports.sort_unstable();
            ev = ev
                .with_attr("port_count", ports.len().to_string())
                .with_attr(
                    "open_ports",
                    // Full-fidelity policy: every open port of the target host.
                    ports
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
        }
        if !body.vulns.is_empty() {
            ev = ev
                .with_attr("vuln_count", body.vulns.len().to_string())
                .with_attr(
                    "top_vulns",
                    // Full-fidelity policy: every CVE reported for the target host.
                    body.vulns
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                );
        }
        entity.add_evidence(ev);
        result.push(entity);

        // Each PTR hostname becomes a Domain entity.
        result.extend(
            body.hostnames
                .iter()
                .filter(|host| !host.is_empty())
                .map(|host| {
                    let mut d = Entity::new(EntityKind::Domain, host, 0.85, &ctx.scan_id);
                    d.tag("shodan");
                    d.tag(tags::PTR);
                    d.add_evidence(
                        Evidence::new(SRC, format!("Hostname known for {ip}")).with_attr("ip", ip),
                    );
                    d
                }),
        );

        let org_lc = body
            .org
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        if let Some(org) = &body.org
            && !org.is_empty()
        {
            let mut oe = Entity::new(EntityKind::Organisation, org, 0.70, &ctx.scan_id);
            oe.tag("shodan");
            oe.add_evidence(Evidence::new(SRC, format!("Organisation for {ip}")));
            result.push(oe);
        }
        // ISP is a distinct OSINT pivot when it differs from org (e.g. org="AWS
        // EC2", isp="Amazon.com" — the provider layer above the customer org).
        if let Some(isp) = &body.isp {
            let isp = isp.trim();
            let isp_lc = isp.to_ascii_lowercase();
            if !isp.is_empty() && org_lc.as_deref() != Some(isp_lc.as_str()) {
                let mut ie = Entity::new(EntityKind::Organisation, isp, 0.65, &ctx.scan_id);
                ie.tag("shodan");
                ie.tag("isp");
                ie.add_evidence(Evidence::new(SRC, format!("ISP for {ip}")));
                result.push(ie);
            }
        }
        if let Some(asn) = &body.asn
            && !asn.is_empty()
        {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, &ctx.scan_id);
            ae.tag("shodan");
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
            result.push(ae);
        }
        for e in geo_entities(&body, ip, &ctx.scan_id) {
            result.push(e);
        }

        Ok(())
    }
}

/// Build the geolocation entities from a paid Shodan host response. Pure, so the
/// precise-coordinate extraction is unit-testable without a network round-trip.
///
/// The paid API returns the host's precise `latitude`/`longitude` and `city` —
/// far sharper than the country centroid this module previously fell back to.
/// When precise coordinates are present they are emitted (gated through
/// [`crate::util::geo::coarse_provider_coords`], the same plausibility gate the
/// other IP-geo providers use); only when they are absent does it geocode the
/// country name to a coarse centroid. The `Address` is qualified with city and
/// region when the response carries them.
fn geo_entities(body: &HostResp, ip: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    let country = body
        .country_name
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());

    // Precise host geolocation from the paid response (city/datacenter level),
    // gated through the shared provider-coord plausibility check the other
    // IP-geo providers use. This is the key value the paid lookup adds over the
    // free InternetDB path, so it is preferred; the country centroid below is
    // only a fallback for when the response omits precise coordinates.
    let precise = match (body.latitude, body.longitude) {
        (Some(lat), Some(lon)) => crate::util::geo::coarse_provider_coords(lat, lon, 0.55, scan_id)
            .map(|mut c| {
                c.tag("shodan");
                c.add_evidence(Evidence::new(
                    SRC,
                    format!("Shodan host geolocation for {ip}"),
                ));
                c
            }),
        _ => None,
    };
    let had_precise = precise.is_some();
    if let Some(c) = precise {
        out.push(c);
    }

    // Coarse country-centroid fallback — only when no precise fix was emitted.
    if !had_precise
        && let Some(country) = country
        && let Some((lat, lon)) = crate::util::city_coords::city_coords(country)
    {
        let coord_val = format!("{lat:.4},{lon:.4}");
        let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.45, scan_id);
        c.tag("shodan");
        c.tag("addr-derived");
        c.tag("geoint");
        c.add_evidence(Evidence::new(SRC, format!("Geocode of country for {ip}")));
        out.push(c);
    }

    // Address — qualified with city and region when the response carries them,
    // otherwise just the country (the prior behaviour).
    if let Some(country) = country {
        let city = body
            .city
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let region = body
            .region_code
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let addr_value = match (city, region) {
            (Some(city), Some(region)) => format!("{city}, {region}, {country}"),
            (Some(city), None) => format!("{city}, {country}"),
            (None, Some(region)) => format!("{region}, {country}"),
            (None, None) => country.to_string(),
        };
        let mut addr = Entity::new(EntityKind::Address, &addr_value, 0.55, scan_id);
        addr.tag("shodan");
        addr.tag("geoint");
        addr.add_evidence(Evidence::new(SRC, format!("Location for {ip}")));
        out.push(addr);
    }

    out
}

/// Helper to build an IP entity from a raw IP string.
pub(super) fn target_entity(ip: &str, scan_id: &str) -> Entity {
    Entity::new(EntityKind::IpAddress, ip, 0.90, scan_id)
}

// Declared at the file's end (not the top) so the `coarse_ip_geo_providers_
// use_the_provider_coord_gate` architecture guard — which truncates each source
// file at its first `mod tests` marker — still sees the production
// `coarse_provider_coords` gate call above.
#[cfg(test)]
mod tests;
