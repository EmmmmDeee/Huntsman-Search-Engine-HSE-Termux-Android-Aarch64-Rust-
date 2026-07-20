//! WhoisXML — structured WHOIS lookup with registrant + history fields.
//!
//! Endpoint: `GET https://www.whoisxmlapi.com/whoisserver/WhoisService?
//!            domainName={d}&apiKey={k}&outputFormat=JSON`
//! Auth:     `apiKey` query param. Key-gated (`HUNTSMAN_WHOISXML_KEY`).
//! Free tier: 500 lookups/month.
//!
//! Sibling of the existing `whois` module (which speaks raw TCP WHOIS).
//! WhoisXML adds:
//!   - structured registrant fields (name, organisation, email,
//!     country) without screen-scraping
//!   - creation / expiration / updated timestamps as parsed dates
//!   - registrar identity + status flags (`clientTransferProhibited`
//!     etc.) the raw protocol returns as unstructured text

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const KEY_ENV: &str = "HUNTSMAN_WHOISXML_KEY";
const SRC: &str = "whoisxml";

pub struct WhoisXml;

#[derive(Deserialize)]
struct Wrap {
    #[serde(rename = "WhoisRecord", default)]
    whois: Option<WhoisRecord>,
    /// Some plan/quota errors come back as HTTP 200 with an
    /// `ErrorMessage` body and no `WhoisRecord`. Capture so we can
    /// mark the key exhausted instead of silently returning empty.
    #[serde(rename = "ErrorMessage", default)]
    error: Option<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    msg: Option<String>,
    #[serde(rename = "errorCode", default)]
    error_code: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct WhoisRecord {
    /// The registrable domain the registry holds the record under. Can differ
    /// from the queried host (e.g. a subdomain query resolves to its parent);
    /// [`build_entities`] surfaces it as a `Domain` pivot when it does.
    #[serde(default)]
    domain_name: Option<String>,
    #[serde(default)]
    created_date: Option<String>,
    #[serde(default)]
    updated_date: Option<String>,
    #[serde(default)]
    expires_date: Option<String>,
    #[serde(default)]
    registrar_name: Option<String>,
    #[serde(default)]
    estimated_domain_age: Option<u64>,
    #[serde(default)]
    registrant: Option<Contact>,
    #[serde(default)]
    administrative_contact: Option<Contact>,
    #[serde(default)]
    technical_contact: Option<Contact>,
    #[serde(default)]
    name_servers: Option<NameServers>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Contact {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    telephone: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NameServers {
    #[serde(default)]
    host_names: Vec<String>,
}

#[async_trait]
impl Module for WhoisXml {
    fn name(&self) -> &'static str {
        "whoisxml"
    }

    fn description(&self) -> &'static str {
        "Structured WHOIS via whoisxmlapi.com — surfaces registrant, contacts, registration dates, and nameservers as parsed fields"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // WHOIS registration data — ATT&CK WHOIS (T1596.002).
        &["T1596.002"]
    }

    fn priority(&self) -> u8 {
        58
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::Domain]
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Domain,
            // Registrant/admin/tech contact telephone as a contactability pivot.
            EntityKind::Phone,
            // Registrant/admin/tech WHOIS location (state, country) as a geo lead.
            EntityKind::Address,
            EntityKind::Coordinates,
        ]
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };
        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={}&apiKey={}&outputFormat=JSON",
            crate::util::http::urlencode(domain),
            crate::util::http::urlencode(key),
        );

        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            // `without_url()` strips the URL (which carries the API key
            // as a query param) before formatting, so transport errors
            // don't leak the key into logs / events.
            .map_err(|e| Error::module(SRC, e.without_url().to_string()))?;
        // 401/403/429 → report_key_exhausted + Err; 404 → Ok(None) (domain
        // not in WHOIS database); other non-2xx → Err via http_status_error.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let wrap: Wrap = crate::util::http::json_decode(SRC, resp).await?;
        // HTTP-200-with-error-payload (quota / scope / plan): mark
        // the key exhausted so subsequent scans don't keep burning
        // calls against a dead credential.
        if let Some(err) = wrap.error {
            let detail = err
                .msg
                .as_deref()
                .or(err.error_code.as_deref())
                .unwrap_or("api error");
            ctx.report_key_exhausted(SRC, key, 200);
            return Err(Error::module(SRC, format!("api 200 error: {detail}")));
        }
        let Some(rec) = wrap.whois else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        for e in build_entities(&rec, domain, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// Trim a field and drop it if empty — an owned-returning adapter over the
/// canonical [`crate::util::str_util::nonempty`], so the trim/empty logic lives
/// in exactly one place.
fn nonempty(s: &Option<String>) -> Option<String> {
    crate::util::str_util::nonempty(s).map(str::to_string)
}

/// Shared evidence stamped on every entity from one lookup: the queried domain
/// plus the record-level metadata (dates, registrar, age, status).
fn base_evidence(rec: &WhoisRecord, domain: &str) -> Evidence {
    let mut ev =
        Evidence::new(SRC, format!("WhoisXML lookup for {domain}")).with_attr("domain", domain);
    if let Some(c) = nonempty(&rec.created_date) {
        ev = ev.with_attr("created", &c);
    }
    if let Some(u) = nonempty(&rec.updated_date) {
        ev = ev.with_attr("updated", &u);
    }
    if let Some(e) = nonempty(&rec.expires_date) {
        ev = ev.with_attr("expires", &e);
    }
    if let Some(reg) = nonempty(&rec.registrar_name) {
        ev = ev.with_attr("registrar", &reg);
    }
    if let Some(age) = rec.estimated_domain_age {
        ev = ev.with_attr("estimated_age_days", age.to_string());
    }
    if let Some(status) = nonempty(&rec.status) {
        ev = ev.with_attr("status", &status);
    }
    if let Some(d) = nonempty(&rec.domain_name) {
        ev = ev.with_attr("registered_domain", &d);
    }
    ev
}

/// Map a WhoisXML record to graph entities. **Pure** (no IO, no quota) so the
/// contact extraction, cross-role de-duplication, location-pivot and
/// registered-domain logic is unit-tested directly, decoupled from the network.
///
/// The registrant / administrative / technical contacts are very often byte
/// identical (one privacy proxy or one owner), so the same org / person / email
/// is collapsed to a single node — tagged with the FIRST role that carried it
/// (registrant wins) — instead of three near-duplicate entities. Beyond the
/// prior org/person/email/nameserver set this also surfaces:
///   • the registry's **registrable domain** as a `Domain` pivot when it differs
///     from the queried host (previously a discarded field);
///   • each contact's **WHOIS location** (`state, country`) as a low-confidence
///     `Address` geo-hint — a real person-locating lead for AU-centric scans.
fn build_entities(rec: &WhoisRecord, domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let base_ev = base_evidence(rec, domain);

    // ── Registrable domain pivot (previously discarded `domain_name`). ──
    if let Some(reg_dom) = nonempty(&rec.domain_name) {
        let low = reg_dom.trim_end_matches('.').to_ascii_lowercase();
        if low != domain.trim_end_matches('.').to_ascii_lowercase()
            && low.contains('.')
            && seen.insert(format!("dom:{low}"))
        {
            let mut e = Entity::new(EntityKind::Domain, &low, confidence::HIGH, scan_id);
            e.tag("whoisxml");
            e.tag("registered-domain");
            e.add_evidence(base_ev.clone().with_attr("queried_domain", domain));
            out.push(e);
        }
    }

    // ── Contacts: org / person / email / location, deduped across roles. ──
    for (contact, role) in [
        (rec.registrant.as_ref(), "registrant"),
        (rec.administrative_contact.as_ref(), "admin"),
        (rec.technical_contact.as_ref(), "technical"),
    ] {
        let Some(c) = contact else { continue };

        if let Some(org) = nonempty(&c.organization)
            .filter(|o| !crate::core::validation::is_whois_privacy_placeholder(o))
            && seen.insert(format!("org:{}", org.to_lowercase()))
        {
            let mut e = Entity::new(
                EntityKind::Organisation,
                &org,
                confidence::HIGH_PLUS,
                scan_id,
            );
            e.tag("whoisxml");
            e.tag(format!("whois-{role}"));
            let mut ev = base_ev.clone().with_attr("contact_role", role);
            if let Some(cc) = nonempty(&c.country_code) {
                ev = ev.with_attr("country_code", &cc);
            }
            e.add_evidence(ev);
            out.push(e);
        }

        if let Some(name) =
            nonempty(&c.name).filter(|n| !crate::core::validation::is_whois_privacy_placeholder(n))
            && seen.insert(format!("person:{}", name.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Person, &name, confidence::MEDIUM_PLUS, scan_id);
            e.tag("whoisxml");
            e.tag(format!("whois-{role}"));
            let mut ev = base_ev.clone().with_attr("contact_role", role);
            if let Some(country) = nonempty(&c.country) {
                ev = ev.with_attr("country", &country);
            }
            if let Some(state) = nonempty(&c.state) {
                ev = ev.with_attr("state", &state);
            }
            e.add_evidence(ev);
            out.push(e);
        }

        if let Some(email) = nonempty(&c.email).filter(|s| s.contains('@')) {
            let low = email.to_lowercase();
            if seen.insert(format!("mail:{low}")) {
                let mut e = Entity::new(EntityKind::Email, &email, confidence::HIGH_PLUS, scan_id);
                e.tag("whoisxml");
                e.tag(format!("whois-{role}-email"));
                e.add_evidence(base_ev.clone().with_attr("contact_role", role));
                out.push(e);
            }
        }

        // Contact telephone (RFC-WHOIS `+CC.number`) — a real contactability
        // pivot, previously decoded nowhere. Skip privacy-placeholder values,
        // and normalise the dotted separator (the shared E.164 scanner treats a
        // space as a separator but not `.`) so each validated number is minted.
        if let Some(tel) = nonempty(&c.telephone)
            .filter(|t| !crate::core::validation::is_whois_privacy_placeholder(t))
        {
            for phone in crate::util::extract::phones(&tel.replace('.', " ")) {
                if seen.insert(format!("phone:{phone}")) {
                    let mut e = Entity::new(EntityKind::Phone, &phone, 0.65, scan_id);
                    e.tag("whoisxml");
                    e.tag(format!("whois-{role}"));
                    e.add_evidence(base_ev.clone().with_attr("contact_role", role));
                    out.push(e);
                }
            }
        }

        // WHOIS registrant location → low-confidence Address geo-hint. A
        // privacy-proxy address ("REDACTED FOR PRIVACY") is never the subject's.
        if let Some(loc) = contact_location(c)
            .filter(|l| !crate::core::validation::is_whois_privacy_placeholder(l))
            && seen.insert(format!("addr:{}", loc.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Address, &loc, confidence::LOW_MEDIUM, scan_id);
            e.tag("whoisxml");
            e.tag(format!("whois-{role}"));
            e.tag("geo-hint");
            e.add_evidence(base_ev.clone().with_attr("contact_role", role));
            out.push(e);
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&loc) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.35, scan_id);
                c.tag("whoisxml");
                c.tag("addr-derived");
                c.tag("geoint");
                c.add_evidence(base_ev.clone().with_attr("contact_role", role));
                out.push(c);
            }
        }
    }

    // ── Name servers as Domain entities (tagged nameserver). ──
    if let Some(ns) = &rec.name_servers {
        for host in &ns.host_names {
            // Strip the FQDN trailing dot before lowercasing so
            // `ns1.example.com.` and `ns1.example.com` collapse together.
            let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() || !host.contains('.') {
                continue;
            }
            if !seen.insert(format!("dom:{host}")) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Domain, &host, confidence::HIGH, scan_id);
            e.tag("whoisxml");
            e.tag("nameserver");
            e.add_evidence(base_ev.clone().with_attr("ns_for", domain));
            out.push(e);
        }
    }

    out
}

/// Compose a WHOIS contact's `city, state, country` into a single location string
/// for an `Address` geo-hint. `None` when no part is present. A registrant `city`
/// sharpens the hint from a state centroid to a city-grain lead.
fn contact_location(c: &Contact) -> Option<String> {
    let parts: Vec<String> = [nonempty(&c.city), nonempty(&c.state), nonempty(&c.country)]
        .into_iter()
        .flatten()
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
