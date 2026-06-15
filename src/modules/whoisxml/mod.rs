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

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
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
    #[allow(dead_code)]
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
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
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
        "Structured WHOIS (registrant, contacts, dates, NS) via whoisxmlapi.com"
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

        let cache_key = domain.to_ascii_lowercase();
        let cache = crate::core::api_cache::global();
        let body_text: String = if let Some(cached) = cache.get(self.name(), &cache_key) {
            cached.body
        } else {
            let resp = ctx
                .http
                .get(&url)
                .send()
                .await
                // `without_url()` strips the URL (which carries the API key
                // as a query param) before formatting, so transport errors
                // don't leak the key into logs / events.
                .map_err(|e| Error::module(SRC, e.without_url().to_string()))?;
            let status = resp.status();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                ctx.report_key_exhausted(SRC, key, status.as_u16());
                return Err(Error::module(
                    SRC,
                    format!("HTTP {status}: invalid or expired API key"),
                ));
            }
            if status.as_u16() == 429 {
                ctx.report_key_exhausted(SRC, key, 429);
                return Err(Error::module(SRC, "rate-limited (429)"));
            }
            if !status.is_success() {
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }
            let text = resp
                .text()
                .await
                .map_err(|e| Error::module(SRC, format!("body: {e}")))?;
            cache.put(
                self.name(),
                &cache_key,
                &text,
                crate::core::api_cache::ttl_secs(self.name()),
            );
            text
        };

        let wrap: Wrap = serde_json::from_str(&body_text)
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;
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
        let mut base_ev =
            Evidence::new(SRC, format!("WhoisXML lookup for {domain}")).with_attr("domain", domain);
        if let Some(c) = rec.created_date.as_deref() {
            base_ev = base_ev.with_attr("created", c);
        }
        if let Some(u) = rec.updated_date.as_deref() {
            base_ev = base_ev.with_attr("updated", u);
        }
        if let Some(e) = rec.expires_date.as_deref() {
            base_ev = base_ev.with_attr("expires", e);
        }
        if let Some(reg) = rec.registrar_name.as_deref() {
            base_ev = base_ev.with_attr("registrar", reg);
        }
        if let Some(age) = rec.estimated_domain_age {
            base_ev = base_ev.with_attr("estimated_age_days", age.to_string());
        }
        if let Some(status) = rec.status.as_deref() {
            base_ev = base_ev.with_attr("status", status);
        }

        // ── Emit Registrant / Organisation entities ──
        for (contact, role) in [
            (rec.registrant.as_ref(), "registrant"),
            (rec.administrative_contact.as_ref(), "admin"),
            (rec.technical_contact.as_ref(), "technical"),
        ] {
            let Some(c) = contact else { continue };
            if let Some(org) = c.organization.as_deref().filter(|s| !s.is_empty()) {
                let mut e = Entity::new(EntityKind::Organisation, org, 0.70, &ctx.scan_id);
                e.tag("whoisxml");
                e.tag(format!("whois-{role}"));
                let mut ev = base_ev.clone().with_attr("contact_role", role);
                if let Some(cc) = c.country_code.as_deref().filter(|s| !s.is_empty()) {
                    ev = ev.with_attr("country_code", cc);
                }
                e.add_evidence(ev);
                result.push(e);
            }
            if let Some(name) = c.name.as_deref().filter(|s| !s.is_empty()) {
                let mut e = Entity::new(EntityKind::Person, name, 0.60, &ctx.scan_id);
                e.tag("whoisxml");
                e.tag(format!("whois-{role}"));
                let mut ev = base_ev.clone().with_attr("contact_role", role);
                if let Some(country) = c.country.as_deref().filter(|s| !s.is_empty()) {
                    ev = ev.with_attr("country", country);
                }
                if let Some(state) = c.state.as_deref().filter(|s| !s.is_empty()) {
                    ev = ev.with_attr("state", state);
                }
                e.add_evidence(ev);
                result.push(e);
            }
            if let Some(email) = c.email.as_deref().filter(|s| s.contains('@')) {
                let mut e = Entity::new(EntityKind::Email, email, 0.70, &ctx.scan_id);
                e.tag("whoisxml");
                e.tag(format!("whois-{role}-email"));
                let ev = base_ev.clone().with_attr("contact_role", role);
                e.add_evidence(ev);
                result.push(e);
            }
        }

        // ── Emit Name Server entities (Domain entities, tagged ns) ──
        if let Some(ns) = rec.name_servers {
            let mut seen_ns: std::collections::HashSet<String> = std::collections::HashSet::new();
            for host in ns.host_names {
                // Strip FQDN trailing dot before lowercasing so
                // `ns1.example.com.` and `ns1.example.com` collapse
                // to a single entity instead of emitting duplicates.
                let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
                if host.is_empty() || !host.contains('.') {
                    continue;
                }
                if !seen_ns.insert(host.clone()) {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Domain, &host, 0.65, &ctx.scan_id);
                e.tag("whoisxml");
                e.tag("nameserver");
                e.add_evidence(base_ev.clone().with_attr("ns_for", domain));
                result.push(e);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
