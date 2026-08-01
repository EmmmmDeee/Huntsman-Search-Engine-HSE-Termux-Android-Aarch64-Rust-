//! Raw whois protocol (TCP port 43). Free, no key, no root.
//!
//! Most TLDs delegate via referral — we follow one hop to the authoritative
//! whois server, then parse the response for registrar / dates / registrant
//! email. The parser is line-prefix based, robust across the half-dozen
//! mostly-but-not-quite-RFC-3912 dialects in the wild.
//!
//! ## Proxy-environment fallback
//!
//! TCP port 43 is not routable through an HTTPS proxy. When `HTTPS_PROXY` or
//! `https_proxy` is set the module detects this at dispatch time:
//! - **Domain targets** — skip cleanly; `rdap_domain` covers RDAP over HTTPS.
//! - **IP targets** — fall back to `https://rdap.org/ip/{addr}` which routes to
//!   the authoritative RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC) and returns the
//!   same org / country / abuse-contact data that TCP WHOIS would have provided.

mod client;
mod parse;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

use client::{find_referral, query, resolve_public_whois};
use parse::{WhoisFields, field, parse_whois};

const SRC: &str = "whois";
const IANA_WHOIS: &str = "whois.iana.org:43";
pub(super) const QUERY_TIMEOUT_MS: u64 = 4000;

// ── Proxy-environment detection ────────────────────────────────────────────

/// True when the process is running behind an HTTPS proxy. In that environment
/// TCP port 43 (raw WHOIS) is not reachable, so domain targets skip and IP
/// targets fall back to RDAP-over-HTTPS.
fn behind_proxy() -> bool {
    std::env::var_os("HTTPS_PROXY").is_some() || std::env::var_os("https_proxy").is_some()
}

// ── RDAP-over-HTTPS fallback for IP targets ────────────────────────────────

#[derive(Deserialize)]
struct RdapIpResp {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    entities: Vec<RdapIpEntity>,
}

#[derive(Deserialize)]
struct RdapIpEntity {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
    #[serde(default)]
    entities: Vec<RdapIpEntity>,
}

/// Extract the value of a named vCard property from a `vcardArray` JSON value.
/// `vcardArray = ["vcard", [[name, params, type, value], ...]]`
pub(crate) fn vcard_field(vcard: &serde_json::Value, prop: &str) -> Option<String> {
    let items = vcard.as_array()?.get(1)?.as_array()?;
    items.iter().find_map(|item| {
        let arr = item.as_array()?;
        (arr.first()?.as_str()? == prop).then(|| arr.get(3)?.as_str().map(str::to_string))?
    })
}

/// The real registrant-location parts (state, then country) for the Address
/// geo-hint — each dropped if it is empty or a whois privacy-proxy placeholder.
/// Uses the SAME single-sourced [`crate::core::validation::is_whois_privacy_placeholder`]
/// guard the registrant name/org paths apply, rather than a narrow inline
/// `redacted`/`privacy` substring check that let masked values like "Data
/// Protected", "Withheld", or ".au statutory masking" through as a fake Address.
/// **Pure** — unit-tested directly.
pub(super) fn registrant_location_parts<'a>(
    state: Option<&'a str>,
    country: &'a str,
) -> Vec<&'a str> {
    [state, Some(country)]
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty() && !crate::core::validation::is_whois_privacy_placeholder(p))
        .collect()
}

/// Walk `entities` recursively, returning the first one whose `roles` list
/// contains `role`.
fn find_ip_entity<'a>(entities: &'a [RdapIpEntity], role: &str) -> Option<&'a RdapIpEntity> {
    for e in entities {
        if e.roles.iter().any(|r| r == role) {
            return Some(e);
        }
        if let Some(found) = find_ip_entity(&e.entities, role) {
            return Some(found);
        }
    }
    None
}

/// RDAP-over-HTTPS fallback for IP targets when TCP/43 is unavailable.
///
/// `https://rdap.org/ip/{ip}` bootstraps to the authoritative RIR (ARIN /
/// RIPE / APNIC / LACNIC / AFRINIC) and returns the same org / country /
/// abuse-contact data that raw WHOIS would have provided.
async fn rdap_ip_fallback(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!(
        "https://rdap.org/ip/{}",
        crate::util::http::urlencode(&target.value)
    );
    let resp = ctx
        .http
        .get(&url)
        .header("Accept", "application/rdap+json")
        .timeout(std::time::Duration::from_secs(10))
        .send_tagged(SRC)
        .await?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(ModuleResult::new());
    }
    if !status.is_success() {
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }

    let body: RdapIpResp = crate::util::http::json_decode(SRC, resp).await?;

    let mut result = ModuleResult::new();
    let net_name = body.name.as_deref().unwrap_or("").trim().to_string();
    let country = body.country.as_deref().unwrap_or("").trim().to_string();

    // Registrant org name from vCard `fn` field, falling back to network block name.
    let org_name = find_ip_entity(&body.entities, "registrant")
        .and_then(|e| e.vcard_array.as_ref())
        .and_then(|vc| vcard_field(vc, "fn"))
        .filter(|s| !s.is_empty())
        .or_else(|| (!net_name.is_empty()).then(|| net_name.clone()));

    if let Some(org) = &org_name {
        let org = org.trim();
        if org.len() >= 3 {
            let mut ev =
                Evidence::new(SRC, format!("RDAP network registrant for {}", target.value))
                    .with_attr("source", "rdap-fallback")
                    .with_attr("ip", target.value.as_str());
            if !net_name.is_empty() {
                ev = ev.with_attr("net_name", net_name.as_str());
            }
            if !country.is_empty() {
                ev = ev.with_attr("country", country.as_str());
            }
            let mut oe = Entity::new(EntityKind::Organisation, org, 0.72, &ctx.scan_id);
            oe.tag("whois");
            oe.tag("rdap-fallback");
            oe.tag("ip-registrant");
            oe.add_evidence(ev);
            result.push(oe);
        }
    }

    if !country.is_empty() {
        let mut ae = Entity::new(
            EntityKind::Address,
            &country,
            confidence::MEDIUM,
            &ctx.scan_id,
        );
        ae.tag("whois");
        ae.tag("rdap-fallback");
        ae.tag("geoint");
        ae.add_evidence(
            Evidence::new(SRC, format!("RDAP country for {}", target.value))
                .with_attr("source", "rdap-fallback")
                .with_attr("ip", target.value.as_str()),
        );
        result.push(ae);
    }

    // Abuse contact email — the RIR abuse role is never GDPR-redacted for IPs.
    if let Some(email) = find_ip_entity(&body.entities, "abuse")
        .and_then(|e| e.vcard_array.as_ref())
        .and_then(|vc| vcard_field(vc, "email"))
        .filter(|e| e.contains('@'))
        .filter(|e| !crate::util::domains::is_infrastructure_email(e))
    {
        let mut ee = Entity::new(EntityKind::Email, &email, 0.72, &ctx.scan_id);
        ee.tag("whois-abuse");
        ee.tag("rdap-fallback");
        ee.add_evidence(
            Evidence::new(SRC, format!("RDAP abuse contact for {}", target.value))
                .with_attr("source", "rdap-fallback")
                .with_attr("ip", target.value.as_str()),
        );
        result.push(ee);
    }

    Ok(result)
}

pub struct Whois;

#[async_trait]
impl Module for Whois {
    fn name(&self) -> &'static str {
        "whois"
    }

    fn description(&self) -> &'static str {
        "WHOIS recon — harvests registration data and extracts registrant contacts from the raw record"
    }

    fn priority(&self) -> u8 {
        32
    }

    /// IANA query + one referral follow-up, each capped at
    /// `QUERY_TIMEOUT_MS = 4000`. Worst case 2 × 4 s = 8 s; round up
    /// to give the response read some headroom past connect timeout.
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::IpAddress | TargetKind::Url
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // WHOIS registration data — ATT&CK WHOIS (T1596.002).
        &["T1596.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        // When running behind an HTTPS proxy, TCP port 43 is not routable.
        // Domain targets skip instantly (rdap_domain covers that path over HTTPS).
        // IP targets fall back to RDAP-over-HTTPS for the same org/country/abuse data.
        if behind_proxy() {
            return match target.kind {
                TargetKind::IpAddress => rdap_ip_fallback(target, _ctx).await,
                _ => {
                    tracing::debug!(
                        module = SRC,
                        "skipping domain WHOIS — TCP/43 unavailable behind HTTPS proxy; \
                         rdap_domain provides structured registry data over HTTPS"
                    );
                    Ok(ModuleResult::new())
                }
            };
        }

        let query_value = match target.kind {
            TargetKind::Url => {
                let host = crate::util::url_util::host_only(&target.value);
                if host.is_empty() {
                    return Ok(ModuleResult::new());
                }
                host.to_string()
            }
            _ => target.value.clone(),
        };
        // 1) Ask IANA who's authoritative for this name.
        let raw = query(IANA_WHOIS, &query_value)
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        // 2) If IANA's response references another whois server, follow once.
        let response = match find_referral(&raw) {
            // SSRF gate (PROBLEM_TREE §7 S2): the referral host comes verbatim from
            // the WHOIS response (attacker-influenceable) and this raw TCP/43 path
            // bypasses the HTTP `SsrfResolver`, so resolve it to a vetted PUBLIC :43
            // address (pinned) before dialling. Refuse a private/internal/non-43
            // referral and keep IANA's answer rather than probing an internal host.
            Some(server) => match resolve_public_whois(&server).await {
                Some(addr) => query(addr, &query_value).await.unwrap_or(raw),
                None => raw,
            },
            None => raw,
        };

        crate::util::http::scan_for_api_keys_with_source(&response, "whois");

        // 3) Parse the response into the fields we surface.
        let WhoisFields {
            registrar,
            registrar_iana,
            registrar_url,
            updated,
            created,
            expires,
            registrant_email,
            registrant_org,
            registrant_country,
            registrant_state,
            admin_email,
            admin_name,
            admin_org,
            tech_email,
            tech_name,
            tech_org,
            abuse_email,
            nameservers,
            statuses,
            dnssec,
            phones,
        } = parse_whois(&response);

        // No actionable data parsed — skip the entity to avoid noise.
        if registrar.is_none() && created.is_none() && nameservers.is_empty() && statuses.is_empty()
        {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS_PLUS, &_ctx.scan_id);

        // Status flags become tags so the SPA can highlight them. These
        // are the most operationally interesting: lock states, hold flags,
        // pending transfers, etc.
        for status in &statuses {
            let lower = status.to_lowercase();
            for flag in [
                "clienttransferprohibited",
                "clientdeleteprohibited",
                "clientholdprohibited",
                "clientupdateprohibited",
                "servertransferprohibited",
                "serverdeleteprohibited",
                "serverholdprohibited",
                "serverupdateprohibited",
                "redemptionperiod",
                "pendingdelete",
                "pendingtransfer",
                "addperiod",
                "autorenewperiod",
                "ok",
            ] {
                if lower.contains(flag) {
                    entity.tag(format!("status:{flag}"));
                }
            }
        }
        if let Some(d) = &dnssec
            && d.to_lowercase().contains("unsigned")
        {
            entity.tag("dnssec:unsigned");
        }
        if let Some(d) = &dnssec
            && d.to_lowercase().contains("signed")
        {
            entity.tag("dnssec:signed");
        }

        // Parsed here (not only at the Person-emission site below) so the
        // registrant/admin/tech NAMES fold into the domain's own evidence attrs —
        // those attrs are what `core::relation::derive_registration` matches a
        // registrant Person against to build the Domain→Person `RegisteredBy`
        // edge. A redacted name folds harmlessly: no Person entity is emitted for
        // it, so it can never form an edge.
        let registrant_name = field(
            &response,
            &["Registrant Name:", "Registrant Person:", "person:"],
        );
        let ev = [
            ("registrar", registrar.clone()),
            ("registrar_iana_id", registrar_iana.clone()),
            ("registrar_url", registrar_url.clone()),
            ("created", created.clone()),
            ("updated", updated.clone()),
            ("expires", expires.clone()),
            (
                "name_servers",
                (!nameservers.is_empty()).then(|| nameservers.join(", ")),
            ),
            (
                "statuses",
                (!statuses.is_empty()).then(|| statuses.join(", ")),
            ),
            ("dnssec", dnssec.clone()),
            ("registrant_org", registrant_org.clone()),
            ("registrant_name", registrant_name.clone()),
            ("admin_name", admin_name.clone()),
            ("tech_name", tech_name.clone()),
            ("registrant_country", registrant_country.clone()),
            ("registrant_state", registrant_state.clone()),
            ("registrant_email", registrant_email.clone()),
            ("admin_email", admin_email.clone()),
            ("tech_email", tech_email.clone()),
            ("abuse_email", abuse_email.clone()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("WHOIS for {}", target.value)),
            |ev, (key, v)| ev.with_attr(key, v),
        );

        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);

        // Surface contact emails as discrete Email entities so they fan
        // out as scan targets in autonomous-expansion mode.
        // A WHOIS contact that is an infrastructure mailbox — a role address
        // (`abuse@`, `dns@`, `hostmaster@`) or a mailbox on a CDN/registrar/cloud
        // provider (`abuse@cloudflare.com`) — is the registrar/provider's desk,
        // NEVER the subject. Emitting it as a confidence::STRONG Email entity made it a
        // breach-checked, identity-clustered, expandable target (a real scan
        // merged `dns@cloudflare.com` / `abuse@cloudflare.com` into the subject's
        // identity). The address is still preserved in the parent domain's
        // evidence attrs above; it just must not become standalone PII.
        result.extend(
            [
                (&registrant_email, "registrant"),
                (&admin_email, "admin"),
                (&tech_email, "tech"),
                (&abuse_email, "abuse"),
            ]
            .into_iter()
            .filter_map(|(email, role)| {
                let addr = email.as_deref()?;
                if crate::util::domains::is_infrastructure_email(addr) {
                    return None;
                }
                let mut e = Entity::new(EntityKind::Email, addr, confidence::STRONG, &_ctx.scan_id);
                e.tag(format!("whois-{role}"));
                e.add_evidence(
                    Evidence::new(SRC, format!("WHOIS {role} contact for {}", target.value))
                        .with_attr("role", role)
                        .with_attr("parent_target", target.value.as_str()),
                );
                Some(e)
            }),
        );

        // Registrant organisation → Organisation entity.
        if let Some(org) = &registrant_org {
            let org = org.trim();
            if org.len() >= 3 && !crate::core::validation::is_whois_privacy_placeholder(org) {
                let mut oe = Entity::new(EntityKind::Organisation, org, 0.72, &_ctx.scan_id);
                oe.tag("whois");
                oe.tag(crate::core::tags::REGISTRANT);
                oe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS registrant for {}", target.value))
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(oe);
            }
        }

        // Registrant name → Person entity (when not redacted). `registrant_name`
        // is parsed above so it can also fold into the domain evidence.
        if let Some(name) = &registrant_name {
            let name = name.trim();
            if name.len() >= 4
                && name.contains(' ')
                && !crate::core::validation::is_whois_privacy_placeholder(name)
            {
                let mut pe = Entity::new(EntityKind::Person, name, 0.72, &_ctx.scan_id);
                pe.tag("whois");
                pe.tag(crate::core::tags::REGISTRANT);
                pe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS registrant for {}", target.value))
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(pe);
            }
        }

        // Registrant address → Address entity (when available and not a
        // privacy-proxy placeholder — via the SAME shared guard the registrant
        // name/org paths above use, not a narrow redacted/privacy substring test).
        if let Some(country) = &registrant_country {
            let parts = registrant_location_parts(registrant_state.as_deref(), country);
            if !parts.is_empty() && parts.iter().any(|p| p.len() >= 2) {
                let addr = parts.join(", ");
                let mut ae = Entity::new(
                    EntityKind::Address,
                    &addr,
                    confidence::MEDIUM,
                    &_ctx.scan_id,
                );
                ae.tag("whois");
                ae.tag(crate::core::tags::REGISTRANT);
                ae.tag("geoint");
                ae.add_evidence(
                    Evidence::new(SRC, format!("Registrant location for {}", target.value))
                        .with_attr("parent_target", target.value.as_str()),
                );
                if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
                    let coord_val = format!("{lat:.4},{lon:.4}");
                    let mut c = Entity::new(
                        EntityKind::Coordinates,
                        &coord_val,
                        confidence::LOW,
                        &_ctx.scan_id,
                    );
                    c.tag("whois");
                    c.tag("addr-derived");
                    c.tag("geoint");
                    c.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Geocode of registrant address for {}", target.value),
                        )
                        .with_attr("parent_target", target.value.as_str()),
                    );
                    result.push(c);
                }
                result.push(ae);
            }
        }

        // Admin and tech contact names / organisations — same redaction filter
        // as the registrant block above (the shared, complete privacy-proxy guard).
        let is_redacted = crate::core::validation::is_whois_privacy_placeholder;
        for (name_opt, role) in [(&admin_name, "admin"), (&tech_name, "tech")] {
            if let Some(name) = name_opt
                .as_deref()
                .map(str::trim)
                .filter(|n| n.len() >= 4 && n.contains(' ') && !is_redacted(n))
            {
                let mut pe = Entity::new(EntityKind::Person, name, confidence::HIGH, &_ctx.scan_id);
                pe.tag("whois");
                pe.tag(role);
                pe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS {} contact for {}", role, target.value))
                        .with_attr("role", role)
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(pe);
            }
        }
        for (org_opt, role) in [(&admin_org, "admin"), (&tech_org, "tech")] {
            if let Some(org) = org_opt
                .as_deref()
                .map(str::trim)
                .filter(|o| o.len() >= 3 && !is_redacted(o))
            {
                let mut oe = Entity::new(EntityKind::Organisation, org, 0.62, &_ctx.scan_id);
                oe.tag("whois");
                oe.tag(role);
                oe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS {} org for {}", role, target.value))
                        .with_attr("role", role)
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(oe);
            }
        }

        // Contact phone numbers — redacted values are already excluded in
        // parse_whois; each surviving number is in E.164 `+<digits>` form.
        for phone in &phones {
            let mut pe = Entity::new(EntityKind::Phone, phone, 0.68, &_ctx.scan_id);
            pe.tag("whois");
            pe.add_evidence(
                Evidence::new(SRC, format!("WHOIS contact phone for {}", target.value))
                    .with_attr("parent_target", target.value.as_str()),
            );
            result.push(pe);
        }

        // Surface nameservers as Domain entities too so DNS chaining
        // picks them up at depth>=1.
        result.extend(nameservers.iter().filter_map(|ns| {
            let host = ns.trim_end_matches('.').to_lowercase();
            if host.is_empty() {
                return None;
            }
            let mut e = Entity::new(EntityKind::Domain, &host, 0.82, &_ctx.scan_id);
            e.tag("whois-ns");
            e.add_evidence(
                Evidence::new(SRC, format!("Nameserver for {}", target.value))
                    .with_attr("parent_target", target.value.as_str()),
            );
            Some(e)
        }));

        Ok(result)
    }
}
