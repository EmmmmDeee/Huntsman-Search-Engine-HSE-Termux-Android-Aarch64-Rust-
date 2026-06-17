//! Raw whois protocol (TCP port 43). Free, no key, no root.
//!
//! Most TLDs delegate via referral — we follow one hop to the authoritative
//! whois server, then parse the response for registrar / dates / registrant
//! email. The parser is line-prefix based, robust across the half-dozen
//! mostly-but-not-quite-RFC-3912 dialects in the wild.

mod client;
mod parse;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

use client::{find_referral, query, resolve_public_whois};
use parse::{WhoisFields, field, parse_whois};

const SRC: &str = "whois";
const IANA_WHOIS: &str = "whois.iana.org:43";
pub(super) const QUERY_TIMEOUT_MS: u64 = 4000;

pub struct Whois;

#[async_trait]
impl Module for Whois {
    fn name(&self) -> &'static str {
        "whois"
    }

    fn description(&self) -> &'static str {
        "WHOIS registration data and contact extraction"
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
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
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
            tech_email,
            abuse_email,
            nameservers,
            statuses,
            dnssec,
        } = parse_whois(&response);

        // No actionable data parsed — skip the entity to avoid noise.
        if registrar.is_none() && created.is_none() && nameservers.is_empty() && statuses.is_empty()
        {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.85, &_ctx.scan_id);

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
        // NEVER the subject. Emitting it as a 0.78 Email entity made it a
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
                let mut e = Entity::new(EntityKind::Email, addr, 0.78, &_ctx.scan_id);
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
            if org.len() >= 3
                && !org.eq_ignore_ascii_case("REDACTED FOR PRIVACY")
                && !org.to_lowercase().contains("privacy")
                && !org.to_lowercase().contains("redacted")
            {
                let mut oe = Entity::new(EntityKind::Organisation, org, 0.72, &_ctx.scan_id);
                oe.tag("whois");
                oe.tag("registrant");
                oe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS registrant for {}", target.value))
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(oe);
            }
        }

        // Registrant name → Person entity (when not redacted).
        let registrant_name = field(
            &response,
            &["Registrant Name:", "Registrant Person:", "person:"],
        );
        if let Some(name) = &registrant_name {
            let name = name.trim();
            if name.len() >= 4
                && name.contains(' ')
                && !name.to_lowercase().contains("privacy")
                && !name.to_lowercase().contains("redacted")
                && !name.to_lowercase().contains("data protected")
                && !name.to_lowercase().contains("not disclosed")
            {
                let mut pe = Entity::new(EntityKind::Person, name, 0.72, &_ctx.scan_id);
                pe.tag("whois");
                pe.tag("registrant");
                pe.add_evidence(
                    Evidence::new(SRC, format!("WHOIS registrant for {}", target.value))
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(pe);
            }
        }

        // Registrant address → Address entity (when available and not redacted).
        if let Some(country) = &registrant_country {
            let parts: Vec<&str> = [registrant_state.as_deref(), Some(country.as_str())]
                .iter()
                .filter_map(|p| *p)
                .filter(|p| {
                    !p.is_empty()
                        && !p.to_lowercase().contains("redacted")
                        && !p.to_lowercase().contains("privacy")
                })
                .collect();
            if !parts.is_empty() && parts.iter().any(|p| p.len() >= 2) {
                let addr = parts.join(", ");
                let mut ae = Entity::new(EntityKind::Address, &addr, 0.50, &_ctx.scan_id);
                ae.tag("whois");
                ae.tag("registrant");
                ae.tag("geoint");
                ae.add_evidence(
                    Evidence::new(SRC, format!("Registrant location for {}", target.value))
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(ae);
            }
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
