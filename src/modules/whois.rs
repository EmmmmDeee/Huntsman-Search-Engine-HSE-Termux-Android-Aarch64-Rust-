//! Raw whois protocol (TCP port 43). Free, no key, no root.
//!
//! Most TLDs delegate via referral — we follow one hop to the authoritative
//! whois server, then parse the response for registrar / dates / registrant
//! email. The parser is line-prefix based, robust across the half-dozen
//! mostly-but-not-quite-RFC-3912 dialects in the wild.

use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "whois";

pub struct Whois;

const IANA_WHOIS: &str = "whois.iana.org:43";
const QUERY_TIMEOUT_MS: u64 = 4000;

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
            Some(server) => {
                let target_server = if server.contains(':') {
                    server.clone()
                } else {
                    format!("{server}:43")
                };
                query(&target_server, &query_value).await.unwrap_or(raw)
            }
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

        let mut ev = Evidence::new(SRC, format!("WHOIS for {}", target.value));
        if let Some(v) = &registrar {
            ev = ev.with_attr("registrar", v);
        }
        if let Some(v) = &registrar_iana {
            ev = ev.with_attr("registrar_iana_id", v);
        }
        if let Some(v) = &registrar_url {
            ev = ev.with_attr("registrar_url", v);
        }
        if let Some(v) = &created {
            ev = ev.with_attr("created", v);
        }
        if let Some(v) = &updated {
            ev = ev.with_attr("updated", v);
        }
        if let Some(v) = &expires {
            ev = ev.with_attr("expires", v);
        }
        if !nameservers.is_empty() {
            ev = ev.with_attr("name_servers", nameservers.join(", "));
        }
        if !statuses.is_empty() {
            ev = ev.with_attr("statuses", statuses.join(", "));
        }
        if let Some(v) = &dnssec {
            ev = ev.with_attr("dnssec", v);
        }
        if let Some(v) = &registrant_org {
            ev = ev.with_attr("registrant_org", v);
        }
        if let Some(v) = &registrant_country {
            ev = ev.with_attr("registrant_country", v);
        }
        if let Some(v) = &registrant_state {
            ev = ev.with_attr("registrant_state", v);
        }
        if let Some(v) = &registrant_email {
            ev = ev.with_attr("registrant_email", v);
        }
        if let Some(v) = &admin_email {
            ev = ev.with_attr("admin_email", v);
        }
        if let Some(v) = &tech_email {
            ev = ev.with_attr("tech_email", v);
        }
        if let Some(v) = &abuse_email {
            ev = ev.with_attr("abuse_email", v);
        }

        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);

        // Surface contact emails as discrete Email entities so they fan
        // out as scan targets in autonomous-expansion mode.
        for (email, role) in [
            (&registrant_email, "registrant"),
            (&admin_email, "admin"),
            (&tech_email, "tech"),
            (&abuse_email, "abuse"),
        ] {
            if let Some(addr) = email {
                let mut e = Entity::new(EntityKind::Email, addr, 0.78, &_ctx.scan_id);
                e.tag(format!("whois-{role}"));
                e.add_evidence(
                    Evidence::new(SRC, format!("WHOIS {role} contact for {}", target.value))
                        .with_attr("role", role)
                        .with_attr("parent_target", target.value.as_str()),
                );
                result.push(e);
            }
        }

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
        for ns in &nameservers {
            let host = ns.trim_end_matches('.').to_lowercase();
            if host.is_empty() {
                continue;
            }
            let mut e = Entity::new(EntityKind::Domain, &host, 0.82, &_ctx.scan_id);
            e.tag("whois-ns");
            e.add_evidence(
                Evidence::new(SRC, format!("Nameserver for {}", target.value))
                    .with_attr("parent_target", target.value.as_str()),
            );
            result.push(e);
        }

        Ok(result)
    }
}

async fn query(server: &str, q: &str) -> std::io::Result<String> {
    let mut stream = timeout(
        Duration::from_millis(QUERY_TIMEOUT_MS),
        TcpStream::connect(server),
    )
    .await??;
    let mut query_line = String::with_capacity(q.len() + 2);
    query_line.push_str(q);
    query_line.push_str("\r\n");
    stream.write_all(query_line.as_bytes()).await?;
    let mut buf = String::with_capacity(4096);
    // Cap the read at 64 KiB so a malicious or misconfigured whois server
    // can't OOM the engine by streaming forever. Real WHOIS responses are
    // ≪ 64 KiB (typically 2–8 KiB).
    timeout(
        Duration::from_millis(QUERY_TIMEOUT_MS),
        (&mut stream).take(65_536).read_to_string(&mut buf),
    )
    .await??;
    Ok(buf)
}

fn find_referral(text: &str) -> Option<String> {
    for line in text.lines() {
        // Use the zero-alloc helper for consistency with field() /
        // all_fields() below. The previous per-line `to_lowercase()`
        // allocation here contradicted the v0.5 "zero allocation" promise.
        if (starts_with_ascii_ci(line, "whois:") || starts_with_ascii_ci(line, "refer:"))
            && let Some((_, rest)) = line.split_once(':')
        {
            let v = rest.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// True if `line`'s leading bytes match `key` ignoring ASCII case. Avoids the
/// per-line `to_lowercase()` allocation a `lower.starts_with(&lkey)` check
/// would force (WHOIS keys are pure ASCII).
fn starts_with_ascii_ci(line: &str, key: &str) -> bool {
    line.len() >= key.len() && line.as_bytes()[..key.len()].eq_ignore_ascii_case(key.as_bytes())
}

fn field(text: &str, keys: &[&str]) -> Option<String> {
    for line in text.lines() {
        for key in keys {
            if starts_with_ascii_ci(line, key)
                && let Some((_, rest)) = line.split_once(':')
            {
                let v = rest.trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

fn all_fields(text: &str, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        for key in keys {
            if starts_with_ascii_ci(line, key)
                && let Some((_, rest)) = line.split_once(':')
            {
                let v = rest.trim().to_string();
                if !v.is_empty() && !out.contains(&v) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// The typed fields parsed out of a raw WHOIS response. Pure data — the
/// entity-building in `process` consumes these by name.
struct WhoisFields {
    registrar: Option<String>,
    registrar_iana: Option<String>,
    registrar_url: Option<String>,
    updated: Option<String>,
    created: Option<String>,
    expires: Option<String>,
    registrant_email: Option<String>,
    registrant_org: Option<String>,
    registrant_country: Option<String>,
    registrant_state: Option<String>,
    admin_email: Option<String>,
    tech_email: Option<String>,
    abuse_email: Option<String>,
    nameservers: Vec<String>,
    statuses: Vec<String>,
    dnssec: Option<String>,
}

/// Parse a raw WHOIS response body into the [`WhoisFields`] we surface. Pure
/// (no I/O), so it is unit-testable against canned WHOIS text. Email fields are
/// filtered to require an `@` (some registries return "REDACTED" placeholders).
fn parse_whois(response: &str) -> WhoisFields {
    WhoisFields {
        registrar: field(response, &["Registrar:", "Sponsoring Registrar:"]),
        registrar_iana: field(response, &["Registrar IANA ID:", "Registrar IANA Number:"]),
        registrar_url: field(response, &["Registrar URL:", "Registrar Website:"]),
        updated: field(
            response,
            &[
                "Updated Date:",
                "Last Modified:",
                "Last updated:",
                "changed:",
            ],
        ),
        created: field(response, &["Creation Date:", "created:", "Created On:"]),
        expires: field(
            response,
            &[
                "Registry Expiry Date:",
                "Registrar Registration Expiration Date:",
                "expires:",
                "paid-till:",
            ],
        ),
        registrant_email: field(
            response,
            &["Registrant Email:", "Tech Email:", "Admin Email:"],
        )
        .filter(|e| e.contains('@')),
        registrant_org: field(
            response,
            &[
                "Registrant Organization:",
                "Registrant Organisation:",
                "org:",
            ],
        ),
        registrant_country: field(response, &["Registrant Country:", "country:"]),
        registrant_state: field(
            response,
            &["Registrant State/Province:", "Registrant State:"],
        ),
        admin_email: field(response, &["Admin Email:"]).filter(|e| e.contains('@')),
        tech_email: field(response, &["Tech Email:"]).filter(|e| e.contains('@')),
        abuse_email: field(
            response,
            &[
                "Registrar Abuse Contact Email:",
                "abuse-mailbox:",
                "OrgAbuseEmail:",
            ],
        )
        .filter(|e| e.contains('@')),
        nameservers: all_fields(response, &["Name Server:", "nserver:"]),
        statuses: all_fields(response, &["Domain Status:", "status:"]),
        dnssec: field(response, &["DNSSEC:", "dnssec:"]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_and_ip() {
        let m = Whois;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn parses_referral() {
        let s = "refer:        whois.verisign-grs.com\nstatus:        ACTIVE";
        assert_eq!(find_referral(s).as_deref(), Some("whois.verisign-grs.com"));
    }

    #[test]
    fn parses_field_case_insensitive() {
        let s = "Registrar: Example LLC\nCreation Date: 2020-01-01";
        assert_eq!(field(s, &["Registrar:"]).as_deref(), Some("Example LLC"));
        assert_eq!(
            field(s, &["Creation Date:", "created:"]).as_deref(),
            Some("2020-01-01")
        );
    }

    #[test]
    fn parses_multiple_nameservers_deduplicated() {
        let s = "Name Server: NS1.EXAMPLE.COM\nName Server: NS2.EXAMPLE.COM\nName Server: NS1.EXAMPLE.COM";
        let ns = all_fields(s, &["Name Server:"]);
        assert_eq!(ns.len(), 2);
    }

    #[test]
    fn parse_whois_extracts_typed_fields() {
        let s = "\
Registrar: Example Registrar LLC
Registrar IANA ID: 1234
Creation Date: 2020-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Updated Date: 2024-06-01T00:00:00Z
Registrant Organization: Example Org
Registrant Country: US
Registrant State/Province: NV
Registrant Email: owner@example.com
Admin Email: admin@example.com
Tech Email: tech@example.com
Registrar Abuse Contact Email: abuse@registrar.com
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
DNSSEC: unsigned
";
        let f = parse_whois(s);
        assert_eq!(f.registrar.as_deref(), Some("Example Registrar LLC"));
        assert_eq!(f.registrar_iana.as_deref(), Some("1234"));
        assert_eq!(f.created.as_deref(), Some("2020-01-01T00:00:00Z"));
        assert_eq!(f.expires.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert_eq!(f.updated.as_deref(), Some("2024-06-01T00:00:00Z"));
        assert_eq!(f.registrant_org.as_deref(), Some("Example Org"));
        assert_eq!(f.registrant_country.as_deref(), Some("US"));
        assert_eq!(f.registrant_state.as_deref(), Some("NV"));
        assert_eq!(f.registrant_email.as_deref(), Some("owner@example.com"));
        assert_eq!(f.admin_email.as_deref(), Some("admin@example.com"));
        assert_eq!(f.tech_email.as_deref(), Some("tech@example.com"));
        assert_eq!(f.abuse_email.as_deref(), Some("abuse@registrar.com"));
        assert_eq!(f.nameservers, ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]);
        assert_eq!(f.statuses, ["clientTransferProhibited"]);
        assert_eq!(f.dnssec.as_deref(), Some("unsigned"));
    }

    #[test]
    fn parse_whois_filters_non_at_email_placeholders() {
        // Registrant Email present but without '@' (REDACTED placeholder) → None.
        let f = parse_whois("Registrant Email: REDACTED FOR PRIVACY\nRegistrar: X");
        assert!(f.registrant_email.is_none());
        assert_eq!(f.registrar.as_deref(), Some("X"));
    }
}
