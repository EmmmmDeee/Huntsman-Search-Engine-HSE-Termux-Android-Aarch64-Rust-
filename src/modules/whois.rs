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
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

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
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        // 1) Ask IANA who's authoritative for this name.
        let raw = query(IANA_WHOIS, &target.value)
            .await
            .map_err(|e| Error::module("whois", e.to_string()))?;

        // 2) If IANA's response references another whois server, follow once.
        let response = match find_referral(&raw) {
            Some(server) => {
                let target_server = format!("{server}:43");
                query(&target_server, &target.value).await.unwrap_or(raw)
            }
            None => raw,
        };

        // 3) Parse the response into the fields we surface.
        let registrar = field(&response, &["Registrar:", "Sponsoring Registrar:"]);
        let registrar_iana = field(&response, &["Registrar IANA ID:", "Registrar IANA Number:"]);
        let registrar_url = field(&response, &["Registrar URL:", "Registrar Website:"]);
        let updated = field(
            &response,
            &[
                "Updated Date:",
                "Last Modified:",
                "Last updated:",
                "changed:",
            ],
        );
        let created = field(&response, &["Creation Date:", "created:", "Created On:"]);
        let expires = field(
            &response,
            &[
                "Registry Expiry Date:",
                "Registrar Registration Expiration Date:",
                "expires:",
                "paid-till:",
            ],
        );
        let registrant_email = field(
            &response,
            &["Registrant Email:", "Tech Email:", "Admin Email:"],
        )
        .filter(|e| e.contains('@'));
        let registrant_org = field(
            &response,
            &[
                "Registrant Organization:",
                "Registrant Organisation:",
                "org:",
            ],
        );
        let registrant_country = field(&response, &["Registrant Country:", "country:"]);
        let registrant_state = field(
            &response,
            &["Registrant State/Province:", "Registrant State:"],
        );
        let admin_email = field(&response, &["Admin Email:"]).filter(|e| e.contains('@'));
        let tech_email = field(&response, &["Tech Email:"]).filter(|e| e.contains('@'));
        let abuse_email = field(
            &response,
            &[
                "Registrar Abuse Contact Email:",
                "abuse-mailbox:",
                "OrgAbuseEmail:",
            ],
        )
        .filter(|e| e.contains('@'));
        let nameservers = all_fields(&response, &["Name Server:", "nserver:"]);
        let statuses = all_fields(&response, &["Domain Status:", "status:"]);
        let dnssec = field(&response, &["DNSSEC:", "dnssec:"]);

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

        let mut ev = Evidence::new("whois", format!("WHOIS for {}", target.value));
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
                    Evidence::new(
                        "whois",
                        format!("WHOIS {role} contact for {}", target.value),
                    )
                    .with_attr("role", role)
                    .with_attr("parent_target", target.value.as_str()),
                );
                result.push(e);
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
                Evidence::new("whois", format!("Nameserver for {}", target.value))
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
}
