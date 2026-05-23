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
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
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

    fn priority(&self) -> u8 {
        32
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
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
        let created = field(&response, &["Creation Date:", "created:", "Created On:"]);
        let expires = field(
            &response,
            &[
                "Registry Expiry Date:",
                "Registrar Registration Expiration Date:",
                "expires:",
            ],
        );
        let registrant_email = field(
            &response,
            &["Registrant Email:", "Tech Email:", "Admin Email:"],
        )
        .filter(|e| e.contains('@'));
        let nameservers = all_fields(&response, &["Name Server:", "nserver:"]);

        // No actionable data parsed — skip the entity to avoid noise.
        if registrar.is_none() && created.is_none() && nameservers.is_empty() {
            return Ok(ModuleResult::new());
        }

        let kind = match target.kind {
            TargetKind::IpAddress => EntityKind::IpAddress,
            _ => EntityKind::Domain,
        };

        let mut entity = Entity::new(kind, &target.value, 0.85, &_ctx.scan_id);

        let mut ev = Evidence::new("whois", format!("WHOIS for {}", target.value));
        if let Some(v) = &registrar {
            ev = ev.with_attr("registrar", v);
        }
        if let Some(v) = &created {
            ev = ev.with_attr("created", v);
        }
        if let Some(v) = &expires {
            ev = ev.with_attr("expires", v);
        }
        if !nameservers.is_empty() {
            ev = ev.with_attr("name_servers", nameservers.join(", "));
        }
        if let Some(v) = &registrant_email {
            ev = ev.with_attr("registrant_email", v);
        }

        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

async fn query(server: &str, q: &str) -> std::io::Result<String> {
    let mut stream = timeout(
        Duration::from_millis(QUERY_TIMEOUT_MS),
        TcpStream::connect(server),
    )
    .await??;
    stream.write_all(format!("{q}\r\n").as_bytes()).await?;
    let mut buf = String::new();
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
    fn is_free() {
        assert_eq!(Whois.cost(), ModuleCost::Free);
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
