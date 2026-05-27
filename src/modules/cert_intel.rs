//! Certificate intelligence — CT log search + live TLS probe.
//!
//! Merges the former `crtsh` and `ssl_probe` modules into one pass.
//! For a Domain target the module:
//!   1. Queries crt.sh for CT-log entries (subdomains, issuers, validity).
//!   2. Connects to port 443 and extracts the live certificate's SANs,
//!      issuer, subject, serial, and HSTS header.
//!
//! Discovered subdomains from both sources are deduplicated before emission.
//! Free, no API key required.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::fetch_json;

// ── crt.sh response types ──────────────────────────────────────────

#[derive(Deserialize)]
struct CrtEntry {
    name_value: String,
    issuer_name: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    serial_number: Option<String>,
}

// ── Module ─────────────────────────────────────────────────────────

const SRC: &str = "cert_intel";

pub struct CertIntel;

#[async_trait]
impl Module for CertIntel {
    fn name(&self) -> &'static str {
        "cert_intel"
    }

    fn description(&self) -> &'static str {
        "Certificate intelligence: CT log search and live TLS probe"
    }

    fn priority(&self) -> u8 {
        33
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let mut seen_subs: HashSet<String> = HashSet::new();
        let parent = domain.to_lowercase();

        // CT-log search only works for domain targets (indexed by name).
        // IP targets skip straight to the live TLS probe.
        if target.kind == TargetKind::Domain {
            let ct_url = format!("https://crt.sh/?q=%.{domain}&output=json");
            if let Ok(entries) = fetch_json::<Vec<CrtEntry>>(&ctx.http, SRC, &ct_url).await
            {
                for entry in &entries {
                    for name in entry.name_value.split('\n') {
                        let name = name.trim().trim_start_matches("*.").to_lowercase();
                        if name.is_empty() || !name.contains('.') {
                            continue;
                        }
                        if name == parent {
                            continue;
                        }
                        if seen_subs.insert(name.clone()) {
                            let mut e = Entity::new(EntityKind::Domain, &name, 0.88, &ctx.scan_id);
                            e.tag(tags::CT_LOG);
                            e.add_evidence(
                                Evidence::new(
                                    SRC,
                                    format!("Certificate transparency: {name}"),
                                )
                                .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or("-"))
                                .with_attr("not_before", entry.not_before.as_deref().unwrap_or("-"))
                                .with_attr("not_after", entry.not_after.as_deref().unwrap_or("-"))
                                .with_attr(
                                    "serial_number",
                                    entry.serial_number.as_deref().unwrap_or("-"),
                                )
                                .with_attr("parent_domain", domain),
                            );
                            result.push(e);
                        }
                    }
                }
            }
        } // end CT-log search (domain-only)

        // ── 2. Live TLS certificate probe (works for both Domain and IP) ──
        let url = format!("https://{domain}/");
        if let Ok(resp) = ctx
            .http
            .head(&url)
            .send()
            .await
            .map_err(|e| Error::module(SRC, format!("TLS connect: {e}")))
        {
            let mut entity = target.to_entity(0.88, &ctx.scan_id);
            entity.tag("tls");

            let mut ev = Evidence::new(SRC, format!("TLS certificate for {domain}"))
                .with_attr("port", "443");

            let tls_info = resp.extensions().get::<reqwest::tls::TlsInfo>();
            if let Some(info) = tls_info
                && let Some(der) = info.peer_certificate()
            {
                parse_certificate(
                    der,
                    domain,
                    &ctx.scan_id,
                    &mut entity,
                    &mut ev,
                    &mut result,
                    &mut seen_subs,
                );
            }

            let status = resp.status();
            ev = ev.with_attr("http_status", status.as_u16().to_string());

            if let Some(hsts) = resp.headers().get("strict-transport-security")
                && let Ok(v) = hsts.to_str()
            {
                ev = ev.with_attr("hsts", v);
                entity.tag("hsts");
            }

            entity.add_evidence(ev);
            result.push(entity);
        }

        Ok(result)
    }
}

// ── DER parsing helpers ───────────────────────────

fn parse_certificate(
    der: &[u8],
    target_domain: &str,
    scan_id: &str,
    entity: &mut Entity,
    ev: &mut Evidence,
    result: &mut ModuleResult,
    seen_subs: &mut HashSet<String>,
) {
    let sans = extract_sans_from_der(der);

    if !sans.is_empty() {
        let san_count = sans.len();
        let san_display: Vec<&str> = sans.iter().take(30).map(String::as_str).collect();
        ev.attributes
            .insert("san_count".into(), san_count.to_string());
        ev.attributes.insert("sans".into(), san_display.join(", "));

        let target_lower = target_domain.to_lowercase();
        for san in &sans {
            let san_lower = san.to_lowercase();
            let is_sub = san_lower != target_lower
                && san_lower.ends_with(&format!(".{target_lower}"))
                && !san_lower.starts_with("*.");

            if is_sub && seen_subs.insert(san_lower.clone()) {
                let mut sub = Entity::new(EntityKind::Domain, &san_lower, 0.85, scan_id);
                sub.tag(tags::SUBDOMAIN);
                sub.tag("tls-san");
                sub.add_evidence(
                    Evidence::new(
                        "cert_intel",
                        format!("TLS SAN on {target_domain} certificate"),
                    )
                    .with_attr("parent_domain", target_domain),
                );
                result.push(sub);
            }
        }

        if san_count > 10 {
            entity.tag("multi-san");
        }
    }

    if let Some(issuer) = extract_field_from_der(der, &[0x55, 0x04, 0x03], true) {
        ev.attributes.insert("issuer".into(), issuer);
    }
    if let Some(subject) = extract_field_from_der(der, &[0x55, 0x04, 0x03], false) {
        ev.attributes.insert("subject".into(), subject);
    }
    if let Some(org) = extract_field_from_der(der, &[0x55, 0x04, 0x0A], true) {
        ev.attributes.insert("issuer_org".into(), org);
    }

    let serial = extract_serial_hex(der);
    if !serial.is_empty() {
        ev.attributes.insert("serial".into(), serial);
    }
}

fn extract_sans_from_der(der: &[u8]) -> Vec<String> {
    let mut sans = Vec::new();
    let san_oid: &[u8] = &[0x55, 0x1D, 0x11];

    for i in 0..der.len().saturating_sub(san_oid.len()) {
        if &der[i..i + san_oid.len()] == san_oid {
            let search_start = i + san_oid.len();
            let search_end = (search_start + 4096).min(der.len());
            let region = &der[search_start..search_end];

            let mut pos = 0;
            while pos + 2 < region.len() {
                let tag = region[pos];
                let len = region[pos + 1] as usize;
                if tag == 0x82 && len > 0 && pos + 2 + len <= region.len() {
                    if let Ok(name) = std::str::from_utf8(&region[pos + 2..pos + 2 + len]) {
                        let name = name.trim();
                        if name.contains('.') && name.len() > 3 && name.len() <= 253 {
                            sans.push(name.to_lowercase());
                        }
                    }
                    pos += 2 + len;
                } else if (tag == 0x82 || tag == 0x87) && len > 0 {
                    pos += 2 + len;
                } else {
                    break;
                }
            }
            break;
        }
    }
    sans.sort_unstable();
    sans.dedup();
    sans
}

fn extract_field_from_der(der: &[u8], oid: &[u8], first: bool) -> Option<String> {
    let mut last_match = None;
    for i in 0..der.len().saturating_sub(oid.len()) {
        if &der[i..i + oid.len()] == oid {
            let after = i + oid.len();
            if after + 4 < der.len() {
                let mut pos = after;
                while pos < der.len() && pos < after + 6 {
                    let tag = der[pos];
                    if tag == 0x0C || tag == 0x13 || tag == 0x16 {
                        let len = der.get(pos + 1).copied().unwrap_or(0) as usize;
                        if pos + 2 + len <= der.len()
                            && let Ok(s) = std::str::from_utf8(&der[pos + 2..pos + 2 + len])
                        {
                            let s = s.trim().to_string();
                            if !s.is_empty() {
                                if first {
                                    return Some(s);
                                }
                                last_match = Some(s);
                            }
                        }
                        break;
                    }
                    pos += 1;
                }
            }
        }
    }
    last_match
}

fn extract_serial_hex(der: &[u8]) -> String {
    if der.len() < 15 {
        return String::new();
    }
    for i in 0..der.len().saturating_sub(3) {
        if der[i] == 0x02 {
            let len = der[i + 1] as usize;
            if len > 0 && len <= 20 && i + 2 + len <= der.len() {
                return der[i + 2..i + 2 + len]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
            }
        }
    }
    String::new()
}

// ── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_and_ip() {
        let m = CertIntel;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
    }

    #[test]
    fn extract_sans_from_empty() {
        assert!(extract_sans_from_der(&[]).is_empty());
    }

    #[test]
    fn extract_serial_from_short_der() {
        assert!(extract_serial_hex(&[0; 5]).is_empty());
    }

    #[test]
    fn extract_field_from_empty() {
        assert!(extract_field_from_der(&[], &[0x55, 0x04, 0x03], true).is_none());
    }

    #[test]
    fn module_metadata() {
        let m = CertIntel;
        assert_eq!(m.name(), "cert_intel");
        assert_eq!(m.priority(), 33);
        assert_eq!(m.max_timeout_ms(), 10_000);
    }
}
