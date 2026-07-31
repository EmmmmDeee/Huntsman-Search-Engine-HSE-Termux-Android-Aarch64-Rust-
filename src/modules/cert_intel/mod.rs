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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
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
        "Certificate intelligence — sweeps CT logs and fingerprints a host via live TLS probe"
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // TLS certificate intel — ATT&CK Digital Certificates (T1596.003).
        &["T1596.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Domain from dNSName SANs / CT-log names; Email from rfc822Name SANs
        // (S/MIME and client-auth certificates) and CT-log email entries.
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::Email];
        KINDS
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
            if let Ok(entries) = fetch_json::<Vec<CrtEntry>>(&ctx.http, SRC, &ct_url).await {
                result.extend(ct_log_entities(
                    &entries,
                    &parent,
                    &ctx.scan_id,
                    &mut seen_subs,
                ));
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
            let mut entity = target.to_entity(confidence::EXPERT, &ctx.scan_id);
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

/// Map crt.sh CT-log entries to Domain entities, discriminating confidence by the
/// subdomain relationship. A `%.domain` CT query returns the WHOLE matched
/// certificate's SAN list, which on a shared-hosting cert includes unrelated
/// co-tenant domains — so a proper subdomain of `parent` is a confirmed asset
/// (confidence::EXPERT, tagged [`tags::SUBDOMAIN`]) while a co-listed non-subdomain is only a
/// weak co-hosting lead (confidence::LOW_MEDIUM, tagged `co-hosted`): they must NOT carry identical
/// high confidence, or an unrelated co-tenant is over-attributed to the subject.
/// Matches the discrimination the TLS-SAN path and the sibling `crtsh` module
/// already apply. Dedups across both cert paths via `seen_subs`.
fn ct_log_entities(
    entries: &[CrtEntry],
    parent: &str,
    scan_id: &str,
    seen_subs: &mut HashSet<String>,
) -> Vec<Entity> {
    let cert_ev = |entry: &CrtEntry, msg: String| {
        Evidence::new(SRC, msg)
            .with_attr("issuer", entry.issuer_name.as_deref().unwrap_or("-"))
            .with_attr("not_before", entry.not_before.as_deref().unwrap_or("-"))
            .with_attr("not_after", entry.not_after.as_deref().unwrap_or("-"))
            .with_attr(
                "serial_number",
                entry.serial_number.as_deref().unwrap_or("-"),
            )
            .with_attr("parent_domain", parent)
    };
    entries
        .iter()
        .flat_map(|entry| entry.name_value.split('\n').map(move |name| (entry, name)))
        .filter_map(|(entry, name)| {
            let name = name.trim().trim_start_matches("*.").to_lowercase();
            if name.is_empty() || name == parent || !seen_subs.insert(name.clone()) {
                return None;
            }
            // An rfc822Name SAN — crt.sh returns these inline in `name_value` — is
            // an email address, not a hostname. Emit it as an Email pivot rather
            // than a bogus Domain like `admin@example.com` (which `.contains('.')`
            // alone would have admitted); parity with the sibling crtsh module.
            if crate::util::extract::looks_like_email(&name) {
                let mut e = Entity::new(EntityKind::Email, &name, 0.70, scan_id);
                e.tag(tags::CT_LOG);
                e.add_evidence(cert_ev(entry, format!("Email in certificate SAN: {name}")));
                return Some(e);
            }
            if !name.contains('.') {
                return None;
            }
            let is_sub = crate::util::domains::is_proper_subdomain_of(&name, parent);
            let conf = if is_sub {
                confidence::EXPERT
            } else {
                confidence::LOW_MEDIUM
            };
            let mut e = Entity::new(EntityKind::Domain, &name, conf, scan_id);
            e.tag(tags::CT_LOG);
            if is_sub {
                e.tag(tags::SUBDOMAIN);
            } else {
                e.tag("co-hosted");
            }
            e.add_evidence(cert_ev(entry, format!("Certificate transparency: {name}")));
            Some(e)
        })
        .collect()
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
    let CertSans {
        domains: sans,
        emails: email_sans,
    } = extract_sans_from_der(der);

    if !sans.is_empty() {
        let san_count = sans.len();
        let san_display: Vec<&str> = sans.iter().take(30).map(String::as_str).collect();
        ev.attributes
            .insert("san_count".into(), san_count.to_string());
        ev.attributes.insert("sans".into(), san_display.join(", "));

        let target_lower = target_domain.to_lowercase();
        result.extend(sans.iter().filter_map(|san| {
            let san_lower = san.to_lowercase();
            let is_sub = crate::util::domains::is_proper_subdomain_of(&san_lower, &target_lower)
                && !san_lower.starts_with("*.");
            if !is_sub || !seen_subs.insert(san_lower.clone()) {
                return None;
            }
            let mut sub = Entity::new(
                EntityKind::Domain,
                &san_lower,
                confidence::HIGH_PLUSPLUS_PLUS,
                scan_id,
            );
            sub.tag(tags::SUBDOMAIN);
            sub.tag("tls-san");
            sub.add_evidence(
                Evidence::new(
                    "cert_intel",
                    format!("TLS SAN on {target_domain} certificate"),
                )
                .with_attr("parent_domain", target_domain),
            );
            Some(sub)
        }));

        if san_count > 10 {
            entity.tag("multi-san");
        }
    }

    // rfc822Name SANs (S/MIME and client-auth certificates carry these) → Email
    // pivots. Deduped across both cert paths via `seen_subs`; an email string can
    // never collide with the hostnames the set also holds.
    for email in &email_sans {
        if !seen_subs.insert(email.clone()) {
            continue;
        }
        let mut e = Entity::new(EntityKind::Email, email, 0.70, scan_id);
        e.tag("tls-san");
        e.add_evidence(
            Evidence::new(SRC, format!("Email SAN on {target_domain} certificate"))
                .with_attr("parent_domain", target_domain),
        );
        result.push(e);
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

/// Decode the length octet(s) of a DER TLV whose tag is at `der[pos]`.
/// Returns `(header_len, content_len)` where `header_len` is the bytes consumed
/// by the tag + length field (so the content starts at `pos + header_len`).
/// Handles short form (`< 0x80`) and long form (`0x81`/`0x82` → 1- or 2-byte
/// length); rejects indefinite/over-long forms (none occur in a DER cert).
fn der_tlv_len(der: &[u8], pos: usize) -> Option<(usize, usize)> {
    let l0 = *der.get(pos + 1)?;
    if l0 < 0x80 {
        return Some((2, l0 as usize));
    }
    let n = (l0 & 0x7f) as usize;
    if n == 0 || n > 2 {
        return None;
    }
    let mut len = 0usize;
    for k in 0..n {
        len = (len << 8) | *der.get(pos + 2 + k)? as usize;
    }
    Some((2 + n, len))
}

/// The Subject Alternative Names a leaf certificate carries, split by
/// GeneralName kind: dNSName (tag 2) hostnames and rfc822Name (tag 1) email
/// addresses. Each is a distinct pivot type (Domain vs Email), so they are kept
/// apart rather than flattened into one hostname list — a rfc822Name emitted as
/// a Domain (`admin@example.com`) is a false attribution.
#[derive(Default)]
struct CertSans {
    domains: Vec<String>,
    emails: Vec<String>,
}

fn extract_sans_from_der(der: &[u8]) -> CertSans {
    let mut out = CertSans::default();
    let san_oid: &[u8] = &[0x55, 0x1D, 0x11];

    for i in 0..der.len().saturating_sub(san_oid.len()) {
        if &der[i..i + san_oid.len()] != san_oid {
            continue;
        }
        let mut pos = i + san_oid.len();
        // In a real certificate the extension value wraps the GeneralNames in
        // `OCTET STRING { SEQUENCE OF GeneralName }`; descend through each header
        // (with proper DER length decoding) to reach the dNSName entries. The
        // hand-built test fragments omit the wrappers and start straight at a
        // `0x82` tag, so the skips are conditional — both shapes parse.
        if der.get(pos) == Some(&0x04)
            && let Some((hdr, _)) = der_tlv_len(der, pos)
        {
            pos += hdr;
        }
        if der.get(pos) == Some(&0x30)
            && let Some((hdr, _)) = der_tlv_len(der, pos)
        {
            pos += hdr;
        }
        // Defensive bound on the GeneralNames scan (unchanged from the original).
        let end = (pos + 4096).min(der.len());
        while pos + 2 <= end {
            let tag = der[pos];
            // Only the GeneralName tags the module cares about advance the
            // cursor; anything else ends the sequence (we've left the SAN value).
            // rfc822Name [1] (0x81) is now consumed too — previously it broke the
            // loop, silently dropping every SAN that followed an email entry.
            if tag != 0x81 && tag != 0x82 && tag != 0x87 {
                break;
            }
            let Some((hdr, len)) = der_tlv_len(der, pos) else {
                break;
            };
            let value_end = pos + hdr + len;
            if len == 0 || value_end > end {
                break;
            }
            // dNSName [2] (0x82) → Domain; rfc822Name [1] (0x81) → Email;
            // iPAddress [7] (0x87) is consumed but not surfaced.
            if (tag == 0x82 || tag == 0x81)
                && let Ok(value) = std::str::from_utf8(&der[pos + hdr..value_end])
            {
                let value = value.trim().to_lowercase();
                if tag == 0x82 {
                    if value.contains('.') && value.len() > 3 && value.len() <= 253 {
                        out.domains.push(value);
                    }
                } else if crate::util::extract::looks_like_email(&value) {
                    out.emails.push(value);
                }
            }
            pos = value_end;
        }
        break;
    }
    out.domains.sort_unstable();
    out.domains.dedup();
    out.emails.sort_unstable();
    out.emails.dedup();
    out
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
    // The serial is the FIRST INTEGER of TBSCertificate, which in a v2/v3 cert is
    // preceded by the `[0] EXPLICIT version` wrapper encoded as `A0 03 02 01 vv`
    // (vv = 0..2). A naive "first 0x02" scan returns the version INTEGER (and its
    // value byte is itself a stray 0x02), so locate the wrapper and take the
    // INTEGER immediately after it. v1 certs (no wrapper) fall back to the first
    // plausible INTEGER.
    let mut start = None;
    for i in 0..der.len().saturating_sub(5) {
        if der[i] == 0xA0
            && der[i + 1] == 0x03
            && der[i + 2] == 0x02
            && der[i + 3] == 0x01
            && der[i + 4] <= 0x02
        {
            if der.get(i + 5) == Some(&0x02) {
                start = Some(i + 5);
            }
            break;
        }
    }
    let start = start.or_else(|| {
        (0..der.len().saturating_sub(3)).find(|&i| {
            der[i] == 0x02 && {
                let len = der[i + 1] as usize;
                len > 0 && len <= 20 && i + 2 + len <= der.len()
            }
        })
    });
    let Some(start) = start else {
        return String::new();
    };
    // Bounds-check the length read: `der` is the remote leaf certificate, fully
    // attacker-controlled and not required to be valid X.509. The wrapper scan
    // can settle `start` on the final bytes, so `der[start + 1]` may be one past
    // the end — guard it instead of indexing (mirrors the safe fallback branch).
    let Some(&len_byte) = der.get(start + 1) else {
        return String::new();
    };
    let len = len_byte as usize;
    if len == 0 || len > 20 || start + 2 + len > der.len() {
        return String::new();
    }
    der[start + 2..start + 2 + len]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// `cargo-fuzz` harness entry point (the standing "proof & measurement
/// infrastructure" foundation). `der` is a
/// leaf certificate's raw DER bytes read straight off a live TLS socket
/// (`process()`'s live-probe path) — fully attacker-controlled, arbitrary
/// bytes that need not even be valid X.509. This hand-rolled scanner already
/// had two real no-fixture bugs (T2.3: a SAN `OCTET STRING → SEQUENCE`
/// unwrap miss, and a serial/version INTEGER mix-up) found by *fixture*
/// testing alone; coverage-guided fuzzing exercises the same untrusted-byte
/// surface far more exhaustively than any hand-written or property-test
/// corpus can. Exists solely so `fuzz/fuzz_targets/cert_der.rs` (a separate,
/// intentionally-not-a-workspace-member crate — see `fuzz/README.md`) can
/// reach these otherwise-private extractors: this crate is `publish = false`
/// and its lib is never consumed as a published API (see the crate-root doc
/// comment), so widening visibility here costs nothing. `#[doc(hidden)]`
/// keeps it out of `cargo doc`'s rendered output; the three calls discard
/// their results deliberately — the only property under test is "never
/// panics, never hangs, never reads out of bounds" on arbitrary input, not
/// any particular decoded value.
#[doc(hidden)]
pub fn fuzz_entry_parse_der(der: &[u8]) {
    let _ = extract_sans_from_der(der);
    let _ = extract_field_from_der(der, &[0x55, 0x04, 0x03], true);
    let _ = extract_field_from_der(der, &[0x55, 0x04, 0x03], false);
    let _ = extract_field_from_der(der, &[0x55, 0x04, 0x0A], true);
    let _ = extract_serial_hex(der);
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
