//! CAA record (RFC 8659) parsing and entity aggregation.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
};

use super::{DohRecord, SRC};

/// Parse one CAA record's DoH `data` field into a `(tag, value)` pair with the
/// tag lowercased. Handles BOTH resolver forms — exactly like `parse_svcb_hints`
/// — because the two DoH endpoints disagree: dns.google returns the presentation
/// string `0 issue "letsencrypt.org"`, while cloudflare-dns returns the raw RFC
/// 3597 generic form `\# <declen> <hex octets>` whose CAA RDATA (RFC 8659 §4.1)
/// is `flags(1) taglen(1) tag(taglen) value(rest)`. Every read is length-checked,
/// so a truncated or non-CAA record yields `None` rather than panicking. **Pure.**
pub(super) fn parse_caa_rdata(data: &str) -> Option<(String, String)> {
    let data = data.trim();
    if let Some(hex_body) = data.strip_prefix(r"\#") {
        // First token is the RFC 3597 decimal rdata length; bound on the decoded
        // bytes instead, so skip it. The rest are hex octets.
        let mut toks = hex_body.split_whitespace();
        toks.next();
        let mut bytes: Vec<u8> = Vec::new();
        for t in toks {
            bytes.push(u8::from_str_radix(t, 16).ok()?);
        }
        // flags(1) taglen(1) tag(taglen) value(rest)
        if bytes.len() < 2 {
            return None;
        }
        let taglen = bytes[1] as usize;
        let tag_end = 2usize.checked_add(taglen)?;
        if tag_end > bytes.len() {
            return None;
        }
        let tag = String::from_utf8_lossy(&bytes[2..tag_end]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(&bytes[tag_end..])
            .trim()
            .to_string();
        if tag.is_empty() || value.is_empty() {
            return None;
        }
        return Some((tag, value));
    }
    // Presentation form: `<flags> <tag> "<value>"`.
    let mut parts = data.splitn(3, char::is_whitespace);
    let _flags = parts.next()?;
    let tag = parts.next()?.to_ascii_lowercase();
    let value = parts.next()?.trim().trim_matches('"').trim().to_string();
    if tag.is_empty() || value.is_empty() {
        return None;
    }
    Some((tag, value))
}

/// Build CAA entities from a DoH CAA answer set — transport parity with the
/// hickory `dns_intel` CAA path, which on Termux frequently never runs (its
/// UDP/TCP port-53 lookups are commonly blocked, leaving DoH as the sole
/// resolver). Aggregates the `issue`/`issuewild`/`iodef` values onto one
/// `caa`-tagged Domain entity, then routes each `iodef` value through the shared
/// `dns_intel::iodef_entities` extractor so a published cert-violation reporting
/// contact — a `mailto:` **security-contact Email** or an `http(s)://` reporting
/// **Domain** — surfaces as a pivotable entity instead of being dropped on
/// Termux. **Pure** (no network/IO).
pub(super) fn caa_entities(records: &[DohRecord], domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut issuers: Vec<String> = Vec::new();
    let mut wildcards: Vec<String> = Vec::new();
    let mut iodefs: Vec<String> = Vec::new();

    for rec in records {
        // parse_caa_rdata self-validates: a stray CNAME/other answer in the set
        // fails to parse and is skipped, so no record-type filter is needed.
        let Some((tag, value)) = parse_caa_rdata(&rec.data) else {
            continue;
        };
        match tag.as_str() {
            "issue" => issuers.push(value),
            "issuewild" => wildcards.push(value),
            "iodef" => iodefs.push(value),
            _ => {}
        }
    }

    if issuers.is_empty() && wildcards.is_empty() && iodefs.is_empty() {
        return Vec::new();
    }

    let mut entity = Entity::new(
        EntityKind::Domain,
        domain,
        confidence::HIGH_PLUSPLUS_PLUS,
        scan_id,
    );
    entity.tag("dns");
    entity.tag("caa");
    let mut ev = Evidence::new(
        SRC,
        format!(
            "CAA policy published: {} issuer(s), {} wildcard issuer(s)",
            issuers.len(),
            wildcards.len()
        ),
    );
    if !issuers.is_empty() {
        ev = ev.with_attr("issue", issuers.join(","));
    }
    if !wildcards.is_empty() {
        ev = ev.with_attr("issuewild", wildcards.join(","));
    }
    if !iodefs.is_empty() {
        ev = ev.with_attr("iodef", iodefs.join(","));
    }
    entity.add_evidence(ev);

    let mut out = vec![entity];
    for value in &iodefs {
        out.extend(crate::modules::dns_intel::iodef_entities(
            value, domain, scan_id,
        ));
    }
    out
}
