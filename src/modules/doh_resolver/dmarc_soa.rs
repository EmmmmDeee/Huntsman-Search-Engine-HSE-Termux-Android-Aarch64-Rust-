//! DMARC (RFC 7489 §6.3) reporting-address extraction and SOA (RFC 1035
//! §3.3.13) primary-nameserver / zone-admin-email extraction. Grouped together
//! because both are single-record-type sub-parses of the apex `records_for_type`
//! sweep — DMARC folds into the `TXT` arm, SOA is its own arm — rather than a
//! standalone aggregating pass like [`super::caa`]'s CAA policy entity.

use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
};
use crate::util::dns::soa_rname_to_email;

use super::SRC;

/// Extract DMARC `rua`/`ruf` reporting-address `Email` entities from a TXT
/// record, if it is a `v=DMARC1` record (RFC 7489 §6.3) — returns empty
/// otherwise. These reveal the organization's DMARC monitoring addresses,
/// often a third-party service or internal security team inbox. Dedup key
/// `dmarc:{addr}` is inserted into the shared `seen` set so this stays
/// idempotent within `records_for_type`'s wider cross-type dedup.
pub(super) fn dmarc_entities(
    txt: &str,
    domain: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
) -> Vec<Entity> {
    let mut out = Vec::new();
    if !txt.to_ascii_lowercase().starts_with("v=dmarc1") {
        return out;
    }
    for field in ["rua=", "ruf="] {
        if let Some(val_start) = txt.to_ascii_lowercase().find(field) {
            let after = &txt[val_start + field.len()..];
            // DMARC tag-value pairs are `;`-delimited (RFC 7489 §6.3):
            // clip the URI list before the next tag, then split on `,`.
            let value_part = after.split(';').next().unwrap_or(after).trim();
            for uri in value_part.split(',').map(str::trim) {
                // Strip trailing `;` or whitespace.
                let uri = uri.trim_end_matches(';').trim();
                if let Some(addr) = uri.strip_prefix("mailto:") {
                    let addr = addr.trim();
                    // May have `!size` suffix: `dmarc@example.com!10m`.
                    let addr = addr.split('!').next().unwrap_or(addr).trim();
                    if addr.contains('@') && seen.insert(format!("dmarc:{addr}")) {
                        let mut e =
                            Entity::new(EntityKind::Email, addr, confidence::MEDIUM_PLUS, scan_id);
                        e.tag("dns");
                        e.tag("dmarc-reporting");
                        e.add_evidence(
                            Evidence::new(
                                SRC,
                                format!("DMARC {} reporting address for {domain}", &field[..3]),
                            )
                            .with_attr("dmarc_field", &field[..3])
                            .with_attr("domain", domain),
                        );
                        out.push(e);
                    }
                }
            }
        }
    }
    out
}

/// Extract the zone's primary nameserver (`mname`) and admin-contact email
/// (`rname`, RFC 1035 §3.3.13's `@`-as-`.` encoding, decoded via
/// [`crate::util::dns::soa_rname_to_email`]) from one SOA answer's RDATA:
/// `<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>`. `owner` is
/// the record's owner name (attached as `record_name` evidence, like every
/// other arm of `records_for_type`). Dedup keys `soa-ns:`/`soa-email:` are
/// inserted into the shared `seen` set.
pub(super) fn soa_entities(
    data: &str,
    owner: &str,
    domain: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
) -> Vec<Entity> {
    let mut out = Vec::new();
    let base = |summary: String| {
        let ev = Evidence::new(SRC, summary);
        if owner.is_empty() {
            ev
        } else {
            ev.with_attr("record_name", owner)
        }
    };
    let parts: Vec<&str> = data.split_whitespace().collect();
    if parts.len() >= 2 {
        // Primary nameserver.
        let mname = parts[0].trim_end_matches('.');
        if mname.contains('.') && seen.insert(format!("soa-ns:{mname}")) {
            let mut e = Entity::new(EntityKind::Domain, mname, confidence::ATTRIBUTED, scan_id);
            e.tag("dns");
            e.tag("soa");
            e.tag("nameserver");
            e.add_evidence(
                base(format!("SOA primary nameserver for {domain}"))
                    .with_attr("record_type", "SOA")
                    .with_attr("role", "mname"),
            );
            out.push(e);
        }
        // Zone admin email from RNAME.
        let rname = parts[1].trim_end_matches('.');
        if let Some(email) = soa_rname_to_email(rname)
            && email.contains('@')
            && seen.insert(format!("soa-email:{}", email.to_ascii_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Email, &email, confidence::NOTABLE, scan_id);
            e.tag("dns");
            e.tag("soa");
            e.tag("zone-admin");
            e.add_evidence(
                base(format!("SOA zone admin email for {domain}"))
                    .with_attr("record_type", "SOA")
                    .with_attr("rname_raw", rname),
            );
            out.push(e);
        }
    }
    out
}
