//! DKIM selector enumeration (RFC 6376) — a domain's DKIM public keys live at
//! `<selector>._domainkey.{domain}`, and the selector name is chosen by whatever
//! platform signs the domain's mail. `dns_intel/resolve.rs` only notices a
//! (non-standard) DKIM record published at the bare apex; the STANDARD selector
//! location is never probed anywhere in the codebase.
//!
//! Probing a curated dictionary of common selectors and keeping the ones that
//! resolve to a real key record does two useful things:
//!   * **Vendor / mail-stack attribution** — a resolvable `google._domainkey`
//!     says Google Workspace signs this domain's mail; `selector1`/`selector2`
//!     say Microsoft 365; `s1`/`s2` SendGrid; `mandrill`, `mailgun`, `k1`
//!     Mailchimp/Mailgun; `fm1..3` Fastmail; `protonmail*` Proton; and so on.
//!     That is a real infrastructure signal complementary to the SPF-include and
//!     domain-verification-TXT vendor detection `dns_intel` already does.
//!   * **Weak-key surfacing** — the `p=` public key's estimated modulus size is
//!     recorded, so an undersized (< 1024-bit) RSA signing key is visible.
//!
//! Apex-only (`registrable_domain(target) == target`): DKIM is organisation-level
//! mail configuration published at the From: domain, so re-probing every
//! discovered subdomain would be wasted queries. Pure DNS TXT, free, no keys.

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleContext,
    scan::Target,
};
use crate::util::dns::shared_resolver;
use crate::util::domains::registrable_domain;

use super::{MAX_CONCURRENT_BRUTE, SRC};

/// Common DKIM selectors paired with the mail platform they attribute to (when
/// the selector is vendor-specific; `None` for generic selectors many platforms
/// reuse). Curated from published ESP setup guides. A generic selector still
/// proves DKIM is configured even though it names no single vendor.
const DKIM_SELECTORS: &[(&str, Option<&str>)] = &[
    ("google", Some("google-workspace")),
    ("selector1", Some("microsoft-365")),
    ("selector2", Some("microsoft-365")),
    ("s1", Some("sendgrid")),
    ("s2", Some("sendgrid")),
    ("mandrill", Some("mandrill")),
    ("k1", Some("mailchimp-or-mailgun")),
    ("k2", None),
    ("k3", None),
    ("mte1", Some("mailgun")),
    ("mg", Some("mailgun")),
    ("mailjet", Some("mailjet")),
    ("mailin", Some("brevo-sendinblue")),
    ("pic", Some("sparkpost")),
    ("pm", Some("postmark")),
    ("amazonses", Some("amazon-ses")),
    ("ses", Some("amazon-ses")),
    ("zoho", Some("zoho")),
    ("zmail", Some("zoho")),
    ("fm1", Some("fastmail")),
    ("fm2", Some("fastmail")),
    ("fm3", Some("fastmail")),
    ("protonmail", Some("protonmail")),
    ("protonmail2", Some("protonmail")),
    ("protonmail3", Some("protonmail")),
    ("hs1", Some("hubspot")),
    ("hs2", Some("hubspot")),
    ("cm", Some("campaign-monitor")),
    ("ctct1", Some("constant-contact")),
    ("ctct2", Some("constant-contact")),
    ("everlytickey1", Some("everlytic")),
    ("mxvault", Some("mxroute")),
    ("dyn", Some("dyn")),
    // Generic selectors many platforms and self-hosted setups reuse.
    ("default", None),
    ("dkim", None),
    ("mail", None),
    ("email", None),
    ("smtp", None),
    ("sig1", None),
    ("key1", None),
    ("key2", None),
];

/// One resolved DKIM selector: `(selector, vendor, key_type, est_key_bits)`.
/// `vendor` is empty for a generic selector; `est_key_bits` is `None` when the
/// key is revoked (`p=` empty) or not an estimable RSA key.
type DkimHit = (&'static str, &'static str, String, Option<u32>);

/// DKIM selector sweep for one target. No-op (returns empty) unless `target` IS
/// its own registrable domain — DKIM is apex-level mail configuration.
pub(super) async fn dkim_enumerate(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let domain = target.value.trim().trim_end_matches('.').to_lowercase();
    if domain.is_empty() || domain.contains('/') || domain.contains(' ') {
        return Ok(Vec::new());
    }
    match registrable_domain(&domain) {
        Some(reg) if reg == domain => {}
        _ => return Ok(Vec::new()),
    }

    let hits = resolve_selectors_concurrently(&domain, MAX_CONCURRENT_BRUTE).await;
    if hits.is_empty() {
        return Ok(Vec::new());
    }

    // Aggregate every resolving selector onto ONE Domain entity for the target:
    // the vendors become tags (the attribution payload) and each selector is one
    // evidence line. Merging onto the domain rather than emitting a pivot per
    // selector keeps the graph clean — the value here is attribution, not fan-out.
    let mut e = Entity::new(EntityKind::Domain, &domain, confidence::EXPERT, &ctx.scan_id);
    e.tag("dkim");
    e.tag("has-dkim");
    let mut weak_key = false;
    for (selector, vendor, key_type, est_bits) in &hits {
        if !vendor.is_empty() {
            e.tag(format!("mail-vendor:{vendor}"));
        }
        let mut ev = Evidence::new(
            SRC,
            format!("DKIM selector {selector}._domainkey.{domain} is configured"),
        )
        .with_attr("selector", *selector)
        .with_attr("key_type", key_type)
        .with_attr("method", "dkim-selector-probe");
        if !vendor.is_empty() {
            ev = ev.with_attr("mail_vendor", *vendor);
        }
        match est_bits {
            Some(bits) => {
                ev = ev.with_attr("est_key_bits", bits.to_string());
                // Only RSA has a meaningful "too small" threshold; ed25519 keys
                // are fixed-size and always strong, so never flagged.
                if key_type.eq_ignore_ascii_case("rsa") && *bits < 1024 {
                    weak_key = true;
                    ev = ev.with_attr("weak_key", "true");
                }
            }
            None => {
                ev = ev.with_attr("key_status", "revoked-or-empty");
            }
        }
        e.add_evidence(ev);
    }
    if weak_key {
        e.tag("dkim-weak-key");
    }
    Ok(vec![e])
}

/// Resolve every `<selector>._domainkey.{domain}` TXT concurrently (bounded to
/// `max_concurrent`), keeping only selectors whose record is a real DKIM key
/// (`p=` tag present). Returns hits sorted by selector for deterministic output.
async fn resolve_selectors_concurrently(domain: &str, max_concurrent: usize) -> Vec<DkimHit> {
    use std::sync::Arc;

    use hickory_resolver::proto::rr::RData;
    use tokio::sync::Semaphore;

    let resolver = shared_resolver();
    let sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for (selector, vendor) in DKIM_SELECTORS {
        let name = format!("{selector}._domainkey.{domain}");
        let sem = Arc::clone(&sem);
        let (selector, vendor) = (*selector, vendor.unwrap_or(""));
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let lookup = resolver.txt_lookup(name.as_str()).await.ok()?;
            // Concatenate all TXT segments of all answers (a DKIM record is often
            // split into 255-byte character-strings that must be rejoined).
            let record: String = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => Some(txt.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("");
            let parsed = parse_dkim_record(&record)?;
            Some((selector, vendor, parsed.0, parsed.1))
        });
    }

    let mut out: Vec<DkimHit> = Vec::new();
    while let Some(join_result) = set.join_next().await {
        if let Ok(Some(hit)) = join_result {
            out.push(hit);
        }
    }
    out.sort_unstable_by(|a, b| a.0.cmp(b.0));
    out
}

/// Parse a DKIM TXT record's tags. Returns `(key_type, est_key_bits)` when the
/// record is a real DKIM key (has a `p=` tag), else `None`. **Pure** — no I/O,
/// independently unit-tested. `key_type` defaults to `rsa` per RFC 6376 when the
/// `k=` tag is absent; `est_key_bits` estimates the RSA modulus size from the
/// base64 `p=` length (DER SubjectPublicKeyInfo overhead subtracted), or `None`
/// when `p=` is empty (a revoked key) or the key is not RSA.
fn parse_dkim_record(record: &str) -> Option<(String, Option<u32>)> {
    let record = record.trim().trim_matches('"');
    // A DKIM key record is a `;`-separated tag list; the defining tag is `p=`.
    let mut key_type = "rsa".to_string();
    let mut p_value: Option<&str> = None;
    let mut saw_p = false;
    for tag in record.split(';') {
        let tag = tag.trim();
        let Some((k, v)) = tag.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k.to_ascii_lowercase().as_str() {
            "k" => key_type = v.to_ascii_lowercase(),
            "p" => {
                saw_p = true;
                if !v.is_empty() {
                    p_value = Some(v);
                }
            }
            _ => {}
        }
    }
    if !saw_p {
        return None;
    }
    let est_bits = match (key_type.as_str(), p_value) {
        ("rsa", Some(p)) => Some(estimate_rsa_bits(p)),
        _ => None,
    };
    Some((key_type, est_bits))
}

/// Estimate an RSA public key's modulus size in bits from the base64-encoded
/// `p=` SubjectPublicKeyInfo. The base64 decodes to a DER blob whose fixed
/// header overhead (~38 bytes for a 2048-bit key's SPKI wrapper + exponent) is
/// subtracted before converting the remaining modulus bytes to bits, then
/// snapped to the nearest standard size. Approximate by design — used only to
/// flag an obviously-undersized key, not for cryptographic precision.
fn estimate_rsa_bits(p_b64: &str) -> u32 {
    // base64 length → decoded byte length (4 chars encode 3 bytes).
    let b64_len = p_b64.trim().trim_end_matches('=').len() as u32;
    let der_bytes = b64_len * 3 / 4;
    // DER SPKI wrapper + 30-bit exponent overhead is ~24–40 bytes; subtract a
    // conservative 38 so the estimate rounds DOWN toward the modulus, never up.
    let modulus_bytes = der_bytes.saturating_sub(38);
    let bits = modulus_bytes * 8;
    // Snap to the nearest common RSA size so the reported figure is a clean
    // 512/768/1024/2048/4096 rather than a noisy estimate.
    const SIZES: &[u32] = &[512, 768, 1024, 2048, 3072, 4096];
    *SIZES
        .iter()
        .min_by_key(|s| s.abs_diff(bits))
        .unwrap_or(&2048)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_list_is_unique_and_nonempty() {
        let mut seen = std::collections::BTreeSet::new();
        for (sel, _) in DKIM_SELECTORS {
            assert!(!sel.is_empty());
            assert!(seen.insert(*sel), "duplicate selector: {sel}");
        }
        assert!(DKIM_SELECTORS.len() >= 25);
    }

    #[test]
    fn parses_a_real_rsa_dkim_record() {
        // A typical 2048-bit RSA DKIM record.
        let rec = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890";
        let (kt, bits) = parse_dkim_record(rec).expect("should parse");
        assert_eq!(kt, "rsa");
        assert!(bits.is_some());
    }

    #[test]
    fn defaults_key_type_to_rsa_when_k_absent() {
        let rec = "v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
        let (kt, _) = parse_dkim_record(rec).expect("should parse");
        assert_eq!(kt, "rsa");
    }

    #[test]
    fn detects_ed25519_key_type() {
        let rec = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let (kt, bits) = parse_dkim_record(rec).expect("should parse");
        assert_eq!(kt, "ed25519");
        assert!(bits.is_none(), "ed25519 is not RSA-bit-estimated");
    }

    #[test]
    fn revoked_key_has_no_bits_but_still_counts() {
        // An empty p= is a revoked selector — still a configured selector.
        let rec = "v=DKIM1; k=rsa; p=";
        let (kt, bits) = parse_dkim_record(rec).expect("empty p= still a DKIM record");
        assert_eq!(kt, "rsa");
        assert!(bits.is_none());
    }

    #[test]
    fn non_dkim_txt_is_rejected() {
        // No p= tag → not a DKIM key record.
        assert!(parse_dkim_record("v=spf1 include:_spf.google.com ~all").is_none());
        assert!(parse_dkim_record("just some text").is_none());
    }

    #[test]
    fn estimates_a_small_key_as_weak() {
        // A short base64 p= estimates well under 1024 bits.
        let bits = estimate_rsa_bits("MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK");
        assert!(
            bits < 1024,
            "a ~64-char SPKI should estimate < 1024, got {bits}"
        );
    }
}
