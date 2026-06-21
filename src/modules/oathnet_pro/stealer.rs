//! Stealer-log entity extraction for OathNet results.
//!
//! Builds Url / Credential / Domain leads from the stealer-context fields of a
//! breach record — kept separate from the breach-PII path and the parent's
//! `Module` wiring. Reaches shared parent items through `use super::*`.

use super::*;

/// Apply the stealer-context tags (`oathnet-pro`, `stealer`, plus any
/// `extra_tags` in order) and a cloned evidence record to `e`, then push it.
/// Unlike [`push_oathnet_entity`] this does NOT add the `breach` tag — stealer
/// login/domain/credential context is not leaked PII per se.
pub(super) fn push_stealer_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag("oathnet-pro");
    e.tag("stealer");
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

pub(super) fn extract_stealer_entities(
    item: &Value,
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let mut ev = Evidence::new(SRC, "Stealer log entry".to_string())
        .with_attr("source", "stealer")
        .with_attr("provider", "oathnet.org")
        .with_attr("api_key_origin", key_fp);
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        ev = ev.with_attr("url", &url);
    }
    if let Some(lid) = val_str(item, "log_id").or_else(|| val_str(item, "log")) {
        ev = ev.with_attr("log_id", &lid);
    }
    if let Some(pw) = val_str(item, "password") {
        ev = ev.with_attr("password", &pw);
        if pw.contains("UPGRADE_TO_SEE") && pw.len() >= 3 {
            // `pw` is untrusted: take the first/last CHAR (not byte) so a
            // multi-byte boundary can't panic the slice.
            let first = pw.chars().next().map(String::from).unwrap_or_default();
            let last = pw.chars().next_back().map(String::from).unwrap_or_default();
            ev = ev
                .with_attr("password_hint_first", first)
                .with_attr("password_hint_last", last)
                .with_attr("password_redacted", "true");
        }
    }
    if let Some(uname) = val_str(item, "username") {
        ev = ev.with_attr("username", &uname);
    }

    // The login URL is where the victim's credentials were captured — the most
    // actionable pivot in a stealer record (it confirms a service the subject
    // uses). Emit it as a first-class Url. Its host is NOT additionally minted as
    // a Domain: a stealer host is a third-party service the subject merely has an
    // account on (`akzonobel.taleo.net`, `bitcoinptc.top`), not a domain they own
    // — minting it spawned subdomain-proliferation noise and misdirected
    // dns/cert/wayback/HudsonRock expansion that enumerates the *platform's*
    // infrastructure (irrelevant to the subject) and forged false correlation
    // brokers across everyone who used the same platform. The Url already records
    // the account pathway, and the subject's genuinely-owned domains still enter
    // the graph via the breach `email_domain` path.
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        let u = url.trim();
        if u.starts_with("http")
            && u.contains('.')
            && seen.insert(format!("@stealer-url:{}", u.to_lowercase()))
        {
            push_stealer_entity(
                result,
                Entity::new(EntityKind::Url, u, 0.55, scan_id),
                &ev,
                &["credential-url"],
            );
        }
    }

    if let Some(emails) = item.get("email").and_then(|v| v.as_array()) {
        for email_val in emails {
            if let Some(email) = email_val.as_str() {
                let lower = email.to_lowercase();
                if looks_like_email(&lower) && seen.insert(lower) {
                    push_oathnet_entity(
                        result,
                        Entity::new(EntityKind::Email, email, 0.65, scan_id),
                        &ev,
                        &["stealer"],
                        // Stealer hits come from a search on the target's own
                        // identity — the row IS the target.
                        true,
                    );
                }
            }
        }
    }

    // Username field often contains an email address (stealer logs use the
    // login email as "username"). Emit it so it expands through the email
    // pipeline — HIBP, emailrep, epieos, etc. can then cross-reference.
    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if looks_like_email(&lower) && seen.insert(format!("@stealer-user:{lower}")) {
            push_stealer_entity(
                result,
                Entity::new(EntityKind::Email, &uname, 0.60, scan_id),
                &Evidence::new(SRC, "Stealer login email (username field)")
                    .with_attr("source", "stealer"),
                &["stealer-login"],
            );
        }
    }

    if let Some(domains) = item.get("domain").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(dom) = d.as_str()
                && dom.contains('.')
                // A stealer `domain` is frequently the reverse-DNS Android/iOS app
                // package the credential was captured in (`com.facebook.katana`),
                // not a web domain — skip it rather than mint a bogus Domain whose
                // last label is not a TLD (`dns_intel`/`cert_intel`/`wayback` would
                // then chase a non-existent host).
                && !crate::util::domains::is_app_package_id(dom)
                && seen.insert(dom.to_lowercase())
            {
                push_stealer_entity(
                    result,
                    Entity::new(EntityKind::Domain, dom, 0.50, scan_id),
                    &Evidence::new(SRC, format!("Stealer credential for {dom}"))
                        .with_attr("source", "stealer"),
                    &[],
                );
            }
        }
    }

    if let Some(uname) = val_str(item, "username")
        && let Some(url_str) = val_str(item, "url").or_else(|| val_str(item, "url_str"))
    {
        let cred_val = format!("{uname}@{url_str}");
        if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
            push_stealer_entity(
                result,
                Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id),
                &ev,
                &[],
            );
        }
    }
}

// ─── Field validation (objective, static — no network) ──────────────────────
//
// OathNet rows carry redacted sentinels (`UPGRADE_TO_SEE…`) and the occasional
// malformed value; emitting them verbatim mints junk entities (a `"1234567"` IP,
// an `"UPGRADE_TO_SEE"` phone). Each extractor gates on an objective check so
// only a well-formed identifier reaches the graph — the same
// validate-before-trust discipline the key-harvest detector applies to keys.
