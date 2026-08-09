//! Stealer-log entity extraction for OathNet results.
//!
//! Builds Url / Credential / Domain leads from the stealer-context fields of a
//! breach record, then runs the shared [`crate::modules::breach_rich`]
//! maximum-raw-data pass to surface the long tail (device fingerprints, extra
//! handles, every remaining scalar) — kept separate from the breach-PII path and
//! the parent's `Module` wiring. Reaches shared parent items through
//! `use super::*`.

use super::*;
use crate::core::confidence;

/// Apply the stealer-context tags (`oathnet-pro`, `stealer`, plus any
/// `extra_tags` in order) and a cloned evidence record to `e`, then push it.
/// Unlike [`push_oathnet_entity`] this does NOT add the `breach` tag — stealer
/// login/domain/credential context is not leaked PII per se.
pub(super) fn push_stealer_entity(
    result: &mut ModuleResult,
    e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    result.push_with_tags(e, ev, &["oathnet-pro", "stealer"], extra_tags);
}

/// Expand one OathNet stealer-log record into its actionable leads.
///
/// From a single infostealer row this mints, each gated on an objective check
/// and deduplicated through `seen`:
///   * the **login `Url`** — where the credentials were captured, the most
///     actionable pivot — but deliberately NOT its host as a `Domain` (a
///     third-party service the subject merely has an account on, whose
///     enumeration is noise; see the inline note);
///   * any `email` array values, pushed as target-true `Email`s (the row came
///     from a search on the subject's own identity);
///   * a `username` that is itself an email, so it re-enters the email
///     pipeline (HIBP/emailrep/epieos);
///   * `domain` array values that pass [`looks_like_domain`](crate::util::domains::looks_like_domain),
///     filtering out reverse-DNS app packages and bare IPs;
///   * a `username@url` `Credential` pairing;
///   * the **maximum-raw-data long tail** — device fingerprints (HWID / MAC /
///     hostname), extra social handles, employer, and every remaining scalar
///     field — via the shared [`crate::modules::breach_rich`] pass that
///     `see_know` also uses, so both stealer consumers extract one identical
///     field set.
///
/// A captured password is preserved VERBATIM in the `password` evidence
/// attribute — full-fidelity, authorised evidentiary data is never redacted,
/// hinted, or hidden. A provider `UPGRADE_TO_SEE…` value is the raw paywall
/// sentinel and is kept as-is (it is the datum the API returned). Shared evidence
/// carries the `api_key_origin` fingerprint for provenance.
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
    if let Some(pw) = val_str(item, "password").filter(|p| !p.is_empty()) {
        // Full fidelity: the captured password is preserved VERBATIM — it is the
        // operator's own authorised, paid-for evidentiary data, and the standing
        // no-redaction / no-hiding contract forbids replacing it with a hint or
        // marker. A provider `UPGRADE_TO_SEE…` value is the raw paywall sentinel
        // and is likewise kept as-is (it IS the datum the API returned), so a
        // consumer can tell a withheld password from a real one.
        ev = ev.with_attr("password", &pw);
    }
    if let Some(uname) = val_str(item, "username") {
        ev = ev.with_attr("username", &uname);
    }
    // Stamp the row's login email onto the SHARED evidence too, so the DeviceId /
    // MacAddress nodes minted from this stealer row (via `breach_rich`) carry the
    // email join-key AU-106 folds into its distinct-handle count — matching the
    // breach / dehashed / see_know sibling paths. First email only: a stealer row
    // is one captured session with one login, and a comma-joined multi-value
    // would not equal the minted `Email` entity's value (breaking the per-account
    // UID match).
    if let Some(email) = item
        .get("email")
        .and_then(|v| v.as_array())
        .and_then(|a| a.iter().find_map(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|e| looks_like_email(&e.to_lowercase()))
    {
        ev = ev.with_attr("email", email);
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
                Entity::new(EntityKind::Url, u, confidence::MEDIUM_HIGH, scan_id),
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
                        Entity::new(EntityKind::Email, email, confidence::HIGH, scan_id),
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
                Entity::new(EntityKind::Email, &uname, confidence::MEDIUM_PLUS, scan_id),
                &Evidence::new(SRC, "Stealer login email (username field)")
                    .with_attr("source", "stealer"),
                &["stealer-login"],
            );
        }
    }

    if let Some(domains) = item.get("domain").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(dom) = d.as_str()
                // A stealer `domain` is frequently NOT a registrable web domain:
                // a reverse-DNS app package (`com.facebook.katana`) or a bare IP
                // (`192.168.0.1`, a router/C2/panel host). Minting either as a
                // Domain sends `dns_intel`/`cert_intel`/`wayback` chasing a
                // non-host — `looks_like_domain` gates both out in one place.
                && crate::util::domains::looks_like_domain(dom)
                && seen.insert(dom.to_lowercase())
            {
                push_stealer_entity(
                    result,
                    Entity::new(EntityKind::Domain, dom, confidence::MEDIUM, scan_id),
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
                Entity::new(
                    EntityKind::Credential,
                    &cred_val,
                    confidence::MEDIUM_PLUS,
                    scan_id,
                ),
                &ev,
                &[],
            );
        }
    }

    // Maximum-raw-data long tail: the defining payload of an infostealer log —
    // device fingerprints (HWID / MAC / hostname), extra social handles,
    // employer, and every remaining scalar field — surfaced as first-class,
    // pivotable entities via the shared provider-agnostic pass that see_know also
    // uses, so the two stealer consumers extract the identical field set and
    // can't drift. A stealer row is the subject's own captured machine/identity
    // (`is_target`), so its rich entities need no candidate demotion. The shared
    // pass uses `@`-namespaced dedup keys disjoint from this path's, so the
    // primary Url/Email/Domain/Credential leads above are never duplicated.
    crate::modules::breach_rich::extract_rich_detail(
        item,
        scan_id,
        "oathnet-pro",
        &ev,
        seen,
        result,
    );
}

// ─── Field validation (objective, static — no network) ──────────────────────
//
// OathNet rows carry redacted sentinels (`UPGRADE_TO_SEE…`) and the occasional
// malformed value; emitting them verbatim mints junk entities (a `"1234567"` IP,
// an `"UPGRADE_TO_SEE"` phone). Each extractor gates on an objective check so
// only a well-formed identifier reaches the graph — the same
// validate-before-trust discipline the key-harvest detector applies to keys.
