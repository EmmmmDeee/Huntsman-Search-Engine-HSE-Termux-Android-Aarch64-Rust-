//! Free leaked-credential search over the public COMB (Compilation of Many
//! Breaches) index — no API key, real public source.
//!
//! This is the free, self-owned emulation of SeekNow's paid stealer/credential
//! `/search` corpus. Where `see_know` queries the key-gated see-know.icu API,
//! this module queries ProxyNova's free, keyless COMB endpoint
//! (`https://api.proxynova.com/comb?query=<q>`) and parses the real
//! `identity:secret` credential lines it returns. No mock, no simulation — the
//! same kind of leaked-credential data, fetched live from a public index.
//!
//! ## Substring-match safeguard (the correctness core)
//!
//! COMB matches the query as a SUBSTRING, not an exact identity: a query for
//! `qwerty-zzz@nope.invalid` returns `qwerty-zzz@bk.ru:…` (matched on the
//! `qwerty-zzz` fragment). Attributing those strangers' credentials to the
//! subject would be fabrication. So every returned line is strictly
//! post-filtered by [`line_matches_target`] to the EXACT target identity
//! (full email / exact local-part / exact host) before any entity is minted.
//! A username match is additionally candidate-quarantined, because a shared
//! username root is not a unique person.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::extract::{CredentialField, classify_credential_field};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "comb_search";

/// Max credential lines requested per query. COMB caps `count` at 10000 (a
/// sentinel, not a real total), so we request a bounded window and rely on the
/// exact-match filter to keep only the relevant lines.
const FETCH_LIMIT: u32 = 100;

/// Max distinct leaked secrets surfaced per scan target — bounds graph growth
/// on a heavily-exposed identity while still proving the exposure.
const MAX_SECRETS: usize = 50;

/// Base confidence for a leaked secret tied to the EXACT subject email. COMB is
/// an aggregated compilation of older breaches (lower fidelity than a live
/// stealer log), so it sits below HudsonRock's 0.85 stealer baseline.
const EMAIL_MATCH_CONF: f64 = 0.62;

/// Confidence for an exposed account discovered under a DOMAIN target — a real
/// account at that domain, but a third party rather than the scan subject.
const DOMAIN_ACCOUNT_CONF: f64 = 0.50;

pub struct CombSearch;

#[derive(serde::Deserialize)]
struct CombResp {
    #[serde(default)]
    lines: Vec<String>,
}

#[async_trait]
impl Module for CombSearch {
    fn name(&self) -> &'static str {
        "comb_search"
    }

    fn description(&self) -> &'static str {
        "Free leaked-credential search via the public COMB index (no API key)"
    }

    fn priority(&self) -> u8 {
        // Free breach tier, alongside hudsonrock (130) / pwned_passwords.
        129
    }

    fn accepts(&self, t: &Target) -> bool {
        // Email / Username / Domain only. A FullName is not indexed as a
        // credential identity and would match COMB only on noisy substrings,
        // so it is deliberately excluded (the engine surfaces a name's
        // discovered emails/usernames as their own typed targets, which this
        // module then consumes precisely).
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Username | TargetKind::Domain
        )
    }

    fn category(&self) -> ModuleCategory {
        // Leaked-credential compilation — a breach-corpus source, mirroring how
        // the correlator already treats hudsonrock / xposed_or_not.
        ModuleCategory::Breach
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Breach category default: leaked credentials + email addresses. COMB
        // returns exactly these two, nothing more, so no override beyond it.
        &["T1589.001", "T1589.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Password];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single public request; the 3s default would clip a slow-but-connected
        // response as a spurious timeout.
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let v = target.value.trim();
        if !accepts_value(target.kind, v) {
            return Ok(result);
        }

        let url = format!(
            "https://api.proxynova.com/comb?query={}&start=0&limit={FETCH_LIMIT}",
            urlencode(v)
        );
        let Some(resp): Option<CombResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
            return Ok(result);
        };

        // Strict exact-match filter — COMB matches substrings, so discard every
        // line whose identity is not EXACTLY this target before minting anything.
        let mut seen_secret: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_email: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut matched = 0usize;

        for line in &resp.lines {
            let Some((identity, secret)) = split_line(line) else {
                continue;
            };
            if !line_matches_target(identity, target.kind, v) {
                continue;
            }
            matched += 1;

            // For a Domain target, the matched identity is an exposed ACCOUNT at
            // the domain (a third party), surfaced as its own breach-tagged Email.
            if target.kind == TargetKind::Domain
                && identity.contains('@')
                && seen_email.insert(identity.to_ascii_lowercase())
            {
                let mut e = Entity::new(
                    EntityKind::Email,
                    identity,
                    DOMAIN_ACCOUNT_CONF,
                    &ctx.scan_id,
                );
                e.tag(tags::BREACH);
                e.tag("comb");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Exposed account `{identity}` in COMB compilation"),
                    )
                    .with_attr("identity", identity)
                    .with_attr("source", "proxynova-comb"),
                );
                result.push(e);
            }

            if seen_secret.len() >= MAX_SECRETS {
                continue;
            }
            // Classify the secret: drop capture sentinels, skip mis-stored
            // emails and junk where the "secret" merely echoes the identity.
            match classify_credential_field(secret) {
                CredentialField::Sentinel => continue,
                CredentialField::Email => continue,
                CredentialField::Secret => {}
            }
            if secret.eq_ignore_ascii_case(identity) {
                // `user@x:user@x` — an echo, not a real password.
                continue;
            }
            if !seen_secret.insert(secret.to_string()) {
                continue;
            }

            let mut pw = Entity::new(
                EntityKind::Password,
                secret,
                secret_confidence(target.kind),
                &ctx.scan_id,
            );
            pw.tag(tags::BREACH);
            pw.tag("credential");
            pw.tag("comb");
            // A username root is not a unique person; quarantine its secrets so
            // they never corroborate the subject as confirmed.
            if target.kind == TargetKind::Username {
                pw.demote_to_candidate();
            }
            pw.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Leaked credential for `{identity}` in COMB compilation"),
                )
                .with_attr("identity", identity)
                .with_attr("source", "proxynova-comb"),
            );
            result.push(pw);
        }

        if matched == 0 {
            return Ok(result);
        }

        // Enrich the seed once with the aggregate exposure summary.
        let mut seed = target.to_entity(seed_confidence(target.kind), &ctx.scan_id);
        seed.tag(tags::BREACH);
        seed.tag("comb");
        seed.add_evidence(
            Evidence::new(
                SRC,
                format!("{matched} leaked credential line(s) in the COMB compilation"),
            )
            .with_attr("matched_lines", matched.to_string())
            .with_attr("source", "proxynova-comb"),
        );
        result.push(seed);

        Ok(result)
    }
}

/// Value-level admission: reject seeds too short / shapeless to match COMB
/// precisely (a 2-char username substring would match half the index).
fn accepts_value(kind: TargetKind, v: &str) -> bool {
    match kind {
        TargetKind::Email => v.contains('@') && v.len() >= 6,
        TargetKind::Username => v.len() >= 4 && !v.chars().all(|c| c.is_ascii_digit()),
        TargetKind::Domain => v.contains('.') && v.len() >= 4,
        _ => false,
    }
}

/// Split a COMB `identity:secret` line on the FIRST colon (a secret may itself
/// contain colons). Returns `None` for a line with no separator or empty
/// identity.
fn split_line(line: &str) -> Option<(&str, &str)> {
    let (identity, secret) = line.split_once(':')?;
    let identity = identity.trim();
    if identity.is_empty() {
        return None;
    }
    Some((identity, secret.trim()))
}

/// EXACT target-identity match guarding against COMB's substring matching.
/// - Email: the whole identity equals the target email.
/// - Domain: the identity's host (after `@`) equals the target domain.
/// - Username: the identity's local-part (before `@`, or the whole token)
///   equals the target username.
fn line_matches_target(identity: &str, kind: TargetKind, target: &str) -> bool {
    match kind {
        TargetKind::Email => identity.eq_ignore_ascii_case(target),
        TargetKind::Domain => identity
            .rsplit_once('@')
            .is_some_and(|(_, host)| host.eq_ignore_ascii_case(target)),
        TargetKind::Username => {
            let local = identity.split('@').next().unwrap_or(identity);
            local.eq_ignore_ascii_case(target)
        }
        _ => false,
    }
}

/// Confidence for a discovered secret, by target kind.
fn secret_confidence(kind: TargetKind) -> f64 {
    match kind {
        TargetKind::Email => EMAIL_MATCH_CONF,
        TargetKind::Domain => DOMAIN_ACCOUNT_CONF,
        // Username secrets are candidate-quarantined downstream; the pre-demote
        // value is moot but kept modest.
        _ => 0.40,
    }
}

/// Confidence for the enriched seed entity, by target kind.
fn seed_confidence(kind: TargetKind) -> f64 {
    match kind {
        TargetKind::Email => 0.75,
        TargetKind::Domain => 0.65,
        _ => 0.45,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
