//! Free leaked-credential search over the public COMB (Compilation of Many
//! Breaches) index — no API key, real public source.
//!
//! This is the free, self-owned emulation of SeekNow's paid stealer/credential
//! `/search` corpus. Where `see_know` queries the key-gated see-know.eu API,
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
//! username root is not a unique person — and the Username seed itself is
//! never enriched or tagged `breach` from those lines: they are other people's
//! accounts that happen to share a local part.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::extract::{
    CredentialField, classify_credential_field, split_identity_secret as split_line,
};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "comb_search";

/// ProxyNova's COMB endpoint. A miss is a `200` with `count: 0, lines: []` —
/// never a 404 — so every non-2xx is a failed lookup, not "not in COMB".
const API_BASE: &str = "https://api.proxynova.com/comb";

/// Max credential lines requested per query. COMB caps `count` at 10000 (a
/// sentinel, not a real total), so we request a bounded window and rely on the
/// exact-match filter to keep only the relevant lines.
const FETCH_LIMIT: u32 = 100;

/// Max distinct leaked secrets surfaced per scan target — bounds graph growth
/// on a heavily-exposed identity while still proving the exposure.
const MAX_SECRETS: usize = 50;

/// Base confidence for a leaked secret tied to the EXACT subject email. COMB is
/// an aggregated compilation of older breaches (lower fidelity than a live
/// stealer log), so it sits below HudsonRock's confidence::HIGH_PLUSPLUS_PLUS stealer baseline.
const EMAIL_MATCH_CONF: f64 = confidence::NOTABLE;

/// Confidence for an exposed account discovered under a DOMAIN target — a real
/// account at that domain, but a third party rather than the scan subject.
const DOMAIN_ACCOUNT_CONF: f64 = confidence::MEDIUM;

pub struct CombSearch;

#[derive(Debug, serde::Deserialize)]
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
        "COMB credential sweep — free leaked-credential search across the public COMB index (no API key)"
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
        // The enriched seed re-affirms the queried identity as its own kind
        // (Email/Domain/Username) alongside the discovered Password secrets.
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Password,
            EntityKind::Domain,
            EntityKind::Username,
        ];
        KINDS
    }

    fn provider_descriptor(&self) -> crate::core::module::ProviderDescriptor {
        crate::core::module::ProviderDescriptor {
            // COMB is an aggregated compilation of older breaches — lower
            // fidelity than a live stealer-log source (see this module's own
            // confidence-baseline doc comment above) — so this sits below the
            // 0.5 neutral default other modules get by default.
            provenance_quality_prior: 0.35,
            ..crate::core::module::derive_default_provider_descriptor(self)
        }
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

        let resp = query_comb(&ctx.http, API_BASE, v).await?;

        for e in build_entities_from_lines(&resp.lines, target, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// One COMB query. Routed through [`fetch_json`], which errors on EVERY
/// non-2xx: this endpoint signals a miss in the body of a `200`, so a 404 (the
/// endpoint moved, a WAF page), a 429 or a 5xx is a failed lookup. Before this
/// the call went through `fetch_json_or_404`, whose `404 → Ok(None)` the caller
/// mapped to an empty result — an outage read as "not in COMB", a clean-negative
/// breach claim about a named subject (`docs/PROVIDER_SWEEP_BACKLOG.md` #12).
async fn query_comb(client: &reqwest::Client, api_base: &str, value: &str) -> Result<CombResp> {
    let url = format!(
        "{api_base}?query={}&start=0&limit={FETCH_LIMIT}",
        urlencode(value)
    );
    fetch_json(client, SRC, &url).await
}

/// Build the credential entities from the raw COMB `lines`. **Pure** (no
/// network), so the exact-match attribution, the AU-047 typed-key stamping
/// (`email`/`username`, the reused-secret join key) and the per-account/secret
/// dedup are unit-tested directly off fixture lines. Returns nothing (not even
/// the seed summary) when no line exactly matches the target.
fn build_entities_from_lines(lines: &[String], target: &Target, scan_id: &str) -> Vec<Entity> {
    let v = target.value.trim();
    let mut out: Vec<Entity> = Vec::new();

    // Strict exact-match filter — COMB matches substrings, so discard every
    // line whose identity is not EXACTLY this target before minting anything.
    let mut seen_secret: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_email: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut matched = 0usize;

    for line in lines {
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
            // Canonicalise before the dedup insert, not the bare ASCII
            // lowercase — it case-folds but does not strip a breach-dump
            // escape tail or surrounding quote characters the way
            // `Entity::new` does internally, so a dirty and a clean spelling
            // of the same address would each earn their own dedup slot here
            // despite collapsing onto the identical uid once constructed.
            && seen_email.insert(crate::core::entity::normalise(&EntityKind::Email, identity))
        {
            let mut e = Entity::new(EntityKind::Email, identity, DOMAIN_ACCOUNT_CONF, scan_id);
            e.tag(tags::BREACH);
            e.tag("comb");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Exposed account `{identity}` in COMB compilation"),
                )
                .with_attr("identity", identity)
                // The reused-secret detector / AU-047 join on a typed
                // `email`/`username` key, not the raw `identity` — this
                // account is an email at the target domain.
                .with_attr("email", identity)
                .with_attr("source", "proxynova-comb"),
            );
            out.push(e);
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
            scan_id,
        );
        pw.tag(tags::BREACH);
        pw.tag("credential");
        pw.tag("comb");
        // A username root is not a unique person; quarantine its secrets so
        // they never corroborate the subject as confirmed.
        if target.kind == TargetKind::Username {
            pw.demote_to_candidate();
        }
        // AU-047 / the `SharesSecretWith` link key on a TYPED `email` /
        // `username` evidence attribute (not the raw `identity`), so stamp
        // the account under its typed key. Without it a COMB-sourced password
        // reused across ≥2 of the subject's accounts never participated in
        // reused-secret detection. A Password entity is value-normalised, so
        // the same secret found for several accounts accumulates all their
        // typed keys onto one entity — exactly what the detector groups on.
        let mut pw_ev = Evidence::new(
            SRC,
            format!("Leaked credential for `{identity}` in COMB compilation"),
        )
        .with_attr("identity", identity)
        .with_attr("source", "proxynova-comb");
        pw_ev = if identity.contains('@') {
            pw_ev.with_attr("email", identity)
        } else {
            pw_ev.with_attr("username", identity)
        };
        pw.add_evidence(pw_ev);
        out.push(pw);
    }

    if matched == 0 {
        return out;
    }

    if target.kind == TargetKind::Username {
        // A Username seed was matched on the exact local part of strangers'
        // addresses — every `john@…` in the compilation — which says nothing
        // about the subject (backlog #13). The candidate-quarantined secrets
        // above are the leads; the seed itself is never enriched: an emitted
        // copy would merge with the confirmed seed (a merge clears a candidate
        // tag), and the `breach` tag is load-bearing downstream — breach-sector
        // enrichment, the AU-061 pass and lead triage would classify the
        // subject as breach-exposed on rows about other people.
        return out;
    }

    // Enrich the seed once with the aggregate exposure summary — an Email or
    // Domain seed's matched lines are the subject's own accounts.
    let mut seed = target.to_entity(seed_confidence(target.kind), scan_id);
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
    out.push(seed);

    out
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

// `split_line` (identity:secret on the FIRST colon) is `util::extract::split_identity_secret`,
// imported above — the single authority for this shape, also backing the
// raw-combolist file importer (`app::import::combolist`), so COMB's live
// fetch and an uploaded combolist parse identity:secret lines identically.

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
            let local = crate::core::validation::email_local(identity);
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
        _ => confidence::LOW,
    }
}

/// Confidence for the enriched seed entity, by target kind.
fn seed_confidence(kind: TargetKind) -> f64 {
    match kind {
        TargetKind::Email => confidence::VERY_HIGH,
        TargetKind::Domain => confidence::HIGH,
        _ => confidence::LOW_MEDIUM,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
