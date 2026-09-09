//! Parser for a raw **combolist** — the plain, line-oriented `identity:secret`
//! (or `;`/tab separated) credential dump that is the single most common
//! real-world breach-data shape: no header, no JSON envelope, no OathNet
//! banner, just one leaked login per line. Previously unrecognised: every
//! `looks_like_*` check in [`super::detect_import_format`] rejected it, so it
//! fell through to the OathNet stealer-log TXT catch-all — which only
//! recognises its own `"URL: "`/`"Username: "` labelled lines and therefore
//! extracted **zero** entities from a bare combolist, silently discarding a
//! real breach file. Shared helpers (`ImportStats`, persistence, `push_*`
//! extractors) live in `super` and are reached via `use super::*`.
//!
//! Line splitting delegates to [`crate::util::extract::split_identity_secret`]
//! (colon — the dominant separator), the same authority `comb_search` uses for
//! its live COMB fetch, so an uploaded combolist and a live COMB result parse
//! identity:secret pairs identically. `;` and a literal tab are tried as
//! fallback separators for the other common combolist export shapes.
//! Malformed lines (no recognised delimiter, an empty identity, or an empty
//! secret) are quarantined — counted in `ImportStats::malformed_lines` and
//! skipped — so one bad line never aborts the rest of the file.

use super::*;

use crate::core::confidence;
use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::extract::{
    CredentialField, classify_credential_field, looks_like_email, split_identity_secret,
};

/// How many non-empty lines [`looks_like_combolist`] samples before deciding.
/// Bounded so detection stays cheap even on a multi-megabyte upload.
const DETECT_SAMPLE_LINES: usize = 50;

/// Detect a raw combolist from its CONTENT: an overwhelming majority of the
/// sampled non-empty lines must split into an email-shaped identity plus a
/// non-empty secret. The high bar (and requiring at least 3 sampled lines)
/// keeps this fallback from misfiring on a handful of incidental
/// `"Key: value"`-shaped lines in some other text format — every more
/// specific `looks_like_*` check in [`super::detect_import_format`] runs
/// first, so this only ever claims what would otherwise reach the OathNet TXT
/// catch-all and yield nothing.
pub(crate) fn looks_like_combolist(body: &str) -> bool {
    let mut total = 0usize;
    let mut matched = 0usize;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        total += 1;
        if let Some((identity, secret)) = split_combo_line(line)
            && !secret.is_empty()
            && looks_like_email(identity)
        {
            matched += 1;
        }
        if total >= DETECT_SAMPLE_LINES {
            break;
        }
    }
    total >= 3 && matched * 10 >= total * 9
}

/// Split one combolist line into `(identity, secret)`, trying colon first (the
/// dominant separator, via the shared [`split_identity_secret`] authority),
/// then `;` and a literal tab for the other common export shapes. `None` when
/// no recognised delimiter yields a non-empty identity.
fn split_combo_line(line: &str) -> Option<(&str, &str)> {
    if let Some(pair) = split_identity_secret(line) {
        return Some(pair);
    }
    for delim in [';', '\t'] {
        if let Some((identity, secret)) = line.split_once(delim) {
            let identity = identity.trim();
            if !identity.is_empty() {
                return Some((identity, secret.trim()));
            }
        }
    }
    None
}

/// Parse a raw combolist into entities + stats. Pure (no I/O), so the
/// quarantine/dedup/entity-shape behaviour is unit-tested directly;
/// `cmd_import_combolist` does the CLI output and `entities_from_upload`
/// reaches this for the web upload.
pub(super) fn parse_combolist(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen = std::collections::HashSet::new();

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((identity, secret)) = split_combo_line(line) else {
            stats.malformed_lines += 1;
            continue;
        };
        if secret.is_empty() {
            stats.malformed_lines += 1;
            continue;
        }

        let is_email = looks_like_email(identity);
        // A bare username identity must still be a single, whitespace-free
        // token — `split_combo_line` already trimmed it, so any remaining
        // internal whitespace means this "identity" is prose, not a login.
        if !is_email && identity.contains(char::is_whitespace) {
            stats.malformed_lines += 1;
            continue;
        }

        // Build the identity entity before deciding anything else: `Entity::new`
        // NORMALISES the value (a `Username` strips surrounding quotes/`@`), so
        // an identity that is punctuation-only (`'`) normalises to the EMPTY
        // string. That must never reach the graph — treat it as the line being
        // malformed (skip the secret too, matching every other whole-line
        // quarantine above) rather than emitting an empty-value entity.
        let (identity_kind, identity_confidence) = if is_email {
            (EntityKind::Email, confidence::ATTRIBUTED)
        } else {
            (EntityKind::Username, confidence::MEDIUM_PLUS)
        };
        let identity_entity = Entity::new(identity_kind, identity, identity_confidence, sid);
        if identity_entity.value.is_empty() {
            stats.malformed_lines += 1;
            continue;
        }
        // Captured before `identity_entity` is moved into `entities` below.
        // The self-echo guard further down must compare against this
        // NORMALISED value, not the raw `identity` text: `Entity::new`
        // strips surrounding quotes/`@` (see the comment above), so a line
        // like `'alice':alice` has raw identity `'alice'` but secret `alice`
        // — a raw-vs-raw comparison misses the echo entirely and mints a
        // spurious Password entity for a value that is just the identity's
        // own normalised form.
        let identity_normalised = identity_entity.value.clone();

        let ev = Evidence::new(
            "import:combolist",
            format!("Combolist entry for `{identity}`"),
        )
        .with_attr("identity", identity)
        .with_attr("source", "combolist");
        let ev = if is_email {
            ev.with_attr("email", identity)
        } else {
            ev.with_attr("username", identity)
        };

        if seen.insert(format!(
            "{}:{}",
            if is_email { "em" } else { "un" },
            identity_entity.value.to_ascii_lowercase()
        )) {
            let mut e = identity_entity;
            e.tag("import");
            e.tag("combolist");
            e.tag("breach");
            e.add_evidence(ev.clone());
            entities.push(e);
            if is_email {
                stats.emails += 1;
            } else {
                stats.usernames += 1;
            }
        }

        // Classify the secret exactly as `comb_search` does for a live COMB
        // result: drop capture sentinels, recover a mis-stored email as its
        // own lead rather than a fake password, and never mint an identity
        // echoed back as its own "secret".
        match classify_credential_field(secret) {
            CredentialField::Sentinel => continue,
            CredentialField::Email => {
                let e = Entity::new(EntityKind::Email, secret, confidence::LOW_MEDIUM, sid);
                // `looks_like_email` (which routed `secret` here) is a shape
                // check on the raw text; `Entity::new`'s normalisation is a
                // second, independent pass (cuts at a stray backslash/control
                // byte) that could in principle still land on empty — never
                // mint that as a finding.
                if !e.value.is_empty() && seen.insert(format!("em:{}", e.value)) {
                    let mut e = e;
                    e.tag("import");
                    e.tag("combolist");
                    entities.push(e);
                    stats.emails += 1;
                }
                continue;
            }
            CredentialField::Secret => {}
        }
        if secret.eq_ignore_ascii_case(&identity_normalised) {
            continue;
        }
        if !seen.insert(format!("pw:{secret}")) {
            continue;
        }
        let mut pw = Entity::new(EntityKind::Password, secret, confidence::MEDIUM_SOLID, sid);
        pw.tag("import");
        pw.tag("combolist");
        pw.tag("breach");
        pw.tag("credential");
        pw.add_evidence(ev);
        entities.push(pw);
        stats.credentials += 1;
    }

    push_macs(body, sid, "combolist", &mut entities);
    push_crypto(body, sid, "combolist", &mut entities);
    push_api_keys(body, sid, "combolist", &mut entities);
    push_ibans(body, sid, "combolist", &mut entities);
    (entities, stats)
}

pub(super) async fn cmd_import_combolist(body: &str, output: &str) -> Result<()> {
    note(output, "Importing raw combolist...");
    let sid = format!("import-combolist-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_combolist(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
