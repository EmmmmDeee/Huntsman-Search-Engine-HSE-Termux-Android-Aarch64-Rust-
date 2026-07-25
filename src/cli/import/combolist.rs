//! Parser for flat **combolist** / **ULP** credential dumps — the single most
//! common credential-leak format traded in OSINT, and the one shape none of the
//! labelled parsers (`stealerlogs`, `oathnet-*`, `dehashed-csv`) recognised.
//!
//! Two line shapes, both `:`-delimited:
//!
//! * **combo** — `identity:password`, e.g. `alice@example.com:hunter2` or
//!   `boblogin:s3cret`. The identity is an [`Email`](crate::core::entity::EntityKind::Email)
//!   when it looks like one, else a [`Username`](crate::core::entity::EntityKind::Username).
//! * **ULP** ("URL:login:pass") — `https://site.com/login:user:pass`. The leading
//!   `http(s)://…` is lifted to a [`Url`](crate::core::entity::EntityKind::Url) plus
//!   its host [`Domain`](crate::core::entity::EntityKind::Domain); the remaining
//!   `user:pass` is parsed as a combo.
//!
//! Every trailing field is emitted as a plaintext [`Credential`](crate::core::entity::EntityKind::Credential)
//! — the cross-account password-reuse join-key the correlator's reuse rules pivot
//! on — mirroring `csv.rs`'s DeHashed plaintext-password gating (≥4 chars, one
//! `Credential` per distinct value). Before this parser existed a pasted combolist
//! fell through to the `OathnetTxt` catch-all, which only reads `URL:`/`Username:`/
//! `Password:`-labelled lines, so the entire payload imported as ZERO entities with
//! no error.

use super::*;

/// Heuristic: does `body` look like a flat combolist / ULP dump?
///
/// True when a clear majority of the first non-blank lines are bare
/// `:`-delimited credential lines whose FIRST field is an email or a plausible
/// bare username — and which carry NO labelled-format markers (so a
/// `Username: x` stealer line or a `key: value` config never trips it). Kept
/// deliberately strict: this is the LAST content heuristic before the
/// `OathnetTxt` catch-all, so a false positive would only ever reclassify text
/// that would otherwise import as nothing.
pub(crate) fn looks_like_combolist(body: &str) -> bool {
    // Labelled formats own their lines — never treat them as a combolist.
    if body.contains("URL: ") || body.contains("Username: ") || body.contains("Password: ") {
        return false;
    }
    let mut considered = 0usize;
    let mut credential_lines = 0usize;
    for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        considered += 1;
        if considered > 200 {
            break; // a bounded sample is enough to classify a homogeneous dump
        }
        if parse_line(line).is_some() {
            credential_lines += 1;
        }
    }
    // Require a real sample and a strong majority so free-form prose (which may
    // contain the odd `a:b`) is never misread as a credential dump.
    considered >= 2 && credential_lines * 100 >= considered * 80
}

/// One parsed combolist line: an optional leading URL (ULP form), the identity,
/// and the plaintext secret.
struct ComboLine<'a> {
    url: Option<&'a str>,
    identity: &'a str,
    secret: &'a str,
}

/// Parse a single line into its `(url?, identity, secret)` parts, or `None` if
/// the line is not a credential line. Pure and allocation-free.
fn parse_line(line: &str) -> Option<ComboLine<'_>> {
    let line = line.trim();
    // ULP: `http(s)://host/path:user:pass`. Split the URL off first (it contains
    // its own `:` in the scheme, which a naive split would mangle), then parse the
    // remaining `user:pass` tail.
    if let Some(rest) = line
        .strip_prefix("http://")
        .or_else(|| line.strip_prefix("https://"))
    {
        // Find the FIRST ':' after the scheme that separates the URL from the
        // login — that's the ':' following the URL's path (URLs here carry no
        // port, matching how these dumps are shaped: `site.com/login:u:p`).
        let scheme_len = line.len() - rest.len();
        let after_scheme = &line[scheme_len..];
        let (url_tail, creds) = after_scheme.split_once(':')?;
        let url = &line[..scheme_len + url_tail.len()];
        let (identity, secret) = split_identity_secret(creds)?;
        return Some(ComboLine {
            url: Some(url),
            identity,
            secret,
        });
    }
    // Plain combo: `identity:secret`.
    let (identity, secret) = split_identity_secret(line)?;
    Some(ComboLine {
        url: None,
        identity,
        secret,
    })
}

/// Split an `identity:secret` (or `identity:secret:extra…`) tail. The identity is
/// everything up to the FIRST ':'; the secret is the remainder (so a password
/// containing ':' survives intact). Rejects the line when either side is empty,
/// the identity carries whitespace (prose, not a credential), or the identity is
/// not email/username-shaped.
fn split_identity_secret(s: &str) -> Option<(&str, &str)> {
    let (identity, secret) = s.split_once(':')?;
    let identity = identity.trim();
    let secret = secret.trim();
    if identity.is_empty() || secret.is_empty() {
        return None;
    }
    // A credential identity is a single token — no spaces/tabs.
    if identity.contains(char::is_whitespace) {
        return None;
    }
    if !identity_is_plausible(identity) {
        return None;
    }
    Some((identity, secret))
}

/// True if `identity` is a plausible email or bare username: either an
/// email-shaped `local@host.tld`, or a handle of ASCII letters/digits and the
/// usual handle punctuation (`. _ - +`) at least 2 chars long. This is what keeps
/// a `key = value` config line or a `12:34:56` timestamp from being read as a
/// credential.
fn identity_is_plausible(identity: &str) -> bool {
    if let Some((local, host)) = identity.split_once('@') {
        return !local.is_empty() && host.contains('.') && !host.contains('@');
    }
    identity.len() >= 2
        && identity
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
        // At least one letter or digit — reject a run of pure punctuation.
        && identity.chars().any(|c| c.is_ascii_alphanumeric())
}

/// Parse a flat combolist / ULP body into entities + stats. Pure (no I/O) so it
/// is unit-tested directly. Emits, per line: the identity (Email or Username),
/// the plaintext secret (Credential), and — for ULP lines — the Url and its host
/// Domain. Values are de-duplicated within the import exactly like the sibling
/// parsers (one entity per distinct value).
pub(super) fn parse_combolist(
    body: &str,
    sid: &str,
) -> (Vec<crate::core::entity::Entity>, ImportStats) {
    use crate::core::entity::{Entity, EntityKind};
    use std::collections::HashSet;

    let mut entities: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut stats = ImportStats::default();

    for raw in body.lines() {
        let Some(parsed) = parse_line(raw) else {
            continue;
        };

        // ── URL + host domain (ULP form only) ──
        if let Some(url) = parsed.url {
            if seen.insert(format!("u:{url}")) {
                let mut e = Entity::new(EntityKind::Url, url, 0.45, sid);
                e.tag("import");
                e.tag("combolist");
                entities.push(e);
                stats.urls += 1;
            }
            if let Some(host) = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
            {
                let domain = host.split('/').next().unwrap_or("").split(':').next().unwrap_or("");
                if domain.contains('.') && seen.insert(format!("d:{domain}")) {
                    let is_sub = domain.split('.').count() >= 3;
                    let mut de = Entity::new(
                        EntityKind::Domain,
                        domain,
                        if is_sub { 0.45 } else { 0.50 },
                        sid,
                    );
                    de.tag("import");
                    de.tag("combolist");
                    if is_sub {
                        de.tag("subdomain");
                        stats.subdomains += 1;
                    } else {
                        stats.domains += 1;
                    }
                    entities.push(de);
                }
            }
        }

        // ── Identity: email or username ──
        let is_email = parsed.identity.contains('@');
        let id_key = if is_email {
            format!("em:{}", parsed.identity.to_lowercase())
        } else {
            format!("un:{}", parsed.identity.to_lowercase())
        };
        if seen.insert(id_key) {
            if is_email {
                let mut e = Entity::new(EntityKind::Email, parsed.identity, 0.55, sid);
                e.tag("import");
                e.tag("combolist");
                entities.push(e);
                stats.emails += 1;
            } else {
                let mut e = Entity::new(EntityKind::Username, parsed.identity, 0.45, sid);
                e.tag("import");
                e.tag("combolist");
                entities.push(e);
                stats.usernames += 1;
            }
        }

        // ── Plaintext secret → Credential (the reuse join-key), ≥4 chars ──
        if parsed.secret.chars().count() >= 4 && seen.insert(format!("cr:{}", parsed.secret)) {
            let mut e = Entity::new(EntityKind::Credential, parsed.secret, 0.55, sid);
            e.tag("import");
            e.tag("combolist");
            e.tag("plaintext-credential");
            entities.push(e);
            stats.credentials += 1;
        }
    }

    (entities, stats)
}

/// CLI wrapper: `hse import` of a combolist / ULP dump. Mirrors
/// [`cmd_import_txt`]'s shape (parse → dedup → stats → persist → render).
pub(super) async fn cmd_import_combolist(body: &str, output: &str) -> Result<()> {
    note(output, "Importing combolist / ULP credential dump...");
    let sid = format!("import-combo-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_combolist(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
