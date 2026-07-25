use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::{ModuleContext, ModuleResult},
};
use crate::util::http::RequestBuilderExt;

use super::helpers::{ssh_fingerprint, top_event_types, usable_commit_email};

const SRC: &str = "github_user";

/// One row of GitHub's `/users/{login}/keys` response — the subject's own
/// published SSH public keys. Kept at module scope (not nested inside the
/// fetch fn) so the entity-building logic can be unit-tested without a live
/// HTTP round-trip.
#[derive(serde::Deserialize)]
pub(super) struct SshKey {
    #[serde(default)]
    pub(super) id: Option<u64>,
    #[serde(default)]
    pub(super) key: Option<String>,
}

/// Turn every one of the subject's published SSH public keys into a
/// fingerprinted, CORRELATABLE `Credential` artifact. A public key published
/// on two accounts proves the same person holds the private key — the
/// strongest cross-account link there is. The artifact value is `ssh:<fp>` (a
/// hash of algo+base64, comment dropped), so two accounts sharing a key
/// produce the SAME uid and the engine merges them into one artifact carrying
/// both logins — which AU-048 then links.
///
/// Every parsed key is emitted, with no cap: these are all the *subject's own*
/// keys (no false-attribution risk), a developer commonly registers more than
/// a handful, and each key is an independent cryptographic pivot, so silently
/// dropping keys 11+ would discard real cross-account evidence.
pub(super) fn ssh_key_entities(keys: &[SshKey], scan_id: &str, login: &str) -> Vec<Entity> {
    keys.iter()
        .filter_map(|key| {
            let fp = key.key.as_deref().and_then(ssh_fingerprint)?;
            let mut e = Entity::new(
                EntityKind::Credential,
                &fp,
                confidence::HIGH_PLUSPLUS_PLUS,
                scan_id,
            );
            e.tag("ssh-key");
            e.tag("public-key");
            e.tag("github");
            let algo = key
                .key
                .as_deref()
                .and_then(|k| k.split_whitespace().next())
                .unwrap_or("ssh");
            e.add_evidence(
                Evidence::new(SRC, format!("SSH public key published by @{login}"))
                    .with_attr("github_login", login)
                    .with_attr("key_type", algo),
            );
            Some(e)
        })
        .collect()
}

pub(super) async fn fetch_ssh_keys(login: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
    let url = format!("https://api.github.com/users/{login}/keys");
    let resp = match ctx
        .http
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header(
            "X-GitHub-Api-Version",
            crate::modules::code::github_api::API_VERSION,
        )
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };
    if !resp.status().is_success() {
        return;
    }

    let keys: Vec<SshKey> = match crate::util::http::json_scanned(resp, SRC).await {
        Ok(k) => k,
        Err(_) => return,
    };
    if keys.is_empty() {
        return;
    }

    if let Some(first) = result.entities.first_mut() {
        first.tag("has-ssh-keys");
        let key_summaries: Vec<String> = keys
            .iter()
            .take(5)
            .filter_map(|k| {
                let key_str = k.key.as_deref()?;
                let algo = key_str.split_whitespace().next().unwrap_or("unknown");
                Some(format!("id={} type={algo}", k.id.unwrap_or(0)))
            })
            .collect();
        first.add_evidence(
            Evidence::new(
                SRC,
                format!("{} SSH public key(s) for @{login}", keys.len()),
            )
            .with_attr("ssh_key_count", keys.len().to_string())
            .with_attr("ssh_keys", key_summaries.join("; ")),
        );
    }

    // Emit EVERY published key as a correlatable Credential artifact (see
    // `ssh_key_entities` — no cap; all keys are the subject's own).
    result.extend(ssh_key_entities(&keys, &ctx.scan_id, login));
}

pub(super) async fn fetch_orgs(
    ctx: &ModuleContext,
    username: &str,
    token: Option<&str>,
) -> Vec<String> {
    let url = format!(
        "https://api.github.com/users/{}/orgs",
        crate::util::http::urlencode(username)
    );
    let mut req = ctx
        .http
        .get(&url)
        .header("User-Agent", crate::util::http::UA_OSINT)
        .header("Accept", "application/vnd.github+json");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let Ok(resp) = req.send().await else {
        return Vec::new();
    };
    let status = resp.status();
    if !status.is_success() {
        // A present token that gets rejected/throttled must be reported to the
        // pool, or a dead/throttled token silently degrades every future scan
        // with no operator-visible signal and no chance to rotate.
        if let Some(t) = token {
            crate::util::http::note_keyed_error(status.as_u16(), "github", t, ctx);
        }
        return Vec::new();
    }
    // Capped read (32 MiB) for the needle scan below — an uncapped `text()`
    // would buffer an unbounded body on the low-RAM Termux target.
    let Some(body) =
        crate::util::http::read_body_capped(resp, crate::util::http::JSON_BODY_CAP).await
    else {
        return Vec::new();
    };
    // Extract org login names.
    crate::util::json::scan_string_field(&body, "login")
}

pub(super) async fn fetch_gists(
    ctx: &ModuleContext,
    username: &str,
    token: Option<&str>,
) -> Vec<String> {
    let url = format!(
        "https://api.github.com/users/{}/gists?per_page=30",
        crate::util::http::urlencode(username)
    );
    let mut req = ctx
        .http
        .get(&url)
        .header("User-Agent", crate::util::http::UA_OSINT)
        .header("Accept", "application/vnd.github+json");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let Ok(resp) = req.send().await else {
        return Vec::new();
    };
    let status = resp.status();
    if !status.is_success() {
        // Same reporting rationale as `fetch_orgs` above.
        if let Some(t) = token {
            crate::util::http::note_keyed_error(status.as_u16(), "github", t, ctx);
        }
        return Vec::new();
    }
    // Capped read (32 MiB) for the needle scan below — an uncapped `text()`
    // would buffer an unbounded body on the low-RAM Termux target.
    let Some(body) =
        crate::util::http::read_body_capped(resp, crate::util::http::JSON_BODY_CAP).await
    else {
        return Vec::new();
    };
    // Extract gist IDs from "id":"..." fields in gist objects. Gist IDs are
    // 32 hex chars — the length filter drops the numeric owner/etc. ids that
    // share the key (scan_string_field already skips the unquoted numerics).
    crate::util::json::scan_string_field(&body, "id")
        .into_iter()
        .filter(|id| id.len() == 32)
        .collect()
}

/// Fetch up to `MAX_GISTS` gist details and scan their file content for emails.
/// Each gist detail call goes through `send_tagged` so the
/// `found_keys` scanner automatically processes every response body for leaked
/// API keys — satisfying the "preserve every API key" vault policy with no
/// extra code.
///
/// Cap: 3 gists × ≤1 API call each = 3 extra calls per user lookup.  Small
/// enough to stay well within the 60 req/hr unauthenticated cap.
pub(super) async fn fetch_gist_content(
    gist_ids: &[String],
    login: &str,
    ctx: &ModuleContext,
    result: &mut ModuleResult,
) {
    const MAX_GISTS: usize = 3;
    let mut seen_emails: std::collections::HashSet<String> = std::collections::HashSet::new();

    for gist_id in gist_ids.iter().take(MAX_GISTS) {
        let url = format!("https://api.github.com/gists/{gist_id}");
        let resp = match ctx
            .http
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header(
                "X-GitHub-Api-Version",
                crate::modules::code::github_api::API_VERSION,
            )
            .send_tagged(SRC)
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }
        // Body is capped to avoid RAM exhaustion on Termux; a 512 KiB cap is
        // generous for gist content (typical source files are well under 10 KiB)
        // while bounding worst-case allocations.
        let Some(body) = crate::util::http::read_body_capped(resp, 512 * 1024).await else {
            continue;
        };

        // Extract emails from the full gist JSON (includes file content inline
        // for files ≤1 MB).  Skip noreply placeholders.
        for email in crate::util::extract::emails(&body) {
            if email.ends_with("@users.noreply.github.com") {
                continue;
            }
            if !seen_emails.insert(email.clone()) {
                continue;
            }
            let mut e = crate::core::entity::Entity::new(
                crate::core::entity::EntityKind::Email,
                &email,
                0.72,
                &ctx.scan_id,
            );
            e.tag("github");
            e.tag("gist-content");
            e.add_evidence(
                crate::core::entity::Evidence::new(
                    SRC,
                    format!("Email extracted from @{login}'s public gist {gist_id}"),
                )
                .with_attr("github_login", login)
                .with_attr("gist_id", gist_id)
                .with_attr("source", "gist_content"),
            );
            result.push(e);
        }
    }
}

/// One entry of GitHub's `/users/{login}/events/public` feed. Kept at module
/// scope (not nested inside `fetch_events`) so the commit-author-email
/// extraction can be unit-tested without a live HTTP round-trip.
#[derive(serde::Deserialize)]
pub(super) struct GhEvent {
    #[serde(default)]
    pub(super) created_at: Option<String>,
    #[serde(default, rename = "type")]
    pub(super) event_type: Option<String>,
    #[serde(default)]
    pub(super) payload: Option<GhPayload>,
}
#[derive(serde::Deserialize)]
pub(super) struct GhPayload {
    #[serde(default)]
    pub(super) commits: Vec<GhCommit>,
}
#[derive(serde::Deserialize)]
pub(super) struct GhCommit {
    #[serde(default)]
    pub(super) author: Option<GhCommitAuthor>,
}
#[derive(serde::Deserialize)]
pub(super) struct GhCommitAuthor {
    #[serde(default)]
    pub(super) email: Option<String>,
}

/// Every DISTINCT usable commit-author email the subject's public push events
/// published, each emitted as a `commit-email` `Email` pivot. A user's own
/// public push events embed the `git` author email of each commit — one of the
/// most reliable real-email → handle links in OSINT. GitHub's privacy
/// `…@users.noreply.github.com` / `noreply@github.com` placeholders carry no
/// identity and are dropped by `usable_commit_email`.
///
/// Dedup is by normalised value; output order is first-seen over the event
/// stream (GitHub returns it newest-first, so the ordering is deterministic for
/// a given response). No cap: the events endpoint is already bounded to 30
/// events, so the distinct-email set is naturally small, and every distinct
/// real address is an independent pivot — silently dropping addresses 11+ (the
/// old `.take(10)`, a bound "to keep a busy account bounded") would discard
/// real handle→email evidence with no signal any were lost. The evidence label
/// states the address came from the subject's commit *author field* — honest
/// provenance, not a claim the address IS the subject.
pub(super) fn commit_email_entities(events: &[GhEvent], scan_id: &str, login: &str) -> Vec<Entity> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    events
        .iter()
        .filter_map(|event| event.payload.as_ref())
        .flat_map(|payload| payload.commits.iter())
        .filter_map(|commit| commit.author.as_ref()?.email.as_deref())
        .filter_map(usable_commit_email)
        .filter(|email| seen.insert(email.clone()))
        .map(|email| {
            let mut e = Entity::new(EntityKind::Email, &email, 0.82, scan_id);
            e.tag("github");
            e.tag("commit-email");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Email from @{login}'s public commit author field"),
                )
                .with_attr("github_login", login)
                .with_attr("source", "commit_author"),
            );
            e
        })
        .collect()
}

pub(super) async fn fetch_events(login: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
    let url = format!("https://api.github.com/users/{login}/events/public?per_page=30");
    let resp = match ctx
        .http
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header(
            "X-GitHub-Api-Version",
            crate::modules::code::github_api::API_VERSION,
        )
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };
    if !resp.status().is_success() {
        return;
    }

    let events: Vec<GhEvent> = match crate::util::http::json_scanned(resp, SRC).await {
        Ok(e) => e,
        Err(_) => return,
    };
    if events.is_empty() {
        return;
    }

    let mut hours: [u32; 24] = [0; 24];
    let mut event_types: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut most_recent: Option<&str> = None;

    for event in &events {
        if let Some(ts) = event.created_at.as_deref() {
            if most_recent.is_none() {
                most_recent = Some(ts);
            }
            if let Some(hour_str) = ts.get(11..13)
                && let Ok(h) = hour_str.parse::<usize>()
                && h < 24
            {
                hours[h] += 1;
            }
        }
        if let Some(et) = event.event_type.as_deref() {
            *event_types.entry(et.to_string()).or_default() += 1;
        }
    }

    let peak_hour = hours
        .iter()
        .enumerate()
        .max_by_key(|(_, count)| **count)
        .map_or(0, |(h, _)| h);

    if let Some(first) = result.entities.first_mut() {
        let mut ev = Evidence::new(
            SRC,
            format!("{} recent public event(s) for @{login}", events.len()),
        )
        .with_attr("event_count", events.len().to_string())
        .with_attr("peak_hour_utc", format!("{peak_hour:02}:00"));

        if let Some(ts) = most_recent {
            ev = ev.with_attr("most_recent_event", ts);
        }

        let top_types = top_event_types(event_types, 3);
        if !top_types.is_empty() {
            ev = ev.with_attr("top_event_types", top_types.join(", "));
        }

        first.add_evidence(ev);
    }

    // Emit EVERY distinct usable commit-author email (see `commit_email_entities`
    // — no cap; deduped, placeholder-filtered).
    result.extend(commit_email_entities(&events, &ctx.scan_id, login));
}
