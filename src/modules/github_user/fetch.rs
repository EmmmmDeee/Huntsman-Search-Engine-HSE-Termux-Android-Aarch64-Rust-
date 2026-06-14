use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::{ModuleContext, ModuleResult},
};

use super::helpers::{ssh_fingerprint, top_event_types, usable_commit_email};

const SRC: &str = "github_user";

/// Result of [`fetch_ssh_keys`]: evidence to attach to the username entity,
/// plus any `Credential` entities to append to the result.
pub(super) struct SshResult {
    /// Evidence to add to `result.entities[0]` (the username entity).
    pub(super) username_evidence: Option<Evidence>,
    /// Extra entities (one per SSH key fingerprint).
    pub(super) extra: Vec<Entity>,
    /// Whether any keys were found (drives the `has-ssh-keys` tag).
    pub(super) has_keys: bool,
}

pub(super) async fn fetch_ssh_keys(login: &str, ctx: &ModuleContext) -> SshResult {
    let url = format!("https://api.github.com/users/{login}/keys");
    let resp = match ctx
        .http
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return SshResult {
                username_evidence: None,
                extra: vec![],
                has_keys: false,
            };
        }
    };
    if !resp.status().is_success() {
        return SshResult {
            username_evidence: None,
            extra: vec![],
            has_keys: false,
        };
    }

    #[derive(serde::Deserialize)]
    struct SshKey {
        #[serde(default)]
        id: Option<u64>,
        #[serde(default)]
        key: Option<String>,
    }

    let keys: Vec<SshKey> = match crate::util::http::json_scanned(resp, SRC).await {
        Ok(k) => k,
        Err(_) => {
            return SshResult {
                username_evidence: None,
                extra: vec![],
                has_keys: false,
            };
        }
    };
    if keys.is_empty() {
        return SshResult {
            username_evidence: None,
            extra: vec![],
            has_keys: false,
        };
    }

    let key_summaries: Vec<String> = keys
        .iter()
        .take(5)
        .filter_map(|k| {
            let key_str = k.key.as_deref()?;
            let algo = key_str.split_whitespace().next().unwrap_or("unknown");
            Some(format!("id={} type={algo}", k.id.unwrap_or(0)))
        })
        .collect();

    let ev = Evidence::new(
        SRC,
        format!("{} SSH public key(s) for @{login}", keys.len()),
    )
    .with_attr("ssh_key_count", keys.len().to_string())
    .with_attr("ssh_keys", key_summaries.join("; "));

    // Emit each SSH public key as a fingerprinted, CORRELATABLE artifact. A
    // public key published on two accounts proves the same person holds the
    // private key — the strongest cross-account link there is. The artifact
    // value is `ssh:<fp>` (a hash of algo+base64, comment dropped), so two
    // accounts sharing a key produce the SAME uid and the engine merges them
    // into one artifact carrying both logins — which AU-048 then links.
    let extra: Vec<Entity> = keys
        .iter()
        .take(10)
        .filter_map(|key| {
            let fp = key.key.as_deref().and_then(ssh_fingerprint)?;
            let mut e = Entity::new(EntityKind::Credential, &fp, 0.85, &ctx.scan_id);
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
        .collect();

    SshResult {
        username_evidence: Some(ev),
        extra,
        has_keys: true,
    }
}

/// Result of [`fetch_events`]: evidence to attach to the username entity,
/// plus any `Email` entities extracted from commit author fields.
pub(super) struct EventsResult {
    /// Evidence to add to `result.entities[0]` (the username entity).
    pub(super) username_evidence: Option<Evidence>,
    /// Extra entities (commit-author email leaks).
    pub(super) extra: Vec<Entity>,
}

pub(super) async fn fetch_events(login: &str, ctx: &ModuleContext) -> EventsResult {
    let url = format!("https://api.github.com/users/{login}/events/public?per_page=30");
    let resp = match ctx
        .http
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return EventsResult {
                username_evidence: None,
                extra: vec![],
            };
        }
    };
    if !resp.status().is_success() {
        return EventsResult {
            username_evidence: None,
            extra: vec![],
        };
    }

    #[derive(serde::Deserialize)]
    struct GhEvent {
        #[serde(default)]
        created_at: Option<String>,
        #[serde(default, rename = "type")]
        event_type: Option<String>,
        #[serde(default)]
        payload: Option<GhPayload>,
    }
    #[derive(serde::Deserialize)]
    struct GhPayload {
        #[serde(default)]
        commits: Vec<GhCommit>,
    }
    #[derive(serde::Deserialize)]
    struct GhCommit {
        #[serde(default)]
        author: Option<GhCommitAuthor>,
    }
    #[derive(serde::Deserialize)]
    struct GhCommitAuthor {
        #[serde(default)]
        email: Option<String>,
    }

    let events: Vec<GhEvent> = match crate::util::http::json_scanned(resp, SRC).await {
        Ok(e) => e,
        Err(_) => {
            return EventsResult {
                username_evidence: None,
                extra: vec![],
            };
        }
    };
    if events.is_empty() {
        return EventsResult {
            username_evidence: None,
            extra: vec![],
        };
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
        .map(|(h, _)| h)
        .unwrap_or(0);

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

    // Commit-author email leak: a user's PUBLIC push events embed the email
    // configured in `git`'s author field for each commit. This is a
    // high-value, operator-published handle→email link — one of the most
    // reliable real-email discoveries in OSINT. GitHub's own privacy
    // `…@users.noreply.github.com` placeholders carry no identity, so they're
    // excluded. Dedup by value; cap to keep a busy account bounded.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let extra: Vec<Entity> = events
        .iter()
        .filter_map(|event| event.payload.as_ref())
        .flat_map(|payload| payload.commits.iter())
        .filter_map(|commit| commit.author.as_ref()?.email.as_deref())
        .filter_map(usable_commit_email)
        .filter(|email| seen.insert(email.clone()))
        .take(10)
        .map(|email| {
            let mut e = Entity::new(EntityKind::Email, &email, 0.82, &ctx.scan_id);
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
        .collect();

    EventsResult {
        username_evidence: Some(ev),
        extra,
    }
}

/// Merge SSH and events results into `result`. Must be called after the
/// username entity (index 0) has been pushed.
pub(super) fn apply_ssh(result: &mut ModuleResult, ssh: SshResult) {
    if let Some(first) = result.entities.first_mut() {
        if ssh.has_keys {
            first.tag("has-ssh-keys");
        }
        if let Some(ev) = ssh.username_evidence {
            first.add_evidence(ev);
        }
    }
    result.extend(ssh.extra);
}

pub(super) fn apply_events(result: &mut ModuleResult, events: EventsResult) {
    if let Some(first) = result.entities.first_mut() {
        if let Some(ev) = events.username_evidence {
            first.add_evidence(ev);
        }
    }
    result.extend(events.extra);
}
