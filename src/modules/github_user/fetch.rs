use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::{ModuleContext, ModuleResult},
};

use super::helpers::{ssh_fingerprint, top_event_types, usable_commit_email};

const SRC: &str = "github_user";

pub(super) async fn fetch_ssh_keys(login: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
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
        Err(_) => return,
    };
    if !resp.status().is_success() {
        return;
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

    // Emit each SSH public key as a fingerprinted, CORRELATABLE artifact. A
    // public key published on two accounts proves the same person holds the
    // private key — the strongest cross-account link there is. The artifact
    // value is `ssh:<fp>` (a hash of algo+base64, comment dropped), so two
    // accounts sharing a key produce the SAME uid and the engine merges them
    // into one artifact carrying both logins — which AU-048 then links.
    result.extend(keys.iter().take(10).filter_map(|key| {
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
    }));
}

pub(super) async fn fetch_orgs(
    http: &reqwest::Client,
    username: &str,
    token: Option<&str>,
) -> Vec<String> {
    let url = format!(
        "https://api.github.com/users/{}/orgs",
        crate::util::http::urlencode(username)
    );
    let mut req = http
        .get(&url)
        .header("User-Agent", crate::util::http::UA_OSINT)
        .header("Accept", "application/vnd.github+json");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let Ok(resp) = req.send().await else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = resp.text().await else {
        return Vec::new();
    };
    // Extract org login names.
    crate::util::json::scan_string_field(&body, "login")
}

pub(super) async fn fetch_gists(
    http: &reqwest::Client,
    username: &str,
    token: Option<&str>,
) -> Vec<String> {
    let url = format!(
        "https://api.github.com/users/{}/gists?per_page=30",
        crate::util::http::urlencode(username)
    );
    let mut req = http
        .get(&url)
        .header("User-Agent", crate::util::http::UA_OSINT)
        .header("Accept", "application/vnd.github+json");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let Ok(resp) = req.send().await else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = resp.text().await else {
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

pub(super) async fn fetch_events(login: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
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
        Err(_) => return,
    };
    if !resp.status().is_success() {
        return;
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

    // Commit-author email leak: a user's PUBLIC push events embed the email
    // configured in `git`'s author field for each commit. This is a
    // high-value, operator-published handle→email link — one of the most
    // reliable real-email discoveries in OSINT. GitHub's own privacy
    // `…@users.noreply.github.com` placeholders carry no identity, so they're
    // excluded. Dedup by value; cap to keep a busy account bounded.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    result.extend(
        events
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
            }),
    );
}
