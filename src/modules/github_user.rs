//! GitHub user profile lookup. Free, no key (uses the public REST API).
//!
//! Endpoint: `GET https://api.github.com/users/{login}`.
//!
//! Public profile data: real name (if exposed), public email (if
//! exposed and explicitly published), company, location, blog, bio,
//! public-repo / follower / following counts, account creation date.
//!
//! Emits one Email entity *only when* the user has explicitly published
//! one on their profile (GitHub's privacy default is to hide it). When
//! present, that link is high-value — it confirms an
//! account-to-real-email mapping.
//!
//! Rate-limited at 60 req/hour for unauthenticated use; on 403/429 we
//! surface a module_error so the user sees the cap was hit.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const SRC: &str = "github_user";

pub struct GithubUser;

#[derive(Deserialize)]
struct GhUser {
    login: String,
    id: u64,
    name: Option<String>,
    email: Option<String>,
    blog: Option<String>,
    company: Option<String>,
    location: Option<String>,
    bio: Option<String>,
    twitter_username: Option<String>,
    public_repos: Option<u64>,
    public_gists: Option<u64>,
    followers: Option<u64>,
    following: Option<u64>,
    created_at: Option<String>,
    html_url: Option<String>,
}

#[async_trait]
impl Module for GithubUser {
    fn name(&self) -> &'static str {
        "github_user"
    }

    fn description(&self) -> &'static str {
        "GitHub profile, repos, and social metadata lookup"
    }

    fn priority(&self) -> u8 {
        107
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Organisation,
            EntityKind::Address,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let login = target.value.trim();
        // GitHub login rules: alphanumeric and hyphens, max 39 chars,
        // not starting/ending with a hyphen. Saves a wasted HTTP round-
        // trip for non-conforming inputs.
        if login.is_empty()
            || login.len() > 39
            || !login.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || login.starts_with('-')
            || login.ends_with('-')
        {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://api.github.com/users/{login}");
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "github_user",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let user: GhUser = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let mut result = ModuleResult::new();

        // Username entity with GitHub profile metadata.
        let mut u_entity = Entity::new(EntityKind::Username, &user.login, 0.95, &ctx.scan_id);
        u_entity.tag("github");
        let mut ev = Evidence::new(SRC, format!("GitHub profile @{}", user.login))
            .with_attr("github_id", user.id.to_string())
            .with_attr(
                "profile_url",
                user.html_url.as_deref().map_or_else(
                    || format!("https://github.com/{}", user.login),
                    String::from,
                ),
            );
        if let Some(n) = user.name.as_deref() {
            ev = ev.with_attr("name", n);
        }
        if let Some(c) = user.company.as_deref() {
            ev = ev.with_attr("company", c);
        }
        if let Some(l) = user.location.as_deref() {
            ev = ev.with_attr("location", l);
            if !l.trim().is_empty() {
                u_entity.tag("has-location");
            }
        }
        if let Some(b) = user.blog.as_deref()
            && !b.is_empty()
        {
            ev = ev.with_attr("blog", b);
        }
        if let Some(b) = user.bio.as_deref()
            && !b.is_empty()
        {
            ev = ev.with_attr("bio", b);
        }
        if let Some(c) = user.created_at.as_deref() {
            ev = ev.with_attr("created_at", c);
        }
        if let Some(n) = user.public_repos {
            ev = ev.with_attr("public_repos", n.to_string());
        }
        if let Some(n) = user.public_gists {
            ev = ev.with_attr("public_gists", n.to_string());
        }
        if let Some(n) = user.followers {
            ev = ev.with_attr("followers", n.to_string());
        }
        if let Some(n) = user.following {
            ev = ev.with_attr("following", n.to_string());
        }
        if let Some(ref tw) = user.twitter_username
            && !tw.is_empty()
        {
            ev = ev.with_attr("twitter", tw);
            u_entity.tag(format!("twitter:{tw}"));
        }
        u_entity.add_evidence(ev);
        result.push(u_entity);

        // Real name → Person entity, when present.
        if let Some(name) = user.name.as_deref()
            && !name.trim().is_empty()
        {
            let mut p = Entity::new(EntityKind::Person, name.trim(), 0.75, &ctx.scan_id);
            p.tag("derived");
            p.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Real name from GitHub profile @{}", user.login),
                )
                .with_attr("source", "github_profile")
                .with_attr("github_login", &user.login),
            );
            result.push(p);
        }

        // Public email → Email entity, when explicitly published.
        if let Some(email) = user.email.as_deref()
            && email.contains('@')
        {
            let mut e = Entity::new(EntityKind::Email, email, 0.90, &ctx.scan_id);
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Email published on GitHub profile @{}", user.login),
                )
                .with_attr("github_login", &user.login)
                .with_attr("profile_url", format!("https://github.com/{}", user.login)),
            );
            result.push(e);
        }

        // Company → Organisation entity, when present.
        if let Some(company) = user.company.as_deref() {
            let company = company.trim().trim_start_matches('@');
            if company.len() >= 2 {
                let mut o = Entity::new(EntityKind::Organisation, company, 0.65, &ctx.scan_id);
                o.tag("github");
                o.tag("derived");
                o.add_evidence(
                    Evidence::new(SRC, format!("Company from GitHub profile @{}", user.login))
                        .with_attr("github_login", &user.login),
                );
                result.push(o);
            }
        }

        // Location → Address entity, when present.
        if let Some(location) = user.location.as_deref() {
            let location = location.trim();
            if location.len() >= 3 {
                let mut a = Entity::new(EntityKind::Address, location, 0.55, &ctx.scan_id);
                a.tag("github");
                a.tag("geoint");
                a.add_evidence(
                    Evidence::new(SRC, format!("Location from GitHub profile @{}", user.login))
                        .with_attr("github_login", &user.login),
                );
                result.push(a);
            }
        }

        // Blog URL → Url entity, when present.
        if let Some(blog) = user.blog.as_deref()
            && !blog.trim().is_empty()
        {
            let blog = blog.trim();
            if blog.starts_with("http://") || blog.starts_with("https://") {
                let mut u = Entity::new(EntityKind::Url, blog, 0.80, &ctx.scan_id);
                u.tag("personal-site");
                u.add_evidence(
                    Evidence::new(
                        "github_user",
                        format!("Personal site linked from GitHub profile @{}", user.login),
                    )
                    .with_attr("github_login", &user.login),
                );
                result.push(u);

                if let Ok(parsed) = url::Url::parse(blog)
                    && let Some(host) = parsed.host_str()
                {
                    let domain = host.to_lowercase();
                    if domain.contains('.') && domain != "github.com" && domain != "github.io" {
                        let mut d = Entity::new(EntityKind::Domain, &domain, 0.72, &ctx.scan_id);
                        d.tag("derived");
                        d.tag("personal-site");
                        d.add_evidence(
                            Evidence::new(SRC, format!("Blog domain from @{}", user.login))
                                .with_attr("blog_url", blog)
                                .with_attr("github_login", &user.login),
                        );
                        result.push(d);
                    }
                }
            }
        }

        // SSH public keys → evidence on the username entity.
        self.fetch_ssh_keys(login, ctx, &mut result).await;

        // Public events → extract active working hours.
        self.fetch_events(login, ctx, &mut result).await;

        Ok(result)
    }

    fn max_timeout_ms(&self) -> u64 {
        5_000
    }
}

impl GithubUser {
    async fn fetch_ssh_keys(&self, login: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
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
    }

    async fn fetch_events(&self, login: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
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
        let mut event_types: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
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
        for event in &events {
            let Some(payload) = event.payload.as_ref() else {
                continue;
            };
            for commit in &payload.commits {
                let Some(raw) = commit.author.as_ref().and_then(|a| a.email.as_deref()) else {
                    continue;
                };
                let Some(email) = usable_commit_email(raw) else {
                    continue;
                };
                if !seen.insert(email.clone()) {
                    continue;
                }
                if seen.len() > 10 {
                    break;
                }
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
                result.push(e);
            }
        }
    }
}

/// Normalise and vet a commit-author email for emission: trimmed + lowercased,
/// must be a plausible address, and must NOT be one of GitHub's privacy
/// placeholders (`…@users.noreply.github.com`, any `noreply`/`*.github.com`
/// address) which carry no real identity. Returns the clean address, or `None`
/// to drop it.
fn usable_commit_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    if email.len() < 5
        || !email.contains('@')
        || email.contains("noreply")
        || email.ends_with("@github.com")
        || email.ends_with(".github.com")
    {
        return None;
    }
    Some(email)
}

/// Top-`n` event types formatted as `type=count`, ranked by count descending
/// then type-name ascending. The name tiebreak makes the ranking deterministic
/// even though `event_types` comes from a `HashMap` (randomised iteration
/// order) — so the `top_event_types` finding is byte-reproducible.
fn top_event_types(event_types: std::collections::HashMap<String, u32>, n: usize) -> Vec<String> {
    let mut sorted: Vec<(String, u32)> = event_types.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sorted
        .into_iter()
        .take(n)
        .map(|(t, c)| format!("{t}={c}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_event_types_is_deterministic_on_ties() {
        // Ties (PushEvent, IssuesEvent, ForkEvent all at 3) must resolve by name
        // — not by the source HashMap's randomised order — so the finding is
        // reproducible. Build the map in a few different insertion orders.
        let mk = || {
            let mut m = std::collections::HashMap::new();
            for (k, v) in [
                ("PushEvent", 3),
                ("IssuesEvent", 3),
                ("ForkEvent", 3),
                ("WatchEvent", 1),
            ] {
                m.insert(k.to_string(), v);
            }
            m
        };
        let expected = vec![
            "ForkEvent=3".to_string(),
            "IssuesEvent=3".to_string(),
            "PushEvent=3".to_string(),
        ];
        // Several independently-seeded HashMaps must all yield the same top-3.
        for _ in 0..8 {
            assert_eq!(top_event_types(mk(), 3), expected);
        }
        assert_eq!(
            top_event_types(std::collections::HashMap::new(), 3),
            Vec::<String>::new()
        );
    }

    #[test]
    fn accepts_only_username() {
        let m = GithubUser;
        assert!(m.accepts(&Target::new(TargetKind::Username, "octocat")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "github.com")));
    }

    #[test]
    fn deserialize_full_profile() {
        let json = r#"{
            "login":"alice","id":12345,"name":"Alice Smith",
            "email":"alice@example.com","blog":"https://alice.dev",
            "company":"@acme-corp","location":"Brisbane, Australia",
            "bio":"Rust dev","twitter_username":"alicedev",
            "public_repos":42,"public_gists":5,"followers":100,
            "following":50,"created_at":"2020-01-15T00:00:00Z",
            "html_url":"https://github.com/alice"
        }"#;
        let u: GhUser = serde_json::from_str(json).unwrap();
        assert_eq!(u.login, "alice");
        assert_eq!(u.id, 12345);
        assert_eq!(u.name.as_deref(), Some("Alice Smith"));
        assert_eq!(u.email.as_deref(), Some("alice@example.com"));
        assert_eq!(u.company.as_deref(), Some("@acme-corp"));
        assert_eq!(u.location.as_deref(), Some("Brisbane, Australia"));
        assert_eq!(u.twitter_username.as_deref(), Some("alicedev"));
        assert_eq!(u.public_repos, Some(42));
        assert_eq!(u.followers, Some(100));
    }

    #[test]
    fn deserialize_minimal_profile() {
        let json = r#"{"login":"bob","id":999}"#;
        let u: GhUser = serde_json::from_str(json).unwrap();
        assert_eq!(u.login, "bob");
        assert!(u.name.is_none());
        assert!(u.email.is_none());
        assert!(u.location.is_none());
        assert!(u.public_repos.is_none());
    }

    #[test]
    fn rejects_invalid_logins() {
        let long = "a".repeat(40);
        let cases = ["", "-start", "end-", "has space", &long, "user@name"];
        for case in cases {
            assert!(
                GithubUser.accepts(&Target::new(TargetKind::Username, case)),
                "accepts() should pass validation to process()"
            );
        }
    }

    #[test]
    fn login_validation_logic() {
        let valid = |s: &str| -> bool {
            !s.is_empty()
                && s.len() <= 39
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !s.starts_with('-')
                && !s.ends_with('-')
        };
        assert!(valid("octocat"));
        assert!(valid("alice-bob"));
        assert!(!valid(""));
        assert!(!valid("-start"));
        assert!(!valid("end-"));
        assert!(!valid("has space"));
        assert!(!valid(&"a".repeat(40)));
    }

    #[test]
    fn company_strips_at_prefix() {
        let company = "@acme-corp";
        let cleaned = company.trim().trim_start_matches('@');
        assert_eq!(cleaned, "acme-corp");
    }

    #[test]
    fn blog_url_domain_extraction() {
        let blog = "https://alice.dev/about";
        let parsed = url::Url::parse(blog).unwrap();
        let host = parsed.host_str().unwrap().to_lowercase();
        assert_eq!(host, "alice.dev");
        assert!(host.contains('.'));
        assert_ne!(host, "github.com");
    }

    #[test]
    fn blog_non_http_ignored() {
        let blog = "alice.dev";
        assert!(!blog.starts_with("http://") && !blog.starts_with("https://"));
    }

    #[test]
    fn commit_email_filter_keeps_real_drops_github_placeholders() {
        // Real personal addresses are kept (normalised); GitHub's privacy
        // placeholders and noreply forms are dropped — they carry no identity.
        assert_eq!(
            usable_commit_email("  Alice@Example.com "),
            Some("alice@example.com".to_string())
        );
        assert_eq!(
            usable_commit_email("dev@personal.dev"),
            Some("dev@personal.dev".to_string())
        );
        assert_eq!(
            usable_commit_email("12345+alice@users.noreply.github.com"),
            None
        );
        assert_eq!(usable_commit_email("noreply@github.com"), None);
        assert_eq!(usable_commit_email("actions@github.com"), None);
        assert_eq!(usable_commit_email("not-an-email"), None);
        assert_eq!(usable_commit_email("a@b"), None); // too short
    }

    #[test]
    fn module_metadata() {
        let m = GithubUser;
        assert_eq!(m.name(), "github_user");
        assert_eq!(m.priority(), 107);
        assert_eq!(m.max_timeout_ms(), 5_000);
        assert!(!m.description().is_empty());
    }
}
