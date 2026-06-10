//! crates.io user lookup. Free, no key — the official public registry API.
//!
//! Endpoint: `GET https://crates.io/api/v1/users/{login}`
//! (documented at <https://crates.io/data-access>; a descriptive User-Agent is
//! required by their crawler policy, which the shared client supplies). Returns
//! the registry account:
//!
//! ```json
//! {"user":{"id":1,"login":"alice","name":"Alice Smith",
//!          "avatar":"https://avatars.githubusercontent.com/u/1",
//!          "url":"https://github.com/alice"}}
//! ```
//!
//! Why it earns a place in the keyless-API set: it confirms the handle on a
//! code-registry platform (the `code` family), exposes the maintainer's REAL
//! NAME (a handle→identity link feeding AU-046), and — because crates.io
//! authenticates via GitHub — its `url` field ties the handle to the owner's
//! GitHub profile, a cross-platform confirmation. Official, keyless, exact-match.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "crates_io";

pub struct CratesIo;

#[derive(Deserialize)]
struct UserResp {
    #[serde(default)]
    user: Option<CrateUser>,
}

#[derive(Deserialize)]
struct CrateUser {
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[async_trait]
impl Module for CratesIo {
    fn name(&self) -> &'static str {
        "crates_io"
    }

    fn description(&self) -> &'static str {
        "crates.io registry user lookup (real name + linked GitHub) via the official API"
    }

    fn priority(&self) -> u8 {
        103
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // crates.io author packages — ATT&CK Code Repositories (T1593.003).
        &["T1593.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Person, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // crates.io logins mirror GitHub logins: alphanumeric + hyphen, ≤39 chars.
        if handle.is_empty()
            || handle.len() > 39
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://crates.io/api/v1/users/{handle}");
        let resp: Option<UserResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let Some(user) = resp.and_then(|r| r.user) else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        // The confirmed-on-crates.io username.
        let mut u = Entity::new(EntityKind::Username, &user.login, 0.88, &ctx.scan_id);
        u.tag("crates-io");
        u.tag("code");
        let mut ev = Evidence::new(SRC, format!("crates.io registry account '{}'", user.login))
            .with_attr(
                "profile_url",
                format!("https://crates.io/users/{}", user.login),
            );
        if let Some(n) = user.name.as_deref() {
            ev = ev.with_attr("name", n);
        }
        u.add_evidence(ev);
        result.push(u);

        // Real name → Person (handle→identity).
        if let Some(name) = user.name.as_deref()
            && name.split_whitespace().count() >= 2
            && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, name)
        {
            let mut p = Entity::new(EntityKind::Person, name.trim(), 0.70, &ctx.scan_id);
            p.tag("crates-io");
            p.tag("derived");
            p.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Real name from crates.io account '{}'", user.login),
                )
                .with_attr("crates_login", &user.login),
            );
            result.push(p);
        }

        // The linked profile URL (crates.io auths via GitHub, so this is usually
        // the owner's GitHub profile — a cross-platform confirmation).
        if let Some(link) = user.url.as_deref()
            && (link.starts_with("http://") || link.starts_with("https://"))
        {
            let mut url_e = Entity::new(EntityKind::Url, link, 0.74, &ctx.scan_id);
            url_e.tag("crates-io");
            url_e.tag("linked-profile");
            url_e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Linked profile of crates.io user '{}'", user.login),
                )
                .with_attr("source", "crates_io_profile"),
            );
            result.push(url_e);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_username() {
        let m = CratesIo;
        assert!(m.accepts(&Target::new(TargetKind::Username, "dtolnay")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn metadata() {
        let m = CratesIo;
        assert_eq!(m.name(), "crates_io");
        assert!(m.produces().contains(&EntityKind::Person));
    }

    #[test]
    fn deserializes_user_and_missing() {
        let json = r#"{"user":{"id":1,"login":"alice","name":"Alice Smith",
            "avatar":"https://x/a","url":"https://github.com/alice"}}"#;
        let r: UserResp = serde_json::from_str(json).unwrap();
        let u = r.user.unwrap();
        assert_eq!(u.login, "alice");
        assert_eq!(u.name.as_deref(), Some("Alice Smith"));
        assert_eq!(u.url.as_deref(), Some("https://github.com/alice"));
        // A no-user body deserializes to None.
        let empty: UserResp = serde_json::from_str(r#"{}"#).unwrap();
        assert!(empty.user.is_none());
    }

    #[test]
    fn handle_validation() {
        let valid = |s: &str| -> bool {
            !s.is_empty()
                && s.len() <= 39
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        assert!(valid("dtolnay"));
        assert!(valid("kylo4kylo"));
        assert!(!valid("has space"));
        assert!(!valid("under_score"));
    }
}
