//! npm registry author lookup. Free, no key — the official public registry
//! search API.
//!
//! Endpoint: `GET https://registry.npmjs.org/-/v1/search?text=maintainer:{name}`
//! (documented at <https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md>).
//! Returns the packages a username maintains, each carrying the author/publisher/
//! maintainer records:
//!
//! ```json
//! {"objects":[{"package":{"name":"foo","links":{"homepage":"…"},
//!   "author":{"name":"…","email":"…"},
//!   "maintainers":[{"username":"kylo4kylo","email":"k@example.com"}]}}],"total":1}
//! ```
//!
//! Why it earns a place in the keyless-API set: it both confirms a handle on a
//! code-hosting/registry platform (the `code` provider family, independent of
//! social/forums for cross-service correlation) AND frequently exposes the
//! maintainer's real EMAIL — a high-value, operator-published handle→identity
//! link that npm requires for publishing. Official, keyless, no rate-limit key.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

const SRC: &str = "npm_author";
/// Cap packages scanned per query — bounds work + entity fan-out on a phone.
const MAX_PACKAGES: usize = 25;

pub struct NpmAuthor;

#[derive(Deserialize)]
struct SearchResp {
    #[serde(default)]
    objects: Vec<SearchObject>,
    #[serde(default)]
    total: u64,
}

#[derive(Deserialize)]
struct SearchObject {
    #[serde(default)]
    package: Option<Package>,
}

#[derive(Deserialize)]
struct Package {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    links: Option<Links>,
    #[serde(default)]
    author: Option<Person>,
    #[serde(default)]
    publisher: Option<Person>,
    #[serde(default)]
    maintainers: Vec<Person>,
}

#[derive(Deserialize)]
struct Links {
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Deserialize)]
struct Person {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[async_trait]
impl Module for NpmAuthor {
    fn name(&self) -> &'static str {
        "npm_author"
    }

    fn description(&self) -> &'static str {
        "npm registry author lookup (packages + maintainer email) via the official API"
    }

    fn priority(&self) -> u8 {
        104
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // npm author packages — ATT&CK Code Repositories (T1593.003).
        &["T1593.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Person,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim().to_lowercase();
        // npm usernames are lowercase, url-safe (letters, digits, `-`, `_`, `.`),
        // 1–214 chars. Reject anything else before the round-trip.
        if handle.is_empty()
            || handle.len() > 64
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://registry.npmjs.org/-/v1/search?text=maintainer:{handle}&size={MAX_PACKAGES}"
        );
        let resp: SearchResp = fetch_json(&ctx.http, SRC, &url).await?;
        if resp.objects.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let mut seen_emails: HashSet<String> = HashSet::new();
        let mut seen_urls: HashSet<String> = HashSet::new();
        let mut seen_persons: HashSet<String> = HashSet::new();
        let mut package_names: Vec<String> = Vec::new();

        let push_email =
            |result: &mut ModuleResult, seen: &mut HashSet<String>, raw: &str, pkg: &str| {
                let email = raw.trim().to_lowercase();
                if email.contains('@') && email.len() >= 5 && seen.insert(email.clone()) {
                    let mut e = Entity::new(EntityKind::Email, &email, 0.74, &ctx.scan_id);
                    e.tag("npm");
                    e.tag("public-profile");
                    e.add_evidence(
                        Evidence::new(SRC, format!("npm maintainer email (package {pkg})"))
                            .with_attr("source", "npm_registry")
                            .with_attr("package", pkg),
                    );
                    result.push(e);
                }
            };

        for obj in resp.objects.iter().take(MAX_PACKAGES) {
            let Some(pkg) = obj.package.as_ref() else {
                continue;
            };
            let pkg_name = pkg.name.as_deref().unwrap_or("");
            if !pkg_name.is_empty() {
                package_names.push(pkg_name.to_string());
            }

            // Emails: only from records whose username matches the queried handle
            // (the author/publisher/maintainer that IS the subject), so a
            // co-maintainer's address isn't mis-attributed.
            for person in std::iter::once(pkg.publisher.as_ref())
                .chain(std::iter::once(pkg.author.as_ref()))
                .flatten()
                .chain(pkg.maintainers.iter())
            {
                let is_subject = person
                    .username
                    .as_deref()
                    .is_some_and(|u| u.eq_ignore_ascii_case(&handle));
                if let Some(email) = person.email.as_deref()
                    && (is_subject || person.username.is_none())
                {
                    push_email(&mut result, &mut seen_emails, email, pkg_name);
                }
                // The author's real NAME (npm `author.name`) is a high-value
                // identity link. Emit a Person only for a plausible real name (a
                // multi-word label, not the handle) from a subject-attributed
                // record, deduped case-insensitively.
                if let Some(name) = person.name.as_deref().map(str::trim)
                    && (is_subject || person.username.is_none())
                    && name.contains(' ')
                    && name.len() >= 3
                    && !name.eq_ignore_ascii_case(&handle)
                    && seen_persons.insert(name.to_lowercase())
                {
                    let mut pe = Entity::new(EntityKind::Person, name, 0.66, &ctx.scan_id);
                    pe.tag("npm");
                    pe.tag("public-profile");
                    pe.add_evidence(
                        Evidence::new(SRC, format!("npm author name (package {pkg_name})"))
                            .with_attr("source", "npm_registry")
                            .with_attr("package", pkg_name),
                    );
                    result.push(pe);
                }
                if let Some(u) = person.url.as_deref()
                    && (u.starts_with("http://") || u.starts_with("https://"))
                    && seen_urls.insert(u.to_string())
                {
                    let mut url_e = Entity::new(EntityKind::Url, u, 0.66, &ctx.scan_id);
                    url_e.tag("npm");
                    url_e.add_evidence(
                        Evidence::new(SRC, format!("npm author URL ({pkg_name})"))
                            .with_attr("package", pkg_name),
                    );
                    result.push(url_e);
                }
            }

            // The package homepage/repository — a personal-site / code link.
            if let Some(links) = pkg.links.as_ref() {
                for link in [links.homepage.as_deref(), links.repository.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    if (link.starts_with("http://") || link.starts_with("https://"))
                        && seen_urls.insert(link.to_string())
                    {
                        let mut url_e = Entity::new(EntityKind::Url, link, 0.60, &ctx.scan_id);
                        url_e.tag("npm");
                        url_e.tag("code");
                        url_e.add_evidence(
                            Evidence::new(SRC, format!("npm package link ({pkg_name})"))
                                .with_attr("package", pkg_name),
                        );
                        result.push(url_e);
                    }
                }
            }
        }

        // The confirmed-on-npm username, carrying package coverage as evidence.
        let mut u = Entity::new(EntityKind::Username, &handle, 0.88, &ctx.scan_id);
        u.tag("npm");
        u.tag("code");
        let sample: Vec<&str> = package_names.iter().take(8).map(String::as_str).collect();
        u.add_evidence(
            Evidence::new(SRC, format!("npm maintainer of {} package(s)", resp.total))
                .with_attr("package_count", resp.total.to_string())
                .with_attr("packages", sample.join(", "))
                .with_attr("profile_url", format!("https://www.npmjs.com/~{handle}")),
        );
        result.push(u);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_username() {
        let m = NpmAuthor;
        assert!(m.accepts(&Target::new(TargetKind::Username, "sindresorhus")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn metadata() {
        let m = NpmAuthor;
        assert_eq!(m.name(), "npm_author");
        assert!(m.produces().contains(&EntityKind::Email));
        // The author's real name is now surfaced as a Person identity pivot.
        assert!(m.produces().contains(&EntityKind::Person));
    }

    #[test]
    fn deserializes_search_response() {
        let json = r#"{"objects":[{"package":{"name":"foo",
            "links":{"homepage":"https://foo.dev","repository":"https://github.com/k/foo"},
            "author":{"name":"K","email":"k@example.com","url":"https://k.dev"},
            "maintainers":[{"username":"kylo4kylo","email":"k@example.com"}]}}],"total":3}"#;
        let r: SearchResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.total, 3);
        let p = r.objects[0].package.as_ref().unwrap();
        assert_eq!(p.name.as_deref(), Some("foo"));
        // The author's real name is parsed (the dropped identity field).
        assert_eq!(p.author.as_ref().unwrap().name.as_deref(), Some("K"));
        assert_eq!(p.maintainers[0].username.as_deref(), Some("kylo4kylo"));
        assert_eq!(p.maintainers[0].email.as_deref(), Some("k@example.com"));
        // Empty registry response deserializes to no objects.
        let empty: SearchResp = serde_json::from_str(r#"{"objects":[],"total":0}"#).unwrap();
        assert!(empty.objects.is_empty());
    }

    #[test]
    fn handle_validation() {
        let valid = |s: &str| -> bool {
            let s = s.to_lowercase();
            !s.is_empty()
                && s.len() <= 64
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        assert!(valid("sindresorhus"));
        assert!(valid("kylo4kylo"));
        assert!(valid("my.scope-name_1"));
        assert!(!valid("has space"));
        assert!(!valid("bad/slash"));
    }
}
