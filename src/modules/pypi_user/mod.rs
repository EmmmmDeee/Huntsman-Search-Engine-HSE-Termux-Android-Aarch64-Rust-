//! PyPI (Python Package Index) author lookup. Free, no API key required.
//!
//! Two requests, both free:
//!
//! 1. **XML-RPC `user_packages`** — `POST https://pypi.org/pypi` with
//!    `Content-Type: text/xml`. Returns the list of packages the user owns or
//!    maintains. This confirms the handle exists on PyPI and surfaces the
//!    package roster.
//!
//! 2. **Package JSON** — `GET https://pypi.org/pypi/{package}/json` for the
//!    first owned package (Owner role preferred). Exposes `author_email`
//!    and `home_page` in RFC 5322 `Name <email>` format, which we parse into
//!    a real-name `Person` and `Email` entity.
//!
//! Why it earns a place in the keyless set: Python is the most popular
//! language for data science, machine learning, and scientific computing —
//! a massive population of developers with distinct handles from GitHub.
//! PyPI is the canonical distribution point; the author-email field is an
//! operator-published, verified identity link that PyPI requires for
//! publishing. Two requests, no rate-limit key.

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "pypi_user";
const MAX_PACKAGES: usize = 30;
const XMLRPC_URL: &str = "https://pypi.org/pypi";

pub struct PypiUser;

/// Minimal package JSON info block.
#[derive(Deserialize, Default)]
pub(super) struct PypiPackageInfo {
    #[serde(default)]
    pub(super) author: Option<String>,
    #[serde(default)]
    pub(super) author_email: Option<String>,
    #[serde(default)]
    pub(super) home_page: Option<String>,
    #[serde(default)]
    pub(super) maintainer: Option<String>,
    #[serde(default)]
    pub(super) maintainer_email: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PypiPackageResp {
    pub(super) info: PypiPackageInfo,
}

/// Parse the XML-RPC `user_packages` response into (role, package_name) pairs.
/// The response alternates `<string>role</string><string>package</string>` inside
/// an array. We extract all `<string>` text content in document order and zip
/// them into pairs.
pub(super) fn parse_user_packages(xml: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut values: Vec<String> = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<string>") {
        rest = &rest[start + "<string>".len()..];
        if let Some(end) = rest.find("</string>") {
            values.push(rest[..end].trim().to_string());
            rest = &rest[end + "</string>".len()..];
        }
    }
    let mut iter = values.into_iter();
    while let (Some(role), Some(pkg)) = (iter.next(), iter.next()) {
        if !role.is_empty() && !pkg.is_empty() {
            pairs.push((role, pkg));
        }
    }
    pairs
}

/// Parse RFC 5322 "Name \<email\>" or plain "email" contacts.
/// Handles the PyPI `author_email` field (single or comma-separated list).
/// Names may themselves contain commas (e.g. `"Doe, John" <j@example.com>`),
/// so we scan for angle-bracket pairs rather than splitting on every comma.
/// Returns (Option\<name\>, email) pairs, one per entry.
pub(super) fn parse_rfc5322_contact(raw: &str) -> Vec<(Option<String>, String)> {
    let mut out = Vec::new();
    let mut rest = raw.trim();
    while !rest.is_empty() {
        if let Some(bracket_start) = rest.find('<')
            && let Some(bracket_end) = rest[bracket_start..].find('>')
        {
            let actual_end = bracket_start + bracket_end;
            let name_part = rest[..bracket_start].trim().trim_matches('"').trim();
            let email = rest[bracket_start + 1..actual_end].trim().to_lowercase();
            if email.contains('@') {
                let name = if name_part.is_empty() {
                    None
                } else {
                    Some(name_part.to_string())
                };
                out.push((name, email));
            }
            rest = rest[actual_end + 1..].trim().trim_start_matches(',').trim();
            continue;
        }
        // No angle-bracket found — treat remaining text as plain email(s).
        for part in rest.split(',') {
            let part = part.trim();
            if part.contains('@') {
                out.push((None, part.to_lowercase()));
            }
        }
        break;
    }
    out
}

/// Build entities from confirmed packages + optional package info.
pub(super) fn build_entities(
    handle: &str,
    packages: &[(String, String)],
    info: Option<&PypiPackageInfo>,
    scan_id: &str,
) -> Vec<Entity> {
    let mut result = ModuleResult::new();
    let mut seen_emails: HashSet<String> = HashSet::new();

    let profile_url = format!("https://pypi.org/user/{handle}/");
    let ev_base = || {
        Evidence::new(SRC, format!("PyPI profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed-on-PyPI username.
    let mut u = Entity::new(EntityKind::Username, handle, 0.85, scan_id);
    u.tag("pypi");
    u.tag("public-profile");
    let pkg_names: Vec<&str> = packages
        .iter()
        .take(MAX_PACKAGES)
        .map(|(_, p)| p.as_str())
        .collect();
    let coverage = if pkg_names.is_empty() {
        ev_base()
    } else {
        let sample = pkg_names
            .iter()
            .take(5)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        let summary = if pkg_names.len() > 5 {
            format!("{sample}, … ({} packages)", pkg_names.len())
        } else {
            sample
        };
        ev_base().with_attr("packages", &summary)
    };
    u.add_evidence(coverage);
    result.push(u);

    // Profile URL.
    let mut pu = Entity::new(EntityKind::Url, &profile_url, 0.78, scan_id);
    pu.tag("pypi");
    pu.add_evidence(ev_base());
    result.push(pu);

    // Enrich from the first owned package's JSON info.
    if let Some(info) = info {
        // author_email and maintainer_email carry RFC 5322 Name <email> entries.
        for raw in [
            info.author_email.as_deref(),
            info.maintainer_email.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            for (name_opt, email) in parse_rfc5322_contact(raw) {
                if seen_emails.insert(email.clone()) {
                    let mut em = Entity::new(EntityKind::Email, &email, 0.72, scan_id);
                    em.tag("pypi");
                    em.tag("public-profile");
                    em.add_evidence(ev_base().with_attr("source_field", "author_email"));
                    result.push(em);

                    // Real name from the "Name" part.
                    if let Some(name) = name_opt
                        && let Some(mut p) = profile_kit::person_from_name(&name, 0.62, scan_id)
                    {
                        p.tag("pypi");
                        p.tag("derived");
                        p.add_evidence(ev_base().with_attr("source_field", "author_email"));
                        result.push(p);
                    }
                }
            }
        }

        // author / maintainer plain-text name fields (older packages).
        for raw_name in [info.author.as_deref(), info.maintainer.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(mut p) = profile_kit::person_from_name(raw_name, 0.55, scan_id) {
                p.tag("pypi");
                p.tag("derived");
                p.add_evidence(ev_base().with_attr("source_field", "author"));
                // Only push if no duplicate Person was already added from author_email.
                if result
                    .entities
                    .iter()
                    .all(|e| e.kind != EntityKind::Person || e.value != p.value)
                {
                    result.push(p);
                }
            }
        }

        // Home page → URL + Domain.
        if let Some(hp) = info.home_page.as_deref() {
            for mut e in profile_kit::website_url_and_domain(hp, 0.65, 0.55, scan_id) {
                e.tag("pypi");
                match e.kind {
                    EntityKind::Domain => e.tag("derived"),
                    _ => e.tag("personal-site"),
                }
                e.add_evidence(ev_base().with_attr("source_field", "home_page"));
                result.push(e);
            }
        }
    }

    result.entities
}

#[async_trait]
impl Module for PypiUser {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "PyPI author lookup: owned packages, email, real name, homepage (Python ecosystem, free)"
    }

    fn priority(&self) -> u8 {
        56
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Package-registry profile — T1593.003; name/email from author record — T1589.002.
        &["T1589.002", "T1593.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // PyPI usernames: 1–50 chars, alphanumeric + hyphen + underscore + dot.
        if handle.is_empty()
            || handle.len() > 50
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Ok(ModuleResult::new());
        }

        // Step 1: XML-RPC user_packages to confirm handle and get package list.
        let xmlrpc_body = format!(
            "<?xml version=\"1.0\"?><methodCall><methodName>user_packages\
             </methodName><params><param><value><string>{}</string></value>\
             </param></params></methodCall>",
            handle
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        );

        let xml_resp = ctx
            .http
            .post(XMLRPC_URL)
            .header("Content-Type", "text/xml")
            .body(xmlrpc_body)
            .send()
            .await?;

        if !xml_resp.status().is_success() {
            return Ok(ModuleResult::new());
        }
        let xml_text = xml_resp.text().await?;
        let packages = parse_user_packages(&xml_text);
        if packages.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Step 2: Fetch the first owned package's JSON for name/email enrichment.
        let first_pkg = packages
            .iter()
            .find(|(role, _)| role.eq_ignore_ascii_case("owner"))
            .or_else(|| packages.first())
            .map(|(_, pkg)| pkg.as_str());

        let info: Option<PypiPackageInfo> = if let Some(pkg) = first_pkg {
            let pkg_url = format!("https://pypi.org/pypi/{}/json", urlencode(pkg));
            fetch_json_or_404::<PypiPackageResp>(&ctx.http, SRC, &pkg_url)
                .await?
                .map(|r| r.info)
        } else {
            None
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(handle, &packages, info.as_ref(), &ctx.scan_id);
        Ok(result)
    }
}
