//! Gravatar profile check. Free, no key, no rate-limit billing.
//!
//! Gravatar identifies users by the MD5 hash of their lowercased,
//! trimmed email address. A request to
//! `https://www.gravatar.com/{hash}.json` returns the public profile
//! if the user signed up, 404 otherwise.
//!
//! When found, emits the Email entity tagged `gravatar` with profile
//! attributes (display name, location, urls). When not found, no
//! entity is emitted (a 404 isn't a finding).

use async_trait::async_trait;
use md5::{Digest, Md5};
use serde::Deserialize;
// `md-5` is the maintained successor crate; the import path is `md5`.

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

pub struct Gravatar;

#[derive(Deserialize)]
struct ProfileResp {
    entry: Vec<ProfileEntry>,
}

#[derive(Deserialize)]
struct ProfileEntry {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "preferredUsername")]
    preferred_username: Option<String>,
    #[serde(default)]
    name: Option<NameField>,
    #[serde(default)]
    urls: Vec<UrlEntry>,
    #[serde(rename = "currentLocation")]
    location: Option<String>,
}

#[derive(Deserialize)]
struct NameField {
    formatted: Option<String>,
}

#[derive(Deserialize)]
struct UrlEntry {
    value: Option<String>,
    title: Option<String>,
}

#[async_trait]
impl Module for Gravatar {
    fn name(&self) -> &'static str {
        "gravatar"
    }

    fn priority(&self) -> u8 {
        85
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let normalised = target.value.trim().to_lowercase();
        if !normalised.contains('@') {
            return Ok(ModuleResult::new());
        }

        let mut hasher = Md5::new();
        hasher.update(normalised.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let url = format!("https://www.gravatar.com/{hash}.json");

        // Intentionally manual rather than using `util::http::fetch_json_or_404`:
        // Gravatar's placeholder profiles return 200 + non-JSON body, and
        // the helper would surface that as a `module_error`. The
        // silent-treat-as-empty behaviour below is the documented contract.
        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::module("gravatar", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            // No Gravatar profile — not a finding.
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "gravatar",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let data: ProfileResp = match resp.json().await {
            Ok(d) => d,
            // Placeholder profile → no findings (not a module error).
            Err(_) => return Ok(ModuleResult::new()),
        };

        let Some(entry) = data.entry.into_iter().next() else {
            return Ok(ModuleResult::new());
        };

        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag("gravatar");
        let mut ev = Evidence::new("gravatar", format!("Gravatar profile for {normalised}"))
            .with_attr("md5", &hash)
            .with_attr("profile_url", format!("https://www.gravatar.com/{hash}"));
        if let Some(d) = entry.display_name.as_deref() {
            ev = ev.with_attr("display_name", d);
        }
        if let Some(u) = entry.preferred_username.as_deref() {
            ev = ev.with_attr("preferred_username", u);
        }
        if let Some(n) = entry.name.and_then(|n| n.formatted) {
            ev = ev.with_attr("name", n);
        }
        if let Some(loc) = entry.location.as_deref() {
            ev = ev.with_attr("location", loc);
        }
        if !entry.urls.is_empty() {
            let mut urls_iter = entry.urls.iter().filter_map(|u| {
                let v = u.value.as_deref()?;
                let t = u.title.as_deref().unwrap_or("link");
                Some(format!("{t}: {v}"))
            });
            if let Some(first) = urls_iter.next() {
                let mut joined = first;
                for item in urls_iter {
                    joined.push_str(" | ");
                    joined.push_str(&item);
                }
                ev = ev.with_attr("urls", joined);
            }
        }
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_email() {
        let m = Gravatar;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
    }
}
