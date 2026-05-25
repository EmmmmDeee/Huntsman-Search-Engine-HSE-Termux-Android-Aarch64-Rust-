use std::collections::HashMap;

use async_trait::async_trait;
use md5::{Digest, Md5};
use serde::Deserialize;
use serde_json::Value;

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
    #[serde(rename = "aboutMe")]
    about_me: Option<String>,
    #[serde(default)]
    photos: Option<Vec<PhotoEntry>>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
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

#[derive(Deserialize)]
struct PhotoEntry {
    value: Option<String>,
}

#[async_trait]
impl Module for Gravatar {
    fn name(&self) -> &'static str {
        "gravatar"
    }

    fn description(&self) -> &'static str {
        "Gravatar profile lookup by email hash"
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

        // Gravatar placeholders return 200 + non-JSON; can't use fetch_json_or_404.
        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::module("gravatar", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
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
            Err(_) => return Ok(ModuleResult::new()),
        };

        let Some(entry) = data.entry.into_iter().next() else {
            return Ok(ModuleResult::new());
        };

        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag("gravatar");
        let urls_joined: Option<String> = {
            let mut iter = entry.urls.iter().filter_map(|u| {
                let v = u.value.as_deref()?;
                let t = u.title.as_deref().unwrap_or("link");
                Some(format!("{t}: {v}"))
            });
            iter.next().map(|first| {
                let mut joined = first;
                for item in iter {
                    joined.push_str(" | ");
                    joined.push_str(&item);
                }
                joined
            })
        };
        let mut ev = Evidence::new("gravatar", format!("Gravatar profile for {normalised}"))
            .with_attr("md5", &hash)
            .with_attr("profile_url", format!("https://www.gravatar.com/{hash}"))
            .with_opt_attr("display_name", entry.display_name.as_deref())
            .with_opt_attr("preferred_username", entry.preferred_username.as_deref())
            .with_opt_attr("name", entry.name.and_then(|n| n.formatted))
            .with_opt_attr("location", entry.location.as_deref())
            .with_opt_attr("bio", entry.about_me.as_deref())
            .with_opt_attr(
                "avatar_url",
                entry
                    .photos
                    .as_ref()
                    .and_then(|p| p.first())
                    .and_then(|p| p.value.clone()),
            )
            .with_opt_attr("urls", urls_joined);
        for (k, v) in &entry.extra {
            let val_str = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            ev = ev.with_attr(format!("gravatar_{k}"), val_str);
        }
        entity.add_evidence(ev);

        // Holehe email service enumeration via OathNet
        let key = crate::util::oathnet::resolve_key(ctx.key_opt(crate::util::oathnet::KEY_ENV));
        if !ctx.cancel.is_cancelled()
            && let Ok(holehe) = crate::util::oathnet::osint(
                key,
                crate::util::oathnet::paths::HOLEHE,
                "email",
                &target.value,
            )
            .await
            && let Some(domains) = holehe.get("domains").and_then(|v| v.as_array())
            && !domains.is_empty()
        {
            let domains_str: Vec<&str> = domains.iter().filter_map(|v| v.as_str()).collect();
            entity.tag("holehe");
            entity.tag_if(domains_str.len() >= 5, crate::core::tags::HIGH_EXPOSURE);
            entity.add_evidence(
                crate::core::entity::Evidence::new(
                    "gravatar:oathnet",
                    format!(
                        "Holehe: email registered on {} service(s)",
                        domains_str.len()
                    ),
                )
                .with_attr("holehe_count", domains_str.len().to_string())
                .with_attr("holehe_domains", domains_str.join(", ")),
            );
        }

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
