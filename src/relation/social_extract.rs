use std::collections::HashMap;

use crate::canonical::{canonical_handle, canonical_url};
use crate::entity::{Entity, EntityKind};

use super::types::{Relation, RelationKind};

fn endpoint_confidence(left: &Entity, right: &Entity) -> f64 {
    left.confidence.min(right.confidence)
}

fn extract_username_from_profile_url(url: &str) -> Option<String> {
    let canonical = canonical_url(url)?;
    let (_, rest) = canonical.split_once("://")?;
    let (authority, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority.trim_start_matches("www.");
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let candidate = match host {
        "github.com" | "twitter.com" | "x.com" => segments.first().copied(),
        "tiktok.com" => segments
            .first()
            .copied()
            .map(|segment| segment.trim_start_matches('@')),
        "reddit.com" => (segments.first() == Some(&"user")).then_some(*segments.get(1)?),
        "bsky.app" => {
            if segments.first() == Some(&"profile") {
                Some(segments.get(1)?.trim_end_matches(".bsky.social"))
            } else {
                None
            }
        }
        "news.ycombinator.com" => query.split('&').find_map(|part| {
            part.split_once('=')
                .filter(|(key, _)| *key == "id")
                .map(|(_, value)| value)
        }),
        _ => None,
    }?;
    canonical_handle(candidate)
}

#[must_use]
pub fn derive_profile_links(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let usernames = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Username)
        .filter_map(|entity| canonical_handle(&entity.value).map(|key| (key, entity)))
        .collect::<HashMap<_, _>>();
    let mut out = Vec::new();
    for url in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Url)
    {
        let Some(handle) = extract_username_from_profile_url(&url.value) else {
            continue;
        };
        if let Some(username) = usernames.get(handle.as_str()) {
            out.push(Relation::new(
                &username.uid,
                &url.uid,
                RelationKind::SameIdentity,
                endpoint_confidence(username, url),
                scan_id,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_supported_profile_shapes() {
        assert_eq!(
            extract_username_from_profile_url("https://github.com/rhino-ryno23"),
            Some("rhinoryno23".into())
        );
        assert_eq!(
            extract_username_from_profile_url("https://www.tiktok.com/@dancequeen"),
            Some("dancequeen".into())
        );
        assert_eq!(
            extract_username_from_profile_url(
                "https://www.reddit.com/user/rhino-ryno23/about.json"
            ),
            Some("rhinoryno23".into())
        );
        assert_eq!(
            extract_username_from_profile_url("https://bsky.app/profile/haigen.bsky.social"),
            Some("haigen".into())
        );
        assert_eq!(
            extract_username_from_profile_url("https://news.ycombinator.com/user?id=pg"),
            Some("pg".into())
        );
        assert_eq!(
            extract_username_from_profile_url("https://unknown.example.com/x"),
            None
        );
    }
}
