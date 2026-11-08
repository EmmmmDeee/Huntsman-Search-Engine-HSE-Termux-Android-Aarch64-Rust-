use std::collections::HashMap;

use crate::canonical::{canonical_handle, canonical_url};
use crate::entity::{Entity, EntityKind, Evidence};

use super::types::{Relation, RelationKind, endpoint_confidence};

/// A profile URL names a platform-specific account, not necessarily a person.
#[derive(Debug, PartialEq, Eq)]
enum ProfileHandle {
    /// Preserve existing sources' canonical handle matching.
    Existing(String),
    /// Instagram separators distinguish different accounts; retain exact spelling.
    Instagram(String),
}

fn extract_username_from_profile_url(url: &str) -> Option<ProfileHandle> {
    let canonical = canonical_url(url)?;
    let (_, rest) = canonical.split_once("://")?;
    let (authority, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority.trim_start_matches("www.");
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    // Instagram's . and _ are significant account-name characters. A post or
    // story URL must not become a person's profile, nor can a guessed spelling
    // variant establish the account behind a URL.
    if host == "instagram.com" {
        if segments.len() != 1 {
            return None;
        }
        let handle = segments[0];
        let valid = (1..=30).contains(&handle.len())
            && !handle.starts_with('.')
            && !handle.ends_with('.')
            && !handle.contains("..")
            && handle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
            && ![
                "p",
                "reel",
                "reels",
                "stories",
                "explore",
                "accounts",
                "direct",
                "tv",
                "tags",
                "locations",
                "challenge",
                "login",
                "signup",
                "about",
            ]
            .contains(&handle.to_ascii_lowercase().as_str());
        return valid.then(|| ProfileHandle::Instagram(handle.to_ascii_lowercase()));
    }
    // Only a bare `t.me/name` is the account's own page; a post, preview or invite is not.
    if host == "t.me" || host == "telegram.me" {
        let [name] = segments.as_slice() else {
            return None;
        };
        let handle =
            crate::value_syntax::telegram_handle_from_link(&format!("https://t.me/{name}"))?;
        return canonical_handle(&handle).map(ProfileHandle::Existing);
    }
    let candidate = match host {
        "github.com" | "twitter.com" | "x.com" => segments.first().copied(),
        "tiktok.com" => segments
            .first()
            .copied()
            .map(|segment| segment.trim_start_matches('@')),
        "reddit.com" => (segments.first() == Some(&"user")).then_some(*segments.get(1)?),
        "bsky.app" => {
            if segments.first() == Some(&"profile") {
                // The suffixes `username`'s Bluesky lookup strips, so a profile's own URL and its
                // username name the same handle.
                Some(crate::atproto::bare_handle(segments.get(1)?))
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
    canonical_handle(candidate).map(ProfileHandle::Existing)
}

#[must_use]
pub fn derive_profile_links(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let usernames = entities
        .iter()
        // A handle guessed from another value is no account a profile link could be.
        .filter(|entity| entity.kind == EntityKind::Username && !entity.is_offline_reading())
        .filter_map(|entity| canonical_handle(&entity.value).map(|key| (key, entity)))
        .collect::<HashMap<_, _>>();
    let mut out = Vec::new();
    for url in entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Url)
    {
        let Some(profile) = extract_username_from_profile_url(&url.value) else {
            continue;
        };
        let key = match &profile {
            ProfileHandle::Existing(handle) => Some(handle.clone()),
            ProfileHandle::Instagram(handle) => canonical_handle(handle),
        };
        let Some(username) = key.as_deref().and_then(|key| usernames.get(key)) else {
            continue;
        };
        let kind = match profile {
            ProfileHandle::Existing(_) => RelationKind::SameIdentity,
            ProfileHandle::Instagram(ref exact) => {
                // Canonical Username UIDs intentionally collapse separators for
                // broad discovery. Instagram does not: @ruby.mae and @ruby_mae
                // are distinct accounts. Only a literally observed or seeded
                // spelling may link to its URL, and the link must not merge
                // real-world identities merely because the text matches.
                let observed = username
                    .observed_spellings()
                    .keys()
                    .any(|spelling| spelling.eq_ignore_ascii_case(exact));
                let seeded = username.evidence.iter().any(Evidence::is_operator_seed)
                    && username
                        .raw_value
                        .trim()
                        .trim_start_matches('@')
                        .eq_ignore_ascii_case(exact);
                if !observed && !seeded {
                    continue;
                }
                RelationKind::AssociatedWith
            }
        };
        out.push(Relation::new(
            &username.uid,
            &url.uid,
            kind,
            endpoint_confidence(username, url),
            scan_id,
        ));
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
            Some(ProfileHandle::Existing("rhinoryno23".into()))
        );
        assert_eq!(
            extract_username_from_profile_url("https://www.tiktok.com/@dancequeen"),
            Some(ProfileHandle::Existing("dancequeen".into()))
        );
        assert_eq!(
            extract_username_from_profile_url(
                "https://www.reddit.com/user/rhino-ryno23/about.json"
            ),
            Some(ProfileHandle::Existing("rhinoryno23".into()))
        );
        assert_eq!(
            extract_username_from_profile_url("https://bsky.app/profile/haigen.bsky.social"),
            Some(ProfileHandle::Existing("haigen".into()))
        );
        for (url, handle) in [
            ("https://bsky.app/profile/alice.bsky.team", "alice"),
            ("https://bsky.app/profile/Alice.BSKY.Social", "alice"),
            ("https://bsky.app/profile/bob.brid.gy", "bob"),
            ("https://bsky.app/profile/pfrazee.com", "pfrazeecom"),
        ] {
            assert_eq!(
                extract_username_from_profile_url(url),
                Some(ProfileHandle::Existing(handle.into())),
                "{url}"
            );
        }
        assert_eq!(
            extract_username_from_profile_url("https://news.ycombinator.com/user?id=pg"),
            Some(ProfileHandle::Existing("pg".into()))
        );
        assert_eq!(
            extract_username_from_profile_url("https://unknown.example.com/x"),
            None
        );
    }

    #[test]
    fn a_telegram_page_url_names_its_handle_but_a_post_or_invite_does_not() {
        assert_eq!(
            extract_username_from_profile_url("https://t.me/Some_Channel"),
            canonical_handle("some_channel").map(ProfileHandle::Existing)
        );
        assert_eq!(
            extract_username_from_profile_url("https://t.me/some_channel/42"),
            None
        );
        assert_eq!(
            extract_username_from_profile_url("https://t.me/s/some_channel"),
            None
        );
        assert_eq!(
            extract_username_from_profile_url("https://t.me/joinchat/AbCdEf"),
            None
        );
    }
    #[test]
    fn instagram_profile_urls_preserve_exact_handle_and_do_not_bind_identity() {
        assert_eq!(
            extract_username_from_profile_url(
                "https://www.instagram.com/AliceTest9777?dlrf=not_a_real_token"
            ),
            Some(ProfileHandle::Instagram("alicetest9777".into()))
        );
        for not_a_profile in [
            "https://www.instagram.com/p/ABC123/",
            "https://instagram.com/reel/ABC123/",
            "https://instagram.com/stories/alicetest9777/",
            "https://instagram.com/explore/",
            "https://instagram.com/alicetest9777/p/ABC/",
            "https://instagram.com/ruby..mae/",
            "https://instagram.com/ruby-mae/",
            "https://instagram.com/ruby%2Fmae/",
            "https://notinstagram.com/alicetest9777/",
        ] {
            assert_eq!(
                extract_username_from_profile_url(not_a_profile),
                None,
                "{not_a_profile}"
            );
        }

        let scan = "scan";
        let target = Entity::new(EntityKind::Username, "alicetest9777", 0.8, scan);
        let url = Entity::new(
            EntityKind::Url,
            "https://www.instagram.com/alicetest9777?dlrf=opaque",
            0.8,
            scan,
        );
        let relations = derive_profile_links(&[target, url.clone()], scan);
        assert_eq!(relations.len(), 1);
        assert_eq!(relations[0].kind, RelationKind::AssociatedWith);
        assert!(!relations[0].kind.binds_identity());

        // Their canonical entity keys collide, but their Instagram account
        // names differ. Neither a separator change nor a near-name match
        // licenses the link.
        for different in ["alice_test9777", "alice.test9777", "alicetest3223"] {
            let other = Entity::new(EntityKind::Username, different, 0.8, scan);
            assert!(
                derive_profile_links(&[other, url.clone()], scan).is_empty(),
                "{different}"
            );
        }
    }
}
