//! Social-platform URL → username extraction (extracted from `builders.rs`).
//!
//! A data-driven [`SocialMatcher`] table maps known profile-URL shapes to the
//! embedded handle, and [`derive_profile_links`] turns a `Username` + its
//! matching profile `Url` into `SameIdentity`/alias edges. Self-contained: it
//! reads only the entity set and emits relations — no dependency on the other
//! relation builders — so it lives beside them rather than inside the 2k-line
//! `builders.rs`.

use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::types::{Relation, RelationKind};

// ── Social platform URL → username extraction ───────────────────────────────

/// How to extract the embedded username from a known social platform URL.
#[derive(Debug, Clone, Copy)]
enum ExtractKind {
    /// Take the `index`-th non-empty path segment (0-based after filtering).
    /// `strip_at` removes a leading `'@'`; `strip_suffix` removes a known
    /// trailing suffix (e.g. `".bsky.social"` in Bluesky profile URLs).
    Segment {
        index: usize,
        strip_at: bool,
        strip_suffix: Option<&'static str>,
    },
    /// The username is the value of query parameter `name` (e.g. HN `?id=`).
    QueryParam { name: &'static str },
}

struct SocialMatcher {
    host: &'static str,
    extract: ExtractKind,
}

/// Static table mapping social-platform hosts to their username extraction rule.
static SOCIAL_MATCHERS: &[SocialMatcher] = &[
    SocialMatcher {
        host: "www.facebook.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "twitter.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "x.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.instagram.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "github.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "gitlab.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.pinterest.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "dev.to",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "keybase.io",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.twitch.tv",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "vimeo.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "soundcloud.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "bitbucket.org",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "myspace.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "linktr.ee",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "about.me",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.behance.net",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "dribbble.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.imlive.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.mydirtyhobby.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.sextpanther.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "stripchat.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.loyalfans.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.tiktok.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: true,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "medium.com",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: true,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "mastodon.social",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: true,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.threads.net",
        extract: ExtractKind::Segment {
            index: 0,
            strip_at: true,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "steamcommunity.com",
        extract: ExtractKind::Segment {
            index: 1,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.flickr.com",
        extract: ExtractKind::Segment {
            index: 1,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "open.spotify.com",
        extract: ExtractKind::Segment {
            index: 1,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.reddit.com",
        extract: ExtractKind::Segment {
            index: 1,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "www.livejasmin.com",
        extract: ExtractKind::Segment {
            index: 1,
            strip_at: false,
            strip_suffix: None,
        },
    },
    SocialMatcher {
        host: "bsky.app",
        extract: ExtractKind::Segment {
            index: 1,
            strip_at: false,
            strip_suffix: Some(".bsky.social"),
        },
    },
    SocialMatcher {
        host: "news.ycombinator.com",
        extract: ExtractKind::QueryParam { name: "id" },
    },
];

/// Extract the embedded username from a known social-platform profile URL.
/// Returns `None` if the URL's host is not in `SOCIAL_MATCHERS`, the path
/// segment is missing, or the extracted string is empty.
fn extract_username_from_profile_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let canonical_host = host.strip_prefix("www.").unwrap_or(host);
    let matcher = SOCIAL_MATCHERS.iter().find(|m| {
        m.host
            .strip_prefix("www.")
            .unwrap_or(m.host)
            .eq_ignore_ascii_case(canonical_host)
    })?;

    let username = match matcher.extract {
        ExtractKind::Segment {
            index,
            strip_at,
            strip_suffix,
        } => {
            let path = parsed.path();
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            let seg = segments.get(index).copied()?;
            let seg = if strip_at {
                seg.strip_prefix('@').unwrap_or(seg)
            } else {
                seg
            };
            let seg = if let Some(suffix) = strip_suffix {
                seg.strip_suffix(suffix).unwrap_or(seg)
            } else {
                seg
            };
            if seg.is_empty() {
                return None;
            }
            seg.to_ascii_lowercase()
        }
        ExtractKind::QueryParam { name } => parsed.query_pairs().find_map(|(k, v)| {
            if k.as_ref() == name {
                Some(v.to_ascii_lowercase())
            } else {
                None
            }
        })?,
    };

    if username.is_empty() {
        None
    } else {
        Some(username)
    }
}

/// Link `Username` entities to the social-platform `Url` entities whose
/// embedded handle matches — making the identity hub explicit in the graph.
///
/// Matching is case-insensitive. The edge is directed `Username → Url`.
/// Confidence = `min(username.conf, url.conf)`.
pub fn derive_profile_links(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    let usernames: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    if usernames.is_empty() {
        return Vec::new();
    }

    let username_index: std::collections::HashMap<String, &Entity> = usernames
        .iter()
        .map(|e| (e.value.to_ascii_lowercase(), *e))
        .collect();

    let mut out = Vec::new();
    for url_entity in entities.iter().filter(|e| e.kind == EntityKind::Url) {
        let Some(extracted) = extract_username_from_profile_url(&url_entity.value) else {
            continue;
        };
        let Some(&uname_entity) = username_index.get(&extracted) else {
            continue;
        };
        let conf = uname_entity.confidence.min(url_entity.confidence);
        out.push(Relation::new(
            uname_entity.uid.as_str(),
            url_entity.uid.as_str(),
            RelationKind::SameIdentity,
            conf,
            scan_id,
        ));
    }
    out
}
