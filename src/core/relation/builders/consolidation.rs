//! Consolidation relation builders: collapsing separately-extracted entities
//! that are actually the SAME real-world identity or account —
//! `derive_canonical_identities` (`SameAs` via the canonical resolver),
//! `derive_profile_links` (`SameIdentity` from social-platform URL → username
//! extraction), and `derive_coreferences` (promoting scored co-reference
//! hypotheses into typed identity edges). These run after the infra/identity
//! passes so they can fold contextual variants into one traversable node.

use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::types::{Relation, RelationKind};

/// Derive `SameAs` edges between distinct entities the canonical resolver proves are
/// the SAME real-world identity wearing two contexts — the reflexive self-pairing
/// pivot ([`crate::core::resolve`]).
///
/// The resolver folds provider-specific representations to one canonical form (Gmail
/// dot / `+tag` blindness, phone digit-only, order-insensitive names), so two entities
/// the engine extracted SEPARATELY — `j.ohn+work@gmail.com` and `john@gmail.com`, a
/// phone in national and E.164 form, "Jane Citizen" and "Citizen, Jane" — are revealed
/// as one identity in two contexts. This wires that previously analysis-only signal
/// into the graph: a single seed and every contextual variant of it collapse to one
/// connected node for traversal, so the variant is a valid state-mutating self-pairing,
/// not a new stranger. Strong by construction (the resolver only groups EXACT canonical
/// collisions, never fuzzy guesses), so it carries full endpoint trust rather than a
/// damp. Symmetric, canonically directed (smaller-uid → larger), deduped, deterministic.
pub fn derive_canonical_identities(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashMap;

    let groups = crate::core::resolve::suggest_merges(entities);
    if groups.is_empty() {
        return Vec::new();
    }
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    // Resolve each canonical group's member UIDs back to entities; `emit_pairwise`
    // links every distinct variant pair as the same node.
    let entity_groups = groups.iter().map(|group| {
        group
            .members
            .iter()
            .filter_map(|uid| by_uid.get(uid.as_str()).copied())
            .collect::<Vec<&Entity>>()
    });
    super::emit_pairwise(entity_groups, RelationKind::SameAs, scan_id, |a, b| {
        a.confidence.min(b.confidence)
    })
}

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

/// Minimum [`crate::core::coref::resolve_coreferences`] score for a co-reference
/// hypothesis to be **promoted into a graph edge**. Far above the read-only view's
/// emission floor: a reported hypothesis is a lead for an analyst to weigh, but a
/// graph edge is consumed by clustering, network synthesis and the autonomous
/// prioritiser, so only a *strong* same-individual match (an exact-handle match,
/// or several independent corroborating signals) earns one.
const COREF_PROMOTE_MIN_SCORE: f64 = 0.80;

/// Promote strong cross-identifier **co-reference** hypotheses
/// ([`crate::core::coref::resolve_coreferences`]) into typed identity relations,
/// so the same-individual links the scorer finds become first-class graph edges
/// the clustering, network and autonomous layers all consume — not just a
/// read-only view. Each promoted pair maps to the edge that fits its kinds:
///   * **Person ↔ identifier** → [`IdentifiedBy`](RelationKind::IdentifiedBy)
///     (Person → Email/Username/Phone) — the person owns the selector;
///   * **Person ↔ Person** → [`SameAs`](RelationKind::SameAs) — two name records
///     of one individual;
///   * **identifier ↔ identifier** → [`AliasOf`](RelationKind::AliasOf) — two
///     selectors of one persona.
///
/// **Strictly additive**: an edge already present in `existing` (same
/// `from|kind|to`) is never re-emitted, so this pass can only *add* links and can
/// never lower the confidence of an edge a higher-trust builder (handles /
/// identity-ownership / canonical-identities) already produced. Confidence is the
/// match score damped by the weaker endpoint's trust (`score × min(conf)`), so an
/// inferred co-reference edge never outranks a structural one. Deterministic
/// (sorted); deduped per `(from, kind, to)`.
pub fn derive_coreferences(
    entities: &[Entity],
    existing: &[Relation],
    scan_id: &str,
) -> Vec<Relation> {
    use std::collections::HashSet;

    // Index the edges already built this finalise so we only ever ADD, never
    // restate (and so never churn a stronger builder's confidence on upsert).
    let prior: HashSet<(&str, &str, &str)> = existing
        .iter()
        .map(|r| (r.from_uid.as_str(), r.kind.as_str(), r.to_uid.as_str()))
        .collect();
    // UID → confidence, to damp each promoted edge by its weaker endpoint.
    let conf_of: std::collections::HashMap<&str, f64> = entities
        .iter()
        .map(|e| (e.uid.as_str(), e.confidence))
        .collect();
    let kind_of: std::collections::HashMap<&str, EntityKind> = entities
        .iter()
        .map(|e| (e.uid.as_str(), e.kind.clone()))
        .collect();

    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut out = Vec::new();
    for c in crate::core::coref::resolve_coreferences(entities, COREF_PROMOTE_MIN_SCORE, 512) {
        let (Some(ka), Some(kb)) = (kind_of.get(c.uid_a.as_str()), kind_of.get(c.uid_b.as_str()))
        else {
            continue;
        };
        let a_person = *ka == EntityKind::Person;
        let b_person = *kb == EntityKind::Person;
        // Choose the typed edge and its canonical direction for the pair's kinds.
        let (from, to, kind) = match (a_person, b_person) {
            // Person → identifier (the person owns the selector).
            (true, false) => (&c.uid_a, &c.uid_b, RelationKind::IdentifiedBy),
            (false, true) => (&c.uid_b, &c.uid_a, RelationKind::IdentifiedBy),
            // Two persons: one individual, two name records. Smaller-UID → larger.
            (true, true) => (&c.uid_a, &c.uid_b, RelationKind::SameAs),
            // Two identifiers: aliases of one persona. Smaller-UID → larger.
            (false, false) => (&c.uid_a, &c.uid_b, RelationKind::AliasOf),
        };
        if prior.contains(&(from.as_str(), kind.as_str(), to.as_str())) {
            continue; // a higher-trust builder already emitted this exact edge
        }
        if !seen.insert((from.clone(), kind.as_str().to_string(), to.clone())) {
            continue;
        }
        let min_conf = conf_of
            .get(from.as_str())
            .copied()
            .unwrap_or(0.0)
            .min(conf_of.get(to.as_str()).copied().unwrap_or(0.0));
        out.push(Relation::new(
            from.as_str(),
            to.as_str(),
            kind,
            c.score * min_conf,
            scan_id,
        ));
    }
    super::sort_edges(&mut out);
    out
}
