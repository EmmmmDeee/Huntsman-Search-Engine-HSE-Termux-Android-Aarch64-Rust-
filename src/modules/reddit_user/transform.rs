//! Pure mapping: a parsed [`Feed`] → the entities it justifies.
//!
//! No network, no clock, no key pool. Every judgement that could produce a
//! confident wrong finding lives here, so this is where the tests point.
//!
//! # The grading, and why it is deliberately flat
//! The feed proves one thing outright — *this account exists and this is its
//! canonical name* — and everything else it carries is one step removed from
//! that. A community is graded low because a single comment and a decade of
//! moderation look identical from here. A link is graded lower still, and
//! **below the noisy-OR expansion floor on purpose**: an account quoting a URL
//! is not the account owning it, so a posted link is worth reporting and is not
//! worth seeding a recursive walk from. The bio is the one place the account
//! speaks about itself, so bio findings alone are graded to expand.

use std::collections::{BTreeMap, HashSet};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::extract;
use crate::util::url_util::host_from_url;

use super::feed::{Feed, ItemKind};
use super::{
    ACCOUNT_CONF, BIO_ATTRIBUTION, BIO_DOMAIN_CONF, BIO_EMAIL_CONF, BIO_URL_CONF, COVERAGE_CAVEAT,
    MAX_POSTED_LINKS, POSTED_DOMAIN_CONF, POSTED_LINK_CAVEAT, POSTED_URL_CONF, PROFILE_BASE,
    REDDIT_HOSTS, SRC, SUBREDDIT_CAVEAT, SUBREDDIT_CONF,
};

/// One community's share of the feed window.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Tally {
    pub(super) items: usize,
    pub(super) comments: usize,
    pub(super) posts: usize,
    /// Permalink of the most recent item observed there — the feed is served
    /// newest first, so the first one seen is it.
    pub(super) newest: String,
}

/// What the feed window shows, counted once so that every entity citing it
/// cites the same numbers.
#[derive(Debug, Default)]
pub(super) struct Summary {
    pub(super) items: usize,
    pub(super) comments: usize,
    pub(super) posts: usize,
    /// Lexicographic extremes of `<updated>`. Reddit serves RFC-3339 at a fixed
    /// `+00:00` offset, which orders correctly as text; they are reported as
    /// *observed* extremes either way, never as the account's lifetime.
    pub(super) earliest: Option<String>,
    pub(super) latest: Option<String>,
    /// Items in the account's own `u_{name}` space. That space is the account's
    /// own profile page, not a community it joined, so it is counted here and
    /// never emitted as an affiliation.
    pub(super) own_profile_items: usize,
    /// Items in *another* account's `u_…` space. Counted so the dossier does not
    /// silently lose them, and deliberately not named: a third party's handle is
    /// their identifier, not the subject's, and putting it in the subject's
    /// findings would assert a link the feed does not support.
    pub(super) other_profile_items: usize,
    /// Communities, sorted by name — a `BTreeMap` so identical input always
    /// yields the identical entity set in the identical order.
    pub(super) communities: BTreeMap<String, Tally>,
}

/// Fold the feed's items into the counts every entity below reports.
pub(super) fn summarise(feed: &Feed) -> Summary {
    let mut s = Summary {
        items: feed.items.len(),
        ..Summary::default()
    };
    let own_space = format!("u_{}", feed.username);

    for item in &feed.items {
        match item.kind {
            ItemKind::Comment => s.comments += 1,
            ItemKind::Post => s.posts += 1,
            ItemKind::Other => {}
        }
        if !item.updated.is_empty() {
            if s.earliest.as_ref().is_none_or(|e| item.updated < *e) {
                s.earliest = Some(item.updated.clone());
            }
            if s.latest.as_ref().is_none_or(|l| item.updated > *l) {
                s.latest = Some(item.updated.clone());
            }
        }

        let Some(sub) = item.subreddit.as_deref() else {
            continue;
        };
        if sub.eq_ignore_ascii_case(&own_space) {
            s.own_profile_items += 1;
            continue;
        }
        // Byte-slice on `as_bytes()`, NOT `sub[..2]`: the latter is a `&str`
        // char-boundary slice and `sub.len() > 2` is only a byte-length guard,
        // so a name whose 2nd byte is a UTF-8 continuation (e.g. "aé") would
        // panic mid-char. `len() > 2` already guarantees ≥3 bytes here, and the
        // `u_` prefix is ASCII, so the byte compare is exact and panic-free.
        if sub.len() > 2 && sub.as_bytes()[..2].eq_ignore_ascii_case(b"u_") {
            s.other_profile_items += 1;
            continue;
        }
        let tally = s.communities.entry(sub.to_string()).or_default();
        tally.items += 1;
        match item.kind {
            ItemKind::Comment => tally.comments += 1,
            ItemKind::Post => tally.posts += 1,
            ItemKind::Other => {}
        }
        if tally.newest.is_empty() {
            tally.newest = item.permalink.clone();
        }
    }
    s
}

/// True for a host Reddit itself serves. A link to one of these is a link to
/// Reddit — infrastructure every redditor shares — and says nothing about the
/// account, so it is dropped rather than reported as an associated domain.
fn is_reddit_host(host: &str) -> bool {
    REDDIT_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

/// Every entity one feed justifies, in a stable order: the account, then what it
/// says about itself, then where it says it, then what it linked to.
pub(super) fn feed_to_entities(feed: &Feed, scan_id: &str) -> Vec<Entity> {
    let summary = summarise(feed);

    // The bio is mined first so a URL the account publishes about itself keeps
    // the bio's grading and is not later re-emitted, weaker, as a posted link.
    let mut seen_urls: HashSet<String> = HashSet::new();
    let bio = bio_entities(feed, scan_id, &mut seen_urls);
    let (links, withheld) = posted_link_entities(feed, scan_id, &mut seen_urls);

    let mut out = Vec::with_capacity(1 + bio.len() + summary.communities.len() + links.len());
    out.push(account_entity(feed, &summary, withheld, scan_id));
    out.extend(bio);
    out.extend(community_entities(feed, &summary, scan_id));
    out.extend(links);
    out
}

/// The account itself: the one finding the feed proves outright.
fn account_entity(feed: &Feed, s: &Summary, links_withheld: usize, scan_id: &str) -> Entity {
    let mut e = Entity::new(EntityKind::Username, &feed.username, ACCOUNT_CONF, scan_id);
    e.tag("reddit");

    let mut ev = Evidence::new(SRC, format!("Reddit account u/{}", feed.username))
        .with_attr("profile_url", format!("{PROFILE_BASE}/{}", feed.username))
        .with_attr("feed_url", format!("{PROFILE_BASE}/{}/.rss", feed.username))
        .with_attr("items_in_feed", s.items.to_string())
        .with_attr("comments_in_feed", s.comments.to_string())
        .with_attr("posts_in_feed", s.posts.to_string())
        .with_attr("communities_in_feed", s.communities.len().to_string())
        // The caveat states what this endpoint does NOT carry, because an
        // operator reading a Reddit finding will otherwise expect the karma and
        // account age the old JSON endpoint used to supply.
        .with_attr("coverage", COVERAGE_CAVEAT);

    for (key, value) in [
        ("earliest_activity_observed", s.earliest.clone()),
        ("latest_activity_observed", s.latest.clone()),
    ] {
        if let Some(v) = value {
            ev = ev.with_attr(key, v);
        }
    }
    // Counted, never silently dropped — including the two buckets that are
    // deliberately not emitted as entities.
    for (key, count) in [
        ("own_profile_page_items", s.own_profile_items),
        ("other_users_profile_page_items", s.other_profile_items),
        ("posted_links_withheld", links_withheld),
    ] {
        if count > 0 {
            ev = ev.with_attr(key, count.to_string());
        }
    }
    if let Some(bio) = feed.bio.as_deref() {
        ev = ev.with_attr("profile_description", bio);
    }

    e.add_evidence(ev);
    e
}

/// What the account publishes about itself in its profile description.
///
/// Emails are taken from here and from nowhere else. A bio is the account
/// speaking about itself; a comment body is a place people paste support
/// addresses, other people's contacts and quoted text, and an `Email` entity is
/// too consequential to mint from a source that cannot tell those apart.
fn bio_entities(feed: &Feed, scan_id: &str, seen_urls: &mut HashSet<String>) -> Vec<Entity> {
    let Some(bio) = feed.bio.as_deref() else {
        return Vec::new();
    };
    let name = &feed.username;
    let mut out = Vec::new();

    for email in extract::emails(bio) {
        let mut e = Entity::new(EntityKind::Email, &email, BIO_EMAIL_CONF, scan_id);
        e.tag("reddit");
        e.tag("public-profile");
        e.add_evidence(
            Evidence::new(SRC, format!("Email in the Reddit profile of u/{name}"))
                .with_attr("source", "reddit_profile_description")
                .with_attr("attribution", BIO_ATTRIBUTION),
        );
        out.push(e);
    }

    for link in extract::urls(bio) {
        if !seen_urls.insert(link.clone()) {
            continue;
        }
        let mut u = Entity::new(EntityKind::Url, &link, BIO_URL_CONF, scan_id);
        u.tag("reddit");
        u.tag("personal-site");
        u.add_evidence(
            Evidence::new(SRC, format!("Link in the Reddit profile of u/{name}"))
                .with_attr("source", "reddit_profile_description")
                .with_attr("attribution", BIO_ATTRIBUTION),
        );
        out.push(u);

        if let Some(host) = host_from_url(&link)
            && host.contains('.')
            && !is_reddit_host(&host)
        {
            let mut d = Entity::new(EntityKind::Domain, &host, BIO_DOMAIN_CONF, scan_id);
            d.tag("reddit");
            d.tag("derived");
            d.tag("personal-site");
            d.add_evidence(
                Evidence::new(SRC, format!("Domain from the Reddit profile of u/{name}"))
                    .with_attr("source_url", &link)
                    .with_attr("reddit_handle", name)
                    .with_attr("attribution", BIO_ATTRIBUTION),
            );
            out.push(d);
        }
    }
    out
}

/// One entity per community the account was observed in.
///
/// The value is namespaced `r/{sub}` rather than the bare name. `Organisation`
/// is a shared kind: emitting `news` would merge r/news with any real body
/// called "news" that another module reports, producing a single dossier entry
/// asserting a connection that does not exist. The prefix is how the rest of the
/// codebase keeps platform-scoped identifiers from colliding.
fn community_entities(feed: &Feed, s: &Summary, scan_id: &str) -> Vec<Entity> {
    // No cap and no truncation: a feed holds at most 25 items, so the community
    // set it can name is bounded by construction — the reason the previous
    // listing-based implementation dropped its `.take(10)` too.
    s.communities
        .iter()
        .map(|(sub, tally)| {
            let mut e = Entity::new(
                EntityKind::Organisation,
                format!("r/{sub}"),
                SUBREDDIT_CONF,
                scan_id,
            );
            e.tag("reddit");
            e.tag("subreddit");
            let mut ev = Evidence::new(SRC, format!("u/{} active in r/{sub}", feed.username))
                .with_attr("subreddit", sub)
                .with_attr("items_in_feed", tally.items.to_string())
                .with_attr("comments_in_feed", tally.comments.to_string())
                .with_attr("posts_in_feed", tally.posts.to_string())
                .with_attr("scope", SUBREDDIT_CAVEAT);
            if !tally.newest.is_empty() {
                ev = ev.with_attr("most_recent_item", &tally.newest);
            }
            e.add_evidence(ev);
            e
        })
        .collect()
}

/// Links the account posted, as `Url` plus the host as `Domain`.
///
/// Returns the entities and the number of distinct links **withheld** by the
/// cap, which the account's evidence reports — a bounded enumeration has to be
/// legible as bounded in the dossier itself.
fn posted_link_entities(
    feed: &Feed,
    scan_id: &str,
    seen_urls: &mut HashSet<String>,
) -> (Vec<Entity>, usize) {
    let name = &feed.username;
    let mut out = Vec::new();
    let mut seen_hosts: HashSet<String> = HashSet::new();
    let mut kept = 0usize;
    let mut withheld = 0usize;

    for item in &feed.items {
        // Mined from the HTML rather than the stripped text: a markdown link
        // keeps its target only in the `href`, so stripping tags first would
        // discard exactly the URLs worth having.
        for link in extract::urls(&item.html) {
            let Some(host) = host_from_url(&link) else {
                continue;
            };
            if !host.contains('.') || is_reddit_host(&host) {
                continue;
            }
            if !seen_urls.insert(link.clone()) {
                continue;
            }
            if kept >= MAX_POSTED_LINKS {
                withheld += 1;
                continue;
            }
            kept += 1;

            let mut u = Entity::new(EntityKind::Url, &link, POSTED_URL_CONF, scan_id);
            u.tag("reddit");
            u.tag("posted-link");
            u.add_evidence(
                Evidence::new(SRC, format!("Link posted by u/{name}"))
                    .with_attr("permalink", &item.permalink)
                    .with_attr("posted_at", &item.updated)
                    .with_attr("attribution", POSTED_LINK_CAVEAT),
            );
            out.push(u);

            if seen_hosts.insert(host.clone()) {
                let mut d = Entity::new(EntityKind::Domain, &host, POSTED_DOMAIN_CONF, scan_id);
                d.tag("reddit");
                d.tag("derived");
                d.tag("posted-link");
                d.add_evidence(
                    Evidence::new(SRC, format!("Domain linked by u/{name}"))
                        .with_attr("source_url", &link)
                        .with_attr("reddit_handle", name)
                        .with_attr("attribution", POSTED_LINK_CAVEAT),
                );
                out.push(d);
            }
        }
    }

    if withheld > 0 {
        tracing::warn!(
            "{SRC}: u/{name} posted more than {MAX_POSTED_LINKS} distinct off-Reddit links; \
             {withheld} are NOT in this scan's results"
        );
    }
    (out, withheld)
}
