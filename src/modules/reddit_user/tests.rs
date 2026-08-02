use super::*;

use super::feed::{ItemKind, parse, subreddit_of};
use super::transform::{feed_to_entities, summarise};

/// A Reddit overview feed, shaped from one captured live in July 2026 (`GET
/// https://www.reddit.com/user/spez/.rss`, 200, Atom).
///
/// The details that look incidental are the ones under test:
///
///   * the request was for `SPEZ` — the head echoes that casing in `<id>`, while
///     `<title>` and the author `<uri>` carry Reddit's own `spez`;
///   * the first entry sits in `u_spez`, the account's *own* profile space, and
///     the fourth in a stranger's — neither is a community;
///   * the feed-level `<category term="u_spez">` disagrees with the entry-level
///     `<category term="u/spez">`, which is why the permalink is authoritative;
///   * `Tom &amp;amp; Jerry` is text Reddit escaped twice (once into HTML, once
///     into XML) and must arrive as `Tom & Jerry`, decoded exactly twice.
const FEED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:media="http://search.yahoo.com/mrss/">
<category term="u_spez" label="u/spez"/>
<updated>2026-07-25T00:07:00+00:00</updated>
<icon>https://www.redditstatic.com/icon.png/</icon>
<id>/user/SPEZ/.rss</id>
<link rel="self" href="https://www.reddit.com/user/SPEZ/.rss" type="application/atom+xml" />
<subtitle>Reddit CEO. Mail Spez@Example.com or see https://example.com/spez.</subtitle>
<title>overview for spez</title>
<entry>
<author><name>/u/spez</name><uri>https://www.reddit.com/user/spez</uri></author>
<category term="u/spez" label="u/spez" />
<content type="html">&lt;div class=&quot;md&quot;&gt;&lt;p&gt;And thank you &lt;a href=&quot;/u/shiruken&quot;&gt;u/shiruken&lt;/a&gt;!&lt;/p&gt;&lt;/div&gt;</content>
<id>t1_os0o1vi</id>
<link href="https://www.reddit.com/r/u_spez/comments/1u7hraf/21_years_of_reddit/os0o1vi/"/>
<updated>2026-06-16T16:59:58+00:00</updated>
<title>/u/spez on 21 years of Reddit</title>
</entry>
<entry>
<author><name>/u/spez</name><uri>https://www.reddit.com/user/spez</uri></author>
<content type="html">&lt;div class=&quot;md&quot;&gt;&lt;p&gt;Numbers: &lt;a href=&quot;https://investor.redditinc.com/q2&quot;&gt;investor page&lt;/a&gt; and &lt;a href=&quot;https://www.reddit.com/r/RDDT/&quot;&gt;our sub&lt;/a&gt;. Tom &amp;amp; Jerry.&lt;/p&gt;&lt;/div&gt;</content>
<id>t1_abc1234</id>
<link href="https://www.reddit.com/r/redditstock/comments/aaa111/earnings/abc1234/"/>
<updated>2026-05-02T10:00:00+00:00</updated>
<title>/u/spez on earnings</title>
</entry>
<entry>
<author><name>/u/spez</name><uri>https://www.reddit.com/user/spez</uri></author>
<content type="html">&lt;div class=&quot;md&quot;&gt;&lt;p&gt;Announcement.&lt;/p&gt;&lt;/div&gt;</content>
<id>t3_zzz9999</id>
<link href="https://www.reddit.com/r/RDDT/comments/zzz9999/announcement/"/>
<updated>2026-07-01T08:30:00+00:00</updated>
<title>Announcement</title>
</entry>
<entry>
<author><name>/u/spez</name><uri>https://www.reddit.com/user/spez</uri></author>
<content type="html">&lt;div class=&quot;md&quot;&gt;&lt;p&gt;Happy cake day.&lt;/p&gt;&lt;/div&gt;</content>
<id>t1_def5678</id>
<link href="https://www.reddit.com/r/u_someone/comments/bbb222/hi/def5678/"/>
<updated>2026-04-01T00:00:00+00:00</updated>
<title>/u/spez on hi</title>
</entry>
<entry>
<author><name>/u/spez</name><uri>https://www.reddit.com/user/spez</uri></author>
<content type="html">&lt;div class=&quot;md&quot;&gt;&lt;p&gt;Quarterly thread.&lt;/p&gt;&lt;/div&gt;</content>
<id>t3_qqq4444</id>
<link href="https://www.reddit.com/r/redditstock/comments/qqq4444/quarterly/"/>
<updated>2026-05-30T12:00:00+00:00</updated>
<title>Quarterly thread</title>
</entry>
</feed>"#;

fn feed() -> feed::Feed {
    parse(FEED).expect("the captured fixture is an overview feed")
}

fn entities() -> Vec<crate::core::entity::Entity> {
    feed_to_entities(&feed(), "scan-1")
}

fn find(ents: &[crate::core::entity::Entity], kind: EntityKind, value: &str) -> usize {
    ents.iter()
        .position(|e| e.kind == kind && e.value == value)
        .unwrap_or_else(|| {
            panic!(
                "expected a {kind:?} entity {value:?}; got {:?}",
                ents.iter()
                    .map(|e| (e.kind.clone(), e.value.as_str()))
                    .collect::<Vec<_>>()
            )
        })
}

fn attr<'a>(e: &'a crate::core::entity::Entity, key: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(key).map(String::as_str)
}

// ── Module metadata ─────────────────────────────────────────────────────────

#[test]
fn accepts_only_username() {
    let m = RedditUser;
    assert!(m.accepts(&Target::new(TargetKind::Username, "spez")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn metadata() {
    let m = RedditUser;
    assert_eq!(m.name(), "reddit_user");
    assert_eq!(m.priority(), 105);
    assert_eq!(m.max_timeout_ms(), 6_000);
    assert!(!m.description().is_empty());
    assert!(m.produces().contains(&EntityKind::Username));
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn handle_validation_matches_reddits_own_grammar() {
    assert!(is_handle("spez", 3, 20));
    assert!(is_handle("kylo-4_kylo", 3, 20));
    assert!(!is_handle("ab", 3, 20)); // too short
    assert!(!is_handle("this_handle_is_way_too_long", 3, 20));
    assert!(!is_handle("has space", 3, 20));
    // The gate gets the raw target value, so a path traversal never reaches the
    // URL this module interpolates the handle into.
    assert!(!is_handle("../../admin", 3, 20));
}

// ── feed::parse ─────────────────────────────────────────────────────────────

#[test]
fn parse_reads_the_canonical_casing_not_the_requested_one() {
    // The fixture's `<id>` echoes the requested `SPEZ`; the title and author URI
    // carry what Reddit holds. Taking the latter is what stops a mis-cased seed
    // minting a second identity for one account.
    assert!(
        FEED.contains("/user/SPEZ/.rss"),
        "fixture must be mis-cased"
    );
    assert_eq!(feed().username, "spez");
}

#[test]
fn parse_reads_the_profile_description_and_every_entry() {
    let f = feed();
    assert_eq!(f.items.len(), 5);
    assert_eq!(
        f.bio.as_deref(),
        Some("Reddit CEO. Mail Spez@Example.com or see https://example.com/spez.")
    );
}

#[test]
fn parse_classifies_comments_and_posts_by_fullname_prefix() {
    let kinds: Vec<ItemKind> = feed().items.iter().map(|i| i.kind).collect();
    assert_eq!(
        kinds,
        vec![
            ItemKind::Comment,
            ItemKind::Comment,
            ItemKind::Post,
            ItemKind::Comment,
            ItemKind::Post,
        ]
    );
}

#[test]
fn parse_takes_the_subreddit_from_the_permalink_not_the_category() {
    // The fixture's first entry carries `<category term="u/spez">` while the
    // feed head carries `term="u_spez"` for the same space — observed live. Only
    // the permalink spelling is used.
    let f = feed();
    assert_eq!(f.items[0].subreddit.as_deref(), Some("u_spez"));
    assert_eq!(f.items[1].subreddit.as_deref(), Some("redditstock"));
    assert_eq!(f.items[2].subreddit.as_deref(), Some("RDDT"));
}

#[test]
fn item_text_decodes_exactly_twice() {
    // Reddit escapes the user's text into HTML and that HTML into XML, so
    // `Tom & Jerry` travels as `Tom &amp;amp; Jerry`. One decode too few leaves
    // `&amp;`; one too many would corrupt a body that legitimately contains an
    // entity-shaped literal.
    let text = feed().items[1].text();
    assert!(text.contains("Tom & Jerry"), "got {text:?}");
    assert!(!text.contains("&amp;"), "over- or under-decoded: {text:?}");
}

#[test]
fn parse_falls_back_to_the_author_uri_when_the_title_changes_shape() {
    let retitled = FEED.replace(
        "<title>overview for spez</title>",
        "<title>spez on Reddit</title>",
    );
    assert_eq!(parse(&retitled).expect("should succeed").username, "spez");
}

#[test]
fn parse_refuses_a_document_that_names_no_account() {
    // Reddit's error pages, a redirect to the login wall, an empty body: none of
    // these identify an account, and a half-filled Feed would be a scan built on
    // a guess about whose data it holds.
    assert!(parse("<html><body>Bad Request</body></html>").is_none());
    assert!(parse("").is_none());
    let anonymous = FEED
        .replace("<title>overview for spez</title>", "<title>reddit</title>")
        .replace("<uri>https://www.reddit.com/user/spez</uri>", "<uri></uri>");
    assert!(parse(&anonymous).is_none());
}

#[test]
fn parse_survives_a_truncated_document() {
    // A body cut mid-entry must yield the entries that completed, never a field
    // running to the end of the file.
    let cut = &FEED[..FEED.find("t1_abc1234").expect("should succeed")];
    let f = parse(cut).expect("the head still identifies the account");
    assert_eq!(f.username, "spez");
    assert_eq!(f.items.len(), 1, "the incomplete entry contributes nothing");
}

#[test]
fn subreddit_of_rejects_anything_outside_reddits_name_grammar() {
    assert_eq!(
        subreddit_of("https://www.reddit.com/r/rust/"),
        Some("rust".into())
    );
    assert_eq!(
        subreddit_of("https://www.reddit.com/r/u_spez/comments/a/b/c/"),
        Some("u_spez".into())
    );
    assert_eq!(subreddit_of("https://www.reddit.com/user/spez/"), None);
    assert_eq!(subreddit_of("https://www.reddit.com/r//comments/"), None);
    assert_eq!(
        subreddit_of("https://www.reddit.com/r/this_name_is_far_too_long_to_be_real/"),
        None
    );
    assert_eq!(subreddit_of("https://www.reddit.com/r/bad name/"), None);
}

// ── transform::summarise ────────────────────────────────────────────────────

#[test]
fn summarise_counts_the_window_and_separates_profile_spaces() {
    let s = summarise(&feed());
    assert_eq!((s.items, s.comments, s.posts), (5, 3, 2));
    assert_eq!(s.own_profile_items, 1, "u_spez is the account's own page");
    assert_eq!(s.other_profile_items, 1, "u_someone belongs to a stranger");
    assert_eq!(
        s.communities.keys().collect::<Vec<_>>(),
        vec!["RDDT", "redditstock"],
        "profile spaces are never counted as communities"
    );
    let stock = &s.communities["redditstock"];
    assert_eq!((stock.items, stock.comments, stock.posts), (2, 1, 1));
    // Observed extremes of the window, not the account's lifetime.
    assert_eq!(s.earliest.as_deref(), Some("2026-04-01T00:00:00+00:00"));
    assert_eq!(s.latest.as_deref(), Some("2026-07-01T08:30:00+00:00"));
}

// ── transform::feed_to_entities ─────────────────────────────────────────────

#[test]
fn account_entity_carries_the_window_and_its_coverage_caveat() {
    let ents = entities();
    let u = &ents[find(&ents, EntityKind::Username, "spez")];
    assert_eq!(u.confidence, ACCOUNT_CONF);
    assert!(u.has_tag("reddit"));
    assert_eq!(
        attr(u, "profile_url"),
        Some("https://www.reddit.com/user/spez")
    );
    assert_eq!(
        attr(u, "feed_url"),
        Some("https://www.reddit.com/user/spez/.rss")
    );
    assert_eq!(attr(u, "items_in_feed"), Some("5"));
    assert_eq!(attr(u, "comments_in_feed"), Some("3"));
    assert_eq!(attr(u, "posts_in_feed"), Some("2"));
    assert_eq!(attr(u, "communities_in_feed"), Some("2"));
    assert_eq!(attr(u, "own_profile_page_items"), Some("1"));
    assert_eq!(attr(u, "other_users_profile_page_items"), Some("1"));
    assert_eq!(attr(u, "coverage"), Some(COVERAGE_CAVEAT));
    assert_eq!(
        attr(u, "latest_activity_observed"),
        Some("2026-07-01T08:30:00+00:00")
    );
    // The fields the dead JSON endpoint used to supply are absent, not guessed.
    for gone in ["link_karma", "comment_karma", "created_unix", "verified"] {
        assert_eq!(
            attr(u, gone),
            None,
            "{gone} is not recoverable from the feed"
        );
    }
}

#[test]
fn no_entity_names_a_third_partys_profile_space() {
    // `u_someone` is counted on the account's evidence and never emitted: another
    // person's handle is their identifier, not the subject's.
    for e in entities() {
        assert!(
            !e.value.contains("someone"),
            "a stranger's profile space leaked as {:?} {:?}",
            e.kind,
            e.value
        );
    }
}

#[test]
fn communities_are_namespaced_so_they_cannot_false_merge_with_organisations() {
    let ents = entities();
    let orgs: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| e.value.as_str())
        .collect();
    // Sorted, and prefixed: a bare `RDDT` would merge r/RDDT with the listed
    // company of that ticker if any other module ever reports one.
    assert_eq!(orgs, vec!["r/RDDT", "r/redditstock"]);
    let stock = &ents[find(&ents, EntityKind::Organisation, "r/redditstock")];
    assert_eq!(stock.confidence, SUBREDDIT_CONF);
    assert!(stock.has_tag("reddit") && stock.has_tag("subreddit"));
    assert_eq!(attr(stock, "subreddit"), Some("redditstock"));
    assert_eq!(attr(stock, "items_in_feed"), Some("2"));
    assert_eq!(attr(stock, "scope"), Some(SUBREDDIT_CAVEAT));
}

#[test]
fn bio_findings_are_graded_to_expand_and_attributed_to_the_holder() {
    let ents = entities();
    let email = &ents[find(&ents, EntityKind::Email, "spez@example.com")];
    assert_eq!(email.confidence, BIO_EMAIL_CONF);
    assert!(email.confidence >= confidence::MEDIUM, "must expand");
    assert!(email.has_tag("reddit") && email.has_tag("public-profile"));
    assert_eq!(attr(email, "attribution"), Some(BIO_ATTRIBUTION));

    let url = &ents[find(&ents, EntityKind::Url, "https://example.com/spez")];
    assert_eq!(url.confidence, BIO_URL_CONF);
    assert!(url.has_tag("personal-site"));

    let domain = &ents[find(&ents, EntityKind::Domain, "example.com")];
    assert_eq!(domain.confidence, BIO_DOMAIN_CONF);
    assert!(domain.has_tag("derived"));
}

#[test]
fn posted_links_are_reported_but_graded_below_the_expansion_floor() {
    let ents = entities();
    let url = &ents[find(&ents, EntityKind::Url, "https://investor.redditinc.com/q2")];
    assert_eq!(url.confidence, POSTED_URL_CONF);
    assert!(url.has_tag("posted-link"));
    assert_eq!(attr(url, "attribution"), Some(POSTED_LINK_CAVEAT));
    assert_eq!(
        attr(url, "permalink"),
        Some("https://www.reddit.com/r/redditstock/comments/aaa111/earnings/abc1234/")
    );

    let host = &ents[find(&ents, EntityKind::Domain, "investor.redditinc.com")];
    assert_eq!(host.confidence, POSTED_DOMAIN_CONF);

    // Below the noisy-OR expansion floor on purpose: quoting a URL is not owning
    // it, and a walk seeded from every pasted link would drown the scan. Asserted
    // on the emitted entities, so re-pointing either constant at a higher grade
    // fails here rather than silently turning the module into a crawler.
    assert!(
        url.confidence < confidence::MEDIUM,
        "posted URL must not expand"
    );
    assert!(
        host.confidence < confidence::MEDIUM,
        "posted host must not expand"
    );
}

#[test]
fn links_to_reddits_own_infrastructure_are_never_reported() {
    // The fixture links `https://www.reddit.com/r/RDDT/` — shared platform
    // infrastructure that says nothing about the account.
    for e in entities() {
        assert!(
            !e.value.contains("www.reddit.com/r/"),
            "reddit's own host leaked as {:?} {:?}",
            e.kind,
            e.value
        );
        if e.kind == EntityKind::Domain {
            assert_ne!(e.value, "reddit.com");
        }
    }
}

#[test]
fn a_self_published_url_keeps_its_bio_grading_even_if_also_posted() {
    // The same URL in the bio and in a comment must be emitted once, at the
    // stronger bio grade — not twice, and not downgraded to a posted link.
    let doubled = FEED.replace(
        "&lt;a href=&quot;https://investor.redditinc.com/q2&quot;&gt;investor page&lt;/a&gt;",
        "&lt;a href=&quot;https://example.com/spez&quot;&gt;my site&lt;/a&gt;",
    );
    let ents = feed_to_entities(&parse(&doubled).expect("should succeed"), "scan-2");
    let hits: Vec<&crate::core::entity::Entity> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.value == "https://example.com/spez")
        .collect();
    assert_eq!(hits.len(), 1, "emitted once, not once per source");
    assert_eq!(hits[0].confidence, BIO_URL_CONF);
}

#[test]
fn the_posted_link_cap_never_fires_silently() {
    // One item can hold arbitrarily many links, so this is the module's only
    // genuinely unbounded enumeration. Whatever the cap drops has to be legible
    // as dropped in the dossier itself.
    let over = MAX_POSTED_LINKS + 5;
    let links: String = (0..over)
        .map(|i| format!("&lt;a href=&quot;https://site{i}.example/&quot;&gt;x&lt;/a&gt; "))
        .collect();
    let flooded = FEED.replace(
        "&lt;a href=&quot;https://investor.redditinc.com/q2&quot;&gt;investor page&lt;/a&gt;",
        &links,
    );
    let ents = feed_to_entities(&parse(&flooded).expect("should succeed"), "scan-3");

    let kept = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url && e.has_tag("posted-link"))
        .count();
    assert_eq!(kept, MAX_POSTED_LINKS);
    let u = &ents[find(&ents, EntityKind::Username, "spez")];
    assert_eq!(attr(u, "posted_links_withheld"), Some("5"));
}

#[test]
fn identical_input_yields_an_identical_entity_sequence() {
    let a: Vec<(EntityKind, String)> = entities().into_iter().map(|e| (e.kind, e.value)).collect();
    let b: Vec<(EntityKind, String)> = entities().into_iter().map(|e| (e.kind, e.value)).collect();
    assert_eq!(a, b, "entity order must not depend on hash iteration order");
}

// ── harvest ─────────────────────────────────────────────────────────────────

#[test]
fn a_leaked_key_in_reddit_text_reaches_the_pool_with_reddit_provenance() {
    // A 234-char BinaryEdge-shaped (`bp0_`-prefixed, poolable) key — the fixture
    // shape used to prove the `wayback` and `hacker_news` key-mining passes —
    // embedded in a comment body, proving this pass reaches `pool.add` with
    // Reddit-specific provenance rather than being a "found it" no-op.
    let leaked_key = format!(
        "bp0_{}",
        "oHBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclRz3AwzKsbVRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIgfFwD3HJoKyrbmEYYmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6G3oT1ogmM"
    );
    let pool = crate::util::key_pool::global_pool();
    let username = "reddit-keymine-test-user";

    harvest::mine_text(
        &pool,
        &format!("oops my config: {leaked_key}"),
        username,
        "post/comment",
    );

    let entry = pool
        .snapshot()
        .services
        .get("binaryedge")
        .into_iter()
        .flatten()
        .find(|e| e.value == leaked_key)
        .cloned();
    let found = entry.is_some();
    if let Some(e) = &entry {
        assert_eq!(
            e.discovered_by.as_deref(),
            Some(format!("reddit_user:{username}").as_str()),
            "provenance must name reddit_user, not a generic/wrong source"
        );
        assert!(
            e.notes
                .as_deref()
                .is_some_and(|n| n.contains("post/comment") && n.contains(username)),
            "notes must carry the source label + username, got {:?}",
            e.notes
        );
    }
    if found {
        pool.remove("binaryedge", &leaked_key);
    }
    assert!(
        found,
        "a leaked key in a Reddit bio or item body must reach the key pool"
    );
}

#[test]
fn mining_a_feed_labels_a_bio_hit_distinctly_from_an_item_hit() {
    let leaked_key = format!(
        "bp0_{}",
        "zzBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclRz3AwzKsbVRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIgfFwD3HJoKyrbmEYYmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6G3oT1ogmZ"
    );
    let leaked = FEED.replace(
        "Reddit CEO.",
        &format!("Reddit CEO. my key is {leaked_key} whoops."),
    );
    harvest::mine_feed(&parse(&leaked).expect("should succeed"));

    let pool = crate::util::key_pool::global_pool();
    let entry = pool
        .snapshot()
        .services
        .get("binaryedge")
        .into_iter()
        .flatten()
        .find(|e| e.value == leaked_key)
        .cloned();
    let found = entry.is_some();
    if let Some(e) = &entry {
        assert!(
            e.notes.as_deref().is_some_and(|n| n.contains("bio")),
            "notes must label this a bio-sourced hit, got {:?}",
            e.notes
        );
    }
    if found {
        pool.remove("binaryedge", &leaked_key);
    }
    assert!(
        found,
        "a leaked key in the profile description must be pooled"
    );
}
