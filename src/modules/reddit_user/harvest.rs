//! Credential mining over already-fetched Reddit text.
//!
//! Split out of entity construction, which is the point of the refactor: the old
//! `build_entities` took a `&KeyPool` purely to mutate it half-way through
//! building a `Vec<Entity>`, so the mapping could not be tested without a pool
//! and the pooling could not be tested without the mapping. Here the side effect
//! is the whole job, and [`super::transform`] is a pure function of the feed.
//!
//! # Why Reddit text is worth scanning at all
//! A post or comment body is unmoderated free text that people paste code into.
//! The classifier is the universal one — the same `found_keys`/`key_harvest`
//! pair `web_crawler`, `username_search`, `wayback` and `hacker_news` run over
//! their own fetched bodies — so a key found here is graded and de-duplicated
//! exactly as one found anywhere else. There is no extra network cost: every
//! byte scanned was already fetched for the entity extraction.

use crate::core::entity::unix_now;
use crate::util::found_keys::{MAX_TOKEN, key_tokens};
use crate::util::key_harvest::identify_api_key;
use crate::util::key_pool::{KeyEntry, KeyPool, KeyStatus};

use super::feed::Feed;

/// Scan every text surface one feed carries: the profile description, then each
/// item body as plain text.
///
/// Item bodies are scanned **stripped of markup** rather than as raw HTML —
/// Reddit renders a pasted snippet into `<code>` blocks, and the tag soup around
/// a token is noise the tokeniser would otherwise have to survive.
pub(super) fn mine_feed(feed: &Feed) {
    let pool = crate::util::key_pool::global_pool();
    if let Some(bio) = feed.bio.as_deref() {
        mine_text(&pool, bio, &feed.username, "bio");
    }
    for item in &feed.items {
        mine_text(&pool, &item.text(), &feed.username, "post/comment");
    }
}

/// Classify the key-shaped tokens in one body and pool any that a service
/// claims.
///
/// No network and no clock beyond the discovery timestamp, so the tests exercise
/// it directly without an HTTP double.
pub(super) fn mine_text(pool: &KeyPool, text: &str, username: &str, source_label: &str) {
    for token in key_tokens(text, MAX_TOKEN) {
        let Some((service, key_val)) = identify_api_key(token) else {
            continue;
        };
        let mut entry = KeyEntry::new(key_val);
        entry.notes = Some(format!("Reddit {source_label} — user {username}"));
        entry.status = KeyStatus::Untested;
        entry.discovered_at = Some(unix_now());
        entry.discovered_by = Some(format!("reddit_user:{username}"));
        if pool.add(service, entry) {
            tracing::info!(
                service,
                username,
                source_label,
                "API key discovered in Reddit content"
            );
        }
    }
}
