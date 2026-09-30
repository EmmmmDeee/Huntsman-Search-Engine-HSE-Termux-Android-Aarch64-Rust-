//! Google News search, Australian edition — current news coverage of a name
//! or organisation, biased to Australian sources and locale.
//!
//! Endpoint: `GET https://news.google.com/rss/search?q="{query}"&hl=en-AU&gl=AU&ceid=AU:en`
//! Keyless — no API key, no login. `hl`/`gl`/`ceid=AU:en` is Google News' own
//! edition selector: it does not filter to Australian publications only, but
//! it biases ranking and inclusion toward the Australian edition the same way
//! visiting news.google.com/au and searching would, which is the "slightly
//! prefer Australia" this module exists to add — distinct from `trove_au`
//! (National Library of Australia, 1803-1954ish digitised newspapers, a
//! historical archive) and `chronicling_america` (US Library of Congress,
//! closes 1963): this is live, current-day news.
//!
//! Live-verified 2026-09-30: HTTP 200, a `<rss version="2.0">` document, one
//! `<item>` per hit:
//! `<item><title>Headline - Source Name</title><link>https://news.google.com/rss/articles/…</link>
//! <pubDate>Sat, 26 Sep 2026 19:00:00 GMT</pubDate>
//! <description>&lt;a href="…"&gt;Headline&lt;/a&gt;&amp;nbsp;&amp;nbsp;&lt;font …&gt;Source Name&lt;/font&gt;</description>
//! <source url="https://www.smh.com.au">Source Name</source></item>`.
//! No total-hit count field exists in this feed (unlike Trove/loc.gov), so the
//! headline entity's evidence reports how many items this fetch itself
//! returned. `<link>` is a Google News redirect (resolves to the real
//! article when opened, per Google's own JS interstitial) rather than the
//! publisher's URL directly — `<source url="…">` gives the publisher's actual
//! site, which is what a Domain-style pivot would want; the redirect link
//! itself is kept as the per-article `Url` so the evidence stays literally
//! what the feed said, matching `chronicling_america`/`trove_au`'s convention
//! of surfacing the feed's own URL rather than a derived one.
//!
//! No XML-parsing crate exists in this workspace (see `reddit_user::feed`'s
//! doc for why); this module reads the same handful of element names with a
//! byte-offset scan; every value a publisher could control (title, source
//! name) arrives HTML/XML-escaped in this feed, exactly as `reddit_user`
//! documents for Atom, so a raw `<` here is always feed structure.
//!
//! ATT&CK: T1593.002 — full-text search of an open news index, the same
//! technique `chronicling_america`/`trove_au` declare for the identical shape.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::html::decode_entities;
use crate::util::http::RequestBuilderExt;

const SRC: &str = "au_news_search";
/// Items read per query. Google News RSS typically returns up to ~100; this
/// keeps the read and the per-article Url fan-out bounded to a reviewable set,
/// the same rationale `chronicling_america::ROWS` documents.
const MAX_ITEMS: usize = 20;

pub struct AuNewsSearch;

/// One parsed `<item>`. Pure data — no `Option` collapse here, so a missing
/// field is visible to the entity builder rather than silently dropping the
/// whole item.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NewsItem {
    /// The feed's own title, WITH the trailing `" - Source Name"` still
    /// attached — [`build_entities`] strips it using the `source` field it
    /// already has, rather than guessing where the headline ends.
    title: String,
    link: String,
    pub_date: Option<String>,
    source_name: Option<String>,
    source_url: Option<String>,
}

impl NewsItem {
    /// The headline with the trailing `" - {source_name}"` Google appends
    /// removed, when the source name is known and the title actually ends
    /// with it. Falls back to the raw title otherwise, rather than guessing.
    fn headline(&self) -> &str {
        if let Some(name) = &self.source_name
            && let Some(stripped) = self.title.strip_suffix(&format!(" - {name}"))
        {
            return stripped;
        }
        &self.title
    }
}

#[async_trait]
impl Module for AuNewsSearch {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Google News (Australian edition) recon — current news coverage of a name or organisation, biased to Australian sources"
    }

    fn priority(&self) -> u8 {
        45
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1593.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Url,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // News moves fast; a short cache avoids hammering the feed within one
        // scan's pivot/recycle passes without going stale across a re-run.
        900
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let seed = target.value.trim();
        if seed.is_empty() {
            return Ok(ModuleResult::new());
        }
        // Quoted so the phrase matches as a whole, not as separate common words.
        let query = crate::util::http::urlencode(&format!("\"{seed}\""));
        let url = format!("https://news.google.com/rss/search?q={query}&hl=en-AU&gl=AU&ceid=AU:en");
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/rss+xml, application/xml, text/xml")
            .send_tagged(SRC)
            .await?;
        let Some(resp) = crate::util::http::ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let body = crate::util::http::read_text(SRC, resp).await?;
        let items = parse_items(&body);
        Ok(build_entities(target.kind, seed, &items, &ctx.scan_id))
    }
}

/// True when an item's own headline shares a whole-word token with the seed —
/// Google News' relevance ranking can surface a phrase match from body text
/// alone, so the returned title does not always literally name the seed. The
/// same "graded, never gated" relevance check `chronicling_america`/
/// `trove_au` apply to their own full-text hits.
fn item_is_relevant(item: &NewsItem, seed: &str) -> bool {
    crate::util::str_util::shares_whole_word_token(item.headline(), seed)
}

/// Pure parse + entity build. `body` is the RSS document; empty when no
/// `<item>` was found (a genuine zero-hit search, or a shape this module
/// does not recognise — both report nothing rather than guessing).
fn build_entities(kind: TargetKind, seed: &str, items: &[NewsItem], scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    if items.is_empty() {
        return result;
    }

    let any_relevant = items.iter().any(|i| item_is_relevant(i, seed));
    let headline_kind = match kind {
        TargetKind::Organisation => EntityKind::Organisation,
        _ => EntityKind::Person,
    };
    let conf = if any_relevant {
        confidence::MEDIUM_HIGH
    } else {
        confidence::LOW_MEDIUM
    };
    let mut headline = Entity::new(headline_kind, seed, conf, scan_id);
    headline.tag(SRC);
    headline.tag("news");
    headline.tag("au-preferenced");
    if !any_relevant {
        headline.tag("needs-identity-verification");
    }
    let mut ev = Evidence::new(
        SRC,
        format!(
            "Google News (AU edition): {} article(s) found for \"{seed}\"",
            items.len()
        ),
    );
    for item in items.iter().take(5) {
        if let Some(d) = &item.pub_date {
            ev = ev.with_attr("article", format!("{d}: {}", item.headline()));
        } else {
            ev = ev.with_attr("article", item.headline());
        }
    }
    if !any_relevant {
        ev = ev.with_attr(
            "caution",
            "None of the fetched articles' own headline names the seed as whole words \
             — Google's ranking may have matched on body text, or on a same-named but \
             unrelated subject; verify before treating this as the subject's own coverage.",
        );
    }
    headline.add_evidence(ev);
    result.push(headline);

    let mut seen_urls = std::collections::HashSet::new();
    for item in items.iter().take(MAX_ITEMS) {
        if item.link.is_empty()
            || !crate::util::url_util::is_absolute_http_url(&item.link)
            || !seen_urls.insert(item.link.clone())
        {
            continue;
        }
        let relevant = item_is_relevant(item, seed);
        let url_conf = if relevant {
            confidence::MEDIUM_HIGH
        } else {
            confidence::LOW_MEDIUM
        };
        let mut url_e = Entity::new(EntityKind::Url, &item.link, url_conf, scan_id);
        url_e.tag(SRC);
        url_e.tag("news");
        url_e.tag("au-preferenced");
        url_e.tag(crate::core::tags::SOURCE_DOCUMENT);
        if !relevant {
            url_e.tag("needs-identity-verification");
        }
        let mut uev = Evidence::new(
            SRC,
            if relevant {
                "Google News (AU edition) article mentioning the subject"
            } else {
                "Google News (AU edition) article returned by the search (relevance unconfirmed)"
            },
        )
        .with_attr("headline", item.headline());
        if let Some(d) = &item.pub_date {
            uev = uev.with_attr("published", d);
        }
        if let Some(name) = &item.source_name {
            uev = uev.with_attr("publisher", name);
        }
        if let Some(u) = &item.source_url {
            uev = uev.with_attr("publisher_url", u);
        }
        url_e.add_evidence(uev);
        result.push(url_e);
    }
    result
}

/// Split the document into `<item>…</item>` chunks and parse each. An item
/// truncated mid-stream (no closing tag) is dropped, not half-read — the same
/// discipline `reddit_user::feed::parse_entry` applies to a cut-short `<entry>`.
fn parse_items(xml: &str) -> Vec<NewsItem> {
    let Some(first) = xml.find("<item>") else {
        return Vec::new();
    };
    xml[first..]
        .split("<item>")
        .skip(1)
        .filter_map(parse_item)
        .collect()
}

fn parse_item(chunk: &str) -> Option<NewsItem> {
    let (chunk, _) = chunk.split_once("</item>")?;
    let title = decode_entities(&tag_text(chunk, "title")?);
    let link = decode_entities(&tag_text(chunk, "link").unwrap_or_default());
    let pub_date = tag_text(chunk, "pubDate").map(|s| decode_entities(&s));
    let (source_name, source_url) = source_of(chunk);
    Some(NewsItem {
        title,
        link,
        pub_date,
        source_name,
        source_url,
    })
}

/// `<source url="https://…">Name</source>` — both the publisher's homepage
/// and its display name, when present.
fn source_of(item: &str) -> (Option<String>, Option<String>) {
    let Some(at) = item.find("<source") else {
        return (None, None);
    };
    let rest = &item[at..];
    let Some(gt) = rest.find('>') else {
        return (None, None);
    };
    let open_tag = &rest[..gt];
    let url = attr(open_tag, "url").map(decode_entities);
    let after_gt = &rest[gt + 1..];
    let name = after_gt
        .find("</source>")
        .map(|end| decode_entities(after_gt[..end].trim()));
    (name.filter(|n| !n.is_empty()), url)
}

/// The value of `name="…"` within one already-delimited opening tag.
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let at = tag.find(&needle)? + needle.len();
    let rest = &tag[at..];
    Some(&rest[..rest.find('"')?])
}

/// Text between the first `<tag>` and its `</tag>`, trimmed. Unlike
/// `reddit_user::feed::tag_text` this feed's elements (`title`, `link`,
/// `pubDate`, `guid`) never carry attributes, so a bare `<tag>` search is
/// exact — no `open_tag_end` scan for a same-prefixed longer name is needed.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let close = xml[open..].find(&format!("</{tag}>"))?;
    let text = xml[open..open + close].trim();
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_text_reads_a_simple_element() {
        assert_eq!(
            tag_text("<title>Hello &amp; World</title>", "title"),
            Some("Hello &amp; World".to_string())
        );
        assert_eq!(tag_text("<title></title>", "title"), None);
        assert_eq!(tag_text("<title>x", "title"), None);
    }

    #[test]
    fn source_of_reads_url_and_name() {
        let item = r#"<source url="https://www.smh.com.au">SMH.com.au</source>"#;
        assert_eq!(
            source_of(item),
            (
                Some("SMH.com.au".to_string()),
                Some("https://www.smh.com.au".to_string())
            )
        );
        assert_eq!(source_of("<title>no source here</title>"), (None, None));
    }

    /// A single realistic `<item>` shaped exactly like the live-verified
    /// 2026-09-30 fetch (module doc comment), parameterised on the bits a
    /// test wants to vary.
    fn item_xml(
        title: &str,
        link: &str,
        pub_date: &str,
        source_name: &str,
        source_url: &str,
    ) -> String {
        format!(
            "<item><title>{title}</title><link>{link}</link>\
             <guid isPermaLink=\"false\">abc123</guid><pubDate>{pub_date}</pubDate>\
             <description>&lt;a href=\"{link}\"&gt;{title}&lt;/a&gt;</description>\
             <source url=\"{source_url}\">{source_name}</source></item>"
        )
    }

    #[test]
    fn parse_items_reads_every_field_of_a_realistic_item() {
        let xml = format!(
            "<rss><channel>{}</channel></rss>",
            item_xml(
                "Albanese got the gong - SMH.com.au",
                "https://news.google.com/rss/articles/XYZ",
                "Sat, 26 Sep 2026 19:00:00 GMT",
                "SMH.com.au",
                "https://www.smh.com.au"
            )
        );
        let items = parse_items(&xml);
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.link, "https://news.google.com/rss/articles/XYZ");
        assert_eq!(
            item.pub_date.as_deref(),
            Some("Sat, 26 Sep 2026 19:00:00 GMT")
        );
        assert_eq!(item.source_name.as_deref(), Some("SMH.com.au"));
        assert_eq!(item.source_url.as_deref(), Some("https://www.smh.com.au"));
    }

    #[test]
    fn headline_strips_the_trailing_source_suffix() {
        let item = NewsItem {
            title: "Albanese got the gong - SMH.com.au".to_string(),
            link: "https://news.google.com/rss/articles/XYZ".to_string(),
            pub_date: None,
            source_name: Some("SMH.com.au".to_string()),
            source_url: None,
        };
        assert_eq!(item.headline(), "Albanese got the gong");
    }

    #[test]
    fn headline_falls_back_to_the_raw_title_when_the_suffix_does_not_match() {
        // The source name is known, but the title does not actually end with
        // it (Google's own formatting is not a hard contract) — guessing
        // where to cut would corrupt the headline, so the raw title is kept.
        let item = NewsItem {
            title: "A headline with no suffix at all".to_string(),
            link: "https://news.google.com/rss/articles/XYZ".to_string(),
            pub_date: None,
            source_name: Some("SMH.com.au".to_string()),
            source_url: None,
        };
        assert_eq!(item.headline(), "A headline with no suffix at all");
    }

    fn sample_item(headline: &str, link: &str) -> NewsItem {
        NewsItem {
            title: format!("{headline} - Example News"),
            link: link.to_string(),
            pub_date: Some("Sat, 26 Sep 2026 19:00:00 GMT".to_string()),
            source_name: Some("Example News".to_string()),
            source_url: Some("https://example-news.com.au".to_string()),
        }
    }

    #[test]
    fn build_entities_emits_organisation_headline_for_an_organisation_target() {
        let items = vec![sample_item(
            "Acme Corp wins award",
            "https://news.google.com/rss/articles/1",
        )];
        let ents = build_entities(
            TargetKind::Organisation,
            "Acme Corp",
            &items,
            "scan-news-001",
        );
        let headline = ents
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Organisation && e.value == "Acme Corp");
        assert!(
            headline.is_some(),
            "must emit an Organisation headline entity"
        );
    }

    #[test]
    fn build_entities_emits_person_headline_for_a_fullname_target() {
        let items = vec![sample_item(
            "Jane Citizen speaks out",
            "https://news.google.com/rss/articles/2",
        )];
        let ents = build_entities(
            TargetKind::FullName,
            "Jane Citizen",
            &items,
            "scan-news-002",
        );
        assert!(
            ents.entities
                .iter()
                .any(|e| e.kind == EntityKind::Person && e.value == "Jane Citizen"),
            "must emit a Person headline entity for a FullName target"
        );
    }

    #[test]
    fn build_entities_returns_empty_for_zero_items() {
        assert!(
            build_entities(
                TargetKind::Organisation,
                "Nobody Pty Ltd",
                &[],
                "scan-news-003"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_relevant_headline_scores_above_an_irrelevant_one() {
        let relevant = sample_item(
            "Acme Corp wins award",
            "https://news.google.com/rss/articles/1",
        );
        let irrelevant = sample_item(
            "Unrelated story about weather",
            "https://news.google.com/rss/articles/2",
        );
        let ents = build_entities(
            TargetKind::Organisation,
            "Acme Corp",
            &[relevant, irrelevant],
            "scan-news-004",
        );
        let relevant_url = ents
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.ends_with("/1"))
            .expect("checked");
        let irrelevant_url = ents
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.ends_with("/2"))
            .expect("checked");
        assert!(
            relevant_url.confidence > irrelevant_url.confidence,
            "a headline naming the seed must score above one that does not"
        );
        assert!(!relevant_url.has_tag("needs-identity-verification"));
        assert!(irrelevant_url.has_tag("needs-identity-verification"));
    }

    #[test]
    fn duplicate_links_across_items_are_not_emitted_twice() {
        let a = sample_item(
            "Acme Corp wins award",
            "https://news.google.com/rss/articles/1",
        );
        let b = sample_item(
            "Acme Corp wins award again",
            "https://news.google.com/rss/articles/1",
        );
        let ents = build_entities(
            TargetKind::Organisation,
            "Acme Corp",
            &[a, b],
            "scan-news-005",
        );
        let count = ents
            .entities
            .iter()
            .filter(|e| {
                e.kind == EntityKind::Url && e.value == "https://news.google.com/rss/articles/1"
            })
            .count();
        assert_eq!(count, 1, "the same article link must not be emitted twice");
    }

    #[test]
    fn every_url_entity_carries_the_publisher_evidence() {
        let items = vec![sample_item(
            "Acme Corp wins award",
            "https://news.google.com/rss/articles/1",
        )];
        let ents = build_entities(
            TargetKind::Organisation,
            "Acme Corp",
            &items,
            "scan-news-006",
        );
        let url_e = ents
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url)
            .expect("checked");
        let ev = url_e.evidence.first().expect("checked");
        assert_eq!(
            ev.attributes.get("publisher").map(String::as_str),
            Some("Example News")
        );
        assert_eq!(
            ev.attributes.get("publisher_url").map(String::as_str),
            Some("https://example-news.com.au")
        );
    }

    #[test]
    fn a_non_absolute_link_is_never_emitted_as_a_url_entity() {
        let mut item = sample_item("Acme Corp wins award", "not-a-url");
        item.link = "not-a-url".to_string();
        let ents = build_entities(
            TargetKind::Organisation,
            "Acme Corp",
            &[item],
            "scan-news-007",
        );
        assert!(!ents.entities.iter().any(|e| e.kind == EntityKind::Url));
    }
}
