//! Pure parse: a Reddit user overview feed → the activity it records.
//!
//! No network, no clock. [`super`] does the fetching; this file decides what the
//! document *says*, which is where a wrong finding would come from, and is
//! therefore where the tests point — the same split [`plc_directory`] uses.
//!
//! # Why a string scan and not an XML crate
//! The engine ships no XML parser (see [`crate::modules::sitemap`], which reads
//! `<loc>` the same way) and adding one to read four element names on a target
//! that already builds for `aarch64-linux-android` would be a dependency bought
//! for nothing. The scan is safe here for a structural reason, not a hopeful
//! one: every scrap of user-controlled text in the feed — post bodies, titles,
//! link URLs — arrives XML-escaped, so a raw `<` in the document is *always* an
//! Atom element and never something a redditor typed.
//!
//! [`plc_directory`]: crate::modules::plc_directory

use crate::util::html::decode_entities;
use crate::util::str_util::is_handle;

/// The feed titles itself `overview for {name}`, and that name is the casing
/// Reddit holds rather than the casing that was asked for: verified live in July
/// 2026, `GET /user/SPEZ/.rss` answers 200 with `overview for spez`. Taking the
/// name from here rather than from the request is what keeps a scan of `SPEZ`
/// from minting a second, differently-cased identity for one account.
const TITLE_PREFIX: &str = "overview for ";

/// Longest subreddit name accepted out of a permalink. Reddit's own limit is 21
/// characters; a profile space is `u_` plus a username, so 24 covers both with
/// room to spare and rejects a path segment that is something else entirely.
const MAX_SUBREDDIT_LEN: usize = 24;

/// What Reddit's fullname prefix says an item is.
///
/// Comments matter as much as posts here, and only the feed carries them: the
/// listing this module used to read (`submitted.json`) held submissions alone,
/// so the majority of most accounts' community footprint was invisible to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ItemKind {
    /// `t1_` — a comment.
    Comment,
    /// `t3_` — a post.
    Post,
    /// Any other fullname prefix, or none. Counted, never described.
    Other,
}

impl ItemKind {
    /// Classify a `<id>` body (`t1_os0o1vi`). Unknown prefixes are [`Self::Other`]
    /// rather than guessed at.
    fn of(id: &str) -> Self {
        match id.split('_').next() {
            Some("t1") => Self::Comment,
            Some("t3") => Self::Post,
            _ => Self::Other,
        }
    }
}

/// One entry in a user's overview feed.
#[derive(Debug, Clone)]
pub(super) struct Item {
    pub(super) kind: ItemKind,
    /// The subreddit the item lives in, read out of the permalink path.
    ///
    /// The permalink is authoritative where the entry's `<category term=…>` is
    /// not: observed live, a comment on the author's own profile carries
    /// `term="u/spez"` while the feed header carries `term="u_spez"` for the
    /// same space. One spelling, taken from the URL Reddit itself links to.
    pub(super) subreddit: Option<String>,
    pub(super) permalink: String,
    /// `<updated>` — RFC-3339, always UTC-offset in observed feeds.
    pub(super) updated: String,
    /// `<content type="html">`, un-escaped exactly once so it is ordinary HTML
    /// again. Stripping to plain text is [`Self::text`]'s job, and callers that
    /// want the `href`s (a markdown link keeps its URL only in the attribute)
    /// read this instead.
    pub(super) html: String,
}

impl Item {
    /// The item body as plain text.
    ///
    /// [`crate::util::html::strip_html`] decodes entities on its way out, which
    /// is the second and final decode this content needs: Reddit escapes the
    /// user's text into HTML and then escapes that HTML into XML, so `a & b`
    /// travels as `a &amp;amp; b` and arrives, correctly, as `a & b`.
    pub(super) fn text(&self) -> String {
        crate::util::html::strip_html(&self.html)
    }
}

/// Everything one overview feed establishes about one account.
#[derive(Debug, Clone)]
pub(super) struct Feed {
    /// The canonical casing Reddit holds — see [`TITLE_PREFIX`].
    pub(super) username: String,
    /// `<subtitle>`: the profile's public description, when the account set one.
    pub(super) bio: Option<String>,
    /// Newest first, as served.
    pub(super) items: Vec<Item>,
}

/// Parse an overview feed, or `None` when the document is not one.
///
/// Returning `None` rather than a half-filled [`Feed`] is deliberate: this
/// endpoint is undocumented, so the shape it answers with today is not a
/// promise. If the identifying title and author URI both go missing the honest
/// report is that this module found nothing, not a scan built on a guess about
/// which account the document describes.
pub(super) fn parse(xml: &str) -> Option<Feed> {
    let head_end = xml.find("<entry>").unwrap_or(xml.len());
    let head = &xml[..head_end];
    let items: Vec<Item> = xml[head_end..]
        .split("<entry>")
        .skip(1)
        .filter_map(parse_entry)
        .collect();

    // The author URI fallback lives inside the first entry, which `parse_entry`
    // has already consumed; re-slice the raw text for it.
    let username = username_of(head, xml[head_end..].split("<entry>").nth(1))?;

    let bio = tag_text(head, "subtitle")
        .as_deref()
        .map(decode_entities)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Some(Feed {
        username,
        bio,
        items,
    })
}

/// The account this document is about, from the feed title, falling back to the
/// author URI of the first entry when Reddit changes how it titles the page.
fn username_of(head: &str, first_entry: Option<&str>) -> Option<String> {
    let titled = tag_text(head, "title")
        .and_then(|t| {
            t.strip_prefix(TITLE_PREFIX)
                .map(str::trim)
                .map(str::to_string)
        })
        .filter(|n| is_reddit_username(n));
    if titled.is_some() {
        return titled;
    }
    // `<author><name>/u/spez</name><uri>https://www.reddit.com/user/spez</uri>`
    // — the last path segment of the URI, which carries the same casing.
    let uri = tag_text(first_entry?, "uri")?;
    let name = uri.trim_end_matches('/').rsplit('/').next()?;
    is_reddit_username(name).then(|| name.to_string())
}

/// Reddit's own username grammar: 3–20 of `[A-Za-z0-9_-]`. Shared with the
/// module's pre-flight gate, so a name this rejects is one no request was ever
/// spent on.
fn is_reddit_username(s: &str) -> bool {
    is_handle(s, 3, 20)
}

/// Fold one `<entry>` chunk into an [`Item`].
///
/// A chunk with no closing `</entry>` is a body that was cut short, not an item:
/// its fields are whatever happened to arrive before the connection died.
/// Dropping it keeps the counts every entity below reports — items, comments,
/// posts, the activity window — a count of things the feed actually recorded,
/// rather than one inflated by a fragment.
fn parse_entry(chunk: &str) -> Option<Item> {
    let (chunk, _) = chunk.split_once("</entry>")?;
    let permalink = link_href(chunk).unwrap_or_default().to_string();
    Some(Item {
        kind: ItemKind::of(tag_text(chunk, "id").as_deref().unwrap_or_default()),
        subreddit: subreddit_of(&permalink),
        permalink,
        updated: tag_text(chunk, "updated").unwrap_or_default(),
        html: tag_text(chunk, "content")
            .as_deref()
            .map(decode_entities)
            .unwrap_or_default(),
    })
}

/// The subreddit a permalink sits in: the `{sub}` of `…/r/{sub}/…`.
///
/// Rejects anything outside Reddit's own name grammar rather than reporting it,
/// so a redirect or a reshaped URL yields "no community" instead of a community
/// that does not exist.
pub(super) fn subreddit_of(permalink: &str) -> Option<String> {
    let at = permalink.find("/r/")? + "/r/".len();
    let rest = &permalink[at..];
    let sub = &rest[..rest.find('/').unwrap_or(rest.len())];
    (!sub.is_empty()
        && sub.len() <= MAX_SUBREDDIT_LEN
        && sub
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then(|| sub.to_string())
}

/// The `href` of the first `<link …/>` in an entry — Atom's permalink for it.
fn link_href(entry: &str) -> Option<&str> {
    let at = entry.find("<link")?;
    let open = &entry[at..];
    attr(&open[..open.find('>')?], "href")
}

/// The value of `name="…"` within one already-delimited opening tag.
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let at = tag.find(&needle)? + needle.len();
    let rest = &tag[at..];
    Some(&rest[..rest.find('"')?])
}

/// Text between the first `<tag …>` and its `</tag>`, trimmed.
///
/// Tolerant of attributes on the opening tag (`<content type="html">`) and of a
/// name that is a prefix of a longer one (`<id>` never matches `<icon>`, and
/// would not match a hypothetical `<idlist>`). `None` when either side is
/// absent, so a truncated document yields no field rather than the rest of the
/// file.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = open_tag_end(xml, tag)?;
    let close = xml[open..].find(&format!("</{tag}>"))?;
    Some(xml[open..open + close].trim().to_string())
}

/// Byte offset just past the `>` of the first opening `<tag …>`.
fn open_tag_end(xml: &str, tag: &str) -> Option<usize> {
    let needle = format!("<{tag}");
    let mut cursor = 0usize;
    while let Some(rel) = xml[cursor..].find(&needle) {
        let at = cursor + rel;
        let after = at + needle.len();
        match xml[after..].chars().next() {
            // A real element: the name ends here, at `>` or at whitespace
            // before its attributes.
            Some(c) if c == '>' || c.is_whitespace() => {
                return xml[at..].find('>').map(|gt| at + gt + 1);
            }
            // `<idlist…>` when looking for `<id>` — keep scanning.
            Some(_) => cursor = after,
            None => return None,
        }
    }
    None
}
