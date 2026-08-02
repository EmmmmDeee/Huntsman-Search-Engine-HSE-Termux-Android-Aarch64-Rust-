//! Reddit account recon from the public user overview feed (free, keyless).
//!
//! `GET https://www.reddit.com/user/{name}/.rss`
//!
//! # Why this module was rebuilt
//! It used to read `https://www.reddit.com/user/{name}/about.json`, which is
//! what every Reddit OSINT recipe still recommends. Verified live in July 2026,
//! that endpoint — and `submitted.json` beside it, and the `old.reddit.com`
//! spelling of both — answers **HTTP 403 to any client that is not an
//! authenticated OAuth application**, regardless of `User-Agent`. Reddit closed
//! the anonymous JSON API. Because 403 was read as "no such user", the module
//! did not fail loudly: it returned nothing, on every scan, silently. That is
//! the worst failure mode a source can have, and it is the gap this closes.
//!
//! The Atom feed is the one keyless path still open. Verified live: `.rss`
//! answers **200** for a real account and **404** for one that does not exist,
//! which is a clean existence oracle. It is undocumented, so its shape is not a
//! promise — [`feed::parse`] returns nothing rather than guessing when the
//! document stops looking like an overview feed.
//!
//! # What the feed carries, and what was lost
//! It is strictly richer than the dead listing on the things that matter for
//! pivoting: it holds **comments as well as posts** — the majority of most
//! accounts' community footprint, which `submitted.json` never showed — plus the
//! profile description, per-item timestamps, permalinks and full item bodies,
//! and Reddit's own casing of the name (`/user/SPEZ/.rss` answers `overview for
//! spez`, so a mis-cased seed resolves to one identity rather than minting a
//! second).
//!
//! Karma, account creation date, `verified` and `is_gold` are **gone** and are
//! not recoverable without an authenticated key. They are therefore not
//! reported, not estimated and not implied; [`COVERAGE_CAVEAT`] says so on the
//! account's own evidence, because an operator who remembers the old output will
//! otherwise read their absence as "this account has none".
//!
//! # Recursion, as this codebase adopts it
//! One dispatch reads one account's feed. Depth comes from the engine
//! re-dispatching what this returns rather than from a call stack here: a bio
//! domain is picked up by the DNS and certificate band, a bio email by the
//! breach band, and the canonical username by the whole social band — including
//! this module, which will resolve the corrected casing afresh. Posted links are
//! deliberately graded **below** the expansion floor so a URL someone merely
//! quoted never seeds a walk of its own.
//!
//! Every item body — and the bio — is also run through the universal
//! `found_keys`/`key_harvest` classifier ([`harvest`]): redditors paste code
//! snippets, and snippets occasionally carry a live key. No extra fetch; the
//! bytes are already in memory.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, UA_OSINT, read_text, urlencode};
use crate::util::str_util::is_handle;

mod feed;
mod harvest;
mod transform;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "reddit_user";

/// Root of a Reddit profile URL. The feed is this plus `/.rss`.
const PROFILE_BASE: &str = "https://www.reddit.com/user";

/// Hosts Reddit itself serves. A link to one of these is a link to shared
/// platform infrastructure, not to anything belonging to the account, so
/// [`transform`] drops them instead of reporting them as associated domains.
const REDDIT_HOSTS: &[&str] = &[
    "reddit.com",
    "redd.it",
    "redditstatic.com",
    "redditmedia.com",
    "reddituploads.com",
];

/// Cap on distinct off-Reddit links turned into entities for one account.
///
/// A feed holds at most 25 items, but a single item can hold arbitrarily many
/// links, so this one enumeration is genuinely unbounded and needs a cap. It
/// never fires silently — the withheld count is stamped onto the account's
/// evidence and logged, the discipline `plc_directory`'s `MAX_HANDLES` and
/// `gleif_lei`'s `MAX_CHILDREN` follow.
const MAX_POSTED_LINKS: usize = 40;

/// The feed answering 200 at all is proof the account exists, under the name the
/// document itself gives. Matches what the old `about.json` path graded the same
/// finding, so nothing downstream sees this rebuild as a downgrade.
const ACCOUNT_CONF: f64 = confidence::VERY_HIGH_PLUS;

/// An email in the profile description. The account published it about itself in
/// the one field it controls and signs, which is as strong as an unverified
/// contact address gets from a social profile.
///
/// Replaces a magic `0.76` literal that sat between two named constants for no
/// reason anyone recorded.
const BIO_EMAIL_CONF: f64 = confidence::VERY_HIGH;

/// A link in the profile description — self-published, so above the expansion
/// floor and worth walking.
const BIO_URL_CONF: f64 = confidence::HIGH_PLUS;

/// The host of a bio link. One step derived from the URL, graded one step below
/// it: the account chose the link, not necessarily the whole domain (a link to a
/// shared host is not ownership of that host).
const BIO_DOMAIN_CONF: f64 = confidence::HIGH;

/// A community the account was observed in.
///
/// Low on purpose and not adjustable from here: within one feed window a single
/// throwaway comment and a decade of moderating look exactly alike, so any
/// higher grade would be asserting an involvement the evidence cannot separate.
const SUBREDDIT_CONF: f64 = confidence::LOW;

/// A URL the account posted. **Below** [`confidence::MEDIUM`], the noisy-OR
/// expansion floor, deliberately: quoting a link is not owning it, and a
/// recursive walk seeded from every URL a redditor ever pasted would drown the
/// scan in other people's infrastructure.
const POSTED_URL_CONF: f64 = confidence::LOW;

/// The host of a posted URL — the weakest thing this module emits, and the
/// furthest from the subject.
const POSTED_DOMAIN_CONF: f64 = confidence::VERY_LOW;

/// Rides on the account entity. States what this endpoint cannot see, because
/// the absence of a field is not evidence that the field is empty.
const COVERAGE_CAVEAT: &str = "Sourced from the public Atom feed, which serves at most the 25 most \
     recent items. Counts and dates below describe THAT WINDOW ONLY and are not the account's \
     lifetime totals; an older or busier account is under-represented. Karma, account creation \
     date, premium and verified status are NOT available without an authenticated Reddit API key \
     and are therefore absent rather than zero.";

/// Rides on everything mined from the profile description.
const BIO_ATTRIBUTION: &str = "Published by the account holder in their own profile description, \
     which is the strongest self-attribution Reddit offers without identity verification. It is \
     still self-asserted: a profile can name a contact the holder does not control.";

/// Rides on every community entity.
const SUBREDDIT_CAVEAT: &str = "Observed in the recent-activity window only. A single comment and \
     years of moderation are indistinguishable from here, so this records PRESENCE in the \
     community, not membership, affiliation or standing.";

/// Rides on every posted link and its host.
const POSTED_LINK_CAVEAT: &str = "Linked by this account in a post or comment. Sharing a URL is \
     not owning, operating or endorsing it — most links redditors post are to third parties. \
     Graded below the expansion threshold so it is reported without seeding further automated \
     queries.";

pub struct RedditUser;

#[async_trait]
impl Module for RedditUser {
    fn name(&self) -> &'static str {
        "reddit_user"
    }

    fn description(&self) -> &'static str {
        "Reddit account recon via the public user feed (free, keyless) — confirms the account and its canonical name, and surfaces its profile description, recent communities, activity window and posted links"
    }

    fn priority(&self) -> u8 {
        105
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default (T1593.001 Social Media + T1589.003 Employee Names).
        // Reddit profiles carry no real-name Person entity — only a username and
        // optionally an email/URL from the profile. T1589.003 is over-claimed;
        // T1589.002 (Email Addresses) is the correct addition for profile emails.
        &["T1589.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        6_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // Reddit usernames are 3–20 chars of [A-Za-z0-9_-]. Reject anything else
        // before the round-trip; the value is also interpolated into a path, so
        // this is a security gate and not only a cost saving.
        if !is_handle(handle, 3, 20) {
            return Ok(ModuleResult::new());
        }

        let Some(xml) = fetch_feed(ctx, handle).await? else {
            return Ok(ModuleResult::new());
        };
        let Some(feed) = feed::parse(&xml) else {
            return Ok(ModuleResult::new());
        };

        // Key mining is a side effect on a process-wide pool, kept out of
        // `transform` so that file stays a pure function of the feed — the whole
        // point of the split.
        harvest::mine_feed(&feed);

        let mut out = ModuleResult::new();
        out.extend(transform::feed_to_entities(&feed, &ctx.scan_id));
        Ok(out)
    }
}

/// Fetch one account's overview feed.
///
/// `Ok(None)` is a clean miss: a 404 means no such account, which is the answer
/// this module exists to give and must not be reported as a failure. Any other
/// non-success is also `Ok(None)` — there is nothing to parse — but is logged,
/// because a blanket 403 is exactly how this module died the first time and the
/// next time it happens the log should say so.
async fn fetch_feed(ctx: &ModuleContext, handle: &str) -> Result<Option<String>> {
    let url = format!("{PROFILE_BASE}/{}/.rss", urlencode(handle));
    let resp = ctx
        .http
        .get(&url)
        // Reddit rate-limits anonymous clients hard and by identity; a
        // descriptive UA is what keeps a research tool distinguishable from a
        // scraper it would rather throttle.
        .header("User-Agent", UA_OSINT)
        // Declare that we are fetching a feed, which is the honest truth: this
        // endpoint IS an Atom document, and a real feed reader always says so.
        // reqwest sends no `Accept` by default, and an edge that fronts Reddit
        // treats "no stated interest in anything" as a bot tell — so the header
        // is both more correct and less likely to be turned away at the door.
        // Not fingerprint evasion: it changes nothing a residential client would
        // not already send, and the block that bit the live smoke test was on
        // the TLS client fingerprint, which no header can (or should) touch.
        .header(
            "Accept",
            "application/atom+xml, application/rss+xml, application/xml;q=0.9, */*;q=0.8",
        )
        .send_tagged(SRC)
        .await?;

    let status = resp.status();
    if !status.is_success() {
        if status != reqwest::StatusCode::NOT_FOUND {
            tracing::warn!(
                "{SRC}: {url} answered HTTP {status} — no findings for u/{handle} from this source"
            );
        }
        return Ok(None);
    }

    let xml = read_text(SRC, resp).await?;
    // `read_text` does not archive, so record it here: the feed IS the source
    // document behind every finding below, and the dossier's raw-source section
    // has to be able to show it.
    crate::util::raw_archive::record_http(SRC, &url, &xml);
    Ok(Some(xml))
}
