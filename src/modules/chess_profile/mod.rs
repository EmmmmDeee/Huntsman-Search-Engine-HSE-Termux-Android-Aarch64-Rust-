//! Free chess-platform profile enrichment over each platform's own public,
//! keyless JSON API — turns a bare username into the self-asserted identity and
//! linked accounts the subject published on their chess profile.
//!
//! A username is the single most common seed this engine sees, and both major
//! chess platforms expose a rich, keyless, exact-match profile API:
//!
//! * **Chess.com** — `GET api.chess.com/pub/player/{username}` (public, no key).
//!   Yields the canonical handle + profile URL, the self-asserted real `name`,
//!   free-text `location`, and `country` (an ISO code in a URL tail). 404 on a
//!   non-existent handle.
//! * **Lichess** — `GET lichess.org/api/user/{username}` (public, no key). Yields
//!   the canonical handle + profile URL and a `profile` block: `realName` (or
//!   `firstName`/`lastName`), `location`, `flag`, `bio`, and — the heavy-tail
//!   value — `links`, the subject's own list of social / personal URLs
//!   (Twitter, YouTube, Mastodon, a personal site, …). 404 on a miss.
//!
//! ## Precision model (why this does not fabricate identity)
//!
//! Both endpoints resolve the handle **exactly** (a miss is a clean 404, never a
//! fuzzy co-hit), mirroring [`crate::modules::gaming_profile`]. So a hit is a
//! precise "this exact handle owns a real chess account" fact, and the canonical
//! `Username` + profile `Url` are emitted at platform-presence confidence.
//!
//! The *self-asserted* fields are treated with deliberate caution:
//! * Each `links` URL is emitted as its own `Url` entity — a first-class,
//!   verifiable pivot the existing correlator (never this module) decides how to
//!   associate, under its own confidence floors.
//! * The self-asserted real name is emitted as a **candidate** `Person` at
//!   medium confidence, so it surfaces as a lead without auto-expanding or
//!   confidently merging into the subject's identity — the same "never Verified
//!   from a self-report" discipline the rest of the platform applies. `location`
//!   / `country` / `bio` ride along as evidence, never as fabricated entities.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "chess_profile";

/// Confidence for a chess account that resolves EXACTLY from the target handle
/// (canonical `Username` + profile `Url`). An exact, keyless platform match with
/// a live public profile — on par with `gaming_profile`'s Minecraft tier; a
/// notch below a dev-platform match because gaming/chess handles collide across
/// people more often than dev handles.
const HANDLE_CONF: f64 = confidence::HIGH_PLUSPLUS_PLUS;

/// Confidence for a social/personal URL the subject listed on their own profile.
/// A self-asserted link is a solid lead but not proof of common ownership — the
/// correlator resolves that — so it sits at plain High, below the handle itself.
const LINK_CONF: f64 = confidence::HIGH;

/// Confidence for the self-asserted real name. Medium and candidate-quarantined:
/// a name someone typed into their own profile is a lead, not a verified
/// identity, and must never auto-expand or merge as if confirmed.
const NAME_CONF: f64 = confidence::MEDIUM;

/// Max characters of a free-text bio carried as evidence — bounds graph/log size.
const BIO_CAP: usize = 200;

pub struct ChessProfile;

#[derive(serde::Deserialize)]
struct ChessComProfile {
    #[serde(default)]
    username: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    location: String,
    /// A URL whose final path segment is an ISO country code, e.g.
    /// `https://api.chess.com/pub/country/US`.
    #[serde(default)]
    country: String,
    #[serde(default)]
    joined: i64,
    #[serde(default)]
    verified: bool,
}

#[derive(serde::Deserialize)]
struct LichessUser {
    #[serde(default)]
    id: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    url: String,
    #[serde(default, rename = "createdAt")]
    created_at: i64,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    profile: LichessProfile,
}

#[derive(serde::Deserialize, Default)]
struct LichessProfile {
    #[serde(default)]
    bio: String,
    #[serde(default, rename = "realName")]
    real_name: String,
    #[serde(default, rename = "firstName")]
    first_name: String,
    #[serde(default, rename = "lastName")]
    last_name: String,
    #[serde(default)]
    location: String,
    #[serde(default)]
    flag: String,
    /// Whitespace / newline separated, and frequently scheme-less
    /// (`github.com/ornicar`).
    #[serde(default)]
    links: String,
}

#[async_trait]
impl Module for ChessProfile {
    fn name(&self) -> &'static str {
        "chess_profile"
    }

    fn description(&self) -> &'static str {
        "Chess-platform profile recon (free) — enriches a username via Chess.com and Lichess public APIs into the self-asserted real name, location, and linked social accounts"
    }

    fn priority(&self) -> u8 {
        // Free social tier, alongside gaming_profile (106) / reddit_user (105).
        106
    }

    fn accepts(&self, t: &Target) -> bool {
        // Chess handles are usernames; the engine already surfaces a person's
        // discovered usernames as their own typed targets for this to consume.
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        // Chess presence is social-media presence.
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Url, EntityKind::Person];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Searching the platforms for a handle is T1593.001 (Search Open
        // Websites/Domains: Social Media). The self-asserted name it can surface
        // is a candidate lead, not employee-name enumeration, so T1589.003 would
        // be over-claimed — same correction as gaming_profile / username_search.
        &["T1593.001"]
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two independent single-GET lookups run concurrently; give a slow mobile
        // link headroom past the 3 s default so neither platform is clipped.
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let v = target.value.trim();
        if !accepts_value(v) {
            return Ok(result);
        }

        // Both platforms queried concurrently; each is best-effort — a failure or
        // miss on one never sinks the other or the module.
        let (chesscom, lichess) = tokio::join!(chesscom_lookup(ctx, v), lichess_lookup(ctx, v));
        result.extend(chesscom);
        result.extend(lichess);

        Ok(result)
    }
}

/// Fetch and parse a Chess.com profile for `username`. Best-effort: any
/// transport / parse failure or a 404 yields an empty batch.
async fn chesscom_lookup(ctx: &ModuleContext, username: &str) -> Vec<Entity> {
    let url = format!("https://api.chess.com/pub/player/{}", urlencode(username));
    match fetch_json_or_404::<ChessComProfile>(&ctx.http, SRC, &url).await {
        Ok(Some(p)) => parse_chesscom(&p, username, &ctx.scan_id),
        Ok(None) => Vec::new(), // no Chess.com account owns this exact handle
        Err(e) => {
            tracing::debug!(error = %e, "chess.com lookup failed");
            Vec::new()
        }
    }
}

/// Fetch and parse a Lichess profile for `username`. Best-effort, same contract.
async fn lichess_lookup(ctx: &ModuleContext, username: &str) -> Vec<Entity> {
    let url = format!("https://lichess.org/api/user/{}", urlencode(username));
    match fetch_json_or_404::<LichessUser>(&ctx.http, SRC, &url).await {
        Ok(Some(u)) => parse_lichess(&u, username, &ctx.scan_id),
        Ok(None) => Vec::new(),
        Err(e) => {
            tracing::debug!(error = %e, "lichess lookup failed");
            Vec::new()
        }
    }
}

/// Build entities from a Chess.com profile. Pure (no I/O) so the parse is unit
/// tested against a real captured response. Guards on an exact handle match so
/// an unexpected upstream shape can't mint an off-target account.
fn parse_chesscom(p: &ChessComProfile, query: &str, scan_id: &str) -> Vec<Entity> {
    let canonical = if p.username.is_empty() {
        query.to_string()
    } else {
        p.username.clone()
    };
    if !canonical.eq_ignore_ascii_case(query) {
        return Vec::new();
    }
    let human_url = if p.url.is_empty() {
        format!("https://www.chess.com/member/{canonical}")
    } else {
        p.url.clone()
    };
    let country = iso_country_from_url(&p.country);

    let mut ev = Evidence::new(SRC, format!("Chess.com account `{canonical}`"))
        .with_attr("profile_url", human_url.as_str())
        .with_attr("source", "chesscom-api");
    if !p.location.trim().is_empty() {
        ev = ev.with_attr("location", p.location.trim());
    }
    if let Some(cc) = &country {
        ev = ev.with_attr("country", cc.as_str());
    }
    if p.joined > 0 {
        ev = ev.with_attr("joined_ts", p.joined.to_string());
    }
    if p.verified {
        ev = ev.with_attr("verified", "true");
    }

    let mut out = Vec::new();
    out.push(handle_entity(
        &canonical,
        HANDLE_CONF,
        scan_id,
        "chesscom",
        ev,
    ));
    out.push(url_entity(
        &human_url,
        HANDLE_CONF,
        scan_id,
        "chesscom",
        format!("Chess.com profile page for `{canonical}`"),
    ));
    if let Some(person) = self_asserted_person(&p.name, scan_id, "chesscom", &canonical) {
        out.push(person);
    }
    out
}

/// Build entities from a Lichess profile. Pure (no I/O) for unit testing.
fn parse_lichess(u: &LichessUser, query: &str, scan_id: &str) -> Vec<Entity> {
    let canonical = [u.username.as_str(), u.id.as_str(), query]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or(query)
        .to_string();
    if !canonical.eq_ignore_ascii_case(query) {
        return Vec::new();
    }
    let human_url = if u.url.is_empty() {
        format!("https://lichess.org/@/{canonical}")
    } else {
        u.url.clone()
    };
    let pr = &u.profile;

    let mut ev = Evidence::new(SRC, format!("Lichess account `{canonical}`"))
        .with_attr("profile_url", human_url.as_str())
        .with_attr("source", "lichess-api");
    if !pr.location.trim().is_empty() {
        ev = ev.with_attr("location", pr.location.trim());
    }
    if !pr.flag.trim().is_empty() {
        ev = ev.with_attr("country", pr.flag.trim());
    }
    let bio = pr.bio.trim();
    if !bio.is_empty() {
        let snippet: String = bio.chars().take(BIO_CAP).collect();
        ev = ev.with_attr("bio", snippet);
    }
    if u.created_at > 0 {
        ev = ev.with_attr("created_ts", u.created_at.to_string());
    }
    if u.disabled {
        ev = ev.with_attr("account_closed", "true");
    }

    let mut out = Vec::new();
    out.push(handle_entity(
        &canonical,
        HANDLE_CONF,
        scan_id,
        "lichess",
        ev,
    ));
    out.push(url_entity(
        &human_url,
        HANDLE_CONF,
        scan_id,
        "lichess",
        format!("Lichess profile page for `{canonical}`"),
    ));

    // Heavy-tail value: each self-listed link is a real, pivotable Url.
    for link in normalise_links(&pr.links) {
        out.push(url_entity(
            &link,
            LINK_CONF,
            scan_id,
            "lichess",
            format!("Link self-listed on Lichess profile `{canonical}`"),
        ));
    }

    // Prefer the single `realName`; fall back to `firstName` + `lastName`.
    let name = if !pr.real_name.trim().is_empty() {
        pr.real_name.clone()
    } else {
        format!("{} {}", pr.first_name.trim(), pr.last_name.trim())
    };
    if let Some(person) = self_asserted_person(&name, scan_id, "lichess", &canonical) {
        out.push(person);
    }
    out
}

/// The canonical-handle `Username` entity for a confirmed chess account.
fn handle_entity(
    canonical: &str,
    conf: f64,
    scan_id: &str,
    platform: &'static str,
    ev: Evidence,
) -> Entity {
    let mut u = Entity::new(EntityKind::Username, canonical, conf, scan_id);
    u.tag("chess");
    u.tag(platform);
    u.tag(tags::SOCIAL_PROFILE);
    u.add_evidence(ev);
    u
}

/// A profile / linked `Url` entity.
fn url_entity(
    url: &str,
    conf: f64,
    scan_id: &str,
    platform: &'static str,
    summary: String,
) -> Entity {
    let mut e = Entity::new(EntityKind::Url, url, conf, scan_id);
    e.tag("chess");
    e.tag(platform);
    e.tag(tags::SOCIAL_PROFILE);
    e.add_evidence(Evidence::new(SRC, summary));
    e
}

/// A **candidate** `Person` from a self-asserted profile name, or `None` when the
/// name is absent / implausible / merely echoes the handle. Candidate-quarantined
/// and medium-confidence on purpose: a self-report is a lead, never a verified
/// identity, so it must not auto-expand or confidently merge.
fn self_asserted_person(
    name: &str,
    scan_id: &str,
    platform: &'static str,
    canonical: &str,
) -> Option<Entity> {
    let name = name.trim();
    // Plausible personal name: has a letter, isn't just the handle again, and is
    // a sane length. Rejects empty, whitespace-only, and handle-echo noise.
    if name.len() < 2
        || name.chars().count() > 80
        || !name.chars().any(char::is_alphabetic)
        || name.eq_ignore_ascii_case(canonical)
    {
        return None;
    }
    let mut p = Entity::new(EntityKind::Person, name, NAME_CONF, scan_id);
    p.tag("chess");
    p.tag(platform);
    p.tag("self-reported");
    p.tag(tags::CANDIDATE);
    p.add_evidence(
        Evidence::new(
            SRC,
            format!("Self-asserted real name on {platform} profile `{canonical}`"),
        )
        .with_attr("self_reported", "true"),
    );
    Some(p)
}

/// Extract the ISO country code from a Chess.com `country` URL
/// (`…/pub/country/US` → `US`). Returns `None` for anything that isn't a short
/// alphabetic code, so a malformed value never becomes a bogus attribute.
fn iso_country_from_url(url: &str) -> Option<String> {
    let code = url.trim_end_matches('/').rsplit('/').next()?;
    (code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()))
        .then(|| code.to_ascii_uppercase())
}

/// Split a Lichess `links` blob into normalised absolute URLs. Tokens are
/// whitespace/newline separated and often scheme-less (`github.com/ornicar`); a
/// missing scheme is filled with `https://`, and only tokens that then parse to
/// a URL with a dotted host survive — so free-text noise never mints a Url.
fn normalise_links(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in raw.split_whitespace() {
        let tok = tok.trim().trim_end_matches([',', ';']);
        if tok.is_empty() {
            continue;
        }
        let candidate = if tok.starts_with("http://") || tok.starts_with("https://") {
            tok.to_string()
        } else {
            format!("https://{tok}")
        };
        let Ok(parsed) = url::Url::parse(&candidate) else {
            continue;
        };
        if parsed.host_str().is_some_and(|h| h.contains('.')) && !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out
}

/// Value-level admission: a chess handle is 2–30 chars, ASCII alphanumeric plus
/// `_`/`-`, with at least one letter. Chess.com allows `-`; Lichess is
/// alphanumeric + `_`. Rejecting all-digit / shapeless seeds keeps a numeric
/// breach id or token from hammering the APIs.
fn accepts_value(v: &str) -> bool {
    let len = v.chars().count();
    (2..=30).contains(&len)
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && v.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
