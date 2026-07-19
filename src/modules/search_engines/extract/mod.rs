//! Post-fetch processing for [`super::SearchEngines`]: lead extraction from the
//! merged result set and live re-query of engines that failed mid-scan.
//!
//! Behaviour-preserving extraction from `mod.rs` (same names/signatures/logic).
//! `mod.rs` re-imports the three entry points it (and `build`) dispatch.

use futures::StreamExt;

use super::fetch::fetch_one;
use super::helpers::*;
use super::{ENGINE_CONCURRENCY, engine_enabled, is_social_host, proven_live_engines};
use crate::core::{
    confidence,
    module::{ModuleContext, ModuleResult},
};

pub(super) async fn recycle_entities(
    ctx: &ModuleContext,
    result: &mut ModuleResult,
    dead_engines: &HashSet<&str>,
    _primary_results: &[SearchResult],
    deadline: std::time::Instant,
) {
    let reliable = proven_live_engines();

    // Pre-allocate based on typical entity count (most pass the confidence filter).
    let mut recycle_queries: Vec<String> = Vec::with_capacity((result.entities.len() / 2).max(4));
    let mut seen_queries: HashSet<String> = HashSet::with_capacity(recycle_queries.capacity());

    for entity in &result.entities {
        if entity.confidence < confidence::LOW {
            continue;
        }
        let q = match entity.kind {
            EntityKind::Email => {
                let local = entity.value.split('@').next().unwrap_or("");
                if local.len() >= 3 {
                    Some(format!("\"{local}\" address OR location OR suburb OR city"))
                } else {
                    None
                }
            }
            EntityKind::Username if entity.value.len() >= 3 => {
                Some(format!("\"{}\" address OR location OR city", entity.value))
            }
            EntityKind::Person => Some(format!("\"{}\" address OR email OR phone", entity.value)),
            EntityKind::Address if entity.confidence >= confidence::LOW => Some(format!(
                "\"{}\" name OR resident OR owner OR phone",
                entity.value
            )),
            EntityKind::Phone => Some(format!("\"{}\" name OR address OR owner", entity.value)),
            EntityKind::Domain if entity.confidence >= confidence::MEDIUM_HIGH => {
                let domain = &entity.value;
                Some(format!(
                    "\"{domain}\" location OR address OR city OR suburb"
                ))
            }
            EntityKind::Organisation if entity.confidence >= confidence::MEDIUM => {
                Some(format!("\"{}\" address OR ABN OR location", entity.value))
            }
            _ => None,
        };
        if let Some(query) = q
            && seen_queries.insert(query.clone())
        {
            recycle_queries.push(query);
        }
    }

    if recycle_queries.is_empty() {
        return;
    }

    let scan_id = result
        .entities
        .first()
        .map(|e| e.scan_id.clone())
        .unwrap_or_default();

    // Flatten the (recycle query × reliable engine) grid into one batch fetched
    // with bounded concurrency — each request self-clamps to the deadline (so the
    // recycler can never overrun the kill timeout, which would discard the whole
    // result, primary findings included), and the batch reaches every job within
    // the reserve budget instead of crawling them serially.
    let mut recycled_results: Vec<SearchResult> = if ctx.cancel.is_cancelled() {
        Vec::new()
    } else {
        let jobs: Vec<_> = recycle_queries
            .iter()
            .take(12)
            .flat_map(|q| {
                reliable
                    .iter()
                    .filter(|e| engine_enabled(e.name) && !dead_engines.contains(e.name))
                    .map(move |e| fetch_one(e, (e.build_url)(q), q.clone(), deadline))
            })
            .collect();
        futures::stream::iter(jobs)
            .buffer_unordered(ENGINE_CONCURRENCY)
            .collect::<Vec<Option<Vec<SearchResult>>>>()
            .await
            .into_iter()
            .flatten()
            .flatten()
            .collect()
    };

    if recycled_results.is_empty() {
        return;
    }
    // Determinism: racy completion order → sort before the dedup/merge.
    recycled_results.sort_by(|a, b| a.engine.cmp(b.engine).then_with(|| a.url.cmp(&b.url)));

    let recycled_results = dedup_results(recycled_results);
    let mut seen_addrs: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut seen_phones: HashSet<String> = HashSet::new();

    // Collect existing entity values to avoid duplicates
    for e in &result.entities {
        match e.kind {
            EntityKind::Address => {
                seen_addrs.insert(e.value.to_lowercase());
            }
            EntityKind::Email => {
                seen_emails.insert(e.value.to_lowercase());
            }
            EntityKind::Phone => {
                seen_phones.insert(e.value.clone());
            }
            _ => {}
        }
    }

    for r in &recycled_results {
        let combined = format!("{} {}", r.title, r.snippet);

        for addr in extract_addresses_from_text(&combined) {
            if seen_addrs.insert(addr.to_lowercase()) {
                let has_postcode = addr
                    .split_whitespace()
                    .last()
                    .is_some_and(|t| t.len() == 4 && t.bytes().all(|b| b.is_ascii_digit()));
                let base_conf = if has_postcode {
                    confidence::MEDIUM_HIGH
                } else {
                    confidence::LOW_MEDIUM
                };
                let mut e = Entity::new(EntityKind::Address, &addr, base_conf, &scan_id);
                e.tag(crate::core::tags::SEARCH_DISCOVERED);
                e.tag("recycled");
                if has_postcode {
                    e.tag("au-postcode");
                }
                if let Some(state) = crate::util::address_au::state_code(&addr) {
                    e.tag(format!("au-state:{state}"));
                }
                e.add_evidence(recycled_evidence(r, "Address", &addr, &combined));
                if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
                    let coord_val = format!("{lat:.4},{lon:.4}");
                    let mut c = Entity::new(
                        EntityKind::Coordinates,
                        &coord_val,
                        base_conf - 0.10,
                        &scan_id,
                    );
                    c.tag("addr-derived");
                    c.tag("geoint");
                    c.tag(crate::core::tags::SEARCH_DISCOVERED);
                    c.tag("recycled");
                    c.add_evidence(recycled_evidence(r, "Coordinates", &coord_val, &combined));
                    result.push(c);
                }
                result.push(e);
            }
        }

        for email in extract_emails_from_text(&combined) {
            if crate::util::domains::is_infrastructure_email(&email) {
                continue;
            }
            if seen_emails.insert(email.clone()) {
                let mut e =
                    Entity::new(EntityKind::Email, &email, confidence::MEDIUM_HIGH, &scan_id);
                e.tag(crate::core::tags::SEARCH_DISCOVERED);
                e.tag("recycled");
                e.add_evidence(recycled_evidence(r, "Email", &email, &combined));
                result.push(e);
            }
        }

        for phone in extract_phones_from_text(&combined) {
            if seen_phones.insert(phone.clone()) {
                let mut e = Entity::new(EntityKind::Phone, &phone, confidence::MEDIUM, &scan_id);
                e.tag(crate::core::tags::SEARCH_DISCOVERED);
                e.tag("recycled");
                e.add_evidence(recycled_evidence(r, "Phone", &phone, &combined));
                result.push(e);
            }
        }
    }
}

/// Build a fully-attributed evidence record for a finding extracted from a
/// recycled search result. Unlike the previous URL-only evidence, this
/// preserves the source page title, a snippet preview, the originating query,
/// and the surrounding text where the value actually appears — so the finding
/// can be manually verified without reconstructing the lost context.
fn recycled_evidence(r: &SearchResult, label: &str, value: &str, combined: &str) -> Evidence {
    // Full-fidelity policy: store the source title and snippet VERBATIM (never
    // truncated) so the operator sees the authentic context the finding came
    // from. Both are already bounded by the search engine's response shape.
    let title: String = r.title.clone();
    let snippet: String = r.snippet.clone();
    let context = extract_surrounding_text(combined, value, 240);
    let mut ev = Evidence::new(
        "search_engines",
        format!(
            "[{}] {} `{}` from recycled search — {}",
            r.engine, label, value, r.url
        ),
    )
    .with_attr("url", &r.url)
    .with_attr("engine", r.engine)
    .with_attr("recycle_query", &r.query);
    if !title.trim().is_empty() {
        ev = ev.with_attr("page_title", title.trim());
    }
    if !snippet.trim().is_empty() {
        ev = ev.with_attr("snippet", snippet.trim());
    }
    if !context.trim().is_empty() {
        ev = ev.with_attr("context", context.trim());
    }
    ev
}

/// Extract family members from search results: people who share the
/// target's last name but have a different first name. These are high-
/// value geolocation and identity leads (same household, same address).
pub(super) fn extract_family_names(
    results: &[SearchResult],
    target: &Target,
) -> Vec<(String, String)> {
    if !matches!(target.kind, TargetKind::FullName | TargetKind::Email) {
        return Vec::new();
    }
    let parts: Vec<&str> = target.value.split_whitespace().collect();
    let lastname = match target.kind {
        // `parts.len() >= 2` guarantees `last()` is Some; match it anyway so
        // the module carries no `unwrap()` that a future refactor could turn
        // into a mid-scan panic.
        TargetKind::FullName if parts.len() >= 2 => match parts.last() {
            Some(last) => last.to_lowercase(),
            None => return Vec::new(),
        },
        TargetKind::Email => {
            let local = target.value.split('@').next().unwrap_or("");
            if local.len() >= 5 {
                // Drop the first CHARACTER (a likely first-initial), not the
                // first byte: a raw `local[1..]` panics on an internationalised
                // local part (e.g. `élise@…`) by splitting the leading codepoint.
                // Then strip a leading separator so the very common
                // `j.smith@…` / `j_smith@…` initial-then-surname forms yield the
                // bare surname (`smith`) — otherwise the retained `.`/`_` made
                // `lastname` (".smith") never equal the alnum-trimmed words it is
                // compared against, so family extraction silently never fired.
                local
                    .chars()
                    .skip(1)
                    .collect::<String>()
                    .trim_start_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase()
            } else {
                return Vec::new();
            }
        }
        _ => return Vec::new(),
    };

    if lastname.len() < 4 {
        return Vec::new();
    }

    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let target_lower = target.value.to_lowercase();
    // The target's own significant terms (≥3 chars), used to reject candidate
    // first names that *embed* the subject's name rather than being a distinct
    // person. A live scan on "Haigen Bamford" surfaced phantom "family members"
    // like "Haigenhaigen Bamford" / "Haigenbhaigen Bamford" — snippet text where
    // the subject's own first name had been doubled/garbled into one token. The
    // `target_lower.contains(first)` guard below only catches a candidate that is
    // a *substring* of the target; these are the reverse (the candidate contains
    // the term), so they slipped through.
    let target_terms: Vec<String> = target_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(str::to_string)
        .collect();

    for r in results {
        // Strip HTML artifacts before scanning for names
        let raw = format!("{} {}", r.title, r.snippet);
        let text = strip_tags(&raw, raw.len());
        let lower = text.to_lowercase();
        let words: Vec<&str> = lower.split_whitespace().collect();
        for window in words.windows(2) {
            let first = window[0].trim_matches(|c: char| !c.is_alphanumeric());
            let last = window[1].trim_matches(|c: char| !c.is_alphanumeric());
            if last != lastname || first.len() < 3 || first.len() > 15 {
                continue;
            }
            if !first.chars().all(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            if target_lower.contains(first) {
                continue;
            }
            // Reject a candidate that embeds one of the subject's own terms
            // (e.g. "haigenhaigen" contains "haigen") — a garbled duplicate of
            // the subject, not a distinct relative.
            if target_terms.iter().any(|t| first.contains(t.as_str())) {
                continue;
            }
            // Reject a first name that is a token doubled onto itself
            // ("fredfred", "annaanna") — snippet garble, never a real given name.
            // The `target_terms` guard above only catches doublings of the
            // SUBJECT's own terms; this catches a doubling of ANY token (a live
            // scan minted "Fredfred Diegmann" from a radaris `/p/Fred/Diegmann/`
            // result whose snippet doubled the first name). ASCII-validated above,
            // so the byte split is codepoint-safe.
            let fb = first.as_bytes();
            if fb.len() >= 6 && fb.len() % 2 == 0 && fb[..fb.len() / 2] == fb[fb.len() / 2..] {
                continue;
            }
            if is_non_name_word(first) {
                continue;
            }
            if !seen.insert(first.to_string()) {
                continue;
            }
            // Title-case by CHAR, not byte: `lastname` is not ASCII-validated
            // (only `first` is, above), so byte slicing it would panic on a
            // multi-byte surname like "Müller".
            let titlecase = |w: &str| -> String {
                let mut c = w.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    None => String::new(),
                }
            };
            let name = format!("{} {}", titlecase(first), titlecase(&lastname));
            found.push((name, r.url.clone()));
        }
    }
    found
}

// ─── Secondary pivot: extract usernames from discovered URLs ──────────────────

/// Matches `(@handle)` in page titles — the canonical form X/Twitter and
/// Instagram use to show "DisplayName (@handle)" in SERP snippets. Compiled
/// once; the capture group is the handle without the `@`.
static TITLE_MENTION_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\(@([A-Za-z0-9_]{2,25})\)").expect("title mention regex")
});

/// Matches a real-name display name before `(@handle)` in social SERP titles —
/// e.g. `"Ryne Manka (@ryno23_) • Instagram Photos and Videos"`. Capture group 1
/// is the name (trailing space included; call `.trim()` on it). Requires each
/// word to start with an uppercase letter so gamertag-only titles like
/// `"Ryno23 (@ZMKCR) / X Posts"` are rejected by the `.is_lowercase()` guard
/// in the caller. Anchored to `^` because the display name is always first.
static TITLE_NAME_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^((?:[A-Z][A-Za-z'.]{0,20} ){1,4})\(@[A-Za-z0-9_]{2,25}\)")
        .expect("title name regex")
});

/// Bio-aggregator hosts: one-page link hubs that people embed in social bios.
/// A search result URL on one of these (or a slug of one in SERP text) is a
/// high-signal cross-platform profile pivot — the same slug typically equals
/// the person's primary username.
const BIO_AGGREGATOR_HOSTS: &[&str] = &[
    "linktr.ee",
    "bio.link",
    "beacons.ai",
    "allmylinks.com",
    "msha.ke",
    "solo.to",
    "bento.me",
    "carrd.co",
    "lnk.bio",
    "campsite.bio",
];

/// Direct-link messaging / community hosts. Sharing a Discord server or
/// Telegram channel in a social bio is a strong identity signal.
const MESSAGING_DIRECT_HOSTS: &[&str] = &["t.me", "discord.gg"];

/// Matches bio aggregator and messaging direct URLs in free text (SERP
/// snippets, page titles) with or without an `https://` prefix.
static BIO_AGGREGATOR_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)(?:https?://)?(?:www\.)?(?P<host>linktr\.ee|bio\.link|beacons\.ai|allmylinks\.com|msha\.ke|solo\.to|bento\.me|carrd\.co|lnk\.bio|campsite\.bio|t\.me|discord\.gg)/(?P<slug>[A-Za-z0-9_.\-]{2,50})"
    )
    .expect("bio aggregator regex")
});

/// Extract potential username pivots from search results. Social
/// profile URLs contain usernames in their path that can be used
/// as secondary search seeds to find cross-platform identity links.
///
/// Also mines `(@handle)` patterns from result titles — the standard
/// format platforms use to disclose the real account handle separately
/// from the display name (e.g. `Ryno23 (@ZMKCR) / Posts / X`).
pub(super) fn extract_username_pivots(results: &[SearchResult], target: &Target) -> Vec<String> {
    let terms = target_terms(target);
    let mut seen = HashSet::new();
    let target_lower = target.value.to_lowercase();
    let mut pivots = Vec::new();

    for r in results {
        let host = extract_host(&r.url);
        if !is_social_host(&host) {
            continue;
        }

        // ── Path-segment pivot ───────────────────────────────────────
        if let Some(username) = extract_path_username(&r.url) {
            let lower = username.to_lowercase();
            if lower.len() >= 3
                && lower != target_lower
                && !is_navigation_path(&lower)
                && seen.insert(lower.clone())
            {
                // Reuse the host computed above instead of recomputing it.
                let (score, _) = score_username(&lower, &host, &terms, r);
                if score >= 3 {
                    pivots.push(format!("\"{username}\""));
                }
            }
        }

        // ── @mention pivot from title ────────────────────────────────
        // Platforms show "DisplayName (@handle)" in page titles; extract
        // the parenthesised handle when the title is confirmed to be about
        // the target (at least one seed term ≥4 chars appears in it).
        // No score gate — title @-mention on a confirmed-target social
        // result is a near-certain cross-platform handle disclosure.
        let title_lower = r.title.to_lowercase();
        if terms
            .iter()
            .filter(|t| t.len() >= 4)
            .any(|t| title_lower.contains(t.as_str()))
        {
            for cap in TITLE_MENTION_RE.captures_iter(&r.title) {
                let handle = &cap[1];
                let lower = handle.to_lowercase();
                if lower.len() >= 2
                    && lower != target_lower
                    && !is_navigation_path(&lower)
                    && seen.insert(lower.clone())
                {
                    pivots.push(format!("\"{handle}\""));
                }
            }
        }
    }
    pivots
}

/// Extract Person entities from social SERP titles in the form
/// `"Name Surname (@handle) • Platform"` (Instagram, X, TikTok, GitHub).
///
/// Guards:
/// - Result URL must be on a social host (rejects ads, blogs, aggregators).
/// - At least one seed term ≥4 chars must appear in the title (confirms the
///   page is about the target, not an incidental mention).
/// - The captured name must contain a lowercase letter (rejects ALL-CAPS
///   banners and gamertag-only display names like `ZMKCR (@ZMKCR)`).
/// - Duplicates are deduplicated by lowercase key within one call.
///
/// Confidence: confidence::HIGH — social title is a near-certain identity disclosure, but
/// display names are not always real names (gamertags, aliases).
pub(super) fn extract_display_names_from_titles(
    results: &[SearchResult],
    target: &Target,
    scan_id: &str,
) -> Vec<Entity> {
    let terms = target_terms(target);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<Entity> = Vec::new();

    for r in results {
        let host = extract_host(&r.url);
        if !is_social_host(&host) {
            continue;
        }
        let title_lower = r.title.to_lowercase();
        if !terms
            .iter()
            .filter(|t| t.len() >= 4)
            .any(|t| title_lower.contains(t.as_str()))
        {
            continue;
        }
        let Some(cap) = TITLE_NAME_RE.captures(&r.title) else {
            continue;
        };
        let raw_name = cap[1].trim().to_string();
        // Reject all-caps / no-lowercase names — gamertags, not real names.
        if !raw_name.chars().any(char::is_lowercase) {
            continue;
        }
        let key = raw_name.to_lowercase();
        if seen.insert(key) {
            let mut e = Entity::new(EntityKind::Person, &raw_name, confidence::HIGH, scan_id);
            e.tag("derived");
            e.tag("social-name");
            e.tag(crate::core::tags::SEARCH_DISCOVERED);
            let ev = Evidence::new(
                SRC,
                format!("[search] display name `{raw_name}` from social SERP title"),
            )
            .with_attr("source_title", &r.title)
            .with_attr("source_url", &r.url)
            .with_attr("engine", r.engine);
            e.add_evidence(ev);
            out.push(e);
        }
    }
    out
}

/// Extract bio-aggregator and direct-messaging URLs from search results.
///
/// Two signals are combined:
///
/// **Signal 1 — result URL is a bio aggregator or messaging host** (confidence::HIGH_PLUS / confidence::HIGH
/// conf): a search engine returned `https://linktr.ee/slug` as a top result.
/// Only emitted when at least one seed term appears in the title+snippet to
/// confirm the page is about the target.
///
/// **Signal 2 — bio URL appears in SERP text** (confidence::HIGH / confidence::MEDIUM_PLUS conf): the SERP
/// snippet or title contains text like `linktr.ee/slug` (with or without
/// `https://`). The URL is reconstructed with an `https://` prefix.
///
/// Both signals deduplicate against the same `seen` set within one call.
pub(super) fn extract_bio_aggregator_urls(
    results: &[SearchResult],
    target: &Target,
    scan_id: &str,
) -> Vec<Entity> {
    let terms = target_terms(target);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<Entity> = Vec::new();

    for r in results {
        let host = extract_host(&r.url);
        let canonical_host = host.strip_prefix("www.").unwrap_or(&host);
        let combined = format!("{} {}", r.title, r.snippet);
        let combined_lower = combined.to_lowercase();

        // Both signals require at least one seed term present in result context.
        if !terms.iter().any(|t| combined_lower.contains(t.as_str())) {
            continue;
        }

        // Signal 1: the result URL itself is a bio aggregator or messaging link.
        let is_bio = BIO_AGGREGATOR_HOSTS.contains(&canonical_host);
        let is_msg = MESSAGING_DIRECT_HOSTS.contains(&canonical_host);
        if is_bio || is_msg {
            let url_str = r.url.trim_end_matches('/').to_string();
            if seen.insert(url_str.to_lowercase()) {
                let conf = if is_msg {
                    confidence::HIGH
                } else {
                    confidence::HIGH_PLUS
                };
                let tag = if is_msg {
                    "messaging-profile"
                } else {
                    "bio-aggregator"
                };
                let mut e = Entity::new(EntityKind::Url, &url_str, conf, scan_id);
                e.tag("social-profile");
                e.tag(crate::core::tags::SEARCH_DISCOVERED);
                e.tag(tag);
                let ev = Evidence::new(
                    SRC,
                    format!("[search] bio link `{url_str}` from SERP result"),
                )
                .with_attr("source_title", &r.title)
                .with_attr("source_url", &r.url)
                .with_attr("engine", r.engine);
                e.add_evidence(ev);
                out.push(e);
            }
        }

        // Signal 2: bio URL mentioned in title or snippet text.
        for cap in BIO_AGGREGATOR_RE.captures_iter(&combined) {
            let slug_host = match cap.name("host") {
                Some(m) => m.as_str(),
                None => continue,
            };
            let slug = match cap.name("slug") {
                Some(m) => m.as_str(),
                None => continue,
            };
            if slug.is_empty() {
                continue;
            }
            let reconstructed = format!("https://{slug_host}/{slug}");
            if seen.insert(reconstructed.to_lowercase()) {
                let is_messaging = MESSAGING_DIRECT_HOSTS.contains(&slug_host);
                let conf = if is_messaging {
                    confidence::MEDIUM_PLUS
                } else {
                    confidence::HIGH
                };
                let tag = if is_messaging {
                    "messaging-profile"
                } else {
                    "bio-aggregator"
                };
                let mut e = Entity::new(EntityKind::Url, &reconstructed, conf, scan_id);
                e.tag("social-profile");
                e.tag(crate::core::tags::SEARCH_DISCOVERED);
                e.tag(tag);
                let ev = Evidence::new(
                    SRC,
                    format!("[search] bio link `{reconstructed}` found in SERP text"),
                )
                .with_attr("source_title", &r.title)
                .with_attr("source_url", &r.url)
                .with_attr("engine", r.engine);
                e.add_evidence(ev);
                out.push(e);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
