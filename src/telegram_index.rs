//! Bounded, keyless Telegram *public-index* discovery.
//!
//! No native Telegram user session or private-message access is performed.
//! Web-engine hits are URL leads, not verified page content, personal
//! identities, account ownership, membership or family relationships.
//! Parsing is pure; network operations reuse the guarded web-query transport.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::http::Transport;
use crate::public_osint::Report;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

const MAX_TELEGRAM_QUERY_BYTES: usize = 120;

fn checked_telegram_query(raw: &str) -> Result<String, &'static str> {
    if raw.len() > MAX_TELEGRAM_QUERY_BYTES
        || raw.chars().any(|c| c.is_control() || c == '\\')
    {
        return Err("Telegram query must be 1..120 bytes without controls or backslashes");
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Telegram query must not be empty");
    }
    Ok(trimmed.to_owned())
}

/// The safe public Telegram surface indicated by an *indexed URL*, not by
/// reading Telegram itself. It cannot establish who owns a profile or post.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedTelegramUrl {
    /// A stable URL for URL-level de-duplication, not proof that a page exists.
    canonical: String,
    surface: &'static str,
}

/// Canonicalise only unambiguous *public URL shapes*. No web fetch or identity
/// resolution occurs here. Rejecting a URL never proves the target is absent.
/// The hot path borrows path segments and allocates only after validation.
fn telegram_index_surface(url: &str) -> Option<IndexedTelegramUrl> {
    if url.len() > 2048
        || !url.starts_with("https://")
        || url
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\')
    {
        return None;
    }
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let suffix = rest.strip_prefix(authority)?;
    let path = suffix.split(['?', '#']).next()?;

    if matches!(
        authority,
        "tgstat.com" | "www.tgstat.com" | "telemetr.io" | "www.telemetr.io"
    ) {
        // A catalogue landing page, general search form, or leaderboard is
        // not a specific record and must not inflate the discovery count.
        if path.len() > 300 || !path.starts_with('/') || path.contains('%') {
            return None;
        }
        let mut segments = path.strip_prefix('/')?.split('/');
        let first = segments.next()?;
        let second = segments.next()?;
        if first.is_empty()
            || second.is_empty()
            || matches!(first, "." | "..")
            || matches!(second, "." | "..")
            || segments.any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return None;
        }
        if first.eq_ignore_ascii_case("search")
            || first.eq_ignore_ascii_case("ratings")
            || first.eq_ignore_ascii_case("catalog")
            || second.eq_ignore_ascii_case("search")
            || second.eq_ignore_ascii_case("catalog")
        {
            return None;
        }
        let host = if authority.contains("tgstat.com") {
            "tgstat.com"
        } else {
            "telemetr.io"
        };
        return Some(IndexedTelegramUrl {
            canonical: format!("https://{host}{path}"),
            surface: "third_party_directory",
        });
    }

    if !matches!(authority, "t.me" | "telegram.me" | "telegram.dog") {
        return None;
    }
    let mut segments = path.strip_prefix('/')?.split('/');
    let first = segments.next()?;
    let preview = first == "s";
    let handle = if preview { segments.next()? } else { first };
    let message = segments.next();
    if segments.next().is_some() {
        return None;
    }

    // 5..32 ASCII chars and a leading Latin letter are Telegram's public
    // username grammar. These are handles, not names of people.
    const RESERVED: &[&str] = &[
        "c", "joinchat", "share", "addstickers", "proxy", "socks",
        "iv", "login", "boost", "setlanguage", "bg", "invoice",
    ];
    if !(5..=32).contains(&handle.len())
        || !handle.as_bytes()[0].is_ascii_alphabetic()
        || !handle.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || RESERVED.iter().any(|r| handle.eq_ignore_ascii_case(r))
    {
        return None;
    }

    let handle = handle.to_ascii_lowercase();
    if let Some(raw_id) = message {
        // Post zero, blank/negative, extremely long or overflowing numeric
        // tokens are not usable message IDs.
        if raw_id.is_empty()
            || raw_id.len() > 19
            || !raw_id.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let id = raw_id.parse::<u64>().ok().filter(|id| *id > 0)?;
        return Some(IndexedTelegramUrl {
            canonical: format!("https://t.me/{handle}/{id}"),
            surface: "indexed_post_url",
        });
    }
    Some(IndexedTelegramUrl {
        canonical: if preview {
            format!("https://t.me/s/{handle}")
        } else {
            format!("https://t.me/{handle}")
        },
        surface: if preview {
            "indexed_public_preview"
        } else {
            "indexed_handle_url"
        },
    })
}

/// Retain every indexed sighting without turning duplicate URLs from the
/// same discovery family into independent entity corroboration. Generic
/// merge_by_uid intentionally accumulates the input entities' counters, so
/// this path adds evidence directly to the already-seen URL entity instead.
fn push_telegram_index_evidence(
    entities: &mut Vec<Entity>,
    positions: &mut BTreeMap<String, usize>,
    parsed: &IndexedTelegramUrl,
    evidence: Evidence,
    scan_id: &str,
) {
    let mut entity = Entity::new(EntityKind::Url, &parsed.canonical, 0.20, scan_id);
    if let Some(&index) = positions.get(&entity.uid) {
        entities[index].add_evidence(evidence);
    } else {
        entity.tag("telegram_index_lead");
        entity.tag("unverified");
        entity.add_evidence(evidence);
        positions.insert(entity.uid.clone(), entities.len());
        entities.push(entity);
    }
}

/// Keyless Telegram-focused *index* discovery, not a Telegram API session.
/// All network traffic uses Huntsman's guarded web engines. A hit becomes an
/// unverified URL entity only after it passes exact host and path checks.
/// Search-index agreement remains one discovery family, never identity proof.
///
/// # Errors
/// Invalid selectors fail before any request; provider failures retain typed
/// outcome rows and never turn into claims that a person is absent.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    raw_query: &str,
    scan_id: &str,
    now: u64,
) -> Result<Report, &'static str> {
    let query = checked_telegram_query(raw_query)?;
    const COHORTS: [(&str, &str); 4] = [
        ("telegram_preview", "site:t.me/s"),
        ("telegram", "site:t.me"),
        ("tgstat", "site:tgstat.com"),
        ("telemetr", "site:telemetr.io"),
    ];
    let mut entities = Vec::new();
    let mut positions = BTreeMap::new();
    let mut outcomes = Vec::new();
    for (cohort, prefix) in COHORTS {
        let search = format!("{prefix} {query}");
        let found = crate::web_query::search_with_provenance(
            transport,
            &search,
            now,
            crate::web_query::EngineSet::Default,
        );
        let Ok((report, observations)) = found else {
            outcomes.push(SourceExecutionOutcome::inconclusive(
                format!("telegram_index_{cohort}"),
                now,
                "web-query boundary could not execute this cohort",
            ));
            continue;
        };
        // Validate the indexed URL *before* declaring that an engine found an
        // in-scope discovery. An engine can return ordinary out-of-scope links
        // despite the 'site:' term, so raw successful HTML parsing is not a
        // Telegram-index discovery.
        let mut accepted_by_engine = BTreeSet::new();
        // The index did not prove page content, account ownership, family
        // relationships or whether the query occurs on the target page.
        for hit in observations.into_iter().take(75) {
            if let Some(parsed) = telegram_index_surface(&hit.url) {
                accepted_by_engine.insert(hit.engine.clone());
                let evidence = Evidence::new(
                    EvidenceProvenance::for_scan("telegram_web_index", scan_id),
                    "Public-index URL lead; Telegram page and identity not verified",
                )
                .with_attr("source_url", &hit.url)
                .with_attr("discovered_by", &hit.engine)
                .with_attr("query", &search)
                .with_attr("surface", parsed.surface)
                .with_attr("canonical_index_url", &parsed.canonical)
                .with_attr("evidence_role", "indexed_url_only");
                push_telegram_index_evidence(
                    &mut entities,
                    &mut positions,
                    &parsed,
                    evidence,
                    scan_id,
                );
            }
        }
        for mut outcome in report.outcomes {
            let engine = outcome.module.clone();
            outcome.module = format!("telegram_index_{cohort}_{engine}");
            if outcome.kind == SourceOutcomeKind::Success
                && !accepted_by_engine.contains(&engine)
            {
                outcomes.push(SourceExecutionOutcome::inconclusive(
                    outcome.module,
                    now,
                    "raw web hits did not pass the Telegram public-index URL contract",
                ));
            } else {
                outcomes.push(outcome);
            }
        }
    }
    Ok(Report {
        query,
        entities,
        outcomes,
        limitations: vec![
            "Search engines index only a subset of Telegram; no results do not prove absence.",
            "Indexed links are not proof of a post's text or a handle's human owner.",
            "Third-party directories are not independent Telegram primary evidence.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::ScriptedTransport;

    fn html_response(html: &str) -> Response {
        Response {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: html.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn telegram_index_end_to_end_keeps_twelve_sightings_as_one_url_entity() {
        let html = r#"<html><a href="https://telegram.me/CheemsCMNews/132">post</a></html>"#;
        let transport = ScriptedTransport::new(
            (0..12).map(|_| Ok(html_response(html))).collect(),
        );
        let report = search(
            &transport,
            r#""unique-telegram-native-index-contract-20261122""#,
            "s",
            1_000,
        )
        .unwrap();
        assert_eq!(transport.seen.borrow().len(), 12);
        assert_eq!(report.outcomes.len(), 12);
        assert_eq!(report.entities.len(), 1);
        assert_eq!(report.entities[0].value, "https://t.me/cheemscmnews/132");
        assert_eq!(report.entities[0].corroboration, 1);
        assert_eq!(report.entities[0].source_count(), 1);
        assert_eq!(report.entities[0].evidence.len(), 12);
        assert!(report.outcomes.iter().all(|o| o.kind == SourceOutcomeKind::Success));
    }

    #[test]
    fn telegram_index_out_of_scope_web_hits_never_claim_successful_discovery() {
        let html = r#"<html><a href="https://evil.example/out-of-scope">other</a></html>"#;
        let transport = ScriptedTransport::new(
            (0..12).map(|_| Ok(html_response(html))).collect(),
        );
        let report = search(
            &transport,
            "unique-telegram-out-of-scope-url-contract-20261122",
            "s",
            2_000,
        )
        .unwrap();
        assert_eq!(transport.seen.borrow().len(), 12);
        assert!(report.entities.is_empty());
        assert!(report.outcomes.iter().all(|o| o.kind == SourceOutcomeKind::Inconclusive));
    }

    #[test]
    fn telegram_index_rejects_spoofed_private_and_noncanonical_links() {
        for raw in [
            "https://t.me@evil.example/truong",
            "https://t.me.evil.example/truong",
            "https://t.me:443/truong",
            "http://t.me/truong",
            "https://t.me/+PrivateInvite",
            "https://t.me/joinchat/SomeInvite",
            "https://t.me/c/100000/123",
            "https://t.me/share/url",
            "https://t.me/s/",
            "https://t.me/truong/abc",
            "https://t.me/truong/123/456",
            "https://evil.example/?site=t.me/truong",
            "https://tgstat.com.evil.example/channel/1",
            "https://telemetr.io",
        ] {
            assert_eq!(telegram_index_surface(raw), None, "{raw}");
        }
    }

    #[test]
    fn telegram_index_distinguishes_public_link_surfaces_without_owner_attribution() {
        for (raw, expected) in [
            ("https://t.me/TRUONG", "indexed_handle_url"),
            ("https://t.me/s/CheemsCMNews", "indexed_public_preview"),
            ("https://t.me/CheemsCMNews/132", "indexed_post_url"),
            ("https://t.me/s/CheemsCMNews/132", "indexed_post_url"),
            ("https://tgstat.com/channel/123", "third_party_directory"),
            ("https://telemetr.io/en/channels/123", "third_party_directory"),
            ("https://telegram.dog/cheemscmnews", "indexed_handle_url"),
        ] {
            assert_eq!(telegram_index_surface(raw).map(|parsed| parsed.surface), Some(expected), "{raw}");
        }
    }

    #[test]
    fn telegram_index_canonicalises_aliases_and_preview_post_urls() {
        let urls = [
            "https://t.me/CheemsCMNews/00132?single",
            "https://t.me/s/cheemscmnews/132#x",
            "https://telegram.me/CHEEMSCMNEWS/132",
            "https://telegram.dog/cheemscmnews/132",
        ];
        for url in urls {
            let parsed = telegram_index_surface(url).expect(url);
            assert_eq!(parsed.canonical, "https://t.me/cheemscmnews/132");
            assert_eq!(parsed.surface, "indexed_post_url");
        }
        let handle = telegram_index_surface("https://telegram.me/TRUONG?start=1").unwrap();
        assert_eq!(handle.canonical, "https://t.me/truong");
        assert_eq!(handle.surface, "indexed_handle_url");
    }

    #[test]
    fn telegram_index_never_turns_generic_directory_pages_into_entity_leads() {
        for url in [
            "https://tgstat.com/channels/search",
            "https://tgstat.com/ratings/posts",
            "https://tgstat.com/search",
            "https://telemetr.io/en/catalog",
            "https://telemetr.io/en/catalog/global",
            "https://tgstat.com/channel/../../admin",
            "https://t.me/TRUONG/0",
            "https://t.me/TRUONG/18446744073709551616",
            "https://t.me/TRUONG/",
        ] {
            assert_eq!(telegram_index_surface(url), None, "{url}");
        }
    }

    #[test]
    fn telegram_index_duplicate_post_sightings_preserve_provenance_without_false_corroboration() {
        let mut entities = Vec::new();
        let mut positions = BTreeMap::new();
        for (engine, raw) in [
            ("bing", "https://telegram.me/CheemsCMNews/132"),
            ("brave", "https://t.me/s/cheemscmnews/0132?single"),
        ] {
            let parsed = telegram_index_surface(raw).unwrap();
            let evidence = Evidence::new(
                EvidenceProvenance::for_scan("telegram_web_index", "s"),
                "Indexed URL; message content and identity not verified",
            )
            .with_attr("source_url", raw)
            .with_attr("discovered_by", engine);
            push_telegram_index_evidence(
                &mut entities,
                &mut positions,
                &parsed,
                evidence,
                "s",
            );
        }
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].value, "https://t.me/cheemscmnews/132");
        assert_eq!(entities[0].corroboration, 1);
        assert_eq!(entities[0].source_count(), 1);
        assert_eq!(entities[0].evidence.len(), 2);
        assert_eq!(
            entities[0].evidence[0].attributes["source_url"],
            "https://telegram.me/CheemsCMNews/132"
        );
        assert_eq!(
            entities[0].evidence[1].attributes["source_url"],
            "https://t.me/s/cheemscmnews/0132?single"
        );
    }

    #[test]
    fn telegram_index_rejects_invalid_query_before_fetch() {
        let silent = crate::test_support::Silent;
        for query in ["", "bad\nname", "bad\\name"] {
            assert!(search(&silent, query, "s", 1).is_err());
        }
        assert!(search(&silent, &"x".repeat(121), "s", 1).is_err());
    }

}
