//! Post-fetch processing for [`super::SearchEngines`]: lead extraction from the
//! merged result set and live re-query of engines that failed mid-scan.
//!
//! Behaviour-preserving extraction from `mod.rs` (same names/signatures/logic).
//! `mod.rs` re-imports the three entry points it (and `build`) dispatch.

use super::engines::reliable_engines;
use super::fetch::fetch_and_parse;
use super::helpers::*;
use super::{INTER_ENGINE_MS, engine_enabled, is_social_host};
use crate::core::module::{ModuleContext, ModuleResult};

pub(super) async fn recycle_entities(
    ctx: &ModuleContext,
    result: &mut ModuleResult,
    dead_engines: &HashSet<&str>,
    _primary_results: &[SearchResult],
) {
    let reliable = reliable_engines();

    let mut recycle_queries: Vec<String> = Vec::new();
    let mut seen_queries: HashSet<String> = HashSet::new();

    for entity in &result.entities {
        if entity.confidence < 0.40 {
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
            EntityKind::Address if entity.confidence >= 0.40 => Some(format!(
                "\"{}\" name OR resident OR owner OR phone",
                entity.value
            )),
            EntityKind::Phone => Some(format!("\"{}\" name OR address OR owner", entity.value)),
            EntityKind::Domain if entity.confidence >= 0.55 => {
                let domain = &entity.value;
                Some(format!(
                    "\"{domain}\" location OR address OR city OR suburb"
                ))
            }
            EntityKind::Organisation if entity.confidence >= 0.50 => {
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

    let mut recycled_results: Vec<SearchResult> = Vec::new();

    for query in recycle_queries.iter().take(12) {
        if ctx.cancel.is_cancelled() {
            break;
        }
        for engine in &reliable {
            if !engine_enabled(engine.name) {
                continue;
            }
            if ctx.cancel.is_cancelled() {
                break;
            }
            if dead_engines.contains(engine.name) {
                continue;
            }
            let url = (engine.build_url)(query);
            if let Some(mut results) = fetch_and_parse(&url, engine, query, None).await {
                recycled_results.append(&mut results);
            }
            tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
        }
    }

    if recycled_results.is_empty() {
        return;
    }

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
                let mut e = Entity::new(EntityKind::Address, &addr, 0.45, &scan_id);
                e.tag("search-discovered");
                e.tag("recycled");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!("[{}] Address from recycled search — {}", r.engine, r.url),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine)
                    .with_attr("recycle_query", &r.query),
                );
                result.push(e);
            }
        }

        for email in extract_emails_from_text(&combined) {
            if seen_emails.insert(email.clone()) {
                let mut e = Entity::new(EntityKind::Email, &email, 0.55, &scan_id);
                e.tag("search-discovered");
                e.tag("recycled");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!("[{}] Email from recycled search — {}", r.engine, r.url),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                result.push(e);
            }
        }

        for phone in extract_phones_from_text(&combined) {
            if seen_phones.insert(phone.clone()) {
                let mut e = Entity::new(EntityKind::Phone, &phone, 0.50, &scan_id);
                e.tag("search-discovered");
                e.tag("recycled");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!("[{}] Phone from recycled search — {}", r.engine, r.url),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                result.push(e);
            }
        }
    }
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

// ─── Secondary pivot: extract usernames from discovered URLs ────────────────

/// Extract potential username pivots from search results. Social
/// profile URLs contain usernames in their path that can be used
/// as secondary search seeds to find cross-platform identity links.
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
        if let Some(username) = extract_path_username(&r.url) {
            let lower = username.to_lowercase();
            if lower.len() >= 3
                && lower != target_lower
                && !is_navigation_path(&lower)
                && seen.insert(lower.clone())
            {
                let (score, _) = score_username(&lower, &extract_host(&r.url), &terms, r);
                if score >= 3 {
                    pivots.push(format!("\"{username}\""));
                }
            }
        }
    }
    pivots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sr(title: &str, snippet: &str) -> SearchResult {
        SearchResult {
            url: "https://example.com/x".to_string(),
            title: title.to_string(),
            snippet: snippet.to_string(),
            engine: "test",
            query: "q".to_string(),
        }
    }

    fn names(results: &[SearchResult], target: &Target) -> Vec<String> {
        extract_family_names(results, target)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn fullname_finds_same_surname_different_first_name() {
        let target = Target::new(TargetKind::FullName, "John Smith");
        let results = [sr("Jane Smith and John Smith", "live in Brisbane")];
        // Jane Smith surfaced; the target John Smith is excluded.
        assert_eq!(names(&results, &target), vec!["Jane Smith"]);
    }

    #[test]
    fn email_initial_dot_surname_now_matches() {
        // Regression: `j.smith@…` must derive the surname `smith`. Before the
        // leading-separator strip, lastname was ".smith" and matched nothing.
        let target = Target::new(TargetKind::Email, "j.smith@example.com");
        let results = [sr("Robert Smith profile", "")];
        assert_eq!(names(&results, &target), vec!["Robert Smith"]);
    }

    #[test]
    fn email_initialsurname_without_separator_still_matches() {
        let target = Target::new(TargetKind::Email, "jsmith@example.com");
        let results = [sr("Robert Smith", "")];
        assert_eq!(names(&results, &target), vec!["Robert Smith"]);
    }

    #[test]
    fn short_surname_is_rejected() {
        // Surname < 4 chars (here "fox") yields nothing — too noisy to pivot on.
        let target = Target::new(TargetKind::FullName, "John Fox");
        let results = [sr("Jane Fox", "")];
        assert!(names(&results, &target).is_empty());
    }

    #[test]
    fn deduplicates_and_titlecases_multibyte_surname() {
        // "Müller" surname must not panic (char-wise title-casing) and repeats
        // collapse to one.
        let target = Target::new(TargetKind::FullName, "Hans Müller");
        let results = [
            sr("anna müller", "anna müller again"),
            sr("anna müller", ""),
        ];
        assert_eq!(names(&results, &target), vec!["Anna Müller"]);
    }

    #[test]
    fn non_fullname_non_email_kinds_yield_nothing() {
        let target = Target::new(TargetKind::Username, "smithy");
        let results = [sr("Jane Smith", "")];
        assert!(extract_family_names(&results, &target).is_empty());
    }
}
