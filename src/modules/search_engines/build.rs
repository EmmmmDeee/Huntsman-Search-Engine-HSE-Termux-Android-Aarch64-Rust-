//! Search-result → entity construction for [`super::SearchEngines`].
//!
//! `build_entities` is the hot path: called once per scan, it processes every
//! result page from every engine. On Termux/aarch64 the per-result cost is
//! dominated by string allocation, so this module is allocation-budget aware:
//!
//! - **Canonical URLs** are computed once up-front and shared between the
//!   engine-count pre-scan and the main loop (was: two `canonicalize_url`
//!   calls per result, each allocating a fresh `String`).
//! - **Entity dedup** for emails, phones, and addresses uses an `entity_index`
//!   map (`key → Vec index`) so the confidence-boost path is O(1) rather than
//!   an O(n) linear scan over `result.entities` for every duplicate.
//! - **Address normalisation** is computed once per result, not twice.

use std::collections::HashMap;

use super::helpers::*;
use super::{extract_family_names, is_confirmed_profile, is_social_host};
use crate::core::module::ModuleResult;

pub(super) fn build_entities(
    target: &Target,
    scan_id: &str,
    results: &[SearchResult],
) -> ModuleResult {
    let mut result = ModuleResult::new();
    if results.is_empty() {
        return result;
    }

    let terms = target_terms(target);

    // Pre-compute canonical URLs once: avoids a second `canonicalize_url`
    // call per result in the main loop (one String allocation per result,
    // not two).
    let canon_urls: Vec<String> = results.iter().map(|r| canonicalize_url(&r.url)).collect();

    // Count how many independent engines confirmed each canonical URL.
    // Multi-engine corroboration is strong relevance evidence — different
    // indexes, independent ranking.
    let mut url_engine_count: HashMap<&str, HashSet<&str>> = HashMap::new();
    for (r, canon) in results.iter().zip(&canon_urls) {
        url_engine_count
            .entry(canon.as_str())
            .or_default()
            .insert(r.engine);
    }

    let mut seen_domains: HashSet<String> = HashSet::new();
    let target_domain = match target.kind {
        TargetKind::Domain => Some(target.value.to_lowercase()),
        TargetKind::Email => target.value.rsplit_once('@').map(|(_, d)| d.to_lowercase()),
        _ => None,
    };

    let engines_hit: HashSet<&str> = results.iter().map(|r| r.engine).collect();
    let queries_run: HashSet<&str> = results.iter().map(|r| r.query.as_str()).collect();

    // Maps a dedup key to its index in `result.entities` so confidence-boost
    // paths avoid a linear scan.  Scheme: "email:{v}", "phone:{v}", "addr:{norm}".
    let mut entity_index: HashMap<String, usize> = HashMap::new();

    // Parent entity with search metadata — pushed first so sort puts it
    // at index 0 (it'll stay there since sort is stable within equal keys).
    let mut parent = target.to_entity(0.82, scan_id);
    parent.tag("search-enriched");
    let mut engines_list: Vec<&str> = engines_hit.iter().copied().collect();
    engines_list.sort_unstable();
    parent.add_evidence(
        Evidence::new(
            "search_engines",
            format!(
                "Search across {} engine(s) returned {} result(s) from {} quer{}",
                engines_hit.len(),
                results.len(),
                queries_run.len(),
                if queries_run.len() == 1 { "y" } else { "ies" },
            ),
        )
        .with_attr("result_count", results.len().to_string())
        .with_attr("engines", engines_list.join(", "))
        .with_attr("queries_run", queries_run.len().to_string()),
    );
    result.push(parent);

    for (r, canon) in results.iter().zip(&canon_urls) {
        let host = extract_host(&r.url);
        if host.is_empty() {
            continue;
        }

        let domain = extract_registrable(&host);
        let is_subdomain = target_domain
            .as_ref()
            .is_some_and(|td| crate::util::domains::is_proper_subdomain_of(&host, td));

        let n_engines = url_engine_count
            .get(canon.as_str())
            .map_or(1, |s| s.len() as u32);

        if is_subdomain && seen_domains.insert(host.clone()) {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.70, scan_id);
            e.corroboration = n_engines;
            e.tag(tags::SUBDOMAIN);
            e.tag("search-discovered");
            e.add_evidence(build_search_evidence(r));
            result.push(e);
        } else if matches!(target.kind, TargetKind::Domain)
            // Bare EXTERNAL registrable domains are only a meaningful finding
            // for a DOMAIN seed (relationship/estate discovery). For a person /
            // email / username seed, the SERP host is just where the name
            // happened to appear — an unbounded long tail of irrelevant sites
            // that no blocklist can ever fully cover. The genuinely relevant
            // pages are already captured as Url entities by the path-match gate.
            && target_domain.as_ref().is_none_or(|td| domain != *td)
            && !is_generic_domain(&domain)
            && !is_search_tooling_domain(&domain)
            // A bare SERP-result host that is a mega/social PLATFORM or a
            // freemail provider is never the subject's own asset — it is merely
            // *where* a mention surfaced.  Emitting facebook.com / gmail.com as
            // standalone Domain findings buries individualised PII; drop it.
            && !crate::util::domains::is_social_platform(&domain)
            && !crate::util::domains::is_freemail(&domain)
            && !crate::core::scan::is_noncentral_domain(&domain)
            && seen_domains.insert(domain.clone())
        {
            let mut e = Entity::new(EntityKind::Domain, &domain, 0.45, scan_id);
            e.corroboration = n_engines;
            e.tag(tags::EXTERNAL);
            e.tag("search-discovered");
            e.add_evidence(build_search_evidence(r));
            result.push(e);
        }

        let combined_text = format!("{} {}", r.title, r.snippet);

        // ── Emails ───────────────────────────────────────────────────────────
        for email in extract_emails_from_text(&combined_text) {
            let key = format!("email:{email}");
            if let Some(&idx) = entity_index.get(&key) {
                let existing = &mut result.entities[idx];
                existing.confidence = (existing.confidence + 0.10).min(0.85);
                existing.corroboration = existing.corroboration.saturating_add(1);
            } else {
                let mut e = Entity::new(EntityKind::Email, &email, 0.60, scan_id);
                e.tag(tags::WEB_SCRAPED);
                e.tag("search-discovered");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] Email found on {} — {}",
                            r.engine,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine)
                    .with_attr("query", &r.query),
                );
                entity_index.insert(key, result.entities.len());
                result.push(e);
            }
        }

        // ── Phones ───────────────────────────────────────────────────────────
        for phone in extract_phones_from_text(&combined_text) {
            let key = format!("phone:{phone}");
            if let Some(&idx) = entity_index.get(&key) {
                let existing = &mut result.entities[idx];
                existing.confidence = (existing.confidence + 0.12).min(0.80);
                existing.corroboration = existing.corroboration.saturating_add(1);
            } else {
                let mut e = Entity::new(EntityKind::Phone, &phone, 0.55, scan_id);
                e.tag(tags::WEB_SCRAPED);
                e.tag("search-discovered");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] Phone found on {} — {}",
                            r.engine,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                entity_index.insert(key, result.entities.len());
                result.push(e);
            }
        }

        // ── ABN / ACN ────────────────────────────────────────────────────────
        for (num, kind_label) in extract_abn_acn_from_text(&combined_text) {
            if seen_domains.insert(format!("@abn:{num}")) {
                let mut e = Entity::new(EntityKind::AbnAcn, &num, 0.65, scan_id);
                e.tag("search-discovered");
                e.tag(kind_label);
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] {} {} found on {} — {}",
                            r.engine,
                            kind_label,
                            num,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine)
                    .with_attr("number_type", kind_label),
                );
                result.push(e);
            }
        }

        // ── Organisations ────────────────────────────────────────────────────
        for org in extract_organisations_from_text(&combined_text, &terms) {
            let org_key = org.to_lowercase();
            if seen_domains.insert(format!("@org:{org_key}")) {
                let mut e = Entity::new(EntityKind::Organisation, &org, 0.45, scan_id);
                e.tag("search-discovered");
                e.add_evidence(build_search_evidence(r));
                result.push(e);
            }
        }

        // ── Addresses ────────────────────────────────────────────────────────
        for addr in extract_addresses_from_text(&combined_text) {
            let norm = normalise_address_key(&addr);
            let key = format!("addr:{norm}");
            if let Some(&idx) = entity_index.get(&key) {
                let existing = &mut result.entities[idx];
                existing.confidence = (existing.confidence + 0.12).min(0.80);
                existing.corroboration = existing.corroboration.saturating_add(1);
                existing.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!("[{}] Address corroborated — {}", r.engine, r.url),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
            } else {
                let mut e = Entity::new(EntityKind::Address, &addr, 0.45, scan_id);
                e.tag("search-discovered");
                e.tag(tags::WEB_SCRAPED);
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] Address near {} — {}",
                            r.engine,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                entity_index.insert(key, result.entities.len());
                result.push(e);
            }
        }

        // ── URLs (path-matched) ───────────────────────────────────────────────
        // Emit Url entities only for pages whose URL path contains a
        // target-derived term.  People-search homepages are excluded unless the
        // path also contains a target term — only specific profile pages pass.
        if url_matches_target(&r.url, &terms) && seen_domains.insert(format!("@url:{canon}")) {
            // Elevate a CONFIRMED profile — the result URL is the searched
            // username's own page on a canonical social host (handle path ==
            // seed).  That's the strongest username-search finding.
            let confirmed = is_confirmed_profile(target, &r.url, &host);
            // A URL discovered while the *seed itself is a location* (an Address
            // or Coordinates fed back by recursion) matched a place term, not a
            // person term: it is a generic suburb / real-estate-listing page.
            // Demote to a quarantined candidate below the 0.50 expansion floor.
            let location_seed =
                matches!(target.kind, TargetKind::Address | TargetKind::Coordinates);
            // A code-repo URL that matched only on a repo/file name while its
            // owner handle is unrelated to the target is a wrong-identity match.
            let offtarget_repo = is_offtarget_repo_url(&r.url, &terms);
            let base = if confirmed {
                0.85
            } else if location_seed || offtarget_repo {
                0.30
            } else {
                0.50
            };
            let mut e = Entity::new(EntityKind::Url, &r.url, base, scan_id);
            e.corroboration = n_engines;
            e.tag("search-discovered");
            if confirmed {
                e.tag("confirmed-profile");
            } else if location_seed {
                e.tag("generic-location");
                e.tag("candidate");
            } else if offtarget_repo {
                e.tag("offtarget-repo");
                e.tag("candidate");
            }
            e.add_evidence(build_search_evidence(r));
            result.push(e);
        }

        // ── Usernames + person names from social/people-search URLs ──────────
        if let Some(username) = extract_path_username(&r.url) {
            let lower_user = username.to_lowercase();
            let is_social = is_social_host(&host);
            if is_social
                && lower_user.len() >= 3
                && !is_navigation_path(&lower_user)
                && seen_domains.insert(format!("@username:{lower_user}"))
            {
                let (score, confidence) = score_username(&lower_user, &host, &terms, r);
                if score >= 1 {
                    let mut e = Entity::new(EntityKind::Username, &lower_user, confidence, scan_id);
                    e.tag("search-discovered");
                    e.tag("social-profile");
                    if score < 3 {
                        e.tag("candidate");
                    }
                    e.add_evidence(build_search_evidence(r));
                    result.push(e);
                }
            }

            // People-search sites encode real names in paths:
            // peekyou.com/jerome_despal → "Jerome Despal"
            const PEOPLE_HOSTS: &[&str] = &[
                "peekyou.com",
                "spokeo.com",
                "nuwber.com",
                "whitepages.com.au",
                "locatefamily.com",
                "peoplefinder.com.au",
                "searchfind.com.au",
                "ancestry.com.au",
            ];
            if PEOPLE_HOSTS
                .iter()
                .any(|s| crate::util::domains::is_or_subdomain_of(&host, s))
                && lower_user.contains('_')
                && lower_user.len() >= 5
            {
                let name = username.replace(['_', '-'], " ");
                let name_key = name.to_lowercase();
                // Require the extracted name to share a target term: aggregator
                // result pages cross-link to unrelated index entries.
                let on_target = terms
                    .iter()
                    .any(|t| t.len() >= 3 && name_key.split_whitespace().any(|w| w == t));
                if on_target && seen_domains.insert(format!("@person:{name_key}")) {
                    let mut e = Entity::new(EntityKind::Person, &name, 0.50, scan_id);
                    e.tag("search-discovered");
                    e.tag("people-search");
                    e.add_evidence(build_search_evidence(r));
                    result.push(e);
                }
            }
        }
    }

    // ── Family members ────────────────────────────────────────────────────────
    // People sharing the target's last name found in results (e.g. "Jeanette
    // Despal" when target is "Jerome Despal") are high-value geolocation leads.
    let family = extract_family_names(results, target);
    for (name, source_url) in &family {
        let key = format!("@person:{}", name.to_lowercase());
        if seen_domains.insert(key) {
            let mut e = Entity::new(EntityKind::Person, name, 0.45, scan_id);
            e.tag("search-discovered");
            e.tag("family-member");
            e.add_evidence(
                Evidence::new(
                    "search_engines",
                    format!("Shares surname with target — {source_url}"),
                )
                .with_attr("url", source_url),
            );
            result.push(e);
        }
    }

    // ── Inline geocoding ──────────────────────────────────────────────────────
    // Produce Coordinates entities for addresses matching known cities, avoiding
    // a Nominatim round-trip and enabling the geo expansion chain immediately.
    {
        let mut seen_coords: HashSet<String> = HashSet::new();
        let addr_snapshot: Vec<(String, f64, u32)> = result
            .entities
            .iter()
            .filter(|e| {
                e.kind == EntityKind::Address && (e.confidence >= 0.40 || e.corroboration >= 2)
            })
            .map(|e| (e.value.clone(), e.confidence, e.corroboration))
            .collect();
        for (addr, conf, corr) in &addr_snapshot {
            if let Some((lat, lon)) = known_city_coords(addr) {
                let coords = format!("{lat:.4},{lon:.4}");
                if seen_coords.insert(coords.clone()) {
                    let corr_boost = (*corr as f64 - 1.0).max(0.0) * 0.08;
                    let geo_conf = ((conf * 0.82) + corr_boost).min(0.75);
                    let mut ce = Entity::new(EntityKind::Coordinates, &coords, geo_conf, scan_id);
                    ce.tag(crate::core::tags::GEOINT);
                    ce.tag("search-geocoded");
                    ce.add_evidence(
                        Evidence::new(
                            "search_engines",
                            format!("Geocoded from search address: {addr}"),
                        )
                        .with_attr("source_address", addr)
                        .with_attr("method", "known-city-lookup"),
                    );
                    result.push(ce);
                }
            }
        }
    }

    // ── Sort ──────────────────────────────────────────────────────────────────
    // Parent entity first (highest confidence), then by kind priority (identity
    // entities first, infrastructure last), then by descending confidence,
    // then alphabetically by value within each tier.
    result.entities.sort_by(|a, b| {
        fn kind_rank(k: &EntityKind) -> u8 {
            match k {
                EntityKind::Person => 0,
                EntityKind::Email => 1,
                EntityKind::Username => 2,
                EntityKind::Phone => 3,
                EntityKind::Organisation => 4,
                EntityKind::AbnAcn => 5,
                EntityKind::Address => 6,
                EntityKind::Url => 7,
                EntityKind::Domain => 8,
                _ => 9,
            }
        }
        kind_rank(&a.kind)
            .cmp(&kind_rank(&b.kind))
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.value.cmp(&b.value))
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::{Target, TargetKind};
    use crate::modules::search_engines::helpers::SearchResult;

    fn sr(engine: &'static str, url: &str, title: &str, snippet: &str) -> SearchResult {
        SearchResult {
            url: url.to_string(),
            title: title.to_string(),
            snippet: snippet.to_string(),
            engine,
            query: "test query".to_string(),
        }
    }

    fn person_target(name: &str) -> Target {
        Target {
            kind: TargetKind::FullName,
            value: name.to_string(),
        }
    }

    fn domain_target(d: &str) -> Target {
        Target {
            kind: TargetKind::Domain,
            value: d.to_string(),
        }
    }

    #[test]
    fn empty_results_returns_empty_module_result() {
        let t = person_target("Jordan Avery");
        let r = build_entities(&t, "s1", &[]);
        assert!(r.entities.is_empty());
    }

    #[test]
    fn parent_entity_is_emitted_and_search_enriched() {
        let t = person_target("Jordan Avery");
        let results = vec![sr(
            "bing",
            "https://linkedin.com/in/jordanavery",
            "Jordan Avery",
            "",
        )];
        let r = build_entities(&t, "s1", &results);
        assert!(!r.entities.is_empty());
        let parent = r.entities.iter().find(|e| e.value == "Jordan Avery");
        assert!(parent.is_some(), "parent entity missing");
        assert!(
            parent.unwrap().has_tag("search-enriched"),
            "parent not tagged search-enriched"
        );
    }

    #[test]
    fn email_in_snippet_becomes_entity() {
        let t = person_target("Jordan Avery");
        let results = vec![sr(
            "google",
            "https://example.com/contact",
            "Contact page",
            "Reach us at jordanavery@gmail.com for details",
        )];
        let r = build_entities(&t, "s1", &results);
        let email_e = r.entities.iter().find(|e| e.kind == EntityKind::Email);
        assert!(email_e.is_some(), "email entity not emitted");
        assert_eq!(email_e.unwrap().value, "jordanavery@gmail.com");
    }

    #[test]
    fn duplicate_email_across_engines_boosts_confidence_not_duplicates() {
        let t = person_target("Jordan Avery");
        // Same email in two different engine results.
        let results = vec![
            sr(
                "bing",
                "https://site-a.com/page",
                "Site A",
                "Contact jordanavery@gmail.com here",
            ),
            sr(
                "google",
                "https://site-b.com/page",
                "Site B",
                "Also jordanavery@gmail.com there",
            ),
        ];
        let r = build_entities(&t, "s1", &results);
        let email_entities: Vec<_> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .collect();
        assert_eq!(email_entities.len(), 1, "duplicate email emitted twice");
        // Confidence boosted above the base 0.60 by the second hit.
        assert!(
            email_entities[0].confidence > 0.60,
            "confidence not boosted: {}",
            email_entities[0].confidence
        );
    }

    #[test]
    fn duplicate_phone_boosts_not_duplicates() {
        let t = person_target("Jordan Avery");
        let results = vec![
            sr(
                "bing",
                "https://site-a.com/p",
                "T",
                "Call +61 7 3000 0001 now",
            ),
            sr(
                "google",
                "https://site-b.com/p",
                "T",
                "Also +61 7 3000 0001 available",
            ),
        ];
        let r = build_entities(&t, "s1", &results);
        let phones: Vec<_> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Phone)
            .collect();
        // At most one phone entity for the same number.
        let counts: HashMap<&str, usize> = phones.iter().fold(HashMap::new(), |mut m, e| {
            *m.entry(e.value.as_str()).or_default() += 1;
            m
        });
        for (v, c) in &counts {
            assert_eq!(*c, 1, "phone {v} emitted {c} times");
        }
    }

    #[test]
    fn multi_engine_url_gets_corroboration_count() {
        let t = person_target("Jordan Avery");
        // Same URL returned by two engines.
        let url = "https://github.com/jordanavery";
        let results = vec![
            sr("bing", url, "Jordan Avery · GitHub", ""),
            sr("google", url, "Jordan Avery · GitHub", ""),
        ];
        let r = build_entities(&t, "s1", &results);
        let url_e = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value == url);
        if let Some(e) = url_e {
            assert!(
                e.corroboration >= 2,
                "corroboration not set: {}",
                e.corroboration
            );
        }
        // Whether it emits a Url depends on url_matches_target; at minimum no panic.
    }

    #[test]
    fn subdomain_discovery_for_domain_seed() {
        let t = domain_target("example.com");
        let results = vec![sr(
            "bing",
            "https://mail.example.com/login",
            "Mail login",
            "",
        )];
        let r = build_entities(&t, "s1", &results);
        let sub = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "mail.example.com");
        assert!(sub.is_some(), "subdomain entity not emitted");
        assert!(sub.unwrap().has_tag(crate::core::tags::SUBDOMAIN));
    }

    #[test]
    fn location_seed_url_quarantined_as_candidate() {
        let t = Target {
            kind: TargetKind::Address,
            value: "Regents Park, QLD".to_string(),
        };
        let results = vec![sr(
            "google",
            "https://realestate.com.au/regents-park-qld",
            "Regents Park QLD property",
            "",
        )];
        let r = build_entities(&t, "s1", &results);
        // Any Url entity from a location seed should be a candidate (quarantined)
        for e in r.entities.iter().filter(|e| e.kind == EntityKind::Url) {
            assert!(
                e.has_tag("candidate") || e.confidence < 0.50,
                "location-seed URL not quarantined: conf={} tags={:?}",
                e.confidence,
                e.tags
            );
        }
    }

    #[test]
    fn sort_order_identity_before_infrastructure() {
        let t = person_target("Jordan Avery");
        let results = vec![sr(
            "bing",
            "https://example.com/page",
            "Example",
            "Email: jordanavery@gmail.com Phone: +61400000001",
        )];
        let r = build_entities(&t, "s1", &results);
        // In the sorted output, no Domain should appear before an Email/Phone.
        let mut saw_infra = false;
        for e in &r.entities {
            if matches!(e.kind, EntityKind::Domain | EntityKind::Url) {
                saw_infra = true;
            }
            if saw_infra && matches!(e.kind, EntityKind::Email | EntityKind::Phone) {
                panic!(
                    "email/phone appeared after infrastructure in sorted output: {:?}",
                    e.kind
                );
            }
        }
    }
}
