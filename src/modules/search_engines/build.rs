//! Search-result → entity construction for [`super::SearchEngines`].
//!
//! Behaviour-preserving extraction from `mod.rs`: `build_entities` keeps its
//! name, signature and logic. The social-host / confirmed-profile classifiers it
//! consults stay in `mod.rs` (also used by the extraction helpers there) and are
//! reached via `super::`.

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

    // Pre-scan: count how many independent engines confirmed each URL.
    // Multi-engine corroboration boosts entity confidence because
    // different engines have different indexes — an independent match
    // is strong evidence of relevance.
    let mut url_engine_count: std::collections::HashMap<String, HashSet<&str>> =
        std::collections::HashMap::new();
    for r in results {
        let key = canonicalize_url(&r.url);
        url_engine_count.entry(key).or_default().insert(r.engine);
    }

    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut seen_phones: HashSet<String> = HashSet::new();
    let target_domain = match target.kind {
        TargetKind::Domain => Some(target.value.to_lowercase()),
        TargetKind::Email => target.value.rsplit_once('@').map(|(_, d)| d.to_lowercase()),
        _ => None,
    };

    let engines_hit: HashSet<&str> = results.iter().map(|r| r.engine).collect();
    let queries_run: HashSet<&str> = results.iter().map(|r| r.query.as_str()).collect();

    // Parent entity with search metadata
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

    for r in results {
        let host = extract_host(&r.url);
        if host.is_empty() {
            continue;
        }

        let domain = extract_registrable(&host);
        let is_subdomain = target_domain
            .as_ref()
            .is_some_and(|td| crate::util::domains::is_proper_subdomain_of(&host, td));

        let n_engines = url_engine_count
            .get(&canonicalize_url(&r.url))
            .map_or(1, |s| s.len() as u32);

        if is_subdomain && seen_domains.insert(host.clone()) {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.70, scan_id);
            e.corroboration = n_engines;
            e.tag(tags::SUBDOMAIN);
            e.tag("search-discovered");
            e.add_evidence(build_search_evidence(r));
            result.push(e);
        } else if matches!(target.kind, TargetKind::Domain)
            // Bare EXTERNAL registrable domains are only a meaningful finding for
            // a DOMAIN seed (relationship/estate discovery). For a person / email
            // / username seed, the SERP host is just where the name happened to
            // appear — an unbounded long tail of irrelevant sites (crazygames.com,
            // csdn.net, mathway.com, funeral notices for a different person) that
            // no blocklist can ever fully cover. The genuinely relevant pages are
            // already captured as Url entities by the path-match gate, so suppress
            // bare external domains entirely for non-domain seeds.
            && target_domain.as_ref().is_none_or(|td| domain != *td)
            && !is_generic_domain(&domain)
            && !is_search_tooling_domain(&domain)
            // A bare SERP-result host that is a mega/social PLATFORM or a freemail
            // provider is never the subject's own asset — it is merely *where* a
            // mention surfaced (the specific profile/page is still kept as a Url
            // entity by the path-match gate). Emitting facebook.com / youtube.com /
            // gmail.com as standalone Domain findings is exactly the generic noise
            // that buries individualised PII; drop it here.
            && !crate::util::domains::is_social_platform(&domain)
            && !crate::util::domains::is_freemail(&domain)
            // Mega platforms and shared infrastructure (whatsapp.com, qq.com,
            // office365.com, blog.google, fast.com, time.is, …) are the haystack
            // a result sits in, never the subject's own asset. The util social/
            // freemail lists miss most of them; core's is_noncentral_domain is
            // the authoritative mega+infra set, so consult it here too.
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

        // Extract emails from title + snippet text
        let combined_text = format!("{} {}", r.title, r.snippet);
        for email in extract_emails_from_text(&combined_text) {
            if crate::util::domains::is_infrastructure_email(&email) {
                continue;
            }
            if seen_emails.insert(email.clone()) {
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
                result.push(e);
            } else if let Some(existing) = result
                .entities
                .iter_mut()
                .find(|e| e.kind == EntityKind::Email && e.value == email)
            {
                existing.confidence = (existing.confidence + 0.10).min(0.85);
                existing.corroboration = existing.corroboration.saturating_add(1);
            }
        }

        for phone in extract_phones_from_text(&combined_text) {
            if seen_phones.insert(phone.clone()) {
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
                result.push(e);
            } else if let Some(existing) = result
                .entities
                .iter_mut()
                .find(|e| e.kind == EntityKind::Phone && e.value == phone)
            {
                existing.confidence = (existing.confidence + 0.12).min(0.80);
                existing.corroboration = existing.corroboration.saturating_add(1);
            }
        }

        // Extract ABN/ACN numbers from snippet text
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

        // Extract organisation names from snippet text
        for org in extract_organisations_from_text(&combined_text, &terms) {
            let org_key = org.to_lowercase();
            if seen_domains.insert(format!("@org:{org_key}")) {
                let mut e = Entity::new(EntityKind::Organisation, &org, 0.45, scan_id);
                e.tag("search-discovered");
                e.add_evidence(build_search_evidence(r));
                result.push(e);
            }
        }

        // Extract addresses from snippet text (geolocation pivot).
        // Confidence is tiered by content richness:
        //   City + State + Postcode → 0.55 (well-localised, AU-specific)
        //   City + State only       → 0.45 (standard locality mention)
        //   AU place contextual     → 0.42 (context-inferred, no explicit state)
        // Corroboration cap for postcode-only / bare addresses is 0.60 to prevent
        // pure suburb mentions reaching Probable (0.75+) via repetition alone.
        for addr in extract_addresses_from_text(&combined_text) {
            let addr_key = format!("@addr:{}", normalise_address_key(&addr));
            let has_postcode = addr
                .split_whitespace()
                .last()
                .is_some_and(|t| t.len() == 4 && t.bytes().all(|b| b.is_ascii_digit()));
            let base_conf = if has_postcode { 0.55 } else { 0.45 };
            // Cap for multi-source merge: postcode-qualified can reach 0.75;
            // bare city+state is capped lower at 0.65 to prevent suburb noise
            // from inflating to Probable via pure repetition.
            let corr_cap = if has_postcode { 0.75 } else { 0.65 };
            if seen_domains.insert(addr_key.clone()) {
                let mut e = Entity::new(EntityKind::Address, &addr, base_conf, scan_id);
                e.tag("search-discovered");
                e.tag(tags::WEB_SCRAPED);
                if has_postcode {
                    e.tag("au-postcode");
                }
                // Attach au-state tag immediately so AU-056 jurisdiction
                // cross-check fires on this address without re-parsing.
                if let Some(state) = crate::util::address_au::state_code(&addr) {
                    e.tag(format!("au-state:{state}"));
                }
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
                result.push(e);
            } else {
                // Address seen before — boost via merge (corroboration increases).
                // Use the normalised key for lookup so "Gatton, QLD" and
                // "Gatton, Queensland" merge rather than forking into two entities.
                let norm = normalise_address_key(&addr);
                if let Some(existing) = result.entities.iter_mut().find(|e| {
                    e.kind == EntityKind::Address && normalise_address_key(&e.value) == norm
                }) {
                    existing.confidence = (existing.confidence + 0.10).min(corr_cap);
                    existing.corroboration = existing.corroboration.saturating_add(1);
                    existing.add_evidence(
                        Evidence::new(
                            "search_engines",
                            format!("[{}] Address corroborated — {}", r.engine, r.url),
                        )
                        .with_attr("url", &r.url)
                        .with_attr("engine", r.engine),
                    );
                }
            }
        }

        // Emit Url entities only for pages whose URL path contains a
        // target-derived term. People-search homepages (spokeo.com/,
        // whitepages.com/people-search) are excluded unless the path
        // also contains a target term — only specific profile pages
        // like peekyou.com/jerome_despal pass.
        if url_matches_target(&r.url, &terms)
            && seen_domains.insert(format!("@url:{}", canonicalize_url(&r.url)))
        {
            // Elevate a CONFIRMED profile — the result URL is the searched
            // username's own page on a canonical social host (handle path ==
            // seed). That's the strongest username-search finding, so emit it at
            // high confidence (Probable→Verified once corroborated) and tag it,
            // distinct from a generic 0.50 page that merely contains the term.
            let confirmed = is_confirmed_profile(target, &r.url, &host);
            // A URL discovered while the *seed itself is a location* (an Address
            // or Coordinates fed back by recursion — e.g. the suburb "Regents
            // Park, QLD") matched a place term, not a person term: it is a
            // generic suburb / real-estate-listing page, not the subject's PII.
            // A live "Haigen Bamford" scan flooded with dozens of
            // realestate.com.au / domain.com.au / suburb-profile pages this way.
            // Demote these to a quarantined candidate (below the 0.50 expansion
            // floor, excluded from confirmed correlation) so they neither inflate
            // results nor recurse into more suburb spam — unless the URL is a
            // confirmed profile, which is identity-bearing regardless of seed.
            let location_seed =
                matches!(target.kind, TargetKind::Address | TargetKind::Coordinates);
            // A code-repo URL that matched only on a repo/file name while its
            // owner handle is unrelated to the target (e.g.
            // `github.com/ExponentiAI/HAIGEN` — an AI project, not the subject's
            // account). The owner is the identity-bearing segment, so this is a
            // wrong-identity match: quarantine it like a generic-location hit.
            let offtarget_repo = is_offtarget_repo_url(&r.url, &terms);
            let base = if confirmed {
                0.85
            } else if location_seed || offtarget_repo {
                0.30
            } else {
                0.50
            };
            let mut e = Entity::new(EntityKind::Url, &r.url, base, scan_id);
            // Credit cross-ENGINE agreement, like the domain branch does: a URL
            // (especially a confirmed profile) independently returned by N engines
            // is far stronger than one from a single engine. Without this the
            // highest-value findings were stuck at base confidence even under
            // unanimous engine agreement; now N engines lift `c_effective` (a
            // confirmed profile + ≥2 engines crosses into the Verified tier).
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

        // Extract usernames and person names from social profile URLs
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
            let people_hosts = [
                "peekyou.com",
                "spokeo.com",
                "nuwber.com",
                "whitepages.com.au",
                "locatefamily.com",
                "peoplefinder.com.au",
                "searchfind.com.au",
                "ancestry.com.au",
            ];
            if people_hosts
                .iter()
                .any(|s| crate::util::domains::is_or_subdomain_of(&host, s))
                && lower_user.contains('_')
                && lower_user.len() >= 5
            {
                let name = username.replace(['_', '-'], " ");
                let name_key = name.to_lowercase();
                // The people-search path encodes a name only if it's the
                // SUBJECT's: these aggregator result pages cross-link to
                // unrelated index entries (a "Haigen Bamford" search surfaced
                // `peekyou.com/_bochary` → a phantom Person "bochary"). Require
                // the extracted name to share a target term before trusting it.
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

    // Extract family members: people sharing the target's last name
    // found in search results (e.g., "Jeanette Despal" when target is
    // "Jerome Despal"). These are high-value geolocation leads.
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

    // Sort entities in a structured order suitable for both human
    // review and LLM consumption: parent entity first (it has the
    // ── Inline geocoding: known AU/world city coordinates ────────────
    // Produce Coordinates entities for addresses that match known cities.
    // This avoids waiting for forward_geocode's Nominatim API call and
    // enables the geo expansion chain immediately.
    {
        let mut seen_coords: HashSet<String> = HashSet::new();
        let addr_snapshot: Vec<(String, f64, u32)> = result
            .entities
            .iter()
            .filter(|e| {
                // All extracted addresses qualify for inline geocoding — the
                // minimum base confidence is now 0.42 so no address falls below
                // this gate. The corroboration bypass (>= 2) is kept for any
                // edge-case address emitted at a lower confidence by other modules.
                e.kind == EntityKind::Address && (e.confidence >= 0.40 || e.corroboration >= 2)
            })
            .map(|e| (e.value.clone(), e.confidence, e.corroboration))
            .collect();
        for (addr, conf, corr) in &addr_snapshot {
            if let Some((lat, lon)) = known_city_coords(addr) {
                let coords = format!("{lat:.4},{lon:.4}");
                if seen_coords.insert(coords.clone()) {
                    // Floor at 0.55: a city match from a search snippet is city-
                    // level precision, comparable to a forward geocode (geocode.rs
                    // emits 0.70 for AU). We use 0.55 as the minimum (not 0.45×0.82
                    // which could sink to 0.37) with a corroboration lift and a cap
                    // at 0.72 (just below the Verified 0.75 threshold — it remains
                    // Probable until a more-authoritative source corroborates).
                    let corr_boost = (*corr as f64 - 1.0).max(0.0) * 0.05;
                    let geo_conf = (conf.max(0.55) + corr_boost).min(0.72);
                    let mut ce = Entity::new(EntityKind::Coordinates, &coords, geo_conf, scan_id);
                    ce.tag("geoint");
                    ce.tag("search-geocoded");
                    // Tag au-state from coordinates so AU-056 jurisdiction
                    // cross-check can fire without re-parsing lat/lon strings.
                    if crate::util::geo::is_in_australia(lat, lon) {
                        ce.tag("au-relevant");
                        if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                            ce.tag(format!("au-state:{state}"));
                        }
                    }
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

    // highest confidence), then by kind priority (identity entities
    // first, infrastructure last), then by descending confidence,
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
