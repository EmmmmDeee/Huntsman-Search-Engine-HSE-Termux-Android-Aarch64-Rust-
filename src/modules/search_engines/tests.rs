//! Unit tests for the live search-engine scrapers.
//!
//! Split out of the module file (mechanical, behaviour-preserving) so the
//! source reads as implementation; tests reach private items via `use super::*`.

use super::queries::{Region, build_queries_fullname, regional_dorks};
use super::*;

#[test]
fn accepts_all_supported_kinds() {
    let m = SearchEngines;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
    assert!(m.accepts(&Target::new(TargetKind::Email, "x")));
    assert!(m.accepts(&Target::new(TargetKind::Username, "x")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "x")));
    assert!(m.accepts(&Target::new(TargetKind::Phone, "x")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "x")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "x")));
    assert!(m.accepts(&Target::new(TargetKind::Asn, "x")));
    assert!(m.accepts(&Target::new(TargetKind::Address, "x")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "x")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "http://x.com")));
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
}

#[test]
fn termux_budget_is_trimmed_below_desktop_and_the_cap() {
    let m = SearchEngines;
    // Desktop budget stays generous; Termux budget is strictly tighter and
    // at/under the engine's 45 s Termux cap so it is honoured verbatim
    // (the module then finalises partials just under that deadline).
    assert_eq!(m.max_timeout_ms(), 120_000);
    assert_eq!(m.termux_timeout_ms(), 30_000);
    assert!(m.termux_timeout_ms() < m.max_timeout_ms());
    assert!(m.termux_timeout_ms() <= 45_000);
    // The proportional reserve preserves desktop behaviour exactly (the old
    // flat 30 s) while staying sane under the trimmed Termux budget.
    let reserve = |budget: u64| (budget / 4).max(8_000);
    assert_eq!(reserve(120_000), 30_000);
    assert_eq!(reserve(30_000), 8_000);
    // Primary pass must retain a positive working window under both budgets.
    assert!(120_000_u64.saturating_sub(reserve(120_000)) > 0);
    assert!(30_000_u64.saturating_sub(reserve(30_000)) >= 20_000);
}

#[test]
fn build_queries_address_produces_dorks() {
    let t = Target::new(TargetKind::Address, "123 Main St, Springfield");
    let q = build_queries(&t);
    assert!(q.len() >= 2);
    assert!(q[0].contains("\"123 Main St, Springfield\""));
}

#[test]
fn build_queries_fullname_handles_multibyte_initial() {
    // Regression: a 3+-token name whose first token lowercases to a
    // multi-byte char must not panic the first-initial extraction (was
    // `&first.to_lowercase()[..1]`, which split the codepoint).
    let qs = build_queries_fullname("Ψ Alpha Β");
    assert!(qs.len() > 2, "3-part name expands");
    assert!(qs.iter().all(|s| !s.is_empty()));
}

#[test]
fn build_queries_fullname_pure_fn_matches_dispatch() {
    // The extracted pure helper must produce exactly what the FullName
    // dispatch arm produces (verbatim extraction, no behaviour change).
    let direct = build_queries_fullname("Jordan Lee Meyer");
    let viadispatch = build_queries(&Target::new(TargetKind::FullName, "Jordan Lee Meyer"));
    assert_eq!(direct, viadispatch);

    // Single-token name → only the two base dorks, no first/last expansion.
    let single = build_queries_fullname("Jordan");
    assert_eq!(single.len(), 2, "single token → 2 base queries: {single:?}");

    // Three-part name unlocks the AU registries + middle-name username pattern.
    assert!(direct.len() > 15, "multi-part name → rich dork set");
    assert!(direct.iter().any(|s| s.contains("ahpra.gov.au")));
    assert!(direct.iter().any(|s| s.contains("profile OR account")));
    assert!(direct.iter().all(|s| !s.is_empty()));
}

#[test]
fn build_queries_asn_normalises_prefix() {
    let t = Target::new(TargetKind::Asn, "13335");
    let q = build_queries(&t);
    assert!(q.iter().any(|qr| qr.contains("AS13335")));
}

#[test]
fn build_queries_abn_extracts_digits() {
    let t = Target::new(TargetKind::AbnAcn, "51 824 753 556");
    let q = build_queries(&t);
    assert!(q.iter().any(|qr| qr.contains("51824753556")));
}

#[test]
fn build_queries_url_extracts_host() {
    let t = Target::new(TargetKind::Url, "https://example.com/page");
    let q = build_queries(&t);
    assert!(q.iter().any(|qr| qr.contains("site:example.com")));
}

#[test]
fn build_queries_coordinates_splits_lat_lon() {
    let t = Target::new(TargetKind::Coordinates, "-33.86,151.20");
    let q = build_queries(&t);
    assert!(q.len() >= 2);
    assert!(q[0].contains("-33.86"));
    assert!(q[0].contains("151.20"));
}

#[test]
fn detect_region_only_fires_on_clear_au_signals() {
    let r = |k, v| detect_region(&Target::new(k, v));
    // Clear AU signals → Au.
    assert_eq!(r(TargetKind::AbnAcn, "51824753556"), Some(Region::Au));
    assert_eq!(r(TargetKind::Domain, "abc.net.au"), Some(Region::Au));
    assert_eq!(
        r(TargetKind::Url, "https://www.abc.net.au/news"),
        Some(Region::Au)
    );
    assert_eq!(
        r(TargetKind::Email, "person@example.com.au"),
        Some(Region::Au)
    );
    assert_eq!(r(TargetKind::Phone, "+61 2 9374 4000"), Some(Region::Au));
    assert_eq!(
        r(TargetKind::Organisation, "Acme Pty Ltd, Sydney NSW"),
        Some(Region::Au)
    );
    // No region signal → None (stays geo-neutral even when regional is on).
    assert_eq!(r(TargetKind::Username, "kylo4kylo"), None);
    assert_eq!(r(TargetKind::Domain, "example.com"), None);
    assert_eq!(r(TargetKind::FullName, "Jane Citizen"), None);
    assert_eq!(r(TargetKind::Email, "a@gmail.com"), None);
}

#[test]
fn regional_dorks_are_minimal_and_region_scoped() {
    // AU phone → a ccTLD-scoped dork + one regional directory dork.
    let d = regional_dorks(&Target::new(TargetKind::Phone, "+61 2 9374 4000"));
    assert!(d.len() <= 2, "regional augmentation must stay minimal");
    assert!(
        d.iter()
            .any(|q| q.contains("site:com.au") && q.contains("site:gov.au"))
    );
    assert!(d.iter().any(|q| q.contains("whitepages.com.au")));
    // AU-focused default: a region-less seed still gets AU-scoped dorks (the
    // `.au` ccTLD dork at minimum), so every scan favours Australian sources.
    let dd = regional_dorks(&Target::new(TargetKind::Username, "kylo4kylo"));
    assert!(
        dd.iter().any(|q| q.contains("site:com.au")),
        "region-less seed should default to AU dorks, got {dd:?}"
    );
    // Still minimal.
    assert!(dd.len() <= 2, "AU-default augmentation must stay minimal");
    // An empty value never produces dorks.
    assert!(regional_dorks(&Target::new(TargetKind::Username, "")).is_empty());
}

#[test]
fn address_extractor_finds_city_state_pattern() {
    let text = "Jordan lives in Nundah, Queensland with his family";
    let addrs = extract_addresses_from_text(text);
    assert!(
        addrs
            .iter()
            .any(|a| a.contains("Nundah") && a.contains("Queensland")),
        "should find Nundah, Queensland: {addrs:?}"
    );
}

#[test]
fn address_extractor_finds_qld_suburb_with_context() {
    let text = "Originally from Redcliffe QLD, now living in Caboolture";
    let addrs = extract_addresses_from_text(text);
    assert!(
        addrs.iter().any(|a| a.contains("Redcliffe")),
        "should find Redcliffe with QLD context: {addrs:?}"
    );
}

#[test]
fn address_extractor_finds_brisbane_with_australia() {
    let text = "Based in Brisbane, Australia. Working at ACME Corp.";
    let addrs = extract_addresses_from_text(text);
    assert!(
        !addrs.is_empty(),
        "should find Brisbane with Australia context"
    );
}

#[test]
fn address_extractor_finds_au_postcode() {
    let text = "Lives at Nundah, Queensland 4012";
    let addrs = extract_addresses_from_text(text);
    assert!(
        addrs.iter().any(|a| a.contains("4012")),
        "should extract 4-digit AU postcode: {addrs:?}"
    );
}

#[test]
fn address_key_collapses_postcode_variants() {
    // Regression from a live self-scan: one suburb surfaced as BOTH
    // "Murrumbateman, NSW" and "Murrumbateman, NSW 2582", becoming two Address
    // entities for a single place (AU-018 then reported a person co-located with
    // "2" addresses). The dedup key (build.rs) must fold "City, STATE" and
    // "City, STATE POSTCODE" together so the variants — even from two different
    // search results — collapse into one entity.
    assert_eq!(
        normalise_address_key("Murrumbateman, NSW"),
        normalise_address_key("Murrumbateman, NSW 2582"),
    );
    // US 5-digit ZIP folds too.
    assert_eq!(
        normalise_address_key("Springfield, Illinois"),
        normalise_address_key("Springfield, Illinois 62704"),
    );
    // A leading street number (also numeric) is NOT stripped — only the trailing
    // postcode is — so two genuinely different street addresses stay distinct.
    assert_ne!(
        normalise_address_key("12 Mary St, Brisbane QLD"),
        normalise_address_key("99 Mary St, Brisbane QLD"),
    );
}

#[test]
fn address_extractor_ignores_non_au_4digit() {
    let text = "Error code 1234 in the system at Houston, Texas";
    let addrs = extract_addresses_from_text(text);
    assert!(
        !addrs.iter().any(|a| a.contains("1234")),
        "should not extract non-AU 4-digit number as postcode: {addrs:?}"
    );
}

#[test]
fn build_queries_domain_produces_five_dorks() {
    let t = Target::new(TargetKind::Domain, "acme.com");
    let q = build_queries(&t);
    assert!(q.len() >= 9);
    // Bare site:{v} removed (50% block rate, 27% hit rate in live scans);
    // operator-enriched site: patterns are first now.
    assert!(q[0].contains("filetype:pdf") && q[0].contains("site:acme.com"));
    assert!(q[1].contains("@acme.com"));
    assert!(q[2].contains("login"));
    assert!(q.iter().any(|s| s.contains("link:acme.com")));
}

#[test]
fn build_queries_email_produces_social_pivots() {
    let t = Target::new(TargetKind::Email, "user@acme.com");
    let q = build_queries(&t);
    assert!(q.len() >= 2);
    assert!(q[0].contains("\"user@acme.com\""));
    assert!(q.iter().any(|qr| qr.contains("github.com")));
}

#[test]
fn build_queries_username_covers_social_platforms() {
    let t = Target::new(TargetKind::Username, "johndoe");
    let q = build_queries(&t);
    // Broad → narrow: ≥16 dorks, universal first, platform site: dorks last.
    assert!(q.len() >= 16, "expected ≥16 dorks, got {}", q.len());
    // Tier 1 — universal lead: the broadest two queries carry no `site:`.
    assert_eq!(
        q[0], "johndoe",
        "first query must be the bare handle (broadest)"
    );
    assert_eq!(q[1], "\"johndoe\"", "second must be the exact-match phrase");
    assert!(
        !q[0].contains("site:") && !q[1].contains("site:"),
        "universal searches must come before seed-specific site: dorks"
    );
    // Tier 2 — intent narrowing.
    assert!(q[2].contains("profile"));
    // Tier 3 — engine-syntax operators (title/URL presence of the handle).
    assert!(
        q.iter()
            .any(|qr| qr.contains("intitle:") && qr.contains("inurl:")),
        "must include intitle:/inurl: engine-syntax dorks"
    );
    // Tier 4 — platform coverage retained (now after the universal lead).
    assert!(q.iter().any(|qr| qr.contains("github.com")));
    assert!(
        q.iter()
            .any(|qr| qr.contains("twitter.com") && qr.contains("reddit.com"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("peekyou.com") || qr.contains("nuwber.com"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("vk.com") && qr.contains("ok.ru"))
    );
    assert!(q.iter().any(|qr| qr.contains("t.me")));
    assert!(
        q.iter()
            .any(|qr| qr.contains("steamcommunity.com") || qr.contains("twitch.tv"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("whatsmyname.app") || qr.contains("namecheckr.com"))
    );
}

#[test]
fn build_queries_username_avoids_blank_queries() {
    let q = build_queries(&Target::new(TargetKind::Username, "alice"));
    for qr in &q {
        assert!(!qr.trim().is_empty(), "blank query in: {q:?}");
        assert!(qr.contains("alice"), "missing target in: {qr}");
    }
}

#[test]
fn build_queries_phone_includes_new_reverse_id_and_messengers() {
    let t = Target::new(TargetKind::Phone, "+1-234-567-8900");
    let q = build_queries(&t);
    // Should include the new NumBuster / GetContact group and the
    // WhatsApp / Telegram messenger dork.
    assert!(
        q.iter()
            .any(|qr| qr.contains("numbuster.com") || qr.contains("getcontact.com"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("wa.me") || qr.contains("t.me"))
    );
}

#[test]
fn build_queries_email_includes_new_breach_and_paste_dorks() {
    let t = Target::new(TargetKind::Email, "alice@target-company.com.au");
    let q = build_queries(&t);
    // Breach corpora dork
    assert!(
        q.iter()
            .any(|qr| qr.contains("leakcheck.io") || qr.contains("snusbase.com"))
    );
    // Paste-site dork
    assert!(
        q.iter()
            .any(|qr| qr.contains("pastebin.com") || qr.contains("paste.ee"))
    );
    // Credential-presence dork
    assert!(
        q.iter()
            .any(|qr| qr.contains("password") || qr.contains("credentials"))
    );
}

#[test]
fn build_queries_fullname_includes_post_soviet_socials_and_gaming() {
    let t = Target::new(TargetKind::FullName, "Ivan Petrov");
    let q = build_queries(&t);
    assert!(
        q.iter()
            .any(|qr| qr.contains("vk.com") && qr.contains("ok.ru"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("t.me") || qr.contains("steamcommunity.com"))
    );
}

#[test]
fn build_queries_fullname_covers_professional() {
    let t = Target::new(TargetKind::FullName, "Jane Doe");
    let q = build_queries(&t);
    assert!(q.len() >= 8, "expected >=8 queries, got {}", q.len());
    assert!(q[0].contains("\"Jane Doe\""));
    assert!(q[1].contains("linkedin.com") || q[1].contains("facebook.com"));
    assert!(
        q.iter()
            .any(|qr| qr.contains("instagram.com") || qr.contains("github.com"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("email") || qr.contains("contact") || qr.contains("profile"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("peekyou.com") || qr.contains("nuwber.com"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("courts") || qr.contains("austlii"))
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("abc.net.au") || qr.contains("news.com.au"))
    );
}

#[test]
fn build_queries_fullname_three_parts_generates_username_variants() {
    let t = Target::new(TargetKind::FullName, "Jordan Leigh Meyers");
    let q = build_queries(&t);
    assert!(
        q.iter()
            .any(|qr| qr.contains("jordanmeyers") || qr.contains("jleighmeyers")),
        "should generate username variants from 3-part name: {q:?}"
    );
    assert!(
        q.iter().any(|qr| qr.contains("\"Jordan Meyers\"")),
        "should search first+last without middle: {q:?}"
    );
    assert!(
        q.iter()
            .any(|qr| qr.contains("Queensland") || qr.contains("Brisbane")),
        "should include AU geo dorks: {q:?}"
    );
}

#[test]
fn build_queries_ip_produces_infra_dorks() {
    let t = Target::new(TargetKind::IpAddress, "8.8.8.8");
    let q = build_queries(&t);
    assert!(q.len() >= 6);
    assert!(q[0].contains("\"8.8.8.8\""));
    assert!(q.iter().any(|qr| qr.contains("shodan.io")));
}

#[test]
fn build_queries_org_produces_business_dorks() {
    let t = Target::new(TargetKind::Organisation, "BHP Group");
    let q = build_queries(&t);
    assert!(q.len() >= 5);
    assert!(q[0].contains("\"BHP Group\""));
    assert!(q.iter().any(|qr| qr.contains("ABN") || qr.contains("ACN")));
    assert!(
        q.iter()
            .any(|qr| qr.contains("abr.business.gov.au") || qr.contains("opencorporates"))
    );
}

#[test]
fn resolve_href_decodes_ddg_uddg() {
    let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc123";
    let resolved = resolve_href(href);
    assert_eq!(resolved.as_deref(), Some("https://example.com/page"));
}

#[test]
fn resolve_href_decodes_yahoo_ru() {
    let href = "https://r.search.yahoo.com/_ylt=Awr/RV=2/RE=123/RO=10/RU=https%3a%2f%2fsoundcloud.com%2fjerome-despal/RK=2/RS=abc123-";
    let resolved = resolve_href(href);
    assert_eq!(
        resolved.as_deref(),
        Some("https://soundcloud.com/jerome-despal")
    );
}

#[test]
fn resolve_href_handles_protocol_relative() {
    let href = "//cdn.example.com/file.js";
    assert_eq!(
        resolve_href(href).as_deref(),
        Some("https://cdn.example.com/file.js")
    );
}

#[test]
fn resolve_href_passes_absolute_urls() {
    assert_eq!(
        resolve_href("https://example.com").as_deref(),
        Some("https://example.com")
    );
}

#[test]
fn resolve_href_rejects_relative_paths() {
    assert!(resolve_href("/page").is_none());
    assert!(resolve_href("page.html").is_none());
}

#[test]
fn href_iter_handles_both_quote_styles() {
    let html = r#"<a href="https://a.com">A</a> <a href='https://b.com'>B</a>"#;
    let links: Vec<&str> = HrefIter::new(html).collect();
    assert_eq!(links, vec!["https://a.com", "https://b.com"]);
}

#[test]
fn parse_results_filters_engine_domains() {
    let html = r#"
            <a href="https://duckduckgo.com/something">Skip</a>
            <a href="https://realsite.com/page">Real</a>
            <a href="https://google.com/redirect">Skip</a>
        "#;
    let results = parse_results(html, "duckduckgo", "test query");
    assert_eq!(results.len(), 1);
    assert!(results[0].url.contains("realsite.com"));
}

#[test]
fn canonicalize_strips_fragment_slash_and_trackers() {
    // Fragment + a pure tracking param + trailing slash are all normalised away.
    assert_eq!(
        canonicalize_url("https://example.com/page?utm_source=x#top"),
        "https://example.com/page"
    );
    assert_eq!(
        canonicalize_url("https://example.com/page/"),
        "https://example.com/page"
    );
    // An ambiguous/content param (`ref` — git ref vs referral) is KEPT so a
    // distinct page is never merged away; only the fragment is dropped.
    assert_eq!(
        canonicalize_url("https://example.com/page?ref=1#top"),
        "https://example.com/page?ref=1"
    );
}

#[test]
fn strip_tags_extracts_clean_text() {
    let html = "<b>Hello</b> <span>world</span>  <i>test</i>";
    assert_eq!(strip_tags(html, 100), "Hello world test");
}

#[test]
fn email_extraction_from_snippet() {
    let text = "Contact support@acme.com or sales@test.org for help";
    let emails = extract_emails_from_text(text);
    assert!(emails.contains(&"support@acme.com".to_string()));
    assert!(emails.contains(&"sales@test.org".to_string()));
}

#[test]
fn email_extraction_skips_image_files() {
    let text = "icon@2x.png and logo@3x.jpg should be skipped";
    let emails = extract_emails_from_text(text);
    assert!(emails.is_empty());
}

#[test]
fn email_extraction_skips_script_url_fragments() {
    // A forum/CMS URL fragment glued to an address during HTML stripping must
    // not become an email (the real-scan bug: viewtopic.phprose.cl@onet.eu).
    let text = "see viewtopic.phprose.cl@onet.eu and index.html@x.com here";
    let emails = extract_emails_from_text(text);
    assert!(
        emails.is_empty(),
        "script-extension local parts must be rejected, got {emails:?}"
    );
    // A legitimate address sharing the same text still extracts.
    let ok = extract_emails_from_text("real person jane.doe@onet.eu posted");
    assert!(ok.contains(&"jane.doe@onet.eu".to_string()));
}

#[test]
fn phone_extraction_international() {
    let text = "Call us at +1-555-123-4567 or +44 20 7946 0958 today";
    let phones = extract_phones_from_text(text);
    assert_eq!(phones.len(), 2);
    assert!(phones.iter().any(|p| p.starts_with("+1")));
    assert!(phones.iter().any(|p| p.starts_with("+44")));
}

#[test]
fn tracking_url_detection() {
    assert!(is_tracking_url("https://r.search.yahoo.com/cbcl/something"));
    assert!(is_tracking_url("https://r.bing.com/rb/something"));
    assert!(is_tracking_url("https://ad.doubleclick.net/thing"));
    assert!(!is_tracking_url("https://example.com/page"));
    assert!(!is_tracking_url("https://example.com/redirect?url=x"));
}

#[test]
fn engine_domain_filtering() {
    assert!(is_engine_domain("duckduckgo.com"));
    assert!(is_engine_domain("search.yahoo.com"));
    assert!(is_engine_domain("r.search.yahoo.com"));
    assert!(!is_engine_domain("example.com"));
    assert!(is_engine_domain("yandex.ru"));
    assert!(is_engine_domain("ecosia.org"));
    assert!(is_engine_domain("api.qwant.com"));
    assert!(is_engine_domain("dogpile.com"));
    assert!(is_engine_domain("swisscows.com"));
}

#[test]
fn registrable_domain_extraction() {
    assert_eq!(extract_registrable("sub.example.com"), "example.com");
    assert_eq!(extract_registrable("example.com"), "example.com");
    assert_eq!(extract_registrable("deep.sub.example.org"), "example.org");
}

#[test]
fn resolve_href_decodes_yandex_clck() {
    let href = "https://yandex.com/clck/jsredir?from=yandex.com\
                     &url=https%3A%2F%2Fexample.com%2Fpath&ts=abc";
    let resolved = resolve_href(href);
    assert_eq!(resolved.as_deref(), Some("https://example.com/path"));
}

#[test]
fn engine_count_is_seventeen() {
    assert_eq!(ENGINES.len(), 17);
}

#[test]
fn all_original_engines_present() {
    let names: Vec<&str> = ENGINES.iter().map(|e| e.name).collect();
    for engine in [
        "yahoo",
        "bing",
        "aol",
        "duckduckgo",
        "google",
        "brave",
        "mojeek",
    ] {
        assert!(names.contains(&engine), "missing original engine: {engine}");
    }
}

#[test]
fn new_engines_present() {
    let names: Vec<&str> = ENGINES.iter().map(|e| e.name).collect();
    for engine in [
        "startpage",
        "yandex",
        "ecosia",
        "qwant",
        "dogpile",
        "swisscows",
        "you",
        "presearch",
        "metager",
        "searx",
    ] {
        assert!(names.contains(&engine), "missing new engine: {engine}");
    }
}

#[test]
fn startpage_uses_post() {
    let sp = ENGINES.iter().find(|e| e.name == "startpage").unwrap();
    assert!(sp.build_post.is_some());
    let body = (sp.build_post.unwrap())("test query");
    assert!(body.contains("query=test+query"));
    assert!(body.contains("cat=web"));
}

#[test]
fn extract_anchor_text_basic() {
    let html = r#"<a href="https://example.com"><b>Example</b> Title</a> other text"#;
    let title = extract_anchor_text(html, "https://example.com", 200);
    assert_eq!(title, "Example Title");
}

#[test]
fn extract_anchor_text_missing_href() {
    let html = r#"<a href="https://other.com">Other</a>"#;
    let title = extract_anchor_text(html, "https://example.com", 200);
    assert!(title.is_empty());
}

#[test]
fn captcha_detection_datadome() {
    let body = "<html><body>Please enable JS \
                     <script src=\"https://ct.captcha-delivery.com/c.js\"></script>\
                     </body></html>";
    let lower = body.to_lowercase();
    assert!(lower.contains("captcha-delivery.com"));
}

#[test]
fn captcha_detection_yandex_smartcaptcha() {
    let body = "<html><title>Verification</title>\
                     <body>showcaptcha challenge</body></html>";
    let lower = body.to_lowercase();
    assert!(lower.contains("showcaptcha"));
}

#[test]
fn html_entity_decoding() {
    assert_eq!(
        decode_html_entities("uddg=https%3A%2F%2Fexample.com&amp;rut=abc"),
        "uddg=https%3A%2F%2Fexample.com&rut=abc"
    );
}

#[test]
fn extract_path_username_social() {
    assert_eq!(
        extract_path_username("https://soundcloud.com/jerome-despal").as_deref(),
        Some("jerome-despal")
    );
    assert_eq!(
        extract_path_username("https://myspace.com/shinigami_jerome").as_deref(),
        Some("shinigami_jerome")
    );
    assert!(extract_path_username("https://example.com/").is_none());
    assert!(extract_path_username("https://example.com/ab").is_none());
}

#[test]
fn is_social_host_accepts_canonical_rejects_subdomains() {
    // Canonical profile hosts: root + www/m/mobile alias.
    for h in [
        "twitter.com",
        "www.twitter.com",
        "m.twitter.com",
        "mobile.twitter.com",
        "www.pinterest.com",
        "x.com",
    ] {
        assert!(is_social_host(h), "{h} should be a social host");
    }
    // Non-profile subdomains that previously mined junk usernames out of
    // their paths (regression for the Kylo4kylo false positives).
    for h in [
        "pic.twitter.com",        // image links, not profiles
        "business.pinterest.com", // marketing
        "create.pinterest.com",   // marketing
        "developer.twitter.com",
        "api.twitter.com",
        "help.instagram.com",
        "music.youtube.com",
        "notreallytwitter.com", // suffix look-alike must not match
    ] {
        assert!(!is_social_host(h), "{h} must NOT be a social host");
    }
}

#[test]
fn confirmed_profile_elevates_exact_handle_on_social_host() {
    // The searched username's own profile (handle == first path segment on a
    // canonical social host) is the strongest finding → elevated.
    let t = Target::new(TargetKind::Username, "kylo4kylo");
    for url in [
        "https://x.com/kylo4kylo",
        "https://twitter.com/Kylo4Kylo", // case-insensitive
        "https://www.instagram.com/kylo4kylo",
        "https://github.com/kylo4kylo",
        "https://m.facebook.com/kylo4kylo",
    ] {
        assert!(
            is_confirmed_profile(&t, url, &extract_host(url)),
            "should be a confirmed profile: {url}"
        );
    }
    // NOT confirmed: a different handle, a non-social host, or a non-username
    // target kind.
    for url in [
        "https://x.com/someoneelse",         // different handle
        "https://example.com/kylo4kylo",     // not a social host
        "https://pic.twitter.com/kylo4kylo", // non-profile subdomain
    ] {
        assert!(
            !is_confirmed_profile(&t, url, &extract_host(url)),
            "should NOT be confirmed: {url}"
        );
    }
    let domain_seed = Target::new(TargetKind::Domain, "kylo4kylo.com");
    assert!(!is_confirmed_profile(
        &domain_seed,
        "https://x.com/kylo4kylo",
        "x.com"
    ));
}

#[test]
fn search_tooling_domains_are_recognised() {
    for d in [
        "peekyou.com",
        "spokeo.com",
        "www.nuwber.com",
        "whitepages.com",
        "pipl.com",
        "usernamegenerator.com",
        "whatsmyname.app",
    ] {
        assert!(is_search_tooling_domain(d), "{d} should be search tooling");
    }
    for d in ["kylosrealsite.com", "github.com", "example.org"] {
        assert!(!is_search_tooling_domain(d), "{d} must NOT be suppressed");
    }
}

#[test]
fn username_seed_emits_profile_urls_not_bare_external_domains() {
    // For a username (non-domain) seed, bare SERP-result hosts are noise — an
    // unbounded long tail of irrelevant sites — so NONE are emitted as Domain
    // entities. The genuinely relevant pages survive as Url entities via the
    // path-match gate, which is what the investigator actually clicks.
    let target = Target::new(TargetKind::Username, "kylo4kylo");
    let mk = |url: &str| SearchResult {
        url: url.to_string(),
        title: "kylo4kylo".to_string(),
        snippet: "kylo4kylo profile page".to_string(),
        engine: "duckduckgo",
        query: "kylo4kylo".to_string(),
    };
    let results = vec![
        mk("https://www.peekyou.com/kylo4kylo"),
        mk("https://spokeo.com/kylo4kylo"),
        mk("https://kylosrealsite.com/about"),
    ];
    let res = build_entities(&target, "s", &results, &url_engine_counts(&results));
    let domains: Vec<&str> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        domains.is_empty(),
        "no bare external domains for a username seed, got {domains:?}"
    );
    let urls: Vec<&str> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        urls.iter().any(|u| u.contains("peekyou.com/kylo4kylo")),
        "the specific profile URL on the aggregator must be kept, got {urls:?}"
    );
}

#[test]
fn people_search_name_extraction_requires_on_target_relation() {
    // Regression from a live "Haigen Bamford" scan: a PeekYou results page for
    // an UNRELATED index entry (`peekyou.com/_bochary`) fabricated a Person
    // "bochary". The people-search path only encodes a name worth trusting when
    // it's the SUBJECT's — require an overlap with the target's terms.
    let target = Target::new(TargetKind::FullName, "Haigen Bamford");
    let mk = |url: &str| SearchResult {
        url: url.to_string(),
        title: "profile".to_string(),
        snippet: "people search".to_string(),
        engine: "yahoo",
        query: "Haigen Bamford".to_string(),
    };
    let results = [
        mk("https://www.peekyou.com/_bochary"),
        mk("https://www.peekyou.com/haigen_bamford"),
    ];
    let res = build_entities(&target, "s", &results, &url_engine_counts(&results));
    let persons: Vec<&str> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        !persons.iter().any(|p| p.to_lowercase().contains("bochary")),
        "an unrelated people-search index entry must not become a Person: {persons:?}"
    );
    assert!(
        persons.iter().any(|p| p.to_lowercase().contains("haigen")),
        "the on-target name IS extracted: {persons:?}"
    );
}

#[test]
fn captcha_page_detection() {
    assert!(is_captcha_page(
        "<html><body>captcha-delivery.com script</body></html>"
    ));
    assert!(is_captcha_page(
        "<html><body>httpservice/retry redirect</body></html>"
    ));
    assert!(!is_captcha_page(
        "<html><body>Normal search results page with lots of content</body></html>"
    ));
}

#[test]
fn email_query_includes_people_search() {
    let t = Target::new(TargetKind::Email, "jdespal@gmail.com");
    let q = build_queries(&t);
    assert!(
        q.iter()
            .any(|qr| qr.contains("peekyou.com") || qr.contains("nuwber.com"))
    );
}

#[test]
fn address_extraction_au_state() {
    let text = "Jerome Despal, Nundah, Queensland, Australia";
    let addrs = extract_addresses_from_text(text);
    assert!(!addrs.is_empty());
    assert_eq!(addrs[0], "Nundah, Queensland");
}

#[test]
fn address_extraction_us_state() {
    let text = "lives in Houston, Texas since 2020";
    let addrs = extract_addresses_from_text(text);
    assert!(!addrs.is_empty());
    assert_eq!(addrs[0], "Houston, Texas");
}

#[test]
fn us_state_address_never_gets_an_au_postcode_appended() {
    // Regression from a live "Haigen Bamford" name-scan: a US "City, State"
    // grabbed a trailing 4-digit YEAR as if it were an AU postcode, surfacing
    // "Ames, Iowa 2011" at high confidence. The AU-postcode pass must only
    // attach to AU-state addresses.
    let addrs = extract_addresses_from_text("relocated to Ames, Iowa 2011 for work");
    assert!(
        !addrs.iter().any(|a| a.contains("2011")),
        "no AU postcode (here a year) on a US-state address: {addrs:?}"
    );
    assert!(addrs.iter().any(|a| a == "Ames, Iowa"));
    // The AU case still attaches its genuine postcode.
    let au = extract_addresses_from_text("based in Nundah, Queensland 4012 now");
    assert!(
        au.iter().any(|a| a.contains("4012")),
        "AU postcode kept: {au:?}"
    );
}

#[test]
fn address_extraction_rejects_noise() {
    let text = "arguments, got nothing back from the server";
    let addrs = extract_addresses_from_text(text);
    assert!(addrs.is_empty());
}

#[test]
fn address_extraction_rejects_us_state_pairs() {
    // "Arizona, Georgia" etc. are two states, not a City, State address —
    // generic-text false positives that flooded a real scan.
    for text in [
        "Arizona, Georgia governors stress ties",
        "compare Indiana, Florida and Texas, Ohio",
    ] {
        let addrs = extract_addresses_from_text(text);
        assert!(
            addrs.is_empty(),
            "state pairs must be rejected, got {addrs:?} from {text:?}"
        );
    }
    // A genuine City, State still extracts.
    assert_eq!(
        extract_addresses_from_text("lives in Houston, Texas now"),
        vec!["Houston, Texas".to_string()]
    );
}

#[test]
fn navigation_path_catches_extensions() {
    assert!(is_navigation_path("login.php"));
    assert!(is_navigation_path("signin_page"));
    assert!(is_navigation_path("qwantcom"));
    assert!(is_navigation_path("swisscows_ch"));
    assert!(!is_navigation_path("jerome-despal"));
    assert!(!is_navigation_path("shinigami_jerome"));
}

#[test]
fn navigation_path_rejects_linkedin_directory_prefixes() {
    // Regression from a live self-scan: `linkedin.com/pub/dir/Jordan/Avery`
    // is a people-search URL, so its first path segment `pub` was emitted as a
    // discovered username. `pub` and `dir` are structural directory prefixes,
    // never handles, and must be filtered.
    assert!(is_navigation_path("pub"));
    assert!(is_navigation_path("dir"));
    // A genuine handle that merely starts with those letters is unaffected.
    assert!(!is_navigation_path("publius"));
    assert!(!is_navigation_path("director_steve"));
}

#[test]
fn fullname_query_includes_geolocation() {
    let t = Target::new(TargetKind::FullName, "Jane Doe");
    let q = build_queries(&t);
    assert!(
        q.iter()
            .any(|qr| qr.contains("address") || qr.contains("location"))
    );
}

#[test]
fn username_scoring_term_overlap() {
    let terms = vec!["jerome".into(), "despal".into()];
    let r = SearchResult {
        url: "https://soundcloud.com/jerome-despal".into(),
        title: String::new(),
        snippet: String::new(),
        engine: "yahoo",
        query: "\"Jerome Despal\"".into(),
    };
    let (score, conf) = score_username("jerome-despal", "soundcloud.com", &terms, &r);
    assert!(score >= 3);
    assert!((conf - 0.55).abs() < 0.01);
}

#[test]
fn username_scoring_no_overlap_with_site_query() {
    // A genuinely-unrelated handle (no term overlap, no shared stem, no
    // bigram similarity to the seed) found ONLY via a site: query is a weak
    // CANDIDATE: the platform-targeted query contributes a single point.
    // (Uses `marcusw`, not `jaydes` — the latter is ~0.36 bigram-similar to
    // `jdespal`, which the potentiated Signal 5 correctly promotes.)
    let terms = vec!["jdespal".into()];
    let r = SearchResult {
        url: "https://soundcloud.com/marcusw/tracks".into(),
        title: String::new(),
        snippet: String::new(),
        engine: "yahoo",
        query: "Jdespal site:soundcloud.com OR site:instagram.com".into(),
    };
    let (score, conf) = score_username("marcusw", "soundcloud.com", &terms, &r);
    assert_eq!(score, 1, "site:-only signal should give exactly 1");
    assert!((conf - 0.30).abs() < 0.01, "weak signal stays CANDIDATE");
}

#[test]
fn username_scoring_cooccurrence() {
    let terms = vec!["jdespal".into()];
    let r = SearchResult {
        url: "https://soundcloud.com/jaydes/tracks".into(),
        title: "Jdespal's favorite tracks".into(),
        snippet: String::new(),
        engine: "yahoo",
        query: "\"Jdespal\"".into(),
    };
    let (score, _) = score_username("jaydes", "soundcloud.com", &terms, &r);
    assert!(score >= 2, "co-occurrence should boost score, got {score}");
}

#[test]
fn username_scoring_people_search() {
    let terms = vec!["shinigami".into(), "jerome".into()];
    let r = SearchResult {
        url: "https://www.peekyou.com/jerome_despal".into(),
        title: String::new(),
        snippet: String::new(),
        engine: "bing",
        query: "\"shinigami_jerome\"".into(),
    };
    let (score, _) = score_username("jerome_despal", "www.peekyou.com", &terms, &r);
    assert!(
        score >= 3,
        "people-search provenance should give high score, got {score}"
    );
}

#[test]
fn people_search_provenance_requires_host_label_boundary() {
    // With no terms and an empty title/snippet/query, only the people-search
    // provenance signal (+3) can fire, so the score isolates it. A genuine
    // people-search host (and a subdomain of it) scores; a domain that merely
    // ends with the provider string mid-label (`myspokeo.com`) must not — the
    // bare `host.ends_with(ps)` false positive this fixes.
    let blank = SearchResult {
        url: String::new(),
        title: String::new(),
        snippet: String::new(),
        engine: "bing",
        query: String::new(),
    };
    let score = |host: &str| score_username("zzqnonsense", host, &[], &blank).0;
    assert_eq!(score("spokeo.com"), 3, "people-search host scores");
    assert_eq!(score("api.spokeo.com"), 3, "subdomain of it scores");
    assert_eq!(score("myspokeo.com"), 0, "mid-label match must not score");
    assert_eq!(
        score("notwhitepages.com"),
        0,
        "mid-label match must not score"
    );
}

#[test]
fn url_relevance_filtering() {
    let terms = vec!["jerome".into(), "despal".into()];
    assert!(url_matches_target(
        "https://soundcloud.com/jerome-despal",
        &terms
    ));
    assert!(url_matches_target(
        "https://www.peekyou.com/jerome_despal",
        &terms
    ));
    assert!(!url_matches_target("https://www.spokeo.com/", &terms));
    assert!(!url_matches_target(
        "https://www.whitepages.com/people-search",
        &terms
    ));
}

#[test]
fn generic_domain_filtering() {
    assert!(is_generic_domain("wikihow.com"));
    assert!(is_generic_domain("windowsreport.com"));
    assert!(is_generic_domain("office.com"));
    assert!(!is_generic_domain("soundcloud.com"));
    assert!(!is_generic_domain("peekyou.com"));
}

#[test]
fn target_terms_extraction() {
    let t = Target::new(TargetKind::Email, "jdespal@gmail.com");
    let terms = target_terms(&t);
    assert!(terms.contains(&"jdespal".to_string()));
    assert!(!terms.contains(&"gmail".to_string()));
    assert!(!terms.contains(&"com".to_string()));

    let t2 = Target::new(TargetKind::FullName, "Jerome Despal");
    let terms2 = target_terms(&t2);
    assert!(terms2.contains(&"jerome".to_string()));
    assert!(terms2.contains(&"despal".to_string()));
}

#[test]
fn target_terms_filters_web_stopwords() {
    // A Url target (created during depth-1 expansion) is split into path
    // tokens — structural ones (scheme/host-alias/tld/ext) must NOT become
    // terms, or they match every unrelated page carrying that token.
    let t = Target::new(
        TargetKind::Url,
        "https://www.cloudflare.com/learning/ssl/why-use-https",
    );
    let terms = target_terms(&t);
    for stop in ["https", "www", "com", "ssl"] {
        assert!(
            !terms.iter().any(|w| w == stop),
            "stopword {stop} must be filtered, got {terms:?}"
        );
    }
    assert!(terms.iter().any(|w| w == "cloudflare"), "kept: {terms:?}");
    // A domain's TLD is dropped too, leaving the registrable label.
    assert_eq!(
        target_terms(&Target::new(TargetKind::Domain, "pinterest.com")),
        vec!["pinterest".to_string()]
    );
}

#[test]
fn url_gate_rejects_unrelated_https_pages() {
    // Regression for the standard Kylo4kylo run: with a `…/why-use-https`
    // Url target, generic HTTPS-explainer pages on OTHER domains used to pass
    // the relevance gate because `https` was a term. They must not now.
    let terms = target_terms(&Target::new(
        TargetKind::Url,
        "https://www.cloudflare.com/learning/ssl/why-use-https",
    ));
    assert!(!url_matches_target(
        "https://en.wikipedia.org/wiki/HTTPS",
        &terms
    ));
    assert!(!url_matches_target(
        "https://www.networksolutions.com/blog/enable-https",
        &terms
    ));
}

#[test]
fn extract_family_names_survives_non_ascii_email_local_part() {
    // Regression: deriving the "lastname" dropped the first BYTE of the email
    // local part (`local[1..]`), which panics on an internationalised local
    // part by splitting the leading codepoint. Must drop the first char
    // instead — no panic.
    for v in [
        "élise@example.com",
        "θεόδωρος@example.com",
        "münch@example.de",
    ] {
        let _ = extract_family_names(&[], &Target::new(TargetKind::Email, v));
    }
}

#[test]
fn extract_family_names_rejects_subject_name_doublings_and_filler() {
    // Regression from a live "Haigen Bamford" scan: snippet text produced phantom
    // "family members" — the subject's own first name doubled into one token
    // ("Haigenhaigen Bamford", "Haigenbhaigen Bamford") and a filler word before
    // the surname ("Named Bamford"). None is a distinct relative.
    let mk = |title: &str, snippet: &str| SearchResult {
        url: "https://example.com/x".into(),
        title: title.into(),
        snippet: snippet.into(),
        engine: "google",
        query: "\"Haigen Bamford\"".into(),
    };
    let target = Target::new(TargetKind::FullName, "Haigen Bamford");
    let results = vec![
        mk("haigenhaigen bamford", ""),
        mk("haigenbhaigen bamford", ""),
        mk("a company named bamford", ""),
    ];
    let fam = extract_family_names(&results, &target);
    assert!(
        fam.is_empty(),
        "subject-name doublings and filler must not become family members: {fam:?}"
    );

    // A genuine relative sharing the surname is still extracted.
    let real = vec![mk("Jeanette Bamford realty", "")];
    let fam2 = extract_family_names(&real, &target);
    assert!(
        fam2.iter().any(|(n, _)| n == "Jeanette Bamford"),
        "a real distinct relative must survive: {fam2:?}"
    );
}

#[test]
fn abn_extraction() {
    let text = "Registered ABN 53 004 085 616 for the company";
    let results = extract_abn_acn_from_text(text);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "53004085616");
    assert_eq!(results[0].1, "ABN");
}

#[test]
fn abn_validation_checksum() {
    assert!(is_valid_abn("53004085616")); // real ABN: Qantas
    assert!(!is_valid_abn("12345678901"));
}

#[test]
fn organisation_extraction() {
    let terms = vec!["despal".into()];
    let text = "Director of Despal Holdings Pty Ltd since 2019";
    let orgs = extract_organisations_from_text(text, &terms);
    assert!(!orgs.is_empty());
    assert!(orgs[0].contains("Pty Ltd"));
}

#[test]
fn bigram_similarity_identical() {
    assert!((bigram_similarity("hello", "hello") - 1.0).abs() < 0.01);
}

#[test]
fn bigram_similarity_partial() {
    let sim = bigram_similarity("jdespal", "jaydes");
    assert!(sim > 0.0, "partial overlap expected, got {sim}");
}

#[test]
fn bigram_similarity_unrelated() {
    let sim = bigram_similarity("jdespal", "elephant");
    assert!(sim < 0.2, "unrelated strings, got {sim}");
}

#[test]
fn bigram_similarity_repeated_bigrams_stay_within_unit_interval() {
    // Regression: the Dice coefficient is a MULTISET intersection. The old
    // "is this bigram present?" count overcounted when a bigram repeated more
    // often in `a` than in `b`, pushing the score above 1.0. "aaaa" has the
    // bigram (a,a) three times; "aaa" has it twice → min(3,2)=2 matches →
    // 2*2/(3+2)=0.8, never 1.2.
    let sim = bigram_similarity("aaaa", "aaa");
    assert!(
        (0.0..=1.0).contains(&sim),
        "similarity must stay in [0,1], got {sim}"
    );
    assert!(
        (sim - 0.8).abs() < 1e-9,
        "expected exact Dice 0.8, got {sim}"
    );
    // Self-similarity of a repetitive string is still exactly 1.0.
    assert!((bigram_similarity("aaaa", "aaaa") - 1.0).abs() < 1e-9);
}

#[test]
fn score_username_promotes_seed_variant_over_cooccurrence() {
    // Potentiated username scoring: a handle sharing the seed's stem (a likely
    // ALIAS of the same person) must outrank — and reach a higher tier than —
    // an unrelated handle that merely co-occurred on the page. Seed
    // "kylo4kylo" → stem "kylo"; both candidates co-occur with the seed.
    let terms = vec!["kylo4kylo".to_string()];
    let res = SearchResult {
        url: "https://x.com/handle".to_string(),
        title: "page".to_string(),
        snippet: "a page mentioning kylo4kylo and others".to_string(),
        engine: "duckduckgo",
        query: "kylo4kylo".to_string(),
    };
    let (s_variant, c_variant) = score_username("kylocool630", "x.com", &terms, &res);
    let (s_noise, c_noise) = score_username("khloekardashian", "x.com", &terms, &res);
    assert!(
        s_variant >= 3 && (c_variant - 0.55).abs() < 1e-9,
        "seed-variant handle should reach PROBABLE (0.55), got score={s_variant} conf={c_variant}"
    );
    assert!(
        s_noise < 3 && (c_noise - 0.30).abs() < 1e-9,
        "pure co-occurrence should stay CANDIDATE (0.30), got score={s_noise} conf={c_noise}"
    );
    assert!(
        s_variant > s_noise,
        "the seed-resembling alias must outrank co-occurrence noise"
    );
}

#[test]
fn confirmed_profile_corroborated_by_engines_reaches_verified() {
    // A confirmed profile independently returned by N engines must credit all N
    // (cross-engine corroboration) and so cross into the Verified tier.
    //
    // This test exercises the REAL `process()` ordering — count engines from the
    // PRE-dedup results, THEN dedup, THEN build — so it genuinely guards the bug
    // it covers. The masked-away regression was that `process()` deduped the
    // results (one `SearchResult` per canonical URL) BEFORE entity construction,
    // and `build_entities` recomputed the engine count from that already-deduped
    // slice, so every URL credited exactly one engine in production. Feeding
    // pre-deduped same-URL results straight into `build_entities` (as this test
    // once did) hid that: it never ran the dedup step. See
    // `corroboration_count_survives_dedup` for the focused dedup-ordering guard.
    let target = Target::new(TargetKind::Username, "kylo4kylo");
    let mk = |engine: &'static str| SearchResult {
        url: "https://x.com/kylo4kylo".to_string(),
        title: "kylo4kylo".to_string(),
        snippet: "kylo4kylo on X".to_string(),
        engine,
        query: "kylo4kylo".to_string(),
    };
    let results = vec![mk("duckduckgo"), mk("brave"), mk("mojeek")];
    // Mirror process(): engine count from PRE-dedup results, then dedup.
    let url_engine_count = url_engine_counts(&results);
    let deduped = dedup_results(results);
    assert_eq!(deduped.len(), 1, "the three same-URL results dedup to one");
    let res = build_entities(&target, "s", &deduped, &url_engine_count);
    let prof = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url && e.value == "https://x.com/kylo4kylo")
        .expect("confirmed profile url entity");
    assert!(prof.has_tag("confirmed-profile"));
    assert_eq!(
        prof.corroboration, 3,
        "all 3 engines must be credited even though dedup kept one result"
    );
    assert!(
        prof.c_effective() >= 0.75,
        "3-engine confirmed profile must be Verified, got c_eff={}",
        prof.c_effective()
    );
}

#[test]
fn corroboration_count_survives_dedup() {
    // Focused regression for the dedup-then-build ordering bug. `process()`
    // dedups results to one `SearchResult` per canonical URL before building
    // entities; the cross-engine corroboration count must therefore be computed
    // from the PRE-dedup results and threaded through, NOT recomputed from the
    // deduped slice (which would always yield 1). This pins the exact data flow:
    // a domain subdomain URL and a confirmed-profile URL each returned by three
    // engines must both carry corroboration == 3 after the dedup pass.
    let domain_seed = Target::new(TargetKind::Domain, "targetcorp.com.au");
    let sub_mk = |engine: &'static str| SearchResult {
        url: "https://mail.targetcorp.com.au/login".to_string(),
        title: "login".to_string(),
        snippet: "mail server".to_string(),
        engine,
        query: "targetcorp.com.au".to_string(),
    };
    let domain_results = vec![sub_mk("duckduckgo"), sub_mk("brave"), sub_mk("yahoo")];
    let domain_counts = url_engine_counts(&domain_results);
    let domain_deduped = dedup_results(domain_results);
    assert_eq!(domain_deduped.len(), 1, "same-URL results dedup to one");
    let domain_res = build_entities(&domain_seed, "s", &domain_deduped, &domain_counts);
    let sub = domain_res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "mail.targetcorp.com.au")
        .expect("subdomain entity");
    assert_eq!(
        sub.corroboration, 3,
        "subdomain corroboration must survive dedup, got {}",
        sub.corroboration
    );

    // Same data flow for a confirmed-profile Url entity.
    let user_seed = Target::new(TargetKind::Username, "kylo4kylo");
    let prof_mk = |engine: &'static str| SearchResult {
        url: "https://x.com/kylo4kylo".to_string(),
        title: "kylo4kylo".to_string(),
        snippet: "kylo4kylo on X".to_string(),
        engine,
        query: "kylo4kylo".to_string(),
    };
    let prof_results = vec![prof_mk("duckduckgo"), prof_mk("brave"), prof_mk("mojeek")];
    let prof_counts = url_engine_counts(&prof_results);
    let prof_deduped = dedup_results(prof_results);
    assert_eq!(prof_deduped.len(), 1, "same-URL results dedup to one");
    let prof_res = build_entities(&user_seed, "s", &prof_deduped, &prof_counts);
    let prof = prof_res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url && e.value == "https://x.com/kylo4kylo")
        .expect("confirmed profile url entity");
    assert_eq!(
        prof.corroboration, 3,
        "profile corroboration must survive dedup, got {}",
        prof.corroboration
    );
}

#[test]
fn email_seed_emits_no_bare_external_domains() {
    // An email (non-domain) seed's SERP hits — platform, freemail, broker, or
    // even an unrelated personal blog — are all just "where a mention
    // appeared". None are the subject's own asset, and the relevant pages are
    // kept as Url entities by the path-match gate, so NO bare external Domain
    // entities are emitted. (Subdomains of the email's OWN domain still would
    // be, but freemail seeds have none.)
    let target = Target::new(TargetKind::Email, "subject@example.org");
    let mk = |url: &str| SearchResult {
        url: url.to_string(),
        title: "subject".to_string(),
        snippet: "subject mention".to_string(),
        engine: "duckduckgo",
        query: "subject".to_string(),
    };
    let results = vec![
        mk("https://www.youtube.com/watch?v=abc"),
        mk("https://facebook.com/groups/xyz"),
        mk("https://neighborwho.com/person/123"),
        mk("https://snusbase.com/result"),
        mk("https://some-unrelated-blog.com/about"),
    ];
    let res = build_entities(&target, "s", &results, &url_engine_counts(&results));
    let domains: Vec<&str> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        domains.is_empty(),
        "no bare external domains for an email seed, got {domains:?}"
    );
}

#[test]
fn build_entities_classifies_subdomain_vs_external_with_engine_corroboration() {
    // The domain branch of `build_entities` has three couplings worth pinning:
    // a host under the target domain is a SUBDOMAIN (conf 0.70); any other
    // registrable domain is EXTERNAL (conf 0.45); and each carries the count
    // of *distinct engines* that returned its URL (cross-engine corroboration,
    // the same signal the profile-URL path uses). Uses a `.com.au` target so
    // the multi-label-suffix registrable logic is exercised too.
    let target = Target::new(TargetKind::Domain, "targetcorp.com.au");
    let mk = |url: &str, engine: &'static str| SearchResult {
        url: url.to_string(),
        title: "result".to_string(),
        snippet: "result body".to_string(),
        engine,
        query: "targetcorp.com.au".to_string(),
    };
    // Same subdomain URL from two independent engines → corroboration 2.
    // One external-domain URL from a single engine → corroboration 1.
    // Mirror process(): count engines from the PRE-dedup results, then dedup,
    // so the two same-URL subdomain hits collapse to one entity that still
    // credits both engines.
    let results = vec![
        mk("https://mail.targetcorp.com.au/login", "duckduckgo"),
        mk("https://mail.targetcorp.com.au/login", "brave"),
        mk("https://partnerfirm.com/about", "duckduckgo"),
    ];
    let url_engine_count = url_engine_counts(&results);
    let results = dedup_results(results);
    let res = build_entities(&target, "s", &results, &url_engine_count);

    let sub = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "mail.targetcorp.com.au")
        .expect("subdomain entity must be emitted");
    assert!(
        sub.has_tag("subdomain"),
        "host under target → SUBDOMAIN tag"
    );
    assert!(
        (sub.confidence - 0.70).abs() < 1e-9,
        "subdomain base conf 0.70"
    );
    assert_eq!(
        sub.corroboration, 2,
        "two engines returned the subdomain URL"
    );

    let ext = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "partnerfirm.com")
        .expect("external domain entity must be emitted");
    assert!(
        ext.has_tag("external"),
        "unrelated registrable → EXTERNAL tag"
    );
    assert!(
        (ext.confidence - 0.45).abs() < 1e-9,
        "external base conf 0.45"
    );
    assert_eq!(ext.corroboration, 1, "one engine returned the external URL");

    // The subdomain must NOT also be emitted as a bare external domain
    // (the `if/else if` makes the two branches mutually exclusive).
    assert!(
        !res.entities.iter().any(|e| e.kind == EntityKind::Domain
            && e.value == "targetcorp.com.au"
            && e.has_tag("external")),
        "the target's own registrable domain must not be re-emitted as external"
    );
}

#[test]
fn offtarget_repo_url_detects_project_named_after_a_term() {
    let terms = vec!["haigen".to_string(), "bamford".to_string()];
    // Repo named after the first-name term, owner is an unrelated org → off-target.
    assert!(is_offtarget_repo_url(
        "https://github.com/ExponentiAI/HAIGEN",
        &terms
    ));
    assert!(is_offtarget_repo_url(
        "https://github.com/ExponentiAI/HAIGEN/blob/main/README.md",
        &terms
    ));
    // The subject's OWN account (owner matches) is never off-target.
    assert!(!is_offtarget_repo_url("https://github.com/Haigen", &terms));
    assert!(!is_offtarget_repo_url(
        "https://github.com/haigenbamford/coolproject",
        &terms
    ));
    assert!(!is_offtarget_repo_url(
        "https://github.com/bamford/anything",
        &terms
    ));
    // Non-repo hosts are out of scope.
    assert!(!is_offtarget_repo_url(
        "https://pickleball.com/players/haigen-bamford",
        &terms
    ));
}

#[test]
fn url_from_a_location_seed_is_quarantined_as_generic_location() {
    // Regression from a live "Haigen Bamford" scan: recursion fed the suburb
    // "Regents Park, QLD" back as an Address seed, so every suburb / real-estate
    // page matched the place term and flooded the results at 0.50. A URL found
    // while the seed is itself a location is generic location content, not the
    // subject's PII — it must be a quarantined candidate (0.30), below the 0.50
    // expansion floor, so it neither inflates results nor recurses further.
    let mk = |url: &str| SearchResult {
        url: url.to_string(),
        title: "Regents Park QLD 4118 real estate".to_string(),
        snippet: "houses for sale in regents park".to_string(),
        engine: "duckduckgo",
        query: "regents park qld".to_string(),
    };
    let results = vec![mk(
        "https://www.realestate.com.au/buy/in-regents+park,+qld+4118/list-1",
    )];

    // From a location seed → quarantined candidate.
    let loc = build_entities(
        &Target::new(TargetKind::Address, "Regents Park, QLD"),
        "s",
        &results,
        &url_engine_counts(&results),
    );
    let u = loc
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("a URL entity is still emitted");
    assert!(
        (u.confidence - 0.30).abs() < 1e-9,
        "location-seed URL is 0.30"
    );
    assert!(u.has_tag("generic-location"));
    assert!(u.has_tag("candidate"));

    // The SAME URL from a person seed keeps the normal 0.50 (terms would have to
    // match; here the path contains no person term, so it simply isn't emitted —
    // assert it is never a 0.50 PROBABLE from the location seed).
    assert!(
        !loc.entities
            .iter()
            .any(|e| e.kind == EntityKind::Url && (e.confidence - 0.50).abs() < 1e-9),
        "a location-seed URL must never reach the 0.50 person-PII tier"
    );
}

#[test]
fn domain_queries_include_abn() {
    let t = Target::new(TargetKind::Domain, "acme.com");
    let q = build_queries(&t);
    assert!(q.iter().any(|qr| qr.contains("ABN")));
}

#[test]
fn fullname_queries_include_abn() {
    let t = Target::new(TargetKind::FullName, "Jane Doe");
    let q = build_queries(&t);
    assert!(
        q.iter()
            .any(|qr| qr.contains("ABN") || qr.contains("director"))
    );
}

#[test]
fn tracking_url_detection_new_engines() {
    assert!(is_tracking_url(
        "https://yandex.com/clck/jsredir?from=yandex"
    ));
    assert!(is_tracking_url("https://www.ecosia.org/newtab/v2"));
    assert!(!is_tracking_url("https://example.com/page"));
}

#[test]
fn username_variant_generation() {
    let v = generate_username_variants("jerome_despal");
    assert!(v.contains(&"jeromedespal".to_string()));
    assert!(v.contains(&"jerome-despal".to_string()));
    assert!(v.contains(&"jerome.despal".to_string()));
}

#[test]
fn username_variant_trailing_digit() {
    let v = generate_username_variants("jdespal");
    assert!(v.contains(&"jdespal1".to_string()));
    assert!(v.contains(&"jdespal2".to_string()));
    assert!(v.contains(&"jdespa".to_string()));
}

#[test]
fn family_name_extraction() {
    let results = vec![SearchResult {
        url: "https://linkedin.com/in/jeanette-despal".into(),
        title: "Jeanette Despal - Manager at SCAN Health Plan".into(),
        snippet: "jeanette despal works at SCAN Health Plan in Long Beach".into(),
        engine: "bing",
        query: "\"Jerome Despal\"".into(),
    }];
    let target = Target::new(TargetKind::FullName, "Jerome Despal");
    let family = extract_family_names(&results, &target);
    assert!(!family.is_empty());
    assert!(family[0].0.contains("Jeanette"));
    assert!(family[0].0.contains("Despal"));
}

#[test]
fn address_normalise_qld_variants() {
    let a = normalise_address_key("Gatton, QLD");
    let b = normalise_address_key("Gatton, Queensland");
    assert_eq!(a, b);
}

#[test]
fn address_normalise_nsw_variants() {
    let a = normalise_address_key("Sydney, NSW");
    let b = normalise_address_key("Sydney, New South Wales");
    assert_eq!(a, b);
}

#[test]
fn address_normalise_strips_punctuation() {
    let a = normalise_address_key("St Lucia, QLD, 4067");
    assert!(!a.contains(','));
    assert!(a.contains("queensland"));
}

#[test]
fn known_city_coords_gatton() {
    let coords = known_city_coords("Gatton, QLD");
    assert!(coords.is_some(), "Gatton should have known coordinates");
    let (lat, lon) = coords.unwrap();
    assert!((lat - (-27.5567)).abs() < 0.01);
    assert!((lon - 152.2767).abs() < 0.01);
}

#[test]
fn known_city_coords_lockyer_valley() {
    let coords = known_city_coords("Lockyer Valley");
    assert!(
        coords.is_some(),
        "Lockyer Valley should have known coordinates"
    );
}

#[test]
fn known_city_coords_expanded_cities() {
    assert!(known_city_coords("Philadelphia").is_some());
    assert!(known_city_coords("Miami, FL").is_some());
    assert!(known_city_coords("Newcastle NSW").is_some());
    assert!(known_city_coords("Auckland").is_some());
}

#[test]
fn address_extractor_finds_gatton_qld() {
    let text = "Jordan Meyer from Gatton QLD works in agriculture";
    let addrs = extract_addresses_from_text(text);
    assert!(
        addrs.iter().any(|a| a.contains("Gatton")),
        "should find Gatton with QLD context: {addrs:?}"
    );
}

#[test]
fn canonicalize_url_keeps_content_params_strips_trackers() {
    // Content params are kept (collapsing them would omit real results)…
    assert_eq!(
        canonicalize_url("https://x.com/page?a=1"),
        "https://x.com/page?a=1"
    );
    // …distinct content URLs therefore stay distinct…
    assert_ne!(
        canonicalize_url("https://yt.com/watch?v=A"),
        canonicalize_url("https://yt.com/watch?v=B"),
    );
    // …pure tracking params are dropped…
    assert_eq!(
        canonicalize_url("https://x.com/page?utm_source=nl&utm_medium=email&fbclid=xyz"),
        "https://x.com/page"
    );
    // …mixed: trackers dropped, content kept and order-normalised.
    assert_eq!(
        canonicalize_url("https://x.com/p?v=B&utm_source=x&id=2"),
        "https://x.com/p?id=2&v=B"
    );
}

#[test]
fn canonicalize_url_strips_fragment() {
    assert_eq!(
        canonicalize_url("https://x.com/page#section"),
        "https://x.com/page"
    );
}

#[test]
fn canonicalize_url_strips_trailing_slash() {
    assert_eq!(
        canonicalize_url("https://x.com/page/"),
        "https://x.com/page"
    );
}

// ── Resilience hardening: scraping-fragility guards ───────────────────

#[test]
fn reliable_engines_resolve_by_name() {
    // The secondary pivot + recycler passes select these engines by NAME,
    // not by `ENGINES[..]` index, so reordering/inserting into `ENGINES`
    // can't silently repoint them. Assert all three resolve, in order —
    // a rename/removal fails CI instead of degrading silently at runtime.
    let names: Vec<&str> = reliable_engines().iter().map(|e| e.name).collect();
    // Live scan data: metager/swisscows/dogpile are 97-100% hit / 0% blocked
    // from DC IPs; yahoo/bing/brave get killed by SESSION_DEAD within ~400
    // dispatches. Reliable pass now uses the DC-stable engines.
    assert_eq!(names, vec!["metager", "swisscows", "dogpile"]);
}

#[test]
fn reliable_engines_are_in_the_registry() {
    let registry: Vec<&str> = ENGINES.iter().map(|e| e.name).collect();
    for e in reliable_engines() {
        assert!(
            registry.contains(&e.name),
            "reliable engine {:?} missing from ENGINES",
            e.name
        );
    }
}

#[test]
fn description_engine_count_matches_registry() {
    // The human-facing description cites an engine count; tie it to the
    // real registry size so they can't drift (they sat at "13" while the
    // registry grew to 17). Adding an engine now forces a description bump.
    let n = ENGINES.len();
    let desc = SearchEngines.description();
    assert!(
        desc.contains(&n.to_string()),
        "module description must cite the real engine count ({n}): {desc:?}"
    );
}

#[test]
fn captcha_detects_modern_vendor_interstitials() {
    // Cloudflare managed challenge ("/cdn-cgi/challenge-platform").
    assert!(is_captcha_page(
        "<html><head><title>Just a moment...</title></head><body>\
             Checking your browser before accessing. \
             <script src=\"/cdn-cgi/challenge-platform/h/g/orchestrate/chl/v1\"></script>\
             cloudflare</body></html>"
    ));
    // Google reCAPTCHA + "unusual traffic ... network" interstitial.
    assert!(is_captcha_page(
        "<html><body>Our systems have detected unusual traffic from your \
             computer network. <div class=\"g-recaptcha\"></div></body></html>"
    ));
    // hCaptcha widget.
    assert!(is_captcha_page(
        "<div class=\"h-captcha\" data-sitekey=\"x\"></div>\
             <script src=\"https://hcaptcha.com/1/api.js\"></script>"
    ));
    // PerimeterX / HUMAN classic block page.
    assert!(is_captcha_page(
        "Access to this page has been denied because we believe you are using automation."
    ));
    // Imperva / Incapsula.
    assert!(is_captcha_page(
        "Request unsuccessful. Incapsula incident ID: 1234-000567"
    ));
}

#[test]
fn captcha_does_not_flag_results_that_merely_mention_block_terms() {
    // A genuine SERP whose snippets discuss these topics must NOT be read
    // as a block page. The AND-set design requires a co-token, so a single
    // ambiguous phrase no longer trips the detector — exactly the false
    // positives the old single-substring matcher produced.
    assert!(!is_captcha_page(
        "Search results: how Cloudflare works and what a reCAPTCHA is — \
             articles about bot detection and network security."
    ));
    assert!(!is_captcha_page(
        "Blog post: detecting unusual traffic spikes in your web analytics."
    ));
    assert!(!is_captcha_page(
        "<html><body>10 results for your query about online privacy.</body></html>"
    ));
}

#[test]
fn html_entity_decoding_apostrophes() {
    // `&apos;` and the hex `&#x27;` both decode to an apostrophe, matching
    // the `util::html` decoder used elsewhere in the tree.
    assert_eq!(decode_html_entities("it&apos;s"), "it's");
    assert_eq!(decode_html_entities("it&#x27;s"), "it's");
    assert_eq!(decode_html_entities("a&#39;b&amp;c"), "a'b&c");
}

#[test]
fn session_dead_threshold_fires_after_n_consecutive_empties() {
    // Use a fake engine name so this test is isolated from other tests
    // that may have touched the real engine names.
    const FAKE: &str = "__test_session_dead__";
    // Reset any leftover state from prior runs of this test.
    SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(FAKE);

    assert!(
        !is_session_dead(FAKE),
        "should not be dead before threshold"
    );
    // An UNPROVEN engine (never produced a result) dies fast — google/you/etc.
    for i in 0..SESSION_DEAD_THRESHOLD {
        record_empty(FAKE);
        if i + 1 < SESSION_DEAD_THRESHOLD {
            assert!(!is_session_dead(FAKE), "dead before threshold at i={i}");
        }
    }
    assert!(
        is_session_dead(FAKE),
        "must be session-dead after threshold"
    );

    // record_hit resets the streak — engine is live again.
    record_hit(FAKE);
    assert!(!is_session_dead(FAKE), "hit must un-dead the engine");
}

#[test]
fn proven_engine_tolerates_long_block_streaks() {
    // A "proven live" engine (≥1 result this session) must ride out the kind of
    // 3-block streaks that intermittently-blocked engines (bing ~48% block,
    // ecosia ~78%) routinely hit BETWEEN real results. The old flat threshold of
    // 3 permanently silenced them mid-scan and discarded their later results.
    const FAKE: &str = "__test_proven_engine__";
    SESSION_EMPTY_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(FAKE);

    // Prove it live, then feed it the streak that WOULD have killed it before.
    record_hit(FAKE);
    for _ in 0..SESSION_DEAD_THRESHOLD {
        record_empty(FAKE);
    }
    assert!(
        !is_session_dead(FAKE),
        "a proven engine must survive an unproven-length empty streak"
    );

    // It still dies if the host genuinely goes down for the full tolerant run.
    for _ in SESSION_DEAD_THRESHOLD..SESSION_DEAD_THRESHOLD_PROVEN {
        record_empty(FAKE);
    }
    assert!(
        is_session_dead(FAKE),
        "a proven engine still dies after the tolerant threshold"
    );

    // A fresh hit revives it AND resets the streak.
    record_hit(FAKE);
    assert!(
        !is_session_dead(FAKE),
        "a later hit revives a silenced engine"
    );
}
