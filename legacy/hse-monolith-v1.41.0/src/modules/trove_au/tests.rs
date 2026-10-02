use super::TroveAu;
use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn metadata() {
    let m = TroveAu;
    assert_eq!(m.name(), "trove_au");
    assert_eq!(m.priority(), 57);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "12345678901")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
    // produces() must now declare the per-article Url source.
    assert!(m.produces().contains(&crate::core::entity::EntityKind::Url));
    // Historical archive results are stable within a day — one of C9's own
    // named motivating examples for the inter-scan cache.
    assert_eq!(m.cache_ttl_secs(), 86_400);
}

#[test]
fn build_entities_emits_org_and_per_article_url_sources() {
    use super::{TroveArticle, build_entities};
    use crate::core::entity::EntityKind;

    let articles = vec![
        TroveArticle {
            id: Some("18341291".into()),
            title: Some("ACME COMPANY NOTICE".into()),
            date: Some("1923-04-01".into()),
            title_id: Some("35".into()),
            snippet: Some("...the directors of Acme...".into()),
            url: Some("https://trove.nla.gov.au/newspaper/article/18341291".into()),
        },
        // A second article with the SAME url must dedup to one entity.
        TroveArticle {
            id: Some("18341291".into()),
            title: Some("dup".into()),
            date: Some("1923-04-02".into()),
            title_id: None,
            snippet: None,
            url: Some("https://trove.nla.gov.au/newspaper/article/18341291".into()),
        },
        // An article with no URL is skipped (nothing to pivot on).
        TroveArticle {
            id: Some("999".into()),
            title: Some("no url".into()),
            date: Some("1924-01-01".into()),
            title_id: None,
            snippet: None,
            url: None,
        },
    ];
    let res = build_entities("Acme Pty Ltd", 42, &articles, "scan");

    let org = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("org headline must be emitted");
    assert_eq!(org.value, "Acme Pty Ltd");
    assert!(org.has_tag("trove") && org.has_tag("newspaper-archive"));

    // Exactly ONE Url source (duplicate deduped; url-less skipped) — the article
    // link that was previously deserialized and dropped.
    let urls: Vec<_> = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .collect();
    assert_eq!(urls.len(), 1, "deduped + url-less skipped");
    let u = urls[0];
    assert_eq!(
        u.value,
        "https://trove.nla.gov.au/newspaper/article/18341291"
    );
    assert!(u.has_tag("trove") && u.has_tag("source-document"));
    // The previously-dropped fields are now preserved on the Url's evidence.
    let attrs = &u.evidence[0].attributes;
    assert_eq!(
        attrs.get("article_id").map(String::as_str),
        Some("18341291")
    );
    assert_eq!(
        attrs.get("title").map(String::as_str),
        Some("ACME COMPANY NOTICE")
    );
    assert!(attrs.get("snippet").is_some(), "snippet preserved");
    // The publishing masthead id (titleId) is now carried as provenance.
    assert_eq!(attrs.get("masthead_id").map(String::as_str), Some("35"));

    // No hits → empty result.
    assert!(
        build_entities("X", 0, &articles, "scan")
            .entities
            .is_empty()
    );
}

#[test]
fn build_entities_demotes_and_flags_an_article_whose_own_text_never_names_the_query() {
    // Regression: `zone=newspaper` is a full-text search across Trove's
    // 150+ year archive — a same-named-but-unrelated historical business is a
    // real risk, and every article used to be trusted at the identical
    // MEDIUM_HIGH confidence with an evidence summary unconditionally
    // asserting it "mentions the subject", regardless of whether the
    // article's own title/snippet ever named the query at all.
    use super::{TroveArticle, build_entities};
    use crate::core::entity::EntityKind;

    let articles = vec![TroveArticle {
        id: Some("1".into()),
        title: Some("Totally Unrelated Historical Notice".into()),
        date: Some("1901-01-01".into()),
        title_id: None,
        snippet: Some("nothing to do with the query at all".into()),
        url: Some("https://trove.nla.gov.au/newspaper/article/1".into()),
    }];
    let res = build_entities("Acme Pty Ltd", 1, &articles, "scan");

    let org = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("org headline");
    assert!(org.has_tag("needs-identity-verification"));
    assert!(
        (org.confidence - crate::core::confidence::LOW_MEDIUM).abs() < 1e-9,
        "unconfirmed relevance must demote below the confirmed HIGH tier: {}",
        org.confidence
    );

    let url = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("url source");
    assert!(url.has_tag("needs-identity-verification"));
    assert!(
        (url.confidence - crate::core::confidence::LOW_MEDIUM).abs() < 1e-9,
        "unconfirmed relevance must demote below MEDIUM_HIGH: {}",
        url.confidence
    );
    assert!(
        !url.evidence[0].summary.contains("mentioning the subject"),
        "an unconfirmed hit's summary must not assert relevance: {}",
        url.evidence[0].summary
    );
}

#[test]
fn build_entities_trusts_an_article_whose_snippet_names_the_query_even_if_the_title_does_not() {
    use super::{TroveArticle, build_entities};
    use crate::core::entity::EntityKind;

    let articles = vec![TroveArticle {
        id: Some("1".into()),
        title: Some("Local Business Notes".into()),
        date: Some("1950-01-01".into()),
        title_id: None,
        snippet: Some("...Acme Pty Ltd announced today...".into()),
        url: Some("https://trove.nla.gov.au/newspaper/article/1".into()),
    }];
    let res = build_entities("Acme Pty Ltd", 1, &articles, "scan");
    let url = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("url source");
    assert!(!url.has_tag("needs-identity-verification"));
    assert!((url.confidence - crate::core::confidence::MEDIUM_HIGH).abs() < 1e-9);
}

#[test]
fn all_fetched_articles_emit_url_sources_not_just_the_first_ten() {
    use super::{TroveArticle, build_entities};
    use crate::core::entity::EntityKind;

    // The request asks for n=20 and process collects every returned article, so
    // articles past the former take(10) cap must still become Url sources.
    let articles: Vec<TroveArticle> = (0..20)
        .map(|i| TroveArticle {
            id: Some(format!("{i}")),
            title: Some(format!("Mention {i}")),
            date: Some("1925-01-01".into()),
            title_id: None,
            snippet: None,
            url: Some(format!("https://trove.nla.gov.au/newspaper/article/{i}")),
        })
        .collect();
    let res = build_entities("Acme Pty Ltd", 20, &articles, "scan");
    let urls = res
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .count();
    assert_eq!(urls, 20, "all 20 fetched articles must emit a Url source");
}
