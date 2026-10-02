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
    use super::{TroveArticle, TroveTitle, build_entities};
    use crate::core::entity::EntityKind;

    let articles = vec![
        TroveArticle {
            id: Some("18341291".into()),
            heading: Some("ACME COMPANY NOTICE".into()),
            date: Some("1923-04-01".into()),
            title: Some(TroveTitle::Object {
                id: Some("35".into()),
                title: Some("The Sydney Morning Herald".into()),
            }),
            snippet: Some("...the directors of Acme...".into()),
            trove_url: None,
            url: Some("https://trove.nla.gov.au/newspaper/article/18341291".into()),
        },
        // A second article with the SAME url must dedup to one entity.
        TroveArticle {
            id: Some("18341291".into()),
            heading: Some("dup".into()),
            date: Some("1923-04-02".into()),
            title: None,
            snippet: None,
            trove_url: None,
            url: Some("https://trove.nla.gov.au/newspaper/article/18341291".into()),
        },
        // An article with no URL is skipped (nothing to pivot on).
        TroveArticle {
            id: Some("999".into()),
            heading: Some("no url".into()),
            date: Some("1924-01-01".into()),
            title: None,
            snippet: None,
            trove_url: None,
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
    // The publishing masthead (v3's `title` object) is carried as provenance.
    assert_eq!(attrs.get("masthead_id").map(String::as_str), Some("35"));
    assert_eq!(
        attrs.get("newspaper").map(String::as_str),
        Some("The Sydney Morning Herald")
    );

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
        heading: Some("Totally Unrelated Historical Notice".into()),
        date: Some("1901-01-01".into()),
        title: None,
        snippet: Some("nothing to do with the query at all".into()),
        trove_url: None,
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
        heading: Some("Local Business Notes".into()),
        date: Some("1950-01-01".into()),
        title: None,
        snippet: Some("...Acme Pty Ltd announced today...".into()),
        trove_url: None,
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
            heading: Some(format!("Mention {i}")),
            date: Some("1925-01-01".into()),
            title: None,
            snippet: None,
            trove_url: None,
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

#[test]
fn the_v3_envelope_is_decoded_and_the_v2_shape_is_a_failed_lookup_not_zero_hits() {
    // Backlog #46. The module decoded v2's `response.zone[]` from the v3
    // endpoint, so every keyed search read as zero hits and was cached for a
    // day. v3 answers a top-level `category[]`, each with `records.total` and
    // `records.article[]`; an article's headline is `heading`, its `title` is
    // the masthead object and `troveUrl` the reader page. (Shape per the Trove
    // API v3 documentation; no key here for a live capture — a body of any
    // other shape is now a failed lookup, never zero hits.)
    use super::{TroveResp, build_entities, newspaper_records};
    let v3: TroveResp = serde_json::from_str(
        r#"{"query":"Acme Pty Ltd","category":[{"code":"newspaper","name":"Newspapers & Gazettes","records":{"s":"*","n":20,"total":42,"article":[{"id":"18341291","url":"https://api.trove.nla.gov.au/v3/newspaper/18341291","heading":"ACME COMPANY NOTICE","category":"Article","title":{"id":"35","title":"The Sydney Morning Herald"},"date":"1923-04-01","troveUrl":"https://trove.nla.gov.au/newspaper/article/18341291","snippet":"...the directors of Acme..."}]}}]}"#,
    )
    .expect("the v3 envelope decodes");
    let (total, articles) = newspaper_records(v3).expect("recognised");
    assert_eq!(total, 42);
    assert_eq!(articles.len(), 1);
    assert_eq!(articles[0].headline(), Some("ACME COMPANY NOTICE"));
    assert_eq!(
        articles[0].link(),
        Some("https://trove.nla.gov.au/newspaper/article/18341291")
    );
    assert_eq!(
        articles[0].newspaper(),
        (Some("The Sydney Morning Herald"), Some("35"))
    );
    let res = build_entities("Acme Pty Ltd", total, &articles, "scan");
    assert!(
        res.entities
            .iter()
            .any(|e| e.value.contains("newspaper/article/18341291"))
    );

    // The v2 envelope — what the module used to expect — is no longer read
    // as an empty archive.
    let v2: TroveResp = serde_json::from_str(
        r#"{"response":{"zone":[{"name":"newspaper","records":{"total":"42","article":[]}}]}}"#,
    )
    .expect("decodes to a defaulted record");
    let err = newspaper_records(v2).expect_err("a shape this module does not recognise");
    assert!(err.to_string().contains("does not recognise"), "{err}");
}
