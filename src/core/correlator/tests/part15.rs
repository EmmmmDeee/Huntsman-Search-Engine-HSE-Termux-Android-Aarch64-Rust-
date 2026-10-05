#[test]
fn seed_and_url_extract_do_not_manufacture_infra_consensus_or_cross_source_corroboration() {
    // Regression (live andersonbushikai.com URL scan, debug bundle
    // 6b2d34664852…): the apex domain's evidence chain was `url_extract` (the
    // offline restatement of the seed URL's own host) plus `dns_intel`,
    // `mnemonic_pdns`, `waf_detect`, `webserver_banner` — four REAL lookups.
    // AU-003 reported "corroborated by 5 independent source(s)" and AU-010
    // reported "confirmed by 5 infrastructure sources: dns_intel,
    // mnemonic_pdns, url_extract, waf_detect, webserver_banner" — both
    // one-too-many, because url_extract restates a fact already in the graph
    // rather than observing it independently.
    use crate::core::test_support::InMemoryStore;
    let store: Arc<dyn StoragePort> = Arc::new(InMemoryStore::new());
    let sid = "seed-infra-test";

    let mut domain = Entity::new(EntityKind::Domain, "example.com", 0.92, sid);
    for src in [
        "url_extract",
        "dns_intel",
        "mnemonic_pdns",
        "waf_detect",
        "webserver_banner",
    ] {
        domain.add_evidence(Evidence::new(src, "seen"));
    }
    store.upsert_entity(&domain).expect("should succeed");

    let corr = Correlator::new(Arc::clone(&store));
    let hits = corr.run(sid).expect("should succeed");

    let au003 = hits
        .iter()
        .find(|c| c.rule_id == "AU-003")
        .expect("4 real sources still clears AU-003's floor");
    assert!(
        au003
            .description
            .contains("corroborated by 4 independent source"),
        "url_extract must not be counted as a 5th independent source, got: {}",
        au003.description
    );

    let au010 = hits
        .iter()
        .find(|c| c.rule_id == "AU-010")
        .expect("4 real infrastructure sources still clears AU-010's floor");
    assert!(
        !au010.description.contains("url_extract"),
        "url_extract must not be listed as an infrastructure source, got: {}",
        au010.description
    );
    assert!(
        au010
            .description
            .contains("confirmed by 4 infrastructure sources"),
        "got: {}",
        au010.description
    );
}
