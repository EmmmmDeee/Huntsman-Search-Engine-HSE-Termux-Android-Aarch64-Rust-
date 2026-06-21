use super::*;

#[test]
fn reads_the_embedded_category_from_real_snusbase_sources() {
    // The exact source-DB values from the "Ali Kareem" combined-search dump.
    assert_eq!(
        source_sector("0645_ZYNGA_COM_202M_GAMING_092019"),
        Some("gaming")
    );
    assert_eq!(
        source_sector("1769_AITYPE_COM_75M_TECH_122017"),
        Some("tech")
    );
    // Case-insensitive (providers vary the casing).
    assert_eq!(
        source_sector("0645_zynga_com_202m_gaming_092019"),
        Some("gaming")
    );
}

#[test]
fn declines_a_non_real_estate_domain_source() {
    // The real oathnet source for the Ali Kareem rows: a B2B data broker, NOT
    // real estate. It must NOT be mislabelled (no trailing-date token, no
    // property keyword) — the conservative `None`.
    assert_eq!(source_sector("pureincubation.com"), None);
    // Generic test sources used across the suites stay unclassified too.
    assert_eq!(source_sector("TestDB"), None);
    assert_eq!(source_sector("TestBreach"), None);
    assert_eq!(source_sector("snusbase"), None);
    assert_eq!(source_sector(""), None);
}

#[test]
fn recognises_real_estate_by_brand_domain_or_category() {
    // Domain-style sources (the oathnet shape).
    assert_eq!(source_sector("realestate.com.au"), Some("real-estate"));
    assert_eq!(source_sector("harcourts.com.au"), Some("real-estate"));
    assert_eq!(source_sector("PropertyTree"), Some("real-estate"));
    assert_eq!(source_sector("ljhooker"), Some("real-estate"));
    assert_eq!(source_sector("onthehouse.com.au"), Some("real-estate"));
    // Structured source whose category token is the property sector.
    assert_eq!(
        source_sector("0123_RENTBERRY_COM_4M_REALESTATE_012020"),
        Some("real-estate")
    );
    // …and brand-in-a-structured-name resolves via the keyword pass.
    assert_eq!(
        source_sector("0456_HARCOURTS_AU_2M_LEAKED_032021"),
        Some("real-estate")
    );
}

#[test]
fn maps_other_structured_categories() {
    assert_eq!(
        source_sector("9001_ACME_COM_10M_FINANCE_012020"),
        Some("finance")
    );
    assert_eq!(
        source_sector("9002_ACME_COM_10M_HEALTH_012020"),
        Some("health")
    );
    // Unknown category token → None (never a guess).
    assert_eq!(source_sector("9003_ACME_COM_10M_WIDGETS_012020"), None);
    // A trailing non-date segment is not a category position → None.
    assert_eq!(source_sector("9004_ACME_COM_10M_FINANCE_FINAL"), None);
}
