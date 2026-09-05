use super::*;

#[test]
fn categorises_each_documented_vn_second_level_domain() {
    // Every VNNIC second-level domain with an unambiguous registrant type maps
    // to the AU-shared category vocabulary. Subdomains classify identically.
    let cases = [
        ("mps.gov.vn", "government"),
        ("mail.mps.gov.vn", "government"),
        ("vnu.edu.vn", "education"),
        ("student.vnu.edu.vn", "education"),
        ("vast.ac.vn", "education"),
        ("redcross.org.vn", "non-profit"),
        ("vietcombank.com.vn", "commercial"),
        ("shop.biz.vn", "commercial"),
        ("isp.net.vn", "commercial"),
        ("nguyen-van-a.name.vn", "individual"),
    ];
    for (domain, want) in cases {
        let (category, label) =
            vn_domain_registrant(domain).unwrap_or_else(|| panic!("{domain} must classify"));
        assert_eq!(category, want, "{domain} → {category}, wanted {want}");
        // The label always names the second-level domain it was matched on.
        assert!(
            label.contains(".vn)") || label.contains("vn)"),
            "{domain} label {label:?} should cite the .vn 2LD"
        );
    }
}

#[test]
fn case_insensitive_and_trailing_dot_tolerant() {
    // An FQDN with a trailing root dot and mixed case must still classify — the
    // same normalisation the AU helper applies.
    assert_eq!(
        vn_domain_registrant("MPS.GOV.VN.").map(|(c, _)| c),
        Some("government")
    );
}

#[test]
fn non_vn_and_categoryless_vn_domains_return_none() {
    // Not `.vn` at all.
    assert!(vn_domain_registrant("example.com").is_none());
    assert!(vn_domain_registrant("commbank.com.au").is_none());
    // A bare second-level `.vn` (VNNIC permits direct registration) and the
    // ambiguous 2LDs carry no registrant-*type* signal.
    assert!(vn_domain_registrant("chinhphu.vn").is_none());
    assert!(vn_domain_registrant("doctor.pro.vn").is_none());
    assert!(vn_domain_registrant("portal.info.vn").is_none());
    assert!(vn_domain_registrant("clinic.health.vn").is_none());
    // Empty / junk.
    assert!(vn_domain_registrant("").is_none());
    assert!(vn_domain_registrant("vn").is_none());
}

#[test]
fn a_vn_substring_that_is_not_a_vn_suffix_does_not_match() {
    // A domain merely CONTAINING "gov.vn" as a non-suffix substring (e.g. a
    // `.com` domain with that text in a label) must not classify as Vietnamese.
    assert!(vn_domain_registrant("gov.vn.example.com").is_none());
    assert!(vn_domain_registrant("mygov.vnet.com").is_none());
}

#[test]
fn category_vocabulary_matches_the_au_registrant_classifier() {
    // The VN categories must be a subset of the AU vocabulary so a shared
    // downstream consumer reads both with one set of category strings. If the AU
    // side ever renames a category, this fails and forces the two to stay in sync.
    use crate::util::address_au::au_domain_registrant;
    let au_categories: std::collections::BTreeSet<&'static str> = [
        "haigen.id.au",     // individual
        "acme.com.au",      // commercial
        "club.org.au",      // non-profit
        "assoc.asn.au",     // association
        "dept.gov.au",      // government
        "uni.edu.au",       // education
    ]
    .iter()
    .filter_map(|d| au_domain_registrant(d).map(|(c, _)| c))
    .collect();

    for domain in [
        "x.gov.vn",
        "x.edu.vn",
        "x.ac.vn",
        "x.org.vn",
        "x.com.vn",
        "x.biz.vn",
        "x.net.vn",
        "x.name.vn",
    ] {
        let (category, _) = vn_domain_registrant(domain).expect("classifies");
        assert!(
            au_categories.contains(category),
            "VN category {category:?} (from {domain}) is not in the AU vocabulary {au_categories:?}"
        );
    }
}
