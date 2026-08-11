use super::*;

#[test]
fn surname_of_takes_the_last_token_lowercased() {
    assert_eq!(surname_of("Erik Diegmann").as_deref(), Some("diegmann"));
    assert_eq!(surname_of("Mary Jane SMITH").as_deref(), Some("smith"));
    assert_eq!(
        surname_of("  spaced   Bamford  ").as_deref(),
        Some("bamford")
    );
    assert_eq!(surname_of("Cher").as_deref(), Some("cher")); // single token
    assert!(surname_of("").is_none());
    assert!(surname_of("   ").is_none());
}

#[test]
fn common_surnames_are_flagged_distinctive_ones_are_not() {
    // High-frequency English / migrant AU surnames → weak shared-surname evidence.
    for common in ["Smith", "JONES", "nguyen", "Williams", "patel", "o'connor"]
        .iter()
        .map(|s| s.replace('\'', ""))
    // o'connor → oconnor (apostrophe-folded form)
    {
        assert!(is_common(&common), "{common} should be common");
    }
    // Top-~100 names whose absence previously over-weighted a shared-surname match.
    for common in ["Griffiths", "Cox", "Chapman", "Lloyd", "Owen", "Hamilton"] {
        assert!(is_common(common), "{common} should be common");
    }
    assert!(is_common("  smith  "), "whitespace is ignored");

    // Distinctive surnames — including the people this tool is actually run on —
    // must NOT be flagged common, or the family signal would be wrongly weakened.
    for rare in [
        "Diegmann",
        "Bamford",
        "Moreau",
        "Avery",
        "Fairweather",
        "Quarry",
    ] {
        assert!(!is_common(rare), "{rare} should be distinctive");
    }
}

#[test]
fn apostrophe_surnames_are_flagged_common_through_the_real_surname_of_path() {
    // Regression: every caller feeds `surname_of` straight into `is_common`, and
    // `surname_of` lower-cases WITHOUT stripping the apostrophe, so its
    // `"o'connor"` never equalled the table's apostrophe-folded `"oconnor"`.
    // The Celtic-prefix names were therefore treated as distinctive, wrongly
    // escalating a bare shared-surname co-residency to a Critical kin signal.
    // Exercise the production path (name → surname_of → is_common), NOT a
    // pre-folded literal, so the fold has to happen inside `is_common`.
    for full in ["Daniel O'Connor", "Siobhan O'Brien", "Liam O'Neill"] {
        let sn = surname_of(full).expect("has a surname");
        assert!(
            is_common(&sn),
            "{full}: surname_of gave {sn:?}, which must be recognised as common"
        );
    }
    // The typographic apostrophe (scraped register text) folds identically.
    assert!(is_common(
        &surname_of("Grace O\u{2019}Connor").expect("has a surname")
    ));
}
