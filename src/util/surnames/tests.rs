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
