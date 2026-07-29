use super::*;

#[test]
fn accepts_only_phone() {
    let m = PhoneIntl;
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+1234567890")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x")));
}

#[test]
fn longest_prefix_wins() {
    let (prefix, iso, _name) = match_country("18764567890").expect("should succeed");
    assert_eq!(prefix, "1876");
    assert_eq!(iso, "JM");

    let (prefix, iso, _name) = match_country("12025550100").expect("should succeed");
    assert_eq!(prefix, "1");
    assert_eq!(iso, "US");
}

#[test]
fn international_codes() {
<<<<<<< HEAD
    assert_eq!(match_country("442071838750").expect("should succeed").1, "GB");
    assert_eq!(match_country("61400000000").expect("should succeed").1, "AU");
    assert_eq!(match_country("33123456789").expect("should succeed").1, "FR");
    assert_eq!(match_country("861234567890").expect("should succeed").1, "CN");
=======
    assert_eq!(
        match_country("442071838750").expect("should succeed").1,
        "GB"
    );
    assert_eq!(
        match_country("61400000000").expect("should succeed").1,
        "AU"
    );
    assert_eq!(
        match_country("33123456789").expect("should succeed").1,
        "FR"
    );
    assert_eq!(
        match_country("861234567890").expect("should succeed").1,
        "CN"
    );
>>>>>>> origin/main
}

#[test]
fn unknown_prefix() {
    assert!(match_country("000000000").is_none());
}

#[test]
fn international_digits_requires_explicit_marker() {
    // Explicit '+' (E.164) → the country-code-leading digit string.
    assert_eq!(
        international_digits("+1 876 456 7890").as_deref(),
        Some("18764567890")
    );
    assert_eq!(
        international_digits(" +61 (4) 0000 0000 ").as_deref(),
        Some("61400000000")
    );
    // ITU '00' international-call prefix → stripped to expose the code.
    assert_eq!(
        international_digits("0061 400 000 000").as_deref(),
        Some("61400000000")
    );
    // No marker → None, even though the leading digits LOOK like a country
    // code. This is the regression: a US national number begins with an
    // area code (202, 415, 650 …) that the old all-digits match mis-read as
    // Egypt (+20), Switzerland (+41), Singapore (+65) and emitted a bogus
    // "+E.164" number. A national/ambiguous number must resolve to nothing.
    assert_eq!(international_digits("202-555-0100"), None);
    assert_eq!(international_digits("(415) 555-0100"), None);
    assert_eq!(international_digits("650 555 0100"), None);
    // A national trunk '0' is a single zero, not the '00' international
    // prefix, so it is correctly treated as national (no attribution).
    assert_eq!(international_digits("0400 000 000"), None);
}

#[test]
fn country_table_is_well_formed_and_prefix_ordered() {
    // 1. Every entry is well-formed: a digit-only dialling prefix, a 2-letter
    //    uppercase ISO code, and a non-empty name.
    for (prefix, iso, name) in COUNTRIES {
        assert!(
            !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()),
            "bad dialling prefix {prefix:?} ({name})"
        );
        assert!(
            iso.len() == 2 && iso.bytes().all(|b| b.is_ascii_uppercase()),
            "bad ISO code {iso:?} ({name})"
        );
        assert!(!name.is_empty(), "empty country name for {iso}");
    }

    // 2. Longest-prefix-first ordering, table-wide. `match_country` returns the
    //    FIRST prefix that the number starts with, so when an earlier entry's
    //    prefix is a string-prefix of a later one's, that later country is
    //    unreachable — every one of its numbers resolves to the earlier code.
    //    The specific code must precede its generic stem (1876 Jamaica before
    //    1 US). Generalises the hand-picked `longest_prefix_wins` check to all
    //    229 entries and any future addition. (Also catches an exact-duplicate
    //    prefix, which `starts_with` flags.)
    let mut violations = Vec::new();
    for (i, (earlier, _, ename)) in COUNTRIES.iter().enumerate() {
        for (later, _, lname) in &COUNTRIES[i + 1..] {
            if later.starts_with(earlier) {
                violations.push(format!(
                    "+{later} ({lname}) is shadowed by the earlier +{earlier} ({ename})"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "phone-prefix ordering violated — move the specific code above its generic stem:\n  {}",
        violations.join("\n  ")
    );
}
