use super::*;
use serde_json::json;

#[test]
fn exact_value_match_short_circuits_on_any_field() {
    let tm = TargetMatch::new("ali.kareem95@gmail.com");
    assert!(tm.matches(&json!({ "email": "ali.kareem95@gmail.com" })));
    // Case-insensitive.
    assert!(tm.matches(&json!({ "email": "Ali.Kareem95@Gmail.com" })));
}

#[test]
fn multi_term_target_requires_every_term_in_one_field() {
    // "Jordan Avery" -> terms {jordan, avery}; a shared FIRST name only must NOT
    // count as the subject (the dominant false-positive on name scans).
    let tm = TargetMatch::new("Jordan Avery");
    assert!(tm.matches(&json!({ "full_name": "Jordan Avery" })));
    assert!(tm.matches(&json!({ "full_name": "JORDAN MICHAEL AVERY" })));
    assert!(!tm.matches(&json!({ "full_name": "Jordan Parker" })));
    assert!(!tm.matches(&json!({ "full_name": "Bob Avery" })));
}

#[test]
fn single_term_target_keeps_substring_matching() {
    // A single significant term (a handle) matches as a substring, so a
    // concatenated variant of the handle still counts as the subject.
    let tm = TargetMatch::new("alikareem");
    assert!(tm.matches(&json!({ "username": "alikareem" })));
    assert!(tm.matches(&json!({ "username": "alikareem2024" })));
    assert!(!tm.matches(&json!({ "username": "bobsmith" })));
}

#[test]
fn matches_across_the_union_of_provider_field_spellings() {
    // `phone` and `name` (see_know spellings) are honoured alongside
    // `phone_number` and `full_name` (oathnet spellings).
    let phone = TargetMatch::new("15551234567");
    assert!(phone.matches(&json!({ "phone": "15551234567" })));
    assert!(phone.matches(&json!({ "phone_number": "15551234567" })));

    let name = TargetMatch::new("Ali Kareem");
    assert!(name.matches(&json!({ "name": "Ali Kareem" })));
    assert!(name.matches(&json!({ "full_name": "Ali Kareem" })));
}

#[test]
fn non_matching_record_is_not_the_subject() {
    let tm = TargetMatch::new("Ali Kareem");
    // A stranger from a broad page — no field carries both terms.
    assert!(!tm.matches(&json!({
        "email": "james.perry@scansamerica.com",
        "full_name": "James Perry",
        "username": "jperry"
    })));
}

#[test]
fn candidate_conf_is_the_quarantine_ceiling() {
    assert!((CANDIDATE_CONF - 0.25).abs() < f64::EPSILON);
}
