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
fn short_name_part_does_not_collapse_into_substring_matching() {
    // A two-word full name whose surname is under the significance threshold
    // ("Ng", "Li", "Wu", "Oh" — extremely common East Asian surnames) must NOT
    // degrade to single-term substring matching. It previously did: the
    // `require_all_terms` guard counted terms AFTER the `len >= 3` filter, so
    // "Sarah Ng" kept only {sarah} and any stranger sharing the given name was
    // accepted as the subject — the exact false positive the multi-term rule
    // exists to prevent, and one that lands hardest on non-Anglo names.
    let tm = TargetMatch::new("Sarah Ng");
    assert!(tm.matches(&json!({ "full_name": "Sarah Ng" })));
    assert!(
        !tm.matches(&json!({ "full_name": "Sarah Johnson" })),
        "a stranger sharing only the given name must not be the subject"
    );

    // The substring hazard is worse than a shared whole name: a short term can
    // land INSIDE an unrelated word. "Ali Ng" -> {ali}, and "Natalie" contains
    // "ali", so an unrelated person was minted as the target at full confidence.
    let tm = TargetMatch::new("Ali Ng");
    assert!(tm.matches(&json!({ "full_name": "Ali Ng" })));
    assert!(
        !tm.matches(&json!({ "full_name": "Natalie Brown" })),
        "a substring hit inside an unrelated name must not be the subject"
    );
}

#[test]
fn all_short_name_parts_still_match_their_own_row() {
    // Both parts under the old significance floor left ZERO terms, so the row
    // could only ever match by exact string equality — a name-only row for the
    // subject was quarantined as a stranger. Counting unfiltered tokens fixes
    // the false negative in the same stroke as the false positive.
    let tm = TargetMatch::new("Li Wu");
    assert!(tm.matches(&json!({ "full_name": "Li Wu" })));
    assert!(tm.matches(&json!({ "name": "LI WU" })));
    // ...without letting either short part match inside a longer word:
    // "william" contains "li", "wu" — substring matching would accept this.
    assert!(
        !tm.matches(&json!({ "full_name": "William Wunsch" })),
        "short parts must match as whole words, not inside longer names"
    );
}

#[test]
fn handle_target_matches_bare_token_not_raw_punctuation() {
    // A single-token target keeps substring matching against the BARE token, so
    // a leading `@` on the seeded handle does not have to reappear in the record.
    let tm = TargetMatch::new("@alikareem");
    assert!(tm.matches(&json!({ "username": "alikareem2024" })));
    // A token below the significance floor never matches partially — a bare
    // "jo" must not select every "John".
    let short = TargetMatch::new("jo");
    assert!(!short.matches(&json!({ "username": "john_smith" })));
    assert!(short.matches(&json!({ "username": "jo" })), "exact still holds");
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
fn ip_target_matches_ip_fields() {
    // Regression: DeHashed IP-target scans were incorrectly demoting all matched
    // records to candidate tier because TargetMatch never inspected the IP fields.
    // A target that is itself an IP address should match rows via ip_address/ip/last_ip.
    let tm = TargetMatch::new("1.2.3.4");
    // Should match on any of the IP field spellings.
    assert!(tm.matches(&json!({ "ip_address": "1.2.3.4" })));
    assert!(tm.matches(&json!({ "ip": "1.2.3.4" })));
    assert!(tm.matches(&json!({ "last_ip": "1.2.3.4" })));
    // Case-insensitive (though IPs are normally numeric).
    assert!(tm.matches(&json!({ "ip_address": "1.2.3.4" })));
    // Should not match unrelated IPs.
    assert!(!tm.matches(&json!({ "ip_address": "5.6.7.8" })));
}

#[test]
fn short_non_ascii_target_stays_exact_only() {
    // Regression: MIN_SIGNIFICANT_TERM was compared against str::len() (bytes),
    // so a two-CHARACTER non-ASCII token (6 bytes for CJK) slipped into
    // permissive substring mode — the exact class of failure the mode gate
    // exists to stop, landing hardest on non-Anglo targets.
    let tm = TargetMatch::new("李明");
    // Substring containment inside a longer name must NOT count as the subject.
    assert!(!tm.matches(&json!({ "full_name": "李明轩" })));
    // Exact equality still holds.
    assert!(tm.matches(&json!({ "full_name": "李明" })));
    // Same bug shape in Cyrillic: "ян" is 2 chars / 4 bytes.
    let tm = TargetMatch::new("ян");
    assert!(!tm.matches(&json!({ "full_name": "янина петрова" })));
}
