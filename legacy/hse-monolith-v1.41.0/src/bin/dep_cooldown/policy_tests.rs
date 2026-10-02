use super::*;
use time::format_description::well_known::Rfc3339;

/// Parse a fixed RFC 3339 instant for test fixtures — avoids pulling in
/// `time`'s `macros` feature (an extra proc-macro dependency) just for
/// `datetime!` literals when this crate already enables `parsing`.
fn dt(rfc3339: &str) -> OffsetDateTime {
    OffsetDateTime::parse(rfc3339, &Rfc3339).expect("valid RFC 3339 fixture")
}

fn publish(name: &str, version: &str, published_at: OffsetDateTime) -> PackagePublish {
    PackagePublish {
        name: name.to_string(),
        version: version.to_string(),
        published_at,
    }
}

fn allow(name: &str, version: &str) -> AllowEntry {
    AllowEntry {
        name: name.to_string(),
        version: version.to_string(),
        reason: "test".to_string(),
    }
}

#[test]
fn flags_a_package_published_inside_the_window() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-22T00:00:00Z"); // 2 days ago
    let violations = find_violations(now, 4, &[publish("evil-crate", "1.0.1", published_at)], &[]);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].name, "evil-crate");
    assert_eq!(violations[0].days_since_publish, 2);
}

#[test]
fn does_not_flag_a_package_published_outside_the_window() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-01T00:00:00Z"); // 23 days ago
    let violations = find_violations(now, 4, &[publish("old-crate", "1.0.0", published_at)], &[]);
    assert!(violations.is_empty());
}

#[test]
fn boundary_exactly_at_cooldown_days_is_not_a_violation() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-20T00:00:00Z"); // exactly 4 days ago
    let violations = find_violations(now, 4, &[publish("crate-a", "1.0.0", published_at)], &[]);
    assert!(violations.is_empty(), "published exactly cooldown_days ago should clear the window");
}

#[test]
fn one_day_inside_the_boundary_is_a_violation() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-21T00:00:00Z"); // 3 days ago, cooldown is 4
    let violations = find_violations(now, 4, &[publish("crate-a", "1.0.0", published_at)], &[]);
    assert_eq!(violations.len(), 1);
}

#[test]
fn allow_listed_exact_version_is_not_flagged() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-23T00:00:00Z"); // 1 day ago
    let violations = find_violations(
        now,
        4,
        &[publish("reviewed-crate", "2.0.0", published_at)],
        &[allow("reviewed-crate", "2.0.0")],
    );
    assert!(violations.is_empty());
}

#[test]
fn allow_list_does_not_cover_a_different_version_of_the_same_crate() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-23T00:00:00Z"); // 1 day ago
    let violations = find_violations(
        now,
        4,
        &[publish("reviewed-crate", "2.0.1", published_at)],
        &[allow("reviewed-crate", "2.0.0")],
    );
    assert_eq!(violations.len(), 1, "allow-listing 2.0.0 must not exempt 2.0.1");
}

#[test]
fn a_publish_timestamp_after_now_is_treated_as_a_violation() {
    // Clock skew or a registry anomaly — fail closed rather than silently pass.
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-25T00:00:00Z"); // "in the future"
    let violations = find_violations(now, 4, &[publish("skewed-crate", "1.0.0", published_at)], &[]);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].days_since_publish < 0);
}

#[test]
fn zero_cooldown_days_flags_nothing_published_before_now() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-23T23:59:59Z");
    let violations = find_violations(now, 0, &[publish("crate-a", "1.0.0", published_at)], &[]);
    assert!(violations.is_empty());
}

#[test]
fn policy_file_parses_cooldown_days_and_allow_list() {
    let raw = r#"
cooldown_days = 7

[[allow]]
name = "urgent-fix"
version = "3.1.4"
reason = "RUSTSEC-2026-0001, reviewed manually"
"#;
    let policy = parse_policy_file(raw).expect("valid policy file");
    assert_eq!(policy.cooldown_days, Some(7));
    assert_eq!(
        policy.allow,
        vec![AllowEntry {
            name: "urgent-fix".to_string(),
            version: "3.1.4".to_string(),
            reason: "RUSTSEC-2026-0001, reviewed manually".to_string(),
        }]
    );
}

#[test]
fn empty_policy_file_defaults_to_no_override_and_no_allow_list() {
    let policy = parse_policy_file("").expect("empty file is valid");
    assert_eq!(policy, PolicyFile::default());
}

#[test]
fn unknown_field_in_policy_file_is_a_parse_error() {
    assert!(parse_policy_file("cooldown-days = 7\n").is_err());
}

fn fetch_error(name: &str) -> crate::registry::FetchError {
    crate::registry::FetchError {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        message: "boom".to_string(),
    }
}

#[test]
fn should_fail_is_false_when_nothing_is_wrong() {
    assert!(!should_fail(&[], &[], 5, false));
    assert!(!should_fail(&[], &[], 5, true));
}

#[test]
fn should_fail_is_true_on_any_violation_regardless_of_strict() {
    let now = dt("2026-08-24T00:00:00Z");
    let published_at = dt("2026-08-23T00:00:00Z");
    let v = find_violations(now, 4, &[publish("evil", "1.0.0", published_at)], &[]);
    assert!(should_fail(&v, &[], 1, false));
    assert!(should_fail(&v, &[], 1, true));
}

#[test]
fn should_fail_is_true_when_every_lookup_failed_even_without_strict() {
    // The fail-open case: a total registry outage must never report "OK" just because
    // find_violations had nothing to flag among zero resolved packages.
    let errors = vec![fetch_error("a"), fetch_error("b")];
    assert!(should_fail(&[], &errors, 2, false));
}

#[test]
fn should_fail_is_false_on_a_partial_lookup_failure_without_strict() {
    let errors = vec![fetch_error("a")];
    assert!(!should_fail(&[], &errors, 3, false));
}

#[test]
fn should_fail_is_true_on_a_partial_lookup_failure_with_strict() {
    let errors = vec![fetch_error("a")];
    assert!(should_fail(&[], &errors, 3, true));
}

#[test]
fn should_fail_is_false_with_zero_packages_in_scope() {
    assert!(!should_fail(&[], &[], 0, false));
    assert!(!should_fail(&[], &[], 0, true));
}
