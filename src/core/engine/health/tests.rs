use super::*;

// Process-global state shared across parallel tests, exactly like `circuit`'s
// (see `circuit/tests.rs`'s own note). Each test uses a UNIQUE module name and
// only ever asserts on its OWN entry via `find`/`any` over `unhealthy_modules()`
// — never on the list's exact contents — so a sibling test's entries can never
// mask or corrupt this one.

#[test]
fn record_failure_increments_the_streak() {
    let m = "t_health_increments";
    record_failure(m);
    record_failure(m);
    record_failure(m);
    let entry = unhealthy_modules()
        .into_iter()
        .find(|h| h.name == m)
        .expect("must be reported after 3 failures");
    assert_eq!(entry.consecutive_failures, 3);
}

#[test]
fn record_success_clears_the_streak_and_stamps_last_success() {
    let m = "t_health_success_clears";
    record_failure(m);
    record_failure(m);
    record_success(m);
    assert!(
        unhealthy_modules().into_iter().all(|h| h.name != m),
        "a healthy module must not appear in the unhealthy list"
    );
}

#[test]
fn a_module_with_zero_failures_never_appears() {
    let m = "t_health_never_touched";
    assert!(unhealthy_modules().into_iter().all(|h| h.name != m));
}

#[test]
fn unrelated_modules_are_independent() {
    record_failure("t_health_indep_a");
    record_failure("t_health_indep_a");
    // A sibling module with its own, lower streak.
    record_failure("t_health_indep_b");
    let a = unhealthy_modules()
        .into_iter()
        .find(|h| h.name == "t_health_indep_a")
        .expect("a must be reported");
    let b = unhealthy_modules()
        .into_iter()
        .find(|h| h.name == "t_health_indep_b")
        .expect("b must be reported");
    assert_eq!(a.consecutive_failures, 2);
    assert_eq!(b.consecutive_failures, 1);
}

#[test]
fn unhealthy_modules_is_sorted_worst_first_then_by_name() {
    // Two modules with the SAME (non-zero) streak so the name tiebreak is what's
    // actually being exercised, plus one with a strictly worse streak.
    let worst = "t_health_sort_worst";
    let tie_b = "t_health_sort_tie_b";
    let tie_a = "t_health_sort_tie_a";
    record_failure(worst);
    record_failure(worst);
    record_failure(worst);
    record_failure(tie_b);
    record_failure(tie_a);

    let all = unhealthy_modules();
    let names: Vec<&str> = all
        .iter()
        .filter(|h| [worst, tie_b, tie_a].contains(&h.name))
        .map(|h| h.name)
        .collect();
    assert_eq!(
        names,
        vec![worst, tie_a, tie_b],
        "worst streak first, ties broken by name"
    );
}

#[test]
fn last_success_at_reflects_a_recorded_success_not_an_untouched_default() {
    let m = "t_health_last_success";
    // No success recorded yet for this fresh name: record a failure only, so
    // it appears in the unhealthy list with no last_success_at.
    record_failure(m);
    let before = unhealthy_modules()
        .into_iter()
        .find(|h| h.name == m)
        .expect("should succeed");
    assert_eq!(
        before.last_success_at, None,
        "a module that has never succeeded must report no last-success time"
    );

    record_success(m);
    record_failure(m); // fail again so it still appears in the unhealthy list
    let after = unhealthy_modules()
        .into_iter()
        .find(|h| h.name == m)
        .expect("should succeed");
    assert!(
        after.last_success_at.is_some(),
        "after a recorded success, last_success_at must be stamped"
    );
    assert_eq!(
        after.consecutive_failures, 1,
        "the streak after the intervening success must restart at 1"
    );
}
