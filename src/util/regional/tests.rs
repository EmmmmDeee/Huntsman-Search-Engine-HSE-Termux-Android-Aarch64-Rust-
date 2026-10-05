use super::*;

#[test]
fn unscoped_defaults_to_false() {
    // No ambient set (mirrors a unit test / a call outside any scan) — must
    // degrade to `false`, the same default `ScanOptions::regional_search`
    // itself has, not panic or silently pick up a stale value.
    assert!(!regional_enabled());
}

#[test]
fn scoped_value_is_read_back_exactly() {
    with_regional_sync(true, || {
        assert!(regional_enabled());
    });
    with_regional_sync(false, || {
        assert!(!regional_enabled());
    });
    // Outside any scope again — back to the unscoped default.
    assert!(!regional_enabled());
}

#[test]
fn nested_scopes_do_not_leak_into_each_other() {
    // PROBLEM_TREE T2.11: two "scans" (here, nested scopes standing in for
    // two `hse serve` scans whose lifetimes overlap) must never see each
    // other's setting — the exact cross-scan contamination the old
    // process-global `AtomicBool` allowed ("last writer wins for the overlap
    // window"). A task-local is inherently per-task, so nesting a `false`
    // scope inside a `true` one must not affect the outer scope's own read
    // once control returns to it.
    with_regional_sync(true, || {
        assert!(regional_enabled(), "outer scope must read its own true");
        with_regional_sync(false, || {
            assert!(!regional_enabled(), "inner scope reads its own false");
        });
        assert!(
            regional_enabled(),
            "outer scope must still read true after the inner scope exited"
        );
    });
}

#[tokio::test]
async fn with_regional_scopes_an_async_future() {
    let inside = with_regional(true, async { regional_enabled() }).await;
    assert!(inside);
    // Outside the scope, the ambient is gone again.
    assert!(!regional_enabled());
}
