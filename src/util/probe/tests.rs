use super::*;

#[test]
fn zero_hits_is_inconclusive_only_when_mostly_blocked() {
    // M6 policy: a zero-hit run is "inconclusive" (surfaced as an error, not a
    // confirmed absence) only when at least half the probes were blocked.
    assert!(inconclusive(0, 30, 30), "all blocked → inconclusive");
    assert!(inconclusive(0, 15, 30), "exactly half blocked → inconclusive");
    assert!(
        !inconclusive(0, 5, 30),
        "mostly definitive not-found → genuine absence"
    );
    assert!(!inconclusive(3, 27, 30), "any hit → never inconclusive");
    assert!(!inconclusive(0, 0, 0), "no probes → not inconclusive");
}

#[test]
fn browser_ua_is_chrome_shaped() {
    // Regression guard: reverting to the tool UA (`huntsman-search-engine/...`)
    // makes Cloudflare-fronted sites 403 a large slice of the table again, so
    // lock in the browser shape — anyone changing it must update this test.
    assert!(BROWSER_UA.contains("Mozilla/5.0"));
    assert!(BROWSER_UA.contains("Chrome/"));
    assert!(!BROWSER_UA.contains("huntsman-search-engine"));
}
