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

#[test]
fn a_blocked_or_failing_status_is_never_a_confirmed_absence() {
    // The defect this exists to stop: every status that was not the site's
    // presence code became `NotFound`, so a Cloudflare-blocked sweep filled
    // `definitive_absent`, `inconclusive()` was never handed anything to weigh,
    // and the module reported a confident "this handle exists nowhere".
    for blocked in [401, 403, 405, 408, 429, 451, 500, 502, 503, 504] {
        assert!(
            matches!(classify_non_matching_status(blocked), ProbeResult::Error),
            "HTTP {blocked} establishes nothing about the handle, so it must be \
             inconclusive — not a definitive absence"
        );
    }
}

#[test]
fn only_a_real_absence_answer_counts_as_definitive() {
    for absent in [404, 410] {
        assert!(
            matches!(classify_non_matching_status(absent), ProbeResult::NotFound),
            "HTTP {absent} is the web's absence answer"
        );
    }
    // The origin answered successfully, just not with this site's presence
    // code — it served a page about this handle and it was not a profile.
    for ok in [200, 201, 204, 299] {
        assert!(
            matches!(classify_non_matching_status(ok), ProbeResult::NotFound),
            "HTTP {ok} is a real answer"
        );
    }
}

#[test]
fn a_surfacing_redirect_or_informational_status_is_inconclusive() {
    // The probe client follows redirects, so a 3xx reaching the classifier means
    // the SSRF guard declined to follow it — nothing was learned. A 1xx is never
    // a final answer.
    for undecided in [100, 101, 301, 302, 303, 307, 308] {
        assert!(
            matches!(classify_non_matching_status(undecided), ProbeResult::Error),
            "HTTP {undecided} is not a final answer about the handle"
        );
    }
}

#[test]
fn a_fully_blocked_sweep_now_reaches_the_inconclusive_guard() {
    // End to end over the two pure functions: 30 sites, every one WAF-blocked.
    // Before the classifier every probe scored `NotFound`, so `errored` was 0 and
    // `inconclusive(0, 0, 30)` was false — a confident zero. Now they all score
    // `Error`, and the guard fires.
    let errored = [403; 30]
        .iter()
        .filter(|s| matches!(classify_non_matching_status(**s), ProbeResult::Error))
        .count();
    assert_eq!(errored, 30);
    assert!(inconclusive(0, errored, 30));
    assert!(
        !inconclusive(0, 0, 30),
        "this is what the old classification produced — pinned so the \
         difference the fix makes stays visible"
    );
}
