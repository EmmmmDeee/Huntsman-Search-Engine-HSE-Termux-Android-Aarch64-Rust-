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

/// The real Cloudflare interstitial AustLII served on 2026-09-15, here served
/// with the site's presence status: it carries no site marker, so the old
/// needle-only reading called it a verified presence on every
/// `StatusAndNotBody` site and a definitive absence on every `StatusAndBody`
/// site. A wall is neither. The site's own pages still read by their marker.
#[test]
fn a_wall_served_with_the_presence_status_is_neither_present_nor_absent() {
    const WALL: &str =
        include_str!("../html/testdata/cloudflare_challenge_austlii_2026-09-15.html");
    assert_eq!(classify_page(WALL, "Page not found", false), PageVerdict::Wall);
    assert_eq!(classify_page(WALL, "profile-header", true), PageVerdict::Wall);
    // A site that 200s for everything: the missing profile carries the marker.
    assert_eq!(
        classify_page("<html><body>Page not found</body></html>", "Page not found", false),
        PageVerdict::Absent
    );
    assert_eq!(
        classify_page("<html><body>@alice's channel</body></html>", "Page not found", false),
        PageVerdict::Present
    );
    // A site whose profile page carries the marker.
    assert_eq!(
        classify_page("<html><div class=\"profile-header\"></div></html>", "profile-header", true),
        PageVerdict::Present
    );
    assert_eq!(
        classify_page("<html><body>nothing here</body></html>", "profile-header", true),
        PageVerdict::Absent
    );
    // Data that merely mentions a vendor path is not a document, so not a wall.
    assert_eq!(
        classify_page("{\"src\":\"/cdn-cgi/challenge-platform/x\"}", "profile-header", true),
        PageVerdict::Absent
    );
}

// ── The negative control: a presence is judged against a handle nobody holds ──

fn present(url: &str) -> ProbeResult {
    ProbeResult::Found {
        url: url.to_string(),
        confidence: 0.74,
        verified: false,
        controlled: false,
    }
}

#[test]
fn the_control_handle_is_a_twelve_character_handle_drawn_once_per_process() {
    let h = control_handle();
    assert_eq!(h.chars().count(), 12, "{h:?}");
    assert!(h.chars().next().is_some_and(|c| c.is_ascii_lowercase()), "{h:?}");
    assert!(
        h.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "{h:?}"
    );
    assert_eq!(control_handle(), h, "the same handle for the whole process");
}

/// The judgement: a presence the site also gave the control handle is
/// indiscriminate; one the site denied the control handle stands, controlled;
/// one whose control could not be read stands as it was; an absence or a
/// refusal needs no control.
#[test]
fn a_presence_the_site_also_gives_the_control_handle_is_indiscriminate() {
    let url = "https://example.test/u/alice";
    assert_eq!(
        controlled(present(url), &present("https://example.test/u/ctl")),
        ProbeResult::Indiscriminate {
            url: url.to_string()
        }
    );
    assert_eq!(
        controlled(
            present(url),
            &ProbeResult::Indiscriminate {
                url: "https://example.test/u/ctl".to_string()
            }
        ),
        ProbeResult::Indiscriminate {
            url: url.to_string()
        }
    );
    assert_eq!(
        controlled(present(url), &ProbeResult::NotFound),
        ProbeResult::Found {
            url: url.to_string(),
            confidence: 0.74,
            verified: false,
            controlled: true,
        }
    );
    // A status-only presence whose control could not be read cannot be
    // judged: never a profile (REQ-PROBE-002). A body-verified one stands,
    // uncontrolled.
    assert_eq!(
        controlled(present(url), &ProbeResult::Error),
        ProbeResult::Uncontrolled {
            url: url.to_string()
        }
    );
    let verified = ProbeResult::Found {
        url: url.to_string(),
        confidence: 0.92,
        verified: true,
        controlled: false,
    };
    assert_eq!(
        controlled(verified.clone(), &ProbeResult::Error),
        ProbeResult::Found {
            url: url.to_string(),
            confidence: 0.92,
            verified: true,
            controlled: false,
        }
    );
    assert_eq!(
        controlled(verified, &present("https://example.test/u/ctl")),
        ProbeResult::Indiscriminate {
            url: url.to_string()
        },
        "a body-verified presence the site also gives the control handle is still indiscriminate"
    );
    assert_eq!(
        controlled(ProbeResult::NotFound, &present(url)),
        ProbeResult::NotFound
    );
    assert_eq!(controlled(ProbeResult::Error, &present(url)), ProbeResult::Error);
}

/// The control wave: only presences are controlled, each site's control
/// answer is remembered for the process, and the judgement lands on the
/// right site.
#[tokio::test]
async fn the_control_wave_controls_only_presences_and_remembers_each_answer() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let probes = Arc::new(AtomicUsize::new(0));
    // Site 1 is a soft 404 (present for everyone); site 2 discriminates; site
    // 3 never answered for the target; site 4 denied the target.
    let first: Vec<(&'static str, ProbeResult)> = vec![
        ("soft404", present("https://soft404.test/u/alice")),
        ("real", present("https://real.test/u/alice")),
        ("blocked", ProbeResult::Error),
        ("absent", ProbeResult::NotFound),
    ];
    let control = |site: &'static str| {
        let probes = Arc::clone(&probes);
        let url = format!("https://{site}.test/u/{}", control_handle());
        (url, async move {
            probes.fetch_add(1, Ordering::SeqCst);
            if site == "soft404" {
                present("ctl")
            } else {
                ProbeResult::NotFound
            }
        })
    };
    let judged = control_presences(first.clone(), control).await;
    assert_eq!(probes.load(Ordering::SeqCst), 2, "only the two presences were controlled");
    assert!(matches!(judged[0].1, ProbeResult::Indiscriminate { .. }), "{:?}", judged[0]);
    assert!(
        matches!(judged[1].1, ProbeResult::Found { controlled: true, .. }),
        "{:?}",
        judged[1]
    );
    assert_eq!(judged[2].1, ProbeResult::Error);
    assert_eq!(judged[3].1, ProbeResult::NotFound);

    // A second target in the same process: the sites' control answers are
    // remembered, so no control probe runs again.
    let again = control_presences(first, control).await;
    assert_eq!(probes.load(Ordering::SeqCst), 2, "remembered answers, no new probes");
    assert!(matches!(again[0].1, ProbeResult::Indiscriminate { .. }));
    assert!(matches!(again[1].1, ProbeResult::Found { controlled: true, .. }));
}

/// An indiscriminate site leaves the sweep's decision capacity: the verdict
/// is judged over the sites that can tell, and a run in which none could is
/// inconclusive.
#[test]
fn an_indiscriminate_site_is_neither_an_answer_nor_a_failure_for_the_verdict() {
    // 8 sites: 3 indiscriminate, 1 blocked, 4 absent → 1 of 5 telling sites
    // blocked: a genuine absence. Counted as blocked, 4 of 8 would have read
    // inconclusive.
    assert!(!inconclusive_after_control(0, 1, 3, 8));
    assert!(inconclusive(0, 4, 8), "the old accounting read it inconclusive");
    // 4 of 5 telling sites blocked → inconclusive.
    assert!(inconclusive_after_control(0, 4, 3, 8));
    // No site could tell → inconclusive, never a clean zero.
    assert!(inconclusive_after_control(0, 0, 8, 8));
    // A hit is never inconclusive.
    assert!(!inconclusive_after_control(1, 4, 3, 8));
    assert!(!inconclusive_after_control(0, 0, 0, 0));
}

#[test]
fn the_sweeps_control_handle_is_a_second_handle_nobody_holds_distinct_from_the_probes() {
    let probes = control_handle();
    let sweep = sweep_control_handle();
    assert_ne!(sweep, probes, "a target equal to the probes' handle would be judged indiscriminate by construction");
    assert_eq!(sweep.len(), 12);
    assert!(sweep.as_bytes()[0].is_ascii_lowercase(), "{sweep}");
    assert!(sweep.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()), "{sweep}");
    assert_eq!(sweep, sweep_control_handle(), "drawn once per process");
}
