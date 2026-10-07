use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn run_username(handle: &str) -> String {
    let out = bin()
        .args(["username", handle])
        .output()
        .expect("run huntsman-recon username");
    assert!(
        out.status.success(),
        "username {handle} failed: status={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

#[test]
fn live_public_identity_resolution_benchmark() {
    if std::env::var_os("HUNTSMAN_LIVE_IDENTITY_BENCH").is_none() {
        eprintln!("live identity benchmark skipped; set HUNTSMAN_LIVE_IDENTITY_BENCH=1");
        return;
    }

    let target = run_username("troyhunt");
    let positive_checks = [
        ("github", target.contains("github_user\tsuccess")),
        ("person", target.contains("person\tTroy Hunt\t")),
        ("domain", target.contains("domain\ttroyhunt.com\t")),
        (
            "github_profile",
            target.contains("url\thttps://github.com/troyhunt\t"),
        ),
        (
            "personal_site",
            target.contains("url\thttps://www.troyhunt.com\t")
                || target.contains("url\thttps://www.troyhunt.com/\t"),
        ),
        (
            "bluesky_profile",
            target.contains("url\thttps://bsky.app/profile/troyhunt.com\t"),
        ),
        (
            "bluesky_did",
            target.contains("other\tdid:plc:hg47czad2gksha3a7iyhwyan\t"),
        ),
        (
            "bluesky_success",
            target.matches("bluesky_user\tsuccess").count() >= 1,
        ),
    ];

    let positive_hits = positive_checks.iter().filter(|(_, ok)| *ok).count();

    let decoy = run_username("troyhunt1");
    let negative_checks = [
        (
            "decoy_not_troy_person",
            !decoy.contains("person\tTroy Hunt\t"),
        ),
        (
            "decoy_not_troy_domain",
            !decoy.contains("domain\ttroyhunt.com\t"),
        ),
        (
            "decoy_not_troy_bluesky",
            !decoy.contains("https://bsky.app/profile/troyhunt.com"),
        ),
    ];
    let negative_hits = negative_checks.iter().filter(|(_, ok)| *ok).count();

    let direct_custom = run_username("troyhunt.com");
    let direct_custom_ok = direct_custom.contains("bluesky_user\tsuccess")
        && direct_custom.contains("person\tTroy Hunt\t")
        && direct_custom.contains("url\thttps://bsky.app/profile/troyhunt.com\t");

    let total = positive_checks.len() + negative_checks.len() + 1;
    let passed = positive_hits + negative_hits + usize::from(direct_custom_ok);

    println!(
        "{{\"benchmark\":\"live_public_identity_resolution\",\"seed\":\"troyhunt\",\"positive\":{{\"passed\":{},\"total\":{}}},\"negative\":{{\"passed\":{},\"total\":{}}},\"direct_custom_handle\":{},\"score\":{:.4}}}",
        positive_hits,
        positive_checks.len(),
        negative_hits,
        negative_checks.len(),
        direct_custom_ok,
        passed as f64 / total as f64
    );

    for (name, ok) in positive_checks {
        assert!(ok, "positive benchmark check failed: {name}\n{target}");
    }
    for (name, ok) in negative_checks {
        assert!(ok, "negative benchmark check failed: {name}\n{decoy}");
    }
    assert!(
        direct_custom_ok,
        "direct custom-domain Bluesky path failed\n{direct_custom}"
    );
}
