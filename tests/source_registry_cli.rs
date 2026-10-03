//! Acceptance tests for capability-backed source routing.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

#[test]
fn sources_routes_a_domain_through_exactly_five_pivot_capabilities() {
    let out = bin().args(["sources", "example.com"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("kind=domain confidence=0.750 routes=5\n"),
        "{stdout}"
    );
    for source in ["google_site", "wayback", "whois", "crtsh", "urlscan"] {
        assert!(
            stdout.contains(&format!(
                "source={source} execution=pivot_only access=public"
            )),
            "{stdout}"
        );
    }
    assert!(
        stdout.contains("https://web.archive.org/web/*/example.com/*"),
        "{stdout}"
    );
    assert!(stdout.contains("https://crt.sh/?q=%25.example.com"), "{stdout}");
}

#[test]
fn sources_canonicalises_domains_before_provider_routing() {
    let out = bin().args(["sources", "EXAMPLE.com."]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("example.com"), "{stdout}");
    assert!(!stdout.contains("EXAMPLE.com."), "{stdout}");
}

#[test]
fn sources_percent_encodes_human_queries() {
    let out = bin().args(["sources", "Ada Lovelace"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("kind=person confidence=0.500 routes=2\n"),
        "{stdout}"
    );
    assert!(stdout.contains("Ada%20Lovelace"), "{stdout}");
    assert!(!stdout.contains("Ada Lovelace"), "{stdout}");
}

#[test]
fn sources_routes_email_through_exact_web_searches() {
    let out = bin()
        .args(["sources", "ada@example.com"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("kind=email confidence=0.950 routes=2\n"),
        "{stdout}"
    );
    assert!(stdout.contains("%22ada%40example.com%22"), "{stdout}");
}

#[test]
fn sources_refuses_unactionable_residual_text() {
    let out = bin().args(["sources", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(out.stdout, [] as [u8; 0]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no actionable source routes"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn sources_routes_a_handle_with_source_specific_transformations() {
    let out = bin().args(["sources", "@octocat"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("kind=username confidence=0.400 routes=3\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "source=github_users execution=pivot_only access=public \
             url=https://github.com/search?q=octocat&type=users"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("%22%40octocat%22"), "{stdout}");
}

#[test]
fn sources_refuses_malformed_handles() {
    for input in ["@", "@@octocat", "@ada lovelace"] {
        let out = bin().args(["sources", input]).output().unwrap();
        assert_eq!(out.status.code(), Some(65), "{input}");
        assert_eq!(out.stdout, [] as [u8; 0], "{input}");
    }
}

#[test]
fn sources_routes_decimal_coordinates_to_maps() {
    let out = bin()
        .args(["sources", "-27.4698, 153.0251"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        "kind=coordinates confidence=0.850 routes=1\n\
         source=google_maps execution=pivot_only access=public \
         url=https://www.google.com/maps?q=-27.4698%2C153.0251\n"
    );
}

#[test]
fn sources_refuses_out_of_range_coordinates() {
    let out = bin().args(["sources", "91.0,0.0"]).output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(out.stdout, [] as [u8; 0]);
}

#[test]
fn sources_routes_ipv4_to_shodan_and_bgp() {
    let out = bin().args(["sources", "8.8.8.8"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("kind=ip_address confidence=0.920 routes=2\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "source=shodan_host execution=pivot_only access=public \
             url=https://www.shodan.io/host/8.8.8.8"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "source=bgp_he execution=pivot_only access=public \
             url=https://bgp.he.net/ip/8.8.8.8"
        ),
        "{stdout}"
    );
}
