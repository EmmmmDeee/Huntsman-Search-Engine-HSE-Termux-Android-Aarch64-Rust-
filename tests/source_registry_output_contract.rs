use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

#[test]
fn route_output_exposes_evidence_and_verification_semantics() {
    let out = bin()
        .args(["sources", "-27.4698,153.0251"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        "kind=coordinates confidence=0.850 routes=1\n\
         source=google_maps category=geo mode=pivot_only access=public evidence=lead_only \
         verification=reference_only verified_at=none ref=https://www.google.com/maps \
         url=https://www.google.com/maps?q=-27.4698%2C153.0251\n"
    );
}

#[test]
fn every_route_keeps_user_controlled_url_last() {
    let out = bin().args(["sources", "@octocat"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    for line in stdout.lines().skip(1) {
        assert!(line.contains(" evidence=lead_only "), "{line}");
        assert!(line.contains(" verification=reference_only "), "{line}");
        assert!(line.contains(" ref=https://"), "{line}");
        let url = line.find(" url=https://").expect("URL is explicit and last");
        assert_eq!(line[url..].matches(" url=").count(), 1, "{line}");
        assert!(!line[url + 1..].contains(" ref="), "{line}");
        assert!(!line[url + 1..].contains(" evidence="), "{line}");
    }
}

#[test]
fn source_output_no_longer_exposes_the_legacy_execution_field() {
    let out = bin().args(["sources", "8.8.8.8"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains(" execution="), "{stdout}");
    assert!(stdout.contains(" mode=pivot_only "), "{stdout}");
}
