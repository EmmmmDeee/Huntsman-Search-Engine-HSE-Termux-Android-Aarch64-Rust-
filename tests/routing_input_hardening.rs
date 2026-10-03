use std::process::Command;

use huntsman_recon::EntityKind;
use huntsman_recon::classifier::classify;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

#[test]
fn ipv4_classification_rejects_noncanonical_ambiguous_forms() {
    for raw in ["+1.+2.+3.+4", "01.02.03.04"] {
        assert_ne!(classify(raw).kind, EntityKind::IpAddress, "{raw}");
    }
}

#[test]
fn numeric_dotted_shapes_do_not_become_domain_pivots() {
    for raw in ["999.1.1.1", "1.2.3", "01.02.03.04"] {
        let classified = classify(raw);
        assert_ne!(classified.kind, EntityKind::Domain, "{raw}");
        assert_ne!(classified.kind, EntityKind::IpAddress, "{raw}");
    }
}

#[test]
fn coordinate_bounds_are_exact_not_binary_float_rounded() {
    for raw in [
        "90.00000000000000001,0.0",
        "-90.00000000000000001,0.0",
        "0.0,180.00000000000000001",
        "0.0,-180.00000000000000001",
    ] {
        assert_ne!(classify(raw).kind, EntityKind::Coordinates, "{raw}");
    }
}

#[test]
fn malformed_at_prefixed_values_are_not_promoted_to_usernames() {
    for raw in ["@", "@@octocat", "@ada lovelace"] {
        assert_eq!(classify(raw).kind, EntityKind::Other, "{raw}");
    }
    assert_eq!(classify("@octocat").kind, EntityKind::Username);
}

#[test]
fn sources_rejects_unconsumed_arguments_instead_of_silently_dropping_them() {
    let out = bin()
        .args(["sources", "example.com", "discarded"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(out.stdout, [] as [u8; 0]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("usage: huntsman-recon sources QUERY"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
