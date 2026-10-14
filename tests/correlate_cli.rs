//! `huntsman-recon correlate ARTIFACT`: rerun the correlation rules on a saved scan, offline.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use huntsman_recon::scan_artifact::{self, ScanArtifact};

fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("correlate-cli-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir.join("scan.json")
}

/// A confirmed domain whose DNS evidence names the address it resolves to.
fn hosted_on(domain: &str, ip: &str) -> Entity {
    let mut entity = Entity::new(EntityKind::Domain, domain, 0.9, "saved-scan");
    entity.add_evidence(
        Evidence::new(EvidenceProvenance::new("dns"), format!("{domain} A record"))
            .with_attr("ip", ip),
    );
    entity
}

/// Two domains on one address (RFC 5737 documentation range) share hosting (AU-110). The artifact
/// stores entities only, as `dehashed --save-artifact` writes it, so `correlate` finds the link
/// from the relations those entities imply, as `plan` does. Before, it printed no relation rule
/// for a saved scan.
#[test]
fn correlate_fires_the_relation_rules_on_a_saved_scan() {
    let path = scratch("relations");
    let artifact = ScanArtifact::new(
        "saved-scan",
        vec![
            hosted_on("alpha.example", "192.0.2.10"),
            hosted_on("beta.example", "192.0.2.10"),
            Entity::new(EntityKind::IpAddress, "192.0.2.10", 0.9, "saved-scan"),
        ],
        Vec::new(),
    );
    scan_artifact::write(&path, &artifact).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .arg("correlate")
        .arg(&path)
        .output()
        .expect("run huntsman-recon correlate");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("entities=3 relations=0"), "{text}");
    assert!(
        text.lines()
            .any(|line| line.starts_with("rule=AU-110 ") && line.ends_with(" entities=3")),
        "{text}"
    );
}
