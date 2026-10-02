//! The two legacy archives are the reference for every future rebuild. They are
//! never deleted, edited or replaced: this test pins their exact bytes.

use std::fs;
use std::path::PathBuf;

use huntsman_recon::sha256::{hex32, sha256};

const ARCHIVES: &[(&str, &str)] = &[
    (
        "Huntsman-HSE-EndToEnd-Refactor-Overlay-feef60a.zip",
        "bba70abb0ac7f8c1f1ade818580273a78d169628c14b4b908ff6a5c08e90faf7",
    ),
    (
        "Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust--main (10).zip",
        "c3c7f843a1c495f443344a228ce2707b097d53edaa7aea2238347452b7495241",
    ),
];

#[test]
fn legacy_archives_are_present_and_unmodified() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (name, want) in ARCHIVES {
        let bytes = fs::read(root.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex32(&sha256(&bytes)), *want, "{name} was changed");
    }
}
