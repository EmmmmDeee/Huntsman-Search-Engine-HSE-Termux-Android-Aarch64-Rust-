//! The committed registry blob is what `xtask oui pack` makes of its own `dump`, so the blob is
//! derivable from the IEEE CSV by one command, and the packer writes the layout the product's
//! reader searches.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BLOB: &str = "../src/oui_ieee.bin";

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask must run")
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("oui-pack-{name}"));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The registry CSV a listing describes, quoted as the IEEE file quotes.
fn csv_of(listing: &str) -> String {
    let mut csv = String::from("Registry,Assignment,Organization Name,Organization Address\r\n");
    for line in listing.lines() {
        let (prefix, vendor) = line.split_once('\t').expect("PREFIX<TAB>VENDOR");
        csv.push_str(&format!(
            "MA-L,{prefix},\"{}\",\r\n",
            vendor.replace('"', "\"\"")
        ));
    }
    csv
}

#[test]
fn the_committed_blob_is_the_pack_of_its_own_dump() {
    let dump = xtask(&["oui", "dump", BLOB]);
    assert!(dump.status.success(), "{dump:?}");
    let listing = String::from_utf8(dump.stdout).expect("UTF-8 listing");
    assert!(
        listing.lines().count() > 30_000,
        "the registry holds tens of thousands of assignments"
    );
    assert!(
        listing
            .lines()
            .any(|line| line.starts_with("001451\t") && line.to_ascii_lowercase().contains("apple")),
        "the listing names Apple's 00:14:51 block"
    );

    let dir = scratch("round-trip");
    let csv = dir.join("oui.csv");
    let out = dir.join("oui.bin");
    fs::write(&csv, csv_of(&listing)).expect("write csv");
    let pack = xtask(&["oui", "pack", csv.to_str().unwrap(), out.to_str().unwrap()]);
    assert!(pack.status.success(), "{pack:?}");
    assert!(
        String::from_utf8_lossy(&pack.stderr).is_empty(),
        "a listing has no duplicate assignments to report"
    );
    assert_eq!(
        fs::read(&out).expect("packed blob"),
        fs::read(BLOB).expect("committed blob"),
        "packing the blob's own listing must reproduce it byte for byte"
    );
}

#[test]
fn oui_refuses_a_missing_command_or_file_with_the_usage_status() {
    assert_eq!(xtask(&["oui"]).status.code(), Some(64));
    assert_eq!(xtask(&["oui", "pack", "only-one"]).status.code(), Some(64));
    let missing = xtask(&["oui", "dump", "/nonexistent/oui.bin"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing.stderr).starts_with("xtask oui: /nonexistent/oui.bin")
    );
}
