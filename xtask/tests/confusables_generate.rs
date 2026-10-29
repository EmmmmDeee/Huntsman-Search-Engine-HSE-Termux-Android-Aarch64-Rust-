//! `xtask confusables generate` turns Unicode's two files into the table the product folds names
//! with: it keeps only one non-ASCII code point mapped to one ASCII letter or digit, merges
//! touching ignorable ranges, records both files' dates, and refuses a file it cannot read as
//! Unicode data instead of writing a partial table.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONFUSABLES: &str = "\u{feff}# confusables.txt
# Date: 2026-08-06, 01:05:35 GMT
0430 ;\t0061 ;\tMA\t# ( \u{0430} \u{2192} a ) CYRILLIC SMALL LETTER A \u{2192} LATIN SMALL LETTER A
0410 ;\t0041 ;\tMA\t# CYRILLIC CAPITAL LETTER A \u{2192} LATIN CAPITAL LETTER A
FF10 ;\t0030 ;\tMA\t# FULLWIDTH DIGIT ZERO \u{2192} DIGIT ZERO
0030 ;\t004F ;\tMA\t# DIGIT ZERO \u{2192} LATIN CAPITAL LETTER O (ASCII source: not kept)
2024 ;\t002E ;\tMA\t# ONE DOT LEADER \u{2192} FULL STOP (not a letter or digit: not kept)
0AA0 ;\t0062 0062 ;\tMA\t# two-letter target: not kept
00E6 ;\t0061 0065 ;\tMA\t# two-letter target: not kept
";

const DERIVED: &str = "# DerivedCoreProperties-18.0.0.txt
# Date: 2026-08-07, 16:19:42 GMT
00AD          ; Default_Ignorable_Code_Point # Cf       SOFT HYPHEN
200B..200F    ; Default_Ignorable_Code_Point # Cf   [5] ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
2010          ; Default_Ignorable_Code_Point # touching the range before: merged
0041..005A    ; Alphabetic # not the property: ignored
";

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask must run")
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("confusables-{name}"));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Generate from `confusables` and `derived`, returning the process output and the table.
fn generate(name: &str, confusables: &str, derived: &str) -> (Output, Option<String>) {
    let dir = scratch(name);
    let (c, d, out) = (
        dir.join("confusables.txt"),
        dir.join("derived.txt"),
        dir.join("lookalike.rs"),
    );
    fs::write(&c, confusables).expect("write");
    fs::write(&d, derived).expect("write");
    let _ = fs::remove_file(&out);
    let output = xtask(&[
        "confusables",
        "generate",
        c.to_str().expect("utf-8 path"),
        d.to_str().expect("utf-8 path"),
        out.to_str().expect("utf-8 path"),
    ]);
    (output, fs::read_to_string(&out).ok())
}

#[test]
fn keeps_one_non_ascii_point_mapped_to_one_ascii_letter_or_digit() {
    let (output, table) = generate("select", CONFUSABLES, DERIVED);
    assert!(output.status.success(), "{output:?}");
    let table = table.expect("a table");
    assert!(table.contains("Date: 2026-08-06, 01:05:35 GMT"), "{table}");
    assert!(table.contains("Date: 2026-08-07, 16:19:42 GMT"), "{table}");
    let lookalikes: Vec<&str> = table
        .lines()
        .skip_while(|line| !line.contains("LOOKALIKE"))
        .filter(|line| line.trim_start().starts_with("(0x"))
        .collect();
    assert_eq!(
        lookalikes,
        ["    (0x0410, b'A'), (0x0430, b'a'), (0xFF10, b'0'),"]
    );
    let ignorable: Vec<&str> = table
        .lines()
        .skip_while(|line| !line.contains("IGNORABLE"))
        .take_while(|line| !line.contains("LOOKALIKE"))
        .filter(|line| line.trim_start().starts_with("(0x"))
        .map(str::trim)
        .collect();
    assert_eq!(ignorable, ["(0x00AD, 0x00AD),", "(0x200B, 0x2010),"]);
}

#[test]
fn the_same_input_always_generates_the_same_table() {
    let (_, first) = generate("stable-a", CONFUSABLES, DERIVED);
    let (_, second) = generate("stable-b", CONFUSABLES, DERIVED);
    assert_eq!(first.expect("a table"), second.expect("a table"));
}

#[test]
fn refuses_a_file_it_cannot_read_and_writes_nothing() {
    let undated = CONFUSABLES.replace("# Date:", "# When:");
    let not_a_point = format!("{CONFUSABLES}XYZ1 ;\t0061 ;\tMA\n");
    let twice = format!("{CONFUSABLES}0430 ;\t006F ;\tMA\n");
    for (name, confusables, derived) in [
        ("undated", undated.as_str(), DERIVED),
        ("bad-point", not_a_point.as_str(), DERIVED),
        ("twice", twice.as_str(), DERIVED),
        (
            "no-ignorable",
            CONFUSABLES,
            "# Date: 2026-08-07\n0041 ; Alphabetic\n",
        ),
    ] {
        let (output, table) = generate(name, confusables, derived);
        assert_eq!(output.status.code(), Some(64), "{name}: {output:?}");
        assert!(table.is_none(), "{name}: a table was written");
    }
}
