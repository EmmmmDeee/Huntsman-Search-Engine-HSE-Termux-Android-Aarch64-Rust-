use super::*;

#[test]
fn is_binary_flags_nul_bytes_and_invalid_utf8() {
    assert!(is_binary(b"hello\x00world"));
    assert!(is_binary(&[0xFF, 0xFE])); // invalid UTF-8, no NUL byte
    assert!(!is_binary(b"hello world\n"));
    assert!(!is_binary(b"")); // empty is valid (trivial) UTF-8
}

#[test]
fn lang_for_handles_normal_dotfile_and_extensionless_names() {
    assert_eq!(lang_for("src/lib.rs", false), "rust");
    assert_eq!(lang_for(".gitignore", false), "gitignore");
    assert_eq!(lang_for("Makefile", false), "text"); // no extension -> falls back to "text"
    assert_eq!(lang_for("src/modules/tls/cert.der", false), "binary");
    assert_eq!(lang_for("anything", true), "binary"); // is_bin short-circuits regardless of name
    assert_eq!(lang_for("README.MD", false), "markdown"); // extension matched case-insensitively
}

#[test]
fn entry_counts_lines_and_eof_newline_correctly() {
    // Ends with newline: eof_newline true, lines == newline count.
    let e = Entry::new("a.txt".to_string(), b"one\ntwo\n".to_vec());
    assert!(e.eof_newline);
    assert_eq!(e.lines, 2);

    // No trailing newline: eof_newline false, one extra line for the
    // unterminated final line.
    let e = Entry::new("b.txt".to_string(), b"one\ntwo".to_vec());
    assert!(!e.eof_newline);
    assert_eq!(e.lines, 2);

    // Empty file: eof_newline true (Python: `... if data else True`), zero lines.
    let e = Entry::new("c.txt".to_string(), Vec::new());
    assert!(e.eof_newline);
    assert_eq!(e.lines, 0);

    // Binary content: lines always 0 regardless of NUL/newline placement.
    let e = Entry::new("d.bin".to_string(), b"a\x00b\nc\n".to_vec());
    assert!(e.is_binary);
    assert_eq!(e.lines, 0);
}

#[test]
fn entry_classifies_layer_and_note_from_its_path() {
    let e = Entry::new("src/util/dns.rs".to_string(), b"x".to_vec());
    assert_eq!(e.rank, 1);
    assert_eq!(e.label, "util");
    assert_eq!(e.note, "");

    let e = Entry::new("Cargo.lock".to_string(), b"x".to_vec());
    assert_eq!(e.note, "generated dependency lockfile");
}
