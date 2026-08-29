use super::*;

#[test]
fn commas_int_groups_thousands() {
    assert_eq!(commas_int(0), "0");
    assert_eq!(commas_int(7), "7");
    assert_eq!(commas_int(999), "999");
    assert_eq!(commas_int(1000), "1,000");
    assert_eq!(commas_int(1_116), "1,116");
    assert_eq!(commas_int(16_977_036), "16,977,036");
}

#[test]
fn human_picks_the_right_unit_at_each_threshold() {
    assert_eq!(human(0), "0 B");
    assert_eq!(human(999), "999 B");
    assert_eq!(human(1023), "1,023 B");
    // >= 1024 B moves to KiB.
    assert_eq!(human(1024), "1.0 KiB");
    assert_eq!(human(1024 * 1024 - 1), "1,024.0 KiB");
    // >= 1024 KiB moves to MiB.
    assert_eq!(human(1024 * 1024), "1.0 MiB");
    // >= 1024 MiB moves to GiB, which is the terminal unit (no TiB tier).
    assert_eq!(human(1024 * 1024 * 1024), "1.0 GiB");
    assert_eq!(human(1024u64 * 1024 * 1024 * 1024), "1,024.0 GiB");
}

#[test]
fn py_list_repr_matches_python_print_of_a_str_list() {
    assert_eq!(py_list_repr(&[]), "[]");
    assert_eq!(py_list_repr(&["a".to_string()]), "['a']");
    assert_eq!(
        py_list_repr(&["a".to_string(), "b".to_string()]),
        "['a', 'b']"
    );
}

#[test]
fn abspath_collapses_dot_and_dotdot_without_touching_the_filesystem() {
    let abs = abspath(std::path::Path::new("/a/b/../c/./d")).unwrap();
    assert_eq!(abs, std::path::PathBuf::from("/a/c/d"));
    // Works for a path that doesn't exist on disk — required for a
    // not-yet-created output file, unlike `std::fs::canonicalize`.
    let abs = abspath(std::path::Path::new("/definitely/does/not/exist.txt")).unwrap();
    assert_eq!(
        abs,
        std::path::PathBuf::from("/definitely/does/not/exist.txt")
    );
}

#[test]
fn relpath_under_strips_the_root_prefix() {
    let root = std::path::Path::new("/repo");
    let target = std::path::Path::new("/repo/HSE_MONOLITH.glm5.txt");
    assert_eq!(relpath_under(root, target), "HSE_MONOLITH.glm5.txt");

    let nested = std::path::Path::new("/repo/out/dir/file.txt");
    assert_eq!(relpath_under(root, nested), "out/dir/file.txt");
}

#[test]
fn temp_dir_creates_and_cleans_up_on_drop() {
    let path;
    {
        let tmp = TempDir::new("hse-pack-monolith-test").unwrap();
        path = tmp.path().to_path_buf();
        assert!(path.is_dir());
    }
    assert!(!path.exists());
}
