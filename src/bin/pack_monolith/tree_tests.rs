use super::*;

#[test]
fn render_tree_puts_directories_before_files_and_sorts_alphabetically() {
    let paths = vec![
        "src/lib.rs".to_string(),
        "src/core/mod.rs".to_string(),
        "src/core/entity.rs".to_string(),
        "Cargo.toml".to_string(),
        "README.md".to_string(),
    ];
    let lines = render_tree(&paths);
    // Root children: `src/` (a directory) sorts before both root-level
    // files, which are then alphabetical ("Cargo.toml" < "README.md").
    // Within `src/`: `core/` (a directory) sorts before the sibling file
    // `lib.rs`. Within `core/`: two files, alphabetical.
    assert_eq!(
        lines,
        vec![
            ".",
            "|-- src/",
            "|   |-- core/",
            "|   |   |-- entity.rs",
            "|   |   `-- mod.rs",
            "|   `-- lib.rs",
            "|-- Cargo.toml",
            "`-- README.md",
        ]
    );
}

#[test]
fn render_tree_of_a_single_file_is_the_root_plus_one_line() {
    assert_eq!(
        render_tree(&["Cargo.toml".to_string()]),
        vec![".", "`-- Cargo.toml"]
    );
}
