//! The test-count floor: the `#[test]` functions in `src/`, `tests/` and `xtask/src/` never fall
//! below the committed floor. A pure move keeps every test; folding or removing tests on purpose
//! lowers the floor in the same commit, which says which tests went and why.

use std::fs;
use std::path::Path;

const FLOOR: &str = include_str!("fixtures/test_count_floor.txt");

/// The `#[test]` attributes on lines of their own under `dir`, in every `.rs` file.
fn count(dir: &Path) -> usize {
    let mut total = 0;
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            total += count(&path);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text =
                fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            total += text.lines().filter(|line| line.trim() == "#[test]").count();
        }
    }
    total
}

#[test]
fn the_test_count_never_falls_below_its_floor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let found: usize = ["src", "tests", "xtask/src"]
        .iter()
        .map(|dir| count(&root.join(dir)))
        .sum();
    let floor: usize = FLOOR
        .lines()
        .find(|line| !line.starts_with('#') && !line.trim().is_empty())
        .and_then(|line| line.trim().parse().ok())
        .expect("the floor file holds one number");
    assert!(
        found >= floor,
        "{found} #[test] functions, below the floor of {floor}. A move keeps every test; if \
         tests were folded or removed on purpose, lower the floor in the same commit and say \
         which tests went and why."
    );
}
