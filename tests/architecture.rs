//! Architecture invariant tests — compile-time and runtime checks that
//! the module boundaries and contracts hold.

/// `core/` must not import `storage/` directly. The engine and correlator
/// depend on `StoragePort` (a trait in `core::port`), not on `Store`.
/// This test greps the source tree to catch regressions.
#[test]
fn core_does_not_import_storage_directly() {
    use std::fs;
    use std::path::Path;

    let core_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let mut violations = Vec::new();

    fn check_dir(dir: &Path, violations: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                check_dir(&path, violations);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let content = fs::read_to_string(&path).unwrap();
                for (i, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    if trimmed.contains("storage::store::Store")
                        || trimmed.contains("crate::storage")
                    {
                        violations.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                    }
                }
            }
        }
    }

    check_dir(&core_dir, &mut violations);
    assert!(
        violations.is_empty(),
        "core/ must not import storage/ directly — use StoragePort instead.\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

/// `modules/` must not import `engine/` or `storage/` — modules depend
/// on the `Module` trait from `core::module`, nothing else.
#[test]
fn modules_do_not_import_engine_or_storage() {
    use std::fs;
    use std::path::Path;

    let modules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
    let mut violations = Vec::new();

    for entry in fs::read_dir(&modules_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let content = fs::read_to_string(&path).unwrap();
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains("crate::core::engine") || trimmed.contains("crate::storage") {
                    violations.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "modules/ must not import engine/ or storage/ directly.\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

/// `api/` must not import `storage/` directly. Handlers access storage
/// exclusively through `StoragePort` on `AppState`.
#[test]
fn api_does_not_import_storage_directly() {
    use std::fs;
    use std::path::Path;

    let api_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
    let mut violations = Vec::new();

    fn check_dir(dir: &Path, violations: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                check_dir(&path, violations);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let content = fs::read_to_string(&path).unwrap();
                for (i, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    if trimmed.contains("crate::storage") || trimmed.contains("storage::store") {
                        violations.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                    }
                }
            }
        }
    }

    check_dir(&api_dir, &mut violations);
    assert!(
        violations.is_empty(),
        "api/ must not import storage/ directly — use StoragePort instead.\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

/// StoragePort is object-safe and can be used as `Arc<dyn StoragePort>`.
#[test]
fn storage_port_is_object_safe() {
    use huntsman_search_engine::core::StoragePort;

    fn _assert_object_safety(_: &dyn StoragePort) {}
}

/// Every registered module has a non-empty description (regression gate).
#[test]
fn all_modules_have_descriptions() {
    let modules = huntsman_search_engine::modules::registry();
    assert!(!modules.is_empty());
    let missing: Vec<_> = modules
        .iter()
        .filter(|m| m.description().trim().is_empty())
        .map(|m| m.name())
        .collect();
    assert!(
        missing.is_empty(),
        "modules with no description: {missing:?}"
    );
}

/// The module registry returns at least the known module count.
#[test]
fn module_registry_count_is_stable() {
    let modules = huntsman_search_engine::modules::registry();
    assert!(
        modules.len() >= 48,
        "expected ≥48 modules, got {}",
        modules.len()
    );
}

/// Architecture constants match their documented values.
#[test]
fn architecture_constants() {
    assert_eq!(huntsman_search_engine::MODULE_TIMEOUT_MS, 3000);
    assert_eq!(huntsman_search_engine::WORKER_THREADS, 2);
    assert_eq!(huntsman_search_engine::DEFAULT_BIND, "127.0.0.1:8080");
}
