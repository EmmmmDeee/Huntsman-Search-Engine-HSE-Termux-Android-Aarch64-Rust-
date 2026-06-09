//! Architecture invariant tests — compile-time and runtime checks that
//! the module boundaries and contracts hold.

use std::fs;
use std::path::Path;

fn scan_for_violations(dir: &Path, patterns: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    scan_dir(dir, patterns, &mut violations);
    violations
}

fn scan_dir(dir: &Path, patterns: &[&str], violations: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, patterns, violations);
        } else if path.file_name().is_some_and(|n| n == "tests.rs") {
            // A dedicated `tests.rs` submodule file is entirely test code — it's
            // declared `#[cfg(test)] mod tests;` in its parent, so the gating
            // `#[cfg(test)]` marker isn't inside the file for the line-scanner to
            // see. Test code is allowed to reach into `util`, so skip it whole,
            // exactly as the inline-`#[cfg(test)]`-module case already is.
            continue;
        } else if path.extension().is_some_and(|e| e == "rs") {
            let content = fs::read_to_string(&path).unwrap();
            let mut in_test = false;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed == "#[cfg(test)]" {
                    in_test = true;
                    continue;
                }
                if in_test {
                    continue;
                }
                if trimmed.starts_with("//") {
                    continue;
                }
                if patterns.iter().any(|p| trimmed.contains(p)) {
                    violations.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                }
            }
        }
    }
}

#[test]
fn core_does_not_import_storage_directly() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["storage::Store", "crate::storage"]);
    assert!(
        v.is_empty(),
        "core/ must not import storage/ directly — use StoragePort.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn api_does_not_import_storage_directly() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
    let v = scan_for_violations(&dir, &["crate::storage", "storage::store"]);
    assert!(
        v.is_empty(),
        "api/ must not import storage/ directly — use StoragePort.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn modules_do_not_import_engine_or_storage() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
    let v = scan_for_violations(&dir, &["crate::core::engine", "crate::storage"]);
    assert!(
        v.is_empty(),
        "modules/ must not import engine/ or storage/.\nViolations:\n{}",
        v.join("\n")
    );
}

#[test]
fn core_does_not_import_util_directly() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let v = scan_for_violations(&dir, &["crate::util"]);
    let allowed: Vec<String> = v
        .into_iter()
        .filter(|line| {
            !line.contains("util::proxy::ProxyPool")
                && !line.contains("util::key_pool")
                && !line.contains("util::key_roi")
                && !line.contains("util::geohash")
                && !line.contains("util::preflight")
                && !line.contains("util::keys::signup_hint")
                && !line.contains("util::oathnet::reset_budget")
                && !line.contains("util::see_know::set_scan_cap_override")
                // Persistent capability toggles (universal toggleability): the
                // engine's module gate reads `module.<name>` on/off.
                && !line.contains("util::settings::get_bool")
                // Pure, dependency-free ABN/ACN checksums — used by
                // `TargetKind::detect` to tell a registry number from a phone
                // number in the unified-scan auto-detector.
                && !line.contains("util::abn::is_valid_abn")
                && !line.contains("util::abn::is_valid_acn")
                // Pure, dependency-free digit-only normaliser — the same leaf
                // category as the ABN checksums above; `core::scan` uses it in
                // the target auto-detector to strip separators from a candidate
                // phone/registry number. No state, no I/O, no upward deps.
                && !line.contains("util::str_util::ascii_digits")
                && !line.contains("modules::wigle::reset_budget")
                && !line.contains("modules::see_know::reset_budget")
                && !line.contains("modules::oathnet_pro::key_harvest::identify_api_key")
        })
        .collect();
    assert!(
        allowed.is_empty(),
        "core/ must not import util/ (except proxy::ProxyPool on ModuleContext).\nViolations:\n{}",
        allowed.join("\n")
    );
}

#[test]
fn storage_port_is_object_safe() {
    use huntsman_search_engine::core::StoragePort;
    fn _assert_object_safety(_: &dyn StoragePort) {}
}

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

#[test]
fn module_registry_count_is_stable() {
    let modules = huntsman_search_engine::modules::registry();
    assert!(
        modules.len() >= 75,
        "expected >=75 modules, got {}",
        modules.len()
    );
}

/// Every non-passive (network-reaching) module must declare a
/// `max_timeout_ms()` strictly greater than the default `MODULE_TIMEOUT_MS`
/// (3s). The engine wraps each `process()` in a `tokio::time::timeout` at
/// this budget; with no client-level total timeout, a module left at the 3s
/// default is killed before a slow-but-connected response can return,
/// surfacing a spurious engine "timeout" and silently yielding nothing.
///
/// Several modules (abn_lookup, disposable_check, mylnikov, sunrise_sunset,
/// and the ip/breach lookups) shipped exactly this defect. This guard makes
/// the whole class a CI failure rather than a silent runtime no-op. Passive
/// modules (local sensors, pure computation) legitimately keep the default
/// and are exempt.
/// Every registered module must appear in `docs/MODULES.md`. The catalogue
/// section there is generated from `hse modules --json`, but nothing stops a
/// future contributor adding a module and forgetting to regenerate it — the
/// doc had drifted to describe only 31 of 85 modules (and listed ~11 that no
/// longer existed) before this guard. A missing module name here fails CI,
/// keeping the operator-facing catalogue honest.
#[test]
fn modules_md_lists_every_registered_module() {
    let doc = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/MODULES.md"))
        .expect("docs/MODULES.md must exist");
    let modules = huntsman_search_engine::modules::registry();
    let missing: Vec<&str> = modules
        .iter()
        .map(|m| m.name())
        .filter(|name| {
            // Match the `\`name\`` form used in the generated table so a
            // substring of another name can't accidentally satisfy it.
            !doc.contains(&format!("`{name}`"))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "modules missing from docs/MODULES.md (regenerate the catalogue from \
         `hse modules --json`): {missing:?}"
    );
}

#[test]
fn non_passive_modules_budget_above_default() {
    let default = huntsman_search_engine::MODULE_TIMEOUT_MS;
    let modules = huntsman_search_engine::modules::registry();
    let under_budget: Vec<(&str, u64)> = modules
        .iter()
        .filter(|m| !m.is_passive())
        .map(|m| (m.name(), m.max_timeout_ms()))
        .filter(|(_, budget)| *budget <= default)
        .collect();
    assert!(
        under_budget.is_empty(),
        "non-passive modules must override max_timeout_ms() above the {default}ms \
         default or the engine kills them mid-request; offenders: {under_budget:?}"
    );
}

#[test]
fn architecture_constants() {
    assert_eq!(huntsman_search_engine::MODULE_TIMEOUT_MS, 3000);
    assert_eq!(huntsman_search_engine::WORKER_THREADS, 2);
    assert_eq!(huntsman_search_engine::DEFAULT_BIND, "127.0.0.1:8080");
}

/// Walk `dir` recursively and collect every `HUNTSMAN_*` identifier literal
/// that appears in a `.rs` source file (i.e. every key a module could read).
fn collect_env_literals(dir: &Path, out: &mut std::collections::HashSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_env_literals(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let content = fs::read_to_string(&path).unwrap();
            for (idx, _) in content.match_indices("HUNTSMAN_") {
                let tail = &content[idx..];
                let end = tail
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(tail.len());
                out.insert(tail[..end].to_string());
            }
        }
    }
}

/// Recursively collect `.rs` file paths under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every embedded default key must have a SINGLE source of truth in
/// `util::keys` — modules reference the `*_DEFAULT_KEY` constants rather than
/// re-declaring the literal. A re-hardcoded copy elsewhere could silently drift
/// from the canonical value (the "which key is actually current?" bug). This
/// asserts each embedded literal appears only in `src/util/keys.rs`.
#[test]
fn embedded_default_keys_have_a_single_source_of_truth() {
    use huntsman_search_engine::util::keys;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let values = [
        keys::OATHNET_DEFAULT_KEY,
        keys::HIBP_DEFAULT_KEY,
        keys::WIGLE_DEFAULT_USER,
        keys::WIGLE_DEFAULT_TOKEN,
        keys::SEEKNOW_DEFAULT_KEY,
        keys::SEEKNOW_SUPERSEDED_KEY,
    ];

    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);

    let mut offenders = Vec::new();
    for path in files {
        // The single source of truth — the literals legitimately live here.
        if path.ends_with("util/keys.rs") {
            continue;
        }
        let content = fs::read_to_string(&path).unwrap();
        if values.iter().any(|v| content.contains(v)) {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "embedded key literals must live only in util::keys.rs (reference the \
         *_DEFAULT_KEY constants, don't re-hardcode them): {offenders:?}"
    );
}

/// Guards against the silent-key-mismatch bug class: a key documented in the
/// provisioning template under a name no module actually reads, so the operator
/// sets it and gets nothing. Every key in `env_template.txt` must be consumed in
/// `src/` (or registered as a service def), or be explicitly listed as reserved.
#[test]
fn env_template_keys_are_all_consumed() {
    use std::collections::HashSet;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    // Documented but not yet wired to a consuming module. Each MUST be marked
    // `[RESERVED]` in the template; setting it has no runtime effect (yet).
    const NOT_YET_WIRED: &[&str] = &[
        "HUNTSMAN_ALIENVAULT_KEY",
        "HUNTSMAN_MALSHARE_KEY",
        "HUNTSMAN_PHISHTANK_KEY",
        "HUNTSMAN_XPOSEDORNOT_KEY",
        "HUNTSMAN_HUDSONROCK_KEY",
        "HUNTSMAN_MACADDRESS_KEY",
        "HUNTSMAN_IPINFO_KEY",
        "HUNTSMAN_MAXMIND_KEY",
    ];

    // 1. Keys declared in the provisioning template.
    let template = fs::read_to_string(root.join("src/cli/env_template.txt")).unwrap();
    let declared: Vec<String> = template
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("HUNTSMAN_"))
        .filter_map(|l| l.split('=').next())
        .map(|k| k.trim().to_string())
        .collect();
    assert!(!declared.is_empty(), "no keys parsed from env template");

    // 2. Keys actually read in source, plus the registered service registry.
    let mut consumed: HashSet<String> = HashSet::new();
    collect_env_literals(&root.join("src"), &mut consumed);
    for d in huntsman_search_engine::util::service_defs::service_defs() {
        consumed.insert(d.env_var.to_string());
    }

    let reserved: HashSet<&str> = NOT_YET_WIRED.iter().copied().collect();

    // Every documented key must be consumed/registered, or explicitly reserved.
    let orphans: Vec<&String> = declared
        .iter()
        .filter(|k| !consumed.contains(k.as_str()) && !reserved.contains(k.as_str()))
        .collect();
    assert!(
        orphans.is_empty(),
        "env template documents keys no module reads (silent no-op for the operator): {orphans:?}"
    );

    // The reserved allowlist must not rot: each entry must still be in the template.
    let declared_set: HashSet<&str> = declared.iter().map(String::as_str).collect();
    let stale: Vec<&str> = NOT_YET_WIRED
        .iter()
        .copied()
        .filter(|k| !declared_set.contains(k))
        .collect();
    assert!(
        stale.is_empty(),
        "NOT_YET_WIRED lists keys absent from the template (remove them): {stale:?}"
    );
}

#[test]
fn every_declared_module_is_registered() {
    // A `pub mod foo;` in src/modules/mod.rs that implements `Module` but is
    // never pushed into `registry()` compiles cleanly, is invisible to clippy
    // (unused pub item in a lib), and silently never runs — exactly how
    // `pwned_passwords` was dead at runtime. Assert every declared module mod
    // is instantiated somewhere in the registry body.
    let src = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/modules/mod.rs"))
        .expect("src/modules/mod.rs must exist");

    let declared: Vec<String> = src
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("pub mod ")
                .and_then(|r| r.strip_suffix(';'))
                .map(|n| n.trim().to_string())
        })
        .collect();

    let body = src.split_once("fn registry(").map(|(_, b)| b).unwrap_or("");

    let missing: Vec<&String> = declared
        .iter()
        .filter(|name| !body.contains(&format!("{name}::")))
        .collect();

    assert!(
        missing.is_empty(),
        "module mods declared in src/modules/mod.rs but never registered in \
         registry() (dead at runtime): {missing:?}"
    );
}

/// Concatenated source of every correlation-rule file. The rules live in a
/// `rules/` module split into thematic families (breach/identity/infra/geo/org/
/// crypto) plus `mod.rs`; the rule-wiring and rule-id guards scan the union, so
/// they keep working regardless of how the rules are partitioned across files.
fn correlator_rules_source() -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/correlator/rules");
    let mut out = String::new();
    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("correlator/rules/ must exist")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort(); // deterministic concatenation order
    for p in files {
        out.push_str(&fs::read_to_string(&p).expect("rule file readable"));
        out.push('\n');
    }
    out
}

/// Every correlation rule defined in the `rules/` module must be wired into a
/// dispatch array in `mod.rs` (`RULES` or `RELATION_RULES`). A `rule_au_*` fn
/// that is never added to an array compiles cleanly (it's referenced by the
/// glob `use rules::*;`, so it isn't even a dead-code warning) and silently
/// never fires — the analyst simply never sees that correlation, with no error
/// anywhere. This is the correlator analog of `every_declared_module_is_registered`
/// (the same failure mode that left `pwned_passwords` dead at runtime).
#[test]
fn every_defined_correlation_rule_is_dispatched() {
    let rules_src = correlator_rules_source();
    let mod_src = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/core/correlator/mod.rs"
    ))
    .expect("correlator mod.rs must exist");

    // Defined: the identifier after `fn ` on any line declaring a `rule_au_*`.
    let defined: Vec<String> = rules_src
        .lines()
        .filter_map(|l| {
            let at = l.find("fn rule_au_")?;
            l[at + "fn ".len()..]
                .split('(')
                .next()
                .map(|name| name.trim().to_string())
        })
        .collect();

    // Dispatched: the leading identifier on each array-element line — every
    // `rule_au_*` occurrence in mod.rs lives in `RULES`/`RELATION_RULES`, one
    // per line (`    rule_au_001_multi_breach,`). Taking the identifier prefix
    // is robust against a trailing comma or comment.
    let dispatched: std::collections::HashSet<String> = mod_src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("rule_au_"))
        .map(|l| {
            l.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .collect();

    assert!(
        !defined.is_empty() && !dispatched.is_empty(),
        "parse failure: defined={} dispatched={}",
        defined.len(),
        dispatched.len()
    );

    let orphans: Vec<&String> = defined
        .iter()
        .filter(|name| !dispatched.contains(*name))
        .collect();

    assert!(
        orphans.is_empty(),
        "correlation rules defined in rules.rs but never added to RULES or \
         RELATION_RULES in mod.rs (they compile but silently never fire): {orphans:?}"
    );
}

/// Each `rule_au_NNN_*` function must emit the matching `"AU-NNN"` rule_id. A
/// copy-pasted rule that keeps the source rule's id (e.g. `rule_au_037` emitting
/// `"AU-036"`) compiles and fires, but mis-attributes the correlation — and the
/// id is the dedup/ranking key, so two rules sharing one id collide silently.
/// The `"AU-NNN"` string literal is the emission marker (verified never to appear
/// quoted in a comment); both emission forms — `rule_id: "AU-NNN".into()` and
/// `Correlation::new("AU-NNN", …)` — are covered.
#[test]
fn correlation_rule_ids_match_their_function_number() {
    let src = correlator_rules_source();

    // Digit run starting at byte `from` in `s` (empty if none).
    fn digits_at(s: &str, from: usize) -> &str {
        let bytes = s.as_bytes();
        let end = (from..bytes.len())
            .find(|&i| !bytes[i].is_ascii_digit())
            .unwrap_or(bytes.len());
        &s[from..end]
    }

    let mut current: Option<&str> = None;
    let mut mismatches: Vec<String> = Vec::new();

    for line in src.lines() {
        if let Some(i) = line.find("fn rule_au_") {
            let n = digits_at(line, i + "fn rule_au_".len());
            if !n.is_empty() {
                current = Some(n);
            }
        }
        // Every quoted `"AU-NNN"` on the line is a rule_id emission.
        let mut from = 0;
        while let Some(rel) = line[from..].find("\"AU-") {
            let at = from + rel + "\"AU-".len();
            let n = digits_at(line, at);
            from = at + n.len();
            if n.is_empty() {
                continue;
            }
            // Compare numerically so id zero-padding need not match the function
            // name's (`rule_au_031` ↔ `"AU-031"`, and would still pass `"AU-31"`).
            match current {
                Some(fnum) if fnum.parse::<u32>().ok() == n.parse::<u32>().ok() => {}
                Some(fnum) => mismatches.push(format!("fn rule_au_{fnum} emits \"AU-{n}\"")),
                None => {
                    mismatches.push(format!("\"AU-{n}\" emitted outside any rule_au_* function"))
                }
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "correlation rule_id does not match its function number (copy-paste \
         mis-attribution / colliding dedup key): {mismatches:?}"
    );
}

/// The README's headline module count is hand-maintained and had drifted
/// (stated as "60+", "63" and "89" across files while the registry held 89).
/// Tie the authoritative "## Module Overview (N modules" figure to the live
/// registry so it can't silently rot again — the same no-silent-drift guard as
/// `modules_md_lists_every_registered_module` and the engine-count test
/// (FTA finding E10.1).
#[test]
fn readme_module_overview_count_matches_registry() {
    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md must exist");
    let n = huntsman_search_engine::modules::registry().len();
    let needle = format!("## Module Overview ({n} modules");
    assert!(
        readme.contains(&needle),
        "README '## Module Overview (N modules ...)' must cite the live registry \
         size ({n}); update README.md after adding/removing a module"
    );
}

/// Runtime AI-independence guard (the `RUNTIME_INDEPENDENCE` charter): the
/// compiled binary must carry NO AI / ML / LLM / cloud-inference / vector /
/// embedding dependency, so every runtime capability is deterministic Rust that
/// reproduces identically on Termux aarch64 (no root), Linux and CI with no AI
/// available. AI is a development-time accelerator only. This turns the principle
/// into a mechanical CI check — adding e.g. `candle`, `onnxruntime`, an LLM SDK,
/// `tokenizers`, or `qdrant-client` fails here. External OSINT *data* APIs
/// (registries, breach corpora, geocoders) are data sources, not AI services,
/// and are deliberately unaffected. See `docs/RUNTIME_INDEPENDENCE.md`.
#[test]
fn runtime_carries_no_ai_ml_inference_dependency() {
    let lock = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("Cargo.lock must exist");

    // Substrings unambiguous enough that no non-AI crate name contains them.
    const DENY_SUBSTR: &[&str] = &[
        "candle-",
        "onnx",
        "openai",
        "anthropic",
        "huggingface",
        "hf-hub",
        "tokenizers",
        "tiktoken",
        "fastembed",
        "text-embeddings",
        "qdrant",
        "pinecone",
        "weaviate",
        "milvus",
        "chromadb",
        "ollama",
        "llama",
        "langchain",
        "llm-chain",
        "rust-bert",
        "instant-distance",
        "tensorflow",
        "torch-sys",
    ];
    // Exact crate names too short/common to match safely as substrings.
    const DENY_EXACT: &[&str] = &[
        "tch",
        "burn",
        "tract",
        "ort",
        "rten",
        "llm",
        "lance",
        "lancedb",
        "hnsw",
        "usearch",
        "faiss",
        "dfdx",
        "smartcore",
        "linfa",
        "genai",
        "kalosm",
        "rig-core",
        "mistralai",
        "mistral-rs",
    ];

    let offenders: Vec<&str> = lock
        .lines()
        .filter_map(|l| {
            l.strip_prefix("name = \"")
                .and_then(|s| s.strip_suffix('"'))
        })
        .filter(|name| DENY_SUBSTR.iter().any(|d| name.contains(d)) || DENY_EXACT.contains(name))
        .collect();

    assert!(
        offenders.is_empty(),
        "RUNTIME_INDEPENDENCE violation — AI/ML/inference crate(s) entered the \
         dependency tree: {offenders:?}. HSE's runtime must stay deterministic \
         Rust with no AI / LLM / vector / embedding dependency (AI is a \
         development-time accelerator only). See docs/RUNTIME_INDEPENDENCE.md."
    );
}

/// Every coarse IP/WiFi-geolocation provider must gate its emitted coordinates
/// on `is_plausible_provider_coord`, not the precise `is_valid_coords`.
///
/// These sources resolve to a city/region centroid and emit a sub-degree
/// null-island *jitter band* (`0.005,0.005`-style "no fix" placeholder) when
/// they have no location. `is_valid_coords` rejects only exact `0,0`, so gating
/// a coarse provider on it lets that placeholder through as a high-confidence
/// `geoint` fix that poisons the AU-014/AU-017 geo-cluster correlator —
/// precisely the drift that slipped into `ip_whois_geo` until it was corrected.
/// Pin the categorization here so a new (or edited) coarse provider can't
/// silently pick the wrong validator.
#[test]
fn coarse_ip_geo_providers_use_the_provider_coord_gate() {
    const COARSE_PROVIDERS: &[&str] = &[
        "ip_geo",
        "ipinfo",
        "ipapi",
        "ip2location",
        "ipquery",
        "ip_whois_geo",
        "wigle",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
    let mut offenders = Vec::new();
    for provider in COARSE_PROVIDERS {
        let path = root.join(format!("{provider}.rs"));
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("coarse provider {provider} missing at {path:?}"));
        // Strip the test module so a `use is_valid_coords` in a unit test
        // doesn't count against the production gate.
        let prod = src.split("mod tests").next().unwrap_or(&src);
        // The gate is satisfied either by calling `is_plausible_provider_coord`
        // directly OR by building the entity through `coarse_provider_coords`,
        // which applies that exact gate internally (ipinfo/ipapi/ip2location/
        // ipquery were consolidated onto the helper).
        let gated =
            prod.contains("is_plausible_provider_coord") || prod.contains("coarse_provider_coords");
        if !gated {
            offenders.push(*provider);
        }
    }
    assert!(
        offenders.is_empty(),
        "coarse IP/WiFi-geo provider(s) {offenders:?} do not gate coordinates on \
         is_plausible_provider_coord / coarse_provider_coords — a null-island placeholder could become a \
         false geoint fix. Use crate::util::geo::is_plausible_provider_coord."
    );
}
