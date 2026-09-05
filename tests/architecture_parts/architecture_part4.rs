/// Concatenated source of every correlation-rule file. The rules live in a
/// `rules/` module split into thematic families (breach/identity/infra/geo/org/
/// crypto) plus `mod.rs`; the rule-wiring and rule-id guards scan the union, so
/// they keep working regardless of how the rules are partitioned across files.
fn correlator_rules_source() -> String {
    // Recurse into subdirectories (`geo/`, `identity/`, `location/`) — a flat
    // `fs::read_dir` would silently skip them (a directory has no `.rs`
    // extension, so the filter drops it entirely), leaving ~46 rules across 3
    // whole subdirectories unscanned by every guard built on this helper
    // (`every_defined_correlation_rule_is_dispatched`,
    // `correlation_rule_ids_match_their_function_number`,
    // `no_two_correlation_rule_functions_share_a_number`). A dead or
    // mis-numbered rule confined to one of those subdirectories would compile,
    // dispatch, and fire while every one of those safety nets stayed silent.
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(p);
            }
        }
    }

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/correlator/rules");
    let mut files = Vec::new();
    walk(&dir, &mut files);
    files.sort(); // deterministic concatenation order

    let mut out = String::new();
    for p in files {
        let text = fs::read_to_string(&p).expect("rule file readable");
        // Drop the file's `#[cfg(test)]` ITEMS. Without this, a test module's
        // `assert_eq!(.., "AU-NNN")` for one rule reads as a SUBSEQUENT emission
        // of whichever rule function was declared last in the file, producing a
        // false `correlation_rule_ids_match_their_function_number` mismatch.
        //
        // This was `text.split("#[cfg(test)]").next()`, justified by a comment
        // claiming the marker sits "always at file end by this codebase's
        // convention". The tree says otherwise: `rules/geo/mod.rs` declares it
        // at line 111 of 540 and `transitive.rs` at 110 of 350, so 429 and 240
        // lines of *rules* went unscanned — the dispatch, id-match and
        // duplicate-number invariants were all reading a fraction of the file.
        //
        // `strip_cfg_test_items`, not `production_source`: the id-match
        // invariant reads `rule_id: "AU-NNN"` out of a string literal, and
        // blanking literals would leave it scanning empty quotes and passing
        // vacuously.
        out.push_str(&strip_cfg_test_items(&text));
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
                    mismatches.push(format!("\"AU-{n}\" emitted outside any rule_au_* function"));
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

/// No two DIFFERENT rule functions may claim the same `AU-NNN` number.
///
/// [`correlation_rule_ids_match_their_function_number`] only checks that a
/// function's OWN emitted id matches ITS OWN number — it has no notion of any
/// OTHER function, so two independently-written, independently-dispatched,
/// independently-tested rules (e.g. `rule_au_076_email_username_localpart_bridge`
/// in `identity/account.rs` and the former `rule_au_076_shared_registrant` in
/// `org.rs`) can each individually satisfy it while silently colliding on one
/// `rule_id`. That id is the dedup/supersede key `storage::upsert_correlation`
/// queries on (`WHERE scan_id = ?1 AND rule_id = ?2`), so a collision makes two
/// semantically unrelated findings overwrite/merge into one, corrupting
/// whichever fires second. This exact collision shipped once — a missed
/// renumbering from a 2026-06-25 `origin/main` merge that unioned two
/// independently-numbered rule sets — and was
/// only caught by a dedicated audit, not by the test suite. This closes that
/// gap permanently: a number is collected with EVERY distinct
/// `rule_au_<NNN>_<name>` function that declares it, and fails if any number
/// has more than one distinct owner.
#[test]
fn no_two_correlation_rule_functions_share_a_number() {
    let src = correlator_rules_source();
    let mut owners: std::collections::BTreeMap<u32, Vec<String>> =
        std::collections::BTreeMap::new();

    for line in src.lines() {
        let Some(i) = line.find("fn rule_au_") else {
            continue;
        };
        let after = &line[i + "fn rule_au_".len()..];
        let digit_end = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        if digit_end == 0 {
            continue;
        }
        let Ok(n) = after[..digit_end].parse::<u32>() else {
            continue;
        };
        let name_start = i + "fn ".len();
        let name_end = line[name_start..]
            .find('(')
            .map_or(line.len(), |p| name_start + p);
        let full_name = line[name_start..name_end].trim().to_string();
        let names = owners.entry(n).or_default();
        if !names.contains(&full_name) {
            names.push(full_name);
        }
    }

    let collisions: Vec<String> = owners
        .into_iter()
        .filter(|(_, names)| names.len() > 1)
        .map(|(n, names)| format!("AU-{n:03}: {names:?}"))
        .collect();

    assert!(
        collisions.is_empty(),
        "two different rule functions claim the same AU-NNN number — they will \
         collide on storage's (scan_id, rule_id) dedup/supersede key and corrupt \
         each other's findings; assign the newer rule an unused number: \
         {collisions:?}"
    );
}

/// Every HTTP response body read in `src/modules` and `src/core` must go
/// through a CAPPED reader (`util::http::{read_text, read_json_text,
/// fetch_json*, read_body_capped}`), never a raw `reqwest::Response::text()`.
///
/// The raw call buffers the WHOLE body in RAM with no upper bound before the
/// caller ever inspects it — exactly the OOM-on-Termux pattern
/// `util::http::fetch`'s `JSON_BODY_CAP` (32 MiB) and its capped helpers exist
/// to close off. One module (`pypi_user`'s XML-RPC step) called the raw method
/// directly and went unnoticed until a dedicated audit found it: every OTHER
/// body read in the tree had already been migrated to a capped helper, so the
/// established convention gave no compile-time or test signal that this one
/// call site had been missed. This closes that gap permanently: the raw
/// method is only legitimate inside `util::http` itself, where it backs the
/// capped wrappers.
#[test]
fn no_module_reads_an_http_body_without_a_size_cap() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for sub in ["modules", "core"] {
        let mut files = Vec::new();
        walk(&root.join(sub), &mut files);
        files.sort();
        for p in files {
            let text = fs::read_to_string(&p).expect("source file readable");
            for (i, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue; // doc/explanatory comments may mention the pattern
                }
                if line.contains(".text().await") {
                    offenders.push(format!("{}:{}", p.display(), i + 1));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "raw, uncapped reqwest::Response::text().await outside util::http — \
         use util::http::read_text / read_json_text / fetch_json* instead, or \
         read_body_capped for a non-erroring truncated read: {offenders:?}"
    );
}

/// Every in-memory read of a byte STREAM in production is size-bounded.
///
/// `read_to_end` / `read_to_string` pull a whole stream into a `Vec`/`String`;
/// on the Termux target a hostile or broken source — a subprocess pipe, stdin,
/// a socket — writing without limit would grow that buffer until the tool is
/// OOM-killed on an 11 GB phone. The canonical form binds the reader with
/// `.take(N)` first (see `util::curl_client::read_capped`,
/// `cli::investigate::read_prompt_bounded`, `modules::whois::client`). This is
/// the same no-unbounded-read discipline `no_module_reads_an_http_body_without_a_size_cap`
/// applies to HTTP bodies, extended to every other stream: it flags a
/// `read_to_end`/`read_to_string` call that has no `.take(` on its own line or
/// the code line immediately above it (the two shapes the cap idiom takes).
#[test]
fn no_production_read_pulls_a_stream_into_memory_without_a_size_cap() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && !p
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with("tests.rs"))
            {
                out.push(p);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();

    let mut offenders = Vec::new();
    for p in &files {
        let text = fs::read_to_string(p).expect("source file readable");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue; // doc/explanatory comments may mention the pattern
            }
            if !(line.contains(".read_to_end(") || line.contains(".read_to_string(")) {
                continue;
            }
            // Bounded when `.take(` is on this line, or on the nearest preceding
            // non-blank, non-comment code line (the reader was capped there).
            let same = line.contains(".take(");
            let prev = lines[..i]
                .iter()
                .rev()
                .find(|l| {
                    let t = l.trim_start();
                    !t.is_empty() && !t.starts_with("//")
                })
                .is_some_and(|l| l.contains(".take("));
            if !same && !prev {
                offenders.push(format!("{}:{}", p.display(), i + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "unbounded read into memory (read_to_end/read_to_string with no `.take(N)` cap) — \
         a stream a hostile or broken source can grow without limit will OOM the tool on a \
         low-RAM phone; bind the reader with `.take(N)` first (see \
         `util::curl_client::read_capped`): {offenders:?}"
    );
}

/// The release profile stays size-optimized for the aarch64 Termux artifact.
///
/// `opt-level="s"`, `lto=true`, `codegen-units=1` and `strip=true` are the knobs
/// that keep the single on-device binary small; flipping any (e.g. `opt-level=3`,
/// or dropping `strip`) silently bloats the artifact a phone has to download and
/// store. The authoritative BYTE-size guard belongs in CI's aarch64 build (this
/// host has no Android NDK, so the local gate skips that job), but the SETTINGS
/// that produce a small binary are cheaply verifiable here and locked so they
/// can't regress unnoticed between CI runs. `panic="unwind"` is deliberately NOT
/// `abort` (a panicking module is contained at the dispatch boundary rather than
/// aborting a long-lived `hse serve`); it is asserted too so a size-motivated
/// flip to `abort` can't quietly reintroduce that process-abort DoS.
#[test]
fn release_profile_stays_size_optimized() {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo.toml readable");
    // Isolate `[profile.release]` — from its header to the next `[` section — so
    // the separate `[profile.fast]` on-device build profile can't satisfy it.
    let start = manifest
        .find("[profile.release]")
        .expect("[profile.release] must exist");
    let rest = &manifest[start + "[profile.release]".len()..];
    let end = rest.find("\n[").map_or(rest.len(), |n| n + 1);
    // Whitespace-stripped, comment-free `key=value` lines of the section, so
    // `opt-level = "s"` matches and a comment that merely NAMES a setting cannot
    // stand in for the real declaration.
    let lines: Vec<String> = rest[..end]
        .lines()
        .map(|l| {
            l.split('#')
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        })
        .filter(|l| !l.is_empty())
        .collect();

    for (setting, why) in [
        ("opt-level=\"s\"", "size-optimized codegen"),
        ("lto=true", "cross-crate size + inlining"),
        ("codegen-units=1", "whole-crate optimization"),
        ("strip=true", "no symbols in the shipped binary"),
        ("panic=\"unwind\"", "module-panic containment — never abort"),
    ] {
        let want: String = setting.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            lines.contains(&want),
            "[profile.release] must keep `{setting}` ({why}) for the aarch64 Termux \
             artifact — the byte-size CI guard rests on these knobs staying put"
        );
    }
}

/// The HSE BLE Radar dependency (`bleradar-core`) must be pinned to an exact git
/// commit AND actually consumed by the radar — never a floating branch, never
/// dead weight.
///
/// `bleradar-core` is `publish = false`, so it is a git dependency. A git
/// dependency without a full `rev` pin tracks a moving branch, so two builds of
/// the *same* HSE commit can compile *different* BLE-Radar code — the exact
/// "improvement disappears/changes after rebuild" failure the lifecycle
/// discipline forbids. And a dependency nothing calls is duplicate authority
/// carried for nothing. This locks both halves: the pin is a full 40-hex commit
/// (no `branch`/`tag`), and `signal_radar` reaches the crate for its channel +
/// proximity math rather than reimplementing the radar's own domain.
#[test]
fn ble_radar_dependency_is_pinned_and_consumed() {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo.toml readable");
    let dep_line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("bleradar-core"))
        .expect("Cargo.toml must declare the bleradar-core (HSE BLE Radar) dependency");
    assert!(
        dep_line.contains("git ="),
        "bleradar-core must be a git dependency (it is publish=false): {dep_line}"
    );
    let rev = dep_line
        .split_once("rev = \"")
        .and_then(|(_, r)| r.split('"').next())
        .expect("bleradar-core git dependency must pin an exact `rev`");
    assert!(
        rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit()),
        "bleradar-core `rev` must be a full 40-hex commit for a reproducible build, got {rev:?}"
    );
    assert!(
        !dep_line.contains("branch =") && !dep_line.contains("tag ="),
        "bleradar-core must pin `rev`, never a moving branch/tag: {dep_line}"
    );

    // The crate must actually be consumed — the single authority for the radar's
    // channel + proximity math, not a local reimplementation.
    let wifi = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/modules/signal_radar/wifi.rs"
    ))
    .expect("signal_radar/wifi.rs readable");
    for call in [
        "bleradar_core::wifi_frequency_to_channel",
        "bleradar_core::proximity_label",
    ] {
        assert!(
            wifi.contains(call),
            "signal_radar/wifi.rs must use the BLE Radar's `{call}` — the radar math \
             has one authority (bleradar-core), never a local reimplementation"
        );
    }
}

/// The days→civil calendar conversion (Howard Hinnant's `civil_from_days`) has
/// exactly one home: `util::timefmt`. `core::timeline::utc_date` and the
/// id-decoding modules (`structured_id`, `discord_snowflake`) format THROUGH it
/// rather than re-inlining the arithmetic — the "divergent copies of leap-year
/// math" the timeline docs warn about, where a fix to one silently skips the
/// others (`utc_date` was itself a second inline copy until it was collapsed
/// onto `civil_from_days`).
///
/// The `36524`-days-per-100-years divisor is the precise fingerprint of that
/// inverse algorithm: the forward `days_from_civil` never uses it, so it can
/// only appear where the days→civil math is (re-)implemented. Production code
/// (comments and strings blanked, `#[cfg(test)]` items dropped, `_` digit
/// separators removed) must contain it in exactly one file.
#[test]
fn civil_from_days_has_a_single_home() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&manifest.join("src"), &mut files);
    collect_rs_files(&manifest.join("hse-core/src"), &mut files);

    let mut homes: Vec<String> = Vec::new();
    for f in &files {
        if f.file_name().is_some_and(|n| n == "tests.rs") {
            continue; // test fixtures are not a production implementation
        }
        let text = fs::read_to_string(f).unwrap();
        let code: String = production_source(&text)
            .chars()
            .filter(|c| *c != '_')
            .collect();
        if code.contains("36524") {
            homes.push(
                f.strip_prefix(manifest)
                    .unwrap_or(f)
                    .display()
                    .to_string(),
            );
        }
    }
    homes.sort();
    assert_eq!(
        homes,
        vec!["src/util/timefmt.rs".to_string()],
        "the days→civil (`civil_from_days`) algorithm must live only in \
         `util::timefmt`; a second copy re-introduces the divergent leap-year \
         math the timeline docs warn against — route callers through \
         `util::timefmt::civil_from_days` (as `core::timeline::utc_date` now \
         does). The `36524` fingerprint was found in: {homes:?}"
    );
}

/// The 2.4/5/6 GHz WiFi band-range boundaries have exactly one home:
/// `util::wifi::band`. The `signal_radar` scan sweep and the `device_sensors`
/// connection probe both read it (each applying its own `band:` spelling) rather
/// than each holding its own `2400..=2500 / 4900..=5900 / 5925..=7125` copy — two
/// copies that had already been kept in sync only by hand. The `5925..=7125`
/// 6 GHz upper bound is the fingerprint (whitespace-insensitive): production code
/// must contain it in exactly one file.
#[test]
fn wifi_band_ranges_have_a_single_home() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&manifest.join("src"), &mut files);
    collect_rs_files(&manifest.join("hse-core/src"), &mut files);

    let mut homes: Vec<String> = Vec::new();
    for f in &files {
        if f.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let text = fs::read_to_string(f).unwrap();
        let code: String = production_source(&text)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if code.contains("5925..=7125") {
            homes.push(
                f.strip_prefix(manifest)
                    .unwrap_or(f)
                    .display()
                    .to_string(),
            );
        }
    }
    homes.sort();
    assert_eq!(
        homes,
        vec!["src/util/wifi/mod.rs".to_string()],
        "the WiFi band-range boundaries must live only in `util::wifi::band`; a \
         second copy is drift waiting to happen — route callers through \
         `util::wifi::band` instead. The `5925..=7125` fingerprint was found in: {homes:?}"
    );
}

/// The cell-tower DeviceId key `{mcc}-{mnc}-{lac}-{cid}` must be formatted in
/// exactly one place — `util::cell::tower_id`. Four producers (`cell_intel`,
/// `signal_radar`, `cell_local`, `opencellid`) mint DeviceId entities for the
/// same physical tower; if any of them re-inlines the format string with a
/// different spacing/order, one tower forks into two entities and the whole
/// dedup/correlation the DeviceId key exists for silently breaks. Route every
/// producer through `util::cell::tower_id` instead of the literal.
#[test]
fn cell_tower_id_format_has_a_single_home() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&manifest.join("src"), &mut files);
    collect_rs_files(&manifest.join("hse-core/src"), &mut files);

    let mut homes: Vec<String> = Vec::new();
    for f in &files {
        if f.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        // Raw text (NOT production_source): the tower-id fingerprint lives inside
        // a `format!` string literal, which production_source blanks. The
        // `{mcc}-{mnc}-{lac}-{cid}` fingerprint is specific enough that a raw
        // scan across src/ has no false matches.
        let code: String = fs::read_to_string(f)
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if code.contains("{mcc}-{mnc}-{lac}-{cid}") {
            homes.push(f.strip_prefix(manifest).unwrap_or(f).display().to_string());
        }
    }
    homes.sort();
    assert_eq!(
        homes,
        vec!["src/util/cell.rs".to_string()],
        "the cell tower-id format must live only in `util::cell::tower_id`; a \
         second copy forks one tower into two DeviceId entities. The \
         `{{mcc}}-{{mnc}}-{{lac}}-{{cid}}` fingerprint was found in: {homes:?}"
    );
}

/// The co-hosting fan-out cap `MAX_CO_HOSTED_REGISTRABLE` must be DEFINED once
/// (in `relation::builders`, re-exported from `core::relation`). The
/// `SameOperator` builder edge and the AU-110 co-hosting finding read the
/// identical membership set, so a second definition is exactly the silent
/// edge-vs-finding disagreement single-sourcing exists to prevent.
#[test]
fn max_co_hosted_registrable_is_defined_once() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&manifest.join("src"), &mut files);
    collect_rs_files(&manifest.join("hse-core/src"), &mut files);

    let mut homes: Vec<String> = Vec::new();
    for f in &files {
        if f.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let text = fs::read_to_string(f).unwrap();
        let code: String = production_source(&text)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if code.contains("constMAX_CO_HOSTED_REGISTRABLE:usize=") {
            homes.push(f.strip_prefix(manifest).unwrap_or(f).display().to_string());
        }
    }
    homes.sort();
    assert_eq!(
        homes,
        vec!["src/core/relation/builders.rs".to_string()],
        "MAX_CO_HOSTED_REGISTRABLE must be DEFINED once (relation::builders, \
         re-exported from core::relation); consumers `use` it. A second \
         definition drifts the SameOperator edge from the AU-110 finding. \
         Found in: {homes:?}"
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

    // The heading's free/key-gated SPLIT is also authoritative and was previously
    // unguarded — so it silently drifted (headline said "128 free, 34 paid" while
    // the registry held a different split, and later edits compounded it). Tie the
    // full split to the live cost() of every registered module so it can't rot
    // again — the same no-silent-drift guard as the total above. (The per-category
    // "highlight" subtotals lower down are a deliberately CURATED subset, not the
    // registry total, so they are intentionally not checked here.)
    use huntsman_search_engine::core::module::ModuleCost;
    let registry = huntsman_search_engine::modules::registry();
    let (mut free, mut key_gated_paid) = (0usize, 0usize);
    for m in &registry {
        match m.cost() {
            ModuleCost::Free => free += 1,
            ModuleCost::KeyGated | ModuleCost::Paid => key_gated_paid += 1,
        }
    }
    let split =
        format!("## Module Overview ({n} modules — {free} free, {key_gated_paid} key-gated/paid)");
    assert!(
        readme.contains(&split),
        "README module-overview headline must cite the live free/key-gated split \
         ({split:?}); update README.md after adding/removing a module or changing \
         a module's cost()"
    );

    // The heading check alone proved insufficient: the intro blurb and the
    // `hse modules` usage comment each carry their own hand-written count and
    // both rotted to a stale figure while the heading stayed correct. Sweep
    // EVERY "<digits> modules" mention in the README against the registry.
    let stale: Vec<&str> = readme
        .lines()
        .filter(|line| {
            let mut rest = *line;
            while let Some(pos) = rest.find(" modules") {
                let prefix = &rest[..pos];
                let digits: String = prefix
                    .chars()
                    .rev()
                    .take_while(char::is_ascii_digit)
                    .collect();
                if !digits.is_empty() {
                    let count: usize = digits.chars().rev().collect::<String>().parse().unwrap();
                    // Only headline totals can match the registry; sub-counts
                    // ("81 free", …) are smaller and skipped via a floor.
                    if count > n / 2 && count != n {
                        return true;
                    }
                }
                rest = &rest[pos + " modules".len()..];
            }
            false
        })
        .collect();
    assert!(
        stale.is_empty(),
        "README cites a stale module total (registry holds {n}): {stale:?}"
    );
}

/// The README's "Deterministic correlator: N rules (E entity + R graph-aware
/// relation)" line is hand-maintained prose and had already drifted once
/// (stated 108 while the registry held 109, immediately after a rule was
/// added and the README was left behind). Tie it to
/// [`huntsman_search_engine::core::correlator::rule_counts`] so it can't
/// silently rot again — the same no-silent-drift guard as
/// `readme_module_overview_count_matches_registry`.
#[test]
fn readme_correlator_rule_count_matches_registry() {
    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md must exist");
    let (entity, relation) = huntsman_search_engine::core::correlator::rule_counts();
    let total = entity + relation;
    let needle = format!(
        "Deterministic correlator: {total} rules ({entity} entity + {relation} graph-aware relation)"
    );
    assert!(
        readme.contains(&needle),
        "README must cite the live correlator rule split ({needle:?}); update \
         README.md after adding/removing a rule"
    );
}

/// The compiled runtime must carry NO third-party AI / ML / inference / vector /
/// embedding crate: every finding-producing capability is deterministic Rust
/// that reproduces identically on Termux aarch64 (no root), Linux and CI with
/// no model available. This turns that into a mechanical CI check — adding
/// e.g. `candle`, `onnxruntime`, an LLM SDK, `tokenizers`, or `qdrant-client`
/// fails here. External OSINT *data* APIs (registries, breach corpora,
/// geocoders) are data sources, not AI services, and are deliberately
/// unaffected.
///
/// This claim is now UNCONDITIONAL. It previously carved out one exception —
/// a hand-rolled HTTP client for a local inference server, which no crate-name
/// denylist could see — guarded by a companion test that kept its output out of
/// the evidence graph. That integration was removed wholesale, so there is no
/// runtime LLM path left to carve out; `no_llm_inference_integration_exists`
/// scans the live tree so it stays gone.
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
         dependency tree: {offenders:?}. Every finding-producing runtime path \
         must stay deterministic Rust, and HSE carries no LLM integration at all \
         (see `no_llm_inference_integration_exists`)."
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
        "ip2location",
        "ipquery",
        "ip_whois_geo",
        "wigle",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
    let mut offenders = Vec::new();
    for provider in COARSE_PROVIDERS {
        // Modules may be a flat file (`{provider}.rs`) or a directory module
        // (`{provider}/mod.rs`). For directory modules we concatenate all
        // non-test source files so the gate check covers the whole module.
        let flat = root.join(format!("{provider}.rs"));
        let dir = root.join(provider);
        let src = if flat.exists() {
            fs::read_to_string(&flat)
                .unwrap_or_else(|_| panic!("coarse provider {provider} missing at {flat:?}"))
        } else if dir.is_dir() {
            // Concatenate the module's PRODUCTION source. Read in a deterministic
            // (sorted) order and strip each file's own `mod tests` section BEFORE
            // concatenating: for a multi-file module whose gate call lives outside
            // `mod.rs` (e.g. wigle's is in `emit.rs`), a `mod.rs` concatenated
            // ahead of it would otherwise be truncated away by the later
            // `split("mod tests")`, making this guard pass or fail on
            // `fs::read_dir` order alone — green locally yet red in CI.
            let mut paths: Vec<_> = fs::read_dir(&dir)
                .unwrap_or_else(|_| panic!("cannot read dir {dir:?}"))
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
                .collect();
            paths.sort();
            let mut combined = String::new();
            for p in paths {
                // `tests.rs` is pure unit-test code — never part of the gate.
                if p.file_name().and_then(|n| n.to_str()) == Some("tests.rs") {
                    continue;
                }
                if let Ok(s) = fs::read_to_string(&p) {
                    // Drop this file's `#[cfg(test)]` items so a
                    // `use is_valid_coords` in a unit test can't satisfy the gate.
                    //
                    // This was `s.split("mod tests").next()`, which cut at the
                    // first occurrence of the *substring* `mod tests` — so with
                    // `#[cfg(test)] mod tests;` at the top of a file, every
                    // production function below it vanished. For a gate phrased
                    // as "must CONTAIN the guard call" that fails the safe way
                    // (a false offender, not a false pass), but it is still
                    // wrong, and it would have started failing spuriously the
                    // moment a provider's coord call moved below the
                    // declaration. `production_source` also means a mention of
                    // the helper in a comment no longer satisfies the gate.
                    combined.push_str(&production_source(&s));
                    combined.push('\n');
                }
            }
            combined
        } else {
            panic!("coarse provider {provider} missing at {flat:?}");
        };
        // Flat-file modules are stripped here (directory modules were already
        // stripped per-file above; this is a no-op for them).
        let prod = production_source(&src);
        let prod = prod.as_str();
        // The gate is satisfied either by calling `is_plausible_provider_coord`
        // directly OR by building the entity through `coarse_provider_coords`,
        // which applies that exact gate internally (ipinfo/ip2location/
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

/// CONVENTIONS.md §2 — hubs declare, never house. Outside `#[cfg(test)]`
/// code, a module body belongs in its own file: `pub mod name;` in the hub,
/// code in `name.rs`. This pin turns the convention into a mechanical check
/// (the same treatment the AI-independence charter got), so the consistency
/// bought by extracting every inline module from core/mod.rs and util/mod.rs
/// can't erode one "harmless exception" at a time. The only permitted inline
/// bodies are trivial wrappers that would be NOISE as files, allow-listed
/// here by (path-suffix, module-name) so adding one is a reviewed decision.
#[test]
fn no_inline_module_bodies_outside_allowed_exceptions() {
    // (path suffix, module name) → why it is legitimately inline.
    const ALLOWED: &[(&str, &str)] = &[
        // 3-line include! wrapper for the build.rs-generated source manifest.
        ("src/lib.rs", "source_manifest"),
        // 5-line path-constants shim local to the oathnet util.
        ("src/util/oathnet.rs", "paths"),
    ];

    fn visit(dir: &Path, offenders: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, offenders);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "tests.rs")
                // A `tests/` directory component catches the same test code
                // when `tests.rs` splits its content into `tests/partNN.rs`
                // fragments via `include!` (done purely to keep each file
                // small enough for reliable transmission through this repo's
                // push tooling) — those fragments are entirely test code too,
                // just as a file literally named `tests.rs` is.
                || path.components().any(|c| c.as_os_str() == "tests")
            {
                continue;
            }
            let raw = fs::read_to_string(&path).unwrap();
            let rel = path.display().to_string().replace('\\', "/");
            // This latched `in_test` on the first `#[cfg(test)]` and never
            // reset, justified by "test modules come last". They do not: the
            // prevailing idiom here is `#[cfg(test)] mod tests;` at the TOP of
            // the file, so every inline `mod foo { … }` below it went unchecked
            // and this invariant under-reported by construction.
            let content = production_source(&raw);
            for (i, line) in content.lines().enumerate() {
                let t = line.trim();
                if !t.ends_with('{') {
                    continue;
                }
                let rest = ["pub(crate) mod ", "pub(super) mod ", "pub mod ", "mod "]
                    .iter()
                    .find_map(|p| t.strip_prefix(p));
                let Some(rest) = rest else { continue };
                let Some(name) = rest.strip_suffix('{').map(str::trim) else {
                    continue;
                };
                if name == "tests"
                    || ALLOWED
                        .iter()
                        .any(|(suf, m)| rel.ends_with(suf) && *m == name)
                {
                    continue;
                }
                offenders.push(format!("{rel}:{}: inline `mod {name}`", i + 1));
            }
        }
    }

    let mut offenders = Vec::new();
    visit(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut offenders,
    );
    assert!(
        offenders.is_empty(),
        "inline module bodies outside the allow-list (CONVENTIONS.md §2 — \
         move the body to its own file, or allow-list a trivial wrapper \
         with a justification): {offenders:#?}"
    );
}

/// The README's "Seed Types (N supported)" table carries a per-seed "Modules"
/// column that is hand-maintained prose, unlike the headline module total and
/// free/key-gated split (guarded by `readme_module_overview_count_matches_registry`)
/// or the correlator rule count (`readme_correlator_rule_count_matches_registry`).
/// It rotted badly: every row still cited an early, ~90-module-era registry
/// snapshot while the live registry grew to 188 (e.g. "Full Name 6" vs the live
/// count, "URL 2" vs the live count, "Organisation 2" vs the live count) — a
/// table an operator reads to gauge how much recon a given seed kind actually
/// gets, silently understating it by 3-12x for most rows. Tie each row to
/// `Module::consumes()` counted over the live registry so it can't silently drift
/// again — the same no-silent-drift guard the other two README-count tests apply.
#[test]
fn readme_seed_type_module_counts_match_registry() {
    use huntsman_search_engine::core::scan::TargetKind;
    use huntsman_search_engine::modules::registry;

    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md must exist");

    // (README row label, its `--kind` alias, the `TargetKind` that alias parses
    // to). Deliberately just the 16 rows the table documents — `device_id`,
    // `ssid`, and `tracking_id` are pivot-only kinds an operator never types as
    // a starting `--kind`, so the table (and this guard) omit them by design.
    const ROWS: &[(&str, &str, TargetKind)] = &[
        ("Email", "email", TargetKind::Email),
        ("Username", "username", TargetKind::Username),
        ("Phone", "phone", TargetKind::Phone),
        ("Full Name", "name", TargetKind::FullName),
        ("IP Address", "ip", TargetKind::IpAddress),
        ("Domain", "domain", TargetKind::Domain),
        ("ASN", "asn", TargetKind::Asn),
        ("CIDR", "cidr", TargetKind::Cidr),
        ("Coordinates", "coords", TargetKind::Coordinates),
        ("Address", "address", TargetKind::Address),
        ("URL", "url", TargetKind::Url),
        ("Organisation", "org", TargetKind::Organisation),
        ("ABN/ACN", "abn", TargetKind::AbnAcn),
        ("MAC Address", "mac", TargetKind::MacAddress),
        ("Crypto Address", "crypto", TargetKind::CryptoAddress),
        ("API Key", "apikey", TargetKind::ApiKey),
    ];

    let live = registry();
    let mut mismatches = Vec::new();
    for (label, flag, kind) in ROWS {
        let live_count = live.iter().filter(|m| m.consumes().contains(kind)).count();
        let needle = format!("| {label} | `--kind {flag}` |");
        let Some(line) = readme.lines().find(|l| l.starts_with(&needle)) else {
            mismatches.push(format!(
                "{label}: README row not found (looked for {needle:?})"
            ));
            continue;
        };
        // Row shape `| Seed | Flag | Example | Modules |` — the last non-empty
        // `|`-delimited cell is the documented module count.
        let documented = line
            .trim_end_matches('|')
            .rsplit('|')
            .next()
            .map(str::trim)
            .and_then(|s| s.parse::<usize>().ok());
        match documented {
            Some(n) if n == live_count => {}
            Some(n) => mismatches.push(format!(
                "{label}: README says {n}, live registry has {live_count}"
            )),
            None => {
                mismatches.push(format!(
                    "{label}: could not parse a module count from {line:?}"
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "README 'Seed Types' table's per-seed module counts drifted from the live \
         registry (update README.md after adding/removing a module or changing a \
         module's consumes()): {mismatches:#?}"
    );

    // The clarifying note explaining why device_id/ssid/tracking_id are
    // deliberately omitted from the table above also states their current
    // module counts — pin those too, so that sentence can't silently drift
    // the same way the table itself once did (REQ-README-003/004).
    let device_id_count = live
        .iter()
        .filter(|m| m.consumes().contains(&TargetKind::DeviceId))
        .count();
    let ssid_count = live
        .iter()
        .filter(|m| m.consumes().contains(&TargetKind::Ssid))
        .count();
    let tracking_id_count = live
        .iter()
        .filter(|m| m.consumes().contains(&TargetKind::TrackingId))
        .count();
    // Singular/plural per count, not one trailing "modules" for the whole
    // list — "1, 1, and 2 modules" read grammatically wrong for the singular
    // entries (Copilot review on PR #569).
    let unit = |n: usize| if n == 1 { "module" } else { "modules" };
    let expected_note = format!(
        "They currently feed {device_id_count} {}, {ssid_count} {}, and \
         {tracking_id_count} {}, respectively.",
        unit(device_id_count),
        unit(ssid_count),
        unit(tracking_id_count),
    );
    // Collapse whitespace before matching: the sentence is prose that wraps
    // across lines in the raw Markdown source (a hard newline where the
    // sentence happens to break), so a literal-newline substring match would
    // be brittle against harmless rewrapping.
    let readme_flat = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        readme_flat.contains(&expected_note),
        "README's pivot-only seed-kind note (device_id/ssid/tracking_id) has drifted \
         from the live registry — expected to find {expected_note:?} in README.md"
    );
}
