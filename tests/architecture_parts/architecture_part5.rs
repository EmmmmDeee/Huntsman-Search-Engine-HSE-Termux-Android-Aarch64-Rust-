/// Every rule wired into RULES or RELATION_RULES must have at least one
/// positive firing test in the correlator test suite. A dispatched rule with
/// no firing test compiles, is called on every scan, but silently produces no
/// correlation even when its trigger condition is met — indistinguishable from
/// a correctly-absent result. Two detection modes are accepted:
///
/// - **Direct**: the rule function name appears in the corpus, AND within ±15
///   lines there is a `len(), N` assertion where N > 0 (the canonical
///   positive-result form used throughout the correlator test suite).
/// - **Indirect**: the quoted `"AU-NNN"` rule-id appears on a line that also
///   contains `assert`/`.unwrap()`/`.expect()`/`contains(` (covers rules
///   verified through `correlate_entities()` or `Correlator::run()` rather
///   than a direct function call).
#[test]
fn every_dispatched_correlation_rule_has_a_firing_test() {
    let mod_src = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/core/correlator/mod.rs"
    ))
    .expect("correlator/mod.rs must exist");

    let corpus = correlator_tests_source();
    let corpus_lines: Vec<&str> = corpus.lines().collect();

    // Extract dispatched rule function names from the RULES / RELATION_RULES
    // arrays: each element is a bare identifier on its own indented line.
    let dispatched: Vec<String> = mod_src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("rule_au_"))
        .map(|l| {
            l.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        })
        .collect();

    assert!(
        !dispatched.is_empty(),
        "parse failure: no dispatched rules found"
    );

    let missing: Vec<&str> = dispatched
        .iter()
        .filter(|rule| {
            // (a) Direct: function name in corpus, positive len assertion nearby.
            let direct = corpus_lines.iter().enumerate().any(|(i, line)| {
                if !line.contains(rule.as_str()) {
                    return false;
                }
                let start = i.saturating_sub(15);
                let end = (i + 15).min(corpus_lines.len());
                corpus_lines[start..end]
                    .iter()
                    .any(|ctx| has_nonzero_len_assert(ctx))
            });
            if direct {
                return false;
            }
            // (b) Indirect: quoted "AU-NNN" id on a line with an assertion form.
            let id_str = rule
                .strip_prefix("rule_au_")
                .and_then(|r| r.split('_').next())
                .and_then(|n| n.parse::<u32>().ok())
                .map(|n| format!("\"AU-{n:03}\""));
            let indirect = id_str.as_deref().is_some_and(|id| {
                corpus_lines.iter().any(|l| {
                    l.contains(id)
                        && (l.contains("assert")
                            || l.contains(".unwrap()")
                            || l.contains(".expect(")
                            || l.contains("contains("))
                })
            });
            !indirect
        })
        .map(String::as_str)
        .collect();

    assert!(
        missing.is_empty(),
        "dispatched correlation rule(s) with no positive firing fixture in the \
         test suite — add a test that calls the rule function directly (or \
         exercises it via correlate_entities/Correlator::run) and asserts at \
         least one correlation is produced: {missing:?}"
    );
}

#[test]
fn every_literal_constructed_entity_kind_is_declared_in_produces() {
    // FORWARD producer-graph accuracy — the dual of smoke.rs's
    // `every_declared_produced_pivot_has_a_consumer`. A module that mints an
    // entity via a literal `Entity::new(EntityKind::X, …)` must declare `X` in
    // `produces()`, so the capability map and consumer-matching can never
    // silently under-represent what the module actually emits. This locks in the
    // produces()-accuracy audit (crtsh / oathnet_pro / see_know et al.).
    //
    // SOUND, not complete — by construction it raises only true positives:
    //   * It inspects only LITERAL constructions. A module that builds entities
    //     with a *variable* kind (wigle / search_engines classify at runtime, the
    //     core `classifier` extracts dynamically) is not checked here — a miss,
    //     never a false alarm.
    //   * The terminal catch-all `EntityKind::Other(_)` is excluded: it is
    //     non-pivotable (`TargetKind::from_entity_kind` → None) and by universal
    //     convention declared by no module — exactly like the Credential/Password
    //     terminals the reverse guard special-cases.
    // Coverage floors keep it from rotting into a vacuous pass.
    use huntsman_search_engine::core::entity::EntityKind;
    use huntsman_search_engine::modules::registry;

    // PascalCase variant identifier for a declared kind, e.g. `IpAddress`; for the
    // tuple variant `Other(String)` the leading `Other` before `(`.
    fn variant_name(k: &EntityKind) -> String {
        let dbg = format!("{k:?}");
        match dbg.split_once('(') {
            Some((head, _)) => head.to_string(),
            None => dbg,
        }
    }

    // Every `Entity::new( EntityKind::<Ident>` variant token in one source file,
    // tolerating whitespace/newlines between `new(` and the kind path.
    fn constructed_kinds(src: &str) -> Vec<String> {
        const NEEDLE: &str = "Entity::new(";
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(p) = rest.find(NEEDLE) {
            rest = &rest[p + NEEDLE.len()..];
            if let Some(tail) = rest.trim_start().strip_prefix("EntityKind::") {
                let ident: String = tail
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !ident.is_empty() {
                    out.push(ident);
                }
            }
        }
        out
    }

    fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(p);
            }
        }
    }

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src/modules");
    let mut scanned_modules = 0usize;
    let mut kinds_checked = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for m in registry() {
        let name = m.name();
        let declared: std::collections::HashSet<String> =
            m.produces().iter().map(variant_name).collect();

        // name → src/modules/<name>/ (dir) or src/modules/<name>.rs (file).
        // Core-hosted modules (e.g. the universal `classifier`) live outside this
        // tree and build dynamically — no literal constructions to check, so they
        // are skipped; the coverage floor below stops that from going vacuous.
        let dir = Path::new(root).join(name);
        let file = Path::new(root).join(format!("{name}.rs"));
        let mut files = Vec::new();
        if dir.is_dir() {
            rs_files(&dir, &mut files);
        } else if file.is_file() {
            files.push(file);
        } else {
            continue;
        }
        scanned_modules += 1;

        for path in files {
            let Ok(src) = fs::read_to_string(&path) else {
                continue;
            };
            for ident in constructed_kinds(&src) {
                if ident == "Other" {
                    continue; // terminal catch-all, never declared by convention
                }
                kinds_checked += 1;
                if !declared.contains(&ident) {
                    let v = format!(
                        "{name} constructs EntityKind::{ident} (literal Entity::new) but \
                         does not declare it in produces()  [{}]",
                        path.display()
                    );
                    if !violations.contains(&v) {
                        violations.push(v);
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "module(s) mint (via literal Entity::new) an EntityKind absent from \
         produces() — add it to the module's produces() so the capability graph \
         reflects what it emits:\n  {}",
        violations.join("\n  ")
    );
    // Floors: the source audit mapped 160 modules and ~450 distinct literal
    // EntityKind constructions. Keep generous lower bounds so a refactor that
    // breaks the name→file map or the scanner can't make this guard pass vacuously.
    assert!(
        scanned_modules >= 120,
        "expected to map most modules to source, only mapped {scanned_modules}"
    );
    assert!(
        kinds_checked >= 300,
        "expected many literal EntityKind constructions, saw {kinds_checked}"
    );
}

#[test]
fn every_checked_feature_flag_is_registered() {
    // Toggle contract (checked ⊆ registered): a `"feature.X"` switch read
    // anywhere OUTSIDE the settings module must name a key registered in
    // FEATURE_TOGGLES — otherwise the operator can never see or control it (the
    // web/CLI toggle catalogue, `hse config`, and the write guard all gate on
    // `is_feature_key`/FEATURE_TOGGLES). Sound by construction: it scans string
    // literals only, and skips `src/util/settings` (the registry + the named
    // constants live there, so their literals are registration, not usage). The
    // reverse direction (no registered toggle is dead) is covered by the read
    // sites every FEATURE_TOGGLES key carries plus
    // `feature_toggles_length_matches_registration`.
    use huntsman_search_engine::util::settings::is_feature_key;

    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.ends_with("util/settings") {
                    continue; // the registry + const defs — literals here are registration
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(p);
            }
        }
    }

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut files = Vec::new();
    walk(Path::new(root), &mut files);

    const NEEDLE: &str = "\"feature.";
    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for path in &files {
        let Ok(src) = fs::read_to_string(path) else {
            continue;
        };
        let mut rest = src.as_str();
        while let Some(p) = rest.find(NEEDLE) {
            rest = &rest[p + 1..]; // step past the opening quote
            let key: String = rest.chars().take_while(|c| *c != '"').collect();
            // Only well-formed `feature.<ident>` keys (ignore a bare prefix).
            if key.len() > "feature.".len()
                && key[8..].chars().all(|c| c.is_ascii_lowercase() || c == '_')
            {
                checked += 1;
                if !is_feature_key(&key) {
                    let v = format!("{key} [{}]", path.display());
                    if !violations.contains(&v) {
                        violations.push(v);
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "feature flag(s) read via a \"feature.*\" literal but NOT registered in \
         FEATURE_TOGGLES — the operator can't toggle them; register each:\n  {}",
        violations.join("\n  ")
    );
    // Floor: the codebase checks several literal feature flags (regional, recall,
    // auto_update, update_notify, …); a refactor that breaks the scan can't make
    // this guard vacuously pass.
    assert!(
        checked >= 3,
        "expected several literal feature.* checks outside settings, saw {checked}"
    );
}

// ── Canonical entity classifier convergence tests ─────────────────────────────
// Phase 1, item 1: `core::classifier` owns the canonical embedded-entity locators;
// `util::entity_extractor` re-uses them. These tests assert that the re-exported
// patterns are identical to the canonical ones and that classification is
// deterministic.

use huntsman_search_engine::core::classifier as core_classifier;
use huntsman_search_engine::util::entity_extractor::EntityKind;
use huntsman_search_engine::util::entity_extractor::classifier::EntityClassifier;
use huntsman_search_engine::util::entity_extractor::patterns;

#[test]
fn entity_extractor_reuses_core_patterns() {
    // The patterns re-exported by `util::entity_extractor::patterns` must be the
    // *same* `Regex` instances as the canonical `core::classifier` patterns.
    assert!(std::ptr::addr_eq(
        &*patterns::EMAIL_PATTERN,
        &*core_classifier::EMAIL_RE
    ));
    assert!(std::ptr::addr_eq(
        &*patterns::IPV4_PATTERN,
        &*core_classifier::IPV4_RE
    ));
    assert!(std::ptr::addr_eq(
        &*patterns::DOMAIN_PATTERN,
        &*core_classifier::DOMAIN_RE
    ));
    assert!(std::ptr::addr_eq(
        &*patterns::URL_PATTERN,
        &*core_classifier::URL_RE
    ));
}

#[test]
fn core_and_extractor_classifiers_agree_on_canonical_values() {
    let classifier = EntityClassifier::new().expect("should succeed");

    let cases: &[(&str, EntityKind)] = &[
        ("test@example.com", EntityKind::Email),
        ("https://example.com/path", EntityKind::Url),
        ("192.168.1.1", EntityKind::Ipv4),
        ("example.com", EntityKind::Domain),
    ];

    for (value, expected) in cases {
        assert_eq!(
            classifier.classify(value, None),
            *expected,
            "classifier mismatch for {value}"
        );
        let core = core_classifier::classify(value);
        assert_eq!(
            core.value, *value,
            "core classifier must preserve the raw value"
        );
        assert!(
            core.confidence > 0.0,
            "core classifier must assign non-zero confidence to {value}"
        );
    }
}

#[test]
fn core_extract_is_deterministic() {
    let text = "Contact: alice@example.com or https://example.com and 8.8.8.8. \
                Also example.org and @handle.";
    let first = core_classifier::extract(text);
    let second = core_classifier::extract(text);
    assert_eq!(
        first, second,
        "core::classifier::extract must be deterministic for the same input"
    );
    // Smoke-check that the canonical locators actually found the expected entities.
    assert!(
        first
            .iter()
            .any(|c| c.kind == huntsman_search_engine::core::entity::EntityKind::Email),
        "expected an email entity"
    );
    assert!(
        first
            .iter()
            .any(|c| c.kind == huntsman_search_engine::core::entity::EntityKind::Url),
        "expected a URL entity"
    );
    assert!(
        first
            .iter()
            .any(|c| c.kind == huntsman_search_engine::core::entity::EntityKind::IpAddress),
        "expected an IP entity"
    );
}

// ── Confidence-ladder invariant ──────────────────────────────────────────────

/// Split the top-level, comma-separated arguments of a call. `s` must start at
/// the call's opening `(`. Nested delimiters and string literals are skipped so
/// a multi-line call, or one whose arguments contain commas inside `{}`/`()`,
/// still yields the correct argument list. Returns `None` if unterminated.
fn call_args(s: &str) -> Option<Vec<String>> {
    let mut depth = 0i32;
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                if depth > 1 {
                    cur.push(c);
                }
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    args.push(cur);
                    return Some(args);
                }
                cur.push(c);
            }
            ',' if depth == 1 => args.push(std::mem::take(&mut cur)),
            '"' => {
                cur.push(c);
                while let Some(d) = chars.next() {
                    cur.push(d);
                    if d == '\\' {
                        if let Some(e) = chars.next() {
                            cur.push(e);
                        }
                        continue;
                    }
                    if d == '"' {
                        break;
                    }
                }
            }
            _ => cur.push(c),
        }
    }
    None
}

/// Every bare float literal (`0.68`) appearing anywhere in `s`, in order.
///
/// # Why "anywhere" and not "is the whole argument"
///
/// This used to be `is_bare_float(&args[2])`, true only when the confidence
/// argument was a lone literal. A literal *embedded in an expression* was
/// therefore invisible, and `steam_profile` has three:
/// `(conf - 0.27).max(0.42)`, `(conf - 0.33).max(0.42)`,
/// `(conf - 0.25).max(0.38)`. Each `.max(..)` is a hardcoded confidence floor —
/// exactly the unauditable magic number the invariant exists to forbid — and
/// each sailed past the ratchet.
///
/// The inventory was visibly inconsistent as a result:
/// `asic_business_names`'s bare `0.42` was baselined while `steam_profile`'s
/// identical `0.42` was not, purely because one sat in an expression.
///
/// Only `0.NN` is matched, which is the entire ladder's shape, and a leading
/// alphanumeric, `_` or `.` disqualifies the match so an identifier or a
/// dotted path cannot be misread as a literal.
fn bare_float_literals(s: &str) -> Vec<String> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let starts_literal = c[i] == '0'
            && c.get(i + 1) == Some(&'.')
            && (i == 0 || !(c[i - 1].is_alphanumeric() || c[i - 1] == '_' || c[i - 1] == '.'));
        if starts_literal {
            let mut j = i + 2;
            while j < c.len() && c[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 2 {
                out.push(c[i..j].iter().collect::<String>());
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// The slicing and literal detection the confidence ratchet depends on, asserted
/// directly — a ratchet whose scanner is untested measures whatever it reaches.
#[test]
fn bare_float_detection_sees_literals_inside_expressions() {
    // The shape that used to evade the ratchet entirely.
    assert_eq!(
        bare_float_literals("(conf - 0.27).max(0.42)"),
        vec!["0.27".to_string(), "0.42".to_string()]
    );
    // A lone literal still matches, as before.
    assert_eq!(bare_float_literals("0.68"), vec!["0.68".to_string()]);
    assert_eq!(bare_float_literals(" 0.68 "), vec!["0.68".to_string()]);
    // Named constants are not literals, however they are combined.
    assert!(bare_float_literals("confidence::HIGH_PLUS").is_empty());
    // Equality, not `.all(..)`: `all` on an empty iterator is TRUE, so the
    // obvious spelling would still pass if the detector regressed to finding
    // nothing — a check that certifies what it never verified, which is the
    // exact class of defect this ratchet exists to catch.
    assert_eq!(
        bare_float_literals("(conf - 0.13).max(confidence::LOW_MEDIUM)"),
        vec!["0.13".to_string()]
    );
    // An identifier or dotted path that merely contains the characters must not
    // be misread — `v0.42` is a name, `x.0.42` is field access.
    assert!(bare_float_literals("v0.42").is_empty());
    assert!(bare_float_literals("tuple.0.42").is_empty());
    // `0.` with no digits is not a literal we recognise.
    assert!(bare_float_literals("0.").is_empty());
}

/// Blank the *contents* of comments and string/char literals, preserving **byte**
/// length and line structure so the result stays offset-aligned with the input.
///
/// Every scanner below counts delimiters, and a brace, quote or semicolon inside
/// a string or a comment is not a delimiter. Doing this once, up front, is what
/// lets [`production_source`] brace-match a `#[cfg(test)] mod tests { … }` body
/// exactly rather than approximately.
///
/// Byte length is preserved, not merely character count: a blanked multi-byte
/// char is replaced by as many spaces as it occupied. That keeps every byte
/// offset in the output valid in the input too, so a future caller can map a
/// finding back to a source position — the obvious next step for these ratchets,
/// which today report file-and-value only. Blanking a 3-byte `…` to one space
/// would silently shift every offset after the first non-ASCII comment in a file.
///
/// Handles the forms that actually occur in this tree: line comments, *nesting*
/// block comments, plain and raw strings (`r"…"`, `r#"…"#`), and char literals —
/// including the lifetime-vs-char-literal ambiguity, where `'static` must not be
/// read as an unterminated `'`.
fn blank_strings_and_comments(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    // Blank one char, keeping newlines so line structure survives and padding to
    // the char's own byte width so offsets survive too.
    let blank = |out: &mut String, ch: char| {
        if ch == '\n' {
            out.push('\n');
        } else {
            for _ in 0..ch.len_utf8() {
                out.push(' ');
            }
        }
    };
    let mut i = 0;
    while i < c.len() {
        let cur = c[i];
        let next = c.get(i + 1).copied();
        match cur {
            '/' if next == Some('/') => {
                while i < c.len() && c[i] != '\n' {
                    blank(&mut out, c[i]);
                    i += 1;
                }
            }
            '/' if next == Some('*') => {
                // Rust block comments nest, so a depth counter is required.
                let mut depth = 1usize;
                out.push_str("  ");
                i += 2;
                while i < c.len() && depth > 0 {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        out.push_str("  ");
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        out.push_str("  ");
                        i += 2;
                    } else {
                        blank(&mut out, c[i]);
                        i += 1;
                    }
                }
            }
            'r' if matches!(next, Some('"' | '#')) => {
                // Raw string: r"…", r#"…"#, r##"…"##. Count the hashes so the
                // terminator matches the opener and an embedded `"#` is safe.
                let mut j = i + 1;
                let mut hashes = 0usize;
                while c.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if c.get(j) != Some(&'"') {
                    // Just an identifier starting with `r` (e.g. `result`).
                    out.push(cur);
                    i += 1;
                    continue;
                }
                out.push('r');
                for _ in 0..hashes {
                    out.push('#');
                }
                out.push('"');
                i = j + 1;
                let close: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                while i < c.len() {
                    if c[i] == '"' && c[i..].iter().take(close.len()).copied().eq(close.chars()) {
                        break;
                    }
                    blank(&mut out, c[i]);
                    i += 1;
                }
                for _ in 0..close.len().min(c.len().saturating_sub(i)) {
                    out.push(c[i]);
                    i += 1;
                }
            }
            '"' => {
                out.push('"');
                i += 1;
                while i < c.len() {
                    if c[i] == '\\' {
                        blank(&mut out, c[i]);
                        i += 1;
                        if i < c.len() {
                            blank(&mut out, c[i]);
                            i += 1;
                        }
                        continue;
                    }
                    if c[i] == '"' {
                        out.push('"');
                        i += 1;
                        break;
                    }
                    blank(&mut out, c[i]);
                    i += 1;
                }
            }
            '\'' => {
                // `'a'` and `'\n'` are char literals; `'static` is a lifetime and
                // must pass through untouched or every following delimiter shifts.
                let is_char_lit = next == Some('\\') || c.get(i + 2) == Some(&'\'');
                if !is_char_lit {
                    out.push(cur);
                    i += 1;
                    continue;
                }
                out.push('\'');
                i += 1;
                while i < c.len() {
                    if c[i] == '\\' {
                        blank(&mut out, c[i]);
                        i += 1;
                        if i < c.len() {
                            blank(&mut out, c[i]);
                            i += 1;
                        }
                        continue;
                    }
                    if c[i] == '\'' {
                        out.push('\'');
                        i += 1;
                        break;
                    }
                    blank(&mut out, c[i]);
                    i += 1;
                }
            }
            _ => {
                out.push(cur);
                i += 1;
            }
        }
    }
    out
}
