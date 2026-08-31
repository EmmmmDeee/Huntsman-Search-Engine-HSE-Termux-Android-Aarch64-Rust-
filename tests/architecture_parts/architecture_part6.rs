/// Byte length of the item a `#[cfg(test)]` attribute applies to, measured from
/// just after the attribute. `s` must already be lexically clean (see
/// [`blank_strings_and_comments`]).
///
/// An item ends at the first `;` outside any bracket, or at the `}` closing the
/// first block it opens — which covers every form in this tree:
/// `mod tests;`, `mod tests { … }`, `use x::{a, b};`, `fn helper(…) { … }`, and
/// `const K: [u8; 4] = …;` (the `;` inside `[u8; 4]` is bracketed, so it is not
/// mistaken for the end).
fn cfg_test_item_len(s: &str) -> usize {
    let mut depth = 0i32;
    let mut opened_block = false;
    for (idx, ch) in s.char_indices() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' => {
                depth += 1;
                opened_block = true;
            }
            '}' => {
                depth -= 1;
                if depth <= 0 && opened_block {
                    return idx + ch.len_utf8();
                }
            }
            ';' if depth <= 0 => return idx + ch.len_utf8(),
            _ => {}
        }
    }
    s.len()
}

/// The production slice of a source file: everything except the items gated
/// behind `#[cfg(test)]`, with comments and literal contents blanked.
///
/// # Why this is not "everything before the first `#[cfg(test)]`"
///
/// It used to be, and that made both scanners below near-blind. The dominant
/// idiom in this tree is `#[cfg(test)] mod tests;` declared at the *top* of a
/// file, right under the imports — so truncating there discarded the entire
/// production body. Measured at the time of the fix: 2661 of 2724 lines unseen
/// in `core/engine/mod.rs`, 521 of 564 in `modules/opencorporates/mod.rs`. A
/// ratchet that reports PASS over the first thirty lines of a file certifies an
/// invariant it never checked, which is worse than having no ratchet.
///
/// Test code is still excluded, just correctly: each `#[cfg(test)]` item is
/// skipped by [`cfg_test_item_len`] and scanning resumes after it. Dedicated
/// `tests.rs` / `*_tests.rs` files are skipped whole by their callers.
///
/// Doc examples survive as text but their string and comment content is blanked,
/// which is deliberate — a `///` example is an illustrative fixture, and a
/// doctest cannot see the parent module's `use` statements, so naming a constant
/// there would not even compile.
fn production_source(content: &str) -> String {
    blank_strings_and_comments(&strip_cfg_test_items(content))
}

/// Byte ranges of every `#[cfg(test)]`-attributed item in `content`, attribute
/// included.
///
/// Boundaries are found on a [`blank_strings_and_comments`] copy so a brace or
/// semicolon inside a literal cannot move them — and because that copy preserves
/// **byte** length, the ranges it yields index the *original* text exactly. That
/// alignment is the whole reason [`strip_cfg_test_items`] can hand back real
/// source rather than blanked source.
fn cfg_test_item_ranges(content: &str) -> Vec<std::ops::Range<usize>> {
    const ATTR: &str = "#[cfg(test)]";
    let clean = blank_strings_and_comments(content);
    assert_eq!(
        clean.len(),
        content.len(),
        "blanking must preserve byte length or these ranges do not index the original"
    );
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = clean[from..].find(ATTR) {
        let at = from + rel;
        let body = at + ATTR.len();
        let end = body + cfg_test_item_len(&clean[body..]);
        out.push(at..end);
        from = end;
    }
    out
}

/// `content` with every `#[cfg(test)]` item removed and its newlines kept, so
/// the result stays line-aligned with the input.
///
/// Unlike [`production_source`], string and comment **content survives**. That
/// is not a detail: `correlation_rule_ids_match_their_function_number` reads the
/// rule id out of `rule_id: "AU-NNN".into()`, a string literal. Blanking it
/// would leave that invariant scanning empty quotes and passing vacuously — the
/// exact failure this whole cluster is about.
///
/// Use this when the scanner reads literals; use [`production_source`] when it
/// reads code, where blanking additionally stops a mention inside a comment from
/// satisfying (or violating) an invariant.
fn strip_cfg_test_items(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut prev = 0usize;
    for r in cfg_test_item_ranges(content) {
        out.push_str(&content[prev..r.start]);
        out.extend(content[r.start..r.end].chars().filter(|c| *c == '\n'));
        prev = r.end;
    }
    out.push_str(&content[prev..]);
    out
}

/// The scanners are only as trustworthy as the slicing they run on, so the
/// slicing is itself asserted. Each case below is a form that occurs in this
/// tree and that the previous truncate-at-first-`#[cfg(test)]` implementation
/// got wrong.
#[test]
fn production_source_keeps_production_and_drops_test_items() {
    let src = r#"
use std::fmt;

#[cfg(test)]
mod tests;

pub fn real() -> f64 { 0.68 }

#[cfg(test)]
mod tests2 {
    pub fn hidden() -> f64 { 0.11 }
}

pub fn also_real() -> f64 { 0.74 }

#[cfg(test)]
pub(super) const HELPER: [u8; 4] = [0; 4];

pub fn third() -> f64 { 0.42 }
"#;
    let out = production_source(src);
    for keep in [
        "pub fn real",
        "0.68",
        "pub fn also_real",
        "0.74",
        "third",
        "0.42",
    ] {
        assert!(
            out.contains(keep),
            "production code dropped: {keep}\n---\n{out}"
        );
    }
    for drop in ["mod tests;", "hidden", "0.11", "HELPER"] {
        assert!(
            !out.contains(drop),
            "test-gated code kept: {drop}\n---\n{out}"
        );
    }
    // The `;` inside `[u8; 4]` must not end the const early and leak `[0; 4]`.
    assert!(
        !out.contains("[0; 4]"),
        "bracketed `;` ended the item early:\n{out}"
    );
}

/// [`strip_cfg_test_items`] must keep production code that sits *below* a
/// top-of-file `#[cfg(test)] mod tests;` — the shape that made four scanners
/// near-blind — **and** must keep string-literal content, which
/// [`production_source`] deliberately destroys.
///
/// The literal half is not hypothetical: `correlation_rule_ids_match_their_
/// function_number` reads the rule id out of `rule_id: "AU-NNN".into()`. Route
/// that scanner through the blanking variant and it scans empty quotes and
/// passes vacuously, which is a worse failure than the truncation it replaced.
#[test]
fn strip_cfg_test_items_keeps_literals_and_code_below_the_marker() {
    const SRC: &str = r#"
use std::fmt;

#[cfg(test)]
mod tests;

pub fn rule_au_042_example() -> Correlation {
    Correlation::new("AU-042", "an example rule")
}

#[cfg(test)]
mod inline_tests {
    fn helper() -> &'static str { "AU-999" }
}

pub fn rule_au_043_second() -> Correlation {
    Correlation::new("AU-043", "a second rule")
}
"#;
    let out = strip_cfg_test_items(SRC);

    // Production code below the top-of-file marker survives — the whole point.
    for keep in [
        "rule_au_042_example",
        "rule_au_043_second",
        "\"AU-042\"",
        "\"AU-043\"",
        "an example rule",
    ] {
        assert!(
            out.contains(keep),
            "dropped from production: {keep}\n---\n{out}"
        );
    }
    // Test-gated code goes, including the id that would forge a duplicate.
    for drop in ["mod tests;", "inline_tests", "helper", "AU-999"] {
        assert!(
            !out.contains(drop),
            "kept test-gated code: {drop}\n---\n{out}"
        );
    }
    // Contrast: the blanking variant would empty exactly the literals the rule-id
    // scanner reads. This pins WHY the two helpers are separate.
    let blanked = production_source(SRC);
    assert!(
        blanked.contains("rule_au_042_example"),
        "code identifiers must survive blanking"
    );
    assert!(
        !blanked.contains("\"AU-042\""),
        "production_source is supposed to blank literal content; if it no longer \
         does, strip_cfg_test_items has no reason to exist separately"
    );
    assert_eq!(
        out.lines().count(),
        SRC.lines().count(),
        "line structure was not preserved"
    );
}

/// A brace, quote or semicolon inside a literal or a comment is not a
/// delimiter. If this slips, every item boundary after it shifts.
///
/// The non-ASCII rows are load-bearing, not decoration: blanking a 3-byte `…` to
/// a single space would preserve the character count while silently shifting
/// every *byte* offset after it, which is the alignment the doc promises and
/// that a future caller mapping a finding back to a source position would rely
/// on. This tree's comments are full of `—` and `…`, so it is the common case.
#[test]
fn lexical_blanking_neutralises_delimiters_in_literals_and_comments() {
    const SRC: &str = r####"
let a = "a } brace ; and \" quote";
let b = r#"raw " with }"#;
let c = '}';
let d: &'static str = "x";
// comment with } and ; — plus an em dash and an ellipsis …
/* nested /* block } */ still comment ; — and another … */
let e = "unicode } inside a string: αβγ — …";
let real = 0.68;
"####;
    let out = blank_strings_and_comments(SRC);

    assert_eq!(out.matches('}').count(), 0, "a delimiter survived:\n{out}");
    assert!(out.contains("0.68"), "real code was blanked:\n{out}");
    assert!(
        out.contains("'static"),
        "lifetime was eaten as a char literal:\n{out}"
    );
    assert_eq!(
        out.lines().count(),
        SRC.lines().count(),
        "line structure was not preserved"
    );
    assert_eq!(
        out.len(),
        SRC.len(),
        "byte length was not preserved, so byte offsets no longer map back to \
         the source — a multi-byte char was blanked to fewer bytes"
    );
}

/// Collect every production `Entity::new` call whose confidence argument is a
/// bare float literal, as `(repo-relative path, literal)`.
fn collect_bare_confidence(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_bare_confidence(&path, root, out);
            continue;
        }
        // `tests.rs` and every `*_tests.rs` are dedicated test-code files,
        // `mod`/`include!`d under a `#[cfg(test)]` at their declaration site, so
        // the gating marker is never inside the file itself for the scanner to
        // see. Skip them whole — test fixtures are deliberately allowed to use
        // bare literals (a threshold assertion that moves when a constant moves
        // is a weaker test). A `tests/` directory component catches the same
        // test code when `tests.rs` splits its content into `tests/partNN.rs`
        // fragments via `include!` (done purely to keep each file small enough
        // for reliable transmission through this repo's push tooling).
        if path
            .file_name()
            .is_some_and(|n| n == "tests.rs" || n.to_string_lossy().ends_with("_tests.rs"))
            || path.components().any(|c| c.as_os_str() == "tests")
            || path.extension().is_none_or(|e| e != "rs")
        {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let src = production_source(&fs::read_to_string(&path).unwrap());
        for (idx, _) in src.match_indices("Entity::new") {
            // Word boundary: don't match a longer identifier ending in this.
            if src[..idx]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            let rest = &src[idx + "Entity::new".len()..];
            let Some(open) = rest.find('(') else { continue };
            if !rest[..open].trim().is_empty() {
                continue;
            }
            let Some(args) = call_args(&rest[open..]) else {
                continue;
            };
            // Entity::new(kind, value, confidence, scan_id)
            if args.len() >= 3 {
                for lit in bare_float_literals(&args[2]) {
                    out.push((rel.clone(), lit));
                }
            }
        }
    }
}

/// Every production `Entity::new` confidence argument must be a named constant
/// from [`huntsman_search_engine::core::confidence`], never a bare float.
///
/// The ladder exists so confidence is comparable across ~140 independently
/// written modules; a bare literal is an unauditable magic number that defeats
/// that. `src/core` is fully normalised and must stay that way.
///
/// The baseline below is the frozen inventory of sites that still carry an
/// unnormalised value. Most sit 0.01–0.03 off an existing rung (0.66 vs `HIGH`
/// 0.65, 0.68 vs `HIGH_PLUS` 0.70, 0.74 vs `VERY_HIGH` 0.75, 0.42 vs `LOW` 0.40,
/// 0.38/0.28 between rungs) — uncoordinated drift between modules rather than
/// deliberately designed tiers.
///
/// Every value that landed *exactly* on a rung has now been named — the four
/// `0.55`/`0.70` rows in `oathnet_pro::breach` and `see_know::extract` were pure
/// renames (`MEDIUM_HIGH` is 0.55, `HIGH_PLUS` is 0.70), so they cost nothing
/// and the inventory shrank rather than grew. What remains cannot be normalised
/// without changing an emitted confidence, which is a behavioural decision
/// needing its own evidence, not a cleanup.
///
/// This is a ratchet, asserted as multiset equality:
///   * a NEW bare literal fails the test — drift cannot grow;
///   * normalising one also fails, asking you to delete its baseline row — so
///     the inventory can only shrink, and never silently misreports.
///
/// The inventory is only as good as [`production_source`]'s slicing, which was
/// truncating most files at their first `#[cfg(test)]` and hiding 18 of the 32
/// occurrences now listed. That is fixed and asserted separately by
/// `production_source_keeps_production_and_drops_test_items`; a ratchet whose
/// scanner is untested measures whatever it happens to reach.
#[test]
fn entity_confidence_uses_named_ladder_constants() {
    /// Frozen drift inventory. Line-number free so unrelated edits above a site
    /// don't churn it. Shrink this list; never extend it.
    ///
    /// The 18 occurrences below marked `[revealed]` are **not new drift**. They
    /// pre-date this inventory and were invisible until `production_source` was
    /// fixed to skip `#[cfg(test)]` *items* rather than truncate the file at the
    /// first one — see that function's docs. Every one of them was already in the
    /// tree when the shorter baseline was frozen; the scanner simply never
    /// reached them. Recording them is the correction, not a regression.
    const BASELINE: &[(&str, &str)] = &[
        ("src/modules/au_people/mod.rs", "0.42"), // [revealed]
        ("src/modules/codewars_user/mod.rs", "0.48"), // [revealed]
        ("src/modules/cpan_user/mod.rs", "0.66"), // [revealed]
        ("src/modules/crates_io/mod.rs", "0.66"),
        ("src/modules/crates_io/mod.rs", "0.74"),
        ("src/modules/epieos/mod.rs", "0.42"), // [revealed]
        ("src/modules/epieos/mod.rs", "0.42"), // [revealed]
        ("src/modules/fediverse/mod.rs", "0.68"),
        ("src/modules/mastodon_user/mod.rs", "0.28"),
        ("src/modules/mastodon_user/mod.rs", "0.38"),
        ("src/modules/nostr/mod.rs", "0.66"),
        ("src/modules/npm_author/mod.rs", "0.66"),
        ("src/modules/npm_author/mod.rs", "0.74"),
        // ── [embedded] ───────────────────────────────────────────────────
        // Literals inside a compound confidence argument, invisible until
        // `bare_float_literals` replaced the whole-argument test. Like the
        // `[revealed]` rows they pre-date this inventory; unlike them they are
        // DELIBERATE, and `derived_confidence_goes_through_the_shared_step`
        // records the same families with the reasons in full:
        //
        //   * `phone_geo` steps by 0.08, not the shared 0.10 — a country
        //     centroid from a dialling prefix is a different inference.
        //   * `steam_profile` runs a graded family (0.05 … 0.33) with per-kind
        //     floors, ranking eight kinds of profile-derived signal against one
        //     another. Its location/coordinates floors (formerly bare `.max(0.42)`
        //     literals here) now flow through the shared `profile_kit::
        //     location_address` / `location_coordinates` helpers instead — the
        //     `0.27` / `0.33` steps are passed to THEM as a confidence argument,
        //     not embedded in a bare `Entity::new` call of this file's own, so
        //     they no longer trip this ratchet (see
        //     `derived_confidence_goes_through_the_shared_step`'s baseline for
        //     why the steps themselves stay deliberately non-uniform). Its
        //     Domain floor (`.max(0.38)`) is the one row left that genuinely
        //     should be named — its other floors already are
        //     (`.max(confidence::LOW_MEDIUM)`), which makes this one
        //     inconsistent rather than principled.
        //
        // The two ratchets deliberately overlap here: one asks whether the
        // derivation STEP is hand-rolled, this one asks whether a bare float
        // sits in an `Entity::new` confidence argument. The `0.25` in
        // `(conf - 0.25).max(0.38)` is honestly both.
        ("src/modules/phone_geo/mod.rs", "0.08"), // [embedded]
        ("src/modules/sourceforge_user/mod.rs", "0.79"), // [revealed]
        ("src/modules/steam_profile/mod.rs", "0.05"), // [embedded]
        ("src/modules/steam_profile/mod.rs", "0.13"), // [embedded]
        ("src/modules/steam_profile/mod.rs", "0.15"), // [embedded]
        ("src/modules/steam_profile/mod.rs", "0.20"), // [embedded]
        ("src/modules/steam_profile/mod.rs", "0.25"), // [embedded]
        ("src/modules/steam_profile/mod.rs", "0.38"), // [embedded] hardcoded floor
        ("src/modules/whois/mod.rs", "0.68"),     // [revealed]
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    collect_bare_confidence(&root.join("src"), root, &mut found);
    found.sort();

    let mut expected: Vec<(String, String)> = BASELINE
        .iter()
        .map(|(p, v)| ((*p).to_string(), (*v).to_string()))
        .collect();
    expected.sort();

    // Compare as MULTISETS, not sets. `Vec::contains` tests membership only, so
    // where a file carries the SAME bare literal at two sites (a duplicate
    // baseline row), a third identical literal in that file would still be
    // "contained" and slip through, and normalising one of a duplicate pair
    // would leave the stale row undetected. Counting occurrences is what
    // actually enforces the ratchet.
    let tally = |rows: &[(String, String)]| {
        let mut m: std::collections::BTreeMap<(String, String), usize> =
            std::collections::BTreeMap::new();
        for r in rows {
            *m.entry(r.clone()).or_default() += 1;
        }
        m
    };
    let found_counts = tally(&found);
    let expected_counts = tally(&expected);

    // Occurrences present more often than the baseline allows.
    let added: Vec<String> = found_counts
        .iter()
        .filter_map(|(k, n)| {
            let allowed = expected_counts.get(k).copied().unwrap_or(0);
            (*n > allowed).then(|| format!("{} `{}` x{} (baseline allows {allowed})", k.0, k.1, n))
        })
        .collect();
    // Baseline rows that no longer occur that many times.
    let fixed: Vec<String> = expected_counts
        .iter()
        .filter_map(|(k, n)| {
            let actual = found_counts.get(k).copied().unwrap_or(0);
            (*n > actual).then(|| format!("{} `{}` x{} (now only {actual})", k.0, k.1, n))
        })
        .collect();

    assert!(
        added.is_empty(),
        "new bare confidence literal(s) in production Entity::new — use a \
         named `confidence::` constant instead of a magic number:\n{added:#?}"
    );
    assert!(
        fixed.is_empty(),
        "these baseline entries no longer exist (nice — you normalised them). \
         Delete them from BASELINE so the inventory stays truthful:\n{fixed:#?}"
    );

    // core must remain fully normalised.
    assert!(
        !found.iter().any(|(p, _)| p.starts_with("src/core/")),
        "src/core must contain no bare confidence literals; found: {:#?}",
        found
            .iter()
            .filter(|(p, _)| p.starts_with("src/core/"))
            .collect::<Vec<_>>()
    );
}

/// The final path segment of the left operand of a `- 0.NN`, if that operand is
/// a simple identifier path. `geo.confidence` → `confidence`;
/// `addr.confidence()` → `confidence`; `conf` → `conf`.
///
/// Returns `None` when the operand is not an identifier — a numeric literal, an
/// opening delimiter, a closing brace — which is how a *negative literal*
/// (`(-0.0236, 37.9062)`, a latitude) is told apart from a *subtraction*.
fn subtraction_lhs_segment(before: &str) -> Option<String> {
    let mut s = before.trim_end();
    // `addr.confidence()` — step back over an empty call's parens so the
    // accessor form is read the same as the field form.
    if let Some(t) = s.strip_suffix("()") {
        s = t.trim_end();
    }
    let mut seg: Vec<char> = s
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    seg.reverse();
    // A leading digit means we walked back into a number, not an identifier.
    let starts_with_digit = seg.first().is_some_and(char::is_ascii_digit);
    (!seg.is_empty() && !starts_with_digit).then(|| seg.into_iter().collect())
}

/// Collect every production site that subtracts a bare float from a
/// confidence-valued expression, as `(repo-relative path, literal)`.
///
/// "Confidence-valued" is decided syntactically: the left operand's final path
/// segment contains `conf`. That matches the vocabulary actually in use
/// (`x.confidence`, `x.confidence()`, `conf`, `base_conf`, `coord_conf`) and
/// deliberately does not match unrelated arithmetic such as
/// `device_fix.rs`'s `ceiling - 0.05`, which clamps a ceiling rather than
/// deriving a finding from a parent.
fn collect_hand_rolled_derivations(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_hand_rolled_derivations(&path, root, out);
            continue;
        }
        // Same test-file exclusions as the bare-literal scan above (including
        // the `tests/` directory-component case — see its comment): a test
        // that asserts `(e.confidence - 0.72).abs() < 1e-9` is comparing, not
        // deriving, and freezing those would make every threshold assertion in
        // the tree a ratchet entry.
        if path
            .file_name()
            .is_some_and(|n| n == "tests.rs" || n.to_string_lossy().ends_with("_tests.rs"))
            || path.components().any(|c| c.as_os_str() == "tests")
            || path.extension().is_none_or(|e| e != "rs")
        {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let src = production_source(&fs::read_to_string(&path).unwrap());
        for (idx, _) in src.match_indices('-') {
            // `->`, `-=` and `--` fail this immediately; so does `- x`.
            let rhs = src[idx + 1..].trim_start();
            if !rhs.starts_with("0.") {
                continue;
            }
            let Some(seg) = subtraction_lhs_segment(&src[..idx]) else {
                continue;
            };
            if !seg.to_ascii_lowercase().contains("conf") {
                continue;
            }
            let lit: String = rhs
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            out.push((rel.clone(), lit));
        }
    }
}

/// Deriving a finding from a parent finding is [`confidence::derived_from`]'s
/// job, not each module's.
///
/// Eleven production sites independently wrote `parent - 0.10`. Four floored the
/// result at `0.10` and seven did not, so a weak parent produced a finding at
/// `ZERO` — the one rung the ladder documents as *never emitted*. Half the tree
/// guarded that and half did not, and nothing made the difference visible. That
/// is the drift this ratchet exists to stop: the arithmetic now has one owner,
/// and a twelfth site cannot quietly re-introduce a twelfth variant.
///
/// The baseline is the frozen inventory of sites that keep their own arithmetic
/// **on purpose**, because folding them into `derived_from` would erase
/// information rather than share it:
///
///   * `phone_geo` steps by `0.08`, not `0.10` — a country-centroid coordinate
///     from a dialling prefix is a different inference from an address-derived
///     one, and the step encodes that.
///   * `steam_profile` runs a *graded* family — `0.05`, `0.13`, `0.15`, `0.20`
///     (twice), `0.25`, `0.27`, `0.33` — each with its own floor, ranking eight
///     kinds of profile-derived signal against one another. One shared step
///     would flatten that ranking to nothing.
///
/// Shrink this list only by making a site's step genuinely uniform; never
/// extend it. A new entry means someone wrote the twelfth variant.
#[test]
fn derived_confidence_goes_through_the_shared_step() {
    /// Frozen inventory of deliberate non-uniform steps. Line-number free so
    /// unrelated edits above a site don't churn it.
    const BASELINE: &[(&str, &str)] = &[
        ("src/modules/phone_geo/mod.rs", "0.08"),
        ("src/modules/steam_profile/mod.rs", "0.05"),
        ("src/modules/steam_profile/mod.rs", "0.13"),
        ("src/modules/steam_profile/mod.rs", "0.15"),
        ("src/modules/steam_profile/mod.rs", "0.20"),
        ("src/modules/steam_profile/mod.rs", "0.20"),
        ("src/modules/steam_profile/mod.rs", "0.25"),
        ("src/modules/steam_profile/mod.rs", "0.27"),
        ("src/modules/steam_profile/mod.rs", "0.33"),
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    collect_hand_rolled_derivations(&root.join("src"), root, &mut found);

    // Multiset, not set: `steam_profile` carries `0.20` at two distinct sites,
    // so membership testing would let a third `0.20` through and would not
    // notice if one of the pair were removed. Counting occurrences is what
    // actually enforces the ratchet.
    let tally = |rows: &[(String, String)]| {
        let mut m: std::collections::BTreeMap<(String, String), usize> =
            std::collections::BTreeMap::new();
        for r in rows {
            *m.entry(r.clone()).or_default() += 1;
        }
        m
    };
    let found_counts = tally(&found);
    let expected_counts = tally(
        &BASELINE
            .iter()
            .map(|(p, v)| ((*p).to_string(), (*v).to_string()))
            .collect::<Vec<_>>(),
    );

    let added: Vec<String> = found_counts
        .iter()
        .filter_map(|(k, n)| {
            let allowed = expected_counts.get(k).copied().unwrap_or(0);
            (*n > allowed)
                .then(|| format!("{} `- {}` x{} (baseline allows {allowed})", k.0, k.1, n))
        })
        .collect();
    let fixed: Vec<String> = expected_counts
        .iter()
        .filter_map(|(k, n)| {
            let actual = found_counts.get(k).copied().unwrap_or(0);
            (*n > actual).then(|| format!("{} `- {}` x{} (now only {actual})", k.0, k.1, n))
        })
        .collect();

    assert!(
        added.is_empty(),
        "hand-rolled confidence derivation(s) — call \
         `huntsman_search_engine::core::confidence::derived_from(parent)` instead of \
         subtracting a step by hand, so the floor that keeps a derived finding off \
         `ZERO` applies everywhere:\n{added:#?}\n\
         If the step is genuinely non-uniform (see `steam_profile`), add it to \
         BASELINE with the reason it differs."
    );
    assert!(
        fixed.is_empty(),
        "these baseline entries no longer exist (nice — you normalised them). \
         Delete them from BASELINE so the inventory stays truthful:\n{fixed:#?}"
    );
}
