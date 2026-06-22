//! Invisible-Unicode stripping and homograph/confusable detection for the
//! seed/target ingestion boundary.
//!
//! Two distinct, dependency-free defences live here. Both are pure and
//! deterministic, take a curated stance (no `unicode-*` crate, no embedded
//! Unicode database), and exist to fix concrete OSINT data-quality defects:
//!
//! 1. **Invisible / format-character stripping** ([`strip_invisible`]). Several
//!    codepoints render as *nothing* (or as a zero-width artefact) yet change a
//!    string's bytes, so two seeds a human reads as identical never deduplicate.
//!    We remove the ones that have no legitimate place in a seed value:
//!      * U+200B/200C/200D zero-width space / non-joiner / joiner and U+FEFF
//!        zero-width no-break space (BOM) — pure-invisible, used to pad a value
//!        so it dodges an exact-match dedup;
//!      * U+202A..=U+202E bidirectional embeddings/overrides and U+2066..=U+2069
//!        the directional isolates — reorder display without changing logical
//!        order, the classic "Trojan Source" spoofing vector;
//!      * U+00AD soft hyphen — a conditional hyphen that renders only at a line
//!        break, invisible inline;
//!      * U+2060 word joiner — a zero-width no-break with no visible glyph.
//!
//! 2. **Confusable skeleton + mixed-script homograph detection**
//!    ([`skeleton`], [`is_confusable_mixed_script`]). A Cyrillic-`а`
//!    `pаypal.com` looks identical to ASCII `paypal.com` but is a different
//!    entity, so it is silently treated as a distinct, legitimate target. We map
//!    a **curated** subset of the most-abused single-codepoint Latin-lookalikes
//!    to their ASCII skeleton and flag a value that *mixes* real ASCII letters
//!    with these foreign-script lookalikes — the deceptive signature. This is an
//!    intentionally small, hand-picked table (a few dozen entries), NOT the full
//!    Unicode TR39 confusables data.

use std::borrow::Cow;

use crate::core::validation::ValidationReport;

/// True for a codepoint that is invisible / a formatting control with no
/// legitimate place in a seed value (see the module docs for why each is
/// stripped). Kept as a single predicate so [`strip_invisible`] can test it
/// without allocating.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'           // zero-width space
        | '\u{200C}'         // zero-width non-joiner
        | '\u{200D}'         // zero-width joiner
        | '\u{FEFF}'         // zero-width no-break space (BOM)
        | '\u{00AD}'         // soft hyphen
        | '\u{2060}'         // word joiner
        | '\u{202A}'..='\u{202E}' // bidi embeddings + overrides (LRE..RLO)
        | '\u{2066}'..='\u{2069}' // bidi isolates (LRI..PDI)
    )
}

/// Remove invisible / format characters that have no place in a seed value and
/// that defeat deduplication (zero-width space/joiner/non-joiner/no-break, the
/// bidirectional formatting/override controls and isolates, the soft hyphen,
/// and the word joiner — see the module docs).
///
/// Returns [`Cow::Borrowed`] unchanged when nothing is stripped — the hot path
/// for the overwhelmingly-common clean input, so a clean seed never allocates.
pub fn strip_invisible(s: &str) -> Cow<'_, str> {
    if s.chars().any(is_invisible_format) {
        Cow::Owned(s.chars().filter(|c| !is_invisible_format(*c)).collect())
    } else {
        Cow::Borrowed(s)
    }
}

/// Map a single codepoint to its ASCII Latin skeleton character if it is one of
/// the curated, most-abused Latin-lookalikes; otherwise return it unchanged.
///
/// Covers Cyrillic and Greek letters that share a glyph with ASCII Latin, plus
/// the full-width ASCII block (U+FF01..=U+FF5E) which maps mechanically to its
/// ASCII equivalent. Intentionally curated — not full TR39.
fn skeleton_char(c: char) -> char {
    // Full-width ASCII variants (U+FF01 '！' .. U+FF5E '～') are a fixed +0xFEE0
    // offset from their ASCII counterpart; fold them back mechanically.
    if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        // Safe: the resulting scalar is in 0x21..=0x7E, a valid ASCII char.
        if let Some(ascii) = char::from_u32(c as u32 - 0xFEE0) {
            return ascii;
        }
    }
    match c {
        // Cyrillic letters that share an ASCII Latin glyph.
        'а' => 'a',
        'е' | 'ё' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        'к' => 'k',
        'м' => 'm',
        'т' => 't',
        'н' => 'h',
        'в' => 'b',
        'і' => 'i', // Cyrillic/Ukrainian dotted i
        'ѕ' => 's', // Cyrillic dze
        'ј' => 'j', // Cyrillic je
        'ԁ' => 'd', // Cyrillic komi de
        'г' => 'r',
        'п' => 'n',
        // Greek letters that share an ASCII Latin glyph.
        'ο' => 'o',
        'α' => 'a',
        'ν' => 'v',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'κ' => 'k',
        'ι' => 'i',
        'χ' => 'x',
        'ϲ' => 'c', // Greek lunate sigma
        // High-value digit / letter lookalikes from other blocks.
        'ѵ' => 'v', // Cyrillic izhitsa
        'ɑ' => 'a', // Latin alpha
        'ɡ' => 'g', // Latin script g
        'ⅰ' => 'i', // Roman numeral one
        'ⅼ' => 'l', // Roman numeral fifty
        'ⅾ' => 'd', // Roman numeral five-hundred
        'ӏ' => 'l', // Cyrillic palochka (lowercase)
        _ => c,
    }
}

/// Map a value to its ASCII Latin **skeleton**: each curated single-codepoint
/// confusable is folded to its ASCII equivalent and the result is lowercased,
/// so two values that differ only by a Latin-lookalike share one skeleton.
///
/// Intentionally a curated subset of the well-known Latin-lookalikes (Cyrillic,
/// Greek, full-width ASCII, and a handful of cross-block letter/digit
/// lookalikes), NOT the full Unicode TR39 confusables data.
pub fn skeleton(s: &str) -> String {
    s.chars()
        .map(skeleton_char)
        .collect::<String>()
        .to_lowercase()
}

/// True when `value` mixes genuine ASCII Latin letters with ASCII-lookalike
/// foreign-script letters — the classic homograph-spoof signature (e.g. a
/// `paypal.com` whose `a` is Cyrillic `а`).
///
/// Precisely: true iff `value` contains at least one non-ASCII letter that the
/// [`skeleton`] map collapses to an ASCII Latin letter AND `value` also contains
/// at least one genuine ASCII Latin letter. A purely non-Latin string (e.g. a
/// legitimate all-Cyrillic value, which has no ASCII letters) is NOT flagged —
/// only the deceptive mix is.
pub fn is_confusable_mixed_script(value: &str) -> bool {
    let mut has_ascii_latin = false;
    let mut has_confusable_foreign = false;
    for c in value.chars() {
        if c.is_ascii_alphabetic() {
            has_ascii_latin = true;
        } else if !c.is_ascii() {
            // A non-ASCII letter that the skeleton folds to an ASCII Latin
            // letter is an ASCII-lookalike — the spoofing half of the mix.
            let folded = skeleton_char(c);
            if folded.is_ascii_alphabetic() && folded != c {
                has_confusable_foreign = true;
            }
        }
        if has_ascii_latin && has_confusable_foreign {
            return true;
        }
    }
    false
}

/// Validation report for a seed value's mixed-script homograph status: fails
/// with reason `seed.confusable` when [`is_confusable_mixed_script`] holds
/// (the detail names the ASCII skeleton), otherwise
/// [`ValidationReport::ok`](crate::core::validation::ValidationReport::ok).
pub fn confusable_report(value: &str) -> ValidationReport {
    if is_confusable_mixed_script(value) {
        ValidationReport::fail(
            "seed.confusable",
            format!(
                "mixed-script homograph; ascii skeleton: {}",
                skeleton(value)
            ),
        )
    } else {
        ValidationReport::ok()
    }
}

/// True when a `Person` value looks like a **random/gibberish string** rather
/// than a real name — the `ZonJZRJHHWD GvkJCJRWHWD`-style junk that breach
/// co-occurrence dumps mint as "names".
///
/// **Deliberately conservative** — silently dropping a real (unusual) name is
/// worse than admitting a low-confidence candidate, so the bar is set where no
/// natural-language name reaches it. A whitespace-separated token is gibberish
/// only when its alphabetic core is ≥ 6 letters AND either:
///   * it contains **no** vowel-like character at all (every letter is an ASCII
///     consonant — `GvkJCJRWHWD`), or
///   * it contains a run of **6+ consecutive** ASCII consonants (`ZonJZRJHHWD`).
///
/// A "vowel-like" char is an ASCII vowel (incl. `y`) **or any non-ASCII letter**:
/// treating accented characters as run-breaking keeps real names safe (`Müller`,
/// `Nguyễn`), and even the consonant-densest Slavic names (`Vrkljan` → max run 5)
/// stay under the 6 bar. Pure/offline.
#[must_use]
pub fn looks_like_gibberish_name(value: &str) -> bool {
    // A char that interrupts a consonant run: an ASCII vowel (incl. `y`) or any
    // non-ASCII letter (an accented vowel/consonant we don't want to misjudge).
    fn breaks_run(c: char) -> bool {
        !c.is_ascii() || matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y')
    }
    value.split_whitespace().any(|token| {
        let letters: Vec<char> = token.chars().filter(|c| c.is_alphabetic()).collect();
        if letters.len() < 6 {
            return false;
        }
        let mut run = 0usize;
        let mut max_run = 0usize;
        let mut any_break = false;
        for &c in &letters {
            if breaks_run(c) {
                any_break = true;
                run = 0;
            } else {
                run += 1;
                max_run = max_run.max(run);
            }
        }
        // No vowel-like char anywhere (all ASCII consonants), or a 6+ run.
        !any_break || max_run >= 6
    })
}
