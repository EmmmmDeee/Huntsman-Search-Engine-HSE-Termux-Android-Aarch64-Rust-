//! Pure, offline look-alike (typosquat / homoglyph) comparison for domain
//! labels — no I/O, no deps, no Unicode tables beyond a curated ASCII/leet
//! confusable fold.
//!
//! This answers a single question: *do two domain labels look like each other to
//! a human?* — the pairwise comparison a brand-impersonation / phishing check
//! needs. It is deliberately NOT the `typosquat` module's job, which is the
//! inverse: *generate* the permutations of one seed to probe. Generation and
//! pairwise comparison are different algorithms, so this is a separate,
//! self-contained primitive rather than a reuse of that module (which `core`
//! cannot import anyway).
//!
//! Two signals, both high-precision:
//!   * **homoglyph skeleton** — fold the classic typosquat confusables
//!     (`0→o`, `1→l`, `5→s`, `rn→m`, `vv→w`, …) to a canonical form; two labels
//!     with the same skeleton are visually confusable (`paypa1`≈`paypal`,
//!     `g00gle`≈`google`, `arnazon`≈`amazon`);
//!   * **edit distance 1** — a single insertion / deletion / substitution
//!     (`microsoft`≈`microsofts`, `example`≈`exemple`).
//!
//! Both gate on a minimum label length so short labels (where almost everything
//! is one edit apart) never manufacture noise.

/// The shortest label this primitive will compare. Below this, single-edit and
/// skeleton collisions are too common to be meaningful.
const MIN_LABEL_LEN: usize = 4;

/// Fold a label to its homoglyph **skeleton**: lowercase, with the classic
/// typosquat confusables collapsed to one canonical glyph. Two labels that a
/// human could confuse at a glance share a skeleton. Pure and allocation-light.
#[must_use]
pub fn homoglyph_skeleton(label: &str) -> String {
    // Multi-character confusables first (they change length), then per-char.
    let lowered = label.to_ascii_lowercase();
    let collapsed = lowered.replace("rn", "m").replace("vv", "w");
    collapsed
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '|' => 'l',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

/// Levenshtein edit distance between two byte strings. Standard two-row dynamic
/// program — O(a·b) time, O(min(a,b)) space, no allocation beyond one row. Pure.
#[must_use]
pub fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// True if two domain labels are visual/typo look-alikes: distinct, both at
/// least [`MIN_LABEL_LEN`] long, and either sharing a homoglyph skeleton or
/// within a single edit. Case-insensitive. Identical labels return `false` —
/// this detects impersonation *between distinct* labels, not equality.
#[must_use]
pub fn is_lookalike(a: &str, b: &str) -> bool {
    let a = a.to_ascii_lowercase();
    let b = b.to_ascii_lowercase();
    if a == b || a.len() < MIN_LABEL_LEN || b.len() < MIN_LABEL_LEN {
        return false;
    }
    if homoglyph_skeleton(&a) == homoglyph_skeleton(&b) {
        return true;
    }
    levenshtein(&a, &b) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homoglyph_skeleton_folds_classic_confusables() {
        assert_eq!(homoglyph_skeleton("paypa1"), homoglyph_skeleton("paypal"));
        assert_eq!(homoglyph_skeleton("g00gle"), homoglyph_skeleton("google"));
        assert_eq!(homoglyph_skeleton("arnazon"), homoglyph_skeleton("amazon"));
        assert_eq!(
            homoglyph_skeleton("micros0ft"),
            homoglyph_skeleton("microsoft")
        );
    }

    #[test]
    fn levenshtein_is_standard() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("microsoft", "microsofts"), 1);
        assert_eq!(levenshtein("example", "exemple"), 1);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn is_lookalike_flags_homoglyph_and_single_edit() {
        assert!(is_lookalike("paypa1", "paypal")); // homoglyph
        assert!(is_lookalike("g00gle", "google")); // homoglyph
        assert!(is_lookalike("arnazon", "amazon")); // rn→m homoglyph
        assert!(is_lookalike("microsoft", "microsofts")); // 1 insertion
        assert!(is_lookalike("example", "exemple")); // 1 substitution
    }

    #[test]
    fn is_lookalike_rejects_identical_short_and_unrelated() {
        assert!(
            !is_lookalike("google", "google"),
            "identical is not impersonation"
        );
        assert!(!is_lookalike("abc", "abd"), "short labels are too noisy");
        assert!(!is_lookalike("google", "facebook"), "unrelated labels");
        // Two-edit typosquats are out of scope here (kept precise on purpose).
        assert!(!is_lookalike("google", "gooogel"));
    }
}
