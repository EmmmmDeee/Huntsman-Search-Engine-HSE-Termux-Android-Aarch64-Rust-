//! Offline, table-driven romanization of non-Latin name tokens.
//!
//! The permutation engine derives usernames/emails by ASCII-folding each name
//! token ([`crate::util::str_util::fold_ascii_lower`]). That fold has no mapping
//! for non-Latin scripts, so a Cyrillic or Greek name folded to the **empty**
//! string and produced **zero** handles — most of the world's population got no
//! derived identifiers at all (proven by real-execution measurement: Cyrillic
//! and Greek seeds emitted 0 usernames / 0 emails while Latin seeds emitted
//! 19 / 20).
//!
//! This module closes that gap. It romanizes a token into an **ordered set of
//! Latin variants** — the first is the primary (most common web form), the rest
//! are real alternate conventions people actually register handles under:
//!
//!   * **Cyrillic** (Russian + Ukrainian coverage) under two internally-
//!     consistent schemes — a BGN/PCGN-style web form (`х→kh`, `я→ya`, `щ→shch`,
//!     Russian `г→g`) and a passport/simple form (`х→h`, `я→ia`, `щ→sch`,
//!     Ukrainian `г→h`). Real seeds validate: `Шарапова→sharapova`,
//!     `Путин→putin`, `Навальный→navalny`.
//!   * **Greek** under a modern web form (`β→v`, `η→i`, `χ→ch`) and a classical
//!     form (`β→b`, `η→e`, `χ→kh`), with the `ου→ou` digraph handled so
//!     `Παπαδόπουλος→papadopoulos` and `Τσίπρας→tsipras`.
//!   * **Latin diacritics** — the primary stays the plain fold (`Müller→muller`,
//!     preserving every existing assertion) and an *expansion* variant adds the
//!     equally-common German/Nordic convention (`Müller→mueller`, `ö→oe`,
//!     `ä→ae`, `å→aa`, `ø→oe`).
//!
//! Everything is pure Rust with no ICU/`deunicode`/C dependency — a single
//! static binary for Termux/aarch64. Whole-token schemes (not per-character
//! cross-products) keep each variant internally consistent, exactly as a real
//! romanization system emits, and bound the output.
//!
//! # Guarantees
//! - **Charset:** every returned string is pure `[a-z0-9]` — the invariant the
//!   permutation engine relies on for safe byte-slicing (enforced by a final
//!   fold and proved by tests).
//! - **Bounded:** at most [`MAX_VARIANTS`] entries per token.
//! - **Total & deterministic:** never panics; identical input ⇒ identical output.
//! - **Latin-preserving:** for a token whose primary romanization has no
//!   alternate, the sole entry equals [`fold_ascii_lower`] of the token, so the
//!   Latin code path is byte-for-byte unchanged.

use crate::util::str_util::fold_ascii_lower;

/// Maximum romanization variants returned per token — bounds the downstream
/// handle/email budget so a single name never floods the graph.
pub(super) const MAX_VARIANTS: usize = 3;

/// The dominant writing system of a token, by its letters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

/// Classify a token by the first strongly-scripted letter it contains. Latin
/// wins ties (a token with any Latin letter folds through the unchanged Latin
/// path); a token with no letter at all is `Other` (folds to empty).
fn detect_script(token: &str) -> Script {
    for ch in token.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' => return Script::Latin,
            // Latin-1 / Latin Extended accented letters keep the Latin path.
            '\u{00C0}'..='\u{024F}' => return Script::Latin,
            '\u{0400}'..='\u{04FF}' => return Script::Cyrillic,
            '\u{0370}'..='\u{03FF}' => return Script::Greek,
            _ => {}
        }
    }
    Script::Other
}

/// Romanize `token` into its ordered Latin variants (primary first), deduped,
/// non-empty, and capped at [`MAX_VARIANTS`]. Empty when nothing romanizes
/// (e.g. Han/Arabic, which have no letter-level offline mapping).
pub(super) fn romanize_variants(token: &str) -> Vec<String> {
    let raw = match detect_script(token) {
        Script::Latin | Script::Other => vec![fold_ascii_lower(token), fold_latin_expand(token)],
        Script::Cyrillic => {
            let lower = token.to_lowercase();
            vec![
                translit_cyrillic(&lower, Scheme::Primary),
                translit_cyrillic(&lower, Scheme::Alt),
            ]
        }
        Script::Greek => {
            let lower = token.to_lowercase();
            vec![
                translit_greek(&lower, Scheme::Primary),
                translit_greek(&lower, Scheme::Alt),
            ]
        }
    };

    let mut out: Vec<String> = Vec::with_capacity(MAX_VARIANTS);
    for v in raw {
        // Enforce the [a-z0-9] charset invariant the permutation engine relies
        // on: drop any stray byte a table entry might carry.
        let clean: String = v
            .chars()
            .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            .collect();
        if !clean.is_empty() && !out.contains(&clean) {
            out.push(clean);
            if out.len() == MAX_VARIANTS {
                break;
            }
        }
    }
    out
}

// ── Latin diacritic expansion ─────────────────────────────────────────────────

/// Like [`fold_ascii_lower`] but with the German/Nordic *expansion* convention:
/// `ä→ae`, `ö→oe`, `ü→ue`, `å→aa`, `ø→oe`. Every other character folds exactly as
/// [`fold_ascii_lower`] does, so a token with none of these letters returns the
/// same string (and is deduped away, leaving one variant).
fn fold_latin_expand(token: &str) -> String {
    let mut out = String::with_capacity(token.len() + 2);
    let mut buf = [0u8; 4];
    for ch in token.chars() {
        match ch {
            'ä' | 'Ä' => out.push_str("ae"),
            'ö' | 'Ö' => out.push_str("oe"),
            'ü' | 'Ü' => out.push_str("ue"),
            'å' | 'Å' => out.push_str("aa"),
            'ø' | 'Ø' => out.push_str("oe"),
            other => out.push_str(&fold_ascii_lower(other.encode_utf8(&mut buf))),
        }
    }
    out
}

// ── Transliteration schemes ────────────────────────────────────────────────────

/// Which internally-consistent romanization scheme to apply. Two schemes span
/// the conventions people actually register handles under.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// Common web / BGN-PCGN-style (Cyrillic) or modern (Greek).
    Primary,
    /// Passport/simple (Cyrillic) or classical (Greek).
    Alt,
}

/// Romanize a lowercased Cyrillic token under `scheme`. Digraph endings
/// `ий`/`ый` (`-y` web form / `-iy`/`-yy` strict) are handled before the
/// per-character pass; the hard/soft signs `ъ`/`ь` drop.
fn translit_cyrillic(lower: &str, scheme: Scheme) -> String {
    let chars: Vec<char> = lower.chars().collect();
    let mut out = String::with_capacity(chars.len() * 2);
    let mut i = 0;
    while i < chars.len() {
        // Common surname endings -ий / -ый: web form collapses to "-y"
        // (Dostoevsky, Navalny); the strict alt keeps "iy"/"yy".
        if i + 1 < chars.len() && chars[i + 1] == 'й' {
            match chars[i] {
                'и' => {
                    out.push_str(if scheme == Scheme::Primary { "y" } else { "iy" });
                    i += 2;
                    continue;
                }
                'ы' => {
                    out.push_str(if scheme == Scheme::Primary { "y" } else { "yy" });
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        let (p, a) = cyrillic_char(chars[i]);
        out.push_str(if scheme == Scheme::Primary { p } else { a });
        i += 1;
    }
    out
}

/// `(primary, alt)` romanization for one lowercase Cyrillic letter. Unlisted
/// characters (punctuation, digits handled elsewhere) map to `("","")`.
fn cyrillic_char(ch: char) -> (&'static str, &'static str) {
    match ch {
        'а' => ("a", "a"),
        'б' => ("b", "b"),
        'в' => ("v", "v"),
        'г' => ("g", "h"), // Russian g / Ukrainian h
        'ґ' => ("g", "g"), // Ukrainian hard g
        'д' => ("d", "d"),
        'е' => ("e", "e"),
        'ё' => ("yo", "e"),
        'є' => ("ye", "ie"), // Ukrainian
        'ж' => ("zh", "zh"),
        'з' => ("z", "z"),
        'и' => ("i", "i"),
        'і' => ("i", "i"),  // Ukrainian / Belarusian
        'ї' => ("yi", "i"), // Ukrainian
        'й' => ("y", "i"),
        'к' => ("k", "k"),
        'л' => ("l", "l"),
        'м' => ("m", "m"),
        'н' => ("n", "n"),
        'о' => ("o", "o"),
        'п' => ("p", "p"),
        'р' => ("r", "r"),
        'с' => ("s", "s"),
        'т' => ("t", "t"),
        'у' => ("u", "u"),
        'ф' => ("f", "f"),
        'х' => ("kh", "h"),
        'ц' => ("ts", "ts"),
        'ч' => ("ch", "ch"),
        'ш' => ("sh", "sh"),
        'щ' => ("shch", "sch"),
        'ъ' => ("", ""), // hard sign — dropped
        'ы' => ("y", "y"),
        'ь' => ("", ""), // soft sign — dropped
        'э' => ("e", "e"),
        'ю' => ("yu", "iu"),
        'я' => ("ya", "ia"),
        'ў' => ("u", "w"), // Belarusian short u
        _ => ("", ""),
    }
}

/// Romanize a lowercased Greek token under `scheme`, handling the `ου→ou`
/// digraph before the per-character pass.
fn translit_greek(lower: &str, scheme: Scheme) -> String {
    let chars: Vec<char> = lower.chars().collect();
    let mut out = String::with_capacity(chars.len() * 2);
    let mut i = 0;
    while i < chars.len() {
        // ου / ού → "ou" (both schemes): Papadopoulos, not Papadopoylos.
        if i + 1 < chars.len() && matches!(chars[i], 'ο' | 'ό') && matches!(chars[i + 1], 'υ' | 'ύ')
        {
            out.push_str("ou");
            i += 2;
            continue;
        }
        let (p, a) = greek_char(chars[i]);
        out.push_str(if scheme == Scheme::Primary { p } else { a });
        i += 1;
    }
    out
}

/// `(primary, alt)` romanization for one lowercase Greek letter. Accented vowels
/// fold to their base; `primary` is the modern web form, `alt` the classical.
fn greek_char(ch: char) -> (&'static str, &'static str) {
    match ch {
        'α' | 'ά' => ("a", "a"),
        'β' => ("v", "b"),
        'γ' => ("g", "g"),
        'δ' => ("d", "d"),
        'ε' | 'έ' => ("e", "e"),
        'ζ' => ("z", "z"),
        'η' | 'ή' => ("i", "e"),
        'θ' => ("th", "th"),
        'ι' | 'ί' | 'ϊ' | 'ΐ' => ("i", "i"),
        'κ' => ("k", "k"),
        'λ' => ("l", "l"),
        'μ' => ("m", "m"),
        'ν' => ("n", "n"),
        'ξ' => ("x", "ks"),
        'ο' | 'ό' => ("o", "o"),
        'π' => ("p", "p"),
        'ρ' => ("r", "r"),
        'σ' | 'ς' => ("s", "s"),
        'τ' => ("t", "t"),
        'υ' | 'ύ' | 'ϋ' | 'ΰ' => ("y", "i"),
        'φ' => ("f", "ph"),
        'χ' => ("ch", "kh"),
        'ψ' => ("ps", "ps"),
        'ω' | 'ώ' => ("o", "o"),
        _ => ("", ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The primary (best) romanization of `token` — its first variant, or `""`.
    fn prim(token: &str) -> String {
        romanize_variants(token)
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    #[test]
    fn latin_primary_is_plain_fold_unchanged() {
        // The Latin path must stay byte-identical to fold_ascii_lower so every
        // existing permutation assertion holds.
        for t in ["Smith", "José", "O'Brien", "Meyers", "Åkerström"] {
            assert_eq!(prim(t), fold_ascii_lower(t), "primary != fold for {t}");
        }
    }

    #[test]
    fn german_umlaut_adds_expansion_variant() {
        // müller → [muller, mueller]; öztürk → [ozturk, oeztuerk]; å → aa.
        assert_eq!(romanize_variants("Müller"), vec!["muller", "mueller"]);
        assert_eq!(romanize_variants("Öztürk"), vec!["ozturk", "oeztuerk"]);
        assert_eq!(romanize_variants("Åberg"), vec!["aberg", "aaberg"]);
        // No expandable letter ⇒ a single variant (dedup collapses the pair).
        assert_eq!(romanize_variants("Smith"), vec!["smith"]);
    }

    #[test]
    fn cyrillic_primary_and_alt() {
        assert_eq!(prim("Иван"), "ivan");
        assert_eq!(prim("Петров"), "petrov");
        assert_eq!(prim("Шарапова"), "sharapova");
        assert_eq!(prim("Александр"), "aleksandr");
        // -ый ending → web "-y", strict alt "-yy".
        let nav = romanize_variants("Навальный");
        assert_eq!(nav[0], "navalny");
        assert!(nav.contains(&"navalnyy".to_string()));
        // х: web "kh", passport "h" — Mikhail.
        let mih = romanize_variants("Михаил");
        assert_eq!(mih[0], "mikhail");
        assert!(mih.contains(&"mihail".to_string()));
    }

    #[test]
    fn greek_primary_and_digraph() {
        assert_eq!(prim("Γιώργος"), "giorgos");
        assert_eq!(prim("Παπαδόπουλος"), "papadopoulos"); // ου → ou
        assert_eq!(prim("Τσίπρας"), "tsipras");
        assert_eq!(prim("Αλέξης"), "alexis"); // ξ → x
        // Each scheme is internally consistent: the modern form is all-modern
        // (χ→ch, η→i ⇒ "charis"); the classical form is all-classical
        // (χ→kh, η→e ⇒ "khares"). The schemes are never mixed.
        assert_eq!(romanize_variants("Χάρης"), vec!["charis", "khares"]);
    }

    #[test]
    fn han_and_arabic_yield_nothing() {
        assert!(romanize_variants("李明").is_empty());
        assert!(romanize_variants("\u{0645}\u{062d}\u{0645}\u{062f}").is_empty()); // محمد
        assert_eq!(prim("田中"), "");
    }

    /// Charset + boundedness + totality over a broad scalar sweep: for every
    /// Unicode scalar, romanizing it never panics, every returned variant is
    /// pure [a-z0-9], and the count is bounded. This is the invariant the
    /// permutation engine relies on for safe byte-slicing.
    #[test]
    fn output_is_ascii_alnum_bounded_and_total_for_all_scalars() {
        for cp in 0u32..=0x10_FFFF {
            let Some(ch) = char::from_u32(cp) else {
                continue;
            };
            let s = ch.encode_utf8(&mut [0u8; 4]).to_string();
            let vs = romanize_variants(&s);
            assert!(vs.len() <= MAX_VARIANTS, "unbounded at U+{cp:04X}");
            for v in &vs {
                assert!(
                    v.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                    "non-[a-z0-9] at U+{cp:04X}: {v:?}"
                );
            }
        }
    }

    /// Determinism: identical input ⇒ identical output (name intelligence must
    /// be stable across repeated executions).
    #[test]
    fn deterministic() {
        for t in ["Müller", "Шарапова", "Γιώργος", "Smith", "李明"] {
            assert_eq!(romanize_variants(t), romanize_variants(t));
        }
    }
}
