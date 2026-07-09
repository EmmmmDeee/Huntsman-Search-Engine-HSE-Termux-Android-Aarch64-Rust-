//! Core-level pure text primitives shared across layers.
//!
//! These are dependency-free string transforms that the **core** identity/
//! correlation logic needs directly (e.g. `scan::classify::identity_norm`). They
//! live in `core` — the base layer — precisely so core can use them without
//! reaching up into `util` (which the layering guard in `tests/architecture.rs`
//! forbids). `util` and `modules` may depend on `core`, so both can still reach
//! these; `util::str_util` re-exports [`fold_ascii_lower`] to keep its historical
//! public path stable.

/// Fold common Latin diacritics to their base ASCII letter, lowercase, and
/// drop everything else. Pure and dependency-free (no `deunicode`/ICU — keeps
/// the Termux single-binary lean). A name like `"José Müller-Łódź"` folds to
/// the ASCII stem real platforms actually use (`josemullerlodz`), so derived
/// usernames/emails match. Multi-char expansions (`æ→ae`, `ß→ss`, `þ→th`) are
/// handled; non-Latin scripts (Arabic, CJK) have no ASCII fold and are
/// dropped — callers should split into words *before* folding each token.
///
/// # Guarantees
/// - **Charset:** the result contains only `[a-z0-9]` — every byte is ASCII
///   lowercase alphanumeric. The result is therefore always valid to index by
///   byte; `name_intel::permute` relies on this for safe slicing. (Proved
///   exhaustively over every Unicode scalar value by
///   `fold_ascii_lower_output_is_ascii_lower_alnum_for_all_scalars`.)
/// - **Idempotent:** `fold_ascii_lower(&fold_ascii_lower(s)) == fold_ascii_lower(s)`
///   (a corollary: `[a-z0-9]` map to themselves).
/// - **Total:** never panics, on any input including arbitrary Unicode.
/// - A token with no foldable Latin content yields the empty string.
///
/// ```
/// use huntsman_search_engine::core::text::fold_ascii_lower;
///
/// assert_eq!(fold_ascii_lower("José Müller"), "josemuller"); // diacritics + space dropped
/// assert_eq!(fold_ascii_lower("O'Brien-Smith"), "obriensmith"); // punctuation dropped
/// assert_eq!(fold_ascii_lower("Straße"), "strasse"); // ß → ss
/// assert_eq!(fold_ascii_lower("日本語"), ""); // no ASCII fold → empty
/// assert!(
///     fold_ascii_lower("Zoë_99 🎉")
///         .bytes()
///         .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
/// );
/// ```
#[must_use]
pub fn fold_ascii_lower(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            'a'..='z' | '0'..='9' => out.push(ch),
            'A'..='Z' => out.push(ch.to_ascii_lowercase()),
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'À' | 'Á' | 'Â' | 'Ã' | 'Ä' | 'Å' | 'ā' | 'ă'
            | 'ą' => out.push('a'),
            'ç' | 'Ç' | 'ć' | 'č' | 'ĉ' | 'ċ' => out.push('c'),
            'è' | 'é' | 'ê' | 'ë' | 'È' | 'É' | 'Ê' | 'Ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' =>
            {
                out.push('e');
            }
            'ì' | 'í' | 'î' | 'ï' | 'Ì' | 'Í' | 'Î' | 'Ï' | 'ī' | 'ĭ' | 'į' | 'ı' => {
                out.push('i');
            }
            'ñ' | 'Ñ' | 'ń' | 'ņ' | 'ň' => out.push('n'),
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'Ò' | 'Ó' | 'Ô' | 'Õ' | 'Ö' | 'Ø' | 'ō' | 'ŏ'
            | 'ő' => out.push('o'),
            'ù' | 'ú' | 'û' | 'ü' | 'Ù' | 'Ú' | 'Û' | 'Ü' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' =>
            {
                out.push('u');
            }
            'ý' | 'ÿ' | 'Ý' | 'Ŷ' | 'ŷ' => out.push('y'),
            'ł' | 'Ł' => out.push('l'),
            'ś' | 'š' | 'ş' | 'Ś' | 'Š' | 'Ş' => out.push('s'),
            'ź' | 'ż' | 'ž' | 'Ź' | 'Ż' | 'Ž' => out.push('z'),
            'ð' | 'Đ' | 'đ' => out.push('d'),
            'ț' | 'ţ' | 'Ț' | 'Ţ' => out.push('t'),
            'ğ' | 'Ğ' => out.push('g'),
            'ř' | 'Ř' => out.push('r'),
            'æ' | 'Æ' => out.push_str("ae"),
            'œ' | 'Œ' => out.push_str("oe"),
            'ß' => out.push_str("ss"),
            'þ' | 'Þ' => out.push_str("th"),
            _ => {}
        }
    }
    out
}
