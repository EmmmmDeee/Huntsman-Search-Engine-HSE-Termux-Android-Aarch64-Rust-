//! Keyless, offline romanisation of Cyrillic to Latin, so a name written in Cyrillic and its Latin
//! transliteration match. This is the one hard problem a Russia-facing OSINT search has that a
//! Latin-only matcher cannot: an OFAC or UN alias written "Prigozhin" and a query "Пригожин" (or
//! the reverse) must reduce to the same key.
//!
//! The table is a practical romanisation close to BGN/PCGN and the forms sanctions lists use: each
//! Russian (and common Ukrainian/Belarusian/Serbian) Cyrillic letter maps to the Latin letters it
//! is usually written with. It romanises each letter in one fixed way (so `е` is always `e`, never
//! a positional `ye`), trading a few missed spellings for never collapsing distinct names. It is
//! deliberately lossy and many-to-one -- several Cyrillic letters share a Latin spelling and several
//! Latin spellings collapse together in [`fold_latin`] -- because matching wants the forms to meet,
//! not a reversible transliteration. A character with no mapping (already Latin, a digit,
//! punctuation) is passed through unchanged.

/// The Latin spelling of one lowercase Cyrillic character, or `None` to pass it through. The caller
/// lowercases first. Multi-letter outputs (`ж`→`zh`) are intended. **Pure.**
fn romanize_char(c: char) -> Option<&'static str> {
    Some(match c {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' | 'ґ' => "g", // ґ: Ukrainian ge
        'д' => "d",
        'е' | 'ё' | 'э' => "e", // ё and э folded onto e for matching
        'є' => "ye",            // Ukrainian ie
        'ж' => "zh",
        'з' => "z",
        'и' | 'і' | 'ы' => "i", // і: Ukrainian/Belarusian i; ы folded onto i
        'ї' => "yi",
        'й' | 'ј' => "y", // ј: Serbian je
        'к' => "k",
        'л' | 'љ' => "l",
        'м' => "m",
        'н' | 'њ' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'ћ' => "c",       // Serbian tshe
        'ђ' => "dj",      // Serbian dje
        'у' | 'ў' => "u", // ў: Belarusian short u
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'џ' => "dz", // Serbian dze
        'ш' => "sh",
        'щ' => "shch",
        'ъ' | 'ь' => "", // hard and soft signs: dropped
        'ю' => "yu",
        'я' => "ya",
        _ => return None,
    })
}

/// Whether `c` is a Cyrillic letter this module might romanise. **Pure.**
#[must_use]
pub fn is_cyrillic(c: char) -> bool {
    matches!(c, '\u{0400}'..='\u{04ff}')
}

/// `text` with every Cyrillic letter replaced by its Latin spelling, lowercased; every other
/// character is passed through in lower case. A string with no Cyrillic comes back only
/// lowercased. **Pure.**
#[must_use]
pub fn romanize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for lower in text.chars().flat_map(char::to_lowercase) {
        match romanize_char(lower) {
            Some(latin) => out.push_str(latin),
            None => out.push(lower),
        }
    }
    out
}

/// Fold a Latin letter to a common matching form: diacritics stripped, and the few letters that
/// romanisations spell differently mapped onto one form. **Pure.**
fn fold_char(c: char) -> char {
    match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => 'a',
        'ç' | 'ć' | 'č' | 'ĉ' | 'ċ' => 'c',
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => 'e',
        'ì' | 'í' | 'î' | 'ï' | 'ī' | 'ĭ' | 'į' => 'i',
        'ñ' | 'ń' | 'ň' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' => 'o',
        'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ŭ' | 'ů' | 'ű' => 'u',
        'ý' | 'ÿ' => 'y',
        'š' | 'ś' | 'ş' => 's',
        'ž' | 'ź' | 'ż' => 'z',
        'ł' => 'l',
        'đ' => 'd',
        other => other,
    }
}

/// Fold Latin letters to a common matching form and keep only ASCII letters and digits, so
/// "Müller"/"Muller" draw closer. Lossy by design. **Pure.**
#[must_use]
pub fn fold_latin(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars().flat_map(char::to_lowercase) {
        let folded = fold_char(c);
        if folded.is_ascii_alphanumeric() {
            out.push(folded);
        }
    }
    out
}

/// The canonical match key of one name token: romanise any Cyrillic, then fold the Latin to ASCII.
/// Two tokens that name the same thing in Cyrillic and Latin reduce to the same key. **Pure.**
#[must_use]
pub fn match_key(token: &str) -> String {
    fold_latin(&romanize(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyrillic_and_latin_spellings_of_a_name_meet() {
        assert_eq!(match_key("Пригожин"), match_key("Prigozhin"));
        assert_eq!(match_key("Путин"), match_key("Putin"));
        assert_eq!(match_key("Шойгу"), match_key("Shoygu"));
    }

    /// `е` is romanised `e` everywhere, not positionally `ye` at a word start, so a Latin spelling
    /// that writes the initial `ye` does not meet the Cyrillic. This is a deliberate precision
    /// choice: a positional `ye` rule, and folding Latin `ye`→`e`, would collapse distinct names.
    #[test]
    fn initial_ye_is_a_known_non_match_kept_for_precision() {
        assert_ne!(match_key("Евгений"), match_key("Yevgeniy"));
        assert_eq!(match_key("Евгений"), match_key("Evgeniy"));
    }

    #[test]
    fn distinct_names_do_not_collapse() {
        assert_ne!(match_key("Путин"), match_key("Petrov"));
        assert_ne!(match_key("Иванов"), match_key("Петров"));
    }

    #[test]
    fn romanize_handles_multi_letter_and_dropped_signs() {
        assert_eq!(romanize("Жуков"), "zhukov");
        assert_eq!(romanize("Щербина"), "shcherbina");
        assert_eq!(romanize("Объедков"), "obedkov"); // hard sign dropped
        assert_eq!(romanize("Хохол"), "khokhol");
    }

    #[test]
    fn latin_only_input_is_just_lowercased_and_folded() {
        assert_eq!(romanize("Smith"), "smith");
        assert_eq!(match_key("Müller"), "muller");
        assert_eq!(match_key("Łukaszenko"), fold_latin("lukaszenko"));
    }

    #[test]
    fn is_cyrillic_detects_the_block() {
        assert!(is_cyrillic('я'));
        assert!(is_cyrillic('Ж'));
        assert!(!is_cyrillic('z'));
        assert!(!is_cyrillic('5'));
    }

    #[test]
    fn match_key_drops_punctuation_and_spaces() {
        assert_eq!(match_key("O'Brien"), "obrien");
        assert_eq!(match_key("ко-ва"), "kova");
    }
}
