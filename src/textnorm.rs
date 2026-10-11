//! Pure text-normalisation helpers rebuilt from the monolith's `util::str_util`.

/// `s` with every control character (tab, newline, ESC, ...) written as a Rust
/// escape (`\t`, `\n`, `\u{1b}`), so a provider-controlled value cannot break a
/// line-oriented record or drive the terminal. Everything else is unchanged.
#[must_use]
pub fn escape_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Decodes the named and numeric character references in `s`. A reference that is unknown,
/// malformed, or not a valid character is left as it is, and so is any `&` that does not begin one.
#[must_use]
pub fn decode_html_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let decoded = if rest.as_bytes()[0] == b'&' {
            decode_one_html_entity(rest)
        } else {
            None
        };
        if let Some((ch, consumed)) = decoded {
            out.push(ch);
            rest = &rest[consumed..];
        } else {
            let ch = rest.chars().next().expect("non-empty");
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    out
}

fn decode_one_html_entity(rest: &str) -> Option<(char, usize)> {
    let after_amp = rest.get(1..)?;
    if after_amp.starts_with('#') {
        let hex = after_amp
            .as_bytes()
            .get(1)
            .is_some_and(|b| *b == b'x' || *b == b'X');
        let digits = if hex {
            after_amp.get(2..)?
        } else {
            after_amp.get(1..)?
        };
        let end = digits.find(';')?;
        let raw = &digits[..end];
        if raw.is_empty() {
            return None;
        }
        let value = if hex {
            u32::from_str_radix(raw, 16).ok()?
        } else {
            raw.parse::<u32>().ok()?
        };
        let ch = char::from_u32(value)?;
        let consumed = 2 + usize::from(hex) + raw.len() + 1;
        return Some((ch, consumed));
    }
    let end = after_amp.find(';')?;
    let name = &after_amp[..end];
    let ch = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        _ => return None,
    };
    Some((ch, 1 + name.len() + 1))
}

/// The alphabetic runs of `full` that are at least two bytes long, lowercased. These are the
/// tokens that name matching compares, so a one-byte initial is not a token.
#[must_use]
pub fn name_tokens(full: &str) -> Vec<String> {
    full.split(|c: char| !c.is_alphabetic())
        .filter(|token| token.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// A trimmed, non-empty borrow of an optional string field.
#[must_use]
pub fn nonempty(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Iterate over non-empty trimmed fields in a pipe-delimited string.
pub fn pipe_delimited(s: &str) -> impl Iterator<Item = &str> {
    s.split('|').map(str::trim).filter(|part| !part.is_empty())
}

/// Title-case each whitespace-delimited word.
#[must_use]
pub fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for word in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            let mut upper = first.to_uppercase();
            if let Some(head) = upper.next() {
                out.push(head);
            }
            for extra in upper {
                out.extend(extra.to_lowercase());
            }
            for ch in chars {
                out.extend(ch.to_lowercase());
            }
        }
    }
    out
}

/// Upper-case only the first character, leaving the tail untouched.
#[must_use]
pub fn upper_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Keep only ASCII digits.
#[must_use]
pub fn ascii_digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// Keep only ASCII digits and `+`.
#[must_use]
pub fn ascii_digits_and_plus(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

/// Parse `AS13335`, `as13335`, or `13335`.
#[must_use]
pub fn parse_asn(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    let digits = match trimmed.get(..2) {
        Some(prefix) if prefix.eq_ignore_ascii_case("AS") => trimmed[2..].trim(),
        _ => trimmed,
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// True when `s` fits the ASCII handle policy and length bounds.
#[must_use]
pub fn is_handle(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// True when `s` is a dotted domain-style handle.
#[must_use]
pub fn is_domain_handle(s: &str) -> bool {
    crate::value_syntax::canonical_domain(s).is_some()
}

/// Floor an index to a UTF-8 character boundary.
#[must_use]
pub fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut cursor = index;
    while cursor > 0 && !s.is_char_boundary(cursor) {
        cursor -= 1;
    }
    cursor
}

/// Ceil an index to a UTF-8 character boundary.
#[must_use]
pub fn ceil_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut cursor = index;
    while cursor < s.len() && !s.is_char_boundary(cursor) {
        cursor += 1;
    }
    cursor
}

/// Borrow the longest UTF-8 prefix whose length is at most `max`.
#[must_use]
pub fn truncate_safe(s: &str, max: usize) -> &str {
    &s[..floor_char_boundary(s, max)]
}

/// Safe byte window rounded out to UTF-8 boundaries.
#[must_use]
pub fn char_window(s: &str, start: usize, end: usize) -> &str {
    let begin = ceil_char_boundary(s, start);
    let finish = ceil_char_boundary(s, end).max(begin);
    &s[begin..finish]
}

/// The ASCII text that each lowercase Latin letter with a diacritic folds to, sorted by code point
/// for the binary search in [`fold_latin`]. The rows with a canonical decomposition are the
/// lowercase letters of U+00C0-U+024F and U+1E00-U+1EFF whose decomposition is one ASCII letter
/// followed by combining marks. The other fifteen rows are letters with no decomposition that
/// ASCII folding maps by convention, such as `ß` to `ss` and `ø` to `o`. Derived from the Unicode
/// 15.1 canonical decompositions, and checked letter by letter against them.
const LATIN_FOLDS: &[(char, &str)] = &[
    ('ß', "ss"),
    ('à', "a"),
    ('á', "a"),
    ('â', "a"),
    ('ã', "a"),
    ('ä', "a"),
    ('å', "a"),
    ('æ', "ae"),
    ('ç', "c"),
    ('è', "e"),
    ('é', "e"),
    ('ê', "e"),
    ('ë', "e"),
    ('ì', "i"),
    ('í', "i"),
    ('î', "i"),
    ('ï', "i"),
    ('ð', "d"),
    ('ñ', "n"),
    ('ò', "o"),
    ('ó', "o"),
    ('ô', "o"),
    ('õ', "o"),
    ('ö', "o"),
    ('ø', "o"),
    ('ù', "u"),
    ('ú', "u"),
    ('û', "u"),
    ('ü', "u"),
    ('ý', "y"),
    ('þ', "th"),
    ('ÿ', "y"),
    ('ā', "a"),
    ('ă', "a"),
    ('ą', "a"),
    ('ć', "c"),
    ('ĉ', "c"),
    ('ċ', "c"),
    ('č', "c"),
    ('ď', "d"),
    ('đ', "d"),
    ('ē', "e"),
    ('ĕ', "e"),
    ('ė', "e"),
    ('ę', "e"),
    ('ě', "e"),
    ('ĝ', "g"),
    ('ğ', "g"),
    ('ġ', "g"),
    ('ģ', "g"),
    ('ĥ', "h"),
    ('ħ', "h"),
    ('ĩ', "i"),
    ('ī', "i"),
    ('ĭ', "i"),
    ('į', "i"),
    ('ı', "i"),
    ('ĳ', "ij"),
    ('ĵ', "j"),
    ('ķ', "k"),
    ('ĺ', "l"),
    ('ļ', "l"),
    ('ľ', "l"),
    ('ŀ', "l"),
    ('ł', "l"),
    ('ń', "n"),
    ('ņ', "n"),
    ('ň', "n"),
    ('ŋ', "n"),
    ('ō', "o"),
    ('ŏ', "o"),
    ('ő', "o"),
    ('œ', "oe"),
    ('ŕ', "r"),
    ('ŗ', "r"),
    ('ř', "r"),
    ('ś', "s"),
    ('ŝ', "s"),
    ('ş', "s"),
    ('š', "s"),
    ('ţ', "t"),
    ('ť', "t"),
    ('ŧ', "t"),
    ('ũ', "u"),
    ('ū', "u"),
    ('ŭ', "u"),
    ('ů', "u"),
    ('ű', "u"),
    ('ų', "u"),
    ('ŵ', "w"),
    ('ŷ', "y"),
    ('ź', "z"),
    ('ż', "z"),
    ('ž', "z"),
    ('ſ', "s"),
    ('ơ', "o"),
    ('ư', "u"),
    ('ǎ', "a"),
    ('ǐ', "i"),
    ('ǒ', "o"),
    ('ǔ', "u"),
    ('ǖ', "u"),
    ('ǘ', "u"),
    ('ǚ', "u"),
    ('ǜ', "u"),
    ('ǟ', "a"),
    ('ǡ', "a"),
    ('ǧ', "g"),
    ('ǩ', "k"),
    ('ǫ', "o"),
    ('ǭ', "o"),
    ('ǰ', "j"),
    ('ǵ', "g"),
    ('ǹ', "n"),
    ('ǻ', "a"),
    ('ȁ', "a"),
    ('ȃ', "a"),
    ('ȅ', "e"),
    ('ȇ', "e"),
    ('ȉ', "i"),
    ('ȋ', "i"),
    ('ȍ', "o"),
    ('ȏ', "o"),
    ('ȑ', "r"),
    ('ȓ', "r"),
    ('ȕ', "u"),
    ('ȗ', "u"),
    ('ș', "s"),
    ('ț', "t"),
    ('ȟ', "h"),
    ('ȧ', "a"),
    ('ȩ', "e"),
    ('ȫ', "o"),
    ('ȭ', "o"),
    ('ȯ', "o"),
    ('ȱ', "o"),
    ('ȳ', "y"),
    ('ḁ', "a"),
    ('ḃ', "b"),
    ('ḅ', "b"),
    ('ḇ', "b"),
    ('ḉ', "c"),
    ('ḋ', "d"),
    ('ḍ', "d"),
    ('ḏ', "d"),
    ('ḑ', "d"),
    ('ḓ', "d"),
    ('ḕ', "e"),
    ('ḗ', "e"),
    ('ḙ', "e"),
    ('ḛ', "e"),
    ('ḝ', "e"),
    ('ḟ', "f"),
    ('ḡ', "g"),
    ('ḣ', "h"),
    ('ḥ', "h"),
    ('ḧ', "h"),
    ('ḩ', "h"),
    ('ḫ', "h"),
    ('ḭ', "i"),
    ('ḯ', "i"),
    ('ḱ', "k"),
    ('ḳ', "k"),
    ('ḵ', "k"),
    ('ḷ', "l"),
    ('ḹ', "l"),
    ('ḻ', "l"),
    ('ḽ', "l"),
    ('ḿ', "m"),
    ('ṁ', "m"),
    ('ṃ', "m"),
    ('ṅ', "n"),
    ('ṇ', "n"),
    ('ṉ', "n"),
    ('ṋ', "n"),
    ('ṍ', "o"),
    ('ṏ', "o"),
    ('ṑ', "o"),
    ('ṓ', "o"),
    ('ṕ', "p"),
    ('ṗ', "p"),
    ('ṙ', "r"),
    ('ṛ', "r"),
    ('ṝ', "r"),
    ('ṟ', "r"),
    ('ṡ', "s"),
    ('ṣ', "s"),
    ('ṥ', "s"),
    ('ṧ', "s"),
    ('ṩ', "s"),
    ('ṫ', "t"),
    ('ṭ', "t"),
    ('ṯ', "t"),
    ('ṱ', "t"),
    ('ṳ', "u"),
    ('ṵ', "u"),
    ('ṷ', "u"),
    ('ṹ', "u"),
    ('ṻ', "u"),
    ('ṽ', "v"),
    ('ṿ', "v"),
    ('ẁ', "w"),
    ('ẃ', "w"),
    ('ẅ', "w"),
    ('ẇ', "w"),
    ('ẉ', "w"),
    ('ẋ', "x"),
    ('ẍ', "x"),
    ('ẏ', "y"),
    ('ẑ', "z"),
    ('ẓ', "z"),
    ('ẕ', "z"),
    ('ẖ', "h"),
    ('ẗ', "t"),
    ('ẘ', "w"),
    ('ẙ', "y"),
    ('ạ', "a"),
    ('ả', "a"),
    ('ấ', "a"),
    ('ầ', "a"),
    ('ẩ', "a"),
    ('ẫ', "a"),
    ('ậ', "a"),
    ('ắ', "a"),
    ('ằ', "a"),
    ('ẳ', "a"),
    ('ẵ', "a"),
    ('ặ', "a"),
    ('ẹ', "e"),
    ('ẻ', "e"),
    ('ẽ', "e"),
    ('ế', "e"),
    ('ề', "e"),
    ('ể', "e"),
    ('ễ', "e"),
    ('ệ', "e"),
    ('ỉ', "i"),
    ('ị', "i"),
    ('ọ', "o"),
    ('ỏ', "o"),
    ('ố', "o"),
    ('ồ', "o"),
    ('ổ', "o"),
    ('ỗ', "o"),
    ('ộ', "o"),
    ('ớ', "o"),
    ('ờ', "o"),
    ('ở', "o"),
    ('ỡ', "o"),
    ('ợ', "o"),
    ('ụ', "u"),
    ('ủ', "u"),
    ('ứ', "u"),
    ('ừ', "u"),
    ('ử', "u"),
    ('ữ', "u"),
    ('ự', "u"),
    ('ỳ', "y"),
    ('ỵ', "y"),
    ('ỷ', "y"),
    ('ỹ', "y"),
];

/// The ASCII text a lowercase Latin letter folds to, or `None` for every other character.
/// Uppercase letters are not in the table, because [`normalise_token`] lowercases a word first.
fn fold_latin(ch: char) -> Option<&'static str> {
    LATIN_FOLDS
        .binary_search_by_key(&ch, |&(letter, _)| letter)
        .ok()
        .map(|index| LATIN_FOLDS[index].1)
}

/// Characters that UAX #29 word rule WB4 ignores: combining marks (Extend) and the format
/// characters that appear in extracted text. Such a character belongs to the word before it, so
/// it never splits a word and is not kept in the token. The covered mark blocks are the Latin,
/// Greek and Cyrillic combining blocks. The marks of other scripts are not covered.
#[must_use]
pub fn is_word_extender(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE20}'..='\u{FE2F}'
            | '\u{FEFF}'
    )
}

/// One search token: the word lowercased, with extenders removed and each Latin letter with a
/// diacritic folded to its base letter. Other letters are kept, so Greek and Cyrillic words stay
/// whole. The whole word is lowercased at once, which keeps the Greek final sigma.
#[must_use]
pub fn normalise_token(word: &str) -> String {
    let lower = word.to_lowercase();
    if lower.is_ascii() {
        return lower;
    }
    let mut out = String::with_capacity(lower.len());
    for ch in lower.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else if !is_word_extender(ch) {
            match fold_latin(ch) {
                Some(folded) => out.push_str(folded),
                None => out.push(ch),
            }
        }
    }
    out
}

/// Lowercase ASCII slug with runs of non-alnum collapsed to `-`.
#[must_use]
pub fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_dash = true;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    if out.ends_with('-') {
        out.pop();
    }
    out
}

/// Display a secret as a 4+ellipsis+4 hint when long enough.
#[must_use]
pub fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 16 {
        return "•".repeat(chars.len().max(1));
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// Byte offset of the first ASCII-case-insensitive substring match.
#[must_use]
pub fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let (hay, nee) = (haystack.as_bytes(), needle.as_bytes());
    if nee.is_empty() {
        return Some(0);
    }
    if hay.len() < nee.len() {
        return None;
    }
    (0..=hay.len() - nee.len())
        .find(|&offset| hay[offset..offset + nee.len()].eq_ignore_ascii_case(nee))
}

/// Byte offset of the last whole-word ASCII-case-insensitive match.
#[must_use]
pub fn rfind_word_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let (hay, nee) = (haystack.as_bytes(), needle.as_bytes());
    if nee.is_empty() || hay.len() < nee.len() {
        return None;
    }
    (0..=hay.len() - nee.len()).rev().find(|&offset| {
        hay[offset..offset + nee.len()].eq_ignore_ascii_case(nee)
            && (offset == 0 || !hay[offset - 1].is_ascii_alphanumeric())
            && (offset + nee.len() == hay.len() || !hay[offset + nee.len()].is_ascii_alphanumeric())
    })
}

/// True when every alphanumeric token of `needle` appears as a whole word in `haystack`.
#[must_use]
pub fn whole_word_token_match(haystack: &str, needle: &str) -> bool {
    let words: Vec<&str> = haystack
        .split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect();
    let tokens: Vec<&str> = needle
        .split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect();
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|token| words.iter().any(|word| word.eq_ignore_ascii_case(token)))
}

/// Minimum token length `shares_whole_word_token` treats as a real name token.
pub const MIN_SHARED_TOKEN: usize = 2;

/// True when at least one sufficiently long alphanumeric token of `needle` appears as a whole word.
#[must_use]
pub fn shares_whole_word_token(haystack: &str, needle: &str) -> bool {
    let words: Vec<&str> = haystack
        .split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect();
    needle
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| token.chars().count() >= MIN_SHARED_TOKEN)
        .any(|token| words.iter().any(|word| word.eq_ignore_ascii_case(token)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_controls_neutralises_line_and_terminal_controls() {
        assert_eq!(escape_controls("a\tb\nc\u{1b}[31m"), "a\\tb\\nc\\u{1b}[31m");
        assert_eq!(escape_controls("breach:DB_A ü"), "breach:DB_A ü");
    }

    #[test]
    fn title_case_stays_idempotent() {
        for input in [
            "ßeta",
            "ﬁona",
            "ERIK DIEGMANN",
            "  kyle   diegmann ",
            "ǳeta",
            "",
        ] {
            let once = title_case(input);
            assert_eq!(title_case(&once), once, "{input:?}");
        }
        assert_eq!(title_case("ßeta"), "Sseta");
        assert_eq!(title_case("ERIK DIEGMANN"), "Erik Diegmann");
    }

    #[test]
    fn upper_first_preserves_tail() {
        assert_eq!(upper_first("mcDonald"), "McDonald");
        assert_eq!(upper_first("ñoño"), "Ñoño");
        assert_eq!(upper_first(""), "");
    }

    #[test]
    fn digits_and_asn_helpers_work() {
        assert_eq!(ascii_digits("+61 (4) 123-456"), "614123456");
        assert_eq!(ascii_digits_and_plus("+61 (4) 123-456"), "+614123456");
        assert_eq!(parse_asn("AS13335"), Some(13_335));
        assert_eq!(parse_asn("AS 13335"), Some(13_335));
        assert_eq!(parse_asn("ASN13335"), None);
        assert!(is_handle("a-b_c9", 3, 20));
        assert!(!is_handle("bad.handle", 3, 20));
    }

    #[test]
    fn safe_slicing_is_total() {
        let sample = "aé😀b xÿz";
        for start in 0..=sample.len() + 2 {
            for end in 0..=sample.len() + 2 {
                let window = char_window(sample, start, end);
                assert!(window.is_empty() || sample.contains(window));
            }
            let prefix = truncate_safe(sample, start);
            assert!(sample.starts_with(prefix));
        }
        assert_eq!(
            rfind_word_ascii_ci("EDWARD 12 COTTESLOE WA 6011", "WA"),
            Some(20)
        );
        assert_eq!(find_ascii_ci("Hello World", "WORLD"), Some(6));
    }

    #[test]
    fn folding_and_slugging_are_stable() {
        assert_eq!(normalise_token("José"), "jose");
        assert_eq!(normalise_token("Müller"), "muller");
        assert_eq!(normalise_token("Nguyễn"), "nguyen");
        assert_eq!(normalise_token("Straße"), "strasse");
        assert_eq!(
            slugify("client transfer prohibited"),
            "client-transfer-prohibited"
        );
        assert_eq!(slugify("café¹"), "caf");
    }

    #[test]
    fn latin_folds_follow_the_unicode_decompositions() {
        // A sample of the table. When the table was written, every lowercase letter of the Latin
        // blocks was checked against the Unicode 15.1 decompositions.
        let pairs = [
            ('é', "e"),
            ('ệ', "e"),
            ('ü', "u"),
            ('ñ', "n"),
            ('ō', "o"),
            ('ș', "s"),
            ('ț', "t"),
            ('ǎ', "a"),
            ('ł', "l"),
            ('ı', "i"),
            ('ĳ', "ij"),
            ('æ', "ae"),
            ('œ', "oe"),
            ('ß', "ss"),
            ('þ', "th"),
            ('ø', "o"),
            ('đ', "d"),
            ('ð', "d"),
        ];
        for (letter, folded) in pairs {
            assert_eq!(fold_latin(letter), Some(folded), "{letter}");
        }
        assert_eq!(fold_latin('a'), None);
        assert_eq!(fold_latin('Ü'), None, "callers lowercase a word first");
        assert_eq!(fold_latin('ж'), None);
    }

    #[test]
    fn fold_table_is_sorted_for_the_binary_search() {
        assert!(LATIN_FOLDS.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }

    #[test]
    fn normalised_tokens_drop_marks_and_keep_other_letters() {
        assert_eq!(normalise_token("Zu\u{0308}rich"), "zurich");
        assert_eq!(normalise_token("Zürich"), "zurich");
        assert_eq!(normalise_token("İstanbul"), "istanbul");
        assert_eq!(normalise_token("co\u{00AD}operate"), "cooperate");
        assert_eq!(normalise_token("ΟΔΟΣ"), "οδος");
        assert_eq!(normalise_token("Москва"), "москва");
    }

    #[test]
    fn masking_and_token_matching_follow_contract() {
        assert_eq!(mask_secret(""), "•");
        assert_eq!(mask_secret("abcdefghijklmno"), "•••••••••••••••");
        assert_eq!(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA…MPLE");
        assert!(whole_word_token_match("Linus Torvalds", "linus torvalds"));
        assert!(!whole_word_token_match("Mildred Smith", "red"));
        assert!(shares_whole_word_token(
            "Marshall Family Foundation",
            "smith family"
        ));
        assert!(!shares_whole_word_token("Ø Smith", "Ø Jones"));
    }

    #[test]
    fn dotted_handles_use_domain_policy() {
        assert!(is_domain_handle("alice.dev"));
        assert!(is_domain_handle(" Example.COM. "));
        assert!(is_domain_handle("a-b.example"));
        assert!(!is_domain_handle("alice"));
        assert!(!is_domain_handle("-bad.example"));
        assert!(!is_domain_handle("bad-.example"));
        assert!(!is_domain_handle("bad..example"));
        assert!(!is_domain_handle("bad_example.com"));
        assert!(!is_domain_handle("example.café"));
    }

    #[test]
    fn optional_and_pipe_helpers_trim() {
        assert_eq!(nonempty(&Some("  hi ".to_string())), Some("hi"));
        assert_eq!(nonempty(&Some("   ".to_string())), None);
        assert_eq!(
            pipe_delimited(" alpha | |beta|| ").collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn html_references_decode_and_unknown_ones_are_left_alone() {
        assert_eq!(decode_html_entities("a &amp; b &lt;c&gt;"), "a & b <c>");
        assert_eq!(decode_html_entities("it&#39;s &#x41;&#65;"), "it's AA");
        assert_eq!(
            decode_html_entities("&bogus; &#xD800; & done"),
            "&bogus; &#xD800; & done"
        );
    }
}
