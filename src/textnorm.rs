//! Pure text-normalisation helpers rebuilt from the monolith's `util::str_util`.

use std::fmt::Write as _;

/// Whether [`escape_controls`] writes `c` escaped: a control character, a line or paragraph
/// separator, or a bidirectional embedding, override or isolate control. The separators start a new
/// line for readers that split on them, and the others reorder the text around them, so a name can
/// read as another. The marks that ordinary right-to-left text uses (U+200E, U+200F, U+061C) and
/// the joiners that Persian and Indic scripts need are not among them.
#[must_use]
pub fn is_escaped(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

fn escape_where(s: &str, escaped: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if escaped(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// `s` with every control character (tab, newline, ESC, ...) written as a Rust escape (`\t`, `\n`,
/// `\u{1b}`), and so are the characters [`is_escaped`] names, so a provider-controlled value cannot
/// break a line-oriented record, drive the terminal or read as other text. Everything else is
/// unchanged.
#[must_use]
pub fn escape_controls(s: &str) -> String {
    escape_where(s, is_escaped)
}

/// [`escape_controls`] for text that already has lines, such as an error message: a line feed and a
/// tab stay as they are.
#[must_use]
pub fn escape_controls_keep_lines(s: &str) -> String {
    escape_where(s, |c| c != '\n' && c != '\t' && is_escaped(c))
}

/// JSON with DEL, the C1 controls, the line and paragraph separators and the bidirectional
/// controls written as `\uXXXX`. JSON already escapes the control characters below U+0020, and
/// the JSON text around these characters is ASCII, so they can only occur inside a string. The
/// escaped form decodes to the same value, so a reader sees the same text.
#[must_use]
pub fn escape_unsafe_text(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        // Below U+007F, JSON has escaped what needs it inside strings, and the rest is layout.
        if c >= '\u{7f}' && is_escaped(c) {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
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
    decode_references(s, Syntax::Html)
}

/// Decodes the references in `s` by XML 1.0's rules, for XML that is not HTML, such as an XMP
/// packet: the five predefined entities, and numeric references to characters XML allows. Anything
/// else is left as it is, so `&nbsp;`, which XML does not define, stays as written.
#[must_use]
pub fn decode_xml_references(s: &str) -> String {
    decode_references(s, Syntax::Xml)
}

/// The rules a reference is read by: HTML's, which takes `&nbsp;`, an upper-case `X` and a sign, or
/// XML's.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Syntax {
    Html,
    Xml,
}

/// One pass over `s`: a reference that `syntax` reads is replaced by its character, and any other
/// character is copied as it is, so a decoded `&` is never decoded again.
fn decode_references(s: &str, syntax: Syntax) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let decoded = if rest.as_bytes()[0] == b'&' {
            decode_one_reference(rest, syntax)
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

/// The position of the `;` that ends a reference, when only a name, a number or a sign comes before
/// it. Any other byte ends the search. A reference cannot hold such a byte, and the next `&` is one
/// of them, so each byte is searched by at most one `&`: a text of ampersands takes linear time, and
/// the decoding is the same as a search for the `;` to the end of the text.
fn reference_end(s: &str) -> Option<usize> {
    for (index, byte) in s.bytes().enumerate() {
        match byte {
            b';' => return Some(index),
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'+' => {}
            _ => return None,
        }
    }
    None
}

/// The reference at the start of `rest`, which begins with `&`, and the bytes it spans.
fn decode_one_reference(rest: &str, syntax: Syntax) -> Option<(char, usize)> {
    if rest.starts_with("&#") {
        return decode_numeric(rest, syntax);
    }
    let after_amp = rest.get(1..)?;
    let end = reference_end(after_amp)?;
    let name = &after_amp[..end];
    let ch = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" if syntax == Syntax::Html => ' ',
        _ => return None,
    };
    Some((ch, 1 + name.len() + 1))
}

/// The character a numeric reference at the start of `rest`, which begins with `&#`, names, and the
/// bytes it spans. HTML takes `x` or `X` for hex and a sign before the digits, and any code point a
/// `char` holds. XML takes a lower-case `x` and digits only, and only a code point XML 1.0 allows.
fn decode_numeric(rest: &str, syntax: Syntax) -> Option<(char, usize)> {
    let html = syntax == Syntax::Html;
    let after_hash = rest.get(2..)?;
    let (hex, digits) = match after_hash.strip_prefix(|c: char| c == 'x' || (html && c == 'X')) {
        Some(hex_digits) => (true, hex_digits),
        None => (false, after_hash),
    };
    let end = reference_end(digits)?;
    let raw = &digits[..end];
    if raw.is_empty() {
        return None;
    }
    let digit = |b: u8| {
        if hex {
            b.is_ascii_hexdigit()
        } else {
            b.is_ascii_digit()
        }
    };
    if !html && !raw.bytes().all(digit) {
        return None;
    }
    let value = u32::from_str_radix(raw, if hex { 16 } else { 10 }).ok()?;
    let ch = char::from_u32(value)?;
    if !html && !is_xml_char(ch) {
        return None;
    }
    let consumed = 2 + usize::from(hex) + raw.len() + 1;
    Some((ch, consumed))
}

/// Whether XML 1.0 allows `c` in a document: tab, line feed, carriage return, and the characters
/// from U+0020 to U+D7FF, U+E000 to U+FFFD and U+10000 to U+10FFFF. A surrogate is not a `char`.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || matches!(
            c,
            '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'
        )
}

/// The alphabetic runs of `full` that are at least two characters long, lowercased. These are the
/// tokens that name matching compares. A one-letter initial is not a token, even an accented one
/// that takes two bytes in UTF-8.
#[must_use]
pub fn name_tokens(full: &str) -> Vec<String> {
    full.split(|c: char| !c.is_alphabetic())
        .filter(|token| token.chars().nth(1).is_some())
        .map(str::to_lowercase)
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

/// Case-insensitive equality over Unicode letters: two words are equal when their characters
/// lowercase, one at a time, to the same sequence, so `Émile` equals `émile`.
///
/// The bytes are compared from the start, and the first difference usually settles the answer.
/// Bytes that are equal, or differ only in ASCII case, are the same character. A difference
/// between two ASCII bytes makes the words unequal, because every ASCII character lowercases to
/// one ASCII character. A difference involving a non-ASCII byte is settled on lowercased
/// characters. With no difference, the words are equal only at the same length: a longer word
/// has characters left after the shorter one ends, and every character has a lowercase form.
fn eq_ignore_case(a: &str, b: &str) -> bool {
    let (x, y) = (a.as_bytes(), b.as_bytes());
    for (p, q) in x.iter().zip(y) {
        if !p.eq_ignore_ascii_case(q) {
            return !(p.is_ascii() && q.is_ascii())
                && a.chars()
                    .flat_map(char::to_lowercase)
                    .eq(b.chars().flat_map(char::to_lowercase));
        }
    }
    x.len() == y.len()
}

/// True when every alphanumeric token of `needle` appears as a whole word in `haystack`, ignoring
/// case for Unicode letters as well as ASCII.
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
            .all(|token| words.iter().any(|word| eq_ignore_case(word, token)))
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
        .any(|token| words.iter().any(|word| eq_ignore_case(word, token)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_unsafe_text_writes_terminal_controls_and_decodes_to_the_same_value() {
        let value = serde_json::json!({"name": "a\u{9b}31m\u{2028}b\u{202e}c\u{7f}d", "n": 1});
        let json = serde_json::to_string_pretty(&value).unwrap();
        let written = escape_unsafe_text(&json);
        // Pretty JSON's own line breaks stay; nothing else that is escaped may appear raw.
        assert!(
            !written.chars().any(|c| c != '\n' && is_escaped(c)),
            "{written:?}"
        );
        assert!(
            written.contains("\\u009b") && written.contains("\\u202e"),
            "{written}"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&written).unwrap(),
            value
        );
    }

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
    fn token_matching_follows_contract() {
        assert!(whole_word_token_match("Linus Torvalds", "linus torvalds"));
        assert!(!whole_word_token_match("Mildred Smith", "red"));
        assert!(shares_whole_word_token(
            "Marshall Family Foundation",
            "smith family"
        ));
        assert!(!shares_whole_word_token("Ø Smith", "Ø Jones"));
    }

    #[test]
    fn name_matching_characterises_ascii_names() {
        // Pinned before the case-folding and token-length changes. ASCII behaviour must not change.
        assert_eq!(name_tokens("Ada Lovelace"), ["ada", "lovelace"]);
        assert_eq!(name_tokens("O'Brien-Smith"), ["brien", "smith"]);
        assert_eq!(name_tokens("Madonna"), ["madonna"]);
        assert!(name_tokens("   ").is_empty());
        assert!(whole_word_token_match("ZOLA, EMILE", "emile zola"));
        assert!(!whole_word_token_match("Mildred Smith", ""));
        assert!(!whole_word_token_match("Mildred Smith", "smith jones"));
        assert!(shares_whole_word_token("Ada Lovelace", "Lovelace Byron"));
        assert!(!shares_whole_word_token("Ada Lovelace", "Byron King"));
        assert!(!shares_whole_word_token("Ada Lovelace", "A"));
    }

    #[test]
    fn name_matching_ignores_case_for_accented_letters() {
        assert_eq!(name_tokens("ÉMILE ZOLA"), ["émile", "zola"]);
        assert_eq!(name_tokens("ÉMILE ZOLA"), name_tokens("émile zola"));
        assert!(whole_word_token_match("ZOLA, ÉMILE", "émile zola"));
        assert!(shares_whole_word_token("ÉMILE ZOLA", "émile"));
        // A letter with an accent is a different letter from its plain form.
        assert!(!whole_word_token_match("ZOLA, EMILE", "émile zola"));
    }

    #[test]
    fn one_accented_letter_is_an_initial_not_a_name_token() {
        // Two bytes in UTF-8 but one letter. The people command has always treated it this way.
        assert_eq!(name_tokens("É Lovelace"), ["lovelace"]);
        assert_eq!(name_tokens("Ø Smith"), ["smith"]);
    }

    /// The definition `eq_ignore_case` keeps: each word lowercases, one character at a time, to the
    /// same sequence.
    fn lowercased_sequences_equal(a: &str, b: &str) -> bool {
        a.chars()
            .flat_map(char::to_lowercase)
            .eq(b.chars().flat_map(char::to_lowercase))
    }

    #[test]
    fn eq_ignore_case_matches_the_lowercase_definition_on_every_short_word() {
        // One character for each rule: ASCII case, the Kelvin sign (lowercases to k), dotted
        // capital I (lowercases to two characters), sharp s, a combining mark and accented letters.
        const ALPHABET: [char; 12] = [
            'a', 'A', 'k', '\u{212A}', 'i', '\u{130}', '\u{DF}', '\u{1E9E}', 'S', '\u{307}', 'é',
            'É',
        ];
        let mut words = vec![String::new()];
        let mut longest = vec![String::new()];
        for _ in 0..3 {
            longest = longest
                .iter()
                .flat_map(|word| ALPHABET.iter().map(move |ch| format!("{word}{ch}")))
                .collect();
            words.extend(longest.iter().cloned());
        }
        assert_eq!(words.len(), 1 + 12 + 12 * 12 + 12 * 12 * 12);
        for a in &words {
            for b in &words {
                assert_eq!(
                    eq_ignore_case(a, b),
                    lowercased_sequences_equal(a, b),
                    "{a:?} and {b:?}"
                );
            }
        }
    }

    #[test]
    fn eq_ignore_case_matches_the_lowercase_definition_on_random_words() {
        const ALPHABET: [char; 16] = [
            'a', 'A', 'b', 'B', 'k', '\u{212A}', 'i', '\u{130}', '\u{DF}', 's', 'S', '\u{17F}',
            '\u{307}', 'é', 'É', '0',
        ];
        // A fixed xorshift sequence, so that any failure can be reproduced.
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = |bound: usize| -> usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
        };
        for _ in 0..50_000 {
            let len = next(13);
            let a: String = (0..len).map(|_| ALPHABET[next(ALPHABET.len())]).collect();
            // Half the pairs are a copy of `a` with some characters changed, so that long equal
            // prefixes are common.
            let b: String = if next(2) == 0 {
                let len = next(13);
                (0..len).map(|_| ALPHABET[next(ALPHABET.len())]).collect()
            } else {
                a.chars()
                    .map(|ch| {
                        if next(4) == 0 {
                            ALPHABET[next(ALPHABET.len())]
                        } else {
                            ch
                        }
                    })
                    .collect()
            };
            assert_eq!(
                eq_ignore_case(&a, &b),
                lowercased_sequences_equal(&a, &b),
                "{a:?} and {b:?}"
            );
        }
    }

    #[test]
    fn name_matching_follows_simple_case_mapping_at_each_length() {
        assert!(eq_ignore_case("ADA", "ada"));
        assert!(eq_ignore_case("\u{212A}", "k"));
        assert!(eq_ignore_case("\u{212A}ing", "king"));
        // A longer word has characters left over, so it is a different word.
        assert!(!eq_ignore_case("ab", "ab\u{212A}"));
        // Dotted capital I lowercases to two characters, so it is not a plain i.
        assert!(!eq_ignore_case("i", "\u{130}"));
        // Simple case mapping is not full case folding: sharp s does not equal SS.
        assert!(!eq_ignore_case("SS", "\u{DF}"));
        assert!(eq_ignore_case("\u{1E9E}", "\u{DF}"));
        assert!(eq_ignore_case("É", "é"));
        assert!(!eq_ignore_case("E", "É"));
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

    #[test]
    fn xml_references_decode_by_xml_rules_and_the_rest_are_left_alone() {
        for (text, decoded) in [
            ("&nbsp;", "&nbsp;"),
            ("&#X41;", "&#X41;"),
            ("&#+65;", "&#+65;"),
            ("&#0;", "&#0;"),
            ("&#x1;", "&#x1;"),
            ("&#xA;", "\n"),
            ("&#32;", " "),
            ("&amp;", "&"),
            ("&#169;", "\u{a9}"),
            ("&#xD800;", "&#xD800;"),
        ] {
            assert_eq!(decode_xml_references(text), decoded, "{text}");
        }
        assert_eq!(
            decode_xml_references("&lt;a&gt; &#x41;&#65;&#x9;&#x0041;&#xFFFE;&#x10FFFF;"),
            "<a> AA\tA&#xFFFE;\u{10ffff}"
        );
        // One pass: an escaped reference is not decoded again.
        assert_eq!(decode_xml_references("&amp;#38; &amp;amp;"), "&#38; &amp;");
    }

    #[test]
    fn the_separators_and_bidirectional_overrides_are_escaped_too() {
        assert_eq!(
            escape_controls("a\u{2028}b\u{2029}c"),
            "a\\u{2028}b\\u{2029}c"
        );
        assert_eq!(
            escape_controls("pay\u{202e}fdp.exe\u{202c} \u{2066}x\u{2069}"),
            "pay\\u{202e}fdp.exe\\u{202c} \\u{2066}x\\u{2069}"
        );
        // Ordinary right-to-left text, its marks and the joiners that scripts need are left alone.
        for text in [
            "مرحبا",
            "a\u{200f}b",
            "a\u{200e}b",
            "\u{061c}",
            "می\u{200c}خواهم",
            "क्\u{200d}ष",
        ] {
            assert_eq!(escape_controls(text), text, "{text:?}");
        }
    }

    #[test]
    fn the_variant_for_messages_keeps_line_feeds_and_tabs() {
        assert_eq!(
            escape_controls_keep_lines("one\ntwo\tx\u{1b}[2J\r\u{7}\u{2028}"),
            "one\ntwo\tx\\u{1b}[2J\\r\\u{7}\\u{2028}"
        );
        assert_eq!(escape_controls_keep_lines("plain text"), "plain text");
    }

    /// The decoder with a plain search for the `;`, which is how it was written before the search
    /// stopped at the first byte a reference cannot hold. The two must agree on every text.
    fn decode_with_plain_search(s: &str) -> String {
        fn one(rest: &str) -> Option<(char, usize)> {
            let after_amp = rest.get(1..)?;
            if let Some(numeric) = after_amp.strip_prefix('#') {
                let (hex, digits) = match numeric.strip_prefix(['x', 'X']) {
                    Some(hex_digits) => (true, hex_digits),
                    None => (false, numeric),
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
                return Some((char::from_u32(value)?, 2 + usize::from(hex) + raw.len() + 1));
            }
            let end = after_amp.find(';')?;
            let ch = match &after_amp[..end] {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                "nbsp" => ' ',
                _ => return None,
            };
            Some((ch, 1 + end + 1))
        }
        let mut out = String::new();
        let mut rest = s;
        while let Some(first) = rest.chars().next() {
            let decoded = if first == '&' { one(rest) } else { None };
            if let Some((ch, consumed)) = decoded {
                out.push(ch);
                rest = &rest[consumed..];
            } else {
                out.push(first);
                rest = &rest[first.len_utf8()..];
            }
        }
        out
    }

    #[test]
    fn the_early_stop_decodes_exactly_what_a_plain_search_does() {
        // A generated mix of the characters a reference is made of, and of ones that break it.
        const ALPHABET: &[&str] = &[
            "&", "&", "&", "#", "x", "X", ";", ";", "a", "m", "p", "l", "t", "g", "q", "u", "o",
            "n", "b", "s", "0", "1", "4", "9", "A", "F", "+", "-", " ", "é", "<",
        ];
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 33) as usize
        };
        for _ in 0..4000 {
            let length = next() % 61;
            let text: String = (0..length)
                .map(|_| ALPHABET[next() % ALPHABET.len()])
                .collect();
            assert_eq!(
                decode_html_entities(&text),
                decode_with_plain_search(&text),
                "{text:?}"
            );
        }
        // References the generator is likely to complete, so the comparison is not vacuous.
        assert_eq!(decode_with_plain_search("&amp;&#65;&#x41;&#+65;"), "&AAA");
        assert_eq!(decode_html_entities("&amp;&#65;&#x41;&#+65;"), "&AAA");
    }

    #[test]
    fn a_reference_of_any_length_is_decoded_as_before() {
        // HTML allows any number of leading zeros, and a reference that spans them still decodes.
        assert_eq!(decode_html_entities("&#0000000000000000000065;"), "A");
        assert_eq!(
            decode_html_entities(&format!("&#{}65;", "0".repeat(60))),
            "A"
        );
        assert_eq!(
            decode_html_entities(&format!("&#x{}41;", "0".repeat(60))),
            "A"
        );
    }

    #[test]
    fn a_text_of_ampersands_decodes_in_linear_time() {
        // Each `&` used to scan the rest of the text for a `;`. A debug build took 0.8 s for 128 Ki
        // of them, and about a minute for this.
        let text = "&".repeat(1 << 20);
        let started = std::time::Instant::now();
        assert_eq!(decode_html_entities(&text), text);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
}
