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

/// Fold a Latin-ish string to lowercase ASCII `[a-z0-9]`, dropping the rest.
#[must_use]
pub fn fold_ascii_lower(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            'a'..='z' | '0'..='9' => out.push(ch),
            'A'..='Z' => out.push(ch.to_ascii_lowercase()),
            'à'
            | 'á'
            | 'â'
            | 'ã'
            | 'ä'
            | 'å'
            | 'À'
            | 'Á'
            | 'Â'
            | 'Ã'
            | 'Ä'
            | 'Å'
            | 'ā'
            | 'ă'
            | 'ą'
            | '\u{1EA0}'..='\u{1EB7}' => out.push('a'),
            'ç' | 'Ç' | 'ć' | 'č' | 'ĉ' | 'ċ' => out.push('c'),
            'è' | 'é' | 'ê' | 'ë' | 'È' | 'É' | 'Ê' | 'Ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' =>
            {
                out.push('e');
            }
            'ì' | 'í' | 'î' | 'ï' | 'Ì' | 'Í' | 'Î' | 'Ï' | 'ī' | 'ĭ' | 'į' | 'ı' | 'ĩ' | 'Ĩ' =>
            {
                out.push('i');
            }
            'ñ' | 'Ñ' | 'ń' | 'ņ' | 'ň' => out.push('n'),
            'ò'
            | 'ó'
            | 'ô'
            | 'õ'
            | 'ö'
            | 'ø'
            | 'Ò'
            | 'Ó'
            | 'Ô'
            | 'Õ'
            | 'Ö'
            | 'Ø'
            | 'ō'
            | 'ŏ'
            | 'ő'
            | 'ơ'
            | 'Ơ'
            | '\u{1ECC}'..='\u{1EE3}' => out.push('o'),
            'ù'
            | 'ú'
            | 'û'
            | 'ü'
            | 'Ù'
            | 'Ú'
            | 'Û'
            | 'Ü'
            | 'ū'
            | 'ŭ'
            | 'ů'
            | 'ű'
            | 'ų'
            | 'ư'
            | 'Ư'
            | '\u{1EE4}'..='\u{1EF1}' => out.push('u'),
            'ý' | 'ÿ' | 'Ý' | 'Ŷ' | 'ŷ' | '\u{1EF2}'..='\u{1EF9}' => out.push('y'),
            'ł' | 'Ł' => out.push('l'),
            'ś' | 'š' | 'ş' | 'Ś' | 'Š' | 'Ş' | 'ѕ' => out.push('s'),
            'ź' | 'ż' | 'ž' | 'Ź' | 'Ż' | 'Ž' => out.push('z'),
            'ð' | 'Đ' | 'đ' => out.push('d'),
            'ț' | 'ţ' | 'Ț' | 'Ţ' => out.push('t'),
            'ğ' | 'Ğ' => out.push('g'),
            'ř' | 'Ř' => out.push('r'),
            '\u{1EB8}'..='\u{1EC7}' => out.push('e'),
            '\u{1EC8}'..='\u{1ECB}' => out.push('i'),
            'æ' | 'Æ' => out.push_str("ae"),
            'œ' | 'Œ' => out.push_str("oe"),
            'ß' => out.push_str("ss"),
            'þ' | 'Þ' => out.push_str("th"),
            _ => {}
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
        assert_eq!(fold_ascii_lower("José Müller"), "josemuller");
        assert_eq!(fold_ascii_lower("Nguyễn"), "nguyen");
        assert_eq!(fold_ascii_lower("Straße"), "strasse");
        assert_eq!(
            slugify("client transfer prohibited"),
            "client-transfer-prohibited"
        );
        assert_eq!(slugify("café¹"), "caf");
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
}
