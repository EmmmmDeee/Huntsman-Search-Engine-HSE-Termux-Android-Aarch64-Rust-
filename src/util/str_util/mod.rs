/// A trimmed, non-empty borrow of an optional string field, else `None`.
/// Whitespace-only is treated as absent. Single definition so the many OSINT
/// modules that surface "the value if the upstream actually sent one" share
/// identical semantics instead of each re-deriving them.
///
/// ```
/// use huntsman_search_engine::util::str_util::nonempty;
///
/// assert_eq!(nonempty(&Some("  hi ".to_string())), Some("hi")); // trimmed
/// assert_eq!(nonempty(&Some("   ".to_string())), None);          // blank → absent
/// assert_eq!(nonempty(&None), None);
/// ```
#[must_use]
pub fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Title-case a personal name into a canonical, merge-stable `Person` value:
/// each whitespace token is lower-cased then its first character upper-cased,
/// and runs of whitespace collapse to one space. `Person` values are NOT
/// case-folded at UID normalisation, so a register's `ERIK DIEGMANN`, a scraped
/// `erik diegmann`, and `name_intel`'s parsed anchor would otherwise fragment
/// into three separate people; routing every module-minted name through this
/// converges them onto one node (matching `name_intel`'s own lower-then-cap
/// casing, so the subject anchor and discovered relatives share UIDs).
///
/// ```
/// use huntsman_search_engine::util::str_util::title_case;
///
/// assert_eq!(title_case("ERIK DIEGMANN"), "Erik Diegmann");
/// assert_eq!(title_case("  kyle   diegmann "), "Kyle Diegmann");
/// assert_eq!(title_case(""), "");
/// ```
#[must_use]
pub fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for word in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            for c in chars {
                out.extend(c.to_lowercase());
            }
        }
    }
    out
}

/// The ASCII digits of `s`, in order, with every other character dropped.
/// One definition of "keep only the digits" for phone / ABN / ACN / LEI
/// normalisation (was re-derived inline in ~9 places).
///
/// ```
/// use huntsman_search_engine::util::str_util::ascii_digits;
///
/// assert_eq!(ascii_digits("+61 (2) 9374-4000"), "61293744000");
/// assert_eq!(ascii_digits("no digits here"), "");
/// ```
#[must_use]
pub fn ascii_digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// Round `i` **down** to the nearest UTF-8 character boundary of `s` (the start
/// of the character `i` falls inside), clamped to `s.len()`. The canonical
/// safe-slicing primitive for a *start* offset or a length cap:
/// `&s[..floor_char_boundary(s, i)]` is valid — never panics — for any `i`.
///
/// A free-function stand-in for the still-unstable `str::floor_char_boundary`,
/// so it is usable at this crate's MSRV and shared by every module that slices
/// scraped text at an arithmetic byte offset.
///
/// ```
/// use huntsman_search_engine::util::str_util::floor_char_boundary;
///
/// let s = "aébc"; // bytes: a=0, é=1..3, b=3, c=4, len=5
/// assert_eq!(floor_char_boundary(s, 2), 1);  // inside 'é' → back to its start
/// assert_eq!(floor_char_boundary(s, 3), 3);  // already a boundary
/// assert_eq!(floor_char_boundary(s, 99), 5); // past the end → len
/// ```
#[must_use]
pub fn floor_char_boundary(s: &str, i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    let mut i = i;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Round `i` **up** to the nearest UTF-8 character boundary of `s` (the start of
/// the next character when `i` lands mid-character), clamped to `s.len()`. The
/// canonical safe-slicing primitive for an *end* offset: a `floor_char_boundary`
/// start paired with a `ceil_char_boundary` end makes any arithmetic byte window
/// (`pos ± N` into scraped HTML) total — the worst case is a window a byte or
/// two off, never a panic.
///
/// A free-function stand-in for the still-unstable `str::ceil_char_boundary`,
/// usable at this crate's MSRV.
///
/// ```
/// use huntsman_search_engine::util::str_util::ceil_char_boundary;
///
/// let s = "aébc"; // bytes: a=0, é=1..3, b=3, c=4, len=5
/// assert_eq!(ceil_char_boundary(s, 2), 3);  // inside 'é' → forward to 'b'
/// assert_eq!(ceil_char_boundary(s, 1), 1);  // already a boundary
/// assert_eq!(ceil_char_boundary(s, 99), 5); // past the end → len
/// ```
#[must_use]
pub fn ceil_char_boundary(s: &str, i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    let mut i = i;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Borrow the longest prefix of `s` that is at most `max` bytes and ends on a
/// UTF-8 character boundary. Zero-copy — caps oversized fields (key fragments,
/// scraped summaries) without ever risking the panic of a raw `&s[..max]`.
///
/// # Guarantees
/// - **Prefix:** `s.starts_with(truncate_safe(s, max))`.
/// - **Bounded:** `truncate_safe(s, max).len() <= max`.
/// - **Lossless when it fits:** if `s.len() <= max`, the whole of `s` is
///   returned.
/// - **Never splits a code point**, so the result is always valid UTF-8;
///   **total** — never panics, for any `s` and any `max` (including `0`).
///
/// ```
/// use huntsman_search_engine::util::str_util::truncate_safe;
///
/// assert_eq!(truncate_safe("hello", 3), "hel");    // ASCII exact cut
/// assert_eq!(truncate_safe("hello", 99), "hello"); // fits → whole string
/// assert_eq!(truncate_safe("", 0), "");
/// // `max` lands inside the 2-byte 'é' (bytes 1..3) → backs off to "a".
/// assert_eq!(truncate_safe("aébc", 2), "a");
/// ```
#[must_use]
pub fn truncate_safe(s: &str, max: usize) -> &str {
    &s[..floor_char_boundary(s, max)]
}

/// A byte-offset substring window that can never panic on a multibyte boundary.
///
/// Direct `&s[start..end]` slicing panics when `start`/`end` fall inside a
/// multibyte UTF-8 character — exactly the hazard when slicing scraped HTML at
/// *arithmetic* offsets like `pos ± N` (a postcode position widened by 60, an
/// HTML marker offset widened by 300). Real web pages routinely carry multibyte
/// bytes (accented names, typographic quotes, NBSP), so such offsets land
/// mid-character. This clamps both ends to the nearest valid char boundary
/// (rounding inward), bounded by `s.len()`, and guarantees `start <= end` — so
/// the worst case is a window a byte or two narrower than requested, never a
/// panic.
///
/// ```
/// use huntsman_search_engine::util::str_util::char_window;
///
/// let s = "aébc"; // bytes: a=0, é=1..3, b=3, c=4, len=5
/// assert_eq!(char_window(s, 0, 5), "aébc"); // whole string
/// // end=2 is inside 'é' → rounds up to 3; start=1 is a boundary → "é".
/// assert_eq!(char_window(s, 1, 2), "é");
/// // start=2 is inside 'é' → rounds up to 3 → "bc"; end past len clamps to len.
/// assert_eq!(char_window(s, 2, 999), "bc");
/// assert_eq!(char_window(s, 999, 999), "");
/// ```
#[must_use]
pub fn char_window(s: &str, start: usize, end: usize) -> &str {
    // Round the start *up* and the end *up*, then keep `end >= start`: a window
    // that never splits a code point and never inverts.
    let a = ceil_char_boundary(s, start);
    let b = ceil_char_boundary(s, end).max(a);
    &s[a..b]
}

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
/// use huntsman_search_engine::util::str_util::fold_ascii_lower;
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

/// URL/tag-safe slug: lowercase **ASCII** alphanumeric runs joined by single `-`,
/// with leading and trailing `-` stripped. Every other character — spaces, dots,
/// underscores, AND non-ASCII letters/digits (`é`, `¹`, `Ⅳ`, fullwidth digits) —
/// is collapsed into a single dash separator. The output is therefore always pure
/// `[a-z0-9-]`: a slug feeds correlation **tags** (`niamonx:breach:{slug}`,
/// `status:{slug}`), so two inputs differing only in the case/accent of a
/// non-ASCII letter must not yield different tags, and a tag must never carry a
/// raw uppercase-accented byte. (Using `char::is_alphanumeric` +
/// `to_ascii_lowercase` did exactly that — `to_ascii_lowercase` is a no-op on
/// non-ASCII, so `slugify("É")` leaked `"É"`.)
///
/// ```
/// use huntsman_search_engine::util::str_util::slugify;
///
/// assert_eq!(slugify("Hello World"), "hello-world");
/// assert_eq!(slugify("github.com"), "github-com");
/// assert_eq!(slugify("---"), "");
/// assert_eq!(slugify("client transfer prohibited"), "client-transfer-prohibited");
/// assert_eq!(slugify("café¹"), "caf"); // non-ASCII → separator, trailing dash stripped
/// ```
#[must_use]
pub fn slugify(s: &str) -> String {
    let mut slug = String::with_capacity(s.len());
    let mut last_dash = true;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }
    if slug.ends_with('-') {
        slug.pop();
    }
    slug
}

/// Char-boundary-safe truncation that appends `…` when the string exceeds
/// `max_chars`. Uses char count, not byte length, so multibyte characters
/// are never split.
///
/// ```
/// use huntsman_search_engine::util::str_util::truncate_display;
///
/// assert_eq!(truncate_display("hello", 10), "hello");
/// assert_eq!(truncate_display("hello world", 5), "hello…");
/// ```
#[must_use]
pub fn truncate_display(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// Byte offset of the first ASCII-case-insensitive occurrence of `needle` in
/// `haystack`, or `None`. The offset indexes the **original** `haystack`, so
/// `haystack[off..]` and `haystack[..off]` are always on a `char` boundary (a
/// match can only land on ASCII bytes). Use this instead of
/// `haystack.to_lowercase().find(needle)` followed by slicing the original:
/// `to_lowercase` is not byte-length-preserving (`İ` → `i̇`, `ẞ` → `ß`), so an
/// offset taken from the lowercased copy can land mid-codepoint in the original
/// and panic. `needle` is matched ASCII-case-insensitively; a non-ASCII byte
/// never matches an ASCII needle byte.
#[must_use]
pub fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let (hb, nb) = (haystack.as_bytes(), needle.as_bytes());
    if nb.is_empty() {
        return Some(0);
    }
    if hb.len() < nb.len() {
        return None;
    }
    (0..=hb.len() - nb.len()).find(|&i| hb[i..i + nb.len()].eq_ignore_ascii_case(nb))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
