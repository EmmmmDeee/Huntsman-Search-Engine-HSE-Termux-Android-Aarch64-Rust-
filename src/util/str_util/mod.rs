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

/// Upper-case only the **first** character of `s`, leaving the rest of the
/// string exactly as-is. Empty input yields `""`. Character-safe: the first
/// scalar's full Unicode upper-casing is applied (so `ß` → `SS`) and the tail
/// is appended untouched, never byte-sliced.
///
/// This is deliberately **not** [`title_case`]: it preserves the remaining
/// characters' original casing rather than lower-casing them, so an
/// intentionally-cased tail survives — `"mcDonald"` → `"McDonald"`, never
/// `"Mcdonald"`. Used to display a lowercased email local-part token or a
/// permuted name component as a leading-capital word without flattening a
/// mixed-case surname. One definition so the three modules that each hand-rolled
/// this `chars().next()` capitaliser share identical semantics.
///
/// ```
/// use huntsman_search_engine::util::str_util::upper_first;
///
/// assert_eq!(upper_first("jane"), "Jane");
/// assert_eq!(upper_first("jane doe"), "Jane doe"); // only the first char
/// assert_eq!(upper_first("mcDonald"), "McDonald"); // tail casing preserved
/// assert_eq!(upper_first("ñoño"), "Ñoño"); // multibyte-safe
/// assert_eq!(upper_first(""), "");
/// ```
#[must_use]
pub fn upper_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().chain(chars).collect(),
    }
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

/// Parse an autonomous-system identifier to its numeric form, accepting an
/// optional case-insensitive `AS` prefix and surrounding whitespace:
/// `"AS13335"`, `"as13335"`, `"13335"`, `" 13335 "` all yield `Some(13335)`.
/// Returns `None` for anything that isn't `AS?<ascii-digits>`, so callers reject
/// malformed ASNs instead of building a garbage URL from them.
///
/// Single definition for the `bgpview` / `ip_registry` / `zoomeye` modules,
/// which each open-coded the prefix-strip-and-validate and drifted on case
/// handling. Re-add a textual prefix at the call site when needed
/// (`format!("AS{n}")`).
///
/// ```
/// use huntsman_search_engine::util::str_util::parse_asn;
///
/// assert_eq!(parse_asn("AS13335"), Some(13335));
/// assert_eq!(parse_asn("as13335"), Some(13335));
/// assert_eq!(parse_asn("  13335 "), Some(13335));
/// assert_eq!(parse_asn("ASN13335"), None); // only a bare `AS` prefix is shed
/// assert_eq!(parse_asn("13335x"), None);
/// ```
#[must_use]
pub fn parse_asn(s: &str) -> Option<u64> {
    let t = s.trim();
    let digits = match t.get(..2) {
        Some(p) if p.eq_ignore_ascii_case("AS") => t[2..].trim(),
        _ => t,
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// True if `s` is a plausible platform handle: its length is in `min..=max` and
/// every character is ASCII-alphanumeric or `-`/`_`. The shared pre-flight
/// `reddit_user` and `hacker_news` gate on before spending an HTTP round-trip —
/// pass each platform's own length bounds. (Byte length equals char count here:
/// the charset test rejects any non-ASCII character.)
///
/// ```
/// use huntsman_search_engine::util::str_util::is_handle;
///
/// assert!(is_handle("spez", 3, 20));
/// assert!(is_handle("pg", 2, 15));
/// assert!(!is_handle("a", 2, 15)); // too short
/// assert!(!is_handle("has space", 2, 15)); // bad charset
/// assert!(!is_handle("toolongggg", 2, 8)); // too long
/// ```
#[must_use]
pub fn is_handle(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
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

/// Mask a secret (API key, token, password) for display: a 4+4 head/tail hint
/// for a value long enough that 8 exposed characters are a small fraction,
/// full masking otherwise. The single-sourced policy for every UI that shows a
/// stored secret (the CLI's `hse keys` bank and the web dashboard's key-pool
/// view) — the two independently reimplemented this at one point and drifted:
/// one used an `> 8` threshold (revealing 8 of an unmasked 9-char key, or ALL
/// of one ≤ 8 chars), the other correctly used `< 16`. Below 16 chars, `head +
/// tail` would leave less than half the value hidden, so the value is fully
/// masked instead — the hint is only a recognition aid, never enough to help
/// reconstruct the secret.
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
    // Only an offset whose byte equals the needle's first byte (in either ASCII
    // case) can begin a match, so jump straight to those candidates with a SIMD
    // byte search (NEON on Termux aarch64) instead of running `eq_ignore_ascii_case`
    // at every offset — the naive scan's cost. `memchr` yields candidates in
    // ascending order, so `.find` still returns the lowest matching offset,
    // preserving the exact contract. `search` is bounded so a candidate always has
    // room for the whole needle; `hb[i..i + nb.len()]` therefore never overruns.
    let last = hb.len() - nb.len();
    let search = &hb[..=last];
    let n0 = nb[0];
    let verify = |i: usize| hb[i..i + nb.len()].eq_ignore_ascii_case(nb);
    let (lo, hi) = (n0.to_ascii_lowercase(), n0.to_ascii_uppercase());
    if lo == hi {
        // Caseless first byte (digit, punctuation, or non-ASCII): one byte class.
        memchr::memchr_iter(n0, search).find(|&i| verify(i))
    } else {
        // ASCII letter: match either case of the first byte in a single pass.
        memchr::memchr2_iter(lo, hi, search).find(|&i| verify(i))
    }
}

/// Byte offset of the **last** whole-word ASCII-case-insensitive occurrence of
/// `needle` in `haystack`, or `None`. "Whole word" means the match is bounded on
/// both sides by a non-ASCII-alphanumeric byte (or a string edge), so a needle
/// embedded inside a longer word never matches: the `WA` inside `EDWARD`, the
/// `SA` inside `SARAH`. The offset indexes the **original** `haystack` and always
/// lands on a `char` boundary (both the ASCII needle bytes and the single-byte
/// boundary tests can only fall on ASCII positions).
///
/// This is the whole-word counterpart to [`find_ascii_ci`], which returns the
/// first *substring* match. Use it when a short ASCII token (an AU state code, a
/// unit abbreviation) must be located as a standalone word rather than wherever
/// its letters first appear inside another word. The **last** occurrence is
/// returned so an address scan anchors on the state token nearest the trailing
/// postcode instead of a coincidental earlier one (an owner name that happens to
/// contain the code as a whole word).
///
/// ```
/// use huntsman_search_engine::util::str_util::rfind_word_ascii_ci;
///
/// // Embedded-in-a-word matches are rejected; the standalone token wins.
/// assert_eq!(rfind_word_ascii_ci("EDWARD COTTESLOE WA 6011", "WA"), Some(17));
/// // No standalone occurrence → None (only the `SA` inside `SARAH`).
/// assert_eq!(rfind_word_ascii_ci("SARAH SMITH", "SA"), None);
/// // Case-insensitive, and the LAST standalone token is returned.
/// assert_eq!(rfind_word_ascii_ci("wa depot WA", "wa"), Some(9));
/// assert_eq!(rfind_word_ascii_ci("", "wa"), None);
/// ```
#[must_use]
pub fn rfind_word_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let (hb, nb) = (haystack.as_bytes(), needle.as_bytes());
    if nb.is_empty() || hb.len() < nb.len() {
        return None;
    }
    let is_word = u8::is_ascii_alphanumeric;
    (0..=hb.len() - nb.len()).rev().find(|&i| {
        hb[i..i + nb.len()].eq_ignore_ascii_case(nb)
            && (i == 0 || !is_word(&hb[i - 1]))
            && (i + nb.len() == hb.len() || !is_word(&hb[i + nb.len()]))
    })
}

/// True when **every** alphanumeric token of `needle` appears as a WHOLE WORD
/// in `haystack`, compared ASCII-case-insensitively. Both sides tokenise on
/// non-alphanumeric boundaries; an empty `needle` (no tokens) matches nothing.
///
/// Whole-word — not substring — is the whole point: it stops a short query token
/// like `"red"` matching inside `"Mildred"`, or a seed initial `"M"` matching
/// inside `"SMITH"` — the false "this relative is the subject" upgrades a
/// substring gate produces. Allocation-free per token (`eq_ignore_ascii_case`,
/// no lower-cased copies). Single-sourced so every register/name matcher
/// (`au_unclaimed`, `wikidata`, `acnc_charities`, `gleif_lei`) shares one
/// definition instead of four hand-rolled copies drifting apart.
///
/// ```
/// use huntsman_search_engine::util::str_util::whole_word_token_match;
///
/// assert!(whole_word_token_match("Linus Torvalds", "linus torvalds"));
/// assert!(whole_word_token_match("The Smith Family", "smith family"));
/// assert!(!whole_word_token_match("Mildred Smith", "red")); // not a whole word
/// assert!(!whole_word_token_match("Linus Torvalds", "linus pauling")); // missing token
/// assert!(!whole_word_token_match("anything at all", "")); // empty needle matches nothing
/// ```
#[must_use]
pub fn whole_word_token_match(haystack: &str, needle: &str) -> bool {
    let words: Vec<&str> = haystack
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let tokens: Vec<&str> = needle
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// Minimum token length [`shares_whole_word_token`] considers a *name* rather
/// than a bare initial: `"M"` in `"M MCLOUGHLIN"` must not license a match
/// against an unrelated `"M SMITH"`.
pub const MIN_SHARED_TOKEN: usize = 2;

/// True when **at least one** alphanumeric token of `needle` (of at least
/// [`MIN_SHARED_TOKEN`] chars) appears as a WHOLE WORD in `haystack`.
///
/// The permissive counterpart to [`whole_word_token_match`]: that one answers
/// *"is this row the seeded subject?"* (every token must land), this one answers
/// *"did this row match on the field we meant at all?"* (any real token will do).
///
/// # Why a floor gate exists at all
/// CKAN's `datastore_search?q=` — behind every `util::ckan` register lookup — is
/// a **full-text search across every column**, not a scoped name lookup. A query
/// for `"shop"` also returns rows whose *address* reads `"Shop 4, 123 Main St"`
/// (ubiquitous in Australian retail), and a query containing `"Sydney"` matches
/// every row whose `Town_City` is Sydney. Those rows come back with a name that
/// shares nothing with the seed, so emitting them attributes unrelated real
/// parties — and their PII — to the subject. Callers use this to drop rows that
/// matched some *other* column, while still keeping genuine partial name matches
/// (a surname-only relative, a charity sharing one name word) that the stricter
/// all-tokens predicate would wrongly reject.
///
/// ```
/// use huntsman_search_engine::util::str_util::shares_whole_word_token;
///
/// // Genuine partial name matches survive.
/// assert!(shares_whole_word_token("Marshall Family Foundation", "smith family"));
/// assert!(shares_whole_word_token("JUNES CARD & GIFT SHOP", "shop"));
/// // A row that matched on some other column shares nothing.
/// assert!(!shares_whole_word_token("Gavin Williams", "shop"));
/// // Whole word, not substring.
/// assert!(!shares_whole_word_token("Mildred Trust", "red"));
/// // A bare initial is not a name token.
/// assert!(!shares_whole_word_token("M Smith", "M Mcloughlin"));
/// // An empty or initials-only needle matches nothing.
/// assert!(!shares_whole_word_token("anything at all", ""));
/// ```
#[must_use]
pub fn shares_whole_word_token(haystack: &str, needle: &str) -> bool {
    let words: Vec<&str> = haystack
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    needle
        .split(|c: char| !c.is_alphanumeric())
        // Chars, not bytes: a single non-ASCII initial is 2+ bytes and would
        // otherwise pass the floor meant to exclude bare initials.
        .filter(|t| t.chars().count() >= MIN_SHARED_TOKEN)
        .any(|tok| words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
