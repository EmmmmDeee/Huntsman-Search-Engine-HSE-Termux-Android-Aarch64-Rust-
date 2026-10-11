//! Rust source reading for the architecture tests: comments and literals blanked, the token
//! stream, and `#[cfg(test)]` items removed. Shared by `architecture_doc.rs` and
//! `architecture_boundaries.rs`, so both read production code the same way.

/// `text` with comments and string/char literals blanked to spaces (newlines kept), so a
/// `mod` line or `crate::` path inside `/* … */`, `//` or a (raw) string is not code.
/// Same scanner as `tests/dispositions.rs` on #675 (`bd363d0d`).
pub fn strip_non_code(text: &str) -> String {
    let src: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, chunk: &[char]| {
        out.extend(chunk.iter().map(|&c| if c == '\n' { '\n' } else { ' ' }));
    };
    let mut i = 0;
    while i < src.len() {
        let rest = &src[i..];
        let is_ident = |at: usize| src[at].is_alphanumeric() || src[at] == '_';
        // `r` starts a raw string unless it ends an identifier; `br` (byte raw) counts too.
        let ident_before =
            i > 0 && is_ident(i - 1) && !(src[i - 1] == 'b' && (i < 2 || !is_ident(i - 2)));
        let end = if rest.starts_with(&['/', '/']) {
            rest.iter().position(|&c| c == '\n').unwrap_or(rest.len())
        } else if rest.starts_with(&['/', '*']) {
            let (mut depth, mut j) = (0_usize, 0);
            while j < rest.len() {
                if rest[j..].starts_with(&['/', '*']) {
                    depth += 1;
                    j += 2;
                } else if rest[j..].starts_with(&['*', '/']) {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            j
        } else if rest[0] == 'r' && !ident_before && raw_string_len(rest).is_some() {
            raw_string_len(rest).unwrap()
        } else if rest[0] == '"' {
            let mut j = 1;
            while j < rest.len() && rest[j] != '"' {
                j += if rest[j] == '\\' { 2 } else { 1 };
            }
            (j + 1).min(rest.len())
        } else if rest[0] == '\'' && rest.get(1) == Some(&'\\') {
            rest.iter()
                .skip(2)
                .position(|&c| c == '\'')
                .map_or(rest.len(), |p| p + 3)
        } else if rest[0] == '\'' && rest.get(2) == Some(&'\'') {
            3
        } else {
            out.push(rest[0]);
            i += 1;
            continue;
        };
        blank(&mut out, &rest[..end]);
        i += end;
    }
    out
}

/// Length of the raw string literal (`r"…"`, `r#"…"#`, …) at the start of `rest`, if any.
pub fn raw_string_len(rest: &[char]) -> Option<usize> {
    let hashes = rest[1..].iter().take_while(|&&c| c == '#').count();
    if rest.get(1 + hashes) != Some(&'"') {
        return None;
    }
    let body = 2 + hashes;
    let close: Vec<char> = std::iter::once('"')
        .chain(std::iter::repeat_n('#', hashes))
        .collect();
    let found = (body..rest.len()).find(|&j| rest[j..].starts_with(&close));
    Some(found.map_or(rest.len(), |j| j + close.len()))
}

/// Identifiers, `::`, and single punctuation characters.
pub fn tokens(code: &str) -> Vec<String> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else if c == ':' && chars.get(i + 1) == Some(&':') {
            out.push("::".to_owned());
            i += 2;
        } else {
            out.push(c.to_string());
            i += 1;
        }
    }
    out
}

pub fn tok(toks: &[String], i: usize) -> &str {
    toks.get(i).map_or("", String::as_str)
}

/// Index just past the bracket group opened at `open`.
pub fn skip_group(toks: &[String], open: usize) -> usize {
    let mut depth = 0_usize;
    for (i, t) in toks.iter().enumerate().skip(open) {
        match t.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced brackets from token {open}")
}

pub const CFG_TEST: [&str; 7] = ["#", "[", "cfg", "(", "test", ")", "]"];

/// `toks` with every item under `#[cfg(test)]` removed, plus the names of out-of-line
/// `#[cfg(test)] mod x;` declarations it removed.
pub fn without_test_items(toks: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut out, mut test_mods) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < toks.len() {
        if !toks[i..].iter().map(String::as_str).take(7).eq(CFG_TEST) {
            out.push(toks[i].clone());
            i += 1;
            continue;
        }
        i += CFG_TEST.len();
        while tok(toks, i) == "#" && tok(toks, i + 1) == "[" {
            i = skip_group(toks, i + 1);
        }
        let start = i;
        let mut depth = 0_usize;
        loop {
            match tok(toks, i) {
                "" => panic!("unterminated #[cfg(test)] item"),
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                ";" | "," if depth == 0 => {
                    i += 1;
                    break;
                }
                "}" if depth == 0 => break,
                "{" if depth == 0 => {
                    i = skip_group(toks, i);
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        let item = &toks[start..i];
        if let Some(p) = item.iter().position(|t| t == "mod") {
            if item.len() == p + 3 && item[p + 2] == ";" {
                test_mods.push(item[p + 1].clone());
            }
        }
    }
    (out, test_mods)
}
