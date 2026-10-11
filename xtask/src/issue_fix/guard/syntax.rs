//! Reads one file for the path guard. A Rust file must parse with syn: a file that does not parse
//! is refused, never skipped. Test markers, inner cfg attributes, include! sites, and the
//! constructs that reach other code are read from the token stream, so a spacing variant or a
//! construct inside a macro body counts the same as plain code, and a marker in a string literal
//! does not count. A commented-out test is still a test: deleting the delimiters of a block
//! comment, or the `//` of a line comment, activates it. So a marker in a block comment counts
//! anywhere in the comment, and a marker in a line comment counts when the comment's text starts
//! with it. Module declarations come from the syntax tree, because their attributes and their
//! inline nesting decide which file they load. A module declaration that the syntax tree does not
//! give (inside a macro's tokens, inside a comment, or in a file that is not read as Rust) is
//! recorded by its line, so the guard can refuse it.

use proc_macro2::{Delimiter, Group, Ident, Punct, Span, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ItemMod, Lit, LitStr, Meta};

/// Everything the guard reads from one file.
#[derive(Debug, Default)]
pub struct FileFacts {
    /// The first line of test code, or 0 when there is none. The first test marker starts it at
    /// the first outer attribute of its run, because an attribute belongs to the item after it. A
    /// marker in a comment starts it at the line of that marker.
    pub start: usize,
    /// The lines where a marker of the token walk starts: the first attribute of each run of
    /// outer attributes that names test. Each marker counts once for every marker attribute in its
    /// run, which is harmless, since only the lines are compared.
    pub token_markers: Vec<usize>,
    /// The lines of the markers that the comments of the file hold, as `comment_facts` finds them.
    pub comment_markers: Vec<usize>,
    /// The text nests its brackets deeper than `MAX_NESTING`, so it was not read, and every other
    /// field is empty. `read_text_checked` refuses such a text.
    pub too_deep: bool,
    /// The file has an inner `#![cfg(...)]` that names test. Every line of such a file is test
    /// code.
    pub inner_cfg_test: bool,
    /// The out-of-line module declarations, `mod NAME;`, in source order. Empty when the file is
    /// not read with its syntax tree.
    pub mods: Vec<ModDecl>,
    /// The include! macro calls, in source order.
    pub includes: Vec<Include>,
    /// The constructs that reach code beyond their own lines: a macro definition, a path,
    /// macro_use, or macro_export attribute, and an include! call.
    pub scope_constructs: Vec<Construct>,
    /// The cfg attributes, extern crate items, and import aliases.
    pub cfg_constructs: Vec<Construct>,
    /// The lines of `mod NAME;` text that `mods` does not give: inside a macro's tokens, inside a
    /// comment, or in a file that is not read with its syntax tree.
    pub unfollowed_mods: Vec<usize>,
}

impl FileFacts {
    /// The texts of the scope constructs, and of the cfg constructs when CFG is set.
    pub fn construct_texts(&self, cfg: bool) -> Vec<&str> {
        let scope = self
            .scope_constructs
            .iter()
            .map(|construct| construct.text.as_str());
        let cfg_texts = self
            .cfg_constructs
            .iter()
            .filter(|_| cfg)
            .map(|construct| construct.text.as_str());
        scope.chain(cfg_texts).collect()
    }
}

/// One construct of a file: its first and last lines, and its tokens as text. The text does not
/// depend on the lines, so a construct that moves reads the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Construct {
    /// The line where the construct starts.
    pub first: usize,
    /// The line where the construct ends.
    pub last: usize,
    /// The tokens of the construct, with spacing normalized.
    pub text: String,
}

/// One out-of-line module declaration.
#[derive(Debug)]
pub struct ModDecl {
    /// The name of the module, without a raw identifier's `r#`, since the file name has none.
    pub name: String,
    /// The line of the `mod` keyword.
    pub line: usize,
    /// The path attribute of the declaration, if it has one.
    pub path: PathAttr,
    /// The names of the inline modules that enclose the declaration, outermost first.
    pub inline: Vec<String>,
    /// True when an enclosing inline module carries a path attribute, which the guard does not
    /// follow.
    pub unsupported_nesting: bool,
}

/// The path attribute of a module declaration.
#[derive(Debug, PartialEq, Eq)]
pub enum PathAttr {
    /// No path attribute: the module loads from its name.
    None,
    /// A path attribute whose value is a string literal.
    Literal(String),
    /// A path attribute the guard cannot read (not a string literal, repeated, or inside a
    /// cfg_attr). The module may load any file.
    Unsupported,
}

/// One include! call. The path is None when the argument is not a single string literal.
#[derive(Debug)]
pub struct Include {
    /// The line of the `include` name.
    pub line: usize,
    /// The file that the call names, as written.
    pub path: Option<String>,
}

/// Reads TEXT as a Rust file, which must parse. The error is a reason for a person.
pub fn read(text: &str) -> Result<FileFacts, String> {
    check_nesting(text)?;
    let file = syn::parse_file(text).map_err(|error| error.to_string())?;
    let tokens: TokenStream = text.parse().map_err(|error| format!("{error}"))?;
    let mut scan = Scan::default();
    scan.stream(tokens, false);
    let mut facts = scan.into_facts(text);
    let mut mods = Mods::default();
    mods.visit_file(&file);
    facts.mods = mods.decls;
    Ok(facts)
}

/// Reads TEXT as a file that is not read with its syntax tree, which is any file that is not Rust
/// source. It has no module declarations that the guard follows, so every `mod NAME;` in it is
/// unfollowed. A text that does not lex has only the markers in its comments. A text nested deeper
/// than `MAX_NESTING` is not walked: its facts are empty, with `too_deep` set.
pub fn read_text(text: &str) -> FileFacts {
    if bracket_depth(text) > MAX_NESTING {
        return FileFacts {
            too_deep: true,
            ..FileFacts::default()
        };
    }
    let mut scan = Scan::default();
    if let Ok(tokens) = text.parse::<TokenStream>() {
        scan.stream(tokens, true);
    }
    scan.into_facts(text)
}

/// `read_text` for a file that the guard must read. A text nested deeper than `MAX_NESTING` is an
/// error, which refuses the change with a message.
pub fn read_text_checked(text: &str) -> Result<FileFacts, String> {
    let facts = read_text(text);
    if facts.too_deep {
        return Err(nesting_error());
    }
    Ok(facts)
}

/// The deepest bracket nesting that the guard reads. The token walk, the syntax tree, and the drop
/// of a token stream recurse once per level, so a file nested more deeply would overflow the stack
/// and abort the process. A file nested deeper than this is refused with a message instead.
pub const MAX_NESTING: usize = 128;

/// The reason for refusing a file nested deeper than `MAX_NESTING`.
fn nesting_error() -> String {
    format!("its brackets nest more than {MAX_NESTING} levels deep, which the guard does not read")
}

/// Refuses TEXT when its brackets nest deeper than `MAX_NESTING`.
fn check_nesting(text: &str) -> Result<(), String> {
    if bracket_depth(text) > MAX_NESTING {
        return Err(nesting_error());
    }
    Ok(())
}

/// The deepest nesting of brackets in code. Strings, character literals and comments are skipped
/// the way `comments` skips them, so a bracket inside one of them does not count. The walk is
/// iterative, so it cannot overflow the stack whatever the depth.
fn bracket_depth(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut deepest = 0usize;
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        at = match byte {
            b'/' if bytes.get(at + 1) == Some(&b'/') => bytes[at..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |offset| at + offset),
            b'/' if bytes.get(at + 1) == Some(&b'*') => block_end(bytes, at + 2).1,
            b'"' => string_end(bytes, at + 1),
            b'\'' => char_end(bytes, at),
            b'r' => raw_string_end(bytes, at).unwrap_or(at + 1),
            b'(' | b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
                at + 1
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                at + 1
            }
            _ => at + 1,
        };
    }
    deepest
}

/// The facts that the token walk collects.
#[derive(Default)]
struct Scan {
    markers: Vec<usize>,
    inner_cfg_test: bool,
    includes: Vec<Include>,
    scope_constructs: Vec<Construct>,
    cfg_constructs: Vec<Construct>,
    unfollowed_mods: Vec<usize>,
}

impl Scan {
    /// Walks every token of STREAM, and of every group inside it, in source order. IN_MACRO is set
    /// inside the tokens of a macro, which the syntax tree does not give.
    fn stream(&mut self, stream: TokenStream, in_macro: bool) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        let mut at = 0;
        // The line where the run of outer attributes starts, when the token before AT is an outer
        // attribute of such a run. An attribute belongs to the item that follows it, so the test
        // code of a marker starts at the first attribute of its run.
        let mut run: Option<usize> = None;
        while let Some(tree) = trees.get(at) {
            let carried = run.take();
            let consumed = match tree {
                TokenTree::Punct(punct) if punct.as_char() == '#' => {
                    let first = carried.unwrap_or_else(|| line(punct.span()));
                    let (consumed, outer) = self.attribute(&trees, at, punct, first, in_macro);
                    if outer {
                        run = Some(first);
                    }
                    consumed
                }
                TokenTree::Ident(ident) => {
                    self.word(&trees, at, ident, in_macro);
                    1
                }
                TokenTree::Group(group) => {
                    self.stream(group.stream(), in_macro || is_macro_body(&trees, at));
                    1
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => 1,
            };
            at += consumed;
        }
    }

    /// Reads the attribute whose `#` is at AT, when its run of outer attributes starts at line
    /// FIRST. Returns the number of tokens that the attribute spans, and whether it is an outer
    /// attribute.
    fn attribute(
        &mut self,
        trees: &[TokenTree],
        at: usize,
        hash: &Punct,
        first: usize,
        in_macro: bool,
    ) -> (usize, bool) {
        let inner = is_punct(trees.get(at + 1), '!');
        let open = if inner { at + 2 } else { at + 1 };
        let Some(TokenTree::Group(group)) = trees.get(open) else {
            return (1, false);
        };
        if group.delimiter() != Delimiter::Bracket {
            return (1, false);
        }
        let facts = AttrFacts::read(group);
        if inner {
            if facts.cfg_test {
                self.inner_cfg_test = true;
            }
        } else if facts.marker {
            self.markers.push(first);
        }
        if facts.cfg_like {
            let construct = construct(trees, at, open, hash.span(), group.span_close());
            self.cfg_constructs.push(construct);
        }
        if facts.path_like {
            let construct = construct(trees, at, open, hash.span(), group.span_close());
            self.scope_constructs.push(construct);
        }
        self.stream(group.stream(), in_macro);
        (open + 1 - at, !inner)
    }

    /// Reads the word IDENT, at AT: a macro definition, an include! call, an extern crate item, an
    /// import alias, or a module declaration inside a macro.
    fn word(&mut self, trees: &[TokenTree], at: usize, ident: &Ident, in_macro: bool) {
        let next = trees.get(at + 1);
        match ident.to_string().as_str() {
            "macro_rules" if is_punct(next, '!') => {
                let (through, last) = first_group(trees, at + 2).unwrap_or((at + 1, ident.span()));
                self.scope_constructs
                    .push(construct(trees, at, through, ident.span(), last));
            }
            "include" if is_punct(next, '!') => self.include(trees, at, ident),
            "extern" if is_ident(next, "crate") => {
                let end = semicolon_index(trees, at + 2).unwrap_or(at + 1);
                let last = trees.get(end).map_or(ident.span(), TokenTree::span);
                self.cfg_constructs
                    .push(construct(trees, at, end, ident.span(), last));
            }
            "use" => {
                let end = semicolon_index(trees, at + 1).unwrap_or(trees.len());
                let rest = trees.get(at + 1..end).unwrap_or_default();
                if rest.iter().any(contains_as) {
                    let last = trees.get(end).map_or(ident.span(), TokenTree::span);
                    self.cfg_constructs
                        .push(construct(trees, at, end, ident.span(), last));
                }
            }
            "mod"
                if in_macro
                    && matches!(next, Some(TokenTree::Ident(_)))
                    && is_punct(trees.get(at + 2), ';') =>
            {
                self.unfollowed_mods.push(line(ident.span()));
            }
            _ => {}
        }
    }

    /// Records the include! call whose name is at AT.
    fn include(&mut self, trees: &[TokenTree], at: usize, ident: &Ident) {
        let name = line(ident.span());
        match trees.get(at + 2) {
            Some(TokenTree::Group(group)) => {
                let path = include_path(group);
                let construct = construct(trees, at, at + 2, ident.span(), group.span_close());
                self.scope_constructs.push(construct);
                self.includes.push(Include { line: name, path });
            }
            _ => self.includes.push(Include {
                line: name,
                path: None,
            }),
        }
    }

    /// The facts of the tokens, together with the markers and the module declarations in the
    /// block comments of TEXT.
    fn into_facts(self, text: &str) -> FileFacts {
        let (comment_markers, comment_mods) = comment_facts(text);
        let start = self
            .markers
            .iter()
            .chain(&comment_markers)
            .min()
            .copied()
            .unwrap_or(0);
        let mut unfollowed_mods = self.unfollowed_mods;
        unfollowed_mods.extend(comment_mods);
        FileFacts {
            start,
            token_markers: self.markers,
            comment_markers,
            too_deep: false,
            inner_cfg_test: self.inner_cfg_test,
            mods: Vec::new(),
            includes: self.includes,
            scope_constructs: self.scope_constructs,
            cfg_constructs: self.cfg_constructs,
            unfollowed_mods,
        }
    }
}

/// What one attribute means to the guard.
struct AttrFacts {
    /// The attribute marks test code: a cfg or cfg_attr that names test, or a test attribute
    /// such as `#[test]`, `#[tokio::test]`, `#[test_case]`, or `#[rstest]`.
    marker: bool,
    /// The attribute is an inner `cfg` that names test.
    cfg_test: bool,
    /// The attribute is a cfg or cfg_attr, of any predicate.
    cfg_like: bool,
    /// The attribute names `path`, `macro_use`, or `macro_export`.
    path_like: bool,
}

impl AttrFacts {
    /// Reads the tokens inside the brackets of an attribute.
    fn read(group: &Group) -> Self {
        let trees: Vec<TokenTree> = group.stream().into_iter().collect();
        let mut segments = Vec::new();
        for tree in &trees {
            match tree {
                TokenTree::Ident(ident) => segments.push(ident.to_string()),
                TokenTree::Punct(punct) if punct.as_char() == ':' => {}
                _ => break,
            }
        }
        let first = segments.first().map_or("", String::as_str);
        let mentions_test = any_token(group.stream(), &|tree| match tree {
            TokenTree::Ident(ident) => ident.to_string().contains("test"),
            TokenTree::Literal(literal) => literal.to_string().contains("test"),
            _ => false,
        });
        let is_cfg = first == "cfg" || first == "cfg_attr";
        let marker = if is_cfg {
            mentions_test
        } else {
            segments.iter().any(|segment| is_test_name(segment))
        };
        Self {
            marker,
            cfg_test: first == "cfg" && mentions_test,
            cfg_like: first.starts_with("cfg"),
            path_like: any_token(group.stream(), &|tree| {
                matches!(tree, TokenTree::Ident(ident)
                    if ident == "path" || ident == "macro_use" || ident == "macro_export")
            }),
        }
    }
}

/// True when NAME is the last part of a test attribute: `test`, a name ending in `test` or
/// `test_case`, or a name that starts with `rstest`.
fn is_test_name(name: &str) -> bool {
    name.ends_with("test") || name.ends_with("test_case") || name.starts_with("rstest")
}

/// True when some token of STREAM, at any depth, satisfies PREDICATE.
fn any_token(stream: TokenStream, predicate: &dyn Fn(&TokenTree) -> bool) -> bool {
    stream.into_iter().any(|tree| {
        predicate(&tree)
            || match &tree {
                TokenTree::Group(group) => any_token(group.stream(), predicate),
                _ => false,
            }
    })
}

/// True when TREE is the `as` keyword, at any depth.
fn contains_as(tree: &TokenTree) -> bool {
    match tree {
        TokenTree::Ident(ident) => ident == "as",
        TokenTree::Group(group) => any_token(
            group.stream(),
            &|inner| matches!(inner, TokenTree::Ident(ident) if ident == "as"),
        ),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    }
}

/// True when TREE is the punctuation character C.
fn is_punct(tree: Option<&TokenTree>, c: char) -> bool {
    matches!(tree, Some(TokenTree::Punct(punct)) if punct.as_char() == c)
}

/// True when TREE is the identifier NAME.
fn is_ident(tree: Option<&TokenTree>, name: &str) -> bool {
    matches!(tree, Some(TokenTree::Ident(ident)) if ident == name)
}

/// True when the group at AT is the body of a macro invocation, `name!(...)`, or of a macro
/// definition, `macro_rules! name {...}`.
fn is_macro_body(trees: &[TokenTree], at: usize) -> bool {
    [at.checked_sub(1), at.checked_sub(2)]
        .into_iter()
        .flatten()
        .any(|index| is_punct(trees.get(index), '!'))
}

/// The index of the first `;` at or after FROM at this level, if there is one.
fn semicolon_index(trees: &[TokenTree], from: usize) -> Option<usize> {
    trees
        .iter()
        .enumerate()
        .skip(from)
        .find_map(|(index, tree)| is_punct(Some(tree), ';').then_some(index))
}

/// The index and the closing span of the first group at or after FROM, if there is one. A macro
/// definition ends at its body, and a macro call at its arguments.
fn first_group(trees: &[TokenTree], from: usize) -> Option<(usize, Span)> {
    trees
        .iter()
        .enumerate()
        .skip(from)
        .find_map(|(index, tree)| match tree {
            TokenTree::Group(group) => Some((index, group.span_close())),
            _ => None,
        })
}

/// The construct of the tokens from index FROM through index THROUGH, which starts at FIRST and
/// ends at LAST. A range that runs past the tokens is cut to them.
fn construct(
    trees: &[TokenTree],
    from: usize,
    through: usize,
    first: Span,
    last: Span,
) -> Construct {
    let slice = trees
        .get(from..=through)
        .or_else(|| trees.get(from..))
        .unwrap_or_default();
    Construct {
        first: line(first),
        last: line(last),
        text: slice.iter().cloned().collect::<TokenStream>().to_string(),
    }
}

/// The string that an include! call names, when its argument is one string literal.
fn include_path(group: &Group) -> Option<String> {
    let trees: Vec<TokenTree> = group.stream().into_iter().collect();
    match trees.as_slice() {
        [TokenTree::Literal(literal)] => syn::parse_str::<LitStr>(&literal.to_string())
            .ok()
            .map(|value| value.value()),
        _ => None,
    }
}

/// The line where SPAN starts. Spans come from parsing a text, so the line is known.
fn line(span: Span) -> usize {
    span.start().line
}

/// Reads the path attribute of a module declaration.
fn path_attr(attrs: &[Attribute]) -> PathAttr {
    let mut found = PathAttr::None;
    for attr in attrs {
        if attr.path().is_ident("path") {
            if found != PathAttr::None {
                return PathAttr::Unsupported;
            }
            found = match &attr.meta {
                Meta::NameValue(pair) => match &pair.value {
                    Expr::Lit(expr) => match &expr.lit {
                        Lit::Str(value) => PathAttr::Literal(value.value()),
                        _ => PathAttr::Unsupported,
                    },
                    _ => PathAttr::Unsupported,
                },
                _ => PathAttr::Unsupported,
            };
        } else if attr.path().is_ident("cfg_attr") {
            if let Meta::List(list) = &attr.meta {
                let names_path = any_token(
                    list.tokens.clone(),
                    &|tree| matches!(tree, TokenTree::Ident(ident) if ident == "path"),
                );
                if names_path {
                    return PathAttr::Unsupported;
                }
            }
        }
    }
    found
}

/// The marker lines and the module declaration lines in the comments of TEXT. A block comment
/// counts a marker or a declaration anywhere in its text. A line comment counts one only when its
/// text starts with it, as a commented-out test or module does.
fn comment_facts(text: &str) -> (Vec<usize>, Vec<usize>) {
    let mut markers = Vec::new();
    let mut mods = Vec::new();
    for comment in comments(text) {
        if comment.block {
            for (at, _) in comment.text.match_indices('#') {
                if attribute_marks_at(comment.text, at) {
                    markers.push(comment.line + newlines(&comment.text[..at]));
                }
            }
            for at in mod_declarations(comment.text) {
                mods.push(comment.line + newlines(&comment.text[..at]));
            }
        } else {
            // The `/` of a doc comment and the `!` of an inner one are not part of the text.
            let body = comment
                .text
                .strip_prefix(['/', '!'])
                .unwrap_or(comment.text)
                .trim_start();
            if attribute_marks_at(body, 0) {
                markers.push(comment.line);
            }
            if mod_declarations(body).first() == Some(&0) {
                mods.push(comment.line);
            }
        }
    }
    (markers, mods)
}

/// True when the `#` at AT in TEXT opens an outer attribute that names test.
fn attribute_marks_at(text: &str, at: usize) -> bool {
    if !text.get(at..).is_some_and(|rest| rest.starts_with('#')) {
        return false;
    }
    text.get(at + 1..)
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix('['))
        .and_then(bracketed)
        .is_some_and(attribute_names_test)
}

/// The text of an attribute, from just after its `[` to the `]` that closes it, when it closes.
fn bracketed(after: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (index, c) in after.char_indices() {
        match c {
            '[' => depth += 1,
            ']' if depth == 0 => return Some(&after[..index]),
            ']' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// True when INNER, the text between the brackets of an attribute, is a test marker, decided as
/// the token walk decides it for an attribute in code.
fn attribute_names_test(inner: &str) -> bool {
    let Ok(tokens) = format!("[{inner}]").parse::<TokenStream>() else {
        return false;
    };
    match tokens.into_iter().next() {
        Some(TokenTree::Group(group)) => AttrFacts::read(&group).marker,
        _ => false,
    }
}

/// The byte offsets of the `mod` keyword of each `mod NAME;` in BODY, where NAME is an identifier.
fn mod_declarations(body: &str) -> Vec<usize> {
    body.match_indices("mod")
        .filter(|&(at, _)| {
            let word_start = body[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !is_ident_char(c));
            let after = &body[at + 3..];
            let rest = after.trim_start();
            let name_len = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
            word_start
                && after.starts_with(char::is_whitespace)
                && name_len > 0
                && rest[name_len..].trim_start().starts_with(';')
        })
        .map(|(at, _)| at)
        .collect()
}

/// True when C can be part of an identifier.
fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The number of line breaks in TEXT.
fn newlines(text: &str) -> usize {
    text.matches('\n').count()
}

/// A comment of a text: the line where it starts, its text, and whether it is a block comment.
/// The text of a block comment lies between its `/*` and its `*/`. The text of a line comment
/// follows its `//`.
struct Comment<'a> {
    line: usize,
    text: &'a str,
    block: bool,
}

/// The comments of TEXT, in source order. A delimiter in a string literal or a char literal opens
/// none.
fn comments(text: &str) -> Vec<Comment<'_>> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut line = 1;
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let next = match byte {
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                let end = bytes[at..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(bytes.len(), |offset| at + offset);
                if let Some(body) = text.get(at + 2..end) {
                    found.push(Comment {
                        line,
                        text: body,
                        block: false,
                    });
                }
                end
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let (close, after) = block_end(bytes, at + 2);
                if let Some(body) = text.get(at + 2..close) {
                    found.push(Comment {
                        line,
                        text: body,
                        block: true,
                    });
                }
                after
            }
            b'"' => string_end(bytes, at + 1),
            b'\'' => char_end(bytes, at),
            b'r' => raw_string_end(bytes, at).unwrap_or(at + 1),
            _ => at + 1,
        };
        line += bytes
            .get(at..next)
            .map_or(0, |passed| passed.iter().filter(|&&b| b == b'\n').count());
        at = next;
    }
    found
}

/// The start of the `*/` that closes the block comment whose text starts at FROM, and the index
/// after it. Block comments nest. A comment that is not closed runs to the end of the text.
fn block_end(bytes: &[u8], from: usize) -> (usize, usize) {
    let mut depth = 1usize;
    let mut at = from;
    while let Some(&byte) = bytes.get(at) {
        match (byte, bytes.get(at + 1)) {
            (b'/', Some(b'*')) => {
                depth += 1;
                at += 2;
            }
            (b'*', Some(b'/')) => {
                depth -= 1;
                if depth == 0 {
                    return (at, at + 2);
                }
                at += 2;
            }
            _ => at += 1,
        }
    }
    (bytes.len(), bytes.len())
}

/// The index after the string literal whose contents start at FROM.
fn string_end(bytes: &[u8], from: usize) -> usize {
    let mut at = from;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\\' => at += 2,
            b'"' => return at + 1,
            _ => at += 1,
        }
    }
    bytes.len()
}

/// The index after the char literal that starts at AT, a quote. A quote that opens a lifetime
/// ends no literal, and the index after the quote is returned for it.
fn char_end(bytes: &[u8], at: usize) -> usize {
    match bytes.get(at + 1) {
        Some(&b'\\') => bytes
            .get(at + 3..)
            .and_then(|rest| rest.iter().position(|&b| b == b'\''))
            .map_or(bytes.len(), |offset| at + 3 + offset + 1),
        Some(&first) => {
            let width = match first {
                0..=0x7f => 1,
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                _ => 4,
            };
            if bytes.get(at + 1 + width) == Some(&b'\'') {
                at + 2 + width
            } else {
                at + 1
            }
        }
        None => at + 1,
    }
}

/// The index after the raw string literal that starts at AT, an `r`, when one starts there. A
/// raw identifier (`r#type`) and a name that merely holds an `r` start none.
fn raw_string_end(bytes: &[u8], at: usize) -> Option<usize> {
    let hashes = bytes
        .get(at + 1..)?
        .iter()
        .take_while(|&&b| b == b'#')
        .count();
    let quote = at + 1 + hashes;
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let closes = |index: usize| {
        bytes.get(index) == Some(&b'"')
            && bytes
                .get(index + 1..index + 1 + hashes)
                .is_some_and(|tail| tail.iter().all(|&b| b == b'#'))
    };
    Some(
        (quote + 1..bytes.len())
            .find(|&index| closes(index))
            .map_or(bytes.len(), |index| index + 1 + hashes),
    )
}

/// Collects the out-of-line module declarations, with the inline modules that enclose each.
#[derive(Default)]
struct Mods {
    frames: Vec<Frame>,
    decls: Vec<ModDecl>,
}

/// An inline module that is being visited.
struct Frame {
    name: String,
    path_module: bool,
}

impl<'ast> Visit<'ast> for Mods {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        // A raw identifier names its file without the `r#`: `mod r#type;` loads `type.rs`.
        let name = node.ident.unraw().to_string();
        match &node.content {
            None => {
                self.decls.push(ModDecl {
                    name,
                    line: line(node.mod_token.span),
                    path: path_attr(&node.attrs),
                    inline: self.frames.iter().map(|frame| frame.name.clone()).collect(),
                    unsupported_nesting: self.frames.iter().any(|frame| frame.path_module),
                });
            }
            Some(_) => {
                self.frames.push(Frame {
                    name,
                    path_module: path_attr(&node.attrs) != PathAttr::None,
                });
                visit::visit_item_mod(self, node);
                self.frames.pop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_comment_is_found_with_its_line() {
        let found = comments("a\n/* x\n y */ b");
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].line, found[0].text, found[0].block),
            (2, " x\n y ", true)
        );
    }

    #[test]
    fn a_delimiter_in_a_string_or_a_char_literal_opens_no_comment() {
        assert!(comments("let s = \"/*\";\n").is_empty());
        assert!(comments("let c = '/';\n").is_empty());
    }

    #[test]
    fn a_line_comment_is_not_a_block_comment() {
        let found = comments("// /* open\nx\n");
        assert_eq!(found.len(), 1);
        assert!(!found[0].block);
    }

    #[test]
    fn a_raw_identifier_is_not_a_raw_string() {
        let blocks = comments("let r#type = 1; /* t */")
            .iter()
            .filter(|comment| comment.block)
            .count();
        assert_eq!(blocks, 1);
    }

    #[test]
    fn a_marker_in_a_block_comment_starts_test_code_at_its_line() {
        assert_eq!(read_text("x\n/*\n#[test]\n*/\n").start, 3);
    }

    #[test]
    fn a_commented_out_test_starts_test_code_but_a_mention_does_not() {
        assert_eq!(read_text("x\n// #[test]\n// fn t() {}\n").start, 2);
        assert_eq!(read_text("x\n/// Use `#[test]` here.\n").start, 0);
        assert_eq!(read_text("x\n// see #[test] above\n").start, 0);
    }

    #[test]
    fn a_commented_out_module_declaration_is_unfollowed() {
        assert_eq!(read_text("x\n// mod helper;\n").unfollowed_mods, vec![2]);
        assert!(
            read_text("x\n// the mod helper; is below\n")
                .unfollowed_mods
                .is_empty()
        );
    }

    #[test]
    fn a_bracket_in_a_string_or_a_comment_is_not_nesting() {
        assert_eq!(bracket_depth("let s = \"((((\"; // ((((\n/* (((( */ ()"), 1);
        assert_eq!(bracket_depth(&"(".repeat(5)), 5);
    }

    #[test]
    fn a_text_nested_past_the_limit_is_refused_and_not_walked() {
        assert!(read_text_checked(&"(".repeat(MAX_NESTING)).is_ok());
        assert!(read_text_checked(&"(".repeat(MAX_NESTING + 1)).is_err());
        assert!(read_text(&"(".repeat(30_000)).too_deep);
        assert!(read(&"(".repeat(30_000)).is_err());
    }
}
