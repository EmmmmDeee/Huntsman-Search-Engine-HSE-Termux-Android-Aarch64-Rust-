//! Reads one Rust file for the path guard. The file must parse with syn: a file that does not
//! parse is refused, never skipped. Test markers, inner cfg attributes, include! sites, and the
//! constructs that reach other code are read from the token stream, so a spacing variant or a
//! construct inside a macro body counts the same as plain code, and a marker in a string literal
//! or a comment does not count. Module declarations come from the syntax tree, because their
//! attributes and their inline nesting decide which file they load.

use proc_macro2::{Delimiter, Group, Punct, Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ItemMod, Lit, LitStr, Meta};

/// Everything the guard reads from one Rust file.
#[derive(Debug, Default)]
pub struct FileFacts {
    /// The first line of test code: the line of the first test marker, or 0 when there is none.
    pub start: usize,
    /// The file has an inner `#![cfg(...)]` that names test. Every line of such a file is test
    /// code.
    pub inner_cfg_test: bool,
    /// The out-of-line module declarations, `mod NAME;`, in source order.
    pub mods: Vec<ModDecl>,
    /// The include! macro calls, in source order.
    pub includes: Vec<Include>,
    /// The (first, last) lines of each construct that reaches code beyond its own lines: a
    /// macro definition, a path, macro_use, or macro_export attribute, or an include! call.
    pub scope_constructs: Vec<(usize, usize)>,
    /// The (first, last) lines of each cfg attribute, extern crate item, and import alias.
    pub cfg_constructs: Vec<(usize, usize)>,
}

/// One out-of-line module declaration.
#[derive(Debug)]
pub struct ModDecl {
    /// The name of the module.
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

/// Reads TEXT. The error is a reason for a person: the text does not parse as Rust.
pub fn read(text: &str) -> Result<FileFacts, String> {
    let file = syn::parse_file(text).map_err(|error| error.to_string())?;
    let tokens: TokenStream = text.parse().map_err(|error| format!("{error}"))?;
    let mut scan = Scan::default();
    scan.stream(tokens);
    let mut mods = Mods::default();
    mods.visit_file(&file);
    Ok(FileFacts {
        start: scan.markers.iter().min().copied().unwrap_or(0),
        inner_cfg_test: scan.inner_cfg_test,
        mods: mods.decls,
        includes: scan.includes,
        scope_constructs: scan.scope_constructs,
        cfg_constructs: scan.cfg_constructs,
    })
}

/// The facts that the token walk collects.
#[derive(Default)]
struct Scan {
    markers: Vec<usize>,
    inner_cfg_test: bool,
    includes: Vec<Include>,
    scope_constructs: Vec<(usize, usize)>,
    cfg_constructs: Vec<(usize, usize)>,
}

impl Scan {
    /// Walks every token of STREAM, and of every group inside it, in source order.
    fn stream(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        let mut at = 0;
        while let Some(tree) = trees.get(at) {
            let next = trees.get(at + 1);
            let consumed = match tree {
                TokenTree::Punct(punct) if punct.as_char() == '#' => {
                    self.attribute(&trees, at, punct)
                }
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    match (name.as_str(), next) {
                        ("macro_rules", Some(TokenTree::Punct(bang))) if bang.as_char() == '!' => {
                            let last = first_group_end(&trees, at + 2).unwrap_or(ident.span());
                            self.scope_constructs.push((line(ident.span()), line(last)));
                        }
                        ("include", Some(TokenTree::Punct(bang))) if bang.as_char() == '!' => {
                            self.include(&trees, at);
                        }
                        ("extern", Some(TokenTree::Ident(keyword))) if keyword == "crate" => {
                            let last = semicolon_span(&trees, at + 2).unwrap_or(keyword.span());
                            self.cfg_constructs.push((line(ident.span()), line(last)));
                        }
                        ("use", _) => {
                            let end = semicolon_index(&trees, at + 1);
                            let rest = trees.get(at + 1..end).unwrap_or_default();
                            if rest.iter().any(contains_as) {
                                let last = trees.get(end).map_or(ident.span(), TokenTree::span);
                                self.cfg_constructs.push((line(ident.span()), line(last)));
                            }
                        }
                        _ => {}
                    }
                    1
                }
                TokenTree::Group(group) => {
                    self.stream(group.stream());
                    1
                }
                _ => 1,
            };
            at += consumed;
        }
    }

    /// Reads the attribute that starts at AT (a `#`), and returns the number of tokens it spans.
    fn attribute(&mut self, trees: &[TokenTree], at: usize, hash: &Punct) -> usize {
        let inner =
            matches!(trees.get(at + 1), Some(TokenTree::Punct(bang)) if bang.as_char() == '!');
        let open = if inner { at + 2 } else { at + 1 };
        let Some(TokenTree::Group(group)) = trees.get(open) else {
            return 1;
        };
        if group.delimiter() != Delimiter::Bracket {
            return 1;
        }
        let facts = AttrFacts::read(group);
        let start = line(hash.span());
        let end = line(group.span_close());
        if inner {
            if facts.cfg_test {
                self.inner_cfg_test = true;
            }
        } else if facts.marker {
            self.markers.push(start);
        }
        if facts.cfg_like {
            self.cfg_constructs.push((start, end));
        }
        if facts.path_like {
            self.scope_constructs.push((start, end));
        }
        self.stream(group.stream());
        open + 1 - at
    }

    /// Records the include! call whose name is at AT.
    fn include(&mut self, trees: &[TokenTree], at: usize) {
        let Some(name) = trees.get(at).map(TokenTree::span) else {
            return;
        };
        let group = match trees.get(at + 2) {
            Some(TokenTree::Group(group)) => group,
            _ => {
                self.includes.push(Include {
                    line: line(name),
                    path: None,
                });
                return;
            }
        };
        let path = include_path(group);
        self.scope_constructs
            .push((line(name), line(group.span_close())));
        self.includes.push(Include {
            line: line(name),
            path,
        });
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

/// The index of the first `;` at or after FROM at this level, or the length of TREES.
fn semicolon_index(trees: &[TokenTree], from: usize) -> usize {
    trees
        .iter()
        .enumerate()
        .skip(from)
        .find(|(_, tree)| matches!(tree, TokenTree::Punct(punct) if punct.as_char() == ';'))
        .map_or(trees.len(), |(index, _)| index)
}

/// The span of the `;` that ends a statement at or after FROM, if there is one.
fn semicolon_span(trees: &[TokenTree], from: usize) -> Option<Span> {
    let index = semicolon_index(trees, from);
    trees.get(index).map(TokenTree::span)
}

/// The span where the first group at or after FROM ends, if there is one. A macro definition
/// ends at its body, and a macro call at its arguments.
fn first_group_end(trees: &[TokenTree], from: usize) -> Option<Span> {
    trees.iter().skip(from).find_map(|tree| match tree {
        TokenTree::Group(group) => Some(group.span_close()),
        _ => None,
    })
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
        match &node.content {
            None => {
                self.decls.push(ModDecl {
                    name: node.ident.to_string(),
                    line: line(node.mod_token.span),
                    path: path_attr(&node.attrs),
                    inline: self.frames.iter().map(|frame| frame.name.clone()).collect(),
                    unsupported_nesting: self.frames.iter().any(|frame| frame.path_module),
                });
            }
            Some(_) => {
                self.frames.push(Frame {
                    name: node.ident.to_string(),
                    path_module: path_attr(&node.attrs) != PathAttr::None,
                });
                visit::visit_item_mod(self, node);
                self.frames.pop();
            }
        }
    }
}
