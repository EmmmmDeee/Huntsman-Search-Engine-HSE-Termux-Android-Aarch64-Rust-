//! The block-style YAML that rule files are written in, read into JSON values.
//!
//! Spiderfoot's correlation rules are YAML, and a rule a user writes for Huntsman is the same
//! file. This reads the part of YAML such files use: block mappings and sequences (a sequence may
//! sit at its key's indentation), `- key: value` items, plain, single- and double-quoted scalars,
//! folded (`>`) and literal (`|`) block scalars with `-`/`+` chomping, `#` comments and a leading
//! `---`. Scalars are typed as YAML 1.2's core schema types them: `true`/`false`, `null`/`~`,
//! integers and floats; everything else is a string. Flow collections, anchors, aliases, tags,
//! multi-line flow scalars and several documents are refused with the line they are on, never
//! guessed at.

use std::collections::BTreeSet;

use serde_json::{Map, Number, Value};
use thiserror::Error;

/// The largest file read; rules are a few hundred bytes.
pub const MAX_BYTES: usize = 256 * 1024;

/// Nesting deeper than this is refused, so a hostile file cannot exhaust the stack.
pub const MAX_DEPTH: usize = 64;

/// Why a document could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("line {line}: {reason}")]
pub struct YamlError {
    pub line: usize,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct Line {
    /// 1-based, for errors.
    number: usize,
    indent: usize,
    /// The content after the indentation, comments not yet removed.
    text: String,
}

struct Reader {
    lines: Vec<Line>,
    pos: usize,
}

fn refuse<T>(line: usize, reason: impl Into<String>) -> Result<T, YamlError> {
    Err(YamlError {
        line,
        reason: reason.into(),
    })
}

/// Read one YAML document.
///
/// # Errors
/// [`YamlError`] naming the line of the first construct outside the supported subset, a tab in
/// indentation, a duplicate key, or a document over [`MAX_BYTES`].
pub fn parse(text: &str) -> Result<Value, YamlError> {
    if text.len() > MAX_BYTES {
        return refuse(1, format!("larger than {MAX_BYTES} bytes"));
    }
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let body = raw.trim_start_matches(' ');
        if body.starts_with('\t') {
            return refuse(index + 1, "a tab in indentation");
        }
        lines.push(Line {
            number: index + 1,
            indent: raw.len() - body.len(),
            text: body.trim_end().to_owned(),
        });
    }
    let mut reader = Reader { lines, pos: 0 };
    reader.skip_blank();
    if reader.current().is_some_and(|line| {
        line.indent == 0 && (line.text == "---" || line.text.starts_with("--- "))
    }) {
        reader.pos += 1;
    }
    reader.skip_blank();
    let Some(first) = reader.current() else {
        return Ok(Value::Null);
    };
    let value = reader.block(first.indent, 0)?;
    reader.skip_blank();
    if let Some(line) = reader.current() {
        if line.text != "..." {
            return refuse(line.number, "content after the end of the document");
        }
    }
    Ok(value)
}

fn is_blank(text: &str) -> bool {
    text.is_empty() || text.starts_with('#')
}

fn is_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

impl Reader {
    fn current(&self) -> Option<&Line> {
        self.lines.get(self.pos)
    }

    fn skip_blank(&mut self) {
        while self.current().is_some_and(|line| is_blank(&line.text)) {
            self.pos += 1;
        }
    }

    /// The node starting at the current line, which is at `indent`.
    fn block(&mut self, indent: usize, depth: usize) -> Result<Value, YamlError> {
        let Some(line) = self.current() else {
            return Ok(Value::Null);
        };
        if depth > MAX_DEPTH {
            return refuse(line.number, "nested too deeply");
        }
        if is_item(&line.text) {
            self.sequence(indent, depth)
        } else if split_key(&line.text).is_some() {
            self.mapping(indent, depth)
        } else {
            let number = line.number;
            let text = line.text.clone();
            self.pos += 1;
            scalar(&text, number)
        }
    }

    fn sequence(&mut self, indent: usize, depth: usize) -> Result<Value, YamlError> {
        let mut items = Vec::new();
        loop {
            self.skip_blank();
            let Some(line) = self.current() else {
                break;
            };
            if line.indent != indent || !is_item(&line.text) {
                if line.indent > indent {
                    return refuse(line.number, "unexpected indentation in a sequence");
                }
                break;
            }
            let number = line.number;
            let rest = line.text[1..].trim_start().to_owned();
            if is_blank(&rest) {
                self.pos += 1;
                self.skip_blank();
                match self.current() {
                    Some(next) if next.indent > indent => {
                        let child = next.indent;
                        items.push(self.block(child, depth + 1)?);
                    }
                    _ => items.push(Value::Null),
                }
                continue;
            }
            // `- rest`: read `rest` as a node at its own column, so `- key: value` starts a
            // mapping whose later keys line up under `key`.
            let column = indent + (line.text.len() - rest.len());
            self.lines[self.pos].indent = column;
            self.lines[self.pos].text = rest;
            if is_item(&self.lines[self.pos].text)
                || split_key(&self.lines[self.pos].text).is_some()
            {
                items.push(self.block(column, depth + 1)?);
            } else {
                let text = self.lines[self.pos].text.clone();
                if let Some(style) = block_scalar_style(&text) {
                    self.pos += 1;
                    items.push(Value::String(self.block_scalar(indent, style, number)?));
                } else {
                    self.pos += 1;
                    items.push(scalar(&text, number)?);
                }
            }
        }
        Ok(Value::Array(items))
    }

    fn mapping(&mut self, indent: usize, depth: usize) -> Result<Value, YamlError> {
        let mut map = Map::new();
        let mut keys = BTreeSet::new();
        loop {
            self.skip_blank();
            let Some(line) = self.current() else {
                break;
            };
            if line.indent < indent || (line.indent == indent && is_item(&line.text)) {
                break;
            }
            let number = line.number;
            if line.indent > indent {
                return refuse(number, "unexpected indentation in a mapping");
            }
            let Some((key, rest)) = split_key(&line.text) else {
                return refuse(number, "expected `key: value`");
            };
            let key = key_text(&key, number)?;
            if !keys.insert(key.clone()) {
                return refuse(number, format!("duplicate key {key:?}"));
            }
            self.pos += 1;
            let value = if let Some(style) = block_scalar_style(&rest) {
                Value::String(self.block_scalar(indent, style, number)?)
            } else if is_blank(&rest) {
                self.skip_blank();
                match self.current() {
                    Some(next) if next.indent > indent => {
                        let child = next.indent;
                        self.block(child, depth + 1)?
                    }
                    // A sequence may sit at its key's indentation.
                    Some(next) if next.indent == indent && is_item(&next.text) => {
                        self.sequence(indent, depth + 1)?
                    }
                    _ => Value::Null,
                }
            } else {
                scalar(&rest, number)?
            };
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    /// The lines of a `>` or `|` scalar under a key or item at `parent` indentation.
    fn block_scalar(
        &mut self,
        parent: usize,
        (folded, chomp): (bool, Chomp),
        number: usize,
    ) -> Result<String, YamlError> {
        let mut body: Vec<(usize, &str)> = Vec::new();
        let start = self.pos;
        while let Some(line) = self.lines.get(self.pos) {
            if !line.text.is_empty() && line.indent <= parent {
                break;
            }
            self.pos += 1;
        }
        for line in &self.lines[start..self.pos] {
            body.push((line.indent, line.text.as_str()));
        }
        let Some(block_indent) = body
            .iter()
            .find(|(_, text)| !text.is_empty())
            .map(|(indent, _)| *indent)
        else {
            return Ok(String::new());
        };
        if body
            .iter()
            .any(|(indent, text)| !text.is_empty() && *indent < block_indent)
        {
            return refuse(
                number,
                "a block scalar line is indented less than its first line",
            );
        }
        let lines: Vec<String> = body
            .iter()
            .map(|(indent, text)| {
                if text.is_empty() {
                    String::new()
                } else {
                    format!("{}{text}", " ".repeat(indent - block_indent))
                }
            })
            .collect();
        let trailing_blank = lines
            .iter()
            .rev()
            .take_while(|line| line.is_empty())
            .count();
        let content = &lines[..lines.len() - trailing_blank];
        let mut out = String::new();
        if folded {
            let mut previous_blank = true;
            for line in content {
                if line.is_empty() {
                    out.push('\n');
                    previous_blank = true;
                } else if line.starts_with(' ') {
                    // A more-indented line keeps its own line, as YAML folds.
                    if !previous_blank && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(line);
                    out.push('\n');
                    previous_blank = true;
                } else {
                    if !previous_blank {
                        out.push(' ');
                    }
                    out.push_str(line);
                    previous_blank = false;
                }
            }
        } else {
            out = content.join("\n");
        }
        match chomp {
            Chomp::Strip => {
                // A folded scalar's more-indented last line ends in its line break.
                if out.ends_with('\n') {
                    out.pop();
                }
            }
            Chomp::Clip => {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            Chomp::Keep => {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&"\n".repeat(trailing_blank));
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chomp {
    Strip,
    Clip,
    Keep,
}

/// `>`, `|`, `>-`, `|+`... with nothing after but a comment.
fn block_scalar_style(text: &str) -> Option<(bool, Chomp)> {
    let text = strip_comment(text);
    let mut chars = text.chars();
    let folded = match chars.next()? {
        '>' => true,
        '|' => false,
        _ => return None,
    };
    let chomp = match chars.as_str() {
        "" => Chomp::Clip,
        "-" => Chomp::Strip,
        "+" => Chomp::Keep,
        _ => return None,
    };
    Some((folded, chomp))
}

/// Where a leading quoted scalar ends, just past its closing quote; 0 when `text` does not start
/// with a quote, and its length when the quote is never closed. A backslash escapes the next
/// character inside double quotes, and `''` is a quote inside single quotes.
fn after_quote(text: &str) -> usize {
    let mut chars = text.char_indices().peekable();
    let Some((_, open @ ('"' | '\''))) = chars.next() else {
        return 0;
    };
    while let Some((index, c)) = chars.next() {
        if open == '"' && c == '\\' {
            chars.next();
        } else if c == open {
            if open == '\'' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                chars.next();
                continue;
            }
            return index + 1;
        }
    }
    text.len()
}

/// A line's `key` and the rest after `: `, outside any quotes.
fn split_key(text: &str) -> Option<(String, String)> {
    let start = after_quote(text);
    let mut previous = ' ';
    for (offset, c) in text[start..].char_indices() {
        let index = start + offset;
        match c {
            '#' if index > 0 && previous == ' ' => return None,
            ':' => {
                let after = text[index + 1..].chars().next();
                if after.is_none() || after == Some(' ') {
                    return Some((
                        text[..index].trim_end().to_owned(),
                        text[index + 1..].trim().to_owned(),
                    ));
                }
            }
            _ => {}
        }
        previous = c;
    }
    None
}

fn key_text(key: &str, number: usize) -> Result<String, YamlError> {
    match scalar(key, number)? {
        Value::String(text) => Ok(text),
        Value::Null => Ok(String::new()),
        other => Ok(other.to_string()),
    }
}

/// `text` without a ` #` comment, outside quotes.
fn strip_comment(text: &str) -> &str {
    let start = after_quote(text);
    let mut previous = if start == 0 { ' ' } else { '"' };
    for (offset, c) in text[start..].char_indices() {
        if c == '#' && previous == ' ' {
            return text[..start + offset].trim_end();
        }
        previous = c;
    }
    text.trim_end()
}

fn scalar(text: &str, number: usize) -> Result<Value, YamlError> {
    let text = strip_comment(text);
    match text.chars().next() {
        Some('"') => return double_quoted(text, number).map(Value::String),
        Some('\'') => return single_quoted(text, number).map(Value::String),
        Some('[' | '{') => return refuse(number, "flow collections are not supported"),
        Some('&' | '*' | '!') => {
            return refuse(number, "anchors, aliases and tags are not supported");
        }
        Some('|' | '>') => return refuse(number, "a block scalar indicator here is not supported"),
        Some('%' | '@' | '`') => return refuse(number, "a plain scalar cannot start with this"),
        _ => {}
    }
    Ok(match text {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => {
            if let Ok(integer) = text.parse::<i64>() {
                Value::Number(integer.into())
            } else if let Some(number) = text
                .parse::<f64>()
                .ok()
                .filter(|_| {
                    text.chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E'))
                })
                .and_then(Number::from_f64)
            {
                Value::Number(number)
            } else {
                Value::String(text.to_owned())
            }
        }
    })
}

fn double_quoted(text: &str, number: usize) -> Result<String, YamlError> {
    let Some(inner) = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return refuse(number, "unterminated or multi-line double-quoted scalar");
    };
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            return refuse(number, "a stray quote inside a double-quoted scalar");
        }
        if c != '\\' {
            out.push(c);
            continue;
        }
        let escaped = match chars.next() {
            Some('\\') => '\\',
            Some('"') => '"',
            Some('/') => '/',
            Some('n') => '\n',
            Some('t') => '\t',
            Some('r') => '\r',
            Some('0') => '\0',
            Some(' ') => ' ',
            Some(kind @ ('x' | 'u' | 'U')) => {
                let width = match kind {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let digits: String = chars.by_ref().take(width).collect();
                match u32::from_str_radix(&digits, 16)
                    .ok()
                    .filter(|_| digits.len() == width)
                    .and_then(char::from_u32)
                {
                    Some(c) => c,
                    None => return refuse(number, "a bad \\x, \\u or \\U escape"),
                }
            }
            _ => return refuse(number, "an unknown escape in a double-quoted scalar"),
        };
        out.push(escaped);
    }
    Ok(out)
}

fn single_quoted(text: &str, number: usize) -> Result<String, YamlError> {
    let Some(inner) = text
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    else {
        return refuse(number, "unterminated or multi-line single-quoted scalar");
    };
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
            } else {
                return refuse(number, "a stray quote inside a single-quoted scalar");
            }
        }
        out.push(c);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_spiderfoot_rule_reads_as_the_json_python_yaml_gives() {
        let rule = "\
id: multiple_malicious
version: 1
meta:
  name: >
    An IP, host, subnet or email address was considered malicious by
    multiple sources
  description: >
    First paragraph
    continues.

    Second paragraph.
  risk: HIGH
collections:
  - collect:
      - method: regex
        field: type
        value:
          - MALICIOUS_*
          - BLACKLIST_*
      # Filter out all subnets
      - method: regex
        field: source.data
        value: not .*/.*
aggregation:
  field: source.data
analysis:
  - method: threshold
    field: source.data
    minimum: 2
headline: \"Entity considered malicious by multiple sources: {source.data}\"
";
        assert_eq!(
            parse(rule).unwrap(),
            json!({
                "id": "multiple_malicious",
                "version": 1,
                "meta": {
                    "name": "An IP, host, subnet or email address was considered malicious by multiple sources\n",
                    "description": "First paragraph continues.\nSecond paragraph.\n",
                    "risk": "HIGH",
                },
                "collections": [{"collect": [
                    {"method": "regex", "field": "type", "value": ["MALICIOUS_*", "BLACKLIST_*"]},
                    {"method": "regex", "field": "source.data", "value": "not .*/.*"},
                ]}],
                "aggregation": {"field": "source.data"},
                "analysis": [{"method": "threshold", "field": "source.data", "minimum": 2}],
                "headline": "Entity considered malicious by multiple sources: {source.data}",
            })
        );
    }

    #[test]
    fn scalars_quotes_comments_and_same_indent_sequences() {
        let doc = "\
---
plain: ^[a-zA-Z0-9\\.\\-]+$  # trailing comment
backslashes: ^192\\\\.168\\\\..*
quoted: \"a \\\"b\\\" \\u00e9 # not a comment\"
single: 'it''s'
empty:
nothing: ~
flag: true
ratio: 2.5
list:
- one
- two: 2
  three: 3
-
  - nested
literal: |
  line one
    indented
  line three
stripped: >-
  folded
  text
stripped_indented: >-
  folded
    more indented
";
        assert_eq!(
            parse(doc).unwrap(),
            json!({
                "plain": "^[a-zA-Z0-9\\.\\-]+$",
                "backslashes": "^192\\\\.168\\\\..*",
                "quoted": "a \"b\" \u{e9} # not a comment",
                "single": "it's",
                "empty": null,
                "nothing": null,
                "flag": true,
                "ratio": 2.5,
                "list": ["one", {"two": 2, "three": 3}, ["nested"]],
                "literal": "line one\n  indented\nline three\n",
                "stripped": "folded text",
                "stripped_indented": "folded\n  more indented",
            })
        );
    }

    #[test]
    fn what_is_outside_the_subset_is_refused_with_its_line() {
        for (doc, line) in [
            ("a: [1, 2]", 1),
            ("a: 1\nb: &x 2", 2),
            ("a: 1\na: 2", 2),
            ("a:\n\t- b", 2),
            ("a: \"open", 1),
            ("a: 1\n   b: 2", 2),
            ("- a\nb: 1", 2),
        ] {
            let error = parse(doc).unwrap_err();
            assert_eq!(error.line, line, "{doc:?}: {error}");
        }
        let deep: String = (0..100).map(|depth| " ".repeat(depth) + "k:\n").collect();
        assert!(parse(&deep).unwrap_err().reason.contains("deeply"));
    }
}

#[cfg(test)]
mod hostile {
    use super::*;

    /// A fixed-seed xorshift, so a failing document is reproduced by its case number.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn pick<'a>(&mut self, from: &[&'a str]) -> &'a str {
            from[usize::try_from(self.next() % from.len() as u64).unwrap_or(0)]
        }
    }

    const PIECES: &[&str] = &[
        "- ", "-", "key: ", "k:", "a b: ", "'", "''", "\"", "\\\"", "\\u12", "|", "|-", "|+", ">",
        ">-", "#", " #c", "---", "...", "[", "{", "&a", "*a", "!t", "true", "~", "1e9", "-0",
        "0x1f", "é", "😀", "\u{FEFF}", ":", "  ", "    ", "x", "- - ", "? ",
    ];

    /// Any document built from YAML's own syntax is either read or refused with a line: none
    /// panics, and each is answered in bounded time.
    #[test]
    fn every_generated_document_is_read_or_refused_never_a_panic() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for case in 0..20_000 {
            let mut doc = String::new();
            for _ in 0..(rng.next() % 12) {
                for _ in 0..(rng.next() % 4) {
                    doc.push_str(rng.pick(&["", " ", "  ", "    ", "      "]));
                }
                for _ in 0..(rng.next() % 5) {
                    doc.push_str(rng.pick(PIECES));
                }
                doc.push('\n');
            }
            let outcome = std::panic::catch_unwind(|| parse(&doc));
            assert!(outcome.is_ok(), "case {case} panicked on {doc:?}");
            if let Ok(Err(error)) = outcome {
                assert!(error.line >= 1, "case {case}: {error:?}");
            }
        }
    }

    /// Nesting past the limit is refused, whichever way it nests, before the stack runs out.
    #[test]
    fn nesting_past_the_limit_is_refused_not_a_stack_overflow() {
        // Indented nesting costs its depth in bytes per line, so 300 levels stay under MAX_BYTES;
        // nesting on one line costs two bytes a level.
        let indented = 300;
        let (mut mappings, mut sequences) = (String::new(), String::new());
        for level in 0..indented {
            mappings.push_str(&" ".repeat(level));
            mappings.push('k');
            mappings.push_str(&level.to_string());
            mappings.push_str(":\n");
            sequences.push_str(&" ".repeat(level * 2));
            sequences.push_str("-\n");
        }
        let inline = format!("{}x\n", "- ".repeat(50_000));
        for doc in [mappings, sequences, inline] {
            assert!(doc.len() <= MAX_BYTES, "{}", doc.len());
            let error = parse(&doc).expect_err("too deep");
            assert!(error.reason.contains("deep"), "{error:?}");
        }
    }
}
