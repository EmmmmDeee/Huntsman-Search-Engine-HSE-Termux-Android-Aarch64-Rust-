//! HTML as text, with no dependency: the one reader every source that receives a web page uses.
//!
//! [`Markup`] walks an HTML fragment forward-only, so malformed markup can neither panic nor make
//! it loop: a `<` that opens no complete tag is text, and each step consumes input. It drops
//! comments, declarations and the content of `script` and `style`. [`html_to_text`] turns a page
//! into readable plain text, and [`attribute`] reads one attribute of a start tag.

use crate::textnorm::decode_html_entities;

/// Ends a text that [`html_to_text`] cut short.
pub const ELLIPSIS: char = '\u{2026}';

/// The HTML elements that separate text: a tag of one of these reads as a space, any other tag as
/// nothing, so `a<br>b` reads `a b` and `a<b>b</b>` reads `ab`.
pub const BLOCK_ELEMENTS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
];

/// `html` as readable plain text: tags removed (a block tag reads as a space), comments and the
/// content of `script` and `style` dropped, character references decoded, whitespace collapsed,
/// and at most `max_chars` characters, the last of them [`ELLIPSIS`] when the text was cut.
/// `None` when no text is left. Malformed markup cannot make it panic or loop: a `<` that opens
/// no complete tag is text, and every step moves forward through the input.
#[must_use]
pub fn html_to_text(html: &str, max_chars: usize) -> Option<String> {
    let mut raw = String::with_capacity(html.len());
    for piece in Markup::new(html) {
        match piece {
            Piece::Text(text) => raw.push_str(text),
            Piece::Tag { name, .. }
                if BLOCK_ELEMENTS
                    .iter()
                    .any(|block| name.eq_ignore_ascii_case(block)) =>
            {
                raw.push(' ');
            }
            Piece::Tag { .. } | Piece::Ignored => {}
        }
    }
    let decoded = decode_html_entities(&raw);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() || max_chars == 0 {
        return None;
    }
    if collapsed.chars().nth(max_chars).is_none() {
        return Some(collapsed);
    }
    let keep = max_chars - 1;
    let cut = collapsed
        .char_indices()
        .nth(keep)
        .map_or(collapsed.len(), |(index, _)| index);
    let mut out = collapsed
        .get(..cut)
        .unwrap_or_default()
        .trim_end()
        .to_owned();
    out.push(ELLIPSIS);
    Some(out)
}

/// The value of the attribute `wanted` (ASCII case ignored) in the attribute text of a start tag.
/// A quoted value runs to its closing quote and an unquoted one to the next whitespace. The first
/// occurrence decides, as in HTML. An attribute with no value, or a quote that never closes, gives
/// `None`. Each step consumes at least one character, so the scan ends.
#[must_use]
pub fn attribute<'a>(attrs: &'a str, wanted: &str) -> Option<&'a str> {
    let mut rest = attrs;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '/');
        if rest.is_empty() {
            return None;
        }
        let name_len = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '=' || c == '/')
            .unwrap_or(rest.len());
        let name = rest.get(..name_len)?;
        let after_name = rest
            .get(name_len..)?
            .trim_start_matches(|c: char| c.is_ascii_whitespace());
        let (value, after) = match after_name.strip_prefix('=') {
            None => (None, after_name),
            Some(value) => {
                let value = value.trim_start_matches(|c: char| c.is_ascii_whitespace());
                if let Some(quote @ ('"' | '\'')) = value.chars().next() {
                    let body = value.get(1..)?;
                    match body.find(quote) {
                        Some(close) => (body.get(..close), body.get(close + 1..)?),
                        None => (None, ""),
                    }
                } else {
                    let len = value
                        .find(|c: char| c.is_ascii_whitespace())
                        .unwrap_or(value.len());
                    (value.get(..len), value.get(len..)?)
                }
            }
        };
        if !name.is_empty() && name.eq_ignore_ascii_case(wanted) {
            return value;
        }
        rest = after;
    }
}

/// One piece of an HTML fragment, as [`Markup`] reads it.
pub enum Piece<'a> {
    /// Text between tags, its character references still encoded.
    Text(&'a str),
    /// A start or end tag: its name as written, and for a start tag the text of its attributes.
    Tag {
        name: &'a str,
        end: bool,
        attrs: &'a str,
    },
    /// A comment, a declaration, a processing instruction, or a `script` or `style` element.
    Ignored,
}

/// A forward-only reader of an HTML fragment. A `<` opens markup only when a letter, `/` and a
/// letter, `!` or `?` follows it and a `>` closes it; any other `<` is text. In a tag, a `>`
/// inside a quoted attribute value does not close it, as in [`attribute`]. Markup that never
/// closes is text, and so is everything after it: each search starts where the last one ended,
/// and none is repeated after one fails, so reading is linear in the input even when it is
/// malformed. An unterminated HTML comment is ignored through end-of-input.
pub struct Markup<'a> {
    html: &'a str,
    /// `html` with ASCII letters lower-cased: the same bytes at the same offsets otherwise, for
    /// case-insensitive searches.
    lower: String,
    pos: usize,
    /// Markup at or before `pos` never closed, so the rest of the input is text.
    no_close: bool,
}

/// The offset in `tag` (the text after a tag's `<`) of the `>` that closes it, or `None` when the
/// input ends first. A quote right after an `=` (spaces allowed between) opens a value that runs to
/// the same quote; any other quote is an ordinary character.
fn tag_close(tag: &str) -> Option<usize> {
    let bytes = tag.as_bytes();
    let mut index = 0;
    let mut after_equals = false;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'>' => return Some(index),
            b'=' => after_equals = true,
            b'"' | b'\'' if after_equals => {
                let value = tag.get(index + 1..)?;
                index += 1 + value.find(char::from(byte))?;
                after_equals = false;
            }
            _ if byte.is_ascii_whitespace() => {}
            _ => after_equals = false,
        }
        index += 1;
    }
    None
}

impl<'a> Markup<'a> {
    #[must_use]
    pub fn new(html: &'a str) -> Self {
        Self {
            html,
            lower: html.to_ascii_lowercase(),
            pos: 0,
            no_close: false,
        }
    }

    /// The markup that the `<` at `start` opens and the offset just past it, or `None` when that
    /// `<` is text.
    fn markup_at(&mut self, start: usize) -> Option<(Piece<'a>, usize)> {
        if self.no_close {
            return None;
        }
        let after = self.html.get(start + 1..)?;
        let mut bytes = after.bytes();
        let first = bytes.next()?;
        let second = bytes.next();
        if after.starts_with("!--") {
            // An unterminated comment consumes the rest of the document. Treating
            // its first stray '>' as a declaration terminator would expose the
            // remaining comment body as visible evidence text.
            let body = start + 4;
            let end = self.lower.get(body..)?.find("-->").map_or(self.html.len(), |offset| body + offset + 3);
            return Some((Piece::Ignored, end));
        }
        let end_tag = first == b'/';
        let tag = first.is_ascii_alphabetic()
            || (end_tag && second.is_some_and(|b| b.is_ascii_alphabetic()));
        if !tag && !matches!(first, b'!' | b'?') {
            return None;
        }
        let closed = if tag {
            tag_close(after)
        } else {
            after.find('>')
        };
        let Some(offset) = closed else {
            self.no_close = true;
            return None;
        };
        let gt = start + 1 + offset;
        let next = gt + 1;
        if !tag {
            return Some((Piece::Ignored, next));
        }
        let inner = self.html.get(start + 1 + usize::from(end_tag)..gt)?;
        let name_len = inner.bytes().take_while(u8::is_ascii_alphanumeric).count();
        let name = inner.get(..name_len)?;
        let attrs = inner.get(name_len..)?;
        let raw_text = ["script", "style"]
            .into_iter()
            .find(|element| name.eq_ignore_ascii_case(element));
        if let (Some(element), false) = (raw_text, end_tag) {
            // The element's content is not text: skip to its end tag, or to the end of input.
            let end_marker = format!("</{element}");
            let resume = self
                .lower
                .get(next..)
                .and_then(|rest| rest.find(&end_marker))
                .map_or(self.html.len(), |offset| {
                    let after_marker = next + offset + end_marker.len();
                    self.html
                        .get(after_marker..)
                        .and_then(|rest| rest.find('>'))
                        .map_or(self.html.len(), |end| after_marker + end + 1)
                });
            return Some((Piece::Ignored, resume));
        }
        Some((
            Piece::Tag {
                name,
                end: end_tag,
                attrs,
            },
            next,
        ))
    }
}

impl<'a> Iterator for Markup<'a> {
    type Item = Piece<'a>;

    fn next(&mut self) -> Option<Piece<'a>> {
        let rest = self.html.get(self.pos..).filter(|rest| !rest.is_empty())?;
        if !rest.starts_with('<') {
            let len = rest.find('<').unwrap_or(rest.len());
            self.pos += len;
            return rest.get(..len).map(Piece::Text);
        }
        let start = self.pos;
        if let Some((piece, next)) = self.markup_at(start) {
            self.pos = next;
            return Some(piece);
        }
        self.pos = start + 1;
        Some(Piece::Text("<"))
    }
}

#[cfg(test)]
mod tests {
    use super::html_to_text;

    #[test]
    fn unterminated_html_comment_does_not_surface_hidden_suffix() {
        assert_eq!(
            html_to_text("Visible <!-- private > SHOULD_NOT_SURFACE", 200),
            Some("Visible".to_owned())
        );
        assert_eq!(html_to_text("<!-- private > SHOULD_NOT_SURFACE", 200), None);
        assert_eq!(
            html_to_text("Visible <!-- private without a terminator", 200),
            Some("Visible".to_owned())
        );
    }

    #[test]
    fn closed_html_comment_preserves_subsequent_visible_text() {
        assert_eq!(
            html_to_text("Before <!-- hidden > comment --> After", 200),
            Some("Before After".to_owned())
        );
    }
}
