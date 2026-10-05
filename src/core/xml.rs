//! The one XML text-escaper every serializer in this crate uses.
//!
//! It exists because there were two. `core::gexf` hardened its own copy against the XML 1.0
//! character restriction; `core::snake_graph`'s copy — a `.replace()` chain covering only the five
//! metacharacters — did not, and a discovered entity value carrying a stray control byte therefore
//! produced an SVG that no XML parser would accept. Same job, two implementations, one of them
//! wrong: the defect was the duplication. Both now call this, so they cannot drift again.
//!
//! Two distinct rules are applied, and both are load-bearing:
//!
//! * **The five metacharacters** are replaced. `&` is handled in the same single pass as the
//!   others rather than by a chain of `replace` calls — a chain that substitutes `&` first and
//!   then `<` is correct, but one that reorders them silently double-escapes (`&lt;` becomes
//!   `&amp;lt;`). Matching per character makes that mistake unrepresentable.
//! * **XML-illegal characters are dropped.** XML 1.0 §2.2 excludes the C0 controls except tab, LF
//!   and CR, plus the noncharacters `U+FFFE`/`U+FFFF`. These are illegal *in the document*, not
//!   merely in need of escaping — a numeric reference like `&#8;` is just as invalid — so the only
//!   correct handling at a serialization boundary is to remove them. This matters because entity
//!   values are attacker-influenced: breach dumps, scraped pages and third-party API JSON all carry
//!   stray control bytes, and `core::entity::normalise`'s catch-all arm passes an *interior*
//!   control character through for kinds like `Person`, `Address` and `Password`. One such value
//!   anywhere in the graph would otherwise make the WHOLE document unparseable — not just that
//!   node — costing the entire scan's rendered output.
//!
//! C1 controls (`0x80`–`0x9F`) are valid in XML 1.0 and are deliberately kept. Surrogates need no
//! handling: a Rust `&str` cannot contain one.

/// Escape `s` for inclusion as XML text or as an attribute value.
///
/// Both contexts are covered by one function because it escapes `"` and `'` as well as `& < >`, so
/// a value placed inside either flavour of quoted attribute cannot terminate it. Pure and total.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\u{FFFE}' | '\u{FFFF}' => {}
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    include!("xml_tests.rs");
}
