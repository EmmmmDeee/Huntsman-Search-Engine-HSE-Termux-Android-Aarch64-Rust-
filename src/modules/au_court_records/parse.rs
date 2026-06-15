//! HTML parsing for AustLII search result pages.

/// Extract `(url, title)` pairs from an AustLII search result HTML page.
///
/// AustLII result links look like:
/// `<a href="http://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html">Case Title</a>`
pub(super) fn extract_case_links(html: &str) -> Vec<(String, String)> {
    let mut hits: Vec<(String, String)> = Vec::new();

    // Find all anchor tags whose href points to /au/cases/
    let mut pos = 0;
    while let Some(start) = html[pos..].find("<a ") {
        let abs = pos + start;
        let tag_end = html[abs..].find('>').map_or(html.len(), |e| abs + e + 1);
        let tag = &html[abs..tag_end.min(html.len())];

        if let Some(href) = attr_value(tag, "href")
            && (href.contains("/au/cases/") || href.contains("austlii.edu.au/au/cases/"))
        {
            // Extract link text up to </a>
            let text_start = tag_end;
            let text_end = html[text_start..]
                .find("</a>")
                .map_or(html.len(), |e| text_start + e);
            let raw_text = &html[text_start..text_end.min(html.len())];
            let title = strip_tags(raw_text).trim().to_string();
            if !title.is_empty() && !hits.iter().any(|(u, _)| u == &href) {
                hits.push((href, title));
            }
        }

        pos = tag_end;
        if pos >= html.len() {
            break;
        }
    }

    hits
}

/// Extract an HTML attribute value from a tag string.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let search = format!("{attr}=");
    let idx = tag.find(&search)?;
    let rest = &tag[idx + search.len()..];
    let (quote, end_char) = if let Some(s) = rest.strip_prefix('"') {
        (s, '"')
    } else if let Some(s) = rest.strip_prefix('\'') {
        (s, '\'')
    } else {
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    };
    quote.find(end_char).map(|e| quote[..e].to_string())
}

/// Remove HTML tags from a string.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}
