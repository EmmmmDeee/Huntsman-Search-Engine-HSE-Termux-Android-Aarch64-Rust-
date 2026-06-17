//! HTML parsing helpers for electoral commission response pages.

/// Parse a confirmed division name from an AEC or state EC HTML response.
/// Returns `(division_name, suburb_hint)` when a match is found. Pure.
///
/// The AEC "Check enrolment" response contains patterns like:
/// `"You are enrolled for the Division of Sydney"` or
/// `"enrolled for Sydney (NSW)"`. State commissions use similar phrasing.
pub(crate) fn extract_division(html: &str) -> Option<(String, Option<String>)> {
    let text = strip_electoral_html(html);
    let lc = text.to_lowercase();

    // AEC pattern: "division of <name>"
    if let Some(pos) = lc.find("division of ") {
        let rest = &text[pos + "division of ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
            .collect();
        let name = name.trim().to_string();
        if !name.is_empty() && name.len() < 40 {
            // Try to extract a suburb hint from the same context window.
            let suburb = extract_suburb_hint(&text[pos..]);
            return Some((name, suburb));
        }
    }

    // State EC pattern: "enrolled in <Division>" or "enrolled for <Division>".
    ["enrolled in ", "enrolled for "].iter().find_map(|marker| {
        let pos = lc.find(marker)?;
        let rest = &text[pos + marker.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
            .collect();
        let name = name.trim().to_string();
        (!name.is_empty() && name.len() < 40).then(|| (name, extract_suburb_hint(&text[pos..])))
    })
}

/// Strip HTML tags from an electoral response, inserting spaces at each tag
/// boundary to prevent word concatenation. Pure.
pub(super) fn strip_electoral_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    // Collapse runs of whitespace.
    let mut result = String::with_capacity(out.len());
    let mut prev_space = false;
    for ch in out.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result
}

/// Extract a suburb hint from the text window around a division match.
/// Looks for AU postcode patterns to anchor a suburb name. Pure.
fn extract_suburb_hint(window: &str) -> Option<String> {
    // A 4-digit postcode in range 2000..9999 indicates a suburb is nearby.
    let bytes = window.as_bytes();
    for i in 0..bytes.len().saturating_sub(4) {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
        {
            let pc: u32 = window[i..i + 4].parse().ok()?;
            if (2000..=9999).contains(&pc) {
                // Walk backwards to collect the suburb name before the postcode.
                let before = window[..i].trim_end();
                let suburb: String = before
                    .chars()
                    .rev()
                    .take_while(|c| c.is_alphabetic() || *c == ' ')
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                let suburb = suburb.trim().to_string();
                if !suburb.is_empty() && suburb.len() < 30 {
                    return Some(suburb);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod suburb_hint_tests {
    use super::extract_suburb_hint;

    #[test]
    fn anchors_suburb_on_in_range_postcode() {
        assert_eq!(
            extract_suburb_hint("Bondi Beach 2026 NSW"),
            Some("Bondi Beach".to_string())
        );
    }

    #[test]
    fn out_of_range_postcode_yields_none() {
        assert_eq!(extract_suburb_hint("Suburbia 1234"), None);
    }

    #[test]
    fn no_postcode_yields_none() {
        assert_eq!(extract_suburb_hint("Division of Sydney NSW"), None);
    }

    #[test]
    fn postcode_with_no_preceding_alpha_yields_none() {
        assert_eq!(extract_suburb_hint("2000 only"), None);
    }
}
