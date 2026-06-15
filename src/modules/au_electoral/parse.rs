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

/// Parse an ECSA (SA) enrolment response.
/// Returns `(enrolled, division)`. Pure.
pub(crate) fn parse_ecsa(html: &str) -> (bool, Option<String>) {
    let text = strip_electoral_html(html);
    let lc = text.to_lowercase();
    let enrolled = lc.contains("you are enrolled")
        || lc.contains("enrolled in")
        || lc.contains("enrolled for");
    if !enrolled {
        return (false, None);
    }
    let division =
        extract_named_division(&text, &lc).or_else(|| extract_electorate_label(&text, &lc));
    (true, division)
}

/// Parse a WAEC (WA) enrolment response.
/// Returns `(enrolled, district)`. Pure.
pub(crate) fn parse_waec(html: &str) -> (bool, Option<String>) {
    let text = strip_electoral_html(html);
    let lc = text.to_lowercase();
    let enrolled = lc.contains("you are enrolled")
        || lc.contains("enrolled in")
        || lc.contains("enrolled for");
    if !enrolled {
        return (false, None);
    }
    let division = extract_named_division(&text, &lc)
        .or_else(|| extract_electorate_label(&text, &lc))
        .or_else(|| extract_district_label(&text, &lc));
    (true, division)
}

/// Parse a TEC (TAS) enrolment response.
/// Returns `(enrolled, division)`. Pure.
pub(crate) fn parse_tec(html: &str) -> (bool, Option<String>) {
    let text = strip_electoral_html(html);
    let lc = text.to_lowercase();
    let enrolled = lc.contains("you are enrolled")
        || lc.contains("enrolled in")
        || lc.contains("enrolled for");
    if !enrolled {
        return (false, None);
    }
    let division =
        extract_named_division(&text, &lc).or_else(|| extract_electorate_label(&text, &lc));
    (true, division)
}

/// Parse an Elections ACT enrolment response.
/// Returns `(enrolled, electorate)`. Pure.
pub(crate) fn parse_elections_act(html: &str) -> (bool, Option<String>) {
    let text = strip_electoral_html(html);
    let lc = text.to_lowercase();
    let enrolled = lc.contains("you are enrolled")
        || lc.contains("enrolled in")
        || lc.contains("enrolled for");
    if !enrolled {
        return (false, None);
    }
    let division =
        extract_named_division(&text, &lc).or_else(|| extract_electorate_label(&text, &lc));
    (true, division)
}

/// Parse an NTEC (NT) enrolment response.
/// Returns `(enrolled, electorate)`. Pure.
pub(crate) fn parse_ntec(html: &str) -> (bool, Option<String>) {
    let text = strip_electoral_html(html);
    let lc = text.to_lowercase();
    let enrolled = lc.contains("you are enrolled")
        || lc.contains("enrolled in")
        || lc.contains("enrolled for");
    if !enrolled {
        return (false, None);
    }
    let division =
        extract_named_division(&text, &lc).or_else(|| extract_electorate_label(&text, &lc));
    (true, division)
}

/// Extract a division name from patterns like `"division of NAME"` or
/// `"enrolled in NAME"` / `"enrolled for NAME"`. Pure.
fn extract_named_division(text: &str, lc: &str) -> Option<String> {
    // "division of <Name>"
    if let Some(pos) = lc.find("division of ") {
        let rest = &text[pos + "division of ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
            .collect();
        let name = name.trim().to_string();
        if !name.is_empty() && name.len() < 40 {
            return Some(name);
        }
    }
    // "enrolled in/for <Name>"
    for marker in &["enrolled in ", "enrolled for "] {
        if let Some(pos) = lc.find(marker) {
            let rest = &text[pos + marker.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
                .collect();
            let name = name.trim().to_string();
            if !name.is_empty() && name.len() < 40 {
                return Some(name);
            }
        }
    }
    None
}

/// Extract a division from `"electorate: NAME"` or `"electorate:NAME"`. Pure.
fn extract_electorate_label(text: &str, lc: &str) -> Option<String> {
    for marker in &["electorate: ", "electorate:"] {
        if let Some(pos) = lc.find(marker) {
            let rest = &text[pos + marker.len()..];
            let name: String = rest
                .chars()
                .skip_while(|c| c.is_whitespace())
                .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
                .collect();
            let name = name.trim().to_string();
            if !name.is_empty() && name.len() < 40 {
                return Some(name);
            }
        }
    }
    None
}

/// Extract a division from `"district: NAME"` or `"district:NAME"`. Pure.
fn extract_district_label(text: &str, lc: &str) -> Option<String> {
    for marker in &["district: ", "district:"] {
        if let Some(pos) = lc.find(marker) {
            let rest = &text[pos + marker.len()..];
            let name: String = rest
                .chars()
                .skip_while(|c| c.is_whitespace())
                .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
                .collect();
            let name = name.trim().to_string();
            if !name.is_empty() && name.len() < 40 {
                return Some(name);
            }
        }
    }
    None
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
