//! HTML parsing helpers for electoral commission response pages.

static DIVISION_MARKER: std::sync::LazyLock<crate::util::scan::MatchSet> =
    std::sync::LazyLock::new(|| crate::util::scan::MatchSet::new_ascii_ci(["division of "]));

static ENROLLED_MARKERS: std::sync::LazyLock<crate::util::scan::MatchSet> =
    std::sync::LazyLock::new(|| {
        crate::util::scan::MatchSet::new_ascii_ci(["enrolled in ", "enrolled for "])
    });

/// Parse a confirmed division name from an AEC or state EC HTML response.
/// Returns `(division_name, suburb_hint)` when a match is found. Pure.
///
/// The AEC "Check enrolment" response contains patterns like:
/// `"You are enrolled for the Division of Sydney"` or
/// `"enrolled for Sydney (NSW)"`. State commissions use similar phrasing.
pub(crate) fn extract_division(html: &str) -> Option<(String, Option<String>)> {
    let text = strip_electoral_html(html);

    // AEC pattern: "division of <name>". `find_range` returns boundary-safe
    // `[start, end)` from original bytes — no offset-on-a-copy panic risk.
    if let Some((pos, end)) = DIVISION_MARKER.find_range(&text) {
        let rest = &text[end..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
            .collect();
        let name = name.trim().to_string();
        if !name.is_empty() && name.len() < 40 {
            let suburb = extract_suburb_hint(&text[pos..]);
            return Some((name, suburb));
        }
    }

    // State EC pattern: "enrolled in <Division>" or "enrolled for <Division>".
    // One aho-corasick pass covers both markers; `end` skips past whichever
    // matched without needing to know its length.
    if let Some((pos, end)) = ENROLLED_MARKERS.find_range(&text) {
        let rest = &text[end..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphabetic() || *c == '-' || *c == ' ')
            .collect();
        let name = name.trim().to_string();
        if !name.is_empty() && name.len() < 40 {
            return Some((name, extract_suburb_hint(&text[pos..])));
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
    // `saturating_sub(3)` (not 4): a 4-digit postcode occupying the final 4 bytes of
    // the window must still be examined — `saturating_sub(4)` skipped it. Matches the
    // sibling au_property::extract_postcode bound.
    for i in 0..bytes.len().saturating_sub(3) {
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
mod extract_division_tests {
    use super::extract_division;

    #[test]
    fn aec_division_of_pattern() {
        // Typical AEC format: "Division of Sydney" followed by punctuation/digits.
        let html = "<div>You are enrolled for the Division of Sydney (2026)</div>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Sydney");
    }

    #[test]
    fn state_ec_enrolled_for_pattern() {
        let html = "<p>You are enrolled for Bondi Beach 2026</p>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Bondi Beach");
    }

    #[test]
    fn state_ec_enrolled_in_pattern() {
        let html = "<p>You are enrolled in Parramatta</p>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Parramatta");
    }

    #[test]
    fn no_marker_returns_none() {
        assert_eq!(extract_division("<p>Nothing electoral here</p>"), None);
    }

    #[test]
    fn case_insensitive_match() {
        let html = "<p>DIVISION OF Melbourne</p>";
        let (name, _) = extract_division(html).expect("should succeed");
        assert_eq!(name, "Melbourne");
    }
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
