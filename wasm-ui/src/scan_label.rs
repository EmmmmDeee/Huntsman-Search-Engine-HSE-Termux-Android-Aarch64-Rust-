//! What the console calls a scan, and what it scanned: the name its operator
//! gave it (SpiderFoot's "Scan Name"), else its target, else its id, with the
//! target shown beside a named scan. One rule, so the scan list, Scan Info,
//! Compare's pickers and the Live page agree (REQ-SCANNAME-001). The JS views
//! reach it as `scanLabel(scan)`, exported beside the scan table's own row
//! type in [`crate::views::scans`].

/// A scan's title, and its target when that says something the title does
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLabel<'a> {
    /// The name, else the target's value, else the id.
    pub title: &'a str,
    /// The target's value, when it is not the title: a named scan still
    /// shows what it scanned.
    pub target: Option<&'a str>,
}

/// Label a scan from its name, its target's value and its id. Each is
/// trimmed, and a blank name or value counts as none.
#[must_use]
pub fn scan_label<'a>(
    name: Option<&'a str>,
    target: Option<&'a str>,
    id: &'a str,
) -> ScanLabel<'a> {
    let target = target.map(str::trim).filter(|t| !t.is_empty());
    let name = name.map(str::trim).filter(|n| !n.is_empty());
    let title = name.or(target).unwrap_or(id);
    ScanLabel {
        title,
        target: target.filter(|t| *t != title),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_scan_is_called_by_its_name_and_shows_its_target() {
        assert_eq!(
            scan_label(Some("Q3 audit"), Some("a@example.com"), "abc"),
            ScanLabel {
                title: "Q3 audit",
                target: Some("a@example.com"),
            }
        );
    }

    #[test]
    fn an_unnamed_scan_is_called_by_its_target_then_its_id() {
        let plain = ScanLabel {
            title: "a@example.com",
            target: None,
        };
        assert_eq!(scan_label(None, Some("a@example.com"), "abc"), plain);
        assert_eq!(
            scan_label(Some("  "), Some(" a@example.com "), "abc"),
            plain
        );
        assert_eq!(
            scan_label(None, None, "abc"),
            ScanLabel {
                title: "abc",
                target: None,
            }
        );
        assert_eq!(scan_label(Some(""), Some(" "), "abc").title, "abc");
    }

    #[test]
    fn a_name_that_is_its_target_is_shown_once() {
        assert_eq!(
            scan_label(Some("a@example.com"), Some("a@example.com"), "abc").target,
            None
        );
    }
}
