use super::{AuCourtRecords, parse::extract_case_links};
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

#[test]
fn extracts_case_links() {
    let html = r#"
        <div class="results">
          <a href="http://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html">Smith v Jones [2023] HCA 1</a>
          <a href="http://www.austlii.edu.au/au/cases/nsw/NSWCA/2022/45.html">Jones v Smith [2022] NSWCA 45</a>
          <a href="https://example.com/other">Not a case</a>
        </div>
    "#;
    let hits = extract_case_links(html);
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].1, "Smith v Jones [2023] HCA 1");
    assert_eq!(hits[1].1, "Jones v Smith [2022] NSWCA 45");
}

#[test]
fn empty_html() {
    assert!(extract_case_links("").is_empty());
}

#[test]
fn deduplicates_urls() {
    let html = r#"
        <a href="http://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html">Case 1</a>
        <a href="http://www.austlii.edu.au/au/cases/cth/HCA/2023/1.html">Case 1 duplicate</a>
    "#;
    let hits = extract_case_links(html);
    assert_eq!(hits.len(), 1);
}

#[test]
fn accepts_fullname_and_organisation() {
    let m = AuCourtRecords;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}
