//! Build-time console provenance. The exact same rendered page supplies both wire encodings.

use std::fmt::Write as _;

pub const PAGE_ID_SLOT: &str = r#"<meta name="huntsman-page" content="">"#;

pub fn render(source: &str) -> (String, String) {
    assert_eq!(
        source.matches(PAGE_ID_SLOT).count(),
        1,
        "the Web UI needs exactly one page ID slot"
    );
    let digest = ring::digest::digest(&ring::digest::SHA256, source.as_bytes());
    let mut id = String::with_capacity(16);
    for byte in &digest.as_ref()[..8] {
        write!(id, "{byte:02x}").expect("writing to String is infallible");
    }
    let page = source.replacen(
        PAGE_ID_SLOT,
        &format!(r#"<meta name="huntsman-page" content="{id}">"#),
        1,
    );
    (id, page)
}
