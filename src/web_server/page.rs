//! The page the console serves and the Content-Security-Policy each response carries. The page's
//! inline script and style are pinned by SHA-256 in the policy, so the page's hashes, its id and
//! the policies that name them are all derived here, from the one embedded file.

use std::sync::LazyLock;

use crate::base64;
use crate::sha256::sha256;

/// The page's policy. Its one inline script and its one inline style run because their SHA-256
/// is listed, so injected markup cannot run script. Nothing loads from elsewhere, requests go
/// only to this server, and no other page may frame it. Without that last rule, a site open in
/// the same phone browser could lay this page under its own and turn taps into lookups that
/// spend the operator's keys.
pub(super) static PAGE_POLICY: LazyLock<String> = LazyLock::new(|| {
    format!(
        "default-src 'none'; script-src '{}'; style-src '{}'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        hash_source(inline_block(INDEX_HTML, "script")),
        hash_source(inline_block(INDEX_HTML, "style")),
    )
});

/// Dedicated, script-free CSP for locally rendered dossier pages.
pub(super) static DOSSIER_POLICY: LazyLock<String> = LazyLock::new(|| {
    format!(
        "default-src 'none'; script-src 'none'; style-src '{}'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        hash_source(crate::dossier_view::STYLE)
    )
});

/// Every other response loads nothing and may not be framed.
pub(super) const OTHER_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

/// The text between `<tag>` and `</tag>`, the part a browser hashes for a CSP hash source.
pub(crate) fn inline_block<'a>(page: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    match (page.find(&open), page.find(&close)) {
        (Some(start), Some(end)) if start + open.len() <= end => &page[start + open.len()..end],
        _ => "",
    }
}

pub(crate) fn hash_source(content: &str) -> String {
    format!("sha256-{}", base64::standard(&sha256(content.as_bytes())))
}

/// The page: one inline style and one inline script, so the policy can pin both by hash. It is
/// the HSE console's look (app bar, bottom tabs on a phone, panels), over this server's routes.
pub(super) const INDEX_HTML: &str = include_str!("../web_ui.html");

/// The empty page id [`PAGE`] fills in, in the page's head and outside its script and style, so
/// filling it leaves the hashes [`PAGE_POLICY`] lists unchanged.
pub(super) const PAGE_ID_SLOT: &str = r#"<meta name="huntsman-page" content="">"#;

/// The first 16 hex digits of the SHA-256 of the page this build embeds. Every page an upgrade
/// changes gets a new id, a build without provenance metadata included.
pub(super) static PAGE_ID: LazyLock<String> =
    LazyLock::new(|| crate::sha256::hex32(&sha256(INDEX_HTML.as_bytes()))[..16].to_owned());

/// The page as served: [`INDEX_HTML`] carrying its [`PAGE_ID`], which the page compares with
/// the one every health answer names.
pub(super) static PAGE: LazyLock<String> = LazyLock::new(|| {
    INDEX_HTML.replacen(
        PAGE_ID_SLOT,
        &format!(r#"<meta name="huntsman-page" content="{}">"#, *PAGE_ID),
        1,
    )
});

/// The console's locator mark, as the tab icon. It is a file of its own because the page policy
/// loads images only from this server.
pub(super) const FAVICON_SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect width=\"32\" height=\"32\" rx=\"6\" fill=\"#0a0d11\"/><circle cx=\"16\" cy=\"16\" r=\"8\" fill=\"none\" stroke=\"#1cb8f5\" stroke-width=\"2\"/><circle cx=\"16\" cy=\"16\" r=\"2.4\" fill=\"#1cb8f5\"/><path d=\"M16 2v6M16 24v6M2 16h6M24 16h6\" stroke=\"#1cb8f5\" stroke-width=\"2\"/></svg>\n";
