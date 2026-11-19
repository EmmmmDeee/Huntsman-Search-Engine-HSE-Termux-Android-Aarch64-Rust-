//! The page the console serves and the Content-Security-Policy each response carries. The page's
//! inline script and style are pinned by SHA-256 in the policy, so the page's hashes, its id and
//! the policies that name them are all derived here, from the one embedded file.

use std::sync::LazyLock;

use super::response::response_bytes;
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
        hash_source(inline_block(PAGE, "script")),
        hash_source(inline_block(PAGE, "style")),
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

/// Static, public content rendered at build time, with its provenance marker in the head.
/// The page carries no credentials, queries or case data.
const PAGE: &str = include_str!(concat!(env!("OUT_DIR"), "/huntsman-page.html"));
const PAGE_GZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/huntsman-page.gz"));

/// The first 16 hex digits of the SHA-256 of the page source this build embeds.
pub(super) const PAGE_ID: &str = include_str!(concat!(env!("OUT_DIR"), "/huntsman-page.id"));

#[cfg(test)]
pub(super) const INDEX_HTML: &str = include_str!("../web_ui.html");
#[cfg(test)]
#[path = "page_asset.rs"]
mod asset;
#[cfg(test)]
pub(super) use asset::PAGE_ID_SLOT;

#[cfg(test)]
#[test]
fn both_page_encodings_carry_exactly_the_build_provenance() {
    let (id, page) = asset::render(INDEX_HTML);
    assert_eq!(id, PAGE_ID);
    assert_eq!(page, PAGE);
    let deflate = &PAGE_GZIP[10..PAGE_GZIP.len() - 8];
    assert_eq!(
        miniz_oxide::inflate::decompress_to_vec(deflate).unwrap(),
        PAGE.as_bytes()
    );
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct PageEncodings {
    gzip: Option<u16>,
    identity: Option<u16>,
    wildcard: Option<u16>,
}

impl PageEncodings {
    pub(super) fn add(&mut self, field: &str) {
        for item in field.split(',') {
            let (coding, parameter) = item
                .split_once(';')
                .map_or((item, None), |(coding, parameter)| {
                    (coding, Some(parameter))
                });
            let coding = coding.trim();
            let entry = if coding.eq_ignore_ascii_case("gzip") {
                &mut self.gzip
            } else if coding.eq_ignore_ascii_case("identity") {
                &mut self.identity
            } else if coding == "*" {
                &mut self.wildcard
            } else {
                continue;
            };
            let weight = parameter.map_or(1000, |parameter| {
                parameter
                    .split_once('=')
                    .filter(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
                    .and_then(|(_, value)| quality(value.trim()))
                    .unwrap_or(0)
            });
            // An explicit refusal has precedence over either a wildcard or a repeated offer.
            *entry = Some(entry.map_or(weight, |previous| previous.min(weight)));
        }
    }
}

fn quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    match whole {
        "1" if fraction.bytes().all(|digit| digit == b'0') => Some(1000),
        "0" => Some(
            fraction
                .bytes()
                .zip([100, 10, 1])
                .map(|(digit, place)| u16::from(digit - b'0') * place)
                .sum(),
        ),
        _ => None,
    }
}

pub(super) fn page_response(encodings: PageEncodings, head: bool) -> Vec<u8> {
    const HTML: &str = "text/html; charset=utf-8";
    const VARY: &str = "Vary: Accept-Encoding\r\n";
    const GZIP_HEADERS: &str = "Vary: Accept-Encoding\r\nContent-Encoding: gzip\r\n";

    let gzip = encodings.gzip.or(encodings.wildcard).unwrap_or(0);
    let identity_allowed = encodings
        .identity
        .map_or(encodings.wildcard != Some(0), |weight| weight > 0);
    if gzip > 0 && gzip >= encodings.identity.unwrap_or(0) {
        response_bytes(200, HTML, PAGE_GZIP, head, GZIP_HEADERS)
    } else if identity_allowed {
        response_bytes(200, HTML, PAGE.as_bytes(), head, VARY)
    } else {
        response_bytes(
            406,
            "text/plain; charset=utf-8",
            b"no acceptable content encoding\n",
            head,
            VARY,
        )
    }
}

/// The console's locator mark, as the tab icon. It is a file of its own because the page policy
/// loads images only from this server.
pub(super) const FAVICON_SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect width=\"32\" height=\"32\" rx=\"6\" fill=\"#0a0d11\"/><circle cx=\"16\" cy=\"16\" r=\"8\" fill=\"none\" stroke=\"#1cb8f5\" stroke-width=\"2\"/><circle cx=\"16\" cy=\"16\" r=\"2.4\" fill=\"#1cb8f5\"/><path d=\"M16 2v6M16 24v6M2 16h6M24 16h6\" stroke=\"#1cb8f5\" stroke-width=\"2\"/></svg>\n";
