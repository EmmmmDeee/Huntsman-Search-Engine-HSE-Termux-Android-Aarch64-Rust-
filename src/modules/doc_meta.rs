//! Document metadata harvesting from PDF URLs — author, authoring toolchain,
//! and any embedded GPS.
//!
//! The classic FOCA-style pivot: published PDFs (reports, résumés, leaked
//! documents, council/court filings) routinely carry an `/Info` dictionary
//! and/or an XMP packet naming the **author**, the **authoring application**
//! (`/Creator`), and the **producing library** (`/Producer`) — strong
//! identity and toolchain-fingerprint leads that the same person/organisation
//! leaves across many separate documents.
//!
//! Workflow when a `.pdf` `Url` target arrives:
//!   1. Range-fetch the bytes via `ctx.http` (capped at 16 MB).
//!   2. Parse the `/Info` dictionary + embedded XMP via `util::metadata`
//!      (dependency-free byte-scan — no PDF/zip crate pulled into the build).
//!   3. Emit `Person` (author), `DeviceId` (authoring/producing tool, tagged
//!      `authoring-tool`), and `Coordinates` (rare embedded XMP GPS). Each
//!      entity carries a `doc_url` evidence attribute so the AU-033 correlator
//!      can cluster documents of shared origin.
//!
//! In-memory only: the document is parsed and dropped — **never written to
//! disk** (privacy + storage constraint on Termux).

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::metadata::parse_pdf;

const SRC: &str = "doc_meta";

/// Cap on document fetch size. Most metadata-bearing PDFs are well under this;
/// a deliberately huge file is bounded here to protect memory on-device.
const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Document extensions worth fetching. PDF only for now — Office OOXML
/// (`.docx`/`.xlsx`/`.pptx`) is ZIP-compressed, so its `docProps/core.xml`
/// can't be byte-scanned without an inflate dependency; deferred to keep the
/// single binary dependency-free.
const DOC_EXTS: &[&str] = &[".pdf"];

pub struct DocMeta;

#[async_trait]
impl Module for DocMeta {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Harvest author + authoring toolchain from PDF document metadata"
    }

    fn priority(&self) -> u8 {
        // Same band as exif_geo (28): below the crawlers/search engines that
        // surface the URLs, above the background geo bench.
        28
    }

    fn category(&self) -> ModuleCategory {
        // Output is identity-centric (authors), so it groups with People.
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::DeviceId,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only gate so the probe-derived dispatch index includes `Url`;
        // the `.pdf` filter runs in `process()` (a value-shaped check here
        // would leave `consumes()` empty and the module never dispatched).
        matches!(t.kind, TargetKind::Url)
    }

    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::Url]
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let url = target.value.trim();
        // Value-shape gate (moved out of `accepts()`): only fetch `.pdf` URLs.
        if url.is_empty() || !looks_like_doc_url(url) {
            return Ok(result);
        }

        // In-memory only: range-fetch, parse, drop. The document is NEVER
        // written to disk.
        let resp = match ctx
            .http
            .get(url)
            .header("Range", format!("bytes=0-{}", MAX_BYTES.saturating_sub(1)))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(result),
        };
        if !resp.status().is_success() && resp.status().as_u16() != 206 {
            return Ok(result);
        }
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => return Ok(result),
        };
        if bytes.len() > MAX_BYTES as usize {
            return Ok(result);
        }

        let meta = parse_pdf(&bytes);

        // ── Author → Person ──
        if let Some(author) = meta.author.as_deref().map(str::trim).filter(non_empty) {
            let mut e = Entity::new(EntityKind::Person, author, 0.70, &ctx.scan_id);
            e.tag("doc-author");
            e.tag("doc-derived");
            let mut ev =
                Evidence::new(SRC, format!("PDF author from {url}")).with_attr("doc_url", url);
            if let Some(t) = meta.title.as_deref().filter(non_empty) {
                ev = ev.with_attr("title", t);
            }
            if let Some(c) = meta.created.as_deref().filter(non_empty) {
                ev = ev.with_attr("created", c);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        // ── Authoring/producing toolchain → DeviceId ──
        // `/Creator` (authoring app) is preferred; fall back to `/Producer`
        // (the rendering library). Same toolchain across many documents is a
        // fingerprint that links them — tagged weak, like a cohort signal.
        if let Some(tool) = meta
            .creator
            .as_deref()
            .or(meta.producer.as_deref())
            .map(str::trim)
            .filter(non_empty)
        {
            let mut e = Entity::new(EntityKind::DeviceId, tool, 0.45, &ctx.scan_id);
            e.tag("authoring-tool");
            e.tag("weak-device-link");
            let mut ev = Evidence::new(SRC, format!("authoring toolchain for {url}"))
                .with_attr("doc_url", url);
            if let Some(c) = meta.creator.as_deref().filter(non_empty) {
                ev = ev.with_attr("creator", c);
            }
            if let Some(p) = meta.producer.as_deref().filter(non_empty) {
                ev = ev.with_attr("producer", p);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        // ── Embedded XMP GPS → Coordinates (rare, but free) ──
        if let Some((lat, lon)) = meta.gps {
            let coord_str = format!("{lat:.6},{lon:.6}");
            let mut e = Entity::new(EntityKind::Coordinates, &coord_str, 0.75, &ctx.scan_id);
            e.tag("geoint");
            e.tag("doc-derived");
            e.add_evidence(
                Evidence::new(SRC, format!("PDF XMP GPS from {url}")).with_attr("doc_url", url),
            );
            result.push(e);
        }

        Ok(result)
    }
}

/// `true` if `s` is non-empty after trimming. Tiny helper used as a filter
/// predicate, accepting `&&str` so it works inside `.filter(|s| …)`.
fn non_empty(s: &&str) -> bool {
    !s.trim().is_empty()
}

/// True if the URL path (query/fragment stripped) ends in a document
/// extension we can parse.
fn looks_like_doc_url(url: &str) -> bool {
    let path = url
        .trim()
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_lowercase();
    DOC_EXTS.iter().any(|ext| path.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_url_kind_only() {
        // Kind-only gate (the .pdf filter is applied in process()), and
        // consumes() surfaces Url so the dispatch index is built.
        let m = DocMeta;
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://x.com/report.pdf")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://x.com/page.html")));
        assert_eq!(m.consumes(), vec![TargetKind::Url]);
        // Non-URL kinds never route here, even shaped like a PDF.
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.pdf")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.pdf")));
    }

    // The `.pdf` filter that used to live in accepts() is exercised via the
    // looks_like_doc_url helper test below.

    #[test]
    fn category_is_people_and_produces_expected_kinds() {
        assert_eq!(DocMeta.category(), ModuleCategory::People);
        assert_eq!(
            DocMeta.produces(),
            &[
                EntityKind::Person,
                EntityKind::DeviceId,
                EntityKind::Coordinates
            ]
        );
    }

    #[test]
    fn looks_like_doc_url_strips_query() {
        assert!(looks_like_doc_url("https://a.b/c.pdf?x=1#y"));
        assert!(looks_like_doc_url("https://a.b/C.PDF"));
        assert!(!looks_like_doc_url("https://a.b/c.pdf.html"));
    }
}
