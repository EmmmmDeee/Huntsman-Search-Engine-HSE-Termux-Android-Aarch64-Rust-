//! Sitemap enumeration — fetch and parse a domain's owner-published
//! `sitemap.xml` (and `sitemap-index.xml`, and any `Sitemap:` directive in
//! `robots.txt`) to seed `Url` entities beyond what the live BFS crawl's
//! link-following finds.
//!
//! A sitemap is the site owner's OWN declaration of the URLs they consider
//! canonical — it routinely lists pages the live navigation never links to
//! (paginated archives, gated/orphaned content, API doc roots, region variants),
//! each of which becomes a fresh `Url` pivot the engine re-dispatches through
//! `web_crawler`, `url_extract`, `wayback`, and every other `Url`-accepting
//! module. Complementary to `web_crawler` (which follows `href` links from a
//! live page) and `wayback` (which recovers *historical* URLs): this reads the
//! owner's *current* canonical list.
//!
//! Sources, in order: (1) `robots.txt` `Sitemap:` directives (the authoritative
//! pointer), then (2) `/sitemap.xml` and `/sitemap_index.xml` at the apex (the
//! conventional locations).
//!
//! A `<sitemapindex>` is followed ONE level into its child sitemaps. Every
//! fetched sitemap URL is confined to the target's own registrable domain (no
//! following an index that points off-site — scope and SSRF safety). Zero new
//! dependencies: `<loc>` values are extracted by string scan, the same
//! regex-free approach `web_crawler` uses. Bounded fetches, body caps, and a
//! hard URL cap keep it Termux-friendly.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::domains::registrable_domain;
use crate::util::http::{RequestBuilderExt, read_body_capped};

const SRC: &str = "sitemap";

/// Max sitemap documents fetched per scan (the apex candidates plus children of
/// one index), bounding total round-trips on a mobile link.
const MAX_SITEMAP_FETCHES: usize = 12;

/// Max `Url` entities emitted per scan — a large sitemap can list tens of
/// thousands of URLs; cap the pivots so recursion stays bounded.
const MAX_URLS: usize = 200;

/// Per-document body cap. Sitemaps are text/XML; 5 MiB covers a full 50k-URL
/// sitemap (the sitemaps.org per-file limit) without letting a hostile server
/// stream unbounded bytes onto the device.
const MAX_SITEMAP_BYTES: usize = 5 * 1024 * 1024;

/// Inter-fetch delay — polite pacing for the target's own server.
const INTER_FETCH_MS: u64 = 150;

pub struct Sitemap;

/// Extract every `<loc>…</loc>` value from a sitemap or sitemap-index document.
/// **Pure**: a regex-free scan (matching `web_crawler`'s approach), tolerant of
/// attributes on the `<loc>` tag and surrounding whitespace, XML-unescaping the
/// handful of entities a URL can legally carry. Deduped, order-preserving.
fn extract_locs(xml: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let bytes = xml.as_bytes();
    let lower = xml.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find("<loc") {
        let tag_start = cursor + rel;
        // Find the '>' that closes the opening <loc ...> tag.
        let Some(gt_rel) = xml[tag_start..].find('>') else {
            break;
        };
        let content_start = tag_start + gt_rel + 1;
        // Find the closing </loc>.
        let Some(end_rel) = lower[content_start..].find("</loc>") else {
            break;
        };
        let content_end = content_start + end_rel;
        let raw = xml[content_start..content_end].trim();
        if !raw.is_empty() {
            let url = xml_unescape(raw);
            if seen.insert(url.clone()) {
                out.push(url);
            }
        }
        cursor = content_end + "</loc>".len();
        // Defensive: never spin on a malformed doc.
        if cursor >= bytes.len() {
            break;
        }
    }
    out
}

/// Unescape the entities a `<loc>` URL can legally carry, via the crate's single
/// shared decoder.
///
/// Delegates to [`crate::util::html::decode_entities`] rather than hand-rolling a
/// `.replace()` chain. A chain applies each replacement to the *previous one's
/// output*, so `&amp;` decoding to `&` can combine with the text after it to form
/// an entity a later link then decodes again: `&amp;lt;` — a literal `&lt;` in the
/// source — came out as `<`, a silently wrong URL rather than an error. The shared
/// decoder consumes each `&…;` exactly once, so that round-trips correctly, and it
/// also resolves the numeric character references (`&#38;`, `&#x26;`) the chain
/// left raw in the URL.
///
/// One decoder for the whole crate is the point, so this deliberately accepts a
/// wider named set than XML's five predefined entities — `&copy;`, `&trade;` and
/// the rest of the HTML table decode here too. A well-formed sitemap cannot
/// contain those undeclared, so the only documents affected are already
/// malformed, and re-introducing a narrower local decoder to reject them is
/// exactly the drift this delegation removes. **Pure**.
fn xml_unescape(s: &str) -> String {
    crate::util::html::decode_entities(s)
}

/// True if the document is a sitemap INDEX (lists child sitemaps) rather than a
/// urlset (lists page URLs). **Pure**.
fn is_sitemap_index(xml: &str) -> bool {
    xml.to_ascii_lowercase().contains("<sitemapindex")
}

/// What one fetched document turned out to be, and what to do with its
/// `<loc>` values. Returned by [`classify_document`].
enum DocumentKind {
    /// A `<sitemapindex>` — its `<loc>` values are child sitemap URLs, never
    /// page URLs. Empty when the index was encountered past the one level of
    /// recursion this module follows (a deeper index-of-indexes): its
    /// children are dropped rather than enqueued further or, worse,
    /// misreported as page content.
    Index(Vec<String>),
    /// A urlset — its `<loc>` values are page URLs to emit.
    UrlSet(Vec<String>),
}

/// Classify one fetched sitemap-adjacent document and extract its `<loc>`
/// values accordingly. **Pure** — this is the exact decision `process()`'s
/// enumeration loop applies, factored out so it is unit-testable without a
/// live fetch loop.
///
/// Regression: this used to be `is_sitemap_index(&body) && depth == 0` inline
/// in the loop, with anything else (a urlset, OR an index found past depth 0)
/// falling through to the "emit these as page URLs" branch. A nested
/// index-of-indexes is a real, if uncommon, sitemap shape — sites split a
/// root index into per-section indexes, each pointing to per-date urlsets —
/// and its `<loc>` values are further sitemap documents, not pages. The old
/// code minted them as `Url` entities tagged `sitemap-url` regardless.
fn classify_document(xml: &str, depth: u32) -> DocumentKind {
    let locs = extract_locs(xml);
    if is_sitemap_index(xml) {
        DocumentKind::Index(if depth == 0 { locs } else { Vec::new() })
    } else {
        DocumentKind::UrlSet(locs)
    }
}

/// Why the enumeration loop stopped short of exhausting every candidate
/// document. Kept distinct (rather than a single flat boolean) because each
/// cause implies a different thing about how complete the emitted list is:
/// hitting the URL cap means the site likely publishes MORE URLs than were
/// emitted, hitting the fetch cap means there were more CANDIDATE DOCUMENTS
/// left unfetched (independent of how many URLs came from the ones that
/// were), and a cancellation is an operator-initiated stop, not a site
/// property at all. Regression: a single `sitemap_url_cap` attribute used to
/// be written even when the true cause was the fetch cap or a cancellation,
/// which claimed a specific numeric URL ceiling was hit when it may not have
/// been.
#[derive(Clone, Copy)]
enum TruncationReason {
    /// `MAX_URLS` was reached.
    UrlCap,
    /// `MAX_SITEMAP_FETCHES` was reached with candidate documents still
    /// queued.
    FetchCap,
    /// The scan was cancelled mid-enumeration.
    Cancelled,
}

/// Mark the last emitted entity's evidence to say the enumeration was cut
/// short, and why, rather than silently presenting a partial list as the
/// complete sitemap. **Pure**. No-op when `entities` is empty (every
/// candidate document failed to fetch) — there is nowhere to attach the
/// note. Mirrors `web_crawler`'s `image_leads_capped` convention.
fn mark_truncated(entities: &mut [Entity], reason: TruncationReason) {
    if let Some(last) = entities.last_mut()
        && let Some(last_ev) = last.evidence.last_mut()
    {
        last_ev.attributes.insert(
            "sitemap_enumeration_truncated".to_string(),
            "true".to_string(),
        );
        match reason {
            TruncationReason::UrlCap => {
                last_ev
                    .attributes
                    .insert("sitemap_url_cap".to_string(), MAX_URLS.to_string());
            }
            TruncationReason::FetchCap => {
                last_ev.attributes.insert(
                    "sitemap_fetch_cap".to_string(),
                    MAX_SITEMAP_FETCHES.to_string(),
                );
            }
            TruncationReason::Cancelled => {
                last_ev.attributes.insert(
                    "sitemap_enumeration_cancelled".to_string(),
                    "true".to_string(),
                );
            }
        }
    }
}

/// Extract `Sitemap:` directive URLs from a `robots.txt`. **Pure**: case-
/// insensitive on the directive name, one URL per matching line.
fn parse_robots_sitemaps(robots: &str) -> Vec<String> {
    robots
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("sitemap") {
                let url = v.trim();
                (!url.is_empty()).then(|| url.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Reduce a Domain/Url target to its bare lowercase host. **Pure**.
fn target_host(kind: TargetKind, value: &str) -> String {
    match kind {
        TargetKind::Url => crate::util::url_util::host_only(value).to_lowercase(),
        _ => value.trim().trim_end_matches('.').to_lowercase(),
    }
}

/// The "effective site" of a host: its lowercase form with a single leading
/// `www.` stripped. **Pure**. Used so the apex and its `www.` alias compare
/// equal — which `registrable_domain` does NOT guarantee for hosts on a public
/// suffix (`gov.uk` vs `www.gov.uk` have *different* registrable domains because
/// `gov.uk` is itself a public suffix).
fn effective_site(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_lowercase();
    h.strip_prefix("www.").unwrap_or(&h).to_string()
}

/// True if `url`'s host is the target site itself, its `www.`/apex alias, or a
/// subdomain of it — the scope gate on which sitemaps and URLs we accept.
/// **Pure**. SSRF to internal hosts is blocked separately at fetch time
/// ([`fetch_capped`]'s private-host preflight), so this is purely a *scope*
/// backstop against a sitemap that points off the target's own site.
fn in_scope(url: &str, site: &str) -> bool {
    let Some(h) = crate::util::url_util::host_from_url(url) else {
        return false;
    };
    let h = effective_site(&h);
    h == site || h.ends_with(&format!(".{site}"))
}

#[async_trait]
impl Module for Sitemap {
    fn name(&self) -> &'static str {
        "sitemap"
    }

    fn description(&self) -> &'static str {
        "Owner-published sitemap.xml / robots.txt Sitemap enumeration — harvests Url entities"
    }

    fn priority(&self) -> u8 {
        37
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // T1594 — Search Victim-Owned Websites (a sitemap is the owner's own
        // published URL inventory). Superset of the Web default.
        &["T1594"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // robots.txt + up to MAX_SITEMAP_FETCHES documents with INTER_FETCH_MS
        // gaps and per-fetch latency: ~12 × (150ms + ~2s) ≈ 26s. 30s headroom.
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let host = target_host(target.kind, &target.value);
        if host.is_empty() || host.contains('/') || host.contains(' ') || !host.contains('.') {
            return Ok(ModuleResult::new());
        }
        // Must be a real registrable host (rejects bare TLDs / garbage).
        if registrable_domain(&host).is_none() {
            return Ok(ModuleResult::new());
        }
        let site = effective_site(&host);

        // Probe both the host as given AND its www/apex counterpart: the engine
        // normalises a seed to its apex (`www.gov.uk` → `gov.uk`), but many sites
        // serve robots/sitemap only on `www` — and vice-versa. Deduped by the
        // worklist's seen-set, so the redundant pair costs nothing when they
        // resolve to the same document.
        let www = format!("www.{site}");
        let host_variants: Vec<&str> = if host == www {
            vec![host.as_str()]
        } else {
            vec![host.as_str(), www.as_str()]
        };

        // Candidate sitemap URLs: robots.txt Sitemap directives first (the
        // authoritative pointer), then the two conventional locations, for each
        // host variant.
        let mut candidates: Vec<String> = Vec::new();
        for h in &host_variants {
            if let Some(robots) = fetch_capped(ctx, &format!("https://{h}/robots.txt")).await {
                for sm in parse_robots_sitemaps(&robots) {
                    if in_scope(&sm, &site) {
                        candidates.push(sm);
                    }
                }
            }
            candidates.push(format!("https://{h}/sitemap.xml"));
            candidates.push(format!("https://{h}/sitemap_index.xml"));
        }

        let mut fetched = 0usize;
        let mut seen_docs: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut entities: Vec<Entity> = Vec::new();
        // A worklist so a <sitemapindex> can enqueue its children (one level).
        let mut queue: std::collections::VecDeque<(String, u32)> =
            candidates.into_iter().map(|u| (u, 0u32)).collect();
        // Set whenever the enumeration stopped short of exhausting every
        // candidate document — surfaced as evidence below (with the specific
        // reason) rather than silently presenting a partial list as complete.
        let mut truncated: Option<TruncationReason> = None;

        while let Some((doc_url, depth)) = queue.pop_front() {
            if fetched >= MAX_SITEMAP_FETCHES || entities.len() >= MAX_URLS {
                // The popped candidate itself goes unprocessed here — put it
                // back rather than losing it to `pop_front`, so the queue's
                // state honestly reflects that there was more left to do.
                queue.push_front((doc_url, depth));
                truncated = Some(if entities.len() >= MAX_URLS {
                    TruncationReason::UrlCap
                } else {
                    TruncationReason::FetchCap
                });
                break;
            }
            if ctx.cancel.is_cancelled() {
                queue.push_front((doc_url, depth));
                truncated = Some(TruncationReason::Cancelled);
                break;
            }
            if !seen_docs.insert(doc_url.clone()) {
                continue;
            }
            let Some(body) = fetch_capped(ctx, &doc_url).await else {
                continue;
            };
            fetched += 1;

            match classify_document(&body, depth) {
                DocumentKind::Index(children) => {
                    for child in children {
                        if in_scope(&child, &site) {
                            queue.push_back((child, depth + 1));
                        }
                    }
                    continue;
                }
                DocumentKind::UrlSet(locs) => {
                    // A urlset: emit its URLs as page-URL pivots.
                    for url in locs {
                        if entities.len() >= MAX_URLS {
                            truncated = Some(TruncationReason::UrlCap);
                            break;
                        }
                        if !in_scope(&url, &site) {
                            continue;
                        }
                        if !seen_urls.insert(url.clone()) {
                            continue;
                        }
                        let mut e =
                            Entity::new(EntityKind::Url, &url, confidence::VERY_HIGH, &ctx.scan_id);
                        e.tag("sitemap");
                        e.tag("sitemap-url");
                        e.add_evidence(
                            Evidence::new(SRC, format!("Listed in {doc_url}"))
                                .with_attr("sitemap_url", &doc_url)
                                .with_attr("source_domain", &host)
                                .with_attr("method", "owner-published-sitemap"),
                        );
                        entities.push(e);
                    }
                    if entities.len() >= MAX_URLS {
                        truncated = Some(TruncationReason::UrlCap);
                        break;
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(INTER_FETCH_MS)).await;
        }

        if let Some(reason) = truncated {
            mark_truncated(&mut entities, reason);
        }

        let mut result = ModuleResult::new();
        for e in entities {
            result.push(e);
        }
        Ok(result)
    }
}

/// Fetch a URL as text, size-capped, returning `None` on any error, non-success
/// status, or private-host preflight rejection. Confines the read to
/// [`MAX_SITEMAP_BYTES`] so a hostile server cannot stream unbounded bytes.
async fn fetch_capped(ctx: &ModuleContext, url: &str) -> Option<String> {
    if crate::util::preflight::url_host_is_private(url) {
        return None;
    }
    let resp = ctx.http.get(url).send_tagged(SRC).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    read_body_capped(resp, MAX_SITEMAP_BYTES).await
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
