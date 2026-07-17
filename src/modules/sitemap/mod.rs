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

/// Unescape the five predefined XML entities a `<loc>` URL can legally contain
/// (`&amp; &lt; &gt; &quot; &apos;`). **Pure**. Numeric character references are
/// left as-is (they do not appear in well-formed sitemap URLs).
fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// True if the document is a sitemap INDEX (lists child sitemaps) rather than a
/// urlset (lists page URLs). **Pure**.
fn is_sitemap_index(xml: &str) -> bool {
    xml.to_ascii_lowercase().contains("<sitemapindex")
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
        "Owner-published sitemap.xml / robots.txt Sitemap enumeration → Url entities"
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

        while let Some((doc_url, depth)) = queue.pop_front() {
            if fetched >= MAX_SITEMAP_FETCHES || entities.len() >= MAX_URLS {
                break;
            }
            if ctx.cancel.is_cancelled() {
                break;
            }
            if !seen_docs.insert(doc_url.clone()) {
                continue;
            }
            let Some(body) = fetch_capped(ctx, &doc_url).await else {
                continue;
            };
            fetched += 1;

            let locs = extract_locs(&body);
            if is_sitemap_index(&body) && depth == 0 {
                // Child sitemaps — enqueue those on the same site.
                for child in locs {
                    if in_scope(&child, &site) {
                        queue.push_back((child, depth + 1));
                    }
                }
                continue;
            }

            // A urlset (or a deeper index we won't recurse further): emit URLs.
            for url in locs {
                if entities.len() >= MAX_URLS {
                    break;
                }
                if !in_scope(&url, &site) {
                    continue;
                }
                if !seen_urls.insert(url.clone()) {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Url, &url, 0.75, &ctx.scan_id);
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

            tokio::time::sleep(std::time::Duration::from_millis(INTER_FETCH_MS)).await;
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
