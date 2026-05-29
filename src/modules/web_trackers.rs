//! Web tracker / analytics-ID extraction — operator-fingerprint OSINT.
//!
//! Operators paste the *same* analytics/ad snippet across every property they
//! run, so a shared tracking ID is a near-definitive "same operator" link — a
//! **latent fingerprint** that ties together sites someone tries to keep
//! separate. (Clive Robinson, on de-anonymisation by metadata: *"individuals
//! have styles, habits and circles of influence that can be recognised by
//! various forms of metadata … sufficient to verify … multiple accounts"*.)
//!
//! This module fetches a Domain/Url's HTML and extracts embedded tracking
//! identifiers (Google Analytics UA / GA4, AdSense, Tag Manager, Meta Pixel,
//! Yandex Metrika, Hotjar). They attach to the domain as structured evidence;
//! the correlator's `AU-037` rule then clusters every domain sharing an ID into
//! a likely-same-operator group — the aggressive pivot from one site to an
//! operator's whole footprint.
//!
//! Defensive by design: the response body is read **streamed and capped**
//! ([`MAX_BODY`]) so a hostile/oversized page cannot exhaust memory.

use std::collections::HashSet;
use std::sync::LazyLock;

use async_trait::async_trait;
use regex::Regex;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "web_trackers";

/// Cap on bytes read from a target page. Trackers live in `<head>`/early
/// `<script>`s; 600 KiB is generous while bounding a hostile body.
const MAX_BODY: usize = 600 * 1024;

/// `(tracker_type, capture-group-1 pattern)`. The identifier is always group 1.
const PATTERNS: &[(&str, &str)] = &[
    ("google-analytics", r"(UA-\d{4,10}-\d{1,4})"),
    ("google-analytics-4", r"(G-[A-Z0-9]{10})"),
    ("google-adsense", r"(ca-pub-\d{16})"),
    ("google-tag-manager", r"(GTM-[A-Z0-9]{4,8})"),
    (
        "facebook-pixel",
        r#"fbq\(\s*['"]init['"]\s*,\s*['"](\d{15,16})['"]"#,
    ),
    ("yandex-metrika", r"ym\(\s*(\d{6,9})\s*,"),
    ("hotjar", r"hjid\s*[:=]\s*(\d{6,9})"),
];

static TRACKERS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .map(|(t, p)| {
            (
                *t,
                Regex::new(p).expect("static tracker regex must compile"),
            )
        })
        .collect()
});

/// Extract unique `(tracker_type, id)` pairs from a page body. Pure — the
/// offensive core is unit-tested without the network.
fn extract_trackers(body: &str) -> Vec<(&'static str, String)> {
    let mut seen: HashSet<(&'static str, String)> = HashSet::new();
    let mut out = Vec::new();
    for (ty, re) in TRACKERS.iter() {
        for caps in re.captures_iter(body) {
            if let Some(m) = caps.get(1) {
                let id = m.as_str().to_string();
                if seen.insert((*ty, id.clone())) {
                    out.push((*ty, id));
                }
            }
        }
    }
    out
}

pub struct WebTrackers;

#[async_trait]
impl Module for WebTrackers {
    fn name(&self) -> &'static str {
        "web_trackers"
    }

    fn description(&self) -> &'static str {
        "Extract web analytics/ad tracking IDs (operator fingerprints) for cross-site correlation"
    }

    fn priority(&self) -> u8 {
        95
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (fetch_url, domain) = match target.kind {
            TargetKind::Url => {
                let host = crate::util::url_util::host_from_url(&target.value).unwrap_or_default();
                (target.value.trim().to_string(), host)
            }
            TargetKind::Domain => {
                let d = target.value.trim().to_lowercase();
                (format!("https://{d}"), d)
            }
            _ => return Ok(ModuleResult::new()),
        };
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let Some(body) = fetch_capped(&ctx.http, &fetch_url).await else {
            return Ok(ModuleResult::new());
        };

        let found = extract_trackers(&body);
        if found.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Attach every tracker to the parent domain as structured evidence;
        // AU-037 clusters domains sharing an id into an operator group.
        let mut e = Entity::new(EntityKind::Domain, &domain, 0.80, &ctx.scan_id);
        e.tag("web-tracker");
        for (ty, id) in &found {
            e.tag(format!("tracker:{ty}"));
            e.add_evidence(
                Evidence::new(SRC, format!("Embeds {ty} tracking id {id}"))
                    .with_attr("tracker_type", *ty)
                    .with_attr("tracker_id", id)
                    .with_attr("source_domain", &domain),
            );
        }

        let mut result = ModuleResult::new();
        result.push(e);
        Ok(result)
    }
}

/// GET `url` and return its body, **streamed and truncated to [`MAX_BODY`]** so
/// an oversized/hostile response can never exhaust memory. `None` on any
/// transport error or non-success status.
async fn fetch_capped(client: &reqwest::Client, url: &str) -> Option<String> {
    use futures::StreamExt as _;
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.ok()?;
        buf.extend_from_slice(&bytes);
        if buf.len() >= MAX_BODY {
            buf.truncate(MAX_BODY);
            break;
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_and_url_only() {
        let m = WebTrackers;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn extracts_the_common_tracker_families() {
        let html = r#"
            <script async src="https://www.googletagmanager.com/gtag/js?id=UA-123456-1"></script>
            <script>gtag('config', 'G-ABCDE12345');</script>
            <script>(adsbygoogle=window.adsbygoogle||[]).push({google_ad_client:"ca-pub-1234567890123456"});</script>
            <!-- GTM-AB12CD -->
            <script>fbq('init', '123456789012345');</script>
            <script>ym(87654321, 'init', {});</script>
            <script>hjid:1234567</script>
        "#;
        let mut got: Vec<(&str, String)> = extract_trackers(html);
        got.sort();
        let mut want = vec![
            ("google-analytics", "UA-123456-1".to_string()),
            ("google-analytics-4", "G-ABCDE12345".to_string()),
            ("google-adsense", "ca-pub-1234567890123456".to_string()),
            ("google-tag-manager", "GTM-AB12CD".to_string()),
            ("facebook-pixel", "123456789012345".to_string()),
            ("yandex-metrika", "87654321".to_string()),
            ("hotjar", "1234567".to_string()),
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn dedupes_repeated_ids_and_ignores_clean_pages() {
        // Same UA id twice → one result (account field is 4–10 digits).
        let dup = "UA-5550-1 ... later ... UA-5550-1";
        assert_eq!(
            extract_trackers(dup),
            vec![("google-analytics", "UA-5550-1".to_string())]
        );
        // A page with no trackers yields nothing.
        assert!(extract_trackers("<html><body>hello world</body></html>").is_empty());
    }
}
