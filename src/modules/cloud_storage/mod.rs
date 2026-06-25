//! Cloud storage exposure scanning — check for publicly accessible
//! S3 buckets, Azure Blob containers, GCS buckets, DigitalOcean Spaces,
//! and Wasabi buckets derived from domain/organisation names.
//!
//! Generates candidate bucket names from the target domain or org name
//! (16 suffix variants × 5 providers = 80 candidates) and probes them
//! concurrently. Tags exposed storage as vulnerable.  No API key required.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "cloud_storage";

/// Name-variant suffixes probed for every provider.
///
/// Covers the most common real-world bucket naming conventions: bare name,
/// environment qualifiers (prod/staging/dev/test), content-type qualifiers
/// (assets/static/media/images/uploads/files), and operational qualifiers
/// (backup/data/logs/archive).
const SUFFIXES: &[&str] = &[
    "", "-backup", "-assets", "-data", "-public", "-dev", "-prod", "-staging", "-static", "-media",
    "-logs", "-images", "-uploads", "-test", "-archive", "-files",
];

pub struct CloudStorage;

#[async_trait]
impl Module for CloudStorage {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Probe for publicly exposed S3/Azure/GCS/DO-Spaces/Wasabi buckets derived from domain names"
    }
    fn priority(&self) -> u8 {
        25
    }
    fn max_timeout_ms(&self) -> u64 {
        20_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let base = extract_base_name(&target.value);
        if base.is_empty() || base.len() < 3 {
            return Ok(result);
        }

        let candidates = generate_bucket_candidates(&base);

        // Probe candidates concurrently but bounded — at most 10 in-flight at a
        // time to stay within Termux socket/FD limits and avoid looking like a
        // flood to cloud providers.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
        let mut set: tokio::task::JoinSet<(String, &'static str, String, Option<u16>)> =
            tokio::task::JoinSet::new();
        for (url, provider, bucket_name) in candidates {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let http = ctx.http.clone();
            let sem = std::sync::Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore not closed");
                let status = probe_url(&http, &url).await;
                (url, provider, bucket_name, status)
            });
        }

        while let Some(join_result) = set.join_next().await {
            if ctx.cancel.is_cancelled() {
                set.abort_all();
                break;
            }
            if let Ok((url, provider, bucket_name, Some(status))) = join_result
                && is_exposed(status, provider)
            {
                let mut e = Entity::new(EntityKind::Url, &url, 0.80, &ctx.scan_id);
                e.tag("vulnerable");
                e.tag("cloud-storage");
                e.tag(format!("provider:{provider}"));
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("{provider} bucket '{bucket_name}' is publicly accessible"),
                    )
                    .with_attr("provider", provider)
                    .with_attr("bucket", &bucket_name)
                    .with_attr("http_status", status.to_string()),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}

fn extract_base_name(value: &str) -> String {
    let lower = value.trim().to_lowercase();
    let stripped = lower.strip_prefix("www.").unwrap_or(&lower);
    stripped
        .split('.')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}

/// Generate all (url, provider, bucket_name) triples for `base`.
///
/// `SUFFIXES.len() × 5 providers` candidates total.
pub(crate) fn generate_bucket_candidates(base: &str) -> Vec<(String, &'static str, String)> {
    SUFFIXES
        .iter()
        .flat_map(|suffix| {
            let name = format!("{base}{suffix}");
            [
                (
                    format!("https://{name}.s3.amazonaws.com"),
                    "AWS S3",
                    name.clone(),
                ),
                (
                    format!("https://{name}.blob.core.windows.net"),
                    "Azure Blob",
                    name.clone(),
                ),
                (
                    format!("https://storage.googleapis.com/{name}"),
                    "GCS",
                    name.clone(),
                ),
                (
                    format!("https://{name}.nyc3.digitaloceanspaces.com"),
                    "DigitalOcean Spaces",
                    name.clone(),
                ),
                (
                    format!("https://s3.us-east-1.wasabisys.com/{name}"),
                    "Wasabi",
                    name,
                ),
            ]
        })
        .collect()
}

async fn probe_url(http: &reqwest::Client, url: &str) -> Option<u16> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(4),
        http.head(url).send_tagged(SRC),
    )
    .await
    {
        Ok(Ok(resp)) => Some(resp.status().as_u16()),
        _ => None,
    }
}

/// Returns `true` when the HTTP status indicates the bucket exists and is at
/// least partially accessible. AWS S3, GCS, DO Spaces, and Wasabi all return
/// 403 for private-but-existent buckets; Azure Blob only returns 200 for
/// truly public containers.
pub(crate) fn is_exposed(status: u16, provider: &str) -> bool {
    match provider {
        "AWS S3" | "GCS" | "DigitalOcean Spaces" | "Wasabi" => matches!(status, 200 | 403),
        "Azure Blob" => status == 200,
        _ => status == 200,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
