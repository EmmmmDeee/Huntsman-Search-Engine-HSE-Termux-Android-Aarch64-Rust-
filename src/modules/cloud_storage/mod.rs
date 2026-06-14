//! Cloud storage exposure scanning — check for publicly accessible
//! S3 buckets, Azure Blob containers, and GCS buckets derived from
//! domain/organisation names.
//!
//! Generates candidate bucket names from the target domain or org name
//! and probes each with a HEAD request. Tags exposed storage as
//! vulnerable. No API key required.

use async_trait::async_trait;
use futures::future::join_all;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "cloud_storage";
const MAX_PROBES: usize = 18;

pub struct CloudStorage;

#[async_trait]
impl Module for CloudStorage {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Probe for publicly exposed S3/Azure/GCS buckets derived from domain names"
    }
    fn priority(&self) -> u8 {
        25
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
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

        let candidates = generate_bucket_names(&base);

        let probes = candidates
            .iter()
            .take(MAX_PROBES)
            .map(|(url, provider, bucket_name)| {
                let http = ctx.http.clone();
                let url = url.clone();
                let bucket_name = bucket_name.clone();
                async move {
                    let status = probe_url(&http, &url).await;
                    (url, *provider, bucket_name, status)
                }
            });
        let outcomes = join_all(probes).await;
        for (url, provider, bucket_name, status) in outcomes {
            if let Some(status) = status
                && is_exposed(status, provider)
            {
                let mut e = Entity::new(EntityKind::Url, &url, 0.80, &ctx.scan_id);
                e.tag("vulnerable");
                e.tag("cloud-storage");
                e.tag(["provider:", provider].concat());
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

fn generate_bucket_names(base: &str) -> Vec<(String, &'static str, String)> {
    // One probe triple (S3 / Azure / GCS) per name variant, flattened — the six
    // suffixes × three providers give the MAX_PROBES (18) candidate URLs.
    ["", "-backup", "-assets", "-data", "-public", "-dev"]
        .into_iter()
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
                    name,
                ),
            ]
        })
        .collect()
}

async fn probe_url(http: &reqwest::Client, url: &str) -> Option<u16> {
    match tokio::time::timeout(std::time::Duration::from_secs(3), http.head(url).send()).await {
        Ok(Ok(resp)) => Some(resp.status().as_u16()),
        _ => None,
    }
}

fn is_exposed(status: u16, provider: &str) -> bool {
    match provider {
        "AWS S3" => matches!(status, 200 | 403),
        "Azure Blob" => status == 200,
        "GCS" => matches!(status, 200 | 403),
        _ => status == 200,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
