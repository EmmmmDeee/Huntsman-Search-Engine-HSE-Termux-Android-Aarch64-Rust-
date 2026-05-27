//! Cloud storage exposure scanning — check for publicly accessible
//! S3 buckets, Azure Blob containers, and GCS buckets derived from
//! domain/organisation names.
//!
//! Generates candidate bucket names from the target domain or org name
//! and probes each with a HEAD request. Tags exposed storage as
//! vulnerable. No API key required.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
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

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let base = extract_base_name(&target.value);
        if base.is_empty() || base.len() < 3 {
            return Ok(result);
        }

        let candidates = generate_bucket_names(&base);

        for (url, provider, bucket_name) in candidates.iter().take(MAX_PROBES) {
            if ctx.cancel.is_cancelled() {
                break;
            }
            if let Some(status) = probe_url(&ctx.http, url).await
                && is_exposed(status, provider)
            {
                let mut e = Entity::new(EntityKind::Url, url, 0.80, &ctx.scan_id);
                e.tag("vulnerable");
                e.tag("cloud-storage");
                e.tag(format!("provider:{provider}"));
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("{provider} bucket '{bucket_name}' is publicly accessible"),
                    )
                    .with_attr("provider", *provider)
                    .with_attr("bucket", bucket_name)
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
    let mut out = Vec::with_capacity(MAX_PROBES);
    let suffixes = ["", "-backup", "-assets", "-data", "-public", "-dev"];
    for suffix in &suffixes {
        let name = format!("{base}{suffix}");
        out.push((
            format!("https://{name}.s3.amazonaws.com"),
            "AWS S3",
            name.clone(),
        ));
        out.push((
            format!("https://{name}.blob.core.windows.net"),
            "Azure Blob",
            name.clone(),
        ));
        out.push((
            format!("https://storage.googleapis.com/{name}"),
            "GCS",
            name,
        ));
    }
    out
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
    use super::*;

    #[test]
    fn extract_base_from_domain() {
        assert_eq!(extract_base_name("www.example.com"), "example");
        assert_eq!(extract_base_name("acme-corp.com.au"), "acme-corp");
        assert_eq!(extract_base_name("EXAMPLE.COM"), "example");
    }

    #[test]
    fn generate_buckets_bounded() {
        let names = generate_bucket_names("test");
        assert!(names.len() <= MAX_PROBES);
        assert!(names.iter().any(|(u, _, _)| u.contains("s3.amazonaws")));
        assert!(names.iter().any(|(u, _, _)| u.contains("blob.core")));
        assert!(
            names
                .iter()
                .any(|(u, _, _)| u.contains("storage.googleapis"))
        );
    }

    #[test]
    fn s3_403_is_exposed() {
        assert!(is_exposed(403, "AWS S3"));
        assert!(is_exposed(200, "AWS S3"));
        assert!(!is_exposed(404, "AWS S3"));
    }

    #[test]
    fn azure_needs_200() {
        assert!(is_exposed(200, "Azure Blob"));
        assert!(!is_exposed(403, "Azure Blob"));
    }

    #[test]
    fn short_name_skipped() {
        assert!(extract_base_name("a.b").len() < 3);
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = CloudStorage;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
