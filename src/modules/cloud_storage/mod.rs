//! Cloud-storage exposure scanning — discover publicly accessible object
//! storage (AWS S3, Google Cloud Storage, Azure Blob, DigitalOcean Spaces)
//! whose name is derived from the target domain/organisation.
//!
//! A rich, deduplicated permutation set (the label plus affixes like
//! `-backup`/`-assets`/`-dev`/`-dumps` in prefix and suffix position) is probed
//! across all four providers with bounded concurrency. Existence is classified
//! per response — **not found**, **exists but private** (a confirmed asset, even
//! if locked down), or **public** — and for a public, *listable* bucket the
//! object listing is parsed to surface the exposed object keys and total size,
//! which is the actual data-exposure intel. No API key required.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Semaphore;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "cloud_storage";

/// Candidate bucket names probed (× [`Provider::ALL`] = the request budget).
const MAX_NAMES: usize = 9;
/// Concurrent in-flight probes.
const MAX_CONCURRENT: usize = 16;
/// Per-request timeout.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Exposed object keys retained from a public listing (the rest are summarised).
const KEY_SAMPLE: usize = 25;
/// Confidence for the per-object `Url` entities minted from a `PublicListable`
/// finding's key sample — slightly below the 0.9 bucket-root confidence since
/// each is a derived pivot (a joined URL) rather than the directly-observed
/// listing itself.
const OBJECT_KEY_CONFIDENCE: f64 = confidence::HIGH_PLUSPLUS_PLUS;

pub struct CloudStorage;

#[async_trait]
impl Module for CloudStorage {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Cloud-bucket sweep — probes S3/GCS/Azure/DigitalOcean for exposed buckets derived from the target name"
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
        if base.len() < 3 {
            return Ok(result);
        }

        // (name × provider) probe set, bounded.
        let mut probes = Vec::new();
        for name in generate_bucket_names(&base).into_iter().take(MAX_NAMES) {
            for &provider in Provider::ALL {
                probes.push((provider, name.clone()));
            }
        }

        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
        let mut set = tokio::task::JoinSet::new();
        for (provider, name) in probes {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let sem = Arc::clone(&sem);
            let http = ctx.http.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                probe(&http, provider, &name).await
            });
        }

        let mut findings: Vec<Finding> = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(Some(f)) = joined {
                findings.push(f);
            }
        }
        // Deterministic, most-severe-first.
        findings.sort_by(|a, b| {
            b.access
                .severity()
                .cmp(&a.access.severity())
                .then_with(|| a.url.cmp(&b.url))
        });

        for f in findings {
            // `into_entity` consumes `f`, so pull out what's needed for the
            // per-object entities (below) from the still-borrowed `access`
            // before the move.
            let listable = match &f.access {
                Access::PublicListable { sample, .. } => Some((
                    f.provider.label(),
                    f.bucket.clone(),
                    f.url.clone(),
                    sample.clone(),
                )),
                _ => None,
            };
            result.push(f.into_entity(&ctx.scan_id));
            if let Some((label, bucket, bucket_root, sample)) = listable {
                result.extend(object_key_entities(
                    label,
                    &bucket,
                    &bucket_root,
                    &sample,
                    &ctx.scan_id,
                ));
            }
        }
        Ok(result)
    }
}

// ── Providers ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    AwsS3,
    Gcs,
    AzureBlob,
    DigitalOcean,
}

impl Provider {
    const ALL: &'static [Provider] = &[
        Provider::AwsS3,
        Provider::Gcs,
        Provider::AzureBlob,
        Provider::DigitalOcean,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::AwsS3 => "AWS S3",
            Self::Gcs => "GCS",
            Self::AzureBlob => "Azure Blob",
            Self::DigitalOcean => "DigitalOcean Spaces",
        }
    }

    fn url(self, name: &str) -> String {
        match self {
            // Path-style for S3 so the bucket name need not be a TLS-SNI host.
            Self::AwsS3 => format!("https://s3.amazonaws.com/{name}"),
            Self::Gcs => format!("https://storage.googleapis.com/{name}"),
            Self::AzureBlob => format!("https://{name}.blob.core.windows.net/"),
            // Region is part of the host; nyc3 is the most common default.
            Self::DigitalOcean => format!("https://{name}.nyc3.digitaloceanspaces.com/"),
        }
    }

    /// Classify a response status into bucket existence. Redirects are followed
    /// by the client, so an S3 bucket in another region resolves to its real
    /// status rather than a 301.
    fn existence(self, status: u16) -> Existence {
        match status {
            200 | 206 => Existence::Public,
            401 | 403 => Existence::Private,
            _ => Existence::NotFound,
        }
    }

    /// Whether this provider's public listing is the S3-style `ListBucketResult`
    /// XML the [`parse_listing`] helper understands (Azure uses a different
    /// schema and is treated as read-only).
    fn s3_style_listing(self) -> bool {
        matches!(self, Self::AwsS3 | Self::Gcs | Self::DigitalOcean)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Existence {
    NotFound,
    Private,
    Public,
}

// ── Findings ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Access {
    /// Bucket name is registered but access is denied (a confirmed asset).
    Private,
    /// Publicly readable, but the listing is not enumerable (or not parsed).
    PublicRead,
    /// Publicly *listable* — object keys are exposed. The serious finding.
    PublicListable {
        object_count: usize,
        total_size: u64,
        sample: Vec<String>,
    },
}

impl Access {
    /// Higher = more severe (drives ordering and the entity confidence).
    fn severity(&self) -> u8 {
        match self {
            Self::Private => 1,
            Self::PublicRead => 2,
            Self::PublicListable { .. } => 3,
        }
    }
}

struct Finding {
    provider: Provider,
    bucket: String,
    url: String,
    access: Access,
}

impl Finding {
    fn into_entity(self, scan_id: &str) -> Entity {
        let confidence = match self.access.severity() {
            3 => 0.9,
            2 => 0.8,
            _ => 0.6,
        };
        let label = self.provider.label();
        let mut e = Entity::new(EntityKind::Url, &self.url, confidence, scan_id);
        e.tag("cloud-storage");
        e.tag(format!("provider:{label}"));
        let ev = match &self.access {
            Access::Private => {
                e.tag("bucket-exists");
                Evidence::new(
                    SRC,
                    format!("{label} bucket '{}' exists (access denied)", self.bucket),
                )
            }
            Access::PublicRead => {
                e.tag(crate::core::tags::VULNERABLE);
                e.tag("public-read");
                Evidence::new(
                    SRC,
                    format!("{label} bucket '{}' is publicly readable", self.bucket),
                )
            }
            Access::PublicListable {
                object_count,
                total_size,
                sample,
            } => {
                e.tag(crate::core::tags::VULNERABLE);
                e.tag("public-listable");
                Evidence::new(
                    SRC,
                    format!(
                        "{label} bucket '{}' is publicly LISTABLE — {object_count} object(s), \
                         {total_size} byte(s) exposed",
                        self.bucket
                    ),
                )
                .with_attr("object_count", object_count.to_string())
                .with_attr("total_size_bytes", total_size.to_string())
                .with_attr("sample_keys", sample.join(", "))
            }
        };
        e.add_evidence(
            ev.with_attr("provider", label)
                .with_attr("bucket", &self.bucket),
        );
        e
    }
}

/// Mint one pivotable [`EntityKind::Url`] entity per exposed object key from a
/// `PublicListable` finding's `sample` — the individual objects behind the
/// single bucket-root entity [`Finding::into_entity`] already emits. A free
/// function (rather than living on `Finding`) so it can be exercised directly
/// against the same fixture data `parse_listing`'s tests use, without needing
/// an HTTP-mocked `Finding`.
fn object_key_entities(
    provider_label: &str,
    bucket: &str,
    bucket_root: &str,
    sample: &[String],
    scan_id: &str,
) -> Vec<Entity> {
    sample
        .iter()
        .filter_map(|key| {
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            let url = join_bucket_url(bucket_root, key);
            let mut e = Entity::new(EntityKind::Url, &url, OBJECT_KEY_CONFIDENCE, scan_id);
            e.tag("cloud-storage");
            e.tag("cloud-storage-object");
            e.tag(format!("provider:{provider_label}"));
            e.tag(crate::core::tags::VULNERABLE);
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "{provider_label} bucket '{bucket}' publicly lists exposed object '{key}'"
                    ),
                )
                .with_attr("provider", provider_label)
                .with_attr("bucket", bucket)
                .with_attr("key", key),
            );
            Some(e)
        })
        .collect()
}

/// Join a bucket-root URL with an object key. Azure/DigitalOcean roots already
/// end in `/`; S3/GCS path-style roots don't — so only add the separator when
/// it isn't already there, to avoid a doubled slash.
fn join_bucket_url(bucket_root: &str, key: &str) -> String {
    if bucket_root.ends_with('/') {
        format!("{bucket_root}{key}")
    } else {
        format!("{bucket_root}/{key}")
    }
}

// ── Probe ───────────────────────────────────────────────────────────────────

/// Probe one (provider, name): a `HEAD` to classify existence, then — only for a
/// public S3-style bucket — a `GET` to read and parse the object listing.
async fn probe(http: &reqwest::Client, provider: Provider, name: &str) -> Option<Finding> {
    let url = provider.url(name);
    let head = tokio::time::timeout(PROBE_TIMEOUT, http.head(&url).send_tagged(SRC))
        .await
        .ok()?
        .ok()?;
    let access = match provider.existence(head.status().as_u16()) {
        Existence::NotFound => return None,
        Existence::Private => Access::Private,
        Existence::Public => fetch_listing(http, provider, &url).await,
    };
    Some(Finding {
        provider,
        bucket: name.to_string(),
        url,
        access,
    })
}

/// For a public bucket, fetch and parse the listing. Falls back to `PublicRead`
/// when the body isn't an enumerable S3-style listing.
async fn fetch_listing(http: &reqwest::Client, provider: Provider, url: &str) -> Access {
    if !provider.s3_style_listing() {
        return Access::PublicRead;
    }
    let body = match tokio::time::timeout(PROBE_TIMEOUT, http.get(url).send_tagged(SRC)).await {
        // Capped read (32 MiB): the public-bucket `ListBucketResult` is
        // attacker-influenceable, so an uncapped `text()` is an OOM vector on the
        // low-RAM Termux target.
        Ok(Ok(resp)) => crate::util::http::read_body_capped(resp, crate::util::http::JSON_BODY_CAP)
            .await
            .unwrap_or_default(),
        _ => return Access::PublicRead,
    };
    if !body.contains("<ListBucketResult") {
        return Access::PublicRead;
    }
    let listing = parse_listing(&body, KEY_SAMPLE);
    Access::PublicListable {
        object_count: listing.object_count,
        total_size: listing.total_size,
        sample: listing.sample,
    }
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

/// The registrable label of a domain/org value: lowercase, `www.` stripped,
/// first dotted label, kept to `[a-z0-9-]`.
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

/// Affixes appended/prepended to the base, highest-signal first so the
/// per-scan cap keeps the most useful candidates.
const AFFIXES: &[&str] = &[
    "backup",
    "backups",
    "bak",
    "dev",
    "staging",
    "prod",
    "assets",
    "static",
    "media",
    "data",
    "db",
    "dump",
    "dumps",
    "logs",
    "archive",
    "files",
    "uploads",
    "downloads",
    "public",
    "private",
    "internal",
    "cdn",
    "images",
    "docs",
    "config",
    "store",
    "storage",
    "web",
    "app",
    "test",
];

/// Generate candidate bucket names from `base`: the bare label first, then
/// `base-affix` and `affix-base` for each affix, deduplicated and filtered to
/// syntactically valid bucket names. Ordered by signal; callers apply the cap.
fn generate_bucket_names(base: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |name: String| {
        if is_valid_bucket(&name) && seen.insert(name.clone()) {
            out.push(name);
        }
    };
    push(base.to_string());
    for affix in AFFIXES {
        push(format!("{base}-{affix}"));
    }
    for affix in AFFIXES {
        push(format!("{affix}-{base}"));
    }
    out
}

/// A syntactically valid object-storage bucket name usable as a TLS-SNI-free
/// path segment: 3–63 chars of `[a-z0-9-]`, no leading/trailing hyphen.
fn is_valid_bucket(name: &str) -> bool {
    (3..=63).contains(&name.len())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A parsed S3-style `ListBucketResult`.
struct Listing {
    object_count: usize,
    total_size: u64,
    sample: Vec<String>,
}

/// Parse an S3-style XML listing: every `<Key>` is an exposed object (sampled up
/// to `sample_cap`), every `<Size>` summed. Allocation-light, panic-free.
fn parse_listing(xml: &str, sample_cap: usize) -> Listing {
    let mut sample = Vec::new();
    let mut object_count = 0;
    for key in tag_values(xml, "<Key>", "</Key>") {
        object_count += 1;
        if sample.len() < sample_cap {
            sample.push(key.to_string());
        }
    }
    let total_size = tag_values(xml, "<Size>", "</Size>")
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .sum();
    Listing {
        object_count,
        total_size,
        sample,
    }
}

/// Iterate the text between each `open`…`close` tag pair, in document order.
fn tag_values<'a>(xml: &'a str, open: &'a str, close: &'a str) -> impl Iterator<Item = &'a str> {
    let mut rest = xml;
    std::iter::from_fn(move || {
        let start = rest.find(open)? + open.len();
        let after = &rest[start..];
        let end = after.find(close)?;
        let value = &after[..end];
        rest = &after[end + close.len()..];
        Some(value)
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
