//! Pure archive observation model, URL identity, aggregation, and deterministic interest tags.

use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::canonical_domain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArchiveSource {
    Wayback,
    CommonCrawl,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArchiveUrlKey {
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveCapture {
    pub source: ArchiveSource,
    pub dataset: String,
    pub collection: Option<String>,
    pub original_url: String,
    pub key: ArchiveUrlKey,
    pub captured_at: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub digest: Option<String>,
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveDatasetObservation {
    pub source: ArchiveSource,
    pub dataset: String,
    pub collections: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub capture_count: usize,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub digest: Option<String>,
    pub source_urls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveRecord {
    pub key: ArchiveUrlKey,
    pub representative_url: String,
    pub observations: Vec<ArchiveDatasetObservation>,
    pub interests: Vec<ArchiveInterest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArchiveInterest {
    Document,
    ArchiveOrBackup,
    ConfigurationLike,
    ScriptLike,
    AdminAuthApiLike,
    Parameterized,
}

#[must_use]
pub fn parse_archive_url(raw: &str) -> Option<ArchiveUrlKey> {
    let raw = raw.trim();
    let (scheme, rest) = raw.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }

    let without_fragment = rest.split_once('#').map_or(rest, |(before, _)| before);
    let authority_end = without_fragment
        .find(['/', '?'])
        .unwrap_or(without_fragment.len());
    let authority = &without_fragment[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }

    let (raw_host, raw_port) = split_authority(authority)?;
    let host = canonical_domain(raw_host.trim_end_matches('.'))?;
    let port = match raw_port {
        None => None,
        Some(value) => {
            let parsed = value.parse::<u16>().ok()?;
            if (scheme == "http" && parsed == 80) || (scheme == "https" && parsed == 443) {
                None
            } else {
                Some(parsed)
            }
        }
    };

    let tail = &without_fragment[authority_end..];
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let path = if path.is_empty() { "/" } else { path };
    if !path.starts_with('/') {
        return None;
    }

    Some(ArchiveUrlKey {
        host,
        port,
        path: path.to_owned(),
        query: query.to_owned(),
    })
}

fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            if host.is_empty() || port.is_empty() {
                None
            } else {
                Some((host, Some(port)))
            }
        }
        Some(_) => None,
        None => Some((authority, None)),
    }
}

#[derive(Debug)]
struct ObservationBuilder {
    source: ArchiveSource,
    dataset: String,
    collections: BTreeSet<String>,
    first_seen: String,
    last_seen: String,
    capture_count: usize,
    status: Option<u16>,
    mime: Option<String>,
    digest: Option<String>,
    source_urls: BTreeSet<String>,
}

impl ObservationBuilder {
    fn new(capture: &ArchiveCapture) -> Self {
        let mut collections = BTreeSet::new();
        if let Some(collection) = capture.collection.as_ref() {
            collections.insert(collection.clone());
        }
        let mut source_urls = BTreeSet::new();
        if let Some(source_url) = capture.source_url.as_ref() {
            source_urls.insert(source_url.clone());
        }
        Self {
            source: capture.source,
            dataset: capture.dataset.clone(),
            collections,
            first_seen: capture.captured_at.clone(),
            last_seen: capture.captured_at.clone(),
            capture_count: 1,
            status: capture.status,
            mime: capture.mime.clone(),
            digest: capture.digest.clone(),
            source_urls,
        }
    }

    fn absorb(&mut self, capture: &ArchiveCapture) {
        if capture.captured_at < self.first_seen {
            self.first_seen.clone_from(&capture.captured_at);
        }
        if capture.captured_at >= self.last_seen {
            self.last_seen.clone_from(&capture.captured_at);
            if capture.status.is_some() {
                self.status = capture.status;
            }
            if capture.mime.is_some() {
                self.mime.clone_from(&capture.mime);
            }
            if capture.digest.is_some() {
                self.digest.clone_from(&capture.digest);
            }
        }
        self.capture_count = self.capture_count.saturating_add(1);
        if let Some(collection) = capture.collection.as_ref() {
            self.collections.insert(collection.clone());
        }
        if let Some(source_url) = capture.source_url.as_ref() {
            self.source_urls.insert(source_url.clone());
        }
    }

    fn finish(self) -> ArchiveDatasetObservation {
        ArchiveDatasetObservation {
            source: self.source,
            dataset: self.dataset,
            collections: self.collections.into_iter().collect(),
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            capture_count: self.capture_count,
            status: self.status,
            mime: self.mime,
            digest: self.digest,
            source_urls: self.source_urls.into_iter().collect(),
        }
    }
}

#[derive(Debug)]
struct RecordBuilder {
    key: ArchiveUrlKey,
    representative_url: String,
    representative_at: String,
    observations: BTreeMap<String, ObservationBuilder>,
}

impl RecordBuilder {
    fn new(capture: &ArchiveCapture) -> Self {
        let mut observations = BTreeMap::new();
        observations.insert(capture.dataset.clone(), ObservationBuilder::new(capture));
        Self {
            key: capture.key.clone(),
            representative_url: capture.original_url.clone(),
            representative_at: capture.captured_at.clone(),
            observations,
        }
    }

    fn absorb(&mut self, capture: &ArchiveCapture) {
        if capture.captured_at < self.representative_at
            || (capture.captured_at == self.representative_at
                && capture.original_url < self.representative_url)
        {
            self.representative_at.clone_from(&capture.captured_at);
            self.representative_url.clone_from(&capture.original_url);
        }
        if let Some(observation) = self.observations.get_mut(&capture.dataset) {
            observation.absorb(capture);
        } else {
            self.observations
                .insert(capture.dataset.clone(), ObservationBuilder::new(capture));
        }
    }

    fn finish(self) -> ArchiveRecord {
        ArchiveRecord {
            interests: classify_archive_path(&self.key.path, &self.key.query),
            key: self.key,
            representative_url: self.representative_url,
            observations: self
                .observations
                .into_values()
                .map(ObservationBuilder::finish)
                .collect(),
        }
    }
}

#[must_use]
pub fn merge_captures(captures: Vec<ArchiveCapture>) -> Vec<ArchiveRecord> {
    let mut records: BTreeMap<ArchiveUrlKey, RecordBuilder> = BTreeMap::new();
    for capture in captures {
        if let Some(record) = records.get_mut(&capture.key) {
            record.absorb(&capture);
        } else {
            records.insert(capture.key.clone(), RecordBuilder::new(&capture));
        }
    }
    records.into_values().map(RecordBuilder::finish).collect()
}

#[must_use]
pub fn classify_archive_path(path: &str, query: &str) -> Vec<ArchiveInterest> {
    let lower = path.to_ascii_lowercase();
    let segments: Vec<&str> = lower
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let basename = segments.last().copied().unwrap_or("");
    let extension = basename.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    let mut interests = BTreeSet::new();

    if matches!(
        extension,
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "csv" | "ppt" | "pptx" | "rtf" | "odt"
    ) {
        interests.insert(ArchiveInterest::Document);
    }
    if matches!(
        extension,
        "zip"
            | "tar"
            | "gz"
            | "tgz"
            | "bz2"
            | "7z"
            | "rar"
            | "sql"
            | "dump"
            | "bak"
            | "backup"
            | "old"
    ) || segments
        .iter()
        .any(|segment| matches!(*segment, "backup" | "backups" | "database" | "databases"))
    {
        interests.insert(ArchiveInterest::ArchiveOrBackup);
    }
    if matches!(basename, ".env" | "id_rsa" | "wp-config.php")
        || segments.iter().any(|segment| *segment == ".git")
        || matches!(extension, "ini" | "toml" | "yaml" | "yml")
        || (basename.starts_with("config.")
            && matches!(extension, "json" | "xml" | "ini" | "toml" | "yaml" | "yml"))
    {
        interests.insert(ArchiveInterest::ConfigurationLike);
    }
    if matches!(
        extension,
        "js" | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "jsx"
            | "py"
            | "rb"
            | "php"
            | "sh"
            | "ps1"
            | "go"
            | "rs"
    ) {
        interests.insert(ArchiveInterest::ScriptLike);
    }
    if segments.iter().any(|segment| {
        matches!(
            *segment,
            "admin"
                | "administrator"
                | "login"
                | "signin"
                | "sign-in"
                | "auth"
                | "oauth"
                | "api"
                | "swagger"
                | "openapi"
                | "graphql"
        )
    }) {
        interests.insert(ArchiveInterest::AdminAuthApiLike);
    }
    if !query.is_empty() {
        interests.insert(ArchiveInterest::Parameterized);
    }

    interests.into_iter().collect()
}
