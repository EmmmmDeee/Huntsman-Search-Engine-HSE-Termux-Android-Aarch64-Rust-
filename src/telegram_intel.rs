//! Read-only Telegram intelligence primitives.
//!
//! The always-compiled portion of this module owns deterministic local indexing only.
//! Authenticated Telegram network access is feature-gated and never required for local search.

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fsio::{read_bounded, write_atomic};
use crate::search::tokenize;

pub const TELEGRAM_INDEX_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_TELEGRAM_INDEX_CAPACITY: usize = 10_000;
pub const MAX_TELEGRAM_INDEX_RECORDS: usize = 10_000;
pub const MAX_TELEGRAM_INDEX_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TELEGRAM_MESSAGE_TEXT_BYTES: usize = 1_048_576;
pub const MAX_TELEGRAM_SEARCH_RESULTS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TelegramMessageKey {
    pub peer_id: i64,
    pub message_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramRecord {
    pub peer_id: i64,
    pub message_id: i32,
    pub date_unix: i64,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_count: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_count: Option<i32>,
}

impl TelegramRecord {
    #[must_use]
    pub fn new(peer_id: i64, message_id: i32, date_unix: i64, text: impl Into<String>) -> Self {
        Self {
            peer_id,
            message_id,
            date_unix,
            text: text.into(),
            peer_username: None,
            peer_title: None,
            sender_id: None,
            sender_username: None,
            sender_phone: None,
            reply_to_message_id: None,
            view_count: None,
            forward_count: None,
        }
    }

    #[must_use]
    pub const fn key(&self) -> TelegramMessageKey {
        TelegramMessageKey {
            peer_id: self.peer_id,
            message_id: self.message_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramSearchHit {
    pub score: usize,
    pub record: TelegramRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelegramIngestOutcome {
    pub inserted: bool,
    pub evicted: Option<TelegramMessageKey>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TelegramIntelError {
    #[error("invalid Telegram index capacity: {0}")]
    InvalidCapacity(usize),
    #[error("unsupported Telegram index schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("invalid Telegram index snapshot: {0}")]
    InvalidSnapshot(String),
    #[error("Telegram index storage: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelegramIndexSnapshot {
    schema_version: u32,
    capacity: usize,
    records: Vec<TelegramRecord>,
}

#[derive(Debug, Clone)]
pub struct TelegramIndex {
    capacity: usize,
    records: BTreeMap<TelegramMessageKey, TelegramRecord>,
    postings: BTreeMap<String, BTreeMap<TelegramMessageKey, usize>>,
}

impl Default for TelegramIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl TelegramIndex {
    #[must_use]
    pub fn new() -> Self {
        Self {
            capacity: DEFAULT_TELEGRAM_INDEX_CAPACITY,
            records: BTreeMap::new(),
            postings: BTreeMap::new(),
        }
    }

    /// # Errors
    /// Returns `InvalidCapacity` for zero or capacities above the hard record bound.
    pub fn with_capacity(capacity: usize) -> Result<Self, TelegramIntelError> {
        if capacity == 0 || capacity > MAX_TELEGRAM_INDEX_RECORDS {
            return Err(TelegramIntelError::InvalidCapacity(capacity));
        }
        Ok(Self {
            capacity,
            records: BTreeMap::new(),
            postings: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        TELEGRAM_INDEX_SCHEMA_VERSION
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn ingest(&mut self, record: TelegramRecord) -> TelegramIngestOutcome {
        let key = record.key();
        let inserted = !self.records.contains_key(&key);
        if let Some(previous) = self.records.remove(&key) {
            self.remove_postings(&previous);
        }
        self.add_postings(&record);
        self.records.insert(key, record);

        let evicted = if self.records.len() > self.capacity {
            self.oldest_key().inspect(|oldest| {
                if let Some(previous) = self.records.remove(oldest) {
                    self.remove_postings(&previous);
                }
            })
        } else {
            None
        };

        TelegramIngestOutcome { inserted, evicted }
    }

    #[must_use]
    pub fn search(&self, query: &str, limit: usize) -> Vec<TelegramSearchHit> {
        let mut terms = tokenize(query);
        terms.sort_unstable();
        terms.dedup();
        if terms.is_empty() || limit == 0 {
            return Vec::new();
        }

        let Some(seed) = terms
            .iter()
            .filter_map(|term| self.postings.get(term).map(|posting| (term, posting)))
            .min_by_key(|(_, posting)| posting.len())
        else {
            return Vec::new();
        };
        if terms.iter().any(|term| !self.postings.contains_key(term)) {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for key in seed.1.keys() {
            let mut score = 0usize;
            let mut matched = true;
            for term in &terms {
                if let Some(count) = self.postings.get(term).and_then(|posting| posting.get(key)) {
                    score = score.saturating_add(*count);
                } else {
                    matched = false;
                    break;
                }
            }
            if matched {
                if let Some(record) = self.records.get(key) {
                    hits.push(TelegramSearchHit {
                        score,
                        record: record.clone(),
                    });
                }
            }
        }

        hits.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.record.peer_id.cmp(&right.record.peer_id))
                .then_with(|| left.record.message_id.cmp(&right.record.message_id))
        });
        hits.truncate(limit.min(MAX_TELEGRAM_SEARCH_RESULTS));
        hits
    }

    /// # Errors
    /// Returns an error for missing, oversized, malformed, duplicate, or unsupported snapshots.
    pub fn load(path: &Path) -> Result<Self, TelegramIntelError> {
        let body = read_bounded(path, MAX_TELEGRAM_INDEX_BYTES)
            .map_err(|error| TelegramIntelError::Storage(error.to_string()))?;
        let snapshot: TelegramIndexSnapshot = serde_json::from_slice(&body)
            .map_err(|error| TelegramIntelError::InvalidSnapshot(error.to_string()))?;
        if snapshot.schema_version != TELEGRAM_INDEX_SCHEMA_VERSION {
            return Err(TelegramIntelError::UnsupportedSchema(
                snapshot.schema_version,
            ));
        }
        let mut index = Self::with_capacity(snapshot.capacity)?;
        if snapshot.records.len() > snapshot.capacity {
            return Err(TelegramIntelError::InvalidSnapshot(
                "record count exceeds declared capacity".into(),
            ));
        }

        let mut keys = BTreeSet::new();
        for record in snapshot.records {
            validate_record(&record)?;
            if !keys.insert(record.key()) {
                return Err(TelegramIntelError::InvalidSnapshot(
                    "duplicate message identity".into(),
                ));
            }
            let outcome = index.ingest(record);
            if outcome.evicted.is_some() {
                return Err(TelegramIntelError::InvalidSnapshot(
                    "snapshot unexpectedly required eviction".into(),
                ));
            }
        }
        Ok(index)
    }

    /// Load an existing snapshot, or create a fresh index only when the path is absent.
    ///
    /// # Errors
    /// Existing invalid, oversized, or inaccessible paths fail closed.
    pub fn load_or_new(path: &Path) -> Result<Self, TelegramIntelError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Self::load(path),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::new()),
            Err(error) => Err(TelegramIntelError::Storage(format!(
                "{}: {error}",
                path.display()
            ))),
        }
    }

    /// # Errors
    /// Returns storage/serialization errors and refuses snapshots above 16 MiB.
    pub fn save(&self, path: &Path) -> Result<(), TelegramIntelError> {
        let snapshot = TelegramIndexSnapshot {
            schema_version: TELEGRAM_INDEX_SCHEMA_VERSION,
            capacity: self.capacity,
            records: self.records.values().cloned().collect(),
        };
        let body = serde_json::to_vec_pretty(&snapshot)
            .map_err(|error| TelegramIntelError::InvalidSnapshot(error.to_string()))?;
        write_atomic(path, &body, MAX_TELEGRAM_INDEX_BYTES)
            .map_err(|error| TelegramIntelError::Storage(error.to_string()))
    }

    fn add_postings(&mut self, record: &TelegramRecord) {
        let mut counts = BTreeMap::<String, usize>::new();
        for token in tokenize(&record.text) {
            *counts.entry(token).or_default() += 1;
        }
        let key = record.key();
        for (token, count) in counts {
            self.postings.entry(token).or_default().insert(key, count);
        }
    }

    fn remove_postings(&mut self, record: &TelegramRecord) {
        let key = record.key();
        let mut tokens = tokenize(&record.text);
        tokens.sort_unstable();
        tokens.dedup();
        for token in tokens {
            let remove_token = if let Some(posting) = self.postings.get_mut(&token) {
                posting.remove(&key);
                posting.is_empty()
            } else {
                false
            };
            if remove_token {
                self.postings.remove(&token);
            }
        }
    }

    fn oldest_key(&self) -> Option<TelegramMessageKey> {
        self.records
            .values()
            .min_by_key(|record| (record.date_unix, record.peer_id, record.message_id))
            .map(TelegramRecord::key)
    }
}

fn validate_record(record: &TelegramRecord) -> Result<(), TelegramIntelError> {
    if record.message_id <= 0 {
        return Err(TelegramIntelError::InvalidSnapshot(
            "message id must be positive".into(),
        ));
    }
    if record.text.len() > MAX_TELEGRAM_MESSAGE_TEXT_BYTES {
        return Err(TelegramIntelError::InvalidSnapshot(format!(
            "message text exceeds {MAX_TELEGRAM_MESSAGE_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}
