//! Pure fold: a PLC audit log → the identity history it describes.
//!
//! No network, no IO, no clock. [`super::resolve`] does the fetching; this file
//! decides what the log *says*, which is where every judgement that could
//! produce a wrong finding lives, and is therefore where the tests point.
//!
//! # Why nullified operations are excluded from the history
//! PLC gives the holders of a DID's rotation keys a window in which to revert an
//! operation. When they use it, the reverted operation stays in the audit log
//! flagged `nullified` — and its contents are precisely the state the account
//! *never legitimately had*. Folding a nullified handle into the handle history
//! would attribute to the subject a name that, in the common case, an attacker
//! set during a takeover. So nullified operations contribute nothing to the
//! history and are instead counted and reported on their own: the presence of
//! one is a recovery event, which is a finding in its own right.

use std::collections::BTreeSet;

use crate::util::url_util::host_from_url;

use super::types::AuditEntry;

/// A value observed in the log, with the window it was seen in.
///
/// `first_seen`/`last_seen` are exactly that — first and last **observed**, not
/// a guarantee of continuity. A handle can be dropped and later reclaimed (seen
/// live: `retr0.id` → `retr0-id.translate.goog` → `retr0.id`), in which case the
/// window spans a gap the log itself records. Reporting the extremes is honest;
/// claiming continuous use would not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Spell {
    pub(super) value: String,
    pub(super) first_seen: String,
    pub(super) last_seen: String,
}

/// Everything the audit log establishes about one DID.
#[derive(Debug, Default)]
pub(super) struct History {
    /// First effective operation's date — the account's true creation, which
    /// survives profile edits and account deletion alike.
    pub(super) created_at: Option<String>,
    /// Total entries in the log, nullified ones included.
    pub(super) ops: usize,
    /// Entries reverted through the PLC recovery window.
    pub(super) nullified_ops: usize,
    /// Date of the `plc_tombstone` that deleted the DID, if any.
    pub(super) tombstoned: Option<String>,
    /// Every handle ever effective, in order of first appearance.
    pub(super) handles: Vec<Spell>,
    /// Handles declared by the most recent effective operation.
    pub(super) current_handles: Vec<String>,
    /// Every PDS host ever effective, in order of first appearance.
    pub(super) pds: Vec<Spell>,
    /// PDS host declared by the most recent effective operation.
    pub(super) current_pds: Option<String>,
    /// Distinct rotation keys across every effective operation, in order of
    /// first appearance. Not yet filtered — [`super::transform`] decides which
    /// of these say anything about the subject rather than about their host.
    pub(super) rotation_keys: Vec<String>,
}

impl History {
    /// True if `handle` is not one the most recent effective operation declares.
    pub(super) fn is_former(&self, handle: &str) -> bool {
        !self.current_handles.iter().any(|h| h == handle)
    }
}

/// The `YYYY-MM-DD` prefix of an ISO-8601 timestamp, or the whole string when it
/// is shorter than that. Never invents a date for an entry that carries none.
fn date_of(ts: Option<&str>) -> Option<String> {
    let ts = ts.map(str::trim).filter(|s| !s.is_empty())?;
    Some(ts.get(..10).unwrap_or(ts).to_string())
}

/// Record `value` as observed at `date`, extending its window if already seen.
fn note(spells: &mut Vec<Spell>, value: String, date: &str) {
    if let Some(existing) = spells.iter_mut().find(|s| s.value == value) {
        if !date.is_empty() {
            if existing.first_seen.is_empty() {
                existing.first_seen = date.to_string();
            }
            existing.last_seen = date.to_string();
        }
        return;
    }
    spells.push(Spell {
        value,
        first_seen: date.to_string(),
        last_seen: date.to_string(),
    });
}

/// Fold an audit log, oldest entry first, into the history it describes.
pub(super) fn fold(log: &[AuditEntry]) -> History {
    let mut h = History {
        ops: log.len(),
        ..History::default()
    };
    let mut keys: BTreeSet<&str> = BTreeSet::new();

    for entry in log {
        if entry.nullified {
            h.nullified_ops += 1;
            continue;
        }
        let Some(op) = entry.operation.as_ref() else {
            continue;
        };
        let date = date_of(entry.created_at.as_deref()).unwrap_or_default();
        if h.created_at.is_none() && !date.is_empty() {
            h.created_at = Some(date.clone());
        }

        // A tombstone deletes the DID and declares nothing else. The history
        // before it stands — that is the whole reason this module exists.
        if op.is_tombstone() {
            h.tombstoned = Some(date);
            continue;
        }

        // Handles are case-insensitive in AT Protocol; normalise so a casing
        // change is not reported as a rename.
        let handles: Vec<String> = op
            .handles()
            .into_iter()
            .map(str::to_ascii_lowercase)
            .collect();
        if !handles.is_empty() {
            h.current_handles = handles.clone();
        }
        for handle in handles {
            note(&mut h.handles, handle, &date);
        }

        if let Some(host) = op.pds_endpoint().and_then(host_from_url) {
            h.current_pds = Some(host.clone());
            note(&mut h.pds, host, &date);
        }

        for key in &op.rotation_keys {
            let key = key.trim();
            if !key.is_empty() && keys.insert(key) {
                h.rotation_keys.push(key.to_string());
            }
        }
    }

    h
}
