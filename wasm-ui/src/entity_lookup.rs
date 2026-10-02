//! Shared "resolve a UID to a display value" lookup, used by every
//! `scan_info` view that receives a UID list from its own API response but
//! needs the scan's already-loaded entities (the browser's `S.entities`) to
//! show something human-readable for each one. Extracted once a second
//! `scan_info` port ([`crate::scan_info::communities`]) needed the exact same
//! lookup [`crate::scan_info::duplicates`] already had inline.

use std::collections::HashMap;

use crate::html::{escape_html, kind_pill};

/// `uid -> hse_core::Entity` lookup built once per render.
pub struct EntityLookup<'a> {
    by_uid: HashMap<&'a str, &'a hse_core::Entity>,
}

impl<'a> EntityLookup<'a> {
    pub fn new(entities: &'a [hse_core::Entity]) -> Self {
        Self {
            by_uid: entities.iter().map(|e| (e.uid.as_str(), e)).collect(),
        }
    }

    /// The full entity for `uid`, when a caller needs more than
    /// [`display`](Self::display) gives (e.g. its `kind`, for a kind pill
    /// alongside the value) and wants to build its own not-found fallback
    /// rather than this type's.
    pub fn get(&self, uid: &str) -> Option<&'a hse_core::Entity> {
        self.by_uid.get(uid).copied()
    }

    /// HTML-escaped display value for `uid`: the entity's `raw_value` (or
    /// `value` when `raw_value` is empty) if found, else the UID's first 12
    /// characters plus an ellipsis — the same fallback every JS original
    /// used for a UID that (should not happen in practice, but was always
    /// tolerated) isn't present.
    pub fn display(&self, uid: &str) -> String {
        match self.by_uid.get(uid) {
            Some(e) if !e.raw_value.is_empty() => escape_html(&e.raw_value),
            Some(e) => escape_html(&e.value),
            None => format!(
                "{}\u{2026}",
                escape_html(&uid.chars().take(12).collect::<String>())
            ),
        }
    }

    /// Rich label for `uid`: a kind pill plus display value when it resolves
    /// to a known entity, else a muted, 16-character-truncated UID
    /// placeholder (no kind pill, since there is no known kind) — the label
    /// every ranked/graph view built on this scan's entities (trust, pivots)
    /// uses, extracted once the second such view needed the exact same thing
    /// [`crate::scan_info::trust`] already had inline.
    pub fn label(&self, uid: &str) -> String {
        match self.by_uid.get(uid) {
            Some(e) => {
                let value = if e.raw_value.is_empty() {
                    &e.value
                } else {
                    &e.raw_value
                };
                format!(
                    "{} <code>{}</code>",
                    kind_pill(&e.kind.to_string()),
                    escape_html(value)
                )
            }
            None => format!(
                "<code class=\"text-muted\" style=\"font-size:10px\">{}\u{2026}</code>",
                escape_html(&uid.chars().take(16).collect::<String>())
            ),
        }
    }
}
