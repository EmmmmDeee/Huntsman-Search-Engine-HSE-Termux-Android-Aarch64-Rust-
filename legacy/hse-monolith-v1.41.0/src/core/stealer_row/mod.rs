//! `core::stealer_row` — one paired credential row from a stealer-log import.
//!
//! The generic entity graph (`core::entity`) intentionally flattens a stealer
//! log into independent `Email`/`Username`/`Credential`/`Domain` entities so
//! they merge and correlate like any other finding — but that flattening
//! loses the one thing an operator browsing a stolen-credential dump actually
//! wants: which login, password, domain and capture date belonged to the
//! SAME record. `StealerRow` is that paired record, persisted alongside (not
//! instead of) the entity graph, powering the dedicated Stealer Logs Viewer.

use serde::{Deserialize, Serialize};

/// One paired login/password (+ domain, capture date, source machine) record
/// from a stealer-log import — the "smart split" a stealer-log viewer needs:
/// a row naming a site is a [`StealerRowKind::Password`] entry
/// (URL · Login · Password); a bare pair with no site is a
/// [`StealerRowKind::Combo`] entry (Login · Password).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealerRow {
    /// The infected machine's log id (the victim's `Log Id:`) this row
    /// belongs to — the "machine" grouping in the file-explorer layout.
    /// `None` for a row with no known source machine.
    pub log_id: Option<String>,
    pub domain: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    /// This credential's own capture date — distinct from the victim-level
    /// newest/oldest range already carried on the entity graph's evidence.
    pub pwned_at: Option<String>,
    pub kind: StealerRowKind,
}

/// Which "virtual file" a row belongs to, mirroring the Stealerlogs export's
/// own Passwords.txt (site-keyed) / Combos.txt (raw pair) distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StealerRowKind {
    Password,
    Combo,
}

impl StealerRowKind {
    /// Classify by presence of a site — a row naming a non-blank domain is
    /// `Password`, otherwise `Combo`. **Pure.**
    pub fn classify(domain: Option<&str>) -> Self {
        match domain {
            Some(d) if !d.trim().is_empty() => Self::Password,
            _ => Self::Combo,
        }
    }

    /// The value persisted in `stealer_rows.row_kind`. **Pure.**
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Combo => "combo",
        }
    }

    /// Parse a persisted `row_kind` column value back into a kind. Defaults
    /// to [`StealerRowKind::Combo`] for any unrecognised value — a forward-
    /// compatible fallback that never fabricates a site. **Pure.**
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            _ => Self::Combo,
        }
    }
}

impl StealerRow {
    /// True when this row carries neither a login nor a password — nothing
    /// worth persisting or displaying.
    pub fn is_empty(&self) -> bool {
        self.login.is_none() && self.password.is_none()
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
