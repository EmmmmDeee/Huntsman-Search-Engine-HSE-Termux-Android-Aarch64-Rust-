//! Bounded JSON session store. No symlinks. Id must be a safe stem. Writes are atomic.

use std::path::PathBuf;

use crate::error::Error;
use crate::fsio::{read_bounded, write_atomic};
use crate::session::{valid_session_id, Session};

const MAX_BYTES: u64 = 1_048_576;

pub struct Store {
    root: PathBuf,
}

impl Store {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Save a session and mark it current.
    ///
    /// # Errors
    /// `Error::Invalid` for an unsafe id; `Error::Store` for IO, size, or symlink refusal.
    pub fn save(&self, session: &Session) -> Result<PathBuf, Error> {
        if !valid_session_id(&session.id) {
            return Err(Error::Invalid(format!("unsafe session id: {}", session.id)));
        }
        let path = self.root.join("sessions").join(format!("{}.json", session.id));
        let body = serde_json::to_vec_pretty(session).map_err(|e| Error::Store(e.to_string()))?;
        write_atomic(&path, &body, MAX_BYTES)?;
        write_atomic(&self.root.join("current.txt"), session.id.as_bytes(), MAX_BYTES)?;
        Ok(path)
    }

    /// Load a session by id.
    ///
    /// # Errors
    /// `Error::Invalid` for an unsafe id; `Error::Store` for IO, size, symlink, or JSON failure.
    pub fn load(&self, id: &str) -> Result<Session, Error> {
        if !valid_session_id(id) {
            return Err(Error::Invalid(format!("unsafe session id: {id}")));
        }
        let path = self.root.join("sessions").join(format!("{id}.json"));
        let body = read_bounded(&path, MAX_BYTES)?;
        serde_json::from_slice(&body).map_err(|e| Error::Store(e.to_string()))
    }
}
