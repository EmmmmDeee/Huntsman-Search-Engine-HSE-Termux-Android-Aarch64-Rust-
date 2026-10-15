//! Bounded JSON session store. No symlinks. Id must be a safe stem. Writes are atomic.

use std::path::PathBuf;

use crate::error::Error;
use crate::fsio::{read_bounded, write_atomic_private};
use crate::session::{Session, valid_session_id};

const MAX_BYTES: u64 = 1_048_576;

pub struct Store {
    root: PathBuf,
}

impl Store {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Save a session and mark it current. Both files are mode 600 on Unix: a session holds the
    /// seeds and findings of an investigation.
    ///
    /// # Errors
    /// `Error::Invalid` for an unsafe id; `Error::Store` for IO, size, or symlink refusal.
    pub fn save(&self, session: &Session) -> Result<PathBuf, Error> {
        if !valid_session_id(&session.id) {
            return Err(Error::Invalid(format!("unsafe session id: {}", session.id)));
        }
        let path = self
            .root
            .join("sessions")
            .join(format!("{}.json", session.id));
        let body = serde_json::to_vec_pretty(session).map_err(|e| Error::Store(e.to_string()))?;
        write_atomic_private(&path, &body, MAX_BYTES)?;
        write_atomic_private(
            &self.root.join("current.txt"),
            session.id.as_bytes(),
            MAX_BYTES,
        )?;
        Ok(path)
    }

    /// Load a session by id.
    ///
    /// # Errors
    /// `Error::Invalid` for an unsafe id, or for a file that was read but does not hold a session
    /// (bad data); `Error::Store` for IO, size, or symlink refusal (unreadable input). Callers map
    /// the two to distinct exit statuses, as they do for `ledger::load_chain`.
    pub fn load(&self, id: &str) -> Result<Session, Error> {
        if !valid_session_id(id) {
            return Err(Error::Invalid(format!("unsafe session id: {id}")));
        }
        let path = self.root.join("sessions").join(format!("{id}.json"));
        let body = read_bounded(&path, MAX_BYTES)?;
        serde_json::from_slice(&body)
            .map_err(|e| Error::Invalid(format!("{}: not a session: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("huntsman-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sessions")).unwrap();
        dir
    }

    /// A file that is read but does not parse is bad data, as a malformed ledger is; only a file
    /// that cannot be read is a store failure. `plan --load-session` exits 65 and 66 on them.
    #[test]
    fn a_session_file_that_does_not_parse_is_bad_data_not_a_store_failure() {
        let dir = scratch("malformed");
        let store = Store::new(dir.clone());
        // Truncated JSON, and a document an older build could have written without a field.
        for body in ["{\"id\": \"broken\"", "{\"id\": \"broken\"}"] {
            std::fs::write(dir.join("sessions").join("broken.json"), body).unwrap();
            match store.load("broken") {
                Err(Error::Invalid(message)) => {
                    assert!(message.contains("broken.json"), "{message}");
                    assert!(message.contains("not a session"), "{message}");
                }
                other => panic!("{body}: {other:?}"),
            }
        }
        assert!(matches!(store.load("missing"), Err(Error::Store(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
