//! Bounded JSON session store. No symlinks. Id must be a safe stem. Writes are atomic.

use std::path::PathBuf;

use crate::error::Error;
use crate::fsio::{read_bounded, write_atomic_private};
use crate::session::{Session, valid_session_id};

/// A saved session's ceiling is the saved-artifact ceiling, as a saved ledger's is: a long
/// investigation that `plan` can finish must also save, and a 1 MiB cap failed it after the work.
const MAX_SESSION_BYTES: u64 = crate::scan_artifact::MAX_ARTIFACT_BYTES;

/// `current.txt` holds one session id, which [`valid_session_id`] bounds at 80 characters.
const MAX_POINTER_BYTES: u64 = 128;

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
        write_atomic_private(&path, &body, MAX_SESSION_BYTES)?;
        write_atomic_private(
            &self.root.join("current.txt"),
            session.id.as_bytes(),
            MAX_POINTER_BYTES,
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
        let body = read_bounded(&path, MAX_SESSION_BYTES)?;
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

    /// A long investigation saves and reloads whole. Over the old 1 MiB cap, `save` refused it.
    #[test]
    fn a_session_larger_than_a_megabyte_saves_and_reloads() {
        let dir = scratch("large");
        let store = Store::new(dir.clone());
        let mut session = Session::new("large investigation");
        session.title = "finding ".repeat(200_000);
        assert!(serde_json::to_vec(&session).unwrap().len() > 1_048_576);
        store.save(&session).unwrap();
        let reloaded = store.load(&session.id).unwrap();
        assert_eq!(reloaded, session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ceiling still refuses a session that cannot be bounded, so a runaway save is an error.
    #[test]
    fn a_session_over_the_ceiling_is_refused() {
        let dir = scratch("ceiling");
        let store = Store::new(dir.clone());
        let mut session = Session::new("oversized");
        session.title = "x".repeat(usize::try_from(MAX_SESSION_BYTES).unwrap());
        assert!(matches!(store.save(&session), Err(Error::Store(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
