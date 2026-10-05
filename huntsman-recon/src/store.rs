//! Bounded JSON session store. No symlinks. Id must be a safe stem.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Error;
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

    pub fn save(&self, session: &Session) -> Result<PathBuf, Error> {
        if !valid_session_id(&session.id) {
            return Err(Error::Invalid(format!("unsafe session id: {}", session.id)));
        }
        let dir = self.root.join("sessions");
        fs::create_dir_all(&dir).map_err(|e| Error::Store(e.to_string()))?;
        let path = dir.join(format!("{}.json", session.id));
        let body = serde_json::to_vec_pretty(session).map_err(|e| Error::Store(e.to_string()))?;
        if body.len() as u64 > MAX_BYTES {
            return Err(Error::Store("session exceeds 1 MiB".into()));
        }
        fs::write(&path, &body).map_err(|e| Error::Store(e.to_string()))?;
        fs::write(self.root.join("current.txt"), session.id.as_bytes())
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(path)
    }

    pub fn load(&self, id: &str) -> Result<Session, Error> {
        if !valid_session_id(id) {
            return Err(Error::Invalid(format!("unsafe session id: {id}")));
        }
        let path = self.root.join("sessions").join(format!("{id}.json"));
        read_bounded(&path)
    }
}

fn read_bounded(path: &Path) -> Result<Session, Error> {
    let meta = fs::metadata(path).map_err(|e| Error::Store(e.to_string()))?;
    if meta.len() > MAX_BYTES {
        return Err(Error::Store("session exceeds 1 MiB".into()));
    }
    let body = fs::read(path).map_err(|e| Error::Store(e.to_string()))?;
    serde_json::from_slice(&body).map_err(|e| Error::Store(e.to_string()))
}
