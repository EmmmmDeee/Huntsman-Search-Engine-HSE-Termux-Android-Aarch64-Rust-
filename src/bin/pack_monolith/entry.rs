//! The file model: one [`Entry`] per packed file, plus the binary/language
//! detection it's built from.

use sha2::{Digest, Sha256};

use crate::topology::{category_note, classify_layer};

/// Extensions treated as syntax-highlightable text → language tag for the agent.
const LANG_BY_EXT: &[(&str, &str)] = &[
    ("rs", "rust"),
    ("toml", "toml"),
    ("lock", "toml"),
    ("md", "markdown"),
    ("txt", "text"),
    ("sh", "bash"),
    ("yml", "yaml"),
    ("yaml", "yaml"),
    ("json", "json"),
    ("js", "javascript"),
    ("css", "css"),
    ("html", "html"),
    ("der", "binary"),
    ("py", "python"),
    ("gitignore", "gitignore"),
];

pub struct Entry {
    pub path: String,
    pub data: Vec<u8>,
    pub is_binary: bool,
    pub sha256: String,
    pub lines: usize,
    pub eof_newline: bool,
    pub rank: u32,
    pub label: &'static str,
    pub note: &'static str,
}

impl Entry {
    pub fn new(path: String, data: Vec<u8>) -> Self {
        let is_binary = is_binary(&data);
        let sha256 = sha256_hex(&data);
        let eof_newline = data.is_empty() || data.last() == Some(&b'\n');
        let lines = if is_binary {
            0
        } else {
            let nl = data.iter().filter(|&&b| b == b'\n').count();
            nl + usize::from(!data.is_empty() && !eof_newline)
        };
        let (rank, label) = classify_layer(&path);
        let note = category_note(&path);
        Entry {
            path,
            data,
            is_binary,
            sha256,
            lines,
            eof_newline,
            rank,
            label,
            note,
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// A file is binary if it has a NUL byte or is not valid UTF-8.
pub fn is_binary(data: &[u8]) -> bool {
    data.contains(&0u8) || std::str::from_utf8(data).is_err()
}

pub fn lang_for(path: &str, is_bin: bool) -> &'static str {
    if is_bin {
        return "binary";
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    let ext: String = if base.starts_with('.') && !base[1..].contains('.') {
        base[1..].to_string()
    } else if let Some(pos) = base.rfind('.') {
        base[pos + 1..].to_string()
    } else {
        String::new()
    };
    let ext_lower = ext.to_lowercase();
    LANG_BY_EXT
        .iter()
        .find(|(k, _)| *k == ext_lower)
        .map_or("text", |(_, v)| v)
}

#[cfg(test)]
mod tests {
    include!("entry_tests.rs");
}
