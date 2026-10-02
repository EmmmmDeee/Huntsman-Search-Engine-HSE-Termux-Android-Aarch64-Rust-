//! Local search. Operator-supplied documents only.
//! A blocked or throttled fetch is not a hit. No paid source. No live client.

use std::collections::HashMap;
use std::path::Path;

use crate::classify::classify_response;
use crate::error::Error;
use crate::fsio::read_bounded;

/// Per-document read bound for operator directories.
pub const MAX_DOC_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub id: String,
    pub body: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: String,
    pub score: usize,
    pub source: String,
}

/// A candidate file that was not loaded, with the reason. Skipped is not scored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    pub docs: Vec<Document>,
    pub skipped: Vec<Skipped>,
}

/// Unicode word tokens, lowercased. Single-character tokens are dropped.
/// A non-ASCII letter never splits a word.
#[must_use]
pub fn tokenize(raw: &str) -> Vec<String> {
    raw.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().nth(1).is_some())
        .map(str::to_lowercase)
        .collect()
}

/// Every distinct query term must occur. Score is the total occurrence count.
#[must_use]
pub fn search(docs: &[Document], query: &str) -> Vec<Hit> {
    let mut terms = tokenize(query);
    terms.sort_unstable();
    terms.dedup();
    if terms.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for doc in docs {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for token in tokenize(&doc.body) {
            *counts.entry(token).or_default() += 1;
        }
        let found: Option<Vec<usize>> = terms.iter().map(|t| counts.get(t).copied()).collect();
        if let Some(found) = found {
            hits.push(Hit {
                id: doc.id.clone(),
                score: found.iter().sum(),
                source: doc.source.clone(),
            });
        }
    }
    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    hits
}

/// Load operator `.txt` and `.md` files from one directory, not recursive.
/// Challenge pages, non-UTF-8, oversize files, and symlinks are reported as skipped.
///
/// # Errors
/// `Error::Store` when the directory itself cannot be read. An unreadable
/// directory is not an empty result.
pub fn load_dir(dir: &Path) -> Result<Loaded, Error> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| Error::Store(format!("{}: {e}", dir.display())))?;
    let mut loaded = Loaded::default();
    for entry in entries {
        let entry = entry.map_err(|e| Error::Store(format!("{}: {e}", dir.display())))?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !["txt", "md"].iter().any(|e| ext.eq_ignore_ascii_case(e)) {
            continue;
        }
        let shown = path.display().to_string();
        let skip = |reason: String| Skipped {
            path: shown.clone(),
            reason,
        };
        let body = match read_bounded(&path, MAX_DOC_BYTES) {
            Ok(bytes) => {
                if let Ok(body) = String::from_utf8(bytes) {
                    body
                } else {
                    loaded.skipped.push(skip("not utf-8".into()));
                    continue;
                }
            }
            Err(e) => {
                loaded.skipped.push(skip(e.to_string()));
                continue;
            }
        };
        if !classify_response(200, &body).is_result() {
            loaded.skipped.push(skip("challenge page".into()));
            continue;
        }
        let id = path
            .file_name()
            .map_or_else(|| "doc".to_owned(), |n| n.to_string_lossy().into_owned());
        loaded.docs.push(Document {
            id,
            body,
            source: shown,
        });
    }
    loaded.docs.sort_by(|a, b| a.id.cmp(&b.id));
    loaded.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(loaded)
}

/// Search one fetched body. Anything but a parsed 2xx is not a hit.
#[must_use]
pub fn search_response(status: u16, body: &str, query: &str, source: &str) -> Vec<Hit> {
    if !classify_response(status, body).is_result() {
        return Vec::new();
    }
    search(
        &[Document {
            id: source.to_owned(),
            body: body.to_owned(),
            source: source.to_owned(),
        }],
        query,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docs() -> Vec<Document> {
        vec![
            Document {
                id: "a".into(),
                body: "Brisbane radar sighting at the port".into(),
                source: "local".into(),
            },
            Document {
                id: "b".into(),
                body: "Sydney harbour note".into(),
                source: "local".into(),
            },
            Document {
                id: "c".into(),
                body: "Brisbane port schedule port".into(),
                source: "local".into(),
            },
        ]
    }

    #[test]
    fn all_terms_required_and_blocked_page_is_not_a_hit() {
        let hits = search(&docs(), "brisbane port");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id, "c");
        let termless = search(&docs(), "");
        assert!(termless.is_empty(), "{termless:?}");
        let challenged = search_response(
            200,
            "<html>just a moment cloudflare</html>",
            "brisbane",
            "remote",
        );
        assert!(challenged.is_empty(), "{challenged:?}");
        let throttled = search_response(429, "brisbane port", "brisbane", "remote");
        assert!(throttled.is_empty(), "{throttled:?}");
        let parsed = search_response(200, "brisbane port open", "brisbane port", "remote");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn non_ascii_words_are_whole_terms() {
        let docs = vec![
            Document {
                id: "rich".into(),
                body: "Rich harbour".into(),
                source: "local".into(),
            },
            Document {
                id: "zurich".into(),
                body: "Zürich station, MÜNCHEN".into(),
                source: "local".into(),
            },
        ];
        let hits = search(&docs, "zürich");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].id, "zurich");
        assert_eq!(search(&docs, "münchen").len(), 1);
    }

    #[test]
    fn operator_dir_requires_every_term() {
        let root = std::env::temp_dir().join(format!("huntsman-docs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("port.txt"), "Brisbane port schedule").unwrap();
        std::fs::write(root.join("other.md"), "Sydney harbour note").unwrap();
        std::fs::write(root.join("skip.bin"), "Brisbane port").unwrap();
        std::fs::write(root.join("UPPER.TXT"), "Brisbane port upper").unwrap();
        std::fs::write(
            root.join("wall.txt"),
            "<html>just a moment cloudflare brisbane port</html>",
        )
        .unwrap();
        std::fs::write(root.join("latin1.txt"), b"Brisbane port \xff").unwrap();
        let loaded = load_dir(&root).unwrap();
        let docs = loaded.docs;
        assert_eq!(docs.len(), 3);
        assert!(docs.iter().any(|d| d.id == "UPPER.TXT"));
        assert!(!docs.iter().any(|d| d.id == "wall.txt"));
        let reasons: Vec<&str> = loaded.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert_eq!(reasons, ["not utf-8", "challenge page"]);
        let hits = search(&docs, "brisbane port");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id, "UPPER.TXT");
        assert_eq!(hits[1].id, "port.txt");
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            load_dir(&root).is_err(),
            "missing dir is an error, not hits=0"
        );
    }

    #[test]
    fn repeated_query_term_does_not_double_score() {
        assert_eq!(
            search(&docs(), "port")[0].score,
            search(&docs(), "port port")[0].score
        );
    }
}
