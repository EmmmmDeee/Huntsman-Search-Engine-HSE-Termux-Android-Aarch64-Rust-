//! Local search. Operator-supplied documents only.
//! A blocked or throttled fetch is not a hit. No paid source. No live client.

use crate::classify::{classify_response, FetchOutcome};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub id: String,
    pub body: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: String,
    pub score: u32,
    pub source: String,
}

#[must_use]
pub fn tokenize(raw: &str) -> Vec<String> {
    raw.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() > 1)
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

#[must_use]
pub fn search(docs: &[Document], query: &str) -> Vec<Hit> {
    let terms = tokenize(query);
    if terms.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for doc in docs {
        let tokens = tokenize(&doc.body);
        let mut score = 0u32;
        let mut matched = 0u32;
        for term in &terms {
            let count = tokens.iter().filter(|t| *t == term).count() as u32;
            if count > 0 {
                matched += 1;
                score += count;
            }
        }
        if matched == terms.len() as u32 {
            hits.push(Hit {
                id: doc.id.clone(),
                score,
                source: doc.source.clone(),
            });
        }
    }
    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    hits
}

/// Load operator text files. Non-text and unreadable entries are skipped, not hits.
pub fn load_dir(dir: &std::path::Path) -> Vec<Document> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut docs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "txt" && ext != "md" {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !classify_response(200, &body).is_result() {
            continue;
        }
        let id = path.file_name().and_then(|n| n.to_str()).unwrap_or("doc").to_owned();
        docs.push(Document { id, body, source: path.display().to_string() });
    }
    docs.sort_by(|a, b| a.id.cmp(&b.id));
    docs
}
#[must_use]
pub fn search_response(status: u16, body: &str, query: &str, source: &str) -> Vec<Hit> {
    if !matches!(classify_response(status, body), FetchOutcome::Parsed) {
        return Vec::new();
    }
    search(
        &[Document { id: source.to_owned(), body: body.to_owned(), source: source.to_owned() }],
        query,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docs() -> Vec<Document> {
        vec![
            Document { id: "a".into(), body: "Brisbane radar sighting at the port".into(), source: "local".into() },
            Document { id: "b".into(), body: "Sydney harbour note".into(), source: "local".into() },
            Document { id: "c".into(), body: "Brisbane port schedule port".into(), source: "local".into() },
        ]
    }

    #[test]
    fn all_terms_required_and_blocked_page_is_not_a_hit() {
        let hits = search(&docs(), "brisbane port");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].id, "c");
        assert!(search(&docs(), "").is_empty());
        assert!(search_response(200, "<html>just a moment cloudflare</html>", "brisbane", "remote").is_empty());
        assert!(search_response(429, "brisbane port", "brisbane", "remote").is_empty());
        let parsed = search_response(200, "brisbane port open", "brisbane port", "remote");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn operator_dir_requires_every_term() {
        let root = std::env::temp_dir().join(format!("huntsman-docs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("port.txt"), "Brisbane port schedule").unwrap();
        std::fs::write(root.join("other.md"), "Sydney harbour note").unwrap();
        std::fs::write(root.join("skip.bin"), "Brisbane port").unwrap();
        std::fs::write(root.join("wall.txt"), "<html>just a moment cloudflare brisbane port</html>").unwrap();
        let docs = load_dir(&root);
        assert_eq!(docs.len(), 2);
        assert!(!docs.iter().any(|d| d.id == "wall.txt"));
        let hits = search(&docs, "brisbane port");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "port.txt");
        let _ = std::fs::remove_dir_all(&root);
    }
}
