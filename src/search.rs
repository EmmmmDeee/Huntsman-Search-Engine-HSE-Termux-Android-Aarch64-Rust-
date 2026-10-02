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

/// A fetch becomes hits only when the classifier says the body is the payload.
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
}
