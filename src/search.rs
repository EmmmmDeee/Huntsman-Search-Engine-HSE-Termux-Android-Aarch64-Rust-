//! Local search. Operator-supplied documents only.
//! A blocked or throttled fetch is not a hit. No paid source. No live client.

use std::path::Path;

use crate::classifier::classify;
use crate::classify::{classify_response, is_saved_challenge};
use crate::entity::EntityKind;
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

/// Every distinct query term must occur. Score is the total occurrence count. A query that is
/// one email address or one domain must also occur as a whole name (see `names_identifier`).
#[must_use]
pub fn search(docs: &[Document], query: &str) -> Vec<Hit> {
    let mut terms = tokenize(query);
    terms.sort_unstable();
    terms.dedup();
    if terms.is_empty() {
        return Vec::new();
    }
    let identifier = identifier_query(query);
    let mut hits = Vec::new();
    let mut counts = vec![0usize; terms.len()];
    for doc in docs {
        counts.fill(0);
        for_each_token(&doc.body, |token| {
            if let Ok(index) = terms.binary_search_by(|term| term.as_str().cmp(token)) {
                counts[index] += 1;
            }
        });
        if counts.iter().all(|&count| count > 0)
            && identifier
                .as_ref()
                .is_none_or(|id| names_identifier(&doc.body, id))
        {
            hits.push(Hit {
                id: doc.id.clone(),
                score: counts.iter().sum(),
                source: doc.source.clone(),
            });
        }
    }
    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    hits
}

/// An email address or a domain that is the whole query, in canonical ASCII form.
struct Identifier {
    value: String,
    /// A domain also names its subdomains and the addresses at it. An address names only itself.
    domain: bool,
}

/// The identifier when the whole query is one ASCII email address or domain. Matching its terms
/// alone would find "ada@example.com" in any document that holds "ada", "example" and "com" apart.
fn identifier_query(query: &str) -> Option<Identifier> {
    let classified = classify(query.trim().trim_end_matches('.'));
    if !classified.value.is_ascii() {
        return None;
    }
    match classified.kind {
        EntityKind::Email => Some(Identifier {
            value: classified.value,
            domain: false,
        }),
        EntityKind::Domain => Some(Identifier {
            value: classified.value,
            domain: true,
        }),
        _ => None,
    }
}

/// Whether `text` names the identifier. Names are runs of letters, digits and `.@-_+`, with a
/// trailing full stop removed, so a sentence that ends in the name still matches. A run matches
/// when it equals the identifier, ignoring ASCII case. For a domain, a run also matches when it
/// ends in the domain after a `.` or `@`: `api.example.com` and `ada@example.com` name
/// `example.com`, while `myexample.com` and `example.com.au` do not.
fn names_identifier(text: &str, identifier: &Identifier) -> bool {
    let value = identifier.value.as_str();
    text.split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '@' | '-' | '_' | '+')))
        .map(|run| run.trim_end_matches('.'))
        .any(|run| {
            run.eq_ignore_ascii_case(value)
                || (identifier.domain
                    && run.len() > value.len()
                    && matches!(run.as_bytes()[run.len() - value.len() - 1], b'.' | b'@')
                    && run
                        .get(run.len() - value.len()..)
                        .is_some_and(|tail| tail.eq_ignore_ascii_case(value)))
        })
}

/// Calls `visit` with each token that [`tokenize`] would return for `text`, in order. Lowercase
/// ASCII tokens are passed without allocation.
fn for_each_token(text: &str, mut visit: impl FnMut(&str)) {
    for word in text.split(|c: char| !c.is_alphanumeric()) {
        if word.chars().nth(1).is_none() {
            continue;
        }
        if word
            .bytes()
            .all(|b| b.is_ascii() && !b.is_ascii_uppercase())
        {
            visit(word);
        } else {
            visit(&word.to_lowercase());
        }
    }
}

/// Load operator `.txt` and `.md` files from one directory, not recursive.
/// Short HTML challenge pages (see [`is_saved_challenge`]), non-UTF-8, oversize files, and
/// symlinks are reported as skipped.
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
        if is_saved_challenge(&body) {
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
    use std::collections::HashMap;

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
    fn email_and_domain_queries_match_the_whole_name() {
        let doc = |id: &str, body: &str| Document {
            id: id.into(),
            body: body.into(),
            source: "local".into(),
        };
        let docs = vec![
            doc("email", "Contact Ada@Example.com for the report."),
            doc(
                "parts",
                "Ada reviewed the example. The com directory lists her",
            ),
            doc("lookalike", "Ada wrote to ada@example.company"),
            doc("subdomain", "See https://api.example.com/v1 for the feed"),
            doc("suffix", "Hosted at myexample.com and example.com.au"),
        ];
        let ids = |query: &str| -> Vec<String> {
            search(&docs, query).into_iter().map(|hit| hit.id).collect()
        };
        assert_eq!(ids("ada@example.com"), ["email"]);
        assert_eq!(ids("example.com"), ["email", "subdomain"]);
        assert_eq!(ids("Ada@EXAMPLE.com."), ["email"]);
    }

    #[test]
    fn saved_documents_that_quote_a_challenge_are_kept() {
        let root = std::env::temp_dir().join(format!("huntsman-quotes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("README.md"),
            "# Notes\n\nThe block page reads `<html>just a moment cloudflare</html>`.\n",
        )
        .unwrap();
        std::fs::write(
            root.join("note.txt"),
            "DataDome blocked our request on Tuesday.",
        )
        .unwrap();
        let article = format!(
            "<html>{}<script src=\"https://www.google.com/recaptcha/api.js\"></script></html>",
            "x".repeat(40 * 1024)
        );
        std::fs::write(root.join("article.txt"), article).unwrap();
        std::fs::write(
            root.join("block.txt"),
            "<html>just a moment cloudflare</html>",
        )
        .unwrap();
        let loaded = load_dir(&root).unwrap();
        let ids: Vec<&str> = loaded.docs.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, ["README.md", "article.txt", "note.txt"]);
        let skipped: Vec<&str> = loaded.skipped.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].ends_with("block.txt"), "{skipped:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The count-per-document search before `for_each_token` replaced the token map. Kept here
    /// as the oracle for the differential test.
    fn reference_search(docs: &[Document], query: &str) -> Vec<Hit> {
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

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            usize::try_from(self.0 % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
        }
    }

    #[test]
    fn counting_matches_the_reference_on_generated_corpora() {
        // Vocabulary covers case, Unicode (including a final sigma and a dotted capital I),
        // one-letter words, punctuation and digits, so every branch of the tokeniser runs.
        let vocabulary = [
            "port",
            "Port",
            "PORT",
            "Zürich",
            "zürich",
            "ΟΔΟΣ",
            "ὈΔΌΣ",
            "a",
            "b1",
            "x-ray",
            "İstanbul",
            "42",
            "brisbane",
            "Brisbane!",
            "",
        ];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..300 {
            let doc_count = 1 + rng.below(12);
            let mut docs = Vec::with_capacity(doc_count);
            for index in 0..doc_count {
                let word_count = rng.below(40);
                let mut words = Vec::with_capacity(word_count);
                for _ in 0..word_count {
                    words.push(vocabulary[rng.below(vocabulary.len())]);
                }
                docs.push(Document {
                    id: format!("doc{round}-{index}"),
                    body: words.join(" "),
                    source: "generated".into(),
                });
            }
            let query_terms = 1 + rng.below(3);
            let mut query_words = Vec::with_capacity(query_terms);
            for _ in 0..query_terms {
                query_words.push(vocabulary[rng.below(vocabulary.len())]);
            }
            let query = query_words.join(" ");
            assert_eq!(
                search(&docs, &query),
                reference_search(&docs, &query),
                "round {round}: {query:?}"
            );
        }
    }

    #[test]
    fn repeated_query_term_does_not_double_score() {
        assert_eq!(
            search(&docs(), "port")[0].score,
            search(&docs(), "port port")[0].score
        );
    }
}
