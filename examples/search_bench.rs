//! Search kernel benchmark. Run with `cargo run --release --locked --example search_bench`.
//!
//! A seeded corpus of operator-sized documents is searched with fixed queries. Each query prints
//! the median time over a fixed number of runs, its hit count, and a checksum of the hit list.
//! The corpus and the queries are fixed, so a changed checksum means a changed result.

use std::time::Instant;

use huntsman_recon::search::{Document, search};

const DOCS: usize = 40;
const WORDS_PER_DOC: usize = 25_000;
const RUNS: usize = 15;
const VOCABULARY: [&str; 12] = [
    "brisbane", "Brisbane", "port", "PORT", "radar", "sighting", "harbour", "Zürich", "note", "x",
    "2026", "station",
];
const QUERIES: [&str; 4] = [
    "port brisbane",
    "Zürich station",
    "harbour",
    "radar sighting port",
];

fn corpus() -> Vec<Document> {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let vocabulary_len = u64::try_from(VOCABULARY.len()).unwrap_or(1);
    (0..DOCS)
        .map(|index| {
            let mut body = String::new();
            for _ in 0..WORDS_PER_DOC {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let pick = usize::try_from(state % vocabulary_len).unwrap_or(0);
                body.push_str(VOCABULARY[pick]);
                body.push(' ');
            }
            Document {
                id: format!("doc-{index:03}"),
                body,
                source: "bench".into(),
            }
        })
        .collect()
}

fn checksum(hits: &[huntsman_recon::search::Hit]) -> u64 {
    hits.iter().fold(0u64, |acc, hit| {
        let score = u64::try_from(hit.score).unwrap_or(0);
        hit.id
            .bytes()
            .fold(acc.wrapping_mul(131).wrapping_add(score), |state, byte| {
                state.wrapping_mul(131).wrapping_add(u64::from(byte))
            })
    })
}

fn main() {
    let docs = corpus();
    let bytes: usize = docs.iter().map(|doc| doc.body.len()).sum();
    println!("corpus\tdocs={}\tbytes={bytes}", docs.len());
    for query in QUERIES {
        let mut times = Vec::with_capacity(RUNS);
        let mut hits = Vec::new();
        for _ in 0..RUNS {
            let start = Instant::now();
            hits = search(&docs, query);
            times.push(start.elapsed().as_nanos());
        }
        times.sort_unstable();
        println!(
            "{query:?}\tmedian_ns={}\thits={}\tchecksum={}",
            times[RUNS / 2],
            hits.len(),
            checksum(&hits)
        );
    }
}
