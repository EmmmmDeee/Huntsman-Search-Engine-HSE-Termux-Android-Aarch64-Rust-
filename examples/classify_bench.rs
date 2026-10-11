//! Classifier extraction benchmark. Run with `cargo run --release --locked --example classify_bench`.
//!
//! A seeded prose text of fixed size is run through `extract`. The median time over a fixed number
//! of runs is printed with the entity count and a checksum of the extracted values.

use std::time::Instant;

use huntsman_recon::classifier::extract;

const WORDS: [&str; 24] = [
    "the",
    "report",
    "since",
    "province",
    "Vincent",
    "Smith",
    "Brisbane",
    "2026",
    "10:30",
    "ada@example.com",
    "https://example.com/path",
    "192.168.0.1",
    "-27.4698,153.0251",
    "example.com",
    "@handle",
    "COVID-19",
    "Acme",
    "Pty",
    "Ltd",
    "harbour",
    "radar",
    "note",
    "Lincoln",
    "street",
];
const RUNS: usize = 9;

fn prose(words: usize) -> String {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let vocabulary_len = u64::try_from(WORDS.len()).unwrap_or(1);
    let mut text = String::new();
    for _ in 0..words {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let pick = usize::try_from(state % vocabulary_len).unwrap_or(0);
        text.push_str(WORDS[pick]);
        text.push(' ');
    }
    text
}

fn main() {
    let text = prose(150_000);
    println!("text_bytes={}", text.len());
    let mut times = Vec::with_capacity(RUNS);
    let mut entities = 0usize;
    let mut checksum = 0u64;
    for _ in 0..RUNS {
        let start = Instant::now();
        let found = extract(&text);
        times.push(start.elapsed().as_nanos());
        entities = found.len();
        checksum = found.iter().fold(0u64, |acc, item| {
            item.value
                .bytes()
                .fold(acc.wrapping_mul(131), |state, byte| {
                    state.wrapping_mul(31).wrapping_add(u64::from(byte))
                })
        });
    }
    times.sort_unstable();
    println!(
        "median_ns={} entities={entities} checksum={checksum}",
        times[RUNS / 2]
    );
}
