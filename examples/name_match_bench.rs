//! Name-matching benchmark. Run with `cargo run --release --locked --example name_match_bench`.
//!
//! Two seeded corpora of directory-style lines are classified with `whole_word_token_match`,
//! `shares_whole_word_token` and `name_tokens`. The ASCII corpus must give the same checksum
//! before and after a change to name matching. The mixed corpus has accented names in capitals,
//! so its checksum may change where case-insensitive matching now finds them. The median time of
//! each matcher over the runs is printed with the checksum.

use std::time::Instant;

use huntsman_recon::textnorm::{name_tokens, shares_whole_word_token, whole_word_token_match};

const LINES: usize = 200_000;
const RUNS: usize = 9;
const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const ASCII_WORDS: [&str; 10] = [
    "ADA",
    "LOVELACE",
    "BILL",
    "ABBOTT",
    "ZOLA",
    "SMITH",
    "MARSHALL",
    "FAMILY",
    "FOUNDATION",
    "BRISBANE",
];
const MIXED_WORDS: [&str; 10] = [
    "ÉMILE", "ZOLA", "BJØRN", "NGUYỄN", "ŁUKASZ", "WÓJCIK", "ADA", "SMITH", "STRAßE", "BRISBANE",
];

/// Lines of three words each, drawn from `words` with a fixed xorshift sequence.
fn corpus(words: &[&str]) -> Vec<String> {
    let mut state = SEED;
    let len = u64::try_from(words.len()).unwrap_or(1);
    (0..LINES)
        .map(|_| {
            let mut line = String::new();
            for _ in 0..3 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let pick = usize::try_from(state % len).unwrap_or(0);
                line.push_str(words[pick]);
                line.push(' ');
            }
            line
        })
        .collect()
}

/// Median nanoseconds of `whole_word_token_match`, `shares_whole_word_token` and `name_tokens`
/// over the lines, and a checksum of the results of the last run.
fn run(lines: &[String], needle: &str) -> (u128, u128, u128, u64) {
    let mut whole_ns = Vec::with_capacity(RUNS);
    let mut shares_ns = Vec::with_capacity(RUNS);
    let mut tokens_ns = Vec::with_capacity(RUNS);
    let mut sum = 0_u64;
    for _ in 0..RUNS {
        let start = Instant::now();
        let word_hits: Vec<bool> = lines
            .iter()
            .map(|line| whole_word_token_match(line, needle))
            .collect();
        whole_ns.push(start.elapsed().as_nanos());

        let start = Instant::now();
        let share_hits: Vec<bool> = lines
            .iter()
            .map(|line| shares_whole_word_token(line, needle))
            .collect();
        shares_ns.push(start.elapsed().as_nanos());

        let start = Instant::now();
        let counts: Vec<usize> = lines.iter().map(|line| name_tokens(line).len()).collect();
        tokens_ns.push(start.elapsed().as_nanos());

        sum = word_hits.iter().zip(&share_hits).zip(&counts).fold(
            0_u64,
            |acc, ((word, share), count)| {
                let count = u64::try_from(*count).unwrap_or(0);
                acc.wrapping_mul(131)
                    .wrapping_add(u64::from(*word) + 2 * u64::from(*share) + 4 * count)
            },
        );
    }
    for times in [&mut whole_ns, &mut shares_ns, &mut tokens_ns] {
        times.sort_unstable();
    }
    (
        whole_ns[RUNS / 2],
        shares_ns[RUNS / 2],
        tokens_ns[RUNS / 2],
        sum,
    )
}

fn main() {
    for (label, words, needle) in [
        ("ascii", &ASCII_WORDS[..], "ada lovelace"),
        ("mixed", &MIXED_WORDS[..], "émile zola"),
    ] {
        let lines = corpus(words);
        let bytes: usize = lines.iter().map(String::len).sum();
        let (whole, shares, tokens, sum) = run(&lines, needle);
        println!(
            "{label}\tlines={LINES}\tbytes={bytes}\tmatch_ns={whole}\tshares_ns={shares}\ttokens_ns={tokens}\tchecksum={sum}"
        );
    }
}
