//! Opt-in SHA-256 benchmark for the real Android/Termux CPU.
//!
//! Run: cargo run --release --example sha256_arm64_bench --locked
//! Compare results on one physical handset with consistent power/thermal state.
//! QEMU throughput and CI cross-build success are not handset speed evidence.

use std::hint::black_box;
use std::time::{Duration, Instant};

use huntsman_recon::sha256::{Sha256, sha256};

fn portable_hash(input: &[u8]) -> [u8; 32] {
    let mut portable = Sha256::new();
    portable.update(input);
    portable.finalize()
}

fn time_path(input: &[u8], repeats: usize, accelerated: bool) -> Duration {
    let start = Instant::now();
    for _ in 0..repeats {
        let digest = if accelerated {
            sha256(black_box(input))
        } else {
            portable_hash(black_box(input))
        };
        black_box(digest);
    }
    start.elapsed()
}

fn main() {
    println!("SHA-256 backend comparison (wall-clock; not hardware attestation)");
    println!(
        "arch={} os={}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!("size_bytes,repetitions,portable_ms,selected_ms,portable_over_selected");

    for size in [64, 1023, 1024, 4096, 65_536, 1_048_576] {
        let input = (0..size)
            .map(|index| (index.wrapping_mul(113).wrapping_add(17) & 255) as u8)
            .collect::<Vec<_>>();
        assert_eq!(portable_hash(&input), sha256(&input), "digest mismatch");
        let repeats = (16 * 1024 * 1024 / size).clamp(16, 100_000);
        // Warm both paths before measuring. Alternate order for each size,
        // avoiding a systematic advantage from always running one path first.
        black_box(sha256(&input));
        black_box(portable_hash(&input));
        let (portable, selected) = if size % 2 == 0 {
            (
                time_path(&input, repeats, false),
                time_path(&input, repeats, true),
            )
        } else {
            let selected = time_path(&input, repeats, true);
            let portable = time_path(&input, repeats, false);
            (portable, selected)
        };
        let ratio = portable.as_secs_f64() / selected.as_secs_f64();
        println!(
            "{size},{repeats},{:.3},{:.3},{ratio:.2}",
            portable.as_secs_f64() * 1000.0,
            selected.as_secs_f64() * 1000.0
        );
    }
}
