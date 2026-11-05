//! Opt-in SHA-256 benchmark for native ARM64 Linux and Android/Termux CPUs.
//!
//! Run: `cargo run --release --example sha256_arm64_bench --locked`
//! QEMU throughput and CI cross-build success are not handset speed evidence.

use std::hint::black_box;
use std::time::{Duration, Instant};

use huntsman_recon::sha256::{Sha256, sha256};

#[derive(Clone, Copy)]
enum Path {
    Portable,
    Ring,
    Selected,
}

fn portable_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize()
}

fn time_path(input: &[u8], repeats: usize, path: Path) -> Duration {
    let start = Instant::now();
    for _ in 0..repeats {
        match path {
            Path::Portable => {
                black_box(portable_hash(black_box(input)));
            }
            Path::Ring => {
                black_box(ring::digest::digest(
                    &ring::digest::SHA256,
                    black_box(input),
                ));
            }
            Path::Selected => {
                black_box(sha256(black_box(input)));
            }
        }
    }
    start.elapsed()
}

fn median_millis(input: &[u8], repeats: usize, path: Path) -> f64 {
    let mut samples = [0_f64; 3];
    for sample in &mut samples {
        *sample = time_path(input, repeats, path).as_secs_f64() * 1000.0;
    }
    samples.sort_by(f64::total_cmp);
    samples[1]
}

const BENCHMARK_SIZES: [usize; 13] = [
    32, 64, 128, 256, 384, 512, 768, 1023, 1024, 2048, 4096, 65_536, 1_048_576,
];

/// Alternate each case's measurement order to reduce first-run bias.
fn portable_first(case_index: usize) -> bool {
    case_index & 1 == 0
}

fn main() {
    println!("SHA-256 backend comparison (median of three wall-clock samples)");
    println!(
        "arch={} os={}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!(
        "size_bytes,repetitions,portable_ms,ring_ms,selected_ms,portable_over_ring,portable_over_selected"
    );

    for (case_index, size) in BENCHMARK_SIZES.into_iter().enumerate() {
        let input = (0..size)
            .map(|index| index.to_le_bytes()[0].wrapping_mul(113).wrapping_add(17))
            .collect::<Vec<_>>();
        let expected = portable_hash(&input);
        assert_eq!(sha256(&input), expected, "dispatch digest mismatch");
        assert_eq!(
            ring::digest::digest(&ring::digest::SHA256, &input).as_ref(),
            expected.as_slice(),
            "direct backend mismatch"
        );
        let repeats = (16 * 1024 * 1024 / size).clamp(16, 100_000);
        black_box(portable_hash(&input));
        black_box(sha256(&input));
        black_box(ring::digest::digest(&ring::digest::SHA256, &input));

        let (portable, ring, selected) = if portable_first(case_index) {
            (
                median_millis(&input, repeats, Path::Portable),
                median_millis(&input, repeats, Path::Ring),
                median_millis(&input, repeats, Path::Selected),
            )
        } else {
            let selected = median_millis(&input, repeats, Path::Selected);
            let ring = median_millis(&input, repeats, Path::Ring);
            let portable = median_millis(&input, repeats, Path::Portable);
            (portable, ring, selected)
        };
        println!(
            "{size},{repeats},{portable:.3},{ring:.3},{selected:.3},{:.2},{:.2}",
            portable / ring,
            portable / selected
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{BENCHMARK_SIZES, portable_first};

    #[test]
    fn measurement_order_alternates_across_benchmark_cases() {
        let actual: Vec<bool> = BENCHMARK_SIZES
            .iter()
            .enumerate()
            .map(|(index, _)| portable_first(index))
            .collect();
        assert!(actual.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(BENCHMARK_SIZES.contains(&1023));
        assert!(BENCHMARK_SIZES.contains(&1024));
    }
}
