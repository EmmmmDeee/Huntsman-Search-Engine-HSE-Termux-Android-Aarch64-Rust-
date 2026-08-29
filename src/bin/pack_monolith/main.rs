//! `pack-monolith` — pack the entire HSE repository into one topologically
//! ordered, loss-less monolithic text file (and unpack it back).
//!
//! ```text
//! cargo run --bin pack-monolith                       # write HSE_MONOLITH.glm5.txt
//! cargo run --bin pack-monolith -- -o OUT             # custom output path
//! cargo run --bin pack-monolith -- --unpack MONO DIR  # reconstruct the tree
//! cargo run --bin pack-monolith -- --verify MONO      # round-trip check
//! ```
//!
//! The artifact captures **100 % of every git-tracked file** — every byte,
//! every path — concatenated in *dependency-topological* order (`util -> core
//! -> storage -> modules -> api -> cli -> audit -> selftest`, then the crate
//! roots, then tests/benches, then the non-code appendix), so an agent reading
//! top-to-bottom always sees a layer's dependencies before the code that uses
//! them. Binary files are embedded base64; every record carries a SHA-256 and a
//! whole-tree digest fingerprints the set. It is deterministic — a pure
//! function of the working tree.
//!
//! Replaces the former `scripts/pack_monolith.py` (an accepted non-Rust
//! exception in `docs/RUST_MIGRATION_AUDIT_2026-08-27.md`) with an equivalent
//! Rust tool. The record format is byte-compatible with the Python original —
//! a monolith written by either side round-trips through the other — verified
//! against the Python packer's output on the real tree before it was removed.
//! See [`pack`] for the ported logic; the only intentional divergence is the
//! artifact's own self-reference (`generator` line + the FORMAT SPEC's
//! reference-unpacker command now name this Rust binary).

mod pack;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "pack-monolith",
    about = "Pack/unpack the HSE repo as one topologically ordered, loss-less monolithic file"
)]
struct Args {
    /// Output artifact path (relative to the repo root unless absolute).
    #[arg(short, long, default_value_t = pack::DEFAULT_OUTPUT.to_string())]
    output: String,
    /// Reconstruct the tree from a monolith: `--unpack <MONOLITH> <DESTDIR>`.
    #[arg(long, num_args = 2, value_names = ["MONOLITH", "DESTDIR"])]
    unpack: Option<Vec<String>>,
    /// Round-trip verify a monolith against the working tree.
    #[arg(long, value_name = "MONOLITH")]
    verify: Option<String>,
}

fn main() -> ExitCode {
    match run(&Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pack-monolith: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let root_s = pack::repo_root()?;
    let root = Path::new(&root_s);

    if let Some(u) = &args.unpack {
        let mono = std::fs::read_to_string(&u[0]).map_err(|e| format!("reading {}: {e}", u[0]))?;
        let restored = pack::unpack(&mono, Path::new(&u[1]))?;
        println!("[unpack] wrote {} files to {}", restored.len(), u[1]);
        return Ok(());
    }

    if let Some(v) = &args.verify {
        let mono = std::fs::read_to_string(v).map_err(|e| format!("reading {v}: {e}"))?;
        let mono_rel = rel_to_root(root, v);
        return if pack::verify(root, &mono, &mono_rel)? {
            Ok(())
        } else {
            Err("round-trip verification failed".to_string())
        };
    }

    // Default action: pack.
    let out_path = if Path::new(&args.output).is_absolute() {
        PathBuf::from(&args.output)
    } else {
        root.join(&args.output)
    };
    let rel_out = rel_to_root(root, &out_path.to_string_lossy());
    let (mono, files, digest) = pack::pack_to_string(root, &rel_out)?;
    std::fs::write(&out_path, &mono).map_err(|e| format!("writing {}: {e}", out_path.display()))?;
    println!("[pack] {files} files  ->  {}", out_path.display());
    println!("[pack] artifact size: {} bytes", mono.len());
    println!("[pack] tree-digest  : sha256:{digest}");
    Ok(())
}

/// Repo-relative form of `p` (for excluding the artifact from its own capture);
/// falls back to `p` verbatim when it is not under `root` (then it cannot
/// collide with a tracked path anyway).
fn rel_to_root(root: &Path, p: &str) -> String {
    let abs = std::path::absolute(p).unwrap_or_else(|_| PathBuf::from(p));
    abs.strip_prefix(root)
        .map_or_else(|_| p.to_string(), |r| r.to_string_lossy().into_owned())
}
