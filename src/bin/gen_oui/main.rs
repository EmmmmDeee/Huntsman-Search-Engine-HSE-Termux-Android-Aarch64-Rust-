//! `gen-oui` — regenerate `src/util/oui/ieee.bin` from the IEEE MA-L registry.
//!
//! ```text
//! cargo run --bin gen-oui                 # fetch and regenerate
//! cargo run --bin gen-oui -- --check       # verify the committed blob is current
//! ```
//!
//! Replaces the former `scripts/gen_oui.py` (tracked as an accepted non-Rust
//! exception in `docs/RUST_MIGRATION_AUDIT_2026-08-27.md`) with an equivalent
//! Rust tool, verified to produce byte-identical output against the live
//! registry before the Python original was removed.
//!
//! Why a packed binary rather than generated Rust source: the registry is
//! ~40,000 assignments. As a `const` array of string literals that is a
//! multi-megabyte source file that must be parsed and monomorphised on every
//! build, and ~20,000 `&'static str` fat pointers each needing a load-time
//! relocation. As one `include_bytes!` blob it costs nothing to compile,
//! nothing to start, and is searched in place with no allocation and no
//! decode step — see `src/util/oui/ieee.rs` for the consumer.
//!
//! Layout, little-endian throughout, all sections 4-byte aligned by
//! construction (see [`build::build`] for the authoritative encoder):
//!
//! ```text
//! magic     8   b"HSEOUI\x01\x00"
//! count     4   number of OUI assignments
//! vcount    4   number of distinct vendor names
//! prefixes  4 × count      u32, the 24-bit OUI, ASCENDING (binary searched)
//! vidx      2 × count      u16 index into the vendor table, parallel to prefixes
//! pad       0 or 2         so `voff` starts 4-byte aligned
//! voff      4 × (vcount+1) u32 byte offsets into blob; entry i spans [i, i+1)
//! blob      …              concatenated UTF-8 vendor names, no separators
//! ```

mod build;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sha2::{Digest, Sha256};

use huntsman_search_engine::util::http::build_client;

const REGISTRY_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

fn out_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/util/oui/ieee.bin")
}

#[derive(Parser)]
#[command(
    name = "gen-oui",
    about = "Regenerate src/util/oui/ieee.bin from the IEEE MA-L registry"
)]
struct Args {
    /// Verify the committed blob matches the live (or `--from-file`)
    /// registry instead of writing it.
    #[arg(long)]
    check: bool,

    /// Read the CSV from a path instead of fetching the live registry —
    /// mainly for reproducible testing against a saved snapshot.
    #[arg(long, value_name = "PATH")]
    from_file: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gen-oui: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &Args) -> Result<(), String> {
    let raw = match &args.from_file {
        Some(path) => {
            std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?
        }
        None => fetch(REGISTRY_URL).await?,
    };
    let packed = build::build(&raw)?;
    let out = out_path();

    if args.check {
        let current = std::fs::read(&out)
            .map_err(|e| format!("{} is missing or unreadable: {e}", out.display()))?;
        if current == packed {
            println!("up to date ({} bytes)", current.len());
            return Ok(());
        }
        return Err(format!(
            "stale: committed {} ({} B) != generated {} ({} B) — re-run `cargo run --bin gen-oui`",
            hex16(&current),
            current.len(),
            hex16(&packed),
            packed.len(),
        ));
    }

    std::fs::write(&out, &packed).map_err(|e| format!("writing {}: {e}", out.display()))?;
    let count = u32::from_le_bytes(packed[8..12].try_into().expect("checked width"));
    let vcount = u32::from_le_bytes(packed[12..16].try_into().expect("checked width"));
    println!(
        "wrote {} — {count} assignments, {vcount} vendors, {} bytes",
        out.display(),
        packed.len()
    );
    println!("sha256 {}", hex_full(&packed));
    Ok(())
}

async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let client = build_client();
    let resp = client
        .get(url)
        .header("User-Agent", "hse-gen-oui/1")
        .send()
        .await
        .map_err(|e| format!("fetching {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("fetching {url}: HTTP {}", resp.status()));
    }
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("reading response body from {url}: {e}"))
}

fn hex_full(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// First 16 hex chars of the digest — a stable, glanceable fingerprint for a
/// diagnostic line, matching the truncated form the Python original printed.
fn hex16(data: &[u8]) -> String {
    hex_full(data)[..16].to_string()
}
