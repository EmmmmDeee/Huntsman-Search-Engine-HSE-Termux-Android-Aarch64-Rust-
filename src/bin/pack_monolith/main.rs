//! Pack the entire HSE repository into one topologically ordered, loss-less
//! monolithic text file (and unpack it back).
//!
//! The artifact it produces (`HSE_MONOLITH.glm5.txt` by default) is a
//! single, self-describing file that captures **100% of every git-tracked
//! file** in the repository — every byte, every path — concatenated in
//! *dependency-topological* order so that an agent reading top-to-bottom
//! always sees a layer's dependencies before the code that uses them.
//!
//! ## Design goals
//!
//! * **Complete.** Every file reported by `git ls-files` is included (the
//!   output artifact itself is the only exclusion). Binary files are
//!   embedded base64. Nothing is summarised, truncated, or sampled.
//! * **Topological.** Files are grouped into the crate's architectural
//!   layers (`util -> core -> storage -> modules -> api -> cli -> audit ->
//!   selftest`, then the crate roots `lib.rs`/`main.rs` which *depend on*
//!   all of the above, then `tests`/`benches` which depend on the whole
//!   crate, then the non-code appendix). Within a layer, a directory's own
//!   `mod.rs` precedes its sub-modules, mirroring Rust's module-declaration
//!   tree — see [`topology`].
//! * **Loss-less & reversible.** `--unpack` reconstructs a byte-identical
//!   tree; every record carries a SHA-256 and a whole-tree digest
//!   fingerprints the set.
//! * **Deterministic.** No wall-clock timestamps or randomness — the output
//!   is a pure function of the working tree, so the same commit always
//!   yields the same bytes (same ethos as the repo's own `build.rs` source
//!   manifest).
//!
//! ## Usage
//!
//! ```text
//! cargo run --bin pack-monolith                      # write HSE_MONOLITH.glm5.txt
//! cargo run --bin pack-monolith -- -o OUT             # custom output path
//! cargo run --bin pack-monolith -- --unpack HSE_MONOLITH.glm5.txt DESTDIR
//! cargo run --bin pack-monolith -- --verify HSE_MONOLITH.glm5.txt   # round-trip check
//! ```

mod entry;
mod format_util;
mod gitinfo;
mod pack;
mod topology;
mod tree;
mod unpack;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

const PACKER_VERSION: &str = "1";
const DEFAULT_OUTPUT: &str = "HSE_MONOLITH.glm5.txt";

// Per-file payload delimiters. These are guaranteed (and re-checked at pack
// time) never to occur at the start of a line inside any file's content, so
// a parser can split records unambiguously by scanning for them at column 0.
const BEGIN: &str = "@@HSE-BEGIN@@";
const END: &str = "@@HSE-END@@";
const BEGIN_B64: &str = "@@HSE-BEGIN-B64@@";
const END_B64: &str = "@@HSE-END-B64@@";
const SENTINELS: &[&str] = &[BEGIN, END, BEGIN_B64, END_B64];

#[derive(Parser)]
#[command(
    name = "pack-monolith",
    about = "Pack/unpack the HSE repo as one monolithic file"
)]
struct Args {
    /// Output artifact path.
    #[arg(short = 'o', long, default_value = DEFAULT_OUTPUT)]
    output: PathBuf,
    /// Reconstruct the tree from a monolith: MONOLITH DESTDIR.
    #[arg(long, num_args = 2, value_names = ["MONOLITH", "DESTDIR"])]
    unpack: Option<Vec<PathBuf>>,
    /// Round-trip verify a monolith against the working tree.
    #[arg(long, value_name = "MONOLITH")]
    verify: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<u8, String> {
    let root = gitinfo::repo_root()?;

    if let Some(pair) = &args.unpack {
        let [mono, dest] = <[PathBuf; 2]>::try_from(pair.clone())
            .map_err(|_| "--unpack takes exactly two paths: MONOLITH DESTDIR".to_string())?;
        let out = unpack::unpack(&mono, &dest)?;
        println!(
            "[unpack] wrote {} files to {}",
            format_util::commas_int(out.len() as u64),
            dest.display()
        );
        return Ok(0);
    }
    if let Some(mono) = &args.verify {
        let code = unpack::verify(std::path::Path::new(&root), mono)?;
        return Ok(code as u8);
    }
    let out_path = if args.output.is_absolute() {
        args.output.clone()
    } else {
        std::path::Path::new(&root).join(&args.output)
    };
    pack::pack(&root, &out_path)?;
    Ok(0)
}
