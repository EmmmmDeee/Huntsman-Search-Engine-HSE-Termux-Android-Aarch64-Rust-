//! `gen_oui` — regenerate `src/util/oui/ieee.bin` from the IEEE MA-L registry.
//!
//!     cargo run --bin gen_oui                    # fetch and regenerate
//!     cargo run --bin gen_oui -- --check         # verify the committed blob is current
//!
//! Why a packed binary rather than generated Rust: the registry is ~40,000
//! assignments. As a `const` array of string literals that is a multi-megabyte
//! source file that must be parsed and monomorphised on every build, and
//! ~20,000 `&'static str` fat pointers each needing a load-time relocation. As
//! one `include_bytes!` blob it costs nothing to compile, nothing to start,
//! and is searched in place with no allocation and no decode step.
//!
//! Layout, little-endian throughout, all sections 4-byte aligned by
//! construction — mirrored (and re-validated) by `src/util/oui/ieee.rs`:
//!
//! ```text
//!     magic     8   b"HSEOUI\x01\x00"
//!     count     4   number of OUI assignments
//!     vcount    4   number of distinct vendor names
//!     prefixes  4 × count      u32, the 24-bit OUI, ASCENDING (binary searched)
//!     vidx      2 × count      u16 index into the vendor table, parallel to prefixes
//!     pad       0 or 2         so `voff` starts 4-byte aligned
//!     voff      4 × (vcount+1) u32 byte offsets into blob; entry i spans [i, i+1)
//!     blob      …              concatenated UTF-8 vendor names, no separators
//! ```
//!
//! Determinism: assignments are emitted in ascending prefix order and vendor
//! names in first-appearance order over that same sequence, so the same
//! registry input always produces byte-identical output.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use sha2::{Digest, Sha256};

use huntsman_search_engine::util::http::build_client;

const REGISTRY_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";
const MAGIC: &[u8] = b"HSEOUI\x01\x00";

#[derive(Parser)]
#[command(
    name = "gen_oui",
    about = "Regenerate src/util/oui/ieee.bin from the IEEE MA-L registry"
)]
struct Args {
    /// Verify the committed blob matches the live (or --from-file) registry
    /// instead of writing it.
    #[arg(long)]
    check: bool,

    /// Read the registry CSV from a local path instead of fetching it.
    #[arg(long, value_name = "PATH")]
    from_file: Option<PathBuf>,

    /// Where the packed blob lives / gets written.
    #[arg(long, default_value = "src/util/oui/ieee.bin")]
    out: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gen_oui: {e}");
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
    let packed = build(&raw)?;

    if args.check {
        let current = std::fs::read(&args.out)
            .map_err(|e| format!("{} is missing or unreadable: {e}", args.out.display()))?;
        if current == packed {
            println!("up to date ({} bytes)", current.len());
            return Ok(());
        }
        return Err(format!(
            "stale: committed {} ({} B) != generated {} ({} B) — re-run gen_oui",
            &sha256_hex(&current)[..16],
            current.len(),
            &sha256_hex(&packed)[..16],
            packed.len(),
        ));
    }

    std::fs::write(&args.out, &packed)
        .map_err(|e| format!("writing {}: {e}", args.out.display()))?;
    let count = u32::from_le_bytes(packed[8..12].try_into().unwrap());
    let vcount = u32::from_le_bytes(packed[12..16].try_into().unwrap());
    println!(
        "wrote {} — {count} assignments, {vcount} vendors, {} bytes",
        args.out.display(),
        packed.len()
    );
    println!("sha256 {}", sha256_hex(&packed));
    Ok(())
}

async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let resp = build_client()
        .get(url)
        .header(reqwest::header::USER_AGENT, "hse-gen-oui/1")
        .timeout(Duration::from_secs(180))
        .send()
        .await
        .map_err(|e| format!("fetching {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("fetching {url}: {e}"))?;
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("reading response body from {url}: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Parse the IEEE MA-L registry CSV and pack it into the on-disk layout
/// documented at the top of this file. Pure function of its input bytes —
/// same registry in, byte-identical blob out.
fn build(csv_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let text = String::from_utf8_lossy(csv_bytes);
    // `flexible`: a real-world registry occasionally has a ragged row: degrade
    // gracefully like Python's `csv.DictReader` (which never raises on a
    // short/long row) rather than hard-failing the whole regeneration on one
    // malformed line.
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = rdr
        .headers()
        .map_err(|e| format!("reading CSV header: {e}"))?
        .clone();
    let assignment_idx = headers.iter().position(|h| h == "Assignment");
    let org_idx = headers.iter().position(|h| h == "Organization Name");

    let mut seen: BTreeMap<u32, String> = BTreeMap::new();
    for result in rdr.records() {
        let record = result.map_err(|e| format!("reading CSV row: {e}"))?;
        let raw = assignment_idx
            .and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        let vendor_raw = org_idx.and_then(|i| record.get(i)).unwrap_or("");
        let vendor = vendor_raw.split_whitespace().collect::<Vec<_>>().join(" ");

        if raw.chars().count() != 6 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let vendor_lower = vendor.to_ascii_lowercase();
        if vendor.is_empty()
            || vendor_lower == "private"
            || vendor_lower == "ieee registration authority"
        {
            // "Private" is the registry's placeholder for a withheld name — it
            // identifies nobody, and surfacing it as a vendor would read as an
            // attribution rather than the absence of one.
            continue;
        }
        let Ok(prefix) = u32::from_str_radix(&raw, 16) else {
            continue;
        };
        // A duplicate assignment should not exist; if the registry ever emits
        // one, keep the first so the output stays a function of the input order.
        seen.entry(prefix).or_insert(vendor);
    }

    // `seen` is a BTreeMap, so this is already ascending-prefix order.
    let prefixes: Vec<u32> = seen.keys().copied().collect();

    // Vendor ids are assigned in first-appearance order while scanning
    // `prefixes` ascending — NOT raw CSV row order — matching the Python
    // generator's `for p in prefixes: ...` loop exactly.
    let mut vendor_id: HashMap<&str, usize> = HashMap::new();
    let mut vendor_names: Vec<&str> = Vec::new();
    let mut vidx_wide: Vec<usize> = Vec::with_capacity(seen.len());
    for vendor in seen.values() {
        let id = *vendor_id.entry(vendor.as_str()).or_insert_with(|| {
            vendor_names.push(vendor.as_str());
            vendor_names.len() - 1
        });
        vidx_wide.push(id);
    }
    if vendor_names.len() > 0xFFFF {
        return Err(format!(
            "vendor count {} exceeds the u16 index width; widen `vidx` to u32 in both this \
             tool and src/util/oui/ieee.rs",
            vendor_names.len()
        ));
    }
    let vidx: Vec<u16> = vidx_wide.into_iter().map(|i| i as u16).collect();

    let mut blob: Vec<u8> = Vec::new();
    let mut voff: Vec<u32> = vec![0];
    for v in &vendor_names {
        blob.extend_from_slice(v.as_bytes());
        voff.push(blob.len() as u32);
    }

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(prefixes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(vendor_names.len() as u32).to_le_bytes());
    for &p in &prefixes {
        out.extend_from_slice(&p.to_le_bytes());
    }
    for &i in &vidx {
        out.extend_from_slice(&i.to_le_bytes());
    }
    if out.len() % 4 != 0 {
        out.extend(std::iter::repeat_n(0u8, 4 - out.len() % 4));
    }
    for &o in &voff {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(&blob);
    Ok(out)
}

#[cfg(test)]
mod tests {
    include!("main_tests.rs");
}
