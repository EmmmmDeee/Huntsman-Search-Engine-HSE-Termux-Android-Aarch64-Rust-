//! Pure CSV-bytes → packed-blob transform. No I/O, no network — everything
//! `main.rs` needs to unit-test without touching the filesystem or a socket.
//!
//! Mirrors the layout and semantics of the tool this replaces
//! (`scripts/gen_oui.py`, ported wholesale rather than reinterpreted) byte
//! for byte: same ascending-prefix ordering, same first-appearance vendor
//! table, same first-wins duplicate-assignment policy, same
//! `Private`/`IEEE Registration Authority` placeholder filter. Verified
//! against the live IEEE registry to produce an output identical to the
//! Python original before this tool replaced it.

use std::collections::BTreeMap;

/// Registry format tag — must match [`crate` `src/util/oui/ieee.rs`]'s own
/// `MAGIC`, which is the actual consumer of this format.
pub(crate) const MAGIC: &[u8] = b"HSEOUI\x01\x00";

/// The two registry placeholder organisation names that identify nobody —
/// filtered the same way the Python original filtered them.
const PLACEHOLDER_VENDORS: [&str; 2] = ["private", "ieee registration authority"];

/// Build the packed registry blob from a raw IEEE `oui.csv` byte stream.
///
/// `Err` only for the one condition the header format cannot represent: more
/// than [`u16::MAX`] distinct vendor names (the `vidx` column is `u16`). Any
/// CSV shape short of that degrades gracefully — a malformed or short
/// `Assignment`, an empty `Organization Name`, or a placeholder vendor simply
/// drops that row, matching the original.
///
/// # Determinism
///
/// Assignments are emitted in ascending prefix order and vendor names in
/// first-appearance order over that same ascending-prefix walk (not raw CSV
/// row order — a vendor with multiple prefixes takes its blob position from
/// whichever of its prefixes sorts lowest), so the same registry input always
/// produces byte-identical output.
pub(crate) fn build(csv_bytes: &[u8]) -> Result<Vec<u8>, String> {
    // Decode-with-replacement FIRST, exactly like the Python original's
    // `csv_bytes.decode("utf-8", errors="replace")` — CSV parsing then runs
    // over already-valid UTF-8, so an invalid byte becomes one U+FFFD in a
    // field rather than aborting the parse or being handled per-record.
    let text = String::from_utf8_lossy(csv_bytes);

    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = rdr
        .headers()
        .map_err(|e| format!("reading CSV header row: {e}"))?
        .clone();
    let assignment_idx = headers.iter().position(|h| h == "Assignment");
    let org_idx = headers.iter().position(|h| h == "Organization Name");

    // prefix -> first-seen vendor name. A `BTreeMap` gives both the
    // first-wins-on-duplicate `seen.setdefault` semantics AND the ascending-
    // prefix walk order in one structure — no separate sort step needed.
    let mut seen: BTreeMap<u32, String> = BTreeMap::new();

    for result in rdr.records() {
        let record = result.map_err(|e| format!("reading a CSV row: {e}"))?;

        let raw_assignment = assignment_idx.and_then(|i| record.get(i)).unwrap_or("");
        let raw_org = org_idx.and_then(|i| record.get(i)).unwrap_or("");

        let raw = raw_assignment.trim().to_ascii_uppercase();
        // Collapse every whitespace run (including embedded newlines some
        // registry rows carry) to one space and trim the ends — the same
        // normalisation `" ".join(vendor.split())` performs.
        let vendor = raw_org.split_whitespace().collect::<Vec<_>>().join(" ");

        if raw.chars().count() != 6 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if vendor.is_empty() || PLACEHOLDER_VENDORS.contains(&vendor.to_lowercase().as_str()) {
            continue;
        }
        // `raw` is verified as exactly 6 ASCII hex digits above, so this
        // cannot fail and cannot exceed `u32` (max 0xFFFFFF).
        let prefix =
            u32::from_str_radix(&raw, 16).expect("6 verified ASCII hex digits always parse as u32");

        seen.entry(prefix).or_insert(vendor);
    }

    let prefixes: Vec<u32> = seen.keys().copied().collect();

    // Vendor table: first-appearance order walking `seen` in ascending-prefix
    // order (which `BTreeMap::values()` gives for free), id width checked
    // before it's ever cast down to u16.
    let mut vendor_id: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    let mut vendor_order: Vec<&str> = Vec::new();
    let mut vidx_wide: Vec<u32> = Vec::with_capacity(seen.len());
    for vendor in seen.values() {
        let id = *vendor_id.entry(vendor.as_str()).or_insert_with(|| {
            let id = vendor_order.len() as u32;
            vendor_order.push(vendor.as_str());
            id
        });
        vidx_wide.push(id);
    }

    if vendor_order.len() > usize::from(u16::MAX) {
        return Err(format!(
            "vendor count {} exceeds the u16 index width; widen `vidx` to u32 in both this tool \
             and src/util/oui/ieee.rs",
            vendor_order.len()
        ));
    }
    let vidx: Vec<u16> = vidx_wide.into_iter().map(|i| i as u16).collect();

    let mut blob: Vec<u8> = Vec::new();
    let mut voff: Vec<u32> = vec![0];
    for v in &vendor_order {
        blob.extend_from_slice(v.as_bytes());
        voff.push(
            u32::try_from(blob.len())
                .map_err(|_| "vendor blob exceeds 4 GiB (u32 byte-offset width)".to_string())?,
        );
    }

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(prefixes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(vendor_order.len() as u32).to_le_bytes());
    for &p in &prefixes {
        out.extend_from_slice(&p.to_le_bytes());
    }
    for &i in &vidx {
        out.extend_from_slice(&i.to_le_bytes());
    }
    while out.len() % 4 != 0 {
        out.push(0);
    }
    for &o in &voff {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(&blob);
    Ok(out)
}

#[cfg(test)]
mod tests {
    include!("build_tests.rs");
}
