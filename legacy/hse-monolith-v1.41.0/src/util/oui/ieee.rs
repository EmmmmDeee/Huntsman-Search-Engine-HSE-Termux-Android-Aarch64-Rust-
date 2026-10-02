//! The full IEEE MA-L registry, searched in place.
//!
//! ## Why this tier exists
//!
//! The curated table next door carries a vendor *and* a device class for ~110
//! prefixes chosen as the consumer hardware a survey most often meets. Measured
//! against a real capture off the device, it resolved **2 of 740** genuine
//! hardware addresses — 0.3%. The curation is not wrong about what it covers;
//! there is simply far more real hardware in the world than a hand-picked list
//! can name, and every unresolved address reported its vendor as `Unknown`.
//!
//! This tier answers the vendor question for the other 99.7%. It deliberately
//! does **not** answer the device-class question: IEEE assigns organisations,
//! not product categories, so a class here would be invention.
//! [`super::DeviceClass::Unknown`] already means exactly "we recognise the
//! vendor but cannot bucket the device", which is precisely this tier's answer.
//!
//! ## Why a packed blob rather than generated Rust
//!
//! ~39,000 assignments as a `const` array of string literals is a multi-megabyte
//! source file recompiled on every build, plus ~20,000 `&'static str` fat
//! pointers each needing a load-time relocation — a real cost on the no-root
//! Android target this ships to. As one [`include_bytes!`] blob it costs nothing
//! to compile, nothing to start, and is binary-searched in place: no decode
//! pass, no allocation, no lazily-built map.
//!
//! Regenerate with `cargo run --bin gen-oui` (`src/bin/gen_oui/`); the layout
//! is documented there and re-validated by [`layout`] here, so a truncated or
//! foreign file is rejected rather than silently misread.

/// The packed registry. See `scripts/gen_oui.py` for the layout.
const DATA: &[u8] = include_bytes!("ieee.bin");

/// Format tag. Bumped whenever the layout changes, so an old binary paired with
/// a new blob refuses it rather than reading garbage offsets.
const MAGIC: &[u8] = b"HSEOUI\x01\x00";

const HEADER: usize = 16;

/// Byte offsets of each section, validated once.
struct Layout {
    count: usize,
    prefixes: usize,
    vidx: usize,
    voff: usize,
    blob: usize,
}

fn le_u32(at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(DATA.get(at..at + 4)?.try_into().ok()?))
}

fn le_u16(at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(DATA.get(at..at + 2)?.try_into().ok()?))
}

/// Validate the blob and locate its sections.
///
/// Fails closed to `None` on anything unexpected — wrong magic, a section that
/// runs past the end of the file — so a corrupt or stale blob degrades to "no
/// IEEE tier" and the curated table still answers, rather than the lookup
/// reading arbitrary bytes as offsets.
fn layout() -> Option<&'static Layout> {
    static CELL: std::sync::OnceLock<Option<Layout>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        if DATA.len() < HEADER || DATA.get(..MAGIC.len())? != MAGIC {
            return None;
        }
        let count = le_u32(8)? as usize;
        let vcount = le_u32(12)? as usize;

        let prefixes = HEADER;
        let vidx = prefixes.checked_add(count.checked_mul(4)?)?;
        let unpadded = vidx.checked_add(count.checked_mul(2)?)?;
        // `voff` is 4-byte aligned by construction; mirror the generator's pad.
        let voff = unpadded.checked_add((4 - unpadded % 4) % 4)?;
        let blob = voff.checked_add(vcount.checked_add(1)?.checked_mul(4)?)?;
        if blob > DATA.len() {
            return None;
        }
        Some(Layout {
            count,
            prefixes,
            vidx,
            voff,
            blob,
        })
    })
    .as_ref()
}

/// The registered organisation for a 24-bit OUI, or `None` when the registry
/// does not list it.
///
/// `prefix` is the OUI as an integer — the first three octets, most significant
/// first (`00:1A:2B` → `0x001A2B`).
pub(super) fn vendor_for(prefix: u32) -> Option<&'static str> {
    let l = layout()?;

    // Binary search the ascending prefix table. Written out rather than using
    // `slice::binary_search` because the keys live as little-endian bytes inside
    // the blob; materialising them into a `&[u32]` would need either an
    // alignment-safe transmute (unsafe, and the crate forbids it) or a decode
    // pass that defeats the point of searching in place.
    let (mut lo, mut hi) = (0usize, l.count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if le_u32(l.prefixes + mid * 4)? < prefix {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo >= l.count || le_u32(l.prefixes + lo * 4)? != prefix {
        return None;
    }

    let vi = le_u16(l.vidx + lo * 2)? as usize;
    let start = le_u32(l.voff + vi * 4)? as usize;
    let end = le_u32(l.voff + (vi + 1) * 4)? as usize;
    if end < start {
        return None;
    }
    let bytes = DATA.get(l.blob.checked_add(start)?..l.blob.checked_add(end)?)?;
    std::str::from_utf8(bytes).ok()
}

/// Number of assignments in the embedded registry.
///
/// Read by the tests, which assert the blob parses to a plausible count rather
/// than trusting the header. NOT yet surfaced by `hse diagnostics`: an earlier
/// version of this comment said it was, which was a claim about intent rather
/// than about the code — nothing outside the tests calls it. The tier's real
/// coverage is therefore still unreportable at runtime; wiring this into the
/// diagnostics bundle is the fix, not restoring the sentence.
#[must_use]
pub fn registry_len() -> usize {
    layout().map_or(0, |l| l.count)
}

#[cfg(test)]
mod tests {
    include!("ieee_tests.rs");
}
