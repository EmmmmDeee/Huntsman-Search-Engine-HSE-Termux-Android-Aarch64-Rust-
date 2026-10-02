//! The full IEEE MA-L registry, searched in place.

const DATA: &[u8] = include_bytes!("oui_ieee.bin");
const MAGIC: &[u8] = b"HSEOUI\x01\x00";
const HEADER: usize = 16;

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

fn layout() -> Option<&'static Layout> {
    static CELL: std::sync::OnceLock<Option<Layout>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        if DATA.len() < HEADER || DATA.get(..MAGIC.len())? != MAGIC {
            return None;
        }
        let count = le_u32(8)? as usize;
        let vendor_count = le_u32(12)? as usize;
        let prefixes = HEADER;
        let vidx = prefixes.checked_add(count.checked_mul(4)?)?;
        let unpadded = vidx.checked_add(count.checked_mul(2)?)?;
        let voff = unpadded.checked_add((4 - unpadded % 4) % 4)?;
        let blob = voff.checked_add(vendor_count.checked_add(1)?.checked_mul(4)?)?;
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

pub(super) fn vendor_for(prefix: u32) -> Option<&'static str> {
    let layout = layout()?;
    let (mut low, mut high) = (0usize, layout.count);
    while low < high {
        let mid = low + (high - low) / 2;
        if le_u32(layout.prefixes + mid * 4)? < prefix {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if low >= layout.count || le_u32(layout.prefixes + low * 4)? != prefix {
        return None;
    }
    let vendor_index = le_u16(layout.vidx + low * 2)? as usize;
    let start = le_u32(layout.voff + vendor_index * 4)? as usize;
    let end = le_u32(layout.voff + (vendor_index + 1) * 4)? as usize;
    if end < start {
        return None;
    }
    let bytes = DATA.get(layout.blob.checked_add(start)?..layout.blob.checked_add(end)?)?;
    std::str::from_utf8(bytes).ok()
}

#[must_use]
pub fn registry_len() -> usize {
    layout().map_or(0, |layout| layout.count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_is_well_formed_and_substantial() {
        assert!(registry_len() > 30_000);
    }

    #[test]
    fn known_assignments_resolve() {
        let apple = vendor_for(0x00_1451).unwrap();
        assert!(apple.to_ascii_lowercase().contains("apple"));
        let cisco = vendor_for(0x00_000c).unwrap();
        assert!(cisco.to_ascii_lowercase().contains("cisco"));
    }

    #[test]
    fn unassigned_prefix_is_none() {
        assert_eq!(vendor_for(0x10_1010), None);
        assert_eq!(vendor_for(0x20_2020), None);
        assert!(vendor_for(0x00_0000).is_some());
    }
}
