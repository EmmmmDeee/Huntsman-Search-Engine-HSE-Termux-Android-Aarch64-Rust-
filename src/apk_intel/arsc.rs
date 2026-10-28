//! The string a resource id resolves to in `resources.arsc`, read without loading or executing the
//! app. An app's displayed name (`android:label`) is almost always a resource reference rather than
//! a literal, so recovering it — the single most human-recognisable fact about an app — needs the
//! compiled resource table.
//!
//! Only what resolving one id requires is read: the table's global value string pool and, in the
//! matching package, the type chunks for the requested type until an entry for the requested id
//! yields a string. Every offset and length is bounds-checked; a malformed or truncated table
//! yields `None` rather than a misread. The first resolvable string value is returned (the default
//! configuration in practice); a localized override in another configuration is not preferred over
//! it, so the result is the base label, never a wrong one.

/// Chunk types in a compiled resource table.
const RES_STRING_POOL: u16 = 0x0001;
const RES_TABLE: u16 = 0x0002;
const RES_TABLE_PACKAGE: u16 = 0x0200;
const RES_TABLE_TYPE: u16 = 0x0201;
/// `ResStringPool_header` flag: strings are UTF-8 rather than UTF-16.
const FLAG_UTF8: u32 = 1 << 8;
/// `Res_value` data type for a reference into the global string pool.
const TYPE_STRING: u8 = 0x03;
/// A `ResTable_type` entry offset meaning "no entry for this id in this type".
const NO_ENTRY: u32 = 0xffff_ffff;
/// Packages, type chunks and entries past these counts are not walked; a real table has few.
const MAX_PACKAGES: usize = 16;
const MAX_TYPE_CHUNKS: usize = 4096;
/// A resolved label longer than this is refused as malformed rather than kept.
const MAX_LABEL_BYTES: usize = 512;

fn le16(data: &[u8], at: usize) -> Option<u16> {
    let field = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

fn le32(data: &[u8], at: usize) -> Option<u32> {
    let field = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn index(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}

/// A chunk's type, header size and whole size, validated to fit within `[at, limit)`.
fn chunk(data: &[u8], at: usize, limit: usize) -> Option<(u16, usize, usize)> {
    let kind = le16(data, at)?;
    let header = usize::from(le16(data, at + 2)?);
    let size = index(le32(data, at + 4)?)?;
    let end = at.checked_add(size)?;
    if header < 8 || size < header || end > limit {
        return None;
    }
    Some((kind, header, size))
}

/// A UTF-8 string-pool length prefix: one byte, or two when the first has its high bit set.
fn len8(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *data.get(at)?;
    if first & 0x80 == 0 {
        Some((usize::from(first), 1))
    } else {
        let second = *data.get(at + 1)?;
        Some(((usize::from(first & 0x7f) << 8) | usize::from(second), 2))
    }
}

/// A UTF-16 string-pool length prefix: one unit, or two when the first has its high bit set.
fn len16(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = le16(data, at)?;
    if first & 0x8000 == 0 {
        Some((usize::from(first), 2))
    } else {
        let second = le16(data, at + 2)?;
        Some(((usize::from(first & 0x7fff) << 16) | usize::from(second), 4))
    }
}

/// A located `ResStringPool`: the slices and flags needed to read one string by index.
struct StringPool<'a> {
    /// The chunk's own bytes.
    chunk: &'a [u8],
    count: usize,
    offsets_at: usize,
    strings_at: usize,
    utf8: bool,
}

impl<'a> StringPool<'a> {
    /// The string at `i`, or `None` when the index is out of range or the entry is malformed.
    fn get(&self, i: usize) -> Option<String> {
        if i >= self.count {
            return None;
        }
        let offset = index(le32(self.chunk, self.offsets_at + i.checked_mul(4)?)?)?;
        let at = self.strings_at.checked_add(offset)?;
        if self.utf8 {
            // UTF-8: a character-count prefix, then a byte-count prefix, then the bytes.
            let (_, chars_len) = len8(self.chunk, at)?;
            let (bytes, byte_len) = len8(self.chunk, at + chars_len)?;
            let start = at + chars_len + byte_len;
            let end = start.checked_add(bytes)?;
            if bytes > MAX_LABEL_BYTES {
                return None;
            }
            let raw = self.chunk.get(start..end)?;
            String::from_utf8(raw.to_vec()).ok()
        } else {
            // UTF-16: a code-unit-count prefix, then that many little-endian units.
            let (units, prefix) = len16(self.chunk, at)?;
            let start = at + prefix;
            let end = start.checked_add(units.checked_mul(2)?)?;
            if units.checked_mul(2)? > MAX_LABEL_BYTES {
                return None;
            }
            let raw = self.chunk.get(start..end)?;
            let wide: Vec<u16> = raw
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16(&wide).ok()
        }
    }

    /// Locates the `ResStringPool` chunk that begins at `at` within `data`.
    fn parse(data: &'a [u8], at: usize, limit: usize) -> Option<StringPool<'a>> {
        let (kind, header, size) = chunk(data, at, limit)?;
        if kind != RES_STRING_POOL {
            return None;
        }
        let count = index(le32(data, at + 8)?)?;
        let flags = le32(data, at + 16)?;
        let strings_start = index(le32(data, at + 20)?)?;
        if strings_start > size {
            return None;
        }
        Some(StringPool {
            chunk: data.get(at..at.checked_add(size)?)?,
            count,
            offsets_at: header,
            strings_at: strings_start,
            utf8: flags & FLAG_UTF8 != 0,
        })
    }
}

/// The string that resource id `id` (`0xPPTTEEEE`: package, type, entry) resolves to, or `None`.
#[must_use]
pub fn string_resource(data: &[u8], id: u32) -> Option<String> {
    let want_package = ((id >> 24) & 0xff) as u8;
    let want_type = ((id >> 16) & 0xff) as u8; // 1-based type id
    let want_entry = index(id & 0xffff)?;

    let (kind, header, size) = chunk(data, 0, data.len())?;
    if kind != RES_TABLE {
        return None;
    }
    let pool = StringPool::parse(data, header, size)?;

    // Walk the table's child chunks for the matching package, then its type chunks.
    let mut at = chunk(data, header, size).map(|(_, _, pool_size)| header + pool_size)?;
    let mut packages = 0;
    while at + 8 <= size {
        let (child_kind, child_header, child_size) = chunk(data, at, size)?;
        if child_kind == RES_TABLE_PACKAGE && packages < MAX_PACKAGES {
            packages += 1;
            if let Some(label) = package_string(
                data,
                at,
                child_header,
                child_size,
                &pool,
                want_package,
                want_type,
                want_entry,
            ) {
                return Some(label);
            }
        }
        at = at.checked_add(child_size)?;
    }
    None
}

/// Scans one `ResTable_package` for a `TYPE_STRING` entry matching the requested id.
#[allow(clippy::too_many_arguments)]
fn package_string(
    data: &[u8],
    at: usize,
    header: usize,
    size: usize,
    pool: &StringPool,
    want_package: u8,
    want_type: u8,
    want_entry: usize,
) -> Option<String> {
    let package_id = le32(data, at + 8)?;
    if u8::try_from(package_id & 0xff).ok()? != want_package {
        return None;
    }
    let end = at.checked_add(size)?;
    let mut child = at.checked_add(header)?;
    let mut types = 0;
    while child + 8 <= end && types < MAX_TYPE_CHUNKS {
        let (kind, child_header, child_size) = chunk(data, child, end)?;
        if kind == RES_TABLE_TYPE {
            types += 1;
            if *data.get(child + 8)? == want_type {
                if let Some(label) =
                    type_entry_string(data, child, child_header, child_size, pool, want_entry)
                {
                    return Some(label);
                }
            }
        }
        child = child.checked_add(child_size)?;
    }
    None
}

/// The string value at `want_entry` in one `ResTable_type` chunk, when that entry is a string.
fn type_entry_string(
    data: &[u8],
    at: usize,
    header: usize,
    size: usize,
    pool: &StringPool,
    want_entry: usize,
) -> Option<String> {
    let entry_count = index(le32(data, at + 12)?)?;
    let entries_start = index(le32(data, at + 16)?)?;
    if want_entry >= entry_count {
        return None;
    }
    let offset = le32(
        data,
        at.checked_add(header)?
            .checked_add(want_entry.checked_mul(4)?)?,
    )?;
    if offset == NO_ENTRY {
        return None;
    }
    let entry_at = at.checked_add(entries_start)?.checked_add(index(offset)?)?;
    if entry_at.checked_add(8)? > at.checked_add(size)? {
        return None;
    }
    // ResTable_entry: size u16, flags u16, key u32. A complex (map) entry carries no inline value.
    let entry_size = usize::from(le16(data, entry_at)?);
    let flags = le16(data, entry_at + 2)?;
    if flags & 0x0001 != 0 {
        return None; // FLAG_COMPLEX: a bag/map, not a plain value
    }
    // Res_value follows the fixed-size entry header.
    let value_at = entry_at.checked_add(entry_size)?;
    let data_type = *data.get(value_at + 3)?;
    if data_type != TYPE_STRING {
        return None;
    }
    let pool_index = index(le32(data, value_at + 4)?)?;
    pool.get(pool_index)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Builds a minimal UTF-8 `ResStringPool` chunk holding `strings`.
    fn string_pool(strings: &[&str]) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut blob = Vec::new();
        for s in strings {
            offsets.extend_from_slice(&u32::try_from(blob.len()).unwrap().to_le_bytes());
            let bytes = s.as_bytes();
            // UTF-8: char-count prefix, byte-count prefix (both < 128 here), bytes, NUL.
            blob.push(u8::try_from(s.chars().count()).unwrap());
            blob.push(u8::try_from(bytes.len()).unwrap());
            blob.extend_from_slice(bytes);
            blob.push(0);
        }
        let header = 28;
        let strings_start = header + offsets.len();
        let size = strings_start + blob.len();
        let mut out = vec![0_u8; header];
        out[0..2].copy_from_slice(&RES_STRING_POOL.to_le_bytes());
        out[2..4].copy_from_slice(&u16::try_from(header).unwrap().to_le_bytes());
        out[4..8].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        out[8..12].copy_from_slice(&u32::try_from(strings.len()).unwrap().to_le_bytes());
        out[16..20].copy_from_slice(&FLAG_UTF8.to_le_bytes());
        out[20..24].copy_from_slice(&u32::try_from(strings_start).unwrap().to_le_bytes());
        out.extend_from_slice(&offsets);
        out.extend_from_slice(&blob);
        out
    }

    /// Builds a `ResTable_type` chunk with a single entry (index `entry`) whose value is the global
    /// string-pool index `string_index`.
    fn type_chunk(type_id: u8, entry: usize, string_index: u32) -> Vec<u8> {
        let header = 20 + 36; // ResTable_type header + a zeroed ResTable_config of size 36
        let entry_count = entry + 1;
        let offsets_len = entry_count * 4;
        // ResTable_entry (8 bytes: size u16, flags u16, key u32) + Res_value (8 bytes).
        let entry_bytes = {
            let mut e = Vec::new();
            e.extend_from_slice(&8_u16.to_le_bytes()); // entry header size
            e.extend_from_slice(&0_u16.to_le_bytes()); // flags: not complex
            e.extend_from_slice(&0_u32.to_le_bytes()); // key index
            e.extend_from_slice(&8_u16.to_le_bytes()); // Res_value size
            e.push(0); // res0
            e.push(TYPE_STRING); // dataType
            e.extend_from_slice(&string_index.to_le_bytes()); // data
            e
        };
        let entries_start = header + offsets_len;
        let size = entries_start + entry_bytes.len();
        let mut out = vec![0_u8; header];
        out[0..2].copy_from_slice(&RES_TABLE_TYPE.to_le_bytes());
        out[2..4].copy_from_slice(&u16::try_from(header).unwrap().to_le_bytes());
        out[4..8].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        out[8] = type_id;
        out[12..16].copy_from_slice(&u32::try_from(entry_count).unwrap().to_le_bytes());
        out[16..20].copy_from_slice(&u32::try_from(entries_start).unwrap().to_le_bytes());
        // Entry offset array: every slot NO_ENTRY except the one we fill.
        let mut offsets = vec![0xff_u8; offsets_len];
        offsets[entry * 4..entry * 4 + 4].copy_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&offsets);
        out.extend_from_slice(&entry_bytes);
        out
    }

    /// Builds a `ResTable_package` chunk (id `package_id`) wrapping `type_chunk`. Its own type and
    /// key string pools are empty — `string_resource` reads neither to resolve a string value.
    fn package(package_id: u32, type_chunk: &[u8]) -> Vec<u8> {
        let header = 288; // ResTable_package fixed header
        let type_pool = string_pool(&[]);
        let key_pool = string_pool(&[]);
        let size = header + type_pool.len() + key_pool.len() + type_chunk.len();
        let mut out = vec![0_u8; header];
        out[0..2].copy_from_slice(&RES_TABLE_PACKAGE.to_le_bytes());
        out[2..4].copy_from_slice(&u16::try_from(header).unwrap().to_le_bytes());
        out[4..8].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        out[8..12].copy_from_slice(&package_id.to_le_bytes());
        out.extend_from_slice(&type_pool);
        out.extend_from_slice(&key_pool);
        out.extend_from_slice(type_chunk);
        out
    }

    /// A whole `resources.arsc` whose global string pool holds `values`, with one package/type/
    /// entry resolving resource id `id` to `values[string_index]`.
    pub(crate) fn table(values: &[&str], id: u32, string_index: u32) -> Vec<u8> {
        let want_package = (id >> 24) & 0xff;
        let want_type = u8::try_from((id >> 16) & 0xff).unwrap();
        let want_entry = usize::try_from(id & 0xffff).unwrap();
        let global = string_pool(values);
        let types = type_chunk(want_type, want_entry, string_index);
        let package = package(want_package, &types);
        let header = 12; // ResTable_header: chunk header (8) + packageCount (4)
        let size = header + global.len() + package.len();
        let mut out = vec![0_u8; header];
        out[0..2].copy_from_slice(&RES_TABLE.to_le_bytes());
        out[2..4].copy_from_slice(&u16::try_from(header).unwrap().to_le_bytes());
        out[4..8].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        out[8..12].copy_from_slice(&1_u32.to_le_bytes()); // packageCount
        out.extend_from_slice(&global);
        out.extend_from_slice(&package);
        out
    }

    #[test]
    fn a_reference_resolves_to_its_default_string() {
        // id 0x7f0e0001: package 0x7f, type 0x0e, entry 0x0001 -> global string index 2 ("Field Tracker").
        let arsc = table(
            &["unused", "com.example.field", "Field Tracker"],
            0x7f0e_0001,
            2,
        );
        assert_eq!(
            string_resource(&arsc, 0x7f0e_0001).as_deref(),
            Some("Field Tracker")
        );
    }

    #[test]
    fn a_missing_or_mismatched_id_yields_none_not_a_wrong_string() {
        let arsc = table(&["App Name"], 0x7f0e_0001, 0);
        // Wrong type, wrong entry, and wrong package each resolve to nothing.
        assert!(string_resource(&arsc, 0x7f0f_0001).is_none(), "wrong type");
        assert!(string_resource(&arsc, 0x7f0e_0002).is_none(), "wrong entry");
        assert!(
            string_resource(&arsc, 0x7e0e_0001).is_none(),
            "wrong package"
        );
    }

    #[test]
    fn a_non_table_or_truncated_blob_yields_none() {
        assert!(string_resource(b"PK\x03\x04 not arsc", 0x7f0e_0001).is_none());
        assert!(string_resource(b"", 0x7f0e_0001).is_none());
        let whole = table(&["Name"], 0x7f0e_0001, 0);
        for cut in [4, 12, whole.len() - 1] {
            assert!(
                string_resource(&whole[..cut], 0x7f0e_0001).is_none(),
                "cut {cut}"
            );
        }
    }
}
