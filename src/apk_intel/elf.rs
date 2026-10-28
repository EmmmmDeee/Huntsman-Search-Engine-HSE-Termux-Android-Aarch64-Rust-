//! What a native library (`lib/*/*.so`) declares about itself, read from its ELF structures
//! without loading or executing it:
//!
//! - its GNU **build-id** — a hash the linker stamps into the binary (`--build-id`, on by default
//!   in the Android NDK). A useful cross-APK candidate pivot, not proof of identical bytes,
//!   provenance, authorship or a shared build: build-id bytes may be supplied or forged;
//! - its **`SONAME`** (the canonical name the library records for itself) and its **`DT_NEEDED`**
//!   list (the shared libraries it links against) — a native dependency fingerprint the Java-level
//!   SDK fingerprint cannot see, because stripped C/C++ code carries no package names.
//!
//! The build-id note sits at a direct file offset. The `SONAME`/`NEEDED` strings sit in the
//! dynamic string table, which the dynamic section references by virtual address, so that address
//! is translated to a file offset through the `PT_LOAD` segment that maps it. Every offset is
//! bounds-checked; a file that is not a little-endian ELF, or whose headers do not fit, yields
//! `None` rather than a misread.

/// `PT_LOAD`: a loadable segment, used to translate a virtual address to a file offset.
const PT_LOAD: u32 = 1;
/// `PT_DYNAMIC`: the segment holding the dynamic-linking array.
const PT_DYNAMIC: u32 = 2;
/// `PT_NOTE`: a program header describing a note segment.
const PT_NOTE: u32 = 4;
/// `NT_GNU_BUILD_ID`: the note type the build-id uses, under the name `GNU`.
const NT_GNU_BUILD_ID: u32 = 3;
/// Dynamic-array tags we read: end, a needed library, the string table, its size, the `SONAME`.
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
/// A build-id longer than this (far beyond SHA-256) is ignored as malformed.
const MAX_BUILD_ID_BYTES: usize = 64;
/// Program headers past this count are not walked; a real `.so` has a handful.
const MAX_PROGRAM_HEADERS: usize = 256;
/// Dynamic entries past this count are not walked; a real `.so` has tens.
const MAX_DYNAMIC_ENTRIES: usize = 8192;
/// `DT_NEEDED` libraries past this count are not kept; a real `.so` names a handful.
const MAX_NEEDED: usize = 64;
/// A `SONAME` or needed-library name longer than this is refused as malformed.
const MAX_LIB_NAME_BYTES: usize = 256;

fn u16_le(data: &[u8], at: usize) -> Option<u16> {
    let field = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

fn u32_le(data: &[u8], at: usize) -> Option<u32> {
    let field = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn u64_le(data: &[u8], at: usize) -> Option<u64> {
    let field = data.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(field.try_into().ok()?))
}

fn index(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}

/// One program header's type, the file range of its contents, and the virtual address it maps to,
/// read for the ELF class.
struct ProgramHeader {
    kind: u32,
    offset: usize,
    size: usize,
    vaddr: u64,
}

/// Where and how the program headers sit, by ELF class.
struct Layout {
    is_64: bool,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

/// Reads the ELF identity and program-header table location, or `None` for a non-ELF or
/// big-endian file (Android has no big-endian native libraries).
fn layout(data: &[u8]) -> Option<Layout> {
    if data.get(..4)? != b"\x7fELF" {
        return None;
    }
    let class = *data.get(4)?;
    let endianness = *data.get(5)?;
    if endianness != 1 {
        return None; // not little-endian
    }
    match class {
        1 => Some(Layout {
            is_64: false,
            phoff: index(u32_le(data, 28)?.into())?,
            phentsize: usize::from(u16_le(data, 42)?),
            phnum: usize::from(u16_le(data, 44)?),
        }),
        2 => Some(Layout {
            is_64: true,
            phoff: index(u64_le(data, 32)?)?,
            phentsize: usize::from(u16_le(data, 54)?),
            phnum: usize::from(u16_le(data, 56)?),
        }),
        _ => None,
    }
}

fn program_header(data: &[u8], at: usize, is_64: bool) -> Option<ProgramHeader> {
    if is_64 {
        Some(ProgramHeader {
            kind: u32_le(data, at)?,
            offset: index(u64_le(data, at + 8)?)?,
            vaddr: u64_le(data, at + 16)?,
            size: index(u64_le(data, at + 32)?)?,
        })
    } else {
        Some(ProgramHeader {
            kind: u32_le(data, at)?,
            offset: index(u32_le(data, at + 4)?.into())?,
            vaddr: u32_le(data, at + 8)?.into(),
            size: index(u32_le(data, at + 16)?.into())?,
        })
    }
}

/// Every program header that parses, up to the header cap.
fn program_headers(data: &[u8], layout: &Layout) -> Vec<ProgramHeader> {
    let mut headers = Vec::new();
    for i in 0..layout.phnum.min(MAX_PROGRAM_HEADERS) {
        let Some(at) = layout.phoff.checked_add(i.saturating_mul(layout.phentsize)) else {
            break;
        };
        if let Some(header) = program_header(data, at, layout.is_64) {
            headers.push(header);
        }
    }
    headers
}

/// The file offset a virtual address maps to, through the `PT_LOAD` segment that contains it.
fn file_offset_of(headers: &[ProgramHeader], vaddr: u64) -> Option<usize> {
    headers.iter().find_map(|header| {
        if header.kind != PT_LOAD {
            return None;
        }
        let end = header.vaddr.checked_add(header.size as u64)?;
        if (header.vaddr..end).contains(&vaddr) {
            index(header.offset as u64 + (vaddr - header.vaddr))
        } else {
            None
        }
    })
}

/// The GNU build-id of ELF `data` as lowercase hex, or `None` when it has none.
#[must_use]
pub fn build_id(data: &[u8]) -> Option<String> {
    let layout = layout(data)?;
    if layout.phentsize < if layout.is_64 { 56 } else { 32 } {
        return None;
    }
    for i in 0..layout.phnum.min(MAX_PROGRAM_HEADERS) {
        let at = layout.phoff.checked_add(i.checked_mul(layout.phentsize)?)?;
        // Reject an out-of-file table before fixed-offset field reads (at + 32, etc.).
        if at.checked_add(layout.phentsize)? > data.len() {
            return None;
        }
        let header = program_header(data, at, layout.is_64)?;
        if header.kind != PT_NOTE {
            continue;
        }
        let end = header.offset.checked_add(header.size)?;
        if end > data.len() {
            continue;
        }
        if let Some(id) = build_id_in_notes(&data[header.offset..end]) {
            return Some(id);
        }
    }
    None
}

/// Scans a note segment for the GNU build-id note. Each note is `namesz`, `descsz`, `type`, then
/// the name and the descriptor, each padded to four bytes.
fn build_id_in_notes(notes: &[u8]) -> Option<String> {
    let mut at = 0;
    while at + 12 <= notes.len() {
        let namesz = index(u32_le(notes, at)?.into())?;
        let descsz = index(u32_le(notes, at + 4)?.into())?;
        let kind = u32_le(notes, at + 8)?;
        let name_at = at + 12;
        let name_end = name_at.checked_add(namesz)?;
        let desc_at = name_end.checked_add((4 - namesz % 4) % 4)?;
        let desc_end = desc_at.checked_add(descsz)?;
        if desc_end > notes.len() {
            return None;
        }
        if kind == NT_GNU_BUILD_ID
            && notes.get(name_at..name_end) == Some(b"GNU\0")
            && (1..=MAX_BUILD_ID_BYTES).contains(&descsz)
        {
            return Some(hex(&notes[desc_at..desc_end]));
        }
        at = desc_end.checked_add((4 - descsz % 4) % 4)?;
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// What the dynamic section declares: the library's own `SONAME` (when it records one) and the
/// shared libraries it links against (`DT_NEEDED`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Dynamic {
    pub soname: Option<String>,
    pub needed: Vec<String>,
}

impl Dynamic {
    fn is_empty(&self) -> bool {
        self.soname.is_none() && self.needed.is_empty()
    }
}

/// The size of one dynamic-array entry (`d_tag`, `d_un`), by ELF class.
fn dynamic_entry_size(is_64: bool) -> usize {
    if is_64 { 16 } else { 8 }
}

/// Reads one dynamic-array entry (`d_tag`, `d_un`) at `at`, by ELF class.
fn dynamic_entry(data: &[u8], at: usize, is_64: bool) -> Option<(u64, u64)> {
    if is_64 {
        Some((u64_le(data, at)?, u64_le(data, at + 8)?))
    } else {
        Some((u32_le(data, at)?.into(), u32_le(data, at + 4)?.into()))
    }
}

/// Reads a NUL-terminated name at `offset` into the string table `[strtab, strtab+strsz)`, refusing
/// an empty or over-long name or one running past the table or the file.
fn name_at(data: &[u8], strtab: usize, strsz: usize, offset: u64) -> Option<String> {
    let start = strtab.checked_add(index(offset)?)?;
    // A present DT_STRSZ bounds the table; without it, fall back to the end of the file.
    let table_end = if strsz == 0 {
        data.len()
    } else {
        strtab.checked_add(strsz)?.min(data.len())
    };
    let bytes = data.get(start..table_end)?;
    let end = bytes.iter().position(|&b| b == 0)?;
    if end == 0 || end > MAX_LIB_NAME_BYTES {
        return None;
    }
    // A library name is printable ASCII; anything else means we are not reading a real name.
    let name = bytes.get(..end)?;
    if !name.iter().all(|&b| b.is_ascii_graphic()) {
        return None;
    }
    String::from_utf8(name.to_vec()).ok()
}

/// The `SONAME` and `DT_NEEDED` list `data` declares, or `None` when it has no dynamic section.
#[must_use]
pub fn dynamic(data: &[u8]) -> Option<Dynamic> {
    let layout = layout(data)?;
    if layout.phentsize < if layout.is_64 { 56 } else { 32 } {
        return None;
    }
    let headers = program_headers(data, &layout);
    let segment = headers.iter().find(|h| h.kind == PT_DYNAMIC)?;
    let entry_size = dynamic_entry_size(layout.is_64);
    let count = (segment.size / entry_size).min(MAX_DYNAMIC_ENTRIES);

    // First pass: locate the string table (referenced by virtual address) and its size.
    let mut strtab_vaddr = None;
    let mut strsz = 0usize;
    for i in 0..count {
        let (tag, value) = dynamic_entry(data, segment.offset + i * entry_size, layout.is_64)?;
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab_vaddr = Some(value),
            DT_STRSZ => strsz = index(value).unwrap_or(0),
            _ => {}
        }
    }
    let strtab = file_offset_of(&headers, strtab_vaddr?)?;

    // Second pass: resolve the SONAME and the needed libraries against that table.
    let mut dynamic = Dynamic::default();
    for i in 0..count {
        let (tag, value) = dynamic_entry(data, segment.offset + i * entry_size, layout.is_64)?;
        match tag {
            DT_NULL => break,
            DT_SONAME => dynamic.soname = name_at(data, strtab, strsz, value),
            DT_NEEDED if dynamic.needed.len() < MAX_NEEDED => {
                if let Some(name) = name_at(data, strtab, strsz, value) {
                    dynamic.needed.push(name);
                }
            }
            _ => {}
        }
    }
    if dynamic.is_empty() {
        None
    } else {
        Some(dynamic)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A minimal little-endian ELF (64- or 32-bit) with one `PT_NOTE` segment carrying a GNU
    /// build-id note. Enough for `build_id`, not a loadable library.
    pub(crate) fn elf_with_build_id(is_64: bool, id: &[u8]) -> Vec<u8> {
        fn note(id: &[u8]) -> Vec<u8> {
            let mut note = Vec::new();
            note.extend_from_slice(&4_u32.to_le_bytes()); // namesz "GNU\0"
            note.extend_from_slice(&u32::try_from(id.len()).unwrap().to_le_bytes());
            note.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
            note.extend_from_slice(b"GNU\0");
            note.extend_from_slice(id);
            while note.len() % 4 != 0 {
                note.push(0);
            }
            note
        }
        let note = note(id);
        if is_64 {
            let ehsize = 64;
            let phentsize = 56;
            let note_off = ehsize + phentsize;
            let mut out = vec![0_u8; note_off];
            out[..4].copy_from_slice(b"\x7fELF");
            out[4] = 2; // ELFCLASS64
            out[5] = 1; // little-endian
            out[6] = 1;
            out[32..40].copy_from_slice(&(ehsize as u64).to_le_bytes()); // e_phoff
            out[54..56].copy_from_slice(&u16::try_from(phentsize).unwrap().to_le_bytes());
            out[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum
            // Program header at ehsize.
            out[ehsize..ehsize + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
            out[ehsize + 8..ehsize + 16].copy_from_slice(&(note_off as u64).to_le_bytes());
            out[ehsize + 32..ehsize + 40]
                .copy_from_slice(&u64::try_from(note.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&note);
            out
        } else {
            let ehsize = 52;
            let phentsize = 32;
            let note_off = ehsize + phentsize;
            let mut out = vec![0_u8; note_off];
            out[..4].copy_from_slice(b"\x7fELF");
            out[4] = 1; // ELFCLASS32
            out[5] = 1;
            out[6] = 1;
            out[28..32].copy_from_slice(&u32::try_from(ehsize).unwrap().to_le_bytes()); // e_phoff
            out[42..44].copy_from_slice(&u16::try_from(phentsize).unwrap().to_le_bytes());
            out[44..46].copy_from_slice(&1_u16.to_le_bytes());
            out[ehsize..ehsize + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
            out[ehsize + 4..ehsize + 8]
                .copy_from_slice(&u32::try_from(note_off).unwrap().to_le_bytes());
            out[ehsize + 16..ehsize + 20]
                .copy_from_slice(&u32::try_from(note.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&note);
            out
        }
    }

    #[test]
    fn the_build_id_is_read_from_a_64_and_a_32_bit_elf_note() {
        let id = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67];
        assert_eq!(
            build_id(&elf_with_build_id(true, &id)).as_deref(),
            Some("deadbeef01234567")
        );
        assert_eq!(
            build_id(&elf_with_build_id(false, &id)).as_deref(),
            Some("deadbeef01234567")
        );
    }

    #[test]
    fn a_non_elf_or_build_idless_file_yields_none() {
        assert!(build_id(b"PK\x03\x04 not elf").is_none());
        assert!(build_id(b"").is_none());
        // A big-endian ELF (byte 5 == 2) is refused rather than misread.
        let mut big = elf_with_build_id(true, &[1, 2, 3, 4]);
        big[5] = 2;
        assert!(build_id(&big).is_none());
        // Truncation anywhere yields None, never a partial id.
        let whole = elf_with_build_id(true, &[1, 2, 3, 4, 5, 6]);
        for cut in [4, 40, whole.len() - 1] {
            assert!(build_id(&whole[..cut]).is_none(), "cut at {cut}");
        }
    }

    #[test]
    fn adversarial_program_header_offset_does_not_overflow() {
        let mut elf = elf_with_build_id(true, &[1, 2, 3, 4]);
        // The untrusted e_phoff must not reach unchecked fixed-offset reads.
        elf[32..40].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        assert!(build_id(&elf).is_none());
    }

    #[test]
    fn identical_build_ids_do_not_prove_identical_library_bytes() {
        let first = elf_with_build_id(true, &[0xca, 0xfe, 0xba, 0xbe]);
        let mut second = first.clone();
        second.push(0xff);
        assert_eq!(build_id(&first), build_id(&second));
        assert_ne!(
            crate::sha256::sha256(&first),
            crate::sha256::sha256(&second)
        );
    }

    #[test]
    fn a_lying_note_length_cannot_read_past_the_segment() {
        let mut elf = elf_with_build_id(true, &[1, 2, 3, 4]);
        // Blow up the note's descsz; the bounds check must refuse it.
        let note_off = 64 + 56;
        elf[note_off + 4..note_off + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(build_id(&elf).is_none());
    }

    /// A minimal little-endian ELF (64- or 32-bit) with a `PT_LOAD` segment that maps the whole
    /// file at virtual address 0 (so a virtual address equals its file offset) and a `PT_DYNAMIC`
    /// segment declaring the given `SONAME` and needed libraries against an embedded string table.
    pub(crate) fn elf_with_dynamic(is_64: bool, soname: Option<&str>, needed: &[&str]) -> Vec<u8> {
        let le16 = |v: usize| u16::try_from(v).unwrap().to_le_bytes();
        let le32 = |v: usize| u32::try_from(v).unwrap().to_le_bytes();
        let le64 = |v: usize| (v as u64).to_le_bytes();

        let (ehsize, phentsize, entry_size) = if is_64 { (64, 56, 16) } else { (52, 32, 8) };
        let phnum = 2;
        let phoff = ehsize;
        let strtab_off = phoff + phnum * phentsize;

        // String table: index 0 is NUL, then each name NUL-terminated. Record each name's offset.
        let mut strtab = vec![0_u8];
        let mut intern = |name: &str| {
            let at = strtab.len();
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            at
        };
        let soname_off = soname.map(&mut intern);
        let needed_offs: Vec<usize> = needed.iter().map(|n| intern(n)).collect();
        let strsz = strtab.len();

        // Dynamic array: SONAME, each NEEDED, then the string table's location and size, then NULL.
        let mut entries: Vec<(u64, u64)> = Vec::new();
        if let Some(off) = soname_off {
            entries.push((DT_SONAME, off as u64));
        }
        for off in &needed_offs {
            entries.push((DT_NEEDED, *off as u64));
        }
        entries.push((DT_STRTAB, strtab_off as u64)); // vaddr == file offset via the PT_LOAD below
        entries.push((DT_STRSZ, strsz as u64));
        entries.push((DT_NULL, 0));

        let dyn_off = strtab_off + strsz;
        let dyn_len = entries.len() * entry_size;
        let total = dyn_off + dyn_len;

        let mut out = vec![0_u8; total];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = if is_64 { 2 } else { 1 };
        out[5] = 1; // little-endian
        out[6] = 1;
        let (load, dynamic) = (phoff, phoff + phentsize);
        if is_64 {
            out[32..40].copy_from_slice(&le64(phoff));
            out[54..56].copy_from_slice(&le16(phentsize));
            out[56..58].copy_from_slice(&le16(phnum));
            // PT_LOAD: offset 0, vaddr 0, filesz = whole file.
            out[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            out[load + 32..load + 40].copy_from_slice(&le64(total));
            // PT_DYNAMIC: offset == vaddr == dyn_off.
            out[dynamic..dynamic + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
            out[dynamic + 8..dynamic + 16].copy_from_slice(&le64(dyn_off));
            out[dynamic + 16..dynamic + 24].copy_from_slice(&le64(dyn_off));
            out[dynamic + 32..dynamic + 40].copy_from_slice(&le64(dyn_len));
        } else {
            out[28..32].copy_from_slice(&le32(phoff));
            out[42..44].copy_from_slice(&le16(phentsize));
            out[44..46].copy_from_slice(&le16(phnum));
            out[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            out[load + 16..load + 20].copy_from_slice(&le32(total));
            out[dynamic..dynamic + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
            out[dynamic + 4..dynamic + 8].copy_from_slice(&le32(dyn_off));
            out[dynamic + 8..dynamic + 12].copy_from_slice(&le32(dyn_off));
            out[dynamic + 16..dynamic + 20].copy_from_slice(&le32(dyn_len));
        }
        out[strtab_off..strtab_off + strsz].copy_from_slice(&strtab);
        for (i, (tag, val)) in entries.iter().enumerate() {
            let at = dyn_off + i * entry_size;
            if is_64 {
                out[at..at + 8].copy_from_slice(&tag.to_le_bytes());
                out[at + 8..at + 16].copy_from_slice(&val.to_le_bytes());
            } else {
                out[at..at + 4].copy_from_slice(&u32::try_from(*tag).unwrap().to_le_bytes());
                out[at + 4..at + 8].copy_from_slice(&u32::try_from(*val).unwrap().to_le_bytes());
            }
        }
        out
    }

    #[test]
    fn the_soname_and_needed_libraries_are_read_from_a_64_and_a_32_bit_dynamic_section() {
        for is_64 in [true, false] {
            let elf = elf_with_dynamic(is_64, Some("libfield.so"), &["libflutter.so", "libc.so"]);
            let dynamic = dynamic(&elf).expect("dynamic section");
            assert_eq!(dynamic.soname.as_deref(), Some("libfield.so"), "64={is_64}");
            assert_eq!(dynamic.needed, ["libflutter.so", "libc.so"], "64={is_64}");
        }
    }

    #[test]
    fn a_library_without_a_dynamic_section_or_names_yields_none() {
        // The build-id fixture has a PT_NOTE but no PT_DYNAMIC.
        assert!(dynamic(&elf_with_build_id(true, &[1, 2, 3, 4])).is_none());
        // A dynamic section declaring neither a SONAME nor any NEEDED yields None, not an empty set.
        assert!(dynamic(&elf_with_dynamic(true, None, &[])).is_none());
        assert!(dynamic(b"PK\x03\x04 not elf").is_none());
    }

    #[test]
    fn a_needed_offset_past_the_string_table_is_refused_not_misread() {
        let mut elf = elf_with_dynamic(true, Some("libfield.so"), &["libflutter.so"]);
        // The first dynamic entry is DT_SONAME; overwrite its value with an offset past the table.
        let dyn_off = {
            let layout = layout(&elf).unwrap();
            program_headers(&elf, &layout)
                .into_iter()
                .find(|h| h.kind == PT_DYNAMIC)
                .unwrap()
                .offset
        };
        elf[dyn_off + 8..dyn_off + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        let dynamic = dynamic(&elf).expect("still reads the needed library");
        assert_eq!(dynamic.soname, None, "the out-of-range SONAME is dropped");
        assert_eq!(dynamic.needed, ["libflutter.so"]);
    }
}
