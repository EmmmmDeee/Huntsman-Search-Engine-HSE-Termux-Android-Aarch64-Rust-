//! The GNU build-id of a native library (`lib/*/*.so`), read from its ELF note without loading or
//! executing it. The build-id is a hash the linker stamps into the binary (`--build-id`, on by
//! default in the Android NDK). It is a useful cross-APK candidate pivot, not proof of identical
//! bytes, provenance, authorship, or a shared build: build-id bytes may be supplied or forged.
//!
//! Only the ELF header and the program headers are read, and the build-id note sits at a direct
//! file offset, so no virtual-address mapping is needed. Every offset is bounds-checked; a file
//! that is not a little-endian ELF, or whose headers do not fit, yields `None`.

/// `PT_NOTE`: a program header describing a note segment.
const PT_NOTE: u32 = 4;
/// `NT_GNU_BUILD_ID`: the note type the build-id uses, under the name `GNU`.
const NT_GNU_BUILD_ID: u32 = 3;
/// A build-id longer than this (far beyond SHA-256) is ignored as malformed.
const MAX_BUILD_ID_BYTES: usize = 64;
/// Program headers past this count are not walked; a real `.so` has a handful.
const MAX_PROGRAM_HEADERS: usize = 256;

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

/// One program header's type and the file range of its contents, read for the ELF class.
struct ProgramHeader {
    kind: u32,
    offset: usize,
    size: usize,
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
            size: index(u64_le(data, at + 32)?)?,
        })
    } else {
        Some(ProgramHeader {
            kind: u32_le(data, at)?,
            offset: index(u32_le(data, at + 4)?.into())?,
            size: index(u32_le(data, at + 16)?.into())?,
        })
    }
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
}
