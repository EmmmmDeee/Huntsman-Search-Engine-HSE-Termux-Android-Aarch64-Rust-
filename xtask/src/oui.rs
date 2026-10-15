//! The IEEE MA-L registry, packed for `huntsman_recon::oui_ieee`. `oui pack` builds
//! `src/oui_ieee.bin` from the registry's CSV (<https://standards-oui.ieee.org/oui/oui.csv>) and
//! `oui dump` lists a blob's assignments, so a refresh is one command and two blobs can be diffed.
//!
//! The layout, little-endian throughout: the magic `HSEOUI\x01\x00`; the assignment count and the
//! vendor count, each a u32; the 24-bit prefixes as u32, strictly ascending; one u16 vendor index
//! per prefix; zero padding to a multiple of four; `vendor_count + 1` u32 byte offsets into the
//! name blob; the UTF-8 names, concatenated. A vendor is numbered when its first prefix is
//! reached, so the same assignments always pack to the same bytes, and `xtask/tests/oui_pack.rs`
//! proves the committed blob is what `pack` makes of its own `dump`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use crate::error::{self, Error, Result};

const USAGE: &str = "usage: cargo run --locked -p xtask -- oui <pack CSV OUT|dump BIN>

  pack CSV OUT   pack the IEEE MA-L registry CSV (https://standards-oui.ieee.org/oui/oui.csv)
                 into OUT, the blob src/oui_ieee.bin embeds; the first of duplicate
                 assignments is kept and each duplicate is reported
  dump BIN       print a blob's assignments, one `PREFIX<TAB>VENDOR` line each, prefix in hex";

const MAGIC: &[u8; 8] = b"HSEOUI\x01\x00";
const HEADER: usize = 16;
/// The registry the file holds; 28- and 36-bit blocks come in other files and do not fit a prefix.
const REGISTRY: &str = "MA-L";
const COLUMNS: [&str; 3] = ["Registry", "Assignment", "Organization Name"];

/// One assignment: a 24-bit prefix and the organisation it is assigned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub prefix: u32,
    pub vendor: String,
}

/// The assignments of a registry CSV, ascending by prefix, and a notice for each duplicate
/// assignment, of which the first in the file is kept (on 2026-10-14 the file listed three
/// organisations for `080030`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub assignments: Vec<Assignment>,
    pub notices: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let outcome = match args {
        [command, csv, out] if command == "pack" => pack_file(Path::new(csv), Path::new(out)),
        [command, bin] if command == "dump" => dump_file(Path::new(bin)),
        _ => return error::usage(USAGE),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => error::report("xtask oui", &problem),
    }
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn pack_file(csv: &Path, out: &Path) -> Result<()> {
    let text = String::from_utf8(read(csv)?)
        .map_err(|_| Error::Invalid(format!("{}: not UTF-8", csv.display())))?;
    let parsed = assignments_from_csv(&text)?;
    for notice in &parsed.notices {
        eprintln!("xtask oui: {notice}");
    }
    let blob = pack(&parsed.assignments)?;
    fs::write(out, &blob).map_err(|source| Error::Io {
        path: out.to_path_buf(),
        source,
    })?;
    println!(
        "{}: {} assignments, {} vendors, {} bytes",
        out.display(),
        parsed.assignments.len(),
        vendor_count(&parsed.assignments),
        blob.len()
    );
    Ok(())
}

fn dump_file(bin: &Path) -> Result<()> {
    let mut listing = String::new();
    for assignment in decode(&read(bin)?)? {
        let _ = writeln!(listing, "{:06X}\t{}", assignment.prefix, assignment.vendor);
    }
    print!("{listing}");
    Ok(())
}

fn vendor_count(assignments: &[Assignment]) -> usize {
    assignments
        .iter()
        .map(|assignment| assignment.vendor.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

/// Reads the registry CSV: a byte-order mark and `\r\n` line ends are accepted, a quoted field
/// may hold commas, doubled quotes and line breaks, names are trimmed, and every row must be an
/// MA-L assignment of six hex digits to a non-empty organisation.
pub fn assignments_from_csv(text: &str) -> Result<Parsed> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut records = csv_records(text).into_iter();
    let header = records
        .next()
        .ok_or_else(|| Error::Invalid("the CSV is empty".to_string()))?;
    let columns: Vec<&str> = header
        .iter()
        .take(COLUMNS.len())
        .map(String::as_str)
        .collect();
    if columns != COLUMNS {
        return Err(Error::Invalid(format!(
            "the CSV must start with the columns {}; found {}",
            COLUMNS.join(","),
            header.join(",")
        )));
    }
    let mut assignments = Vec::new();
    for (index, record) in records.enumerate() {
        let line = index + 2;
        if record.iter().all(String::is_empty) {
            continue;
        }
        let [registry, hex, name, ..] = record.as_slice() else {
            return Err(Error::Invalid(format!(
                "line {line}: expected at least {} columns",
                COLUMNS.len()
            )));
        };
        if registry != REGISTRY {
            return Err(Error::Invalid(format!(
                "line {line}: registry {registry:?} is not {REGISTRY}; only the MA-L file packs"
            )));
        }
        let prefix = parse_prefix(hex).ok_or_else(|| {
            Error::Invalid(format!(
                "line {line}: assignment {hex:?} is not six hex digits"
            ))
        })?;
        let vendor = name.trim();
        if vendor.is_empty() {
            return Err(Error::Invalid(format!(
                "line {line}: the organisation name is empty"
            )));
        }
        assignments.push(Assignment {
            prefix,
            vendor: vendor.to_string(),
        });
    }
    Ok(first_of_each_prefix(assignments))
}

fn parse_prefix(hex: &str) -> Option<u32> {
    if hex.len() != 6 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(hex, 16).ok()
}

/// Sorts by prefix (a stable sort, so file order holds among equal prefixes) and keeps the first
/// of each prefix, naming the others in the notices.
fn first_of_each_prefix(mut assignments: Vec<Assignment>) -> Parsed {
    assignments.sort_by_key(|assignment| assignment.prefix);
    let mut parsed = Parsed::default();
    for assignment in assignments {
        match parsed.assignments.last() {
            Some(kept) if kept.prefix == assignment.prefix => parsed.notices.push(format!(
                "{:06X} is assigned again to {:?}; keeping {:?}",
                assignment.prefix, assignment.vendor, kept.vendor
            )),
            _ => parsed.assignments.push(assignment),
        }
    }
    parsed
}

/// RFC 4180 records: fields end at a comma, a record at a line break outside quotes (`\r\n` or
/// `\n`), and a field that starts with a quote runs to the next lone quote, with `""` for one
/// quote. A final record without a line break counts.
fn csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

/// Packs assignments, which must ascend strictly by 24-bit prefix, into the blob layout.
pub fn pack(assignments: &[Assignment]) -> Result<Vec<u8>> {
    let mut vendors: Vec<&str> = Vec::new();
    let mut index_of: HashMap<&str, u16> = HashMap::new();
    let mut vendor_indices: Vec<u16> = Vec::with_capacity(assignments.len());
    for (position, assignment) in assignments.iter().enumerate() {
        if assignment.prefix > 0x00FF_FFFF {
            return Err(Error::Invalid(format!(
                "{:X} is wider than 24 bits",
                assignment.prefix
            )));
        }
        if position > 0 && assignments[position - 1].prefix >= assignment.prefix {
            return Err(Error::Invalid(format!(
                "assignments must ascend: {:06X} follows {:06X}",
                assignment.prefix,
                assignments[position - 1].prefix
            )));
        }
        let index = match index_of.get(assignment.vendor.as_str()) {
            Some(&index) => index,
            None => {
                let index = u16::try_from(vendors.len())
                    .map_err(|_| Error::Invalid("more than 65,536 vendors".to_string()))?;
                vendors.push(assignment.vendor.as_str());
                index_of.insert(assignment.vendor.as_str(), index);
                index
            }
        };
        vendor_indices.push(index);
    }
    let count = u32::try_from(assignments.len())
        .map_err(|_| Error::Invalid("more than 4,294,967,295 assignments".to_string()))?;
    let vendor_count = u32::try_from(vendors.len())
        .map_err(|_| Error::Invalid("more than 65,536 vendors".to_string()))?;

    let mut out = Vec::with_capacity(HEADER + assignments.len() * 6 + vendors.len() * 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&vendor_count.to_le_bytes());
    for assignment in assignments {
        out.extend_from_slice(&assignment.prefix.to_le_bytes());
    }
    for index in &vendor_indices {
        out.extend_from_slice(&index.to_le_bytes());
    }
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let mut offset: u32 = 0;
    out.extend_from_slice(&offset.to_le_bytes());
    for vendor in &vendors {
        offset = u32::try_from(vendor.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .ok_or_else(|| Error::Invalid("the vendor names exceed 4 GiB".to_string()))?;
        out.extend_from_slice(&offset.to_le_bytes());
    }
    for vendor in &vendors {
        out.extend_from_slice(vendor.as_bytes());
    }
    Ok(out)
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

/// Reads a blob back into its assignments, refusing one whose tables or names do not fit.
pub fn decode(bytes: &[u8]) -> Result<Vec<Assignment>> {
    let invalid = |what: &str| Error::Invalid(format!("not an OUI blob: {what}"));
    if bytes.len() < HEADER || &bytes[..MAGIC.len()] != MAGIC {
        return Err(invalid("the magic is missing"));
    }
    let count = usize::try_from(le_u32(bytes, 8).unwrap_or(0)).map_err(|_| invalid("count"))?;
    let vendor_count =
        usize::try_from(le_u32(bytes, 12).unwrap_or(0)).map_err(|_| invalid("vendor count"))?;
    let prefixes_at = HEADER;
    let vendor_indices_at = prefixes_at + count * 4;
    let unpadded = vendor_indices_at + count * 2;
    let offsets_at = unpadded + (4 - unpadded % 4) % 4;
    let blob_at = offsets_at + (vendor_count + 1) * 4;
    if blob_at > bytes.len() {
        return Err(invalid("the tables run past the end"));
    }
    let offset = |vendor: usize| -> Result<usize> {
        let at = le_u32(bytes, offsets_at + vendor * 4).ok_or_else(|| invalid("offset"))?;
        usize::try_from(at).map_err(|_| invalid("offset"))
    };
    let mut vendors: Vec<&str> = Vec::with_capacity(vendor_count);
    for vendor in 0..vendor_count {
        let (start, end) = (offset(vendor)?, offset(vendor + 1)?);
        let name = (start <= end)
            .then(|| bytes.get(blob_at + start..blob_at + end))
            .flatten()
            .ok_or_else(|| invalid("a name lies outside the blob"))?;
        vendors.push(std::str::from_utf8(name).map_err(|_| invalid("a name is not UTF-8"))?);
    }
    if blob_at + offset(vendor_count)? != bytes.len() {
        return Err(invalid("bytes follow the last name"));
    }
    let mut assignments = Vec::with_capacity(count);
    for position in 0..count {
        let prefix = le_u32(bytes, prefixes_at + position * 4).ok_or_else(|| invalid("prefix"))?;
        let vendor = le_u16(bytes, vendor_indices_at + position * 2)
            .and_then(|index| vendors.get(usize::from(index)))
            .ok_or_else(|| invalid("a vendor index is out of range"))?;
        assignments.push(Assignment {
            prefix,
            vendor: (*vendor).to_string(),
        });
    }
    Ok(assignments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment(prefix: u32, vendor: &str) -> Assignment {
        Assignment {
            prefix,
            vendor: vendor.to_string(),
        }
    }

    #[test]
    fn the_registry_csv_is_read_with_its_quoting_line_ends_and_duplicates() {
        let csv = "\u{feff}Registry,Assignment,Organization Name,Organization Address\r\n\
                   MA-L,38E2CA,Katun Corporation,7760 France Ave S Bloomington MN US \r\n\
                   MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road,\r\nShanghai\"\r\n\
                   MA-L,000000,XEROX CORPORATION  ,\r\n\
                   MA-L,0001C8,THOMAS CONRAD CORP.,\r\n\
                   MA-L,0001C8,CONRAD CORP.,\r\n\
                   MA-L,0001C9,\"Say \"\"hi\"\", Inc.\",\r\n\
                   \r\n";
        let parsed = assignments_from_csv(csv).unwrap();
        assert_eq!(
            parsed.assignments,
            vec![
                assignment(0x000000, "XEROX CORPORATION"),
                assignment(0x0001C8, "THOMAS CONRAD CORP."),
                assignment(0x0001C9, "Say \"hi\", Inc."),
                assignment(0x286FB9, "Nokia Shanghai Bell Co., Ltd."),
                assignment(0x38E2CA, "Katun Corporation"),
            ]
        );
        assert_eq!(
            parsed.notices,
            vec!["0001C8 is assigned again to \"CONRAD CORP.\"; keeping \"THOMAS CONRAD CORP.\""]
        );
    }

    #[test]
    fn a_csv_that_is_not_the_mal_registry_is_refused_with_its_line() {
        let header = "Registry,Assignment,Organization Name,Organization Address\n";
        for (body, expected) in [
            (
                "MA-M,38E2CA0,Katun,\n",
                "line 2: registry \"MA-M\" is not MA-L",
            ),
            (
                "MA-L,38E2C,Katun,\n",
                "line 2: assignment \"38E2C\" is not six hex digits",
            ),
            (
                "MA-L,38E2CG,Katun,\n",
                "line 2: assignment \"38E2CG\" is not six hex digits",
            ),
            (
                "MA-L,38E2CA,   ,\n",
                "line 2: the organisation name is empty",
            ),
            (
                "MA-L,38E2CA,Katun,\nMA-L\n",
                "line 3: expected at least 3 columns",
            ),
        ] {
            let error = assignments_from_csv(&format!("{header}{body}")).unwrap_err();
            assert!(error.to_string().starts_with(expected), "{body:?}: {error}");
        }
        let error = assignments_from_csv("Assignment,Organization Name\n").unwrap_err();
        assert!(
            error.to_string().contains("must start with the columns"),
            "{error}"
        );
        assert!(assignments_from_csv("").is_err());
    }

    #[test]
    fn pack_lays_out_the_tables_the_reader_expects_and_decode_reads_them_back() {
        let assignments = vec![
            assignment(0x000000, "XEROX"),
            assignment(0x000001, "XEROX"),
            assignment(0x0001C8, "Prüftechnik"),
        ];
        let blob = pack(&assignments).unwrap();
        assert_eq!(&blob[..8], MAGIC);
        assert_eq!(le_u32(&blob, 8), Some(3), "assignment count");
        assert_eq!(le_u32(&blob, 12), Some(2), "vendor count");
        assert_eq!(&blob[16..28], &[0, 0, 0, 0, 1, 0, 0, 0, 0xC8, 1, 0, 0]);
        assert_eq!(
            &blob[28..34],
            &[0, 0, 0, 0, 1, 0],
            "vendor indices, first use first"
        );
        assert_eq!(&blob[34..36], &[0, 0], "padded to four");
        assert_eq!(
            &blob[36..48],
            &[0, 0, 0, 0, 5, 0, 0, 0, 17, 0, 0, 0],
            "name offsets"
        );
        assert_eq!(&blob[48..], "XEROXPrüftechnik".as_bytes());
        assert_eq!(decode(&blob).unwrap(), assignments);

        let even = pack(&assignments[..2]).unwrap();
        assert_eq!(
            even.len(),
            16 + 8 + 4 + 8 + 5,
            "an even count needs no padding"
        );
        assert_eq!(
            &even[28..36],
            &[0, 0, 0, 0, 5, 0, 0, 0],
            "offsets follow the indices"
        );
        assert_eq!(decode(&even).unwrap(), assignments[..2]);
        assert_eq!(decode(&pack(&[]).unwrap()).unwrap(), []);
    }

    #[test]
    fn pack_refuses_what_the_reader_could_not_search() {
        let unsorted = [assignment(2, "a"), assignment(1, "b")];
        assert!(
            pack(&unsorted)
                .unwrap_err()
                .to_string()
                .contains("must ascend")
        );
        let repeated = [assignment(1, "a"), assignment(1, "b")];
        assert!(
            pack(&repeated)
                .unwrap_err()
                .to_string()
                .contains("must ascend")
        );
        let wide = [assignment(0x0100_0000, "a")];
        assert!(pack(&wide).unwrap_err().to_string().contains("24 bits"));
    }

    #[test]
    fn decode_refuses_a_blob_whose_tables_or_names_do_not_fit() {
        let blob = pack(&[assignment(1, "a")]).unwrap();
        assert!(decode(b"HSEOUI\x01\x00").is_err(), "short");
        assert!(decode(b"NOTOUI\x01\x00\0\0\0\0\0\0\0\0").is_err(), "magic");
        assert!(decode(&blob[..blob.len() - 1]).is_err(), "truncated name");
        let mut trailing = blob.clone();
        trailing.push(b'x');
        assert!(decode(&trailing).is_err(), "trailing bytes");
        let mut index = blob.clone();
        index[20] = 7;
        assert!(decode(&index).is_err(), "vendor index out of range");
        let mut huge = blob;
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&huge).is_err(), "count past the end");
    }
}
