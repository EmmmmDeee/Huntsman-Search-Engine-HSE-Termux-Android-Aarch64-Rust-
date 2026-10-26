//! Excel workbooks (`.xlsx`) with no dependency: Office Open XML parts in a stored ZIP.
//!
//! Spiderfoot exports a scan as a workbook with one sheet per data type. [`workbook`] writes
//! that, and keeps every value whole. Each cell is an inline string, so a value is never read as
//! a formula and needs no guard. A character XML cannot carry is written as Excel's own `_xHHHH_`
//! escape rather than dropped. Text longer than a cell holds carries on, in order, in the cells
//! after the row's last value, so the columns stay aligned. The ZIP is stored (not compressed),
//! which every spreadsheet reads and needs no deflate code, and the same sheets always make the
//! same bytes.

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// The most characters (UTF-16 code units, as Excel counts them) one cell holds.
pub const MAX_CELL_UNITS: usize = 32_767;

/// The longest sheet name Excel accepts.
pub const MAX_SHEET_NAME_CHARS: usize = 31;

/// The media type of a workbook.
pub const CONTENT_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

/// One worksheet: a name and its rows, the first usually the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sheet {
    pub name: String,
    pub rows: Vec<Vec<String>>,
}

/// A name Excel accepts for a sheet: none of `[]:*?/\` nor a character XML cannot carry, not
/// blank, not starting or ending with an apostrophe, at most [`MAX_SHEET_NAME_CHARS`] characters,
/// and unlike every name in `taken` (Excel compares them without case), numbered ` (2)`, ` (3)`,
/// ... when it would repeat one.
fn sheet_name(wanted: &str, taken: &mut BTreeSet<String>) -> String {
    let clean: String = wanted
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '[' | ']' | ':' | '*' | '?' | '/' | '\\' | '\u{fffe}' | '\u{ffff}'
            ) && !c.is_control()
        })
        .collect();
    let clean = clean.trim().trim_matches('\'');
    let cut: String = clean.chars().take(MAX_SHEET_NAME_CHARS).collect();
    let cut = cut.trim_end_matches(|c: char| c == '\'' || c.is_whitespace());
    let base = if cut.is_empty() { "Sheet" } else { cut }.to_owned();
    let mut name = base.clone();
    let mut number = 2;
    while !taken.insert(name.to_lowercase()) {
        let suffix = format!(" ({number})");
        let room = MAX_SHEET_NAME_CHARS - suffix.chars().count();
        name = base
            .chars()
            .take(room)
            .collect::<String>()
            .trim_end()
            .to_owned()
            + &suffix;
        number += 1;
    }
    name
}

/// `A`, `B`, ... `Z`, `AA`, ... for a zero-based column.
fn column(mut index: usize) -> String {
    let mut name = Vec::new();
    loop {
        name.push(char::from(b'A' + u8::try_from(index % 26).unwrap_or(0)));
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    name.iter().rev().collect()
}

/// A value as the cells it fills: one, or several of at most [`MAX_CELL_UNITS`] when longer.
fn pieces(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut units) = (0, 0);
    for (at, c) in value.char_indices() {
        if units + c.len_utf16() > MAX_CELL_UNITS {
            out.push(&value[start..at]);
            (start, units) = (at, 0);
        }
        units += c.len_utf16();
    }
    out.push(&value[start..]);
    out
}

/// Whether `rest` starts with text Excel would decode as an escape: `_x` then four hex digits
/// then `_`.
fn looks_escaped(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    bytes.len() >= 7
        && bytes[1] == b'x'
        && bytes[2..6].iter().all(u8::is_ascii_hexdigit)
        && bytes[6] == b'_'
}

/// Cell text as XML that Excel reads back as the same text: markup escaped; a character XML 1.0
/// cannot carry (a control character other than tab and newline, carriage return so a parser
/// does not fold it, U+FFFE and U+FFFF) written as `_xHHHH_`; and text already shaped like such
/// an escape protected as `_x005F_xHHHH_` so it is not decoded.
fn cell_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for (at, c) in raw.char_indices() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '_' if looks_escaped(&raw[at..]) => out.push_str("_x005F_"),
            '\t' | '\n' => out.push(c),
            c if c < ' ' || matches!(c, '\u{fffe}' | '\u{ffff}') => {
                let _ = write!(out, "_x{:04X}_", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

fn worksheet(rows: &[Vec<String>]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>",
    );
    for (row_index, row) in rows.iter().enumerate() {
        let number = row_index + 1;
        let _ = write!(xml, "<row r=\"{number}\">");
        let mut overflow = Vec::new();
        // Write primary cells directly; only overflow fragments need staging.
        // This avoids an additional allocation proportional to every row's width.
        for (at, value) in row.iter().enumerate() {
            let mut parts = pieces(value).into_iter();
            let first = parts.next().unwrap_or_default();
            overflow.extend(parts);
            let _ = write!(
                xml,
                "<c r=\"{}{number}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
                column(at),
                cell_text(first)
            );
        }
        for (index, value) in overflow.into_iter().enumerate() {
            let _ = write!(
                xml,
                "<c r=\"{}{number}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
                column(row.len() + index),
                cell_text(value)
            );
        }
        xml.push_str("</row>");
    }
    xml.push_str("</sheetData></worksheet>");
    xml
}

/// Text for an XML attribute value.
fn attribute(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const XML_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
const RELATIONSHIPS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const OFFICE: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const SPREADSHEET: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml";

/// A workbook of `sheets`, in order; an empty list still makes a valid workbook of one empty
/// sheet.
#[must_use]
pub fn workbook(sheets: &[Sheet]) -> Vec<u8> {
    let empty = [Sheet {
        name: "Sheet".to_owned(),
        rows: Vec::new(),
    }];
    let sheets = if sheets.is_empty() {
        &empty[..]
    } else {
        sheets
    };
    let mut taken = BTreeSet::new();
    let mut types = format!(
        "{XML_HEAD}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"{SPREADSHEET}.sheet.main+xml\"/>"
    );
    let mut book = format!(
        "{XML_HEAD}<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"{OFFICE}\"><sheets>"
    );
    let mut book_rels = format!("{XML_HEAD}<Relationships xmlns=\"{RELATIONSHIPS}\">");
    let mut parts = Vec::new();
    for (index, sheet) in sheets.iter().enumerate() {
        let number = index + 1;
        let _ = write!(
            types,
            "<Override PartName=\"/xl/worksheets/sheet{number}.xml\" ContentType=\"{SPREADSHEET}.worksheet+xml\"/>"
        );
        let _ = write!(
            book,
            "<sheet name=\"{}\" sheetId=\"{number}\" r:id=\"rId{number}\"/>",
            attribute(&sheet_name(&sheet.name, &mut taken))
        );
        let _ = write!(
            book_rels,
            "<Relationship Id=\"rId{number}\" Type=\"{OFFICE}/worksheet\" Target=\"worksheets/sheet{number}.xml\"/>"
        );
        parts.push((
            format!("xl/worksheets/sheet{number}.xml"),
            worksheet(&sheet.rows).into_bytes(),
        ));
    }
    types.push_str("</Types>");
    book.push_str("</sheets></workbook>");
    book_rels.push_str("</Relationships>");
    let root_rels = format!(
        "{XML_HEAD}<Relationships xmlns=\"{RELATIONSHIPS}\"><Relationship Id=\"rId1\" Type=\"{OFFICE}/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>"
    );
    let mut entries = vec![
        ("[Content_Types].xml".to_owned(), types.into_bytes()),
        ("_rels/.rels".to_owned(), root_rels.into_bytes()),
        ("xl/workbook.xml".to_owned(), book.into_bytes()),
        (
            "xl/_rels/workbook.xml.rels".to_owned(),
            book_rels.into_bytes(),
        ),
    ];
    entries.extend(parts);
    stored_zip(&entries)
}

/// CRC-32 (IEEE 802.3), as ZIP records it.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn u16_le(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u16::try_from(value).unwrap_or(u16::MAX).to_le_bytes());
}

fn u32_le(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u32::try_from(value).unwrap_or(u32::MAX).to_le_bytes());
}

/// 1980-01-01 00:00, the earliest DOS date, so the same workbook is the same bytes.
const DOS_DATE: usize = (1 << 5) | 1;

/// One ZIP header for `name`: the local one before the data, or with `central` the central
/// directory's, which also records where the local one starts.
fn zip_header(out: &mut Vec<u8>, name: &str, data: &[u8], central: Option<usize>) {
    let signature: u32 = if central.is_some() {
        0x0201_4b50
    } else {
        0x0403_4b50
    };
    out.extend_from_slice(&signature.to_le_bytes());
    if central.is_some() {
        u16_le(out, 20); // made by: version 2.0
    }
    u16_le(out, 20); // needed to extract: 2.0
    u16_le(out, 0x0800); // the name is UTF-8
    u16_le(out, 0); // stored
    u16_le(out, 0); // time
    u16_le(out, DOS_DATE);
    out.extend_from_slice(&crc32(data).to_le_bytes());
    u32_le(out, data.len());
    u32_le(out, data.len());
    u16_le(out, name.len());
    u16_le(out, 0); // extra field
    if let Some(offset) = central {
        u16_le(out, 0); // comment
        u16_le(out, 0); // disk
        u16_le(out, 0); // internal attributes
        u32_le(out, 0); // external attributes
        u32_le(out, offset);
    }
    out.extend_from_slice(name.as_bytes());
}

/// A ZIP archive of `entries`, each stored as it is.
fn stored_zip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, data) in entries {
        let offset = out.len();
        zip_header(&mut out, name, data, None);
        out.extend_from_slice(data);
        zip_header(&mut directory, name, data, Some(offset));
    }
    let directory_offset = out.len();
    out.extend_from_slice(&directory);
    out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    u16_le(&mut out, 0); // this disk
    u16_le(&mut out, 0); // the directory's disk
    u16_le(&mut out, entries.len());
    u16_le(&mut out, entries.len());
    u32_le(&mut out, directory.len());
    u32_le(&mut out, directory_offset);
    u16_le(&mut out, 0); // comment
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The stored entries of a ZIP, read back through its central directory, each checked
    /// against its CRC.
    pub(crate) fn unzip(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let le16 = |at: usize| usize::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
        let le32 = |at: usize| {
            usize::try_from(u32::from_le_bytes([
                bytes[at],
                bytes[at + 1],
                bytes[at + 2],
                bytes[at + 3],
            ]))
            .unwrap()
        };
        let end = bytes.len() - 22;
        assert_eq!(&bytes[end..end + 4], &[0x50, 0x4b, 0x05, 0x06]);
        let count = le16(end + 10);
        let mut at = le32(end + 16);
        let mut out = Vec::new();
        for _ in 0..count {
            assert_eq!(&bytes[at..at + 4], &[0x50, 0x4b, 0x01, 0x02]);
            let crc = le32(at + 16);
            let size = le32(at + 24);
            let name_len = le16(at + 28);
            let local = le32(at + 42);
            let name = String::from_utf8(bytes[at + 46..at + 46 + name_len].to_vec()).unwrap();
            assert_eq!(&bytes[local..local + 4], &[0x50, 0x4b, 0x03, 0x04]);
            let data_at = local + 30 + le16(local + 26) + le16(local + 28);
            let data = bytes[data_at..data_at + size].to_vec();
            assert_eq!(u32::try_from(crc).unwrap(), crc32(&data), "{name}");
            out.push((name, data));
            at += 46 + name_len;
        }
        out
    }

    /// One part of a workbook, as text.
    pub(crate) fn part(bytes: &[u8], name: &str) -> String {
        let entries = unzip(bytes);
        let (_, data) = entries.iter().find(|(entry, _)| entry == name).unwrap();
        String::from_utf8(data.clone()).unwrap()
    }

    /// The text of each cell of one sheet, row by row, decoding the `_xHHHH_` escapes as Excel
    /// does.
    pub(crate) fn cells(sheet_xml: &str) -> Vec<Vec<String>> {
        let decode = |text: &str| {
            let text = text
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&");
            let mut out = String::new();
            let mut rest = text.as_str();
            while let Some(at) = rest.find("_x") {
                out.push_str(&rest[..at]);
                let tail = &rest[at..];
                if looks_escaped(tail) {
                    let code = u32::from_str_radix(&tail[2..6], 16).unwrap();
                    out.push(char::from_u32(code).unwrap());
                    rest = &tail[7..];
                } else {
                    out.push_str("_x");
                    rest = &tail[2..];
                }
            }
            out.push_str(rest);
            out
        };
        sheet_xml
            .split("<row ")
            .skip(1)
            .map(|row| {
                row.split("<t xml:space=\"preserve\">")
                    .skip(1)
                    .map(|cell| decode(&cell[..cell.find("</t>").unwrap()]))
                    .collect()
            })
            .collect()
    }

    /// The sheet names of a workbook, in order.
    pub(crate) fn sheet_names(bytes: &[u8]) -> Vec<String> {
        part(bytes, "xl/workbook.xml")
            .split("<sheet name=\"")
            .skip(1)
            .map(|rest| rest[..rest.find('"').unwrap()].to_owned())
            .collect()
    }

    fn two_sheets() -> Vec<Sheet> {
        vec![
            Sheet {
                name: "IP_ADDRESS".into(),
                rows: vec![
                    vec!["Updated".into(), "Data".into()],
                    vec![
                        "2026-10-15 00:00:00".into(),
                        "=1+1 <b>&\u{7}\r\n_x0041_ \u{1F600}".into(),
                    ],
                ],
            },
            Sheet {
                name: "ip_address".into(),
                rows: Vec::new(),
            },
        ]
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_workbook_holds_each_sheet_with_every_value_as_it_was() {
        let bytes = workbook(&two_sheets());
        let names: Vec<String> = unzip(&bytes).into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            [
                "[Content_Types].xml",
                "_rels/.rels",
                "xl/workbook.xml",
                "xl/_rels/workbook.xml.rels",
                "xl/worksheets/sheet1.xml",
                "xl/worksheets/sheet2.xml",
            ]
        );
        // Excel compares sheet names without case.
        assert_eq!(sheet_names(&bytes), ["IP_ADDRESS", "ip_address (2)"]);
        let sheet = part(&bytes, "xl/worksheets/sheet1.xml");
        assert!(!sheet.contains("<f>"), "a value is never a formula");
        assert!(!sheet.contains('\u{7}') && !sheet.contains('\r'));
        assert!(sheet.contains("&lt;b&gt;&amp;_x0007__x000D_\n_x005F_x0041_"));
        assert_eq!(
            cells(&sheet),
            [
                vec!["Updated", "Data"],
                vec!["2026-10-15 00:00:00", "=1+1 <b>&\u{7}\r\n_x0041_ \u{1F600}"],
            ]
        );
        assert_eq!(
            bytes,
            workbook(&two_sheets()),
            "the same sheets, the same bytes"
        );
    }

    #[test]
    fn text_longer_than_a_cell_carries_on_after_the_rows_last_value() {
        let long = "x".repeat(MAX_CELL_UNITS) + "tail";
        let emoji = "\u{1F600}".repeat(MAX_CELL_UNITS / 2 + 1);
        let bytes = workbook(&[Sheet {
            name: "Data".into(),
            rows: vec![vec![long.clone(), "next".into(), emoji.clone()]],
        }]);
        let row = &cells(&part(&bytes, "xl/worksheets/sheet1.xml"))[0];
        assert_eq!(row.len(), 5);
        assert_eq!(row[1], "next", "the columns stay where they were");
        assert_eq!(row[0].len(), MAX_CELL_UNITS);
        assert_eq!(row[3], "tail");
        assert!(
            row.iter()
                .all(|cell| cell.encode_utf16().count() <= MAX_CELL_UNITS)
        );
        assert_eq!(row[0].clone() + &row[3], long);
        assert_eq!(row[2].clone() + &row[4], emoji);
    }

    #[test]
    fn sheet_names_and_columns_follow_excels_rules() {
        let mut taken = BTreeSet::new();
        assert_eq!(sheet_name("a/b:c*d?[e]\\f", &mut taken), "abcdef");
        assert_eq!(sheet_name(" '' ", &mut taken), "Sheet");
        let long = "HSE_A_VERY_LONG_DATA_ELEMENT_TYPE_NAME";
        let first = sheet_name(long, &mut taken);
        assert_eq!(first, "HSE_A_VERY_LONG_DATA_ELEMENT_TY");
        let second = sheet_name(long, &mut taken);
        assert_eq!(second, "HSE_A_VERY_LONG_DATA_ELEMEN (2)");
        // Nothing left once apostrophes and spaces go, a leading apostrophe, a cut that ends in an
        // apostrophe, and a noncharacter XML 1.0 cannot carry.
        let mut fresh = BTreeSet::new();
        assert_eq!(sheet_name("' '", &mut fresh), "Sheet");
        assert_eq!(sheet_name("'Leaked creds", &mut fresh), "Leaked creds");
        assert_eq!(
            sheet_name("Exposed services on the vendor's network", &mut fresh),
            "Exposed services on the vendor"
        );
        assert_eq!(
            sheet_name("Bad \u{fffe} name\u{ffff}", &mut fresh),
            "Bad  name"
        );
        let names = [
            "' '",
            "Exposed services on the vendor's network",
            "Bad \u{fffe} name",
        ];
        let bytes = workbook(&names.map(|name| Sheet {
            name: name.into(),
            rows: Vec::new(),
        }));
        assert_eq!(
            sheet_names(&bytes),
            ["Sheet", "Exposed services on the vendor", "Bad  name"]
        );
        assert_eq!(
            [0, 25, 26, 27, 51, 52, 701, 702].map(column),
            ["A", "Z", "AA", "AB", "AZ", "BA", "ZZ", "AAA"]
        );
        let bytes = workbook(&[Sheet {
            name: "R&D \"<x>\"".into(),
            rows: Vec::new(),
        }]);
        assert!(part(&bytes, "xl/workbook.xml").contains("name=\"R&amp;D &quot;&lt;x&gt;&quot;\""));
    }

    #[test]
    fn no_sheets_still_make_a_workbook() {
        assert_eq!(sheet_names(&workbook(&[])), ["Sheet"]);
    }
}
