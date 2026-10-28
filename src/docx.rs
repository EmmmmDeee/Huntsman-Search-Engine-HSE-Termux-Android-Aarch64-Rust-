//! Word documents (`.docx`) with no dependency: `WordprocessingML` parts in the same stored ZIP
//! the Excel writer uses ([`crate::xlsx::stored_zip`]).
//!
//! [`document`] writes a title, headings, paragraphs and tables. Every text is escaped, a
//! character XML cannot carry is dropped, and the same blocks always make the same bytes, so a
//! generated document can be committed and checked against its source. The page is A4
//! landscape, which fits a wide table on a phone or in print.

use std::fmt::Write as _;

use crate::gexf::escape_xml;

/// The media type of a Word document.
pub const CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// One block of a document, in reading order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// A level 1 or 2 heading.
    Heading(u8, String),
    Paragraph(String),
    /// Rows of cells, the first row the header, shaded and repeated on each page.
    Table(Vec<Vec<String>>),
}

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>"#;

const ROOT_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>"#;

const DOCUMENT_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>"#;

const STYLES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="18"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="80"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="160"/></w:pPr><w:rPr><w:b/><w:color w:val="1F4E8C"/><w:sz w:val="36"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1F4E8C"/><w:sz w:val="28"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="60"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style><w:style w:type="table" w:styleId="Grid"><w:name w:val="Grid"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="BFC7D5"/><w:left w:val="single" w:sz="4" w:color="BFC7D5"/><w:bottom w:val="single" w:sz="4" w:color="BFC7D5"/><w:right w:val="single" w:sz="4" w:color="BFC7D5"/><w:insideH w:val="single" w:sz="4" w:color="BFC7D5"/><w:insideV w:val="single" w:sz="4" w:color="BFC7D5"/></w:tblBorders><w:tblCellMar><w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style></w:styles>"#;

/// Text Word can hold: XML-escaped, with the characters XML 1.0 forbids dropped.
fn text(raw: &str) -> String {
    let allowed: String = raw
        .chars()
        .filter(|c| matches!(c, '\t' | '\n' | '\r') || !c.is_control())
        .filter(|c| !matches!(c, '\u{fffe}' | '\u{ffff}'))
        .collect();
    escape_xml(&allowed)
}

fn paragraph(out: &mut String, style: Option<&str>, raw: &str, bold: bool) {
    out.push_str("<w:p>");
    if let Some(style) = style {
        let _ = write!(out, "<w:pPr><w:pStyle w:val=\"{style}\"/></w:pPr>");
    }
    // Each line is its own run, separated by a line break, so a value's lines survive.
    for (index, line) in raw.split('\n').enumerate() {
        out.push_str("<w:r>");
        if bold {
            out.push_str("<w:rPr><w:b/></w:rPr>");
        }
        if index > 0 {
            out.push_str("<w:br/>");
        }
        let _ = write!(
            out,
            "<w:t xml:space=\"preserve\">{}</w:t></w:r>",
            text(line)
        );
    }
    out.push_str("</w:p>");
}

/// The width between the margins of an A4 landscape page, in twentieths of a point.
const TEXT_WIDTH: usize = 16_838 - 2 * 850;

/// Each column's width: its share of [`TEXT_WIDTH`] follows the longest text in it (a word or
/// a line, at most 120 characters), and no column gets less than a quarter of an even share.
fn column_widths(rows: &[Vec<String>], columns: usize) -> Vec<usize> {
    let weights: Vec<usize> = (0..columns)
        .map(|column| {
            rows.iter()
                .filter_map(|row| row.get(column))
                .map(|cell| {
                    cell.lines()
                        .map(|line| line.chars().count())
                        .max()
                        .unwrap_or(0)
                })
                .max()
                .unwrap_or(0)
                .clamp(4, 120)
        })
        .collect();
    let total: usize = weights.iter().sum();
    let floor = TEXT_WIDTH / columns / 4;
    let free = TEXT_WIDTH - floor * columns;
    weights
        .iter()
        .map(|weight| floor + free * weight / total.max(1))
        .collect()
}

fn table(out: &mut String, rows: &[Vec<String>]) {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0).max(1);
    out.push_str("<w:tbl><w:tblPr><w:tblStyle w:val=\"Grid\"/><w:tblW w:w=\"5000\" w:type=\"pct\"/><w:tblLayout w:type=\"fixed\"/></w:tblPr><w:tblGrid>");
    for width in column_widths(rows, columns) {
        let _ = write!(out, "<w:gridCol w:w=\"{width}\"/>");
    }
    out.push_str("</w:tblGrid>");
    for (index, row) in rows.iter().enumerate() {
        out.push_str("<w:tr>");
        if index == 0 {
            out.push_str("<w:trPr><w:tblHeader/></w:trPr>");
        }
        for column in 0..columns {
            out.push_str("<w:tc>");
            if index == 0 {
                out.push_str(
                    "<w:tcPr><w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"E8EEF7\"/></w:tcPr>",
                );
            }
            paragraph(
                out,
                None,
                row.get(column).map_or("", String::as_str),
                index == 0,
            );
            out.push_str("</w:tc>");
        }
        out.push_str("</w:tr>");
    }
    out.push_str("</w:tbl><w:p/>");
}

/// A Word document titled `title` holding `blocks`, with `title` and `subject` as its
/// document properties.
#[must_use]
pub fn document(title: &str, subject: &str, blocks: &[Block]) -> Vec<u8> {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>",
    );
    paragraph(&mut body, Some("Title"), title, false);
    for block in blocks {
        match block {
            Block::Heading(level, heading) => {
                let style = if *level <= 1 { "Heading1" } else { "Heading2" };
                paragraph(&mut body, Some(style), heading, false);
            }
            Block::Paragraph(content) => paragraph(&mut body, None, content, false),
            Block::Table(rows) => table(&mut body, rows),
        }
    }
    // A4 landscape with 1.5 cm margins.
    body.push_str("<w:sectPr><w:pgSz w:w=\"16838\" w:h=\"11906\" w:orient=\"landscape\"/><w:pgMar w:top=\"850\" w:right=\"850\" w:bottom=\"850\" w:left=\"850\" w:header=\"425\" w:footer=\"425\" w:gutter=\"0\"/></w:sectPr></w:body></w:document>");
    let core = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:title>{}</dc:title><dc:subject>{}</dc:subject><dc:creator>Huntsman</dc:creator></cp:coreProperties>",
        text(title),
        text(subject)
    );
    crate::xlsx::stored_zip(&[
        (
            "[Content_Types].xml".to_owned(),
            CONTENT_TYPES.as_bytes().to_vec(),
        ),
        ("_rels/.rels".to_owned(), ROOT_RELS.as_bytes().to_vec()),
        ("docProps/core.xml".to_owned(), core.into_bytes()),
        (
            "word/_rels/document.xml.rels".to_owned(),
            DOCUMENT_RELS.as_bytes().to_vec(),
        ),
        ("word/styles.xml".to_owned(), STYLES.as_bytes().to_vec()),
        ("word/document.xml".to_owned(), body.into_bytes()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xlsx::tests::{part, unzip};

    fn sample() -> Vec<u8> {
        document(
            "Blueprint <1>",
            "apps & methods",
            &[
                Block::Heading(1, "Radio".into()),
                Block::Paragraph("first line\nsecond \u{1} line".into()),
                Block::Table(vec![
                    vec!["App".into(), "Status".into()],
                    vec!["Tower <Collector>".into()],
                ]),
            ],
        )
    }

    #[test]
    fn a_document_is_a_word_package_with_every_text_escaped() {
        let bytes = sample();
        let names: Vec<String> = unzip(&bytes).into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            [
                "[Content_Types].xml",
                "_rels/.rels",
                "docProps/core.xml",
                "word/_rels/document.xml.rels",
                "word/styles.xml",
                "word/document.xml"
            ]
        );
        let body = part(&bytes, "word/document.xml");
        assert!(body.contains("<w:pStyle w:val=\"Title\"/></w:pPr><w:r><w:t xml:space=\"preserve\">Blueprint &lt;1&gt;</w:t>"), "{body}");
        assert!(body.contains("<w:pStyle w:val=\"Heading1\"/>"));
        assert!(
            body.contains(
                "first line</w:t></w:r><w:r><w:br/><w:t xml:space=\"preserve\">second  line</w:t>"
            ),
            "{body}"
        );
        assert!(body.contains("Tower &lt;Collector&gt;"));
        // A short row is padded to the table's width, and the header repeats on each page.
        assert_eq!(body.matches("<w:tc>").count(), 4);
        assert!(body.contains("<w:tblHeader/>"));
        assert!(!body.contains('\u{1}'));
        assert!(
            part(&bytes, "docProps/core.xml")
                .contains("<dc:subject>apps &amp; methods</dc:subject>")
        );
    }

    #[test]
    fn a_column_is_as_wide_as_its_longest_text_and_never_narrower_than_a_quarter_share() {
        let rows = vec![
            vec!["Field".to_owned(), "Value".to_owned()],
            vec!["Acceptance".to_owned(), "x".repeat(200)],
        ];
        let widths = column_widths(&rows, 2);
        assert!(widths.iter().sum::<usize>() <= TEXT_WIDTH);
        assert!(widths[1] > 3 * widths[0], "{widths:?}");
        assert!(widths[0] >= TEXT_WIDTH / 8, "{widths:?}");
        let even = column_widths(&[vec!["ab".into(), "cd".into()]], 2);
        assert_eq!(even[0], even[1]);
    }

    #[test]
    fn the_same_blocks_make_the_same_bytes() {
        assert_eq!(sample(), sample());
    }
}
