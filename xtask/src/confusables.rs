//! The lookalike table `huntsman_recon::evidence_ancestry` folds dataset and collector names with,
//! so one upstream dataset cannot be counted as two independent families by spelling its name
//! with an invisible character or a lookalike letter. `confusables generate CONFUSABLES DERIVED
//! OUT` writes the Rust source `src/evidence_ancestry/lookalike.rs` from two Unicode files:
//!
//! - UTS #39 `confusables.txt` (<https://www.unicode.org/Public/security/latest/confusables.txt>):
//!   every mapping of one non-ASCII code point to one ASCII letter or digit;
//! - UCD `DerivedCoreProperties.txt`
//!   (<https://www.unicode.org/Public/UCD/latest/ucd/DerivedCoreProperties.txt>): the
//!   `Default_Ignorable_Code_Point` ranges, merged where they touch.
//!
//! The output names both files' `Date:` lines, so a refresh is one command and a diff of the
//! table is a diff of what Unicode changed.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use crate::error::{self, Error, Result};

const USAGE: &str =
    "usage: cargo run --locked -p xtask -- confusables generate CONFUSABLES DERIVED OUT

  generate CONFUSABLES DERIVED OUT
      write OUT (src/evidence_ancestry/lookalike.rs) from UTS #39 confusables.txt
      (https://www.unicode.org/Public/security/latest/confusables.txt) and UCD
      DerivedCoreProperties.txt
      (https://www.unicode.org/Public/UCD/latest/ucd/DerivedCoreProperties.txt)";

const IGNORABLE_PROPERTY: &str = "Default_Ignorable_Code_Point";

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let outcome = match args {
        [command, confusables, derived, out] if command == "generate" => {
            generate(Path::new(confusables), Path::new(derived), Path::new(out))
        }
        _ => return error::usage(USAGE),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => error::report("xtask confusables", &problem),
    }
}

fn read(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    String::from_utf8(bytes).map_err(|_| Error::Invalid(format!("{}: not UTF-8", path.display())))
}

fn generate(confusables: &Path, derived: &Path, out: &Path) -> Result<()> {
    let lookalikes = Lookalikes::parse(&read(confusables)?)?;
    let ignorables = Ignorables::parse(&read(derived)?)?;
    let source = render(&lookalikes, &ignorables);
    fs::write(out, &source).map_err(|source| Error::Io {
        path: out.to_path_buf(),
        source,
    })?;
    println!(
        "{}: {} lookalikes, {} ignorable ranges",
        out.display(),
        lookalikes.pairs.len(),
        ignorables.ranges.len()
    );
    Ok(())
}

/// The `# Date: ...` line of a Unicode data file, or a refusal naming the file.
fn date(text: &str, file: &str) -> Result<String> {
    text.lines()
        .take(8)
        .find_map(|line| line.strip_prefix("# Date:"))
        .map(|date| date.trim().to_owned())
        .ok_or_else(|| Error::Invalid(format!("{file}: no `# Date:` line in its header")))
}

/// One code point written as Unicode data files write it: 4 to 6 hex digits.
fn code_point(field: &str, line: usize) -> Result<u32> {
    let field = field.trim();
    let valid = (4..=6).contains(&field.len()) && field.bytes().all(|b| b.is_ascii_hexdigit());
    valid
        .then(|| u32::from_str_radix(field, 16).ok())
        .flatten()
        .filter(|cp| char::from_u32(*cp).is_some())
        .ok_or_else(|| Error::Invalid(format!("line {line}: `{field}` is not a code point")))
}

/// Every mapping in `confusables.txt` of one non-ASCII code point to one ASCII letter or digit,
/// ascending by code point.
struct Lookalikes {
    date: String,
    pairs: Vec<(u32, u8)>,
}

impl Lookalikes {
    fn parse(text: &str) -> Result<Self> {
        let date = date(text, "confusables.txt")?;
        let mut pairs = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let data = raw.split('#').next().unwrap_or_default().trim();
            let data = data.trim_start_matches('\u{feff}');
            if data.is_empty() {
                continue;
            }
            let mut fields = data.split(';');
            let (Some(source), Some(target)) = (fields.next(), fields.next()) else {
                return Err(Error::Invalid(format!(
                    "confusables.txt line {line}: not `SOURCE ; TARGET ; TYPE`"
                )));
            };
            let source: Vec<&str> = source.split_whitespace().collect();
            let target: Vec<&str> = target.split_whitespace().collect();
            let ([source], [target]) = (source.as_slice(), target.as_slice()) else {
                continue;
            };
            let (source, target) = (code_point(source, line)?, code_point(target, line)?);
            let Ok(ascii) = u8::try_from(target) else {
                continue;
            };
            if source >= 0x80 && ascii.is_ascii_alphanumeric() {
                pairs.push((source, ascii));
            }
        }
        pairs.sort_unstable();
        if let Some(pair) = pairs.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(Error::Invalid(format!(
                "confusables.txt maps U+{:04X} twice",
                pair[0].0
            )));
        }
        if pairs.is_empty() {
            return Err(Error::Invalid(
                "confusables.txt maps no code point to an ASCII letter or digit".into(),
            ));
        }
        Ok(Self { date, pairs })
    }
}

/// The `Default_Ignorable_Code_Point` ranges of `DerivedCoreProperties.txt`, inclusive,
/// ascending, with touching ranges merged.
struct Ignorables {
    date: String,
    ranges: Vec<(u32, u32)>,
}

impl Ignorables {
    fn parse(text: &str) -> Result<Self> {
        let date = date(text, "DerivedCoreProperties.txt")?;
        let mut ranges = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let data = raw.split('#').next().unwrap_or_default();
            let Some((points, property)) = data.split_once(';') else {
                continue;
            };
            if property.trim() != IGNORABLE_PROPERTY {
                continue;
            }
            let (first, last) = match points.trim().split_once("..") {
                Some((first, last)) => (code_point(first, line)?, code_point(last, line)?),
                None => {
                    let only = code_point(points, line)?;
                    (only, only)
                }
            };
            if first > last {
                return Err(Error::Invalid(format!(
                    "DerivedCoreProperties.txt line {line}: a range runs backwards"
                )));
            }
            ranges.push((first, last));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (first, last) in ranges {
            match merged.last_mut() {
                Some(previous) if first <= previous.1.saturating_add(1) => {
                    previous.1 = previous.1.max(last);
                }
                _ => merged.push((first, last)),
            }
        }
        if merged.is_empty() {
            return Err(Error::Invalid(format!(
                "DerivedCoreProperties.txt lists no {IGNORABLE_PROPERTY} code point"
            )));
        }
        Ok(Self {
            date,
            ranges: merged,
        })
    }
}

/// The Rust source of the table. **Pure.**
fn render(lookalikes: &Lookalikes, ignorables: &Ignorables) -> String {
    let mut out = String::new();
    out.push_str(
        "//! Generated by `cargo run --locked -p xtask -- confusables generate CONFUSABLES DERIVED \
         OUT`;\n//! do not edit. See `xtask/src/confusables.rs` for the sources and the selection.\n",
    );
    let _ = writeln!(
        out,
        "//!\n//! - UTS #39 `confusables.txt`, Date: {}",
        lookalikes.date
    );
    let _ = writeln!(
        out,
        "//! - UCD `DerivedCoreProperties.txt`, Date: {}\n",
        ignorables.date
    );
    out.push_str(
        "/// `Default_Ignorable_Code_Point` ranges, inclusive, ascending and disjoint.\n\
         #[rustfmt::skip]\n\
         pub(super) const IGNORABLE: &[(u32, u32)] = &[\n",
    );
    for (first, last) in &ignorables.ranges {
        let _ = writeln!(out, "    (0x{first:04X}, 0x{last:04X}),");
    }
    out.push_str(
        "];\n\n/// Each non-ASCII code point UTS #39 maps to one ASCII letter or digit, ascending.\n\
         #[rustfmt::skip]\n\
         pub(super) const LOOKALIKE: &[(u32, u8)] = &[\n",
    );
    for row in lookalikes.pairs.chunks(6) {
        out.push_str("   ");
        for (source, ascii) in row {
            let _ = write!(out, " (0x{source:04X}, b'{}'),", char::from(*ascii));
        }
        out.push('\n');
    }
    out.push_str("];\n");
    out
}
