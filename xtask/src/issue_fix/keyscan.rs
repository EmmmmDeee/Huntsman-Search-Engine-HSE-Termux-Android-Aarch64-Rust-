//! The model-key scan. The model step runs it after the model exits and before the change is
//! checked. The model's Bash tool can run cargo, and cargo runs code the model wrote, so that code
//! can read the model key and write it into a file that the change carries. The scan refuses a
//! change that holds the key, or a base64 or hex form of it, in any path the change would carry: a
//! file's content, a file name, or a symbolic link's target. It also redacts the key and its forms
//! from the model's output, so that output is safe to keep even when the change is refused.
//!
//! The caller lists the paths the change would carry, NUL-separated, with the ignore rules that
//! git add applies, so no .gitignore hides a file from the scan. The key comes from the environment
//! and is never printed. Decoding never stops at an error. CPython's base64 decoder stops at a
//! completed padding group in 3.11 and 3.12, reads on in 3.13, and raises on a partial group in
//! every version. Reading each candidate to its end, and never failing, makes the scan find the key
//! whichever of those readings a runner's Python uses, and a stray character cannot hide it.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;

use crate::error::{self, Error, Result};

const USAGE: &str = "usage: xtask issue-fix key-scan AGENT_JSON PATHS_FILE";
/// The environment variable that holds the model key.
const KEY_VARIABLE: &str = "ANTHROPIC_API_KEY";
/// A shorter key cannot be searched for without matching unrelated text, so the scan refuses.
const MIN_KEY_BYTES: usize = 8;
/// What each redacted form becomes in the model output.
const REDACTED: &[u8] = b"[redacted]";
const SK_ANT_PREFIX: &[u8] = b"sk-ant-";

/// `issue-fix key-scan AGENT_JSON PATHS_FILE`. Redacts AGENT_JSON in place, then checks every
/// NUL-separated path in PATHS_FILE. Refuses (status 1) when the key, or an encoding of it, is in
/// a path, when a path cannot be read, or when the key is unset or too short. Malformed arguments
/// are a usage error (status 64).
pub fn run(args: &[String]) -> ExitCode {
    let [agent, paths] = args else {
        return error::usage(USAGE);
    };
    match scan(Path::new(agent), Path::new(paths)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(error::EX_REFUSED),
        Err(problem) => error::report("issue-fix key-scan", &problem),
    }
}

/// Redacts AGENT, then scans the entries of PATHS. Returns whether the change is clean. Every
/// finding is printed here, so the caller only sets the status.
fn scan(agent: &Path, paths: &Path) -> Result<bool> {
    let key = match model_key() {
        Ok(key) => key,
        Err(message) => {
            eprintln!("::error::{message}");
            return Ok(false);
        }
    };
    let forms = Forms::new(key);
    redact_output(agent, &forms)?;
    let listing = read_file(paths)?;
    let entries = listing
        .split(|&byte| byte == 0)
        .filter(|entry| !entry.is_empty());
    let mut findings = Vec::new();
    for (number, name) in (1..).zip(entries) {
        findings.extend(inspect(number, name, &forms));
    }
    for finding in &findings {
        eprintln!("::error::the model key, or an encoding of it, is in {finding}");
    }
    Ok(findings.is_empty())
}

/// The model key as bytes. A key that is unset or shorter than MIN_KEY_BYTES is refused, as is one
/// that is not UTF-8: the original encoded the key as UTF-8 to build its forms, and failed when it
/// could not, which refused the change. The refusal is the same here, and it is never a pass.
fn model_key() -> std::result::Result<Vec<u8>, &'static str> {
    let key = std::env::var_os(KEY_VARIABLE)
        .unwrap_or_default()
        .into_encoded_bytes();
    if key.len() < MIN_KEY_BYTES {
        return Err("the model key is unset or too short to scan for");
    }
    if std::str::from_utf8(&key).is_err() {
        return Err("the model key is not UTF-8, so the scan cannot encode it");
    }
    Ok(key)
}

/// Replaces the key and its forms in the model output at AGENT, when that is a file. The output is
/// redacted before the paths are read, so a refused change still leaves a clean output behind.
fn redact_output(agent: &Path, forms: &Forms) -> Result<()> {
    if !fs::metadata(agent).is_ok_and(|meta| meta.is_file()) {
        return Ok(());
    }
    let content = read_file(agent)?;
    let redacted = forms.redact(&content);
    fs::write(agent, redacted).map_err(|source| Error::Io {
        path: agent.to_path_buf(),
        source,
    })
}

/// Returns the finding for entry NUMBER, the NUMBER-th non-empty name in the listing, or None when
/// the entry is clean. A name that carries the key is reported by its number, so it is never
/// printed. An entry that cannot be inspected is skipped, as the original did, unless it is a
/// symbolic link or a regular file that cannot be read, which is a finding.
fn inspect(number: usize, name: &[u8], forms: &Forms) -> Option<String> {
    if forms.carried_by(name) {
        return Some(format!("the file name of entry {number}"));
    }
    let shown = render_path(name);
    let path = Path::new(OsStr::from_bytes(name));
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return match fs::read_link(path) {
            Ok(target) => forms
                .carried_by(target.as_os_str().as_bytes())
                .then_some(shown),
            Err(source) => Some(unreadable(&shown, &source)),
        };
    }
    if !meta.is_file() {
        return None;
    }
    match fs::read(path) {
        Ok(content) => forms.carried_by(&content).then_some(shown),
        Err(source) => Some(unreadable(&shown, &source)),
    }
}

/// Reports a path that cannot be read, and returns it as a finding: an unread path is not clean.
fn unreadable(shown: &str, source: &io::Error) -> String {
    eprintln!("::error::cannot read {shown}: {}", strerror(source));
    shown.to_owned()
}

/// The message of an OS error without the " (os error N)" suffix that Rust adds, which is the text
/// Python's OSError.strerror holds.
fn strerror(source: &io::Error) -> String {
    let text = source.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text.get(..at).unwrap_or_default().to_owned(),
        None => text,
    }
}

/// A path as Python prints it on stderr. Valid UTF-8 is kept as it is. Each byte that is not valid
/// UTF-8 is shown as \udcNN, the escape Python gives the surrogate that surrogateescape decoding
/// makes of it, so the message reads as it did in the original.
fn render_path(name: &[u8]) -> String {
    let mut out = String::new();
    for chunk in name.utf8_chunks() {
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            out.push_str(&format!("\\udc{byte:02x}"));
        }
    }
    out
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// The model key and the forms of it that the scan searches for.
struct Forms {
    raw: Vec<u8>,
    hex_lower: Vec<u8>,
    hex_upper: Vec<u8>,
    /// A base64 run that holds the key is at least this long, at any alignment: 4 * (len / 3).
    min_run: usize,
}

impl Forms {
    fn new(raw: Vec<u8>) -> Self {
        let hex_lower: Vec<u8> = raw
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect();
        let hex_upper = hex_lower.to_ascii_uppercase();
        let min_run = 4 * (raw.len() / 3);
        Self {
            raw,
            hex_lower,
            hex_upper,
            min_run,
        }
    }

    /// Whether BLOB holds the key, its hex in either case, or a base64 run that decodes to the key.
    fn carried_by(&self, blob: &[u8]) -> bool {
        contains(blob, &self.raw)
            || contains(blob, &self.hex_lower)
            || contains(blob, &self.hex_upper)
            || base64_spans(blob)
                .any(|(start, end)| self.is_key_run(blob.get(start..end).unwrap_or_default()))
    }

    /// Whether RUN is long enough to hold the key and decodes to a stream that does.
    fn is_key_run(&self, run: &[u8]) -> bool {
        run.len() >= self.min_run && self.decodes_to_key(run)
    }

    /// Whether RUN, read in either base64 alphabet at each of the four alignments, decodes to a
    /// stream that holds the key. The key can begin at any of the four offsets of a longer stream.
    /// Each candidate is decoded to its end, including a final group that has no padding: the key
    /// can end in that group, as the unpadded base64 of a key does.
    fn decodes_to_key(&self, run: &[u8]) -> bool {
        let url_to_standard: Vec<u8> = run
            .iter()
            .map(|&byte| match byte {
                b'-' => b'+',
                b'_' => b'/',
                other => other,
            })
            .collect();
        [run, url_to_standard.as_slice()].into_iter().any(|text| {
            (0..4).any(|offset| {
                let body = text.get(offset..).unwrap_or_default();
                contains(&decode_base64(body), &self.raw)
            })
        })
    }

    /// The blob with the key, its hex forms, the base64 runs that hold the key, and every sk-ant-
    /// key replaced by "[redacted]", applied in the order the original applied them.
    fn redact(&self, blob: &[u8]) -> Vec<u8> {
        let mut out = blob.to_vec();
        for form in [&self.raw, &self.hex_lower, &self.hex_upper] {
            out = replace_all(&out, form, REDACTED);
        }
        out = replace_base64_runs(&out, |run| self.is_key_run(run));
        replace_sk_ant_keys(&out)
    }
}

/// Decodes BODY with the standard base64 alphabet. Every other byte is skipped, so "-" and "_" are
/// skipped when the caller has not translated them, and "=" never ends the decode early. Each
/// complete byte is kept, and the decode never fails. This returns what CPython's non-validating
/// decoder returns for each version that returns anything, and more where that decoder raises or
/// stops early.
fn decode_base64(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in body {
        let Some(value) = standard_value(byte) else {
            continue;
        };
        acc = ((acc << 6) | u32::from(value)) & 0xFFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    out
}

/// The value of a byte in the standard base64 alphabet, or None for any other byte.
fn standard_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Whether a byte belongs to a base64 run: the standard and URL-safe alphabets together.
fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-')
}

/// The spans of the base64 runs in BLOB, as (start, end) byte offsets. A run is a maximal sequence
/// of base64 bytes followed by at most two "=", which is the pattern the original used. Padding
/// belongs to a run only at its end, so an "=" in the middle ends the run.
fn base64_spans(blob: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut next = 0;
    std::iter::from_fn(move || {
        let start = next
            + blob
                .get(next..)?
                .iter()
                .position(|&byte| is_base64_byte(byte))?;
        let run = blob
            .get(start..)?
            .iter()
            .take_while(|&&byte| is_base64_byte(byte))
            .count();
        let end = start + run;
        let padding = blob
            .get(end..)?
            .iter()
            .take(2)
            .take_while(|&&byte| byte == b'=')
            .count();
        next = end + padding;
        Some((start, next))
    })
}

/// BLOB with each base64 run that SHOULD_REDACT accepts replaced by "[redacted]".
fn replace_base64_runs(blob: &[u8], should_redact: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.len());
    let mut copied = 0;
    for (start, end) in base64_spans(blob) {
        out.extend_from_slice(blob.get(copied..start).unwrap_or_default());
        let run = blob.get(start..end).unwrap_or_default();
        if should_redact(run) {
            out.extend_from_slice(REDACTED);
        } else {
            out.extend_from_slice(run);
        }
        copied = end;
    }
    out.extend_from_slice(blob.get(copied..).unwrap_or_default());
    out
}

/// BLOB with every "sk-ant-" key, the prefix and one or more of [A-Za-z0-9_-], replaced by
/// "[redacted]". A match is taken left to right and is never empty.
fn replace_sk_ant_keys(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.len());
    let mut at = 0;
    while let Some(rest) = blob.get(at..) {
        // The tail is measured only where the prefix matches, so the scan stays linear.
        let tail = if rest.starts_with(SK_ANT_PREFIX) {
            rest.iter()
                .skip(SK_ANT_PREFIX.len())
                .take_while(|&&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                .count()
        } else {
            0
        };
        if tail > 0 {
            out.extend_from_slice(REDACTED);
            at += SK_ANT_PREFIX.len() + tail;
        } else if let Some(&byte) = rest.first() {
            out.push(byte);
            at += 1;
        } else {
            break;
        }
    }
    out
}

/// BLOB with every occurrence of NEEDLE replaced by WITH, scanning left to right and never
/// overlapping, as Python's bytes.replace does.
fn replace_all(blob: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return blob.to_vec();
    }
    let mut out = Vec::with_capacity(blob.len());
    let mut rest = blob;
    while let Some(at) = find(rest, needle) {
        out.extend_from_slice(rest.get(..at).unwrap_or_default());
        out.extend_from_slice(with);
        rest = rest.get(at + needle.len()..).unwrap_or_default();
    }
    out.extend_from_slice(rest);
    out
}

/// Whether NEEDLE occurs in HAY. An empty needle occurs everywhere, as it does in Python.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || find(hay, needle).is_some()
}

/// The offset of the first occurrence of NEEDLE in HAY. An empty needle has no offset here.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    hay.windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inputs and what CPython's non-validating decoder returns for them: 3.12 (which stops at a
    /// completed padding group) and 3.13 (which reads on). None means that decoder raised. The
    /// vectors were generated with `base64.b64decode` under `python3 -I`.
    const PYTHON_VECTORS: &[(&[u8], Option<&str>, Option<&str>)] = &[
        (b"", Some(""), Some("")),
        (b"A", None, None),
        (b"AB", None, None),
        (b"ABC", None, None),
        (b"ABCD", Some("001083"), Some("001083")),
        (b"QQ", None, None),
        (b"QQ=", None, None),
        (b"QQ==", Some("41"), Some("41")),
        (b"QQ===", Some("41"), Some("41")),
        (b"QQ==QQ==", Some("41"), Some("410410")),
        (b"QQ==A", Some("41"), None),
        (b"QQ=R", None, None),
        (b"QQ=-=", Some("41"), Some("41")),
        (b"QU=JD", Some("414243"), Some("414243")),
        (b"QUJD=", Some("414243"), Some("414243")),
        (b"QUJD==", Some("414243"), Some("414243")),
        (b"QUJD===", Some("414243"), Some("414243")),
        (b"QUJDQQ=", None, None),
        (b"QUJDQQ===", Some("41424341"), Some("41424341")),
        (b"QUJDQQ==QQ==", Some("41424341"), Some("414243410410")),
        (b"AB-C", None, None),
        (b"A_-=", None, None),
        (b"Q", None, None),
        (b"Q===", None, None),
        (b"A===", None, None),
        (b"====", Some(""), Some("")),
        (b"=AAA", None, None),
        (b"A=AA", None, None),
        (b"QUJD!", Some("414243"), Some("414243")),
        (b"Q-Q=", None, None),
        (b"QUJ-", None, None),
        (b"QUJDRE", None, None),
        (b"AAAA=", Some("000000"), Some("000000")),
        (b"AAA=", Some("0000"), Some("0000")),
        (b"QR==", Some("41"), Some("41")),
        (
            b"Zml4dHVyZX5+fm1vZGVsfmtleQ==",
            Some("666978747572657e7e7e6d6f64656c7e6b6579"),
            Some("666978747572657e7e7e6d6f64656c7e6b6579"),
        ),
        (b"Zml4dHVyZX5-fm1vZGVsfmtleQ", None, None),
        (b"Zml4dHVyZX5_fm1vZGVsfmtleQ==", None, None),
        (b"ZG9j\x0aZW5k", Some("646f63656e64"), Some("646f63656e64")),
        (b"ZG9j ZW5k", Some("646f63656e64"), Some("646f63656e64")),
        (b"+/+/", Some("fbffbf"), Some("fbffbf")),
        (b"-_-_", Some(""), Some("")),
        (b"+/=", None, None),
        (b"AAAAAAAA==", Some("000000000000"), Some("000000000000")),
        (b"AAAAAAA", None, None),
        (b"AAAAAAAAA", None, None),
        (b"\x00\x01", Some(""), Some("")),
        (b"a\x00b", None, None),
        (b"gqzptgWVy6A", None, None),
        (b"SfDEC", None, None),
        (b"ReeuC5D", None, None),
        (b"b=B=xkuBklsYimrBQeO", None, None),
        (b"ROvTeyD9qrvG3zbhhW", None, None),
        (b"7MJQK5va", Some("ecc2502b9bda"), Some("ecc2502b9bda")),
        (
            b"7nDM1PSpeS4arWHE",
            Some("ee70ccd4f4a9792e1aad61c4"),
            Some("ee70ccd4f4a9792e1aad61c4"),
        ),
        (b"Ro", None, None),
        (
            b"FpgPqpqmoTyU0izv5jUR",
            Some("16980faa9aa6a13c94d22cefe63511"),
            Some("16980faa9aa6a13c94d22cefe63511"),
        ),
        (b"6Q3T/oxWt2zEzlv06aGDF", None, None),
        (b"owspxgVoM", None, None),
        (b"Mq9nYgg/259hoi", None, None),
        (b"Z4YNVzp", None, None),
        (b"znEOA9y", None, None),
        (b"NBopjYTDVMTSClwmOmW", None, None),
        (b"2s/iM8LrtHSfa3TH5qW", None, None),
        (
            b"v5ka1SkqkTSebUYbZXVM",
            Some("bf991ad5292a91349e6d461b65754c"),
            Some("bf991ad5292a91349e6d461b65754c"),
        ),
        (b"7evMkCZJK6lygyYCva/", None, None),
        (b"e", None, None),
        (b"Js03C/4D-ENw.0Th", None, None),
        (b"0jy", None, None),
        (b"sYAFueFM-zb-SDc", None, None),
        (b"Pd=JRos_Shk5uu6", None, None),
        (b"vd+TjszPvqSlE5", None, None),
        (b"LhJGA", None, None),
        (b"QXNy9yPz3", None, None),
        (b"LwaiQoBE", Some("2f06a2428044"), Some("2f06a2428044")),
        (b"oy1x5LKTYzhzwbF", None, None),
        (
            b"tnQlwp1BgLzQExBrWVlr",
            Some("b67425c29d4180bcd013106b59596b"),
            Some("b67425c29d4180bcd013106b59596b"),
        ),
        (b"hmVhVKzdbE", None, None),
        (b"r", None, None),
        (b"0Z2Zj8S", None, None),
        (b"llfn", Some("9657e7"), Some("9657e7")),
        (b"ncOSXAOt/DMmQF", None, None),
        (b"3qnXXf5\x0aNVZ", None, None),
        (b"snRLuljcCDJoWV", None, None),
        (b"9mp", None, None),
        (
            b"pq84N7+DO/kfvA0h",
            Some("a6af3837bf833bf91fbc0d21"),
            Some("a6af3837bf833bf91fbc0d21"),
        ),
        (b"9huTp", None, None),
        (b"FlYwXGZ", None, None),
        (b"FqXgtOl", None, None),
        (
            b"hE20ONL1r/tA_j0WiFuW9",
            Some("844db438d2f5affb408f45a216e5bd"),
            Some("844db438d2f5affb408f45a216e5bd"),
        ),
        (b"0l!_nQP=FpEY", None, None),
        (b"rbDySQ", None, None),
        (b"qIw", None, None),
        (b"CnQxF8HU2rxlxg", None, None),
        (b"1XRUaZ9", None, None),
        (b"6B1w", Some("e81d70"), Some("e81d70")),
        (
            b"4PsnLBZYDQ==",
            Some("e0fb272c16580d"),
            Some("e0fb272c16580d"),
        ),
        (b"eF47k7ouFfEd8Y0", None, None),
        (b"6hbcjYY", None, None),
        (b"Ad8FJpE=", Some("01df052691"), Some("01df052691")),
        (b"FbQc", Some("15b41c"), Some("15b41c")),
        (b"CcVz", Some("09c573"), Some("09c573")),
        (b"t9U", None, None),
        (b"aP8JCMF8Ih-Uex0", None, None),
        (
            b"pCVZhyRapz4wQl8\x0a=",
            Some("a4255987245aa73e30425f"),
            Some("a4255987245aa73e30425f"),
        ),
        (b"YL4r", Some("60be2b"), Some("60be2b")),
        (
            b"dtoN5wjcv\x0a93iLWOY",
            Some("76da0de708dcbfdde22d6398"),
            Some("76da0de708dcbfdde22d6398"),
        ),
        (b"rg==\x0a", Some("ae"), Some("ae")),
        (b"Pa0TkRYfMH/C7g", None, None),
        (
            b"VecxXEULYt4=",
            Some("55e7315c450b62de"),
            Some("55e7315c450b62de"),
        ),
        (
            b"EctDTE6Aqsf4",
            Some("11cb434c4e80aac7f8"),
            Some("11cb434c4e80aac7f8"),
        ),
        (b"URCC8dGl5VP3WbHi2w", None, None),
        (b"kiA", None, None),
        (
            b"OE9Vx5pbVbL4g-Q==",
            Some("384f55c79a5b55b2f881"),
            Some("384f55c79a5b55b2f881"),
        ),
        (
            b"Zml4dHVyZX5+fm1vZGVsfmtleUE=",
            Some("666978747572657e7e7e6d6f64656c7e6b657941"),
            Some("666978747572657e7e7e6d6f64656c7e6b657941"),
        ),
        (
            b"Zml4dHVyZX5+fm1vZGVsfmtleUFC",
            Some("666978747572657e7e7e6d6f64656c7e6b65794142"),
            Some("666978747572657e7e7e6d6f64656c7e6b65794142"),
        ),
        (
            b"Zml4dHVyZX5+fm1vZGVsfmtleUFCQw==",
            Some("666978747572657e7e7e6d6f64656c7e6b6579414243"),
            Some("666978747572657e7e7e6d6f64656c7e6b6579414243"),
        ),
        (
            b"eGZpeHR1cmV+fn5tb2RlbH5rZXk=",
            Some("78666978747572657e7e7e6d6f64656c7e6b6579"),
            Some("78666978747572657e7e7e6d6f64656c7e6b6579"),
        ),
        (
            b"eGZpeHR1cmV+fn5tb2RlbH5rZXlB",
            Some("78666978747572657e7e7e6d6f64656c7e6b657941"),
            Some("78666978747572657e7e7e6d6f64656c7e6b657941"),
        ),
        (
            b"eGZpeHR1cmV+fn5tb2RlbH5rZXlBQg==",
            Some("78666978747572657e7e7e6d6f64656c7e6b65794142"),
            Some("78666978747572657e7e7e6d6f64656c7e6b65794142"),
        ),
        (
            b"eGZpeHR1cmV+fn5tb2RlbH5rZXlBQkM=",
            Some("78666978747572657e7e7e6d6f64656c7e6b6579414243"),
            Some("78666978747572657e7e7e6d6f64656c7e6b6579414243"),
        ),
        (
            b"eHhmaXh0dXJlfn5+bW9kZWx+a2V5",
            Some("7878666978747572657e7e7e6d6f64656c7e6b6579"),
            Some("7878666978747572657e7e7e6d6f64656c7e6b6579"),
        ),
        (
            b"eHhmaXh0dXJlfn5+bW9kZWx+a2V5QQ==",
            Some("7878666978747572657e7e7e6d6f64656c7e6b657941"),
            Some("7878666978747572657e7e7e6d6f64656c7e6b657941"),
        ),
        (
            b"eHhmaXh0dXJlfn5+bW9kZWx+a2V5QUI=",
            Some("7878666978747572657e7e7e6d6f64656c7e6b65794142"),
            Some("7878666978747572657e7e7e6d6f64656c7e6b65794142"),
        ),
        (
            b"eHhmaXh0dXJlfn5+bW9kZWx+a2V5QUJD",
            Some("7878666978747572657e7e7e6d6f64656c7e6b6579414243"),
            Some("7878666978747572657e7e7e6d6f64656c7e6b6579414243"),
        ),
        (
            b"eHh4Zml4dHVyZX5+fm1vZGVsfmtleQ==",
            Some("787878666978747572657e7e7e6d6f64656c7e6b6579"),
            Some("787878666978747572657e7e7e6d6f64656c7e6b6579"),
        ),
        (
            b"eHh4Zml4dHVyZX5+fm1vZGVsfmtleUE=",
            Some("787878666978747572657e7e7e6d6f64656c7e6b657941"),
            Some("787878666978747572657e7e7e6d6f64656c7e6b657941"),
        ),
        (
            b"eHh4Zml4dHVyZX5+fm1vZGVsfmtleUFC",
            Some("787878666978747572657e7e7e6d6f64656c7e6b65794142"),
            Some("787878666978747572657e7e7e6d6f64656c7e6b65794142"),
        ),
        (
            b"eHh4Zml4dHVyZX5+fm1vZGVsfmtleUFCQw==",
            Some("787878666978747572657e7e7e6d6f64656c7e6b6579414243"),
            Some("787878666978747572657e7e7e6d6f64656c7e6b6579414243"),
        ),
    ];

    const KEY: &[u8] = b"fixture~~~model~key";

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| {
                u8::from_str_radix(text.get(at..at + 2).expect("even hex"), 16).expect("hex digit")
            })
            .collect()
    }

    #[test]
    fn the_decoder_keeps_every_byte_that_the_python_decoder_returns() {
        for (input, py312, py313) in PYTHON_VECTORS {
            let mine = decode_base64(input);
            if let Some(expected) = py312 {
                assert!(
                    mine.starts_with(&unhex(expected)),
                    "3.12 decode of {input:?} is not a prefix of {mine:02x?}"
                );
            }
            if let Some(expected) = py313 {
                assert_eq!(mine, unhex(expected), "3.13 decode of {input:?}");
            }
        }
    }

    #[test]
    fn the_decoder_reads_past_a_padding_group_and_skips_stray_bytes() {
        assert_eq!(decode_base64(b"QQ==QQ=="), b"A\x04\x10");
        assert_eq!(decode_base64(b"QUJD!"), b"ABC");
        assert_eq!(decode_base64(b"AB-C"), [0x00, 0x10]);
    }

    #[test]
    fn base64_runs_take_their_padding_and_stop_at_a_middle_equals() {
        let spans: Vec<(usize, usize)> = base64_spans(b"x AAAA== y=Q==z").collect();
        assert_eq!(spans, [(0, 1), (2, 8), (9, 11), (11, 14), (14, 15)]);
    }

    #[test]
    fn redaction_removes_every_form_of_the_key() {
        let forms = Forms::new(KEY.to_vec());
        let text = b"a fixture~~~model~key b 666978747572657e7e7e6d6f64656c7e6b6579 c \
            666978747572657E7E7E6D6F64656C7E6B6579 d Zml4dHVyZX5+fm1vZGVsfmtleQ== e \
            Zml4dHVyZX5-fm1vZGVsfmtleQ== f sk-ant-api03-abc_DEF-9 g";
        let redacted = String::from_utf8(forms.redact(text)).expect("utf-8 output");
        for form in ["fixture", "666978", "6669", "Zml4dHVy", "sk-ant-"] {
            assert!(!redacted.contains(form), "{form} survived: {redacted}");
        }
        assert!(redacted.contains("[redacted]"));
    }

    #[test]
    fn a_key_in_each_form_is_carried_and_clean_text_is_not() {
        let forms = Forms::new(KEY.to_vec());
        assert!(forms.carried_by(b"x fixture~~~model~key y"));
        assert!(forms.carried_by(b"x Zml4dHVyZX5+fm1vZGVsfmtleQ== y"));
        assert!(forms.carried_by(b"x ANTHROPIC_API_KEY=Zml4dHVyZX5+fm1vZGVsfmtleQ== y"));
        assert!(!forms.carried_by(b"pub fn a() -> u8 { 1 }\n"));
    }

    /// The key's last group has no padding. The 19 bytes of the key are 26 characters of unpadded
    /// base64, and the last two characters decode to the final byte. The scan must read that group,
    /// in either alphabet, and after a one-byte prefix that makes the run 27 characters long.
    #[test]
    fn an_unpadded_base64_key_at_the_end_of_a_run_is_carried() {
        let forms = Forms::new(KEY.to_vec());
        assert!(forms.carried_by(b"const X: &str = \"Zml4dHVyZX5+fm1vZGVsfmtleQ\";\n"));
        assert!(forms.carried_by(b"Zml4dHVyZX5-fm1vZGVsfmtleQ"));
        assert!(forms.carried_by(b"x eGZpeHR1cmV+fn5tb2RlbH5rZXk y"));
    }

    /// A run that holds the key at an alignment where CPython's decoder raises "Incorrect padding"
    /// (the "-" is skipped in the standard pass, which leaves a partial group). The original scan missed
    /// the key here, and this scan must find it.
    #[test]
    fn a_key_at_an_alignment_that_cpython_rejects_is_still_found() {
        let forms = Forms::new(b"k3y-with_chars+/=~".to_vec());
        assert!(forms.carried_by(b"mmtjTbihTBDyNrd3hd4rximxazN5LXdpdGhfY2hhcnMrLz-1+GHfvr6SYzczz"));
    }

    #[test]
    fn a_path_is_printed_as_python_prints_it() {
        assert_eq!(render_path(b"src/lib.rs"), "src/lib.rs");
        assert_eq!(render_path(b"a\xffb\xc3\xa9"), "a\\udcffbé");
    }

    #[test]
    fn an_os_error_is_described_without_its_code() {
        let source = io::Error::from_raw_os_error(13);
        assert_eq!(strerror(&source), "Permission denied");
    }

    #[test]
    fn replacing_sk_ant_keys_needs_a_tail_after_the_prefix() {
        assert_eq!(replace_sk_ant_keys(b"sk-ant-"), b"sk-ant-");
        assert_eq!(replace_sk_ant_keys(b"x sk-ant-a_1-b y"), b"x [redacted] y");
    }
}
