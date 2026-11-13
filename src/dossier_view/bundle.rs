//! Verify the extracted dossier bundle against its register and SHA-256 manifest.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path};

use serde::Serialize;
use serde_json::Value;

use super::{Dossier, DossierError, GROUPS, MAX_DOSSIER_BYTES, json, open_regular};
use crate::html_text::{Markup, Piece, attribute};
use crate::sha256::{Sha256, hex32};

const MAX_FILES: usize = 256;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const REGISTER: &str = "register.json";
const MEDIA: &str = "media_manifest";
const AUDIT: &str = "audit_changes_2026_10_24";

/// Successful checks on an extracted bundle. Hashes attest to consistency with
/// the supplied manifests. The manifest itself has no signature or trust root.
#[derive(Serialize)]
pub struct BundleReport {
    pub register_sha256: String,
    pub indexed_records: usize,
    pub checksummed_files: usize,
    pub verified_media: usize,
    pub verified_csv_tables: usize,
    pub verified_html_anchors: usize,
}

pub struct VerifiedBundle {
    pub dossier: Dossier,
    pub report: BundleReport,
}

fn invalid(message: impl Into<String>) -> DossierError {
    DossierError::Invalid(message.into())
}

/// Cross-check the register, its CSV and HTML projections, the original media
/// bytes, and every file listed by the extracted bundle's checksum manifest.
pub fn verify_bundle(root: &Path) -> Result<VerifiedBundle, DossierError> {
    let manifest_path = member_path(root, "SHA256SUMS.txt")?;
    let bytes = crate::fsio::read_bounded(&manifest_path, MAX_DOSSIER_BYTES)
        .map_err(|error| invalid(error.to_string()))?;
    let manifest = parse_manifest(&bytes)?;

    // Only retain the bounded text inputs needed for cross-checks. Media and
    // historical artifacts are hashed in a fixed-size buffer.
    let mut documents = BTreeMap::new();
    let mut checked = BTreeMap::new();
    let mut budget = MAX_BUNDLE_BYTES;
    for (&name, &expected) in &manifest {
        let path = member_path(root, name)?;
        let keep = matches!(
            name,
            REGISTER
                | "index.html"
                | "binary_verification.json"
                | "media_manifest.csv"
                | "audit_changes_2026_10_24.csv"
        ) || name
            .strip_suffix(".csv")
            .is_some_and(|key| GROUPS.iter().any(|(group, _)| key == *group));
        let (size, digest) = if keep {
            let body = crate::fsio::read_bounded(&path, MAX_DOSSIER_BYTES.min(budget))
                .map_err(|error| invalid(error.to_string()))?;
            let result = (body.len() as u64, hex32(&crate::sha256::sha256(&body)));
            documents.insert(name, body);
            result
        } else {
            hash_member(&path, MAX_MEMBER_BYTES.min(budget))?
        };
        if !digest.eq_ignore_ascii_case(expected) {
            return Err(invalid(format!("checksum mismatch for {name}")));
        }
        budget -= size;
        checked.insert(name, (size, digest));
    }

    let dossier = Dossier::from_bytes(
        documents
            .remove(REGISTER)
            .ok_or_else(|| invalid("manifest omits register.json"))?,
    )?;
    let index = text(required(&documents, "index.html")?, "index.html")?;
    let anchors = verify_anchors(index, &dossier.ids)?;

    let verification = json::parse(required(&documents, "binary_verification.json")?)
        .map_err(|error| invalid(format!("binary_verification.json: {error}")))?;
    if dossier.root.get("binary_verification_2026_10_24") != Some(&verification) {
        return Err(invalid(
            "binary verification metadata differs from the register",
        ));
    }

    let mut tables = 0;
    for group in GROUPS
        .map(|(group, _)| group)
        .into_iter()
        .chain([AUDIT, MEDIA])
    {
        let csv = format!("{group}.csv");
        let table = text(required(&documents, &csv)?, &csv)?;
        let rows = dossier
            .root
            .get(group)
            .and_then(Value::as_array)
            .ok_or_else(|| invalid(format!("missing register table {group}")))?;
        verify_csv(table, group, rows)?;
        tables += 1;
    }
    let media = dossier.root[MEDIA]
        .as_array()
        .expect("CSV verification checked the media array");
    verify_media(media, &checked)?;
    let report = BundleReport {
        register_sha256: dossier.sha256(),
        indexed_records: dossier.record_count(),
        checksummed_files: checked.len(),
        verified_media: media.len(),
        verified_csv_tables: tables,
        verified_html_anchors: anchors,
    };
    Ok(VerifiedBundle { dossier, report })
}

fn verify_anchors(index: &str, ids: &BTreeSet<String>) -> Result<usize, DossierError> {
    let mut anchored = BTreeSet::new();
    let anchors = Markup::new(index).filter_map(|piece| match piece {
        Piece::Tag {
            end: false, attrs, ..
        } => attribute(attrs, "id"),
        _ => None,
    });
    for id in anchors.filter(|id| ids.contains(*id)) {
        if !anchored.insert(id) {
            return Err(invalid(format!("duplicate HTML evidence anchor {id}")));
        }
    }
    if anchored.len() != ids.len() {
        return Err(invalid("HTML index is missing evidence anchors"));
    }
    Ok(anchored.len())
}

fn required<'a>(
    documents: &'a BTreeMap<&str, Vec<u8>>,
    name: &str,
) -> Result<&'a [u8], DossierError> {
    documents
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(format!("manifest omits {name}")))
}

fn text<'a>(bytes: &'a [u8], name: &str) -> Result<&'a str, DossierError> {
    std::str::from_utf8(bytes).map_err(|_| invalid(format!("{name} is not UTF-8")))
}

fn parse_manifest(bytes: &[u8]) -> Result<BTreeMap<&str, &str>, DossierError> {
    let mut entries = BTreeMap::new();
    for line in text(bytes, "SHA256SUMS.txt")?.lines() {
        let (digest, name) = line
            .split_once("  ")
            .filter(|(digest, name)| valid_digest(digest) && valid_member(name))
            .ok_or_else(|| invalid("invalid SHA256SUMS.txt entry"))?;
        if entries.insert(name, digest).is_some() {
            return Err(invalid(format!("duplicate manifest member {name}")));
        }
        if entries.len() > MAX_FILES {
            return Err(invalid("checksum manifest has too many files"));
        }
    }
    Ok(entries)
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_member(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 512
        && !name.contains(['\\', ':'])
        && !name.chars().any(char::is_control)
        && name.split('/').all(|part| !matches!(part, "" | "." | ".."))
        && Path::new(name)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn member_path(root: &Path, name: &str) -> Result<std::path::PathBuf, DossierError> {
    let mut path = root.to_path_buf();
    check_directory(&path)?;
    let mut parts = name.split('/').peekable();
    while let Some(part) = parts.next() {
        path.push(part);
        if parts.peek().is_some() {
            check_directory(&path)?;
        }
    }
    Ok(path)
}

fn check_directory(path: &Path) -> Result<(), DossierError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("cannot inspect {}: {error}", path.display())))?;
    if !meta.is_dir() {
        return Err(invalid(format!(
            "expected a real directory at {}",
            path.display()
        )));
    }
    Ok(())
}

fn hash_member(path: &Path, limit: u64) -> Result<(u64, String), DossierError> {
    let mut reader = open_regular(path)?.take(limit + 1);
    let mut digest = Sha256::new();
    let mut size = 0;
    let mut chunk = [0; 16 * 1024];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|error| invalid(format!("cannot read {}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > limit {
            return Err(invalid(format!(
                "{} exceeds the bundle byte budget",
                path.display()
            )));
        }
        digest.update(&chunk[..read]);
    }
    Ok((size, hex32(&digest.finalize())))
}

fn verify_media(
    rows: &[Value],
    checked: &BTreeMap<&str, (u64, String)>,
) -> Result<(), DossierError> {
    let mut names = BTreeSet::new();
    for row in rows {
        let name = row["filename"]
            .as_str()
            .filter(|name| valid_member(name) && !name.contains('/'))
            .ok_or_else(|| invalid("invalid media filename"))?;
        if !names.insert(name) {
            return Err(invalid(format!("duplicate media filename {name}")));
        }
        let path = format!("media/{name}");
        let (size, hash) = checked
            .get(path.as_str())
            .ok_or_else(|| invalid(format!("manifest omits {path}")))?;
        if row["bytes"].as_u64() != Some(*size)
            || !row["sha256"]
                .as_str()
                .is_some_and(|expected| hash.eq_ignore_ascii_case(expected))
        {
            return Err(invalid(format!(
                "register media size or SHA-256 mismatch for {name}"
            )));
        }
    }
    if checked
        .keys()
        .filter(|name| name.starts_with("media/"))
        .count()
        != names.len()
    {
        return Err(invalid(
            "manifest lists media that the register does not describe",
        ));
    }
    Ok(())
}

fn verify_csv(input: &str, group: &str, records: &[Value]) -> Result<(), DossierError> {
    let rows = crate::rf::survey_csv::csv_rows(input)
        .map_err(|error| invalid(format!("{group}.csv: {error}")))?;
    let (header, rows) = rows
        .split_first()
        .ok_or_else(|| invalid(format!("{group}.csv has no header")))?;
    let headers: BTreeSet<_> = header.iter().map(String::as_str).collect();
    if rows.len() != records.len() || headers.len() != header.len() || headers.contains("") {
        return Err(invalid(format!(
            "{group}.csv has a row count or header mismatch"
        )));
    }
    for (index, (row, record)) in rows.iter().zip(records).enumerate() {
        let Some(fields) = record.as_object() else {
            return Err(invalid(format!(
                "invalid object in {group} at record {}",
                index + 1
            )));
        };
        if row.len() != header.len() || fields.keys().any(|key| !headers.contains(key.as_str())) {
            return Err(invalid(format!(
                "{group}.csv has missing or extra cells at row {}",
                index + 2
            )));
        }
        for (name, cell) in header.iter().zip(row) {
            if !csv_cell_matches(name, cell, fields.get(name)) {
                return Err(invalid(format!(
                    "{group}.csv differs in {name} at row {}",
                    index + 2
                )));
            }
        }
    }
    Ok(())
}

fn csv_cell_matches(name: &str, cell: &str, value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => cell.is_empty(),
        Some(Value::String(value)) => cell == value,
        Some(Value::Bool(value)) => cell == if *value { "True" } else { "False" },
        Some(Value::Number(value)) => cell == value.to_string(),
        Some(Value::Array(items)) if name == "mp4_top_level_boxes" => {
            // The legacy CSV uses Python repr for boxes; compare its fixed
            // structural fields without interpreting or executing that text.
            let mut expected = Vec::new();
            for item in items {
                let (Some(kind), Some(offset), Some(length)) = (
                    item["type"].as_str(),
                    item["offset"].as_u64(),
                    item["length"].as_u64(),
                ) else {
                    return false;
                };
                let payload = item["payload_hex"]
                    .as_str()
                    .map_or_else(String::new, |hex| format!(", 'payload_hex': '{hex}'"));
                expected.push(format!(
                    "{{'type': '{kind}', 'offset': {offset}, 'length': {length}{payload}}}"
                ));
            }
            cell == format!("[{}]", expected.join(", "))
        }
        Some(Value::Array(_)) if name == "dimensions" => {
            serde_json::from_str::<Value>(cell).is_ok_and(|csv| Some(&csv) == value)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_refuses_traversal_and_duplicate_paths() {
        let hash = "a".repeat(64);
        for path in [
            "../register.json",
            "media//file",
            "/media/file",
            "media/./file",
            "media\\file",
        ] {
            assert!(parse_manifest(format!("{hash}  {path}\n").as_bytes()).is_err());
        }
        assert!(
            parse_manifest(format!("{hash}  index.html\n{hash}  index.html\n").as_bytes()).is_err()
        );
    }

    #[test]
    fn html_checks_actual_anchors() {
        let ids = BTreeSet::from(["E01".to_owned()]);
        assert!(verify_anchors(r#"<article id="E01"></article>"#, &ids).is_ok());
        assert!(verify_anchors(r#"<!-- <article id="E01"></article> -->"#, &ids).is_err());
        assert!(verify_anchors(r#"<p data-id="E01"></p>"#, &ids).is_err());
        assert!(verify_anchors(r#"<p id="E01"></p><p id='E01'></p>"#, &ids).is_err());
    }

    #[test]
    fn csv_checks_fields_instead_of_only_counting_rows() {
        let rows = [serde_json::json!({"id":"E01","finding":"one, two\nthree"})];
        assert!(verify_csv("id,finding\r\nE01,\"one, two\nthree\"\r\n", "claims", &rows).is_ok());
        assert!(verify_csv("id,finding\nE01,changed\n", "claims", &rows).is_err());
        assert!(verify_csv("id,id\nE01,E01\n", "claims", &rows).is_err());
    }
}
