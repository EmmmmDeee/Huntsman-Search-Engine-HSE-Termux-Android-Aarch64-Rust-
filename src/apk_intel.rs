//! Offline, bounded Android APK archive inventory.
//!
//! Parses ZIP central-directory and local-file headers without extraction or execution.
//! Reports observed archive facts, never certificate validity, package authorship or
//! interpreted DEX/manifest contents. No decompression, network, root or new dependencies.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity, scan_id};
use crate::error::Error;
use crate::sha256::{hex32, sha256};
use crate::source_outcome::SourceExecutionOutcome;

pub const SOURCE: &str = "apk_intel";
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 8192;
const MAX_LISTED: usize = 32;
const EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";
const APK_SIG_MAGIC: &[u8] = b"APK Sig Block 42";

pub const APK_HELP: &str = "apk FILE [--json]\nInspect one local Android APK offline. Read at most 64 MiB, refuse symlinks, validate ZIP directory and local headers, inventory DEX files and native ABIs, count compressed/encrypted entries, and identify signing artifacts and APK v2/v3 signing-block IDs (presence only, NOT signature verification). Emit the SHA-256 of exact input bytes and provenance-bearing document evidence. No decompression, certificate validation, code execution, network request or root. A name in an archive is not proof of valid code or ownership.";

#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub sha256: String,
    pub file_size_bytes: usize,
    pub entries: usize,
    pub android_manifest_present: bool,
    pub dex_count: usize,
    pub dex_files: Vec<String>,
    pub dex_files_omitted: usize,
    pub native_library_count: usize,
    pub native_abis: Vec<String>,
    pub v1_signing_artifacts: Vec<String>,
    pub v1_signing_artifacts_omitted: usize,
    pub apk_signing_block_present: bool,
    pub signing_scheme_ids_detected_unverified: Vec<String>,
    pub compressed_entries: usize,
    pub encrypted_entries: usize,
    pub suspicious_paths: usize,
    pub limitations: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub inventory: Inventory,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

fn le16(data: &[u8], at: usize) -> Option<u16> {
    let field = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

fn le32(data: &[u8], at: usize) -> Option<u32> {
    let field = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn le64(data: &[u8], at: usize) -> Option<u64> {
    let field = data.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(field.try_into().ok()?))
}

fn checked_range(data: &[u8], at: usize, size: usize) -> Option<&[u8]> {
    data.get(at..at.checked_add(size)?)
}

/// Find the last complete ZIP EOCD record. The comment length must end at EOF.
fn eocd(data: &[u8]) -> Result<usize, Error> {
    if data.len() < 22 {
        return Err(Error::invalid_value(
            "APK is too short for a ZIP end record",
        ));
    }
    let start = data.len().saturating_sub(22 + 65535);
    for pos in (start..=data.len() - 22).rev() {
        if checked_range(data, pos, 4) == Some(EOCD_SIGNATURE)
            && le16(data, pos + 20).is_some_and(|len| usize::from(len) == data.len() - pos - 22)
        {
            return Ok(pos);
        }
    }
    Err(Error::invalid_value("missing complete ZIP end record"))
}

fn dex_name(name: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix("classes")
        .and_then(|s| s.strip_suffix(".dex"))
    else {
        return false;
    };
    suffix.is_empty() || suffix.bytes().all(|c| c.is_ascii_digit())
}

fn suspicious(name: &str) -> bool {
    name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.split('/').any(|part| part == "..")
}

#[derive(Default)]
struct SigningBlock {
    present: bool,
    schemes: BTreeSet<&'static str>,
}

/// Inspect *structural* signing IDs. A matching ID is never a verified signature.
fn signing_block(data: &[u8], central_at: usize) -> SigningBlock {
    let mut found = SigningBlock::default();
    let Some(footer_at) = central_at.checked_sub(24) else {
        return found;
    };
    if checked_range(data, central_at - 16, 16) != Some(APK_SIG_MAGIC) {
        return found;
    }
    let Some(size) = le64(data, footer_at).and_then(|n| usize::try_from(n).ok()) else {
        return found;
    };
    let Some(total) = size.checked_add(8) else {
        return found;
    };
    let Some(start) = central_at.checked_sub(total) else {
        return found;
    };
    let Ok(size_u64) = u64::try_from(size) else {
        return found;
    };
    if size < 24 || le64(data, start) != Some(size_u64) || start + 8 > footer_at {
        return found;
    }
    let mut pos = start + 8;
    while pos < footer_at {
        let Some(item_len) = le64(data, pos).and_then(|n| usize::try_from(n).ok()) else {
            return SigningBlock::default();
        };
        let Some(next) = pos.checked_add(8).and_then(|x| x.checked_add(item_len)) else {
            return SigningBlock::default();
        };
        if item_len < 4 || next > footer_at {
            return SigningBlock::default();
        }
        let Some(id) = le32(data, pos + 8) else {
            return SigningBlock::default();
        };
        match id {
            0x7109_871a => {
                found.schemes.insert("v2");
            }
            0xf053_68c0 => {
                found.schemes.insert("v3");
            }
            0x1b93_ad61 => {
                found.schemes.insert("v3.1");
            }
            _ => {}
        }
        pos = next;
    }
    found.present = pos == footer_at;
    found
}

/// One archive member verified against both its central and local ZIP headers.
struct Member<'a> {
    name: &'a str,
    flags: u16,
    method: u16,
    next: usize,
}

fn member<'a>(
    data: &'a [u8],
    pos: usize,
    dir_start: usize,
    dir_end: usize,
) -> Result<Member<'a>, Error> {
    if checked_range(data, pos, 4) != Some(CENTRAL_SIGNATURE) {
        return Err(Error::invalid_value("invalid ZIP central directory entry"));
    }
    let flags = le16(data, pos + 8).ok_or_else(|| Error::invalid_value("truncated ZIP flags"))?;
    let method =
        le16(data, pos + 10).ok_or_else(|| Error::invalid_value("truncated ZIP compression"))?;
    let packed = usize::try_from(
        le32(data, pos + 20).ok_or_else(|| Error::invalid_value("missing compressed size"))?,
    )
    .map_err(|_| Error::invalid_value("compressed size overflow"))?;
    let name_len = usize::from(
        le16(data, pos + 28).ok_or_else(|| Error::invalid_value("missing ZIP name size"))?,
    );
    let extra = usize::from(
        le16(data, pos + 30).ok_or_else(|| Error::invalid_value("missing ZIP extra size"))?,
    );
    let comment = usize::from(
        le16(data, pos + 32).ok_or_else(|| Error::invalid_value("missing ZIP comment size"))?,
    );
    let local_at = usize::try_from(
        le32(data, pos + 42).ok_or_else(|| Error::invalid_value("missing local offset"))?,
    )
    .map_err(|_| Error::invalid_value("local offset overflow"))?;
    let name_at = pos
        .checked_add(46)
        .ok_or_else(|| Error::invalid_value("ZIP name offset overflow"))?;
    let raw = checked_range(data, name_at, name_len)
        .ok_or_else(|| Error::invalid_value("truncated ZIP entry name"))?;
    let name =
        std::str::from_utf8(raw).map_err(|_| Error::invalid_value("non UTF-8 APK entry name"))?;
    let next = name_at
        .checked_add(name_len)
        .and_then(|n| n.checked_add(extra))
        .and_then(|n| n.checked_add(comment))
        .ok_or_else(|| Error::invalid_value("ZIP entry overflow"))?;
    if next > dir_end {
        return Err(Error::invalid_value("ZIP entry exceeds directory boundary"));
    }
    if checked_range(data, local_at, 4) != Some(LOCAL_SIGNATURE) {
        return Err(Error::invalid_value("ZIP entry has invalid local header"));
    }
    let local_name_len = usize::from(
        le16(data, local_at + 26).ok_or_else(|| Error::invalid_value("missing local name"))?,
    );
    let local_extra_len = usize::from(
        le16(data, local_at + 28).ok_or_else(|| Error::invalid_value("missing local extra"))?,
    );
    let local_name_at = local_at
        .checked_add(30)
        .ok_or_else(|| Error::invalid_value("local header overflow"))?;
    if checked_range(data, local_name_at, local_name_len) != Some(raw) {
        return Err(Error::invalid_value(
            "central/local ZIP entry names disagree",
        ));
    }
    let payload_end = local_name_at
        .checked_add(local_name_len)
        .and_then(|n| n.checked_add(local_extra_len))
        .and_then(|n| n.checked_add(packed))
        .ok_or_else(|| Error::invalid_value("ZIP payload range overflow"))?;
    if payload_end > dir_start {
        return Err(Error::invalid_value(
            "ZIP payload exceeds start of central directory",
        ));
    }
    Ok(Member {
        name,
        flags,
        method,
        next,
    })
}

/// Inspect ZIP metadata only. No untrusted payload is decompressed or executed.
///
/// # Errors
/// Malformed, multi-disk or ZIP64 archives, invalid local-header offsets, or archives
/// with over 8,192 entries are explicitly refused, not interpreted partially.
pub fn inventory(data: &[u8]) -> Result<Inventory, Error> {
    let end = eocd(data)?;
    let disks = (le16(data, end + 4), le16(data, end + 6));
    if disks != (Some(0), Some(0)) {
        return Err(Error::invalid_value(
            "multi-disk ZIP archives are unsupported",
        ));
    }
    let count = le16(data, end + 10).ok_or_else(|| Error::invalid_value("missing ZIP count"))?;
    if le16(data, end + 8) != Some(count) {
        return Err(Error::invalid_value("inconsistent ZIP entry counts"));
    }
    let size =
        le32(data, end + 12).ok_or_else(|| Error::invalid_value("missing ZIP directory size"))?;
    let start =
        le32(data, end + 16).ok_or_else(|| Error::invalid_value("missing ZIP directory offset"))?;
    if count == u16::MAX || size == u32::MAX || start == u32::MAX {
        return Err(Error::invalid_value("ZIP64 APK archives are unsupported"));
    }
    let count = usize::from(count);
    if count == 0 || count > MAX_ENTRIES {
        return Err(Error::invalid_value(
            "empty APK or APK exceeds 8192 ZIP entries",
        ));
    }
    let dir_start =
        usize::try_from(start).map_err(|_| Error::invalid_value("directory offset overflow"))?;
    let dir_end = dir_start
        .checked_add(
            usize::try_from(size).map_err(|_| Error::invalid_value("directory size overflow"))?,
        )
        .ok_or_else(|| Error::invalid_value("directory range overflow"))?;
    if dir_end > end {
        return Err(Error::invalid_value(
            "ZIP directory extends beyond end record",
        ));
    }

    let mut pos = dir_start;
    let mut manifest = false;
    let mut dex = Vec::new();
    let mut dex_count = 0_usize;
    let mut native_count = 0_usize;
    let mut abis = BTreeSet::new();
    let mut v1 = Vec::new();
    let mut v1_count = 0_usize;
    let mut compressed = 0_usize;
    let mut encrypted = 0_usize;
    let mut unsafe_paths = 0_usize;

    for _ in 0..count {
        let entry = member(data, pos, dir_start, dir_end)?;
        pos = entry.next;
        let Member {
            name,
            flags,
            method,
            ..
        } = entry;
        if method != 0 {
            compressed += 1;
        }
        if flags & 1 != 0 {
            encrypted += 1;
        }
        if suspicious(name) {
            unsafe_paths += 1;
        }
        if name == "AndroidManifest.xml" {
            manifest = true;
        }
        if dex_name(name) {
            dex_count += 1;
            if dex.len() < MAX_LISTED {
                dex.push(name.to_owned());
            }
        }
        if let Some((abi, filename)) = name
            .strip_prefix("lib/")
            .and_then(|rest| rest.split_once('/'))
        {
            if !abi.is_empty() && !filename.contains('/') && filename.ends_with(".so") {
                native_count += 1;
                abis.insert(abi.to_owned());
            }
        }
        if let Some(name_without_prefix) = name.strip_prefix("META-INF/") {
            if !name_without_prefix.contains('/')
                && [".RSA", ".DSA", ".EC", ".SF"]
                    .iter()
                    .any(|extension| name_without_prefix.ends_with(extension))
            {
                v1_count += 1;
                if v1.len() < MAX_LISTED {
                    v1.push(name.to_owned());
                }
            }
        }
    }
    if pos != dir_end {
        return Err(Error::invalid_value(
            "ZIP entry count does not match directory size",
        ));
    }
    if !manifest {
        return Err(Error::invalid_value("archive has no AndroidManifest.xml"));
    }
    let sig = signing_block(data, dir_start);
    Ok(Inventory {
        sha256: hex32(&sha256(data)),
        file_size_bytes: data.len(),
        entries: count,
        android_manifest_present: manifest,
        dex_count,
        dex_files_omitted: dex_count - dex.len(),
        dex_files: dex,
        native_library_count: native_count,
        native_abis: abis.into_iter().collect(),
        v1_signing_artifacts_omitted: v1_count - v1.len(),
        v1_signing_artifacts: v1,
        apk_signing_block_present: sig.present,
        signing_scheme_ids_detected_unverified: if sig.present {
            sig.schemes.into_iter().map(str::to_owned).collect()
        } else {
            Vec::new()
        },
        compressed_entries: compressed,
        encrypted_entries: encrypted,
        suspicious_paths: unsafe_paths,
        limitations: "Archive metadata only; embedded file bytes, DEX code, Android manifest content, and certificate signatures are not decoded or verified.",
    })
}

/// Wrap archive observations in the existing Huntsman evidence contract.
///
/// # Errors
/// Returns a structured input error for invalid or unsupported APK archives.
pub fn run(data: &[u8], label: &str, now_unix: u64) -> Result<Report, Error> {
    let inventory = inventory(data)?;
    let sid = scan_id(SOURCE, label);
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, sid.as_str()),
        format!("Offline ZIP inventory of Android application archive {label}"),
    )
    .with_attr("file_sha256", inventory.sha256.as_str())
    .with_attr("file_hash_scope", "exact_input_bytes")
    .with_attr("file_size_bytes", inventory.file_size_bytes.to_string())
    .with_attr("apk_zip_entries", inventory.entries.to_string())
    .with_attr("apk_dex_count", inventory.dex_count.to_string())
    .with_attr(
        "apk_native_libraries",
        inventory.native_library_count.to_string(),
    )
    .with_attr("apk_native_abis", inventory.native_abis.join(","))
    .with_attr(
        "apk_signing_block_detected_unverified",
        inventory.apk_signing_block_present.to_string(),
    )
    .with_attr(
        "apk_compressed_entries",
        inventory.compressed_entries.to_string(),
    )
    .with_attr(
        "apk_encrypted_entries",
        inventory.encrypted_entries.to_string(),
    )
    .with_attr(
        "apk_suspicious_paths",
        inventory.suspicious_paths.to_string(),
    );
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Document,
        label,
        0.9,
        sid.as_str(),
        evidence,
        &[SOURCE, "offline", "apk"],
    );
    Ok(Report {
        inventory,
        outcomes: vec![SourceExecutionOutcome::success(
            SOURCE,
            now_unix,
            entities.len(),
        )],
        entities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(buf: &mut [u8], at: usize, value: u16) {
        buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn sample(names: &[&str]) -> Vec<u8> {
        let mut zip = Vec::new();
        let mut central = Vec::new();
        for name in names {
            let at = u32::try_from(zip.len()).unwrap();
            let len = u16::try_from(name.len()).unwrap();
            let base = zip.len();
            zip.resize(base + 30, 0);
            zip[base..base + 4].copy_from_slice(LOCAL_SIGNATURE);
            put16(&mut zip, base + 26, len);
            zip.extend_from_slice(name.as_bytes());
            let base = central.len();
            central.resize(base + 46, 0);
            central[base..base + 4].copy_from_slice(CENTRAL_SIGNATURE);
            put16(&mut central, base + 28, len);
            put32(&mut central, base + 42, at);
            central.extend_from_slice(name.as_bytes());
        }
        let dir_at = u32::try_from(zip.len()).unwrap();
        let dir_size = u32::try_from(central.len()).unwrap();
        zip.extend_from_slice(&central);
        let base = zip.len();
        zip.resize(base + 22, 0);
        zip[base..base + 4].copy_from_slice(EOCD_SIGNATURE);
        put16(&mut zip, base + 8, u16::try_from(names.len()).unwrap());
        put16(&mut zip, base + 10, u16::try_from(names.len()).unwrap());
        put32(&mut zip, base + 12, dir_size);
        put32(&mut zip, base + 16, dir_at);
        zip
    }

    #[test]
    fn indexes_apk_without_decompression_or_network() {
        let data = sample(&[
            "AndroidManifest.xml",
            "classes.dex",
            "classes2.dex",
            "lib/arm64-v8a/libprobe.so",
            "META-INF/APP.RSA",
        ]);
        let result = inventory(&data).unwrap();
        assert_eq!(result.entries, 5);
        assert_eq!(result.dex_count, 2);
        assert_eq!(result.native_abis, ["arm64-v8a"]);
        assert_eq!(result.v1_signing_artifacts, ["META-INF/APP.RSA"]);
        assert!(result.signing_scheme_ids_detected_unverified.is_empty());
        assert_eq!(result.sha256, hex32(&sha256(&data)));
        let report = run(&data, "sample.apk", 100).unwrap();
        assert_eq!(report.entities.len(), 1);
        assert_eq!(report.outcomes.len(), 1);
    }

    #[test]
    fn refuses_missing_manifest_and_fake_local_headers() {
        let a = sample(&["classes.dex"]);
        assert!(inventory(&a).is_err());
        let mut b = sample(&["AndroidManifest.xml"]);
        b[0] = 0;
        assert!(inventory(&b).is_err());
    }

    #[test]
    fn refuses_truncation_and_suspicious_member_names_are_counted() {
        let data = sample(&["AndroidManifest.xml", "../other"]);
        assert_eq!(inventory(&data).unwrap().suspicious_paths, 1);
        for len in 0..data.len() {
            assert!(inventory(&data[..len]).is_err(), "truncation at {len}");
        }
    }

    #[test]
    fn rejects_multidisk_and_zip64_markers() {
        let mut a = sample(&["AndroidManifest.xml"]);
        let end = a.len() - 22;
        put16(&mut a, end + 4, 1);
        assert!(inventory(&a).is_err());
        put16(&mut a, end + 4, 0);
        put16(&mut a, end + 10, u16::MAX);
        assert!(inventory(&a).is_err());
    }
    #[test]
    fn signature_ids_are_structural_indicators_not_verified_signatures() {
        let mut bytes = sample(&["AndroidManifest.xml"]);
        let old_directory = usize::try_from(le32(&bytes, bytes.len() - 22 + 16).unwrap()).unwrap();
        let mut block = Vec::new();
        block.extend_from_slice(&36_u64.to_le_bytes());
        block.extend_from_slice(&4_u64.to_le_bytes());
        block.extend_from_slice(&0x7109_871a_u32.to_le_bytes());
        block.extend_from_slice(&36_u64.to_le_bytes());
        block.extend_from_slice(APK_SIG_MAGIC);
        assert_eq!(block.len(), 44);
        bytes.splice(old_directory..old_directory, block);
        let end = bytes.len() - 22;
        put32(
            &mut bytes,
            end + 16,
            u32::try_from(old_directory + 44).unwrap(),
        );
        let parsed = inventory(&bytes).unwrap();
        assert!(parsed.apk_signing_block_present);
        assert_eq!(parsed.signing_scheme_ids_detected_unverified, ["v2"]);
        // Corrupt the first length copy: a signature-looking magic alone does not count.
        bytes[old_directory] ^= 1;
        let parsed = inventory(&bytes).unwrap();
        assert!(!parsed.apk_signing_block_present);
    }
}
