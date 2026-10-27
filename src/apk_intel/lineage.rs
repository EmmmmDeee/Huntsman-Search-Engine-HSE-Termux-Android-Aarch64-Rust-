//! Offline structural comparison of two APK ZIP archives.
//! Stored-byte changes are observations, not signatures, decoded semantics or attribution.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{
    Error, checked_range, dex_name, directory_bounds, hex32, is_v1_signing_artifact, le32, member,
    native_abi, sha256,
};

const MAX_REPORTED_CHANGES: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct MemberChange {
    pub path: String,
    pub component: &'static str,
    pub disposition: &'static str,
    pub old_stored_sha256: Option<String>,
    pub new_stored_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub old_sha256: String,
    pub new_sha256: String,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub unchanged: usize,
    pub changes: Vec<MemberChange>,
    pub omitted_changes: usize,
    pub archive_bytes_differ: bool,
    pub metadata_or_signing_block_diff_possible: bool,
    pub limitations: &'static str,
}

#[derive(PartialEq, Eq)]
struct Fingerprint {
    stored_sha256: [u8; 32],
    method: u16,
    flags: u16,
    crc32: u32,
    unpacked_size: u32,
}

fn component(name: &str) -> &'static str {
    if name == "AndroidManifest.xml" {
        "manifest"
    } else if dex_name(name) {
        "dex"
    } else if native_abi(name).is_some() {
        "native_library"
    } else if is_v1_signing_artifact(name) {
        "v1_signing_artifact"
    } else if name == "resources.arsc" || name.starts_with("res/") {
        "resources"
    } else if name.starts_with("assets/") {
        "assets"
    } else {
        "other"
    }
}

fn fingerprints(data: &[u8]) -> Result<BTreeMap<String, Fingerprint>, Error> {
    let (count, dir_start, dir_end) = directory_bounds(data)?;
    let mut pos = dir_start;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let at = pos;
        let entry = member(data, at, dir_start, dir_end)?;
        pos = entry.next;
        let crc32 = le32(data, at + 16).ok_or_else(|| Error::invalid_value("missing ZIP CRC32"))?;
        let unpacked_size = le32(data, at + 24)
            .ok_or_else(|| Error::invalid_value("missing ZIP uncompressed size"))?;
        let stored = checked_range(data, entry.payload_start, entry.payload_len)
            .ok_or_else(|| Error::invalid_value("invalid ZIP member payload"))?;
        let fingerprint = Fingerprint {
            stored_sha256: sha256(stored),
            method: entry.method,
            flags: entry.flags,
            crc32,
            unpacked_size,
        };
        if entries.insert(entry.name.to_owned(), fingerprint).is_some() {
            return Err(Error::invalid_value("ambiguous duplicate APK member names"));
        }
    }
    if pos != dir_end {
        return Err(Error::invalid_value(
            "ZIP entry count does not match directory size",
        ));
    }
    if !entries.contains_key("AndroidManifest.xml") {
        return Err(Error::invalid_value("archive has no AndroidManifest.xml"));
    }
    Ok(entries)
}

fn changed(name: &str, before: Option<&Fingerprint>, after: Option<&Fingerprint>) -> MemberChange {
    MemberChange {
        path: name.to_owned(),
        component: component(name),
        disposition: match (before, after) {
            (None, Some(_)) => "added",
            (Some(_), None) => "removed",
            (Some(_), Some(_)) => "modified",
            (None, None) => unreachable!("a union key must exist on one side"),
        },
        old_stored_sha256: before.map(|entry| hex32(&entry.stored_sha256)),
        new_stored_sha256: after.map(|entry| hex32(&entry.stored_sha256)),
    }
}

/// Compare two complete APK inputs without unpacking or executing archive contents.
///
/// Each member fingerprint includes exact *stored* bytes and selected untrusted ZIP metadata.
/// A modified fingerprint does not prove that decoded content, functionality or author changed.
/// ZIP metadata and signing blocks can differ even when all member fingerprints are identical.
///
/// # Errors
/// Invalid ZIP structures, ZIP64 and duplicate member names are rejected.
pub fn compare(old: &[u8], new: &[u8]) -> Result<Comparison, Error> {
    let previous = fingerprints(old)?;
    let current = fingerprints(new)?;
    let keys: BTreeSet<&str> = previous
        .keys()
        .chain(current.keys())
        .map(String::as_str)
        .collect();
    let mut added = 0_usize;
    let mut removed = 0_usize;
    let mut modified = 0_usize;
    let mut unchanged = 0_usize;
    let mut changes = Vec::new();
    let mut omitted_changes = 0_usize;

    for name in keys {
        let before = previous.get(name);
        let after = current.get(name);
        match (before, after) {
            (Some(a), Some(b)) if a == b => {
                unchanged += 1;
                continue;
            }
            (None, Some(_)) => added += 1,
            (Some(_), None) => removed += 1,
            (Some(_), Some(_)) => modified += 1,
            (None, None) => unreachable!("a union key must exist on one side"),
        }
        if changes.len() < MAX_REPORTED_CHANGES {
            changes.push(changed(name, before, after));
        } else {
            omitted_changes += 1;
        }
    }
    let old_sha256 = hex32(&sha256(old));
    let new_sha256 = hex32(&sha256(new));
    let archive_bytes_differ = old_sha256 != new_sha256;
    Ok(Comparison {
        old_sha256,
        new_sha256,
        added,
        removed,
        modified,
        unchanged,
        changes,
        omitted_changes,
        archive_bytes_differ,
        metadata_or_signing_block_diff_possible: archive_bytes_differ
            && added == 0
            && removed == 0
            && modified == 0,
        limitations: "Structural ZIP-member lineage only. Untrusted filenames, CRC and compression metadata; stored-byte digest is not decoded-content digest. Whole-archive-only differences can be ZIP metadata, alignment or signing blocks. No signature verification, DEX interpretation, authorship proof, malware verdict or code execution.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn apk(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut file = Vec::new();
        let mut central = Vec::new();
        for (name, payload) in members {
            let local_at = u32::try_from(file.len()).unwrap();
            let size = u32::try_from(payload.len()).unwrap();
            let name_len = u16::try_from(name.len()).unwrap();
            let base = file.len();
            file.resize(base + 30, 0);
            file[base..base + 4].copy_from_slice(b"PK\x03\x04");
            put32(&mut file, base + 18, size);
            put32(&mut file, base + 22, size);
            put16(&mut file, base + 26, name_len);
            file.extend_from_slice(name.as_bytes());
            file.extend_from_slice(payload);
            let base = central.len();
            central.resize(base + 46, 0);
            central[base..base + 4].copy_from_slice(b"PK\x01\x02");
            put32(&mut central, base + 20, size);
            put32(&mut central, base + 24, size);
            put16(&mut central, base + 28, name_len);
            put32(&mut central, base + 42, local_at);
            central.extend_from_slice(name.as_bytes());
        }
        let directory_at = u32::try_from(file.len()).unwrap();
        let directory_size = u32::try_from(central.len()).unwrap();
        file.extend_from_slice(&central);
        let end = file.len();
        file.resize(end + 22, 0);
        file[end..end + 4].copy_from_slice(b"PK\x05\x06");
        put16(&mut file, end + 8, u16::try_from(members.len()).unwrap());
        put16(&mut file, end + 10, u16::try_from(members.len()).unwrap());
        put32(&mut file, end + 12, directory_size);
        put32(&mut file, end + 16, directory_at);
        file
    }

    #[test]
    fn stable_order_and_changed_components() {
        let a = apk(&[
            ("AndroidManifest.xml", b"m1"),
            ("classes.dex", b"a"),
            ("lib/arm64-v8a/libx.so", b"native"),
            ("assets/old.txt", b"retire"),
        ]);
        let b = apk(&[
            ("AndroidManifest.xml", b"m1"),
            ("classes.dex", b"b"),
            ("assets/new.txt", b"add"),
            ("lib/arm64-v8a/libx.so", b"native"),
        ]);
        let result = compare(&a, &b).unwrap();
        assert_eq!(
            (
                result.added,
                result.removed,
                result.modified,
                result.unchanged
            ),
            (1, 1, 1, 2)
        );
        assert!(result.archive_bytes_differ);
        assert_eq!(
            result
                .changes
                .iter()
                .map(|c| (c.path.as_str(), c.disposition, c.component))
                .collect::<Vec<_>>(),
            [
                ("assets/new.txt", "added", "assets"),
                ("assets/old.txt", "removed", "assets"),
                ("classes.dex", "modified", "dex"),
            ]
        );
    }

    #[test]
    fn order_only_change_is_not_member_change() {
        let a = apk(&[("AndroidManifest.xml", b"m"), ("classes.dex", b"1")]);
        let b = apk(&[("classes.dex", b"1"), ("AndroidManifest.xml", b"m")]);
        let v = compare(&a, &b).unwrap();
        assert_eq!((v.added, v.removed, v.modified, v.unchanged), (0, 0, 0, 2));
        assert!(v.metadata_or_signing_block_diff_possible);
    }

    #[test]
    fn refuses_ambiguous_and_corrupt_members() {
        let a = apk(&[("AndroidManifest.xml", b"m")]);
        let duplicates = apk(&[("AndroidManifest.xml", b"m"), ("AndroidManifest.xml", b"n")]);
        assert!(compare(&a, &duplicates).is_err());
        let mut corrupt = a.clone();
        corrupt[0] = 0;
        assert!(compare(&corrupt, &a).is_err());
        assert!(compare(&a[..a.len() - 1], &a).is_err());
    }

    #[test]
    fn tracks_bounded_changes_but_exact_counts() {
        let old = apk(&[("AndroidManifest.xml", b"x")]);
        let mut entries = vec![("AndroidManifest.xml".to_owned(), vec![b'x'])];
        for i in 0..72 {
            entries.push((format!("assets/{i:03}.dat"), vec![u8::try_from(i).unwrap()]));
        }
        let borrowed = entries
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect::<Vec<_>>();
        let new = apk(&borrowed);
        let out = compare(&old, &new).unwrap();
        assert_eq!(out.added, 72);
        assert_eq!(out.changes.len(), 64);
        assert_eq!(out.omitted_changes, 8);
    }
}
