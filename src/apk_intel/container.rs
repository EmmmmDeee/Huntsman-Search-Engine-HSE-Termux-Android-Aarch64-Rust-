//! Offline inventory of APKS, XAPK and APKM ZIP containers. No installation or execution.
//! Container membership and manifest declarations are observations, not package authenticity.

use std::collections::BTreeSet;

use serde::Serialize;

use super::{
    Error, MAX_APK_MANIFEST_BYTES, directory_bounds, hex32, le16, le32, member, read_member,
    scan_id, sha256, suspicious,
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::source_outcome::SourceExecutionOutcome;

pub const SOURCE: &str = "apk_set";
const MAX_NESTED_APKS: usize = 32;
const MAX_NESTED_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_INFLATED: usize = 128 * 1024 * 1024;
const MAX_AUTHENTICATED_SIGNERS: usize = 8;
const LIMITATIONS: &str = "Offline inventory. APK member hashes cover exact decompressed bytes; container names, manifest package/version and base/split filename hints are unauthenticated. Only v3/v3.1 SDK-scoped signer certificates backed by verified signed-data signatures and matching APK content digests are reported as authenticated; v1/v2-only or unsupported signatures remain unverified. Matching or differing SDK-scoped signers do not prove installability, ownership or rotation compatibility. Proprietary/encrypted containers, ZIP64 and non-ZIP variants are unsupported; no files are extracted, installed or fetched.";

/// An SDK-scoped v3/v3.1 signer whose signed-data signature and APK content digest both verify.
/// This authenticates the stated certificate for these bytes, not Android installability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct AuthenticatedSdkSigner {
    pub scheme: String,
    pub min_sdk: u32,
    pub max_sdk: u32,
    pub certificate_sha256: String,
    pub public_key_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NestedApk {
    pub path: String,
    pub sha256: String,
    pub size_bytes: usize,
    pub role_hint_unverified: &'static str,
    pub manifest_package_unverified: Option<String>,
    pub manifest_version_code_unverified: Option<String>,
    pub manifest_error: Option<String>,
    pub authenticated_sdk_signers: Vec<AuthenticatedSdkSigner>,
    pub dex_count: usize,
    pub native_abis: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub container_sha256: String,
    pub container_size_bytes: usize,
    pub format_hint_unverified: &'static str,
    pub zip_entries: usize,
    pub apk_members: Vec<NestedApk>,
    pub package_consistency: &'static str,
    pub version_consistency: &'static str,
    pub signer_continuity: &'static str,
    pub limitations: &'static str,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

fn format_hint(label: &str) -> &'static str {
    match label
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
    {
        Some(ext) if ext == "apks" => "apks",
        Some(ext) if ext == "xapk" => "xapk",
        Some(ext) if ext == "apkm" => "apkm",
        _ => "zip_unknown",
    }
}

fn role_hint(name: &str) -> &'static str {
    let filename = name.rsplit('/').next().unwrap_or(name);
    if filename.eq_ignore_ascii_case("base.apk") || filename.eq_ignore_ascii_case("base-master.apk")
    {
        "base_filename_hint"
    } else {
        "unknown_or_split_filename_hint"
    }
}

fn consistency<'a>(values: impl Iterator<Item = Option<&'a str>>, count: usize) -> &'static str {
    let mut known = BTreeSet::new();
    let mut missing = 0_usize;
    for value in values {
        match value.filter(|value| !value.is_empty()) {
            Some(value) => {
                known.insert(value);
            }
            None => missing += 1,
        }
    }
    if known.len() > 1 {
        "conflicted"
    } else if missing > 0 || known.is_empty() || count == 0 {
        "unverified"
    } else {
        "consistent_unverified"
    }
}

/// Authenticate only the v3/v3.1 signer records for which both the signed-data
/// signature and the AOSP content digest validate against these exact APK bytes.
/// Unsupported, malformed, partially authenticated and ambiguous schemes fail closed.
fn authenticated_sdk_signers(
    data: &[u8],
    inventory: &super::Inventory,
    archive: &super::Archive<'_>,
) -> Vec<AuthenticatedSdkSigner> {
    if !inventory.duplicate_signing_scheme_ids.is_empty() {
        return Vec::new();
    }
    let (Some(start), Ok(end_at)) = (archive.signing_start, super::eocd(data)) else {
        return Vec::new();
    };
    let (checks, errors) = super::content_digest::compare(
        data,
        start,
        archive.directory_start,
        end_at,
        &archive.signing_values,
    );
    if !errors.is_empty() {
        return Vec::new();
    }
    let mut verified = Vec::new();
    for (scheme, value) in &archive.signing_values {
        if !matches!(*scheme, "v3" | "v3.1") {
            continue;
        }
        let claims = super::signer::sdk_signers(value, scheme);
        if claims.is_empty() {
            return Vec::new();
        }
        for claim in claims {
            if !checks.iter().any(|check| {
                check.scheme == claim.scheme
                    && check.signer_index == claim.signer_index
                    && check.signature_authenticated
            }) {
                return Vec::new();
            }
            if verified.len() >= MAX_AUTHENTICATED_SIGNERS {
                return Vec::new();
            }
            verified.push(AuthenticatedSdkSigner {
                scheme: claim.scheme,
                min_sdk: claim.min_sdk,
                max_sdk: claim.max_sdk,
                certificate_sha256: claim.certificate_sha256,
                public_key_sha256: claim.public_key_sha256,
            });
        }
    }
    verified.sort();
    verified.dedup();
    verified
}

/// Compare only fully authenticated, SDK-scoped v3/v3.1 claims. A difference
/// is an observed certificate difference, NOT a verdict on rotation/installability.
fn signer_continuity(members: &[NestedApk]) -> &'static str {
    if members.len() < 2
        || members
            .iter()
            .any(|member| member.authenticated_sdk_signers.is_empty())
    {
        return "unverified";
    }
    let identity = |member: &NestedApk| {
        let mut claims: Vec<_> = member
            .authenticated_sdk_signers
            .iter()
            .map(|signer| {
                (
                    signer.scheme.clone(),
                    signer.min_sdk,
                    signer.max_sdk,
                    signer.certificate_sha256.clone(),
                )
            })
            .collect();
        claims.sort_unstable();
        claims
    };
    let scopes = |member: &NestedApk| {
        let mut ranges: Vec<_> = member
            .authenticated_sdk_signers
            .iter()
            .map(|signer| (signer.scheme.clone(), signer.min_sdk, signer.max_sdk))
            .collect();
        ranges.sort_unstable();
        ranges
    };
    let first = &members[0];
    if members
        .iter()
        .skip(1)
        .all(|member| identity(member) == identity(first))
    {
        "authenticated_sdk_scope_match"
    } else if members
        .iter()
        .skip(1)
        .all(|member| scopes(member) == scopes(first))
    {
        "authenticated_sdk_scope_difference"
    } else {
        "unverified"
    }
}

fn validate_nested_structure(data: &[u8]) -> Result<(), Error> {
    let (count, dir_start, dir_end) = directory_bounds(data)?;
    let mut pos = dir_start;
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let at = pos;
        let entry = member(data, at, dir_start, dir_end)?;
        pos = entry.next;
        if suspicious(entry.name)
            || entry.name.starts_with("./")
            || entry.name.split('/').any(str::is_empty)
            || !seen.insert(entry.name.to_ascii_lowercase())
        {
            return Err(Error::invalid_value("unsafe or duplicate nested APK path"));
        }
        let local_at = le32(data, at + 42)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Error::invalid_value("invalid nested local ZIP offset"))?;
        if le16(data, local_at + 6) != Some(entry.flags)
            || le16(data, local_at + 8) != Some(entry.method)
        {
            return Err(Error::invalid_value(
                "nested APK central/local ZIP disagreement",
            ));
        }
    }
    if pos != dir_end {
        return Err(Error::invalid_value(
            "nested APK directory count/size disagree",
        ));
    }
    Ok(())
}

/// Decode only a nested APK's compiled manifest, keeping failures explicit and unverified.
fn nested_manifest(
    data: &[u8],
    archive: &super::Archive<'_>,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(manifest_member) = archive.manifest else {
        return (
            None,
            None,
            Some("missing nested AndroidManifest.xml".to_owned()),
        );
    };
    let mut budget = MAX_APK_MANIFEST_BYTES;
    match read_member(data, &manifest_member, MAX_APK_MANIFEST_BYTES, &mut budget) {
        Ok((bytes, _)) => match super::axml::manifest(&bytes) {
            Ok(parsed) => (parsed.package, parsed.version_code, None),
            Err(error) => (None, None, Some(error)),
        },
        Err(error) => (None, None, Some(error)),
    }
}

fn inspect_nested(
    data: &[u8],
    entry: &super::Member<'_>,
    central_at: usize,
    budget: &mut usize,
) -> Result<NestedApk, Error> {
    if entry.flags & (1 | (1 << 6) | (1 << 13)) != 0 {
        return Err(Error::invalid_value(
            "encrypted or masked nested APK member",
        ));
    }
    let unix_mode = le32(data, central_at + 38).unwrap_or_default() >> 16;
    if unix_mode & 0o170_000 == 0o120_000 {
        return Err(Error::invalid_value("nested APK member is a ZIP symlink"));
    }
    if entry.method != 0 && entry.method != 8 {
        return Err(Error::invalid_value(
            "unsupported nested APK compression method",
        ));
    }
    if entry.size > MAX_NESTED_BYTES {
        return Err(Error::invalid_value("nested APK exceeds 64 MiB limit"));
    }
    let (bytes, quirk) =
        read_member(data, entry, MAX_NESTED_BYTES, budget).map_err(Error::invalid_value)?;
    if quirk.is_some() {
        return Err(Error::invalid_value(
            "unexpected nested APK compression quirk",
        ));
    }
    validate_nested_structure(&bytes)?;
    let (inventory, archive) = super::walk(&bytes)?;
    let authenticated_sdk_signers = authenticated_sdk_signers(&bytes, &inventory, &archive);
    let (package, version, manifest_error) = nested_manifest(&bytes, &archive);
    Ok(NestedApk {
        path: entry.name.to_owned(),
        sha256: inventory.sha256,
        size_bytes: bytes.len(),
        role_hint_unverified: role_hint(entry.name),
        manifest_package_unverified: package,
        manifest_version_code_unverified: version,
        manifest_error,
        authenticated_sdk_signers,
        dex_count: inventory.dex_count,
        native_abis: inventory.native_abis,
    })
}

fn collect_apks(data: &[u8]) -> Result<(usize, Vec<NestedApk>), Error> {
    let (count, dir_start, dir_end) = directory_bounds(data)?;
    let mut pos = dir_start;
    let mut seen = BTreeSet::new();
    let mut seen_casefolded = BTreeSet::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut members = Vec::new();
    let mut budget = MAX_TOTAL_INFLATED;
    for _ in 0..count {
        let at = pos;
        let entry = member(data, at, dir_start, dir_end)?;
        pos = entry.next;
        if suspicious(entry.name)
            || entry.name.starts_with("./")
            || entry.name.split('/').any(str::is_empty)
        {
            return Err(Error::invalid_value("unsafe APK set member path"));
        }
        if !seen.insert(entry.name) || !seen_casefolded.insert(entry.name.to_ascii_lowercase()) {
            return Err(Error::invalid_value(
                "duplicate or case-ambiguous APK set member path",
            ));
        }
        let local_at = le32(data, at + 42)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Error::invalid_value("invalid local ZIP header offset"))?;
        if le16(data, local_at + 6) != Some(entry.flags)
            || le16(data, local_at + 8) != Some(entry.method)
        {
            return Err(Error::invalid_value(
                "central/local ZIP flags or methods disagree",
            ));
        }
        let end = entry
            .payload_start
            .checked_add(entry.payload_len)
            .ok_or_else(|| Error::invalid_value("APK set payload offset overflow"))?;
        if ranges
            .iter()
            .any(|(start, finish)| entry.payload_start < *finish && *start < end)
        {
            return Err(Error::invalid_value("overlapping APK set member payloads"));
        }
        ranges.push((entry.payload_start, end));
        if entry.name.to_ascii_lowercase().ends_with(".apk") {
            if members.len() >= MAX_NESTED_APKS {
                return Err(Error::invalid_value("APK set exceeds 32 nested APKs"));
            }
            members.push(inspect_nested(data, &entry, at, &mut budget)?);
        }
    }
    if pos != dir_end {
        return Err(Error::invalid_value(
            "APK set directory count/size disagree",
        ));
    }
    if members.is_empty() {
        return Err(Error::invalid_value("APK set has no nested APK members"));
    }
    Ok((count, members))
}

fn graph_entities(
    label: &str,
    outer_sha: &str,
    members: &[NestedApk],
    package_consistency: &str,
    version_consistency: &str,
    signer_continuity: &str,
) -> Vec<Entity> {
    let sid = scan_id(SOURCE, label);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Document,
        label,
        0.9,
        &sid,
        Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, &sid),
            format!("Offline inventory of multi-APK container {label}; no signatures or package identity verified"),
        )
        .with_attr("file_sha256", outer_sha)
        .with_attr("file_hash_scope", "exact_input_bytes")
        .with_attr("apk_set_format_hint_unverified", format_hint(label))
        .with_attr("apk_set_member_count", members.len().to_string())
        .with_attr("apk_set_package_consistency", package_consistency)
        .with_attr("apk_set_version_consistency", version_consistency)
        .with_attr("apk_set_signer_continuity", signer_continuity),
        &[SOURCE, "offline", "apk_container"],
    );
    for nested in members {
        push_entity(
            &mut entities,
            EntityKind::Other,
            &format!("apk-sha256:{}", nested.sha256),
            0.9,
            &sid,
            Evidence::new(
                EvidenceProvenance::for_scan(SOURCE, &sid),
                format!(
                    "Exact decompressed APK bytes in {label}, member {:?}",
                    nested.path
                ),
            )
            .with_attr("apk_member_sha256", nested.sha256.as_str())
            .with_attr("apk_member_path", nested.path.as_str())
            .with_attr(
                "apk_authenticated_sdk_signer_certificates",
                nested
                    .authenticated_sdk_signers
                    .iter()
                    .map(|signer| signer.certificate_sha256.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .with_attr("apk_container_sha256", outer_sha)
            .with_attr(
                "apk_manifest_package_unverified",
                nested.manifest_package_unverified.as_deref().unwrap_or(""),
            )
            .with_attr(
                "apk_member_role_hint_unverified",
                nested.role_hint_unverified,
            ),
            &[SOURCE, "offline", "apk_member"],
        );
    }
    merge_by_uid(&mut entities);
    entities
}

/// Inspect a bounded multi-APK ZIP without extracting to disk.
///
/// # Errors
/// Refuses invalid ZIP structures, duplicate/unsafe paths, unsupported compression, encrypted
/// APK members, CRC failures, invalid embedded APKs and decompression budget overruns.
pub fn run(data: &[u8], label: &str, now_unix: u64) -> Result<Report, Error> {
    if data.len() > 64 * 1024 * 1024 {
        return Err(Error::invalid_value("APK set exceeds 64 MiB input limit"));
    }
    let (count, members) = collect_apks(data)?;
    let outer_sha = hex32(&sha256(data));
    let package_consistency = consistency(
        members
            .iter()
            .map(|member| member.manifest_package_unverified.as_deref()),
        members.len(),
    );
    let version_consistency = consistency(
        members
            .iter()
            .map(|member| member.manifest_version_code_unverified.as_deref()),
        members.len(),
    );
    let signer_continuity = signer_continuity(&members);
    let entities = graph_entities(
        label,
        &outer_sha,
        &members,
        package_consistency,
        version_consistency,
        signer_continuity,
    );
    let outcomes = vec![SourceExecutionOutcome::success(
        SOURCE,
        now_unix,
        entities.len(),
    )];
    Ok(Report {
        container_sha256: outer_sha,
        container_size_bytes: data.len(),
        format_hint_unverified: format_hint(label),
        zip_entries: count,
        apk_members: members,
        package_consistency,
        version_consistency,
        signer_continuity,
        limitations: LIMITATIONS,
        entities,
        outcomes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zip(parts: &[(&str, &[u8], u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for &(name, bytes, method) in parts {
            let packed = if method == 8 {
                miniz_oxide::deflate::compress_to_vec(bytes, 6)
            } else {
                bytes.to_vec()
            };
            let offset = u32::try_from(out.len()).expect("fixture offset");
            let name_len = u16::try_from(name.len()).expect("fixture name");
            let crc = crc32fast::hash(bytes);
            let mut local = [0_u8; 30];
            local[..4].copy_from_slice(b"PK\x03\x04");
            local[8..10].copy_from_slice(&method.to_le_bytes());
            local[14..18].copy_from_slice(&crc.to_le_bytes());
            local[18..22]
                .copy_from_slice(&u32::try_from(packed.len()).expect("packed").to_le_bytes());
            local[22..26].copy_from_slice(&u32::try_from(bytes.len()).expect("size").to_le_bytes());
            local[26..28].copy_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&local);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&packed);

            let mut central = [0_u8; 46];
            central[..4].copy_from_slice(b"PK\x01\x02");
            central[10..12].copy_from_slice(&method.to_le_bytes());
            central[16..20].copy_from_slice(&crc.to_le_bytes());
            central[20..24]
                .copy_from_slice(&u32::try_from(packed.len()).expect("packed").to_le_bytes());
            central[24..28]
                .copy_from_slice(&u32::try_from(bytes.len()).expect("size").to_le_bytes());
            central[28..30].copy_from_slice(&name_len.to_le_bytes());
            central[42..46].copy_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(&central);
            directory.extend_from_slice(name.as_bytes());
        }
        let start = u32::try_from(out.len()).expect("directory start");
        let size = u32::try_from(directory.len()).expect("directory size");
        out.extend_from_slice(&directory);
        let mut end = [0_u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&u16::try_from(parts.len()).expect("count").to_le_bytes());
        end[10..12].copy_from_slice(&u16::try_from(parts.len()).expect("count").to_le_bytes());
        end[12..16].copy_from_slice(&size.to_le_bytes());
        end[16..20].copy_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&end);
        out
    }

    fn apk() -> Vec<u8> {
        zip(&[
            ("AndroidManifest.xml", b"not binary xml", 0),
            ("classes.dex", b"not dex", 0),
        ])
    }

    #[test]
    fn inventories_stored_and_deflated_nested_apks_with_exact_hashes() {
        let inner = apk();
        let outer = zip(&[
            ("base.apk", inner.as_slice(), 0),
            ("splits/config.arm64_v8a.apk", inner.as_slice(), 8),
            ("toc.pb", b"untrusted metadata", 0),
        ]);
        let report = run(&outer, "bundle.apks", 42).expect("valid container");
        assert_eq!(report.apk_members.len(), 2);
        assert_eq!(report.apk_members[0].sha256, hex32(&sha256(&inner)));
        assert_eq!(report.apk_members[1].sha256, hex32(&sha256(&inner)));
        assert_eq!(report.package_consistency, "unverified");
        assert_eq!(report.signer_continuity, "unverified");
        assert!(
            report
                .apk_members
                .iter()
                .all(|member| member.authenticated_sdk_signers.is_empty())
        );
        assert_eq!(
            report.apk_members[0].role_hint_unverified,
            "base_filename_hint"
        );
        assert!(report.apk_members[0].manifest_error.is_some());
        assert_eq!(report.entities.len(), 2);
        assert_eq!(report.outcomes.len(), 1);
    }

    fn member_with_signers(signers: Vec<AuthenticatedSdkSigner>) -> NestedApk {
        NestedApk {
            path: "base.apk".to_owned(),
            sha256: "fixture".to_owned(),
            size_bytes: 0,
            role_hint_unverified: "unknown_or_split_filename_hint",
            manifest_package_unverified: None,
            manifest_version_code_unverified: None,
            manifest_error: None,
            authenticated_sdk_signers: signers,
            dex_count: 0,
            native_abis: Vec::new(),
        }
    }

    fn verified_claim(cert: &str, min_sdk: u32, max_sdk: u32) -> AuthenticatedSdkSigner {
        AuthenticatedSdkSigner {
            scheme: "v3".to_owned(),
            min_sdk,
            max_sdk,
            certificate_sha256: cert.to_owned(),
            public_key_sha256: cert.to_owned(),
        }
    }

    #[test]
    fn signer_continuity_requires_all_members_and_identical_authenticated_scopes() {
        let a = member_with_signers(vec![verified_claim("aa", 28, 32)]);
        let same = member_with_signers(vec![verified_claim("aa", 28, 32)]);
        let different = member_with_signers(vec![verified_claim("bb", 28, 32)]);
        let different_scope = member_with_signers(vec![verified_claim("aa", 33, 35)]);
        let missing = member_with_signers(Vec::new());
        assert_eq!(signer_continuity(&[a.clone()]), "unverified");
        assert_eq!(
            signer_continuity(&[a.clone(), same]),
            "authenticated_sdk_scope_match"
        );
        assert_eq!(
            signer_continuity(&[a.clone(), different]),
            "authenticated_sdk_scope_difference"
        );
        assert_eq!(
            signer_continuity(&[a.clone(), different_scope]),
            "unverified"
        );
        assert_eq!(signer_continuity(&[a, missing]), "unverified");
    }

    #[test]
    fn forged_v3_scheme_id_cannot_authenticate_nested_signers() {
        let inner = apk();
        let old_directory = usize::try_from(
            super::le32(&inner, inner.len() - 22 + 16).expect("directory offset"),
        )
        .expect("directory fits");
        let fake_signer = b"not signed data";
        let mut block = Vec::new();
        let pair_size = u64::try_from(fake_signer.len() + 4).expect("pair size");
        let block_size = pair_size + 8 + 24;
        block.extend_from_slice(&block_size.to_le_bytes());
        block.extend_from_slice(&pair_size.to_le_bytes());
        block.extend_from_slice(&0xf053_68c0_u32.to_le_bytes());
        block.extend_from_slice(fake_signer);
        block.extend_from_slice(&block_size.to_le_bytes());
        block.extend_from_slice(b"APK Sig Block 42");
        let mut tampered = inner[..old_directory].to_vec();
        tampered.extend_from_slice(&block);
        tampered.extend_from_slice(&inner[old_directory..]);
        let end = tampered.len() - 22;
        let new_directory = u32::try_from(old_directory + block.len()).expect("new directory");
        tampered[end + 16..end + 20].copy_from_slice(&new_directory.to_le_bytes());

        let outer = zip(&[
            ("base.apk", tampered.as_slice(), 0),
            ("split.apk", tampered.as_slice(), 0),
        ]);
        let report = run(&outer, "forged.apks", 42).expect("structurally valid APK set");
        assert_eq!(report.signer_continuity, "unverified");
        assert!(
            report
                .apk_members
                .iter()
                .all(|member| member.authenticated_sdk_signers.is_empty())
        );
    }

    #[test]
    fn rejects_missing_nested_apks_and_duplicate_names() {
        assert!(run(&zip(&[("toc.pb", b"metadata", 0)]), "x.apks", 1).is_err());
        let inner = apk();
        assert!(
            run(
                &zip(&[("base.apk", &inner, 0), ("base.apk", &inner, 0)]),
                "x.apks",
                1
            )
            .is_err()
        );
        assert!(
            run(
                &zip(&[("base.apk", &inner, 0), ("BASE.APK", &inner, 0)]),
                "x.apks",
                1
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_path_traversal_and_nested_crc_corruption() {
        let inner = apk();
        assert!(run(&zip(&[("../base.apk", &inner, 0)]), "x.xapk", 1).is_err());
        let mut outer = zip(&[("base.apk", &inner, 0)]);
        let payload = 30 + "base.apk".len();
        outer[payload] ^= 1;
        assert!(run(&outer, "x.apkm", 1).is_err());
    }

    #[test]
    fn refuses_invalid_embedded_apk_and_unsupported_compression() {
        assert!(run(&zip(&[("base.apk", b"not an apk", 0)]), "x.apks", 1).is_err());
        let inner = apk();
        assert!(run(&zip(&[("base.apk", &inner, 99)]), "x.apks", 1).is_err());
    }

    #[test]
    fn rejects_encrypted_flags_and_zip_symlink_members() {
        let inner = apk();
        let mut encrypted = zip(&[("base.apk", &inner, 0)]);
        // Both local and central flags agree, but strong-encryption flag is not admissible.
        encrypted[6..8].copy_from_slice(&0x0040_u16.to_le_bytes());
        let directory =
            usize::try_from(super::le32(&encrypted, encrypted.len() - 22 + 16).expect("directory"))
                .expect("directory offset");
        encrypted[directory + 8..directory + 10].copy_from_slice(&0x0040_u16.to_le_bytes());
        assert!(run(&encrypted, "x.apks", 1).is_err());

        let mut symlink = zip(&[("base.apk", &inner, 0)]);
        let directory =
            usize::try_from(super::le32(&symlink, symlink.len() - 22 + 16).expect("directory"))
                .expect("directory offset");
        let attributes = (0o120_777_u32 << 16).to_le_bytes();
        symlink[directory + 38..directory + 42].copy_from_slice(&attributes);
        assert!(run(&symlink, "x.apks", 1).is_err());
    }

    #[test]
    fn rejects_duplicate_nested_manifest_and_local_method_drift() {
        let duplicate = zip(&[
            ("AndroidManifest.xml", b"first", 0),
            ("AndroidManifest.xml", b"second", 0),
        ]);
        assert!(run(&zip(&[("base.apk", &duplicate, 0)]), "x.apks", 1).is_err());

        let mut inner = apk();
        inner[8..10].copy_from_slice(&8_u16.to_le_bytes());
        assert!(run(&zip(&[("base.apk", &inner, 0)]), "x.apks", 1).is_err());
    }

    #[test]
    fn compiled_axml_package_consistency_is_observed_not_authenticated() {
        use super::super::axml::tests::{Axml, Val, sample_manifest};

        let base_manifest = sample_manifest().build();
        let base = zip(&[("AndroidManifest.xml", &base_manifest, 0)]);
        let same = zip(&[("AndroidManifest.xml", &base_manifest, 0)]);
        let consistent = zip(&[("base.apk", &base, 0), ("config.arm64.apk", &same, 8)]);
        let report = run(&consistent, "sample.apks", 7).expect("compiled AXML");
        assert_eq!(report.package_consistency, "consistent_unverified");
        assert_eq!(report.version_consistency, "consistent_unverified");
        assert_eq!(
            report.apk_members[0].manifest_package_unverified.as_deref(),
            Some("com.example.field")
        );
        assert_eq!(
            report.apk_members[0]
                .manifest_version_code_unverified
                .as_deref(),
            Some("42")
        );

        let mut different = Axml::new(&["versionCode"]);
        different
            .start(
                "manifest",
                &[
                    ("versionCode", Val::Int(99)),
                    ("package", Val::Str("com.example.other")),
                ],
            )
            .end("manifest");
        let other_manifest = different.build();
        let other = zip(&[("AndroidManifest.xml", &other_manifest, 0)]);
        let conflicted = zip(&[("base.apk", &base, 0), ("split.apk", &other, 0)]);
        let report = run(&conflicted, "sample.xapk", 7).expect("valid but conflicting claims");
        assert_eq!(report.package_consistency, "conflicted");
        assert_eq!(report.version_consistency, "conflicted");
    }

    #[test]
    fn conflicting_and_missing_claims_never_become_verified() {
        assert_eq!(
            consistency([Some("a"), Some("b")].into_iter(), 2),
            "conflicted"
        );
        assert_eq!(consistency([Some("a"), None].into_iter(), 2), "unverified");
        assert_eq!(
            consistency([Some("a"), Some("a")].into_iter(), 2),
            "consistent_unverified"
        );
    }
}
