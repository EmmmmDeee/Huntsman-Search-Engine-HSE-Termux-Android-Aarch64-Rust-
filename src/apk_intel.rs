//! Offline, bounded Android APK archive intelligence.
//!
//! Parses ZIP central-directory and local-file headers, then reads the members an investigator
//! needs the way Android's package manager does: the compiled `AndroidManifest.xml` (`axml`), the
//! signing certificates of the v2/v3 signing block and the v1 `META-INF` signature (`signer`),
//! and the URLs in each DEX string table (`dex`). A stored member is read in place and a deflated
//! one inflated within a fixed budget; each is checked against its ZIP CRC-32 before it is read.
//! Nothing is executed, no signature is verified and no network request is made; every value is
//! the archive's own claim, and a certificate name or a URL in code is never proof of authorship.

mod arsc;
mod axml;
mod capability;
mod content_digest;
mod dex;
mod elf;
mod intent;
mod native_framework;
mod network_config;
mod risk;
mod sdk;
mod signer;

use std::borrow::Cow;
use std::collections::BTreeSet;

use serde::Serialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity, scan_id};
use crate::error::Error;
use crate::sha256::{hex32, sha256};
use crate::source_outcome::SourceExecutionOutcome;

pub mod lineage;

pub const SOURCE: &str = "apk_intel";
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 8192;
const MAX_LISTED: usize = 32;
const EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";
const APK_SIG_MAGIC: &[u8] = b"APK Sig Block 42";
/// The most a compiled manifest may inflate to; real ones are kilobytes.
const MAX_APK_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
/// The most the resource table (`resources.arsc`) may inflate to when resolving the app label.
const MAX_APK_RESOURCES_BYTES: usize = 64 * 1024 * 1024;
/// The most one DEX file may inflate to.
const MAX_APK_DEX_BYTES: usize = 128 * 1024 * 1024;
/// The most one native library read for its build-id may inflate to.
const MAX_APK_NATIVE_BYTES: usize = 64 * 1024 * 1024;
/// At most this many native libraries are read for build-ids, so an archive packed with `.so`
/// files cannot make the phone inflate every one.
const MAX_NATIVE_LIBS_READ: usize = 64;
/// The most one v1 signature file may inflate to.
const MAX_APK_SIGNATURE_FILE_BYTES: usize = 1024 * 1024;
/// The most one APK's members may inflate to in total, so a small archive cannot make the phone
/// inflate gigabytes (a ZIP bomb); a member past it is reported as unread.
const MAX_APK_INFLATED_BYTES: usize = 256 * 1024 * 1024;
/// Hosts and URLs turned into entities, each; the report lists more.
const MAX_HOST_ENTITIES: usize = 64;
const LIMITATIONS: &str = "Offline static reading: APK SHA-256 content-digest comparisons do not authenticate signer signatures or certificates; manifest claims and signing certificates are unverified; code URLs and native ELF build-ids are candidate leads, not proof of network contact, identical binaries, provenance or authorship. Nothing is executed or fetched.";

pub const APK_HELP: &str = "apk FILE [--json] | apk diff OLD NEW [--json]\nInspect one local Android APK offline. Read at most 64 MiB, refuse symlinks, validate ZIP directory and local headers, inventory DEX files and native ABIs, count compressed/encrypted entries, and identify signing artifacts and APK v2/v3 signing-block IDs (presence only, NOT signature verification). Decode the binary AndroidManifest (package, versions, permissions, exported components, deep-link hosts) and resolve the app's displayed name from resources.arsc, summarise the v1/v2/v3 signing certificates by the SHA-256 of their DER and of their public key (NOT verifying any signature), compare declared SHA-256 APK content digests using the Android 1 MiB chunk algorithm (matching an unauthenticated declaration is NOT signature verification), list the URLs and third-party SDKs the DEX code references, read each native library's GNU build-id (a cross-APK build pivot), SONAME and linked libraries (DT_NEEDED) from its ELF structures, name the cross-platform framework or game engine it is built on (Flutter, Unity, React Native and more) from those libraries, and grade the manifest's security posture (debuggable, cleartext traffic, exported components, sensitive permissions). Emit the SHA-256 of exact input bytes and provenance-bearing document evidence. Only bounded decompression of selected manifest, DEX, native ELF and signature members; no certificate validation, code execution, network request or root. A name in an archive is not proof of valid code or ownership. diff compares two complete, bounded APK files by exact stored-member bytes and selected ZIP metadata; it detects added, removed and changed structural components without decompression or signature verification. Archive-only differences may reflect signing blocks, order or alignment.";

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
    /// Scheme IDs repeated in one signing block; signer claims from these IDs are withheld.
    pub duplicate_signing_scheme_ids: Vec<String>,
    pub compressed_entries: usize,
    pub encrypted_entries: usize,
    pub suspicious_paths: usize,
    pub limitations: &'static str,
}

pub use axml::{Component, Exposure, IntentFilterDef, Manifest};
pub use content_digest::ContentDigestCheck;
pub use dex::CodeUrls;
pub use intent::IntentAnalysis;
pub use network_config::{DomainRule, NetworkPolicy, PinFingerprint, TrustAnchor};
pub use risk::Flag;
pub use sdk::Tracker;
pub use signer::Certificate;

/// One native library and what its ELF structures declare about it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NativeLibrary {
    /// The ABI directory the library sits in (`arm64-v8a`, …).
    pub abi: String,
    pub name: String,
    /// The GNU build-id as lowercase hex, or empty when the library carries none.
    pub build_id: String,
    /// The library's own recorded name (`DT_SONAME`), when it declares one.
    pub soname: Option<String>,
    /// The shared libraries it links against (`DT_NEEDED`); a native dependency fingerprint.
    pub needed: Vec<String>,
}

/// What reading the archive's members found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub manifest: Option<Manifest>,
    /// Offline SHA-256 comparisons against unauthenticated v2/v3 digest declarations.
    pub content_digest_checks: Vec<ContentDigestCheck>,
    /// Invalid signing-block digest structures or unsupported APK digest boundaries.
    pub content_digest_parse_errors: Vec<String>,
    /// Why the manifest could not be read, when it could not.
    pub manifest_error: Option<String>,
    /// Decoded declarations from the exact manifest-referenced compiled network XML, if readable.
    pub network_policy: Option<NetworkPolicy>,
    /// Each distinct signing certificate, its schemes joined when several present it.
    pub signers: Vec<Certificate>,
    pub code: CodeUrls,
    /// The app's displayed name (`android:label`), resolved from `resources.arsc` when it is a
    /// resource reference, or taken inline when the manifest gives a literal. The manifest's own
    /// claim, never verified against a store listing.
    pub app_label: Option<String>,
    /// Intent filter analysis: implicit intent attack surface assessment.
    pub intent_analysis: Option<IntentAnalysis>,
    /// The manifest's security-posture flags, highest risk first.
    pub risk_flags: Vec<Flag>,
    /// The GNU build-id of each native library read, with its ABI. Candidate pivot only.
    pub native_build_ids: Vec<NativeLibrary>,
    /// Cross-platform frameworks / game engines named from the bundled native libraries
    /// (Flutter, Unity, React Native, …). A classification of the app, not a cross-APK pivot.
    pub native_frameworks: Vec<String>,
    /// Members that were not read, with why.
    pub unread: Vec<String>,
    /// Archive tricks that make analysis tools fail while Android still installs the app.
    pub evasion_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub inventory: Inventory,
    pub analysis: Analysis,
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
struct SigningBlock<'a> {
    present: bool,
    schemes: BTreeSet<&'static str>,
    duplicates: BTreeSet<&'static str>,
    /// Each signature scheme's value, for the certificates its signers present.
    values: Vec<(&'static str, &'a [u8])>,
    start: Option<usize>,
}

/// Convert structurally observed scheme IDs into deterministic labels.
fn observed_scheme_ids(ids: BTreeSet<&'static str>, present: bool) -> Vec<String> {
    if present {
        ids.into_iter().map(str::to_owned).collect()
    } else {
        Vec::new()
    }
}

/// Inspect *structural* signing IDs. A matching ID is never a verified signature.
fn signing_block(data: &[u8], central_at: usize) -> SigningBlock<'_> {
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
        let scheme = match id {
            0x7109_871a => Some("v2"),
            0xf053_68c0 => Some("v3"),
            0x1b93_ad61 => Some("v3.1"),
            _ => None,
        };
        if let Some(scheme) = scheme {
            if found.schemes.insert(scheme) {
                found.values.push((scheme, &data[pos + 12..next]));
            } else {
                found.duplicates.insert(scheme);
            }
        }
        pos = next;
    }
    found.present = pos == footer_at;
    if found.present {
        found.start = Some(start);
    }
    // A repeated scheme ID is ambiguous. Do not promote certificates from either copy.
    // Other, uniquely identified schemes remain available as unverified observations.
    found
        .values
        .retain(|(scheme, _)| !found.duplicates.contains(scheme));
    found
}

/// One archive member verified against both its central and local ZIP headers.
#[derive(Clone, Copy)]
struct Member<'a> {
    name: &'a str,
    flags: u16,
    method: u16,
    /// The CRC-32 and uncompressed size the central directory states.
    crc: u32,
    size: usize,
    next: usize,
    /// Where the local payload starts, and its stored (compressed) length.
    payload_start: usize,
    payload_len: usize,
}

fn member(data: &[u8], pos: usize, dir_start: usize, dir_end: usize) -> Result<Member<'_>, Error> {
    if checked_range(data, pos, 4) != Some(CENTRAL_SIGNATURE) {
        return Err(Error::invalid_value("invalid ZIP central directory entry"));
    }
    let flags = le16(data, pos + 8).ok_or_else(|| Error::invalid_value("truncated ZIP flags"))?;
    let method =
        le16(data, pos + 10).ok_or_else(|| Error::invalid_value("truncated ZIP compression"))?;
    let crc = le32(data, pos + 16).ok_or_else(|| Error::invalid_value("missing ZIP CRC-32"))?;
    let packed = usize::try_from(
        le32(data, pos + 20).ok_or_else(|| Error::invalid_value("missing compressed size"))?,
    )
    .map_err(|_| Error::invalid_value("compressed size overflow"))?;
    let size = usize::try_from(
        le32(data, pos + 24).ok_or_else(|| Error::invalid_value("missing uncompressed size"))?,
    )
    .map_err(|_| Error::invalid_value("uncompressed size overflow"))?;
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
    let payload_start = local_name_at
        .checked_add(local_name_len)
        .and_then(|n| n.checked_add(local_extra_len))
        .ok_or_else(|| Error::invalid_value("ZIP payload range overflow"))?;
    let payload_end = payload_start
        .checked_add(packed)
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
        crc,
        size,
        next,
        payload_start,
        payload_len: packed,
    })
}

fn native_abi(name: &str) -> Option<&str> {
    let (abi, filename) = name.strip_prefix("lib/")?.split_once('/')?;
    if !abi.is_empty()
        && !filename.contains('/')
        && std::path::Path::new(filename)
            .extension()
            .is_some_and(|ext| ext == "so")
    {
        Some(abi)
    } else {
        None
    }
}

/// A v1 signature's certificate file, whose PKCS#7 holds the signer's certificate (the `.SF`
/// manifest-digest file does not).
fn is_v1_certificate(name: &str) -> bool {
    [".RSA", ".DSA", ".EC"]
        .iter()
        .any(|extension| name.ends_with(extension))
}

fn is_v1_signing_artifact(name: &str) -> bool {
    let Some(filename) = name.strip_prefix("META-INF/") else {
        return false;
    };
    !filename.contains('/')
        && [".RSA", ".DSA", ".EC", ".SF"]
            .iter()
            .any(|extension| filename.ends_with(extension))
}

fn directory_bounds(data: &[u8]) -> Result<(usize, usize, usize), Error> {
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

    Ok((count, dir_start, dir_end))
}

/// The members [`analyse`] reads, found while the directory is walked.
#[derive(Default)]
struct Archive<'a> {
    manifest: Option<Member<'a>>,
    resources: Option<Member<'a>>,
    resource_xml: Vec<Member<'a>>,
    dex: Vec<Member<'a>>,
    v1: Vec<Member<'a>>,
    /// Native libraries (`lib/*/*.so`), each with the ABI directory it sits in.
    native: Vec<(&'a str, Member<'a>)>,
    signing_values: Vec<(&'static str, &'a [u8])>,
    signing_start: Option<usize>,
    directory_start: usize,
}

impl Archive<'_> {
    fn with_directory_start(directory_start: usize) -> Self {
        Self {
            directory_start,
            ..Self::default()
        }
    }
}

/// Inspect ZIP metadata only. No untrusted payload is decompressed or executed.
///
/// # Errors
/// Malformed, multi-disk or ZIP64 archives, invalid local-header offsets, or archives
/// with over 8,192 entries are explicitly refused, not interpreted partially.
pub fn inventory(data: &[u8]) -> Result<Inventory, Error> {
    walk(data).map(|(inventory, _)| inventory)
}

fn walk(data: &[u8]) -> Result<(Inventory, Archive<'_>), Error> {
    let (count, dir_start, dir_end) = directory_bounds(data)?;
    let mut archive = Archive::with_directory_start(dir_start);

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
            archive.manifest.get_or_insert(entry);
        }
        if name == "resources.arsc" {
            archive.resources.get_or_insert(entry);
        } else if resource_xml_name(name) {
            archive.resource_xml.push(entry);
        }
        if dex_name(name) {
            archive.dex.push(entry);
            dex_count += 1;
            if dex.len() < MAX_LISTED {
                dex.push(name.to_owned());
            }
        }
        if let Some(abi) = native_abi(name) {
            native_count += 1;
            abis.insert(abi.to_owned());
            if archive.native.len() < MAX_NATIVE_LIBS_READ {
                archive.native.push((abi, entry));
            }
        }
        if is_v1_signing_artifact(name) {
            if is_v1_certificate(name) && archive.v1.len() < MAX_LISTED {
                archive.v1.push(entry);
            }
            v1_count += 1;
            if v1.len() < MAX_LISTED {
                v1.push(name.to_owned());
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
    if sig.present {
        archive.signing_start = sig.start;
        archive.signing_values = sig.values;
    }
    let inventory = Inventory {
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
        signing_scheme_ids_detected_unverified: observed_scheme_ids(sig.schemes, sig.present),
        duplicate_signing_scheme_ids: observed_scheme_ids(sig.duplicates, sig.present),
        compressed_entries: compressed,
        encrypted_entries: encrypted,
        suspicious_paths: unsafe_paths,
        limitations: LIMITATIONS,
    };
    Ok((inventory, archive))
}

/// The bytes of `member`, read in place when stored and inflated when deflated, within `limit`
/// and what is left of `budget`, and checked against the CRC-32 the directory states.
///
/// A member that names a compression method other than stored or deflate is read as stored when
/// its sizes agree, as Android's `libziparchive` reads it; this is a known way to make analysis
/// tools fail on an APK Android still installs, so it is returned as an evasion indicator.
fn read_member<'a>(
    data: &'a [u8],
    member: &Member<'_>,
    limit: usize,
    budget: &mut usize,
) -> Result<(Cow<'a, [u8]>, Option<String>), String> {
    let name = member.name;
    if member.flags & 1 != 0 {
        return Err(format!("{name} is encrypted"));
    }
    if member.size > limit {
        return Err(format!(
            "{name} inflates to {} bytes, over its {limit}-byte limit",
            member.size
        ));
    }
    if member.size > *budget {
        return Err(format!(
            "{name} would pass the {MAX_APK_INFLATED_BYTES}-byte budget for one APK"
        ));
    }
    let raw = &data[member.payload_start..member.payload_start + member.payload_len];
    let (bytes, quirk) = match member.method {
        8 => (
            Cow::Owned(
                miniz_oxide::inflate::decompress_to_vec_with_limit(raw, member.size)
                    .map_err(|error| format!("{name} does not inflate: {:?}", error.status))?,
            ),
            None,
        ),
        0 => (Cow::Borrowed(raw), None),
        other if member.payload_len == member.size => (
            Cow::Borrowed(raw),
            Some(format!(
                "{name} declares compression method {other}, read as stored as Android does"
            )),
        ),
        other => {
            return Err(format!(
                "{name} uses unsupported compression method {other}"
            ));
        }
    };
    if bytes.len() != member.size {
        return Err(format!("{name} is not the size its ZIP entry states"));
    }
    if crc32fast::hash(&bytes) != member.crc {
        return Err(format!("{name} fails its ZIP CRC-32 check"));
    }
    *budget -= member.size;
    Ok((bytes, quirk))
}

/// Read the manifest, signatures and code of an archive [`walk`] indexed.
fn analyse(data: &[u8], archive: &Archive<'_>) -> Analysis {
    let mut analysis = Analysis::default();
    let mut budget = MAX_APK_INFLATED_BYTES;
    let mut read = |member: &Member<'_>, limit: usize, analysis: &mut Analysis| match read_member(
        data,
        member,
        limit,
        &mut budget,
    ) {
        Ok((bytes, quirk)) => {
            analysis.evasion_indicators.extend(quirk);
            Some(bytes)
        }
        Err(reason) => {
            analysis.unread.push(reason);
            None
        }
    };
    if let Some(member) = &archive.manifest {
        match read(member, MAX_APK_MANIFEST_BYTES, &mut analysis) {
            Some(bytes) => match axml::manifest(&bytes) {
                Ok(manifest) => {
                    analysis.risk_flags = risk::flags(&manifest);
                    analysis.intent_analysis = Some(intent::analyze(&manifest));
                    analysis.manifest = Some(manifest);
                }
                Err(error) => analysis.manifest_error = Some(error),
            },
            None => {
                analysis.manifest_error = analysis.unread.last().cloned();
            }
        }
    }
    if let (Some(start), Ok(end_at)) = (archive.signing_start, eocd(data)) {
        let (checks, errors) = content_digest::compare(
            data,
            start,
            archive.directory_start,
            end_at,
            &archive.signing_values,
        );
        analysis.content_digest_checks = checks;
        analysis.content_digest_parse_errors = errors;
    }
    let mut certificates: Vec<Certificate> = Vec::new();
    for (scheme, value) in &archive.signing_values {
        certificates.extend(signer::signing_block(value, scheme));
    }
    for member in &archive.v1 {
        if let Some(bytes) = read(member, MAX_APK_SIGNATURE_FILE_BYTES, &mut analysis) {
            certificates.extend(signer::pkcs7(&bytes, member.name));
        }
    }
    for certificate in certificates {
        match analysis
            .signers
            .iter_mut()
            .find(|known| known.sha256 == certificate.sha256)
        {
            Some(known) => {
                known.scheme.push_str(", ");
                known.scheme.push_str(&certificate.scheme);
            }
            None => analysis.signers.push(certificate),
        }
    }
    for member in &archive.dex {
        if let Some(bytes) = read(member, MAX_APK_DEX_BYTES, &mut analysis) {
            if let Err(error) = analysis.code.read(&bytes) {
                analysis.unread.push(format!("{}: {error}", member.name));
            }
        }
    }
    analysis.code.finish();
    for (abi, member) in &archive.native {
        if let Some(bytes) = read(member, MAX_APK_NATIVE_BYTES, &mut analysis) {
            let build_id = elf::build_id(&bytes);
            let dynamic = elf::dynamic(&bytes).unwrap_or_default();
            // Record a library only when it declares something we read; an unreadable or empty ELF
            // adds no entry.
            if build_id.is_some() || dynamic.soname.is_some() || !dynamic.needed.is_empty() {
                analysis.native_build_ids.push(NativeLibrary {
                    abi: (*abi).to_owned(),
                    name: member
                        .name
                        .rsplit('/')
                        .next()
                        .unwrap_or(member.name)
                        .to_owned(),
                    build_id: build_id.unwrap_or_default(),
                    soname: dynamic.soname,
                    needed: dynamic.needed,
                });
            }
        }
    }
    analysis.native_build_ids.sort();
    analysis.native_frameworks = native_frameworks(&analysis.native_build_ids);
    resolve_resources(data, archive, &mut analysis, &mut budget);
    analysis
}

/// Resolve only resource IDs actually named by the manifest, within the APK's shared
/// inflation budget. No guessed XML names or cross-APK resources are accepted.
fn resolve_resources(
    data: &[u8],
    archive: &Archive<'_>,
    analysis: &mut Analysis,
    budget: &mut usize,
) {
    let mut read = |member: &Member<'_>, limit: usize, analysis: &mut Analysis| match read_member(
        data, member, limit, budget,
    ) {
        Ok((bytes, quirk)) => {
            analysis.evasion_indicators.extend(quirk);
            Some(bytes)
        }
        Err(reason) => {
            analysis.unread.push(reason);
            None
        }
    };
    // Resolve the displayed label and the network policy from the same resource table.
    // A similarly named XML member is never selected without the exact manifest resource ID.
    let (inline_label, label_ref, policy_ref) =
        analysis
            .manifest
            .as_ref()
            .map_or((None, None, None), |manifest| {
                (
                    manifest.label.clone(),
                    manifest.label_resource_id,
                    manifest.network_security_config_resource_id,
                )
            });
    analysis.app_label = inline_label;
    let mut policy_path = None;
    if label_ref.is_some() || policy_ref.is_some() {
        if let Some(member) = &archive.resources {
            if let Some(bytes) = read(member, MAX_APK_RESOURCES_BYTES, analysis) {
                if let Some(id) = label_ref {
                    analysis.app_label = arsc::string_resource(&bytes, id);
                }
                if let Some(id) = policy_ref {
                    policy_path = arsc::string_resource(&bytes, id);
                    if policy_path.is_none() {
                        analysis.unread.push(format!(
                            "network policy resource 0x{id:08x} did not resolve in resources.arsc"
                        ));
                    }
                }
            }
        } else if policy_ref.is_some() {
            analysis
                .unread
                .push("network policy reference has no resources.arsc table".to_owned());
        }
    }
    if let (Some(id), Some(path)) = (policy_ref, policy_path) {
        if valid_network_xml_path(&path) {
            let mut matches = archive
                .resource_xml
                .iter()
                .filter(|member| member.name == path);
            match (matches.next(), matches.next()) {
                (Some(member), None) => {
                    if let Some(bytes) = read(member, MAX_APK_MANIFEST_BYTES, analysis) {
                        match network_config::parse(&bytes, id, &path) {
                            Ok(policy) => analysis.network_policy = Some(policy),
                            Err(error) => analysis.unread.push(format!("{path}: {error}")),
                        }
                    }
                }
                (None, _) => analysis.unread.push(format!(
                    "network policy resource 0x{id:08x} references absent {path}"
                )),
                (Some(_), Some(_)) => analysis.unread.push(format!(
                    "network policy resource 0x{id:08x} references duplicate ZIP path {path}"
                )),
            }
        } else {
            analysis.unread.push(format!(
                "network policy resource 0x{id:08x} resolved to an invalid XML path"
            ));
        }
    }
}

fn resource_xml_name(name: &str) -> bool {
    name.starts_with("res/")
        && std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext == "xml")
        && !suspicious(name)
}

fn valid_network_xml_path(path: &str) -> bool {
    let Some((directory, file)) = path.rsplit_once('/') else {
        return false;
    };
    (directory == "res/xml" || directory.starts_with("res/xml-"))
        && !file.is_empty()
        && std::path::Path::new(file)
            .extension()
            .is_some_and(|ext| ext == "xml")
        && !suspicious(path)
}

/// The frameworks / engines named by the bundled native libraries, deduplicated and sorted. A
/// library's own name, its `SONAME` and each `DT_NEEDED` entry are all considered, so an app that
/// merely links against an engine is named as well as one that bundles it.
fn native_frameworks(libraries: &[NativeLibrary]) -> Vec<String> {
    let mut found = std::collections::BTreeSet::new();
    for library in libraries {
        let names = std::iter::once(library.name.as_str())
            .chain(library.soname.as_deref())
            .chain(library.needed.iter().map(String::as_str));
        for name in names {
            if let Some(framework) = native_framework::framework_of(name) {
                found.insert(framework);
            }
        }
    }
    found.into_iter().map(str::to_owned).collect()
}

/// The document entity's evidence: the archive inventory, then what its members declare.
/// The native build-ids as one evidence line: `name (abi): build_id`, comma-separated. Libraries
/// that carry no build-id are left out.
fn native_build_ids_summary(analysis: &Analysis) -> String {
    analysis
        .native_build_ids
        .iter()
        .filter(|lib| !lib.build_id.is_empty())
        .map(|lib| format!("{} ({}): {}", lib.name, lib.abi, lib.build_id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The native dependency fingerprint as one evidence line: for each library that declares a
/// `SONAME` or a `DT_NEEDED` list, `name [soname] -> needed, libraries`.
fn native_dependencies_summary(analysis: &Analysis) -> String {
    analysis
        .native_build_ids
        .iter()
        .filter(|lib| lib.soname.is_some() || !lib.needed.is_empty())
        .map(|lib| {
            let soname = lib.soname.as_deref().unwrap_or(&lib.name);
            format!("{soname} -> {}", lib.needed.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn network_policy_attrs(analysis: &Analysis, put: &mut impl FnMut(&'static str, String)) {
    if let Some(policy) = &analysis.network_policy {
        put("apk_network_policy_path", policy.resource_path.clone());
        put(
            "apk_network_policy_resource_id",
            format!("0x{:08x}", policy.resource_id),
        );
        put(
            "apk_network_policy_base_cleartext",
            policy
                .base_cleartext_permitted
                .map_or("unknown".to_owned(), |value| value.to_string()),
        );
        put(
            "apk_network_policy_domains",
            policy
                .domains
                .iter()
                .map(|rule| {
                    format!(
                        "{} (subdomains={:?}, declared_cleartext={:?})",
                        rule.domain, rule.include_subdomains, rule.declared_cleartext_permitted
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        );
        put(
            "apk_network_policy_trust_anchors",
            policy
                .trust_anchors
                .iter()
                .map(|anchor| format!("{}:{}", anchor.scope, anchor.source))
                .collect::<Vec<_>>()
                .join("; "),
        );
        put(
            "apk_network_policy_debug_overrides",
            policy.debug_overrides_present.to_string(),
        );
        put("apk_network_policy_pin_sets", policy.pin_sets.to_string());
        put("apk_network_policy_pin_count", policy.pin_count.to_string());
        put(
            "apk_network_policy_pin_fingerprints",
            policy
                .pin_fingerprints
                .iter()
                .map(|pin| {
                    format!(
                        "{}:{} (domains={}, expiration={})",
                        pin.digest_algorithm,
                        pin.digest_base64,
                        pin.declared_domains.join(","),
                        pin.expiration.as_deref().unwrap_or("unknown")
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        );
        put(
            "apk_network_policy_pin_fingerprints_omitted",
            policy.pin_fingerprints_omitted.to_string(),
        );
        put(
            "apk_network_policy_limitations",
            policy.limitations.to_owned(),
        );
    }
}

/// Keep unauthenticated digest comparisons in the document evidence contract without
/// promoting them into signing identities or treating a digest match as authentication.
fn content_digest_attrs(analysis: &Analysis, put: &mut impl FnMut(&'static str, String)) {
    if !analysis.content_digest_checks.is_empty() {
        put(
            "apk_content_digest_sha256_claims_unverified",
            analysis
                .content_digest_checks
                .iter()
                .map(|check| {
                    format!(
                        "{}#{}:0x{:04x}:declared={}:computed={}:matches={}",
                        check.scheme,
                        check.signer_index,
                        check.signature_algorithm_id,
                        check.declared_sha256,
                        check.computed_sha256,
                        check.matches
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        );
        put(
            "apk_content_digest_signature_authenticated",
            "false".to_owned(),
        );
    }
    put(
        "apk_content_digest_parse_errors",
        analysis.content_digest_parse_errors.join("; "),
    );
}

fn document_evidence(
    inventory: &Inventory,
    analysis: &Analysis,
    label: &str,
    sid: &str,
) -> Evidence {
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, sid),
        format!("Offline static reading of Android application archive {label}"),
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
        "apk_signing_scheme_duplicate_ids",
        inventory.duplicate_signing_scheme_ids.join(","),
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
    let mut extra: Vec<(&str, String)> = Vec::new();
    let mut put = |key: &'static str, value: String| {
        if !value.is_empty() {
            extra.push((key, value));
        }
    };
    match (&analysis.manifest, &analysis.manifest_error) {
        (Some(manifest), _) => manifest_attrs(manifest, &mut put),
        (None, Some(error)) => put("apk_manifest_unread", error.clone()),
        (None, None) => {}
    }
    put(
        "apk_app_label",
        analysis.app_label.clone().unwrap_or_default(),
    );
    network_policy_attrs(analysis, &mut put);
    content_digest_attrs(analysis, &mut put);
    signer_digest_attrs(analysis, &mut put);
    if let Some(signer) = analysis.signers.first() {
        put("apk_signer_subject", signer.subject.clone());
        put("apk_signer_valid_from", signer.not_before.clone());
        put("apk_signer_valid_to", signer.not_after.clone());
        put(
            "apk_signer_android_debug_key",
            signer.android_debug.to_string(),
        );
    }
    put(
        "apk_code_url_count",
        (analysis.code.urls.len() + analysis.code.urls_omitted).to_string(),
    );
    if let Some(highest) = risk::highest(&analysis.risk_flags) {
        put("apk_risk_highest", highest.as_str().to_owned());
        put(
            "apk_risk_flags",
            analysis
                .risk_flags
                .iter()
                .map(|flag| format!("{} {}: {}", flag.risk.as_str(), flag.id, flag.detail))
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    native_attrs(analysis, &mut put);
    put(
        "apk_bundled_sdks",
        analysis
            .code
            .trackers
            .iter()
            .map(|tracker| format!("{} ({})", tracker.name, tracker.category))
            .collect::<Vec<_>>()
            .join(", "),
    );
    put(
        "apk_evasion_indicators",
        analysis.evasion_indicators.join("; "),
    );
    put("apk_unread_members", analysis.unread.join("; "));
    extra.into_iter().fold(evidence, |evidence, (key, value)| {
        evidence.with_attr(key, value)
    })
}

/// The signing certificates' and keys' digests as document-evidence attributes, one comma-joined
/// list each.
fn signer_digest_attrs(analysis: &Analysis, put: &mut impl FnMut(&'static str, String)) {
    let join = |pick: fn(&Certificate) -> &str| {
        analysis
            .signers
            .iter()
            .map(pick)
            .collect::<Vec<_>>()
            .join(",")
    };
    put(
        "apk_signer_certificate_sha256_unverified",
        join(|signer| signer.sha256.as_str()),
    );
    put(
        "apk_signer_public_key_sha256_unverified",
        join(|signer| signer.public_key_sha256.as_str()),
    );
}

/// The native libraries' build-ids, dependency fingerprint and detected frameworks as
/// document-evidence attributes.
fn native_attrs(analysis: &Analysis, put: &mut impl FnMut(&'static str, String)) {
    put("apk_native_build_ids", native_build_ids_summary(analysis));
    put(
        "apk_native_dependencies",
        native_dependencies_summary(analysis),
    );
    put(
        "apk_native_frameworks",
        analysis.native_frameworks.join(", "),
    );
}

/// The manifest's facts as document-evidence attributes.
fn manifest_attrs(manifest: &Manifest, put: &mut impl FnMut(&'static str, String)) {
    let flag = |value: Option<bool>| value.map(|on| on.to_string()).unwrap_or_default();
    put("apk_package", manifest.package.clone().unwrap_or_default());
    put(
        "apk_version_code",
        manifest.version_code.clone().unwrap_or_default(),
    );
    put(
        "apk_version_name",
        manifest.version_name.clone().unwrap_or_default(),
    );
    put(
        "apk_shared_user_id",
        manifest.shared_user_id.clone().unwrap_or_default(),
    );
    put("apk_min_sdk", manifest.min_sdk.clone().unwrap_or_default());
    put(
        "apk_target_sdk",
        manifest.target_sdk.clone().unwrap_or_default(),
    );
    put("apk_permissions", manifest.permissions.join(","));
    put("apk_debuggable", flag(manifest.debuggable));
    put("apk_test_only", flag(manifest.test_only));
    put("apk_allow_backup", flag(manifest.allow_backup));
    put(
        "apk_uses_cleartext_traffic",
        flag(manifest.uses_cleartext_traffic),
    );
    put(
        "apk_network_security_config",
        manifest.network_security_config.to_string(),
    );
    put("apk_components", manifest.components.to_string());
    put(
        "apk_reachable_components",
        (manifest.reachable_components.len() + manifest.reachable_components_omitted).to_string(),
    );
    put("apk_deep_link_hosts", manifest.deep_link_hosts.join(","));
    put(
        "apk_provider_authorities",
        manifest.provider_authorities.join(","),
    );
}

/// The pivots the archive names, each its own entity so scans of other APKs, domains and
/// addresses meet it in the graph: its signing certificates, the hosts it claims as deep links,
/// and the hosts and URLs in its code. Each says where in the archive it came from.
/// The build-id pivot entity for each native library that carries one, enriched with its SONAME and
/// linked libraries. A library without a build-id is kept in the document evidence, not here.
fn native_entities(analysis: &Analysis, label: &str, sid: &str, entities: &mut Vec<Entity>) {
    for lib in analysis
        .native_build_ids
        .iter()
        .filter(|lib| !lib.build_id.is_empty())
    {
        let mut lib_evidence = Evidence::new(
            EvidenceProvenance::for_scan(SOURCE, sid),
            format!(
                "Native library {} ({}) in {label} declares this GNU build-id; a matching ID is a candidate lead, not proof of identical bytes, provenance or authorship",
                lib.name, lib.abi
            ),
        )
        .with_attr("native_library", lib.name.as_str())
        .with_attr("abi", lib.abi.as_str())
        .with_attr("build_id", lib.build_id.as_str());
        if let Some(soname) = &lib.soname {
            lib_evidence = lib_evidence.with_attr("soname", soname.as_str());
        }
        if !lib.needed.is_empty() {
            lib_evidence = lib_evidence.with_attr("needed_libraries", lib.needed.join(", "));
        }
        push_entity(
            entities,
            EntityKind::Other,
            &format!("apk-native-buildid:{}", lib.build_id),
            0.9,
            sid,
            lib_evidence,
            &[SOURCE, "offline", "apk_native"],
        );
    }
}

/// The signing-key pivot for each distinct public key across the certificates. Keyed on the
/// `SubjectPublicKeyInfo` digest, it pivots across certificates that re-wrap the same key (Play
/// app-signing, a renewed certificate), which the per-certificate digest cannot.
fn signer_key_entities(analysis: &Analysis, label: &str, sid: &str, entities: &mut Vec<Entity>) {
    let mut seen = std::collections::BTreeSet::new();
    for signer in &analysis.signers {
        if signer.public_key_sha256.is_empty() || !seen.insert(signer.public_key_sha256.clone()) {
            continue;
        }
        push_entity(
            entities,
            EntityKind::Other,
            &format!("apk-signer-pubkey-sha256:{}", signer.public_key_sha256),
            0.9,
            sid,
            Evidence::new(
                EvidenceProvenance::for_scan(SOURCE, sid),
                format!(
                    "Signing key {label} uses (SHA-256 of its SubjectPublicKeyInfo); a matching key is a candidate lead, not a verified signature",
                ),
            )
            .with_attr("public_key_sha256", signer.public_key_sha256.as_str()),
            &[SOURCE, "offline", "apk_signer"],
        );
    }
}

/// One canonical graph pivot per declared SPKI pin digest. Preserve all domain-config
/// scopes within this APK, without treating a declaration as TLS or ownership proof.
fn network_pin_entities(analysis: &Analysis, label: &str, sid: &str, entities: &mut Vec<Entity>) {
    let Some(policy) = &analysis.network_policy else {
        return;
    };
    let mut groups: std::collections::BTreeMap<
        &str,
        std::collections::BTreeSet<(String, Option<String>)>,
    > = std::collections::BTreeMap::new();
    for pin in &policy.pin_fingerprints {
        if pin.digest_algorithm != "SHA-256" || pin.digest_base64.is_empty() {
            continue;
        }
        for domain in &pin.declared_domains {
            if !domain.is_empty() {
                groups
                    .entry(pin.digest_base64.as_str())
                    .or_default()
                    .insert((domain.clone(), pin.expiration.clone()));
            }
        }
    }
    for (digest, scopes) in groups {
        // EntityKind::Other normalises values to lowercase: raw Base64 would collapse
        // distinct case-sensitive digests. Encode the exact 32 bytes as lowercase hex.
        let Some(bytes) = crate::base64::decode_standard(digest) else {
            continue;
        };
        if bytes.len() != 32 || crate::base64::standard(&bytes) != digest {
            continue;
        }
        let digest_hex = crate::base64::base16_lower(&bytes);
        let domains = scopes
            .iter()
            .map(|(domain, _)| domain.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        let declared_scopes = scopes
            .iter()
            .map(|(domain, expiration)| {
                format!(
                    "{domain} (expiration={})",
                    expiration.as_deref().unwrap_or("unknown")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        push_entity(
            entities,
            EntityKind::Other,
            &format!("apk-tls-spki-sha256:{digest_hex}"),
            0.4,
            sid,
            Evidence::new(
                EvidenceProvenance::for_scan(SOURCE, sid),
                format!(
                    "{label} declares this SHA-256 SPKI certificate pin; a matching declaration is a candidate lead, not proof of TLS contact, server ownership or shared APK authorship"
                ),
            )
            .with_attr("pin_digest_algorithm", "SHA-256")
            .with_attr("pin_sha256_base64", digest)
            .with_attr("pin_sha256_hex", digest_hex.as_str())
            .with_attr("declared_domains", domains)
            .with_attr("declared_scopes", declared_scopes)
            .with_attr("network_policy_resource", policy.resource_path.as_str()),
            &[SOURCE, "offline", "apk_tls_pin", "unverified"],
        );
    }
}

fn lead_entities(analysis: &Analysis, label: &str, sid: &str, entities: &mut Vec<Entity>) {
    let evidence = |text: String| Evidence::new(EvidenceProvenance::for_scan(SOURCE, sid), text);
    for signer in &analysis.signers {
        push_entity(
            entities,
            EntityKind::Other,
            &format!("apk-signer-sha256:{}", signer.sha256),
            0.9,
            sid,
            evidence(format!(
                "Signing certificate {label} presents ({}); its signature over the APK is not verified",
                signer.scheme
            ))
            .with_attr("certificate_sha256", signer.sha256.as_str())
            .with_attr("public_key_sha256", signer.public_key_sha256.as_str())
            .with_attr("certificate_subject", signer.subject.as_str())
            .with_attr("certificate_issuer", signer.issuer.as_str())
            .with_attr("certificate_serial", signer.serial.as_str())
            .with_attr("certificate_not_before", signer.not_before.as_str())
            .with_attr("certificate_not_after", signer.not_after.as_str())
            .with_attr("certificate_self_signed", signer.self_signed.to_string())
            .with_attr("certificate_android_debug_key", signer.android_debug.to_string()),
            &[SOURCE, "offline", "apk_signer"],
        );
    }
    signer_key_entities(analysis, label, sid, entities);
    native_entities(analysis, label, sid, entities);
    network_pin_entities(analysis, label, sid, entities);
    let host_entity = |host: &str| {
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            EntityKind::IpAddress
        } else {
            EntityKind::Domain
        }
    };
    if let Some(manifest) = &analysis.manifest {
        for host in manifest
            .deep_link_hosts
            .iter()
            .filter(|host| dex::wanted_host(host))
            .take(MAX_HOST_ENTITIES)
        {
            push_entity(
                entities,
                host_entity(host),
                host,
                0.6,
                sid,
                evidence(format!(
                    "{label} declares it opens links to this host (an AndroidManifest.xml intent filter{}); the host's own assetlinks.json is not fetched",
                    if manifest.app_links_auto_verify { ", autoVerify" } else { "" }
                ))
                .with_attr("apk_package", manifest.package.clone().unwrap_or_default()),
                &[SOURCE, "offline", "apk_deep_link"],
            );
        }
    }
    for host in analysis.code.hosts.iter().take(MAX_HOST_ENTITIES) {
        push_entity(
            entities,
            host_entity(host),
            host,
            0.4,
            sid,
            evidence(format!(
                "A URL with this host is compiled into the code of {label}; not proof the app contacts it"
            )),
            &[SOURCE, "offline", "apk_code_url"],
        );
    }
    for url in analysis.code.urls.iter().take(MAX_HOST_ENTITIES) {
        push_entity(
            entities,
            EntityKind::Url,
            url,
            0.4,
            sid,
            evidence(format!(
                "URL compiled into the code of {label}; not proof the app contacts it"
            )),
            &[SOURCE, "offline", "apk_code_url"],
        );
    }
}

/// Read one APK and wrap what it holds in the existing Huntsman evidence contract.
///
/// # Errors
/// Returns a structured input error for invalid or unsupported APK archives. A member that cannot
/// be read (too large, encrypted, corrupt) is reported in the analysis, not an error.
pub fn run(data: &[u8], label: &str, now_unix: u64) -> Result<Report, Error> {
    let (inventory, archive) = walk(data)?;
    let analysis = analyse(data, &archive);
    let sid = scan_id(SOURCE, label);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Document,
        label,
        0.9,
        sid.as_str(),
        document_evidence(&inventory, &analysis, label, sid.as_str()),
        &[SOURCE, "offline", "apk"],
    );
    lead_entities(&analysis, label, sid.as_str(), &mut entities);
    Ok(Report {
        inventory,
        analysis,
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

    #[test]
    fn repeated_signing_scheme_ids_withhold_ambiguous_signer_evidence() {
        let mut bytes = sample(&["AndroidManifest.xml"]);
        let directory = usize::try_from(le32(&bytes, bytes.len() - 22 + 16).unwrap()).unwrap();
        let certificate = signer::tests::certificate_der("Ambiguous Signer");
        let v2_value = signer::tests::signing_value(&certificate);
        let v3_value = signer::tests::signing_value_v3(&certificate, 28, 35);
        let mut pairs = Vec::new();
        for id in [0x7109_871a_u32, 0x7109_871a, 0xf053_68c0] {
            let value = if id == 0xf053_68c0 {
                &v3_value
            } else {
                &v2_value
            };
            pairs.extend_from_slice(&u64::try_from(value.len() + 4).unwrap().to_le_bytes());
            pairs.extend_from_slice(&id.to_le_bytes());
            pairs.extend_from_slice(value);
        }
        let size = u64::try_from(pairs.len() + 24).unwrap();
        let mut block = size.to_le_bytes().to_vec();
        block.extend_from_slice(&pairs);
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(APK_SIG_MAGIC);
        let block_len = block.len();
        bytes.splice(directory..directory, block);
        let end = bytes.len() - 22;
        put32(
            &mut bytes,
            end + 16,
            u32::try_from(directory + block_len).unwrap(),
        );

        let (inventory, archive) = walk(&bytes).unwrap();
        assert!(inventory.apk_signing_block_present);
        assert_eq!(
            inventory.signing_scheme_ids_detected_unverified,
            ["v2", "v3"]
        );
        assert_eq!(inventory.duplicate_signing_scheme_ids, ["v2"]);
        assert_eq!(
            archive
                .signing_values
                .iter()
                .map(|(scheme, _)| *scheme)
                .collect::<Vec<_>>(),
            ["v3"]
        );
        let analysis = analyse(&bytes, &archive);
        assert_eq!(analysis.signers.len(), 1);
        assert_eq!(analysis.signers[0].scheme, "v3");
    }

    /// One member of a built APK: its name, bytes and ZIP compression method (8 deflates it).
    struct Part<'a> {
        name: &'a str,
        bytes: Vec<u8>,
        method: u16,
    }

    fn part(name: &str, bytes: Vec<u8>, method: u16) -> Part<'_> {
        Part {
            name,
            bytes,
            method,
        }
    }

    /// A ZIP laid out as `apksigner` writes an APK: members with true sizes and CRC-32s, then an
    /// optional APK Signing Block holding a v2 value, then the central directory.
    fn apk(parts: &[Part<'_>], v2_value: Option<&[u8]>) -> Vec<u8> {
        let mut zip = Vec::new();
        let mut central = Vec::new();
        for part in parts {
            let payload = if part.method == 8 {
                miniz_oxide::deflate::compress_to_vec(&part.bytes, 6)
            } else {
                part.bytes.clone()
            };
            let crc = crc32fast::hash(&part.bytes);
            let name = part.name.as_bytes();
            let at = u32::try_from(zip.len()).unwrap();
            let mut local = vec![0_u8; 30];
            local[..4].copy_from_slice(LOCAL_SIGNATURE);
            put16(&mut local, 8, part.method);
            put32(&mut local, 14, crc);
            put32(&mut local, 18, u32::try_from(payload.len()).unwrap());
            put32(&mut local, 22, u32::try_from(part.bytes.len()).unwrap());
            put16(&mut local, 26, u16::try_from(name.len()).unwrap());
            zip.extend_from_slice(&local);
            zip.extend_from_slice(name);
            zip.extend_from_slice(&payload);
            let mut entry = vec![0_u8; 46];
            entry[..4].copy_from_slice(CENTRAL_SIGNATURE);
            put16(&mut entry, 10, part.method);
            put32(&mut entry, 16, crc);
            put32(&mut entry, 20, u32::try_from(payload.len()).unwrap());
            put32(&mut entry, 24, u32::try_from(part.bytes.len()).unwrap());
            put16(&mut entry, 28, u16::try_from(name.len()).unwrap());
            put32(&mut entry, 42, at);
            central.extend_from_slice(&entry);
            central.extend_from_slice(name);
        }
        if let Some(value) = v2_value {
            let pair_len = 4 + value.len();
            let size = u64::try_from(8 + pair_len + 8 + 16).unwrap();
            zip.extend_from_slice(&size.to_le_bytes());
            zip.extend_from_slice(&u64::try_from(pair_len).unwrap().to_le_bytes());
            zip.extend_from_slice(&0x7109_871a_u32.to_le_bytes());
            zip.extend_from_slice(value);
            zip.extend_from_slice(&size.to_le_bytes());
            zip.extend_from_slice(APK_SIG_MAGIC);
        }
        let dir_at = u32::try_from(zip.len()).unwrap();
        let dir_size = u32::try_from(central.len()).unwrap();
        zip.extend_from_slice(&central);
        let mut end = vec![0_u8; 22];
        end[..4].copy_from_slice(EOCD_SIGNATURE);
        let count = u16::try_from(parts.len()).unwrap();
        put16(&mut end, 8, count);
        put16(&mut end, 10, count);
        put32(&mut end, 12, dir_size);
        put32(&mut end, 16, dir_at);
        zip.extend_from_slice(&end);
        zip
    }

    fn field_apk(manifest_method: u16) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let release = signer::tests::certificate_der("Field Apps");
        let debug = signer::tests::certificate_der("Android Debug");
        let bytes = apk(
            &[
                part(
                    "AndroidManifest.xml",
                    axml::tests::sample_manifest().build(),
                    manifest_method,
                ),
                part(
                    "classes.dex",
                    dex::tests::dex_with(&[
                        "Lcom/example/field/Main;",
                        "Lcom/appsflyer/AppsFlyerLib;",
                        "https://api.fieldtrack.io/v2/report",
                        "http://schemas.android.com/apk/res/android",
                    ]),
                    8,
                ),
                part(
                    "META-INF/CERT.SF",
                    b"Signature-Version: 1.0\r\n".to_vec(),
                    8,
                ),
                part(
                    "lib/arm64-v8a/libfield.so",
                    elf::tests::elf_with_build_id(true, &[0xca, 0xfe, 0xba, 0xbe]),
                    0,
                ),
                part(
                    "lib/arm64-v8a/libengine.so",
                    elf::tests::elf_with_dynamic(
                        true,
                        Some("libengine.so"),
                        &["libflutter.so", "libc.so"],
                    ),
                    0,
                ),
                part("META-INF/CERT.RSA", signer::tests::pkcs7_der(&debug), 8),
            ],
            Some(&signer::tests::signing_value(&release)),
        );
        (bytes, release, debug)
    }

    fn attr<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
        entity.evidence[0].attributes.get(key).map(String::as_str)
    }

    #[test]
    fn full_apk_report_compares_declared_content_digest_and_preserves_evidence() {
        let cert = signer::tests::certificate_der("Digest Fixture");
        let parts = [part(
            "AndroidManifest.xml",
            axml::tests::sample_manifest().build(),
            0,
        )];
        let placeholder = signer::tests::signing_value_with_sha256_digest(&cert, &[0_u8; 32]);
        let fixture = apk(&parts, Some(&placeholder));
        let (_, archive) = walk(&fixture).unwrap();
        let digest = content_digest::chunked_sha256(
            &fixture,
            archive.signing_start.unwrap(),
            archive.directory_start,
            eocd(&fixture).unwrap(),
        )
        .unwrap();
        let signed_value = signer::tests::signing_value_with_sha256_digest(&cert, &digest);
        let signed = apk(&parts, Some(&signed_value));
        let report = run(&signed, "digest-fixture.apk", 100).unwrap();
        assert_eq!(report.analysis.content_digest_checks.len(), 1);
        assert!(report.analysis.content_digest_checks[0].matches);
        assert!(!report.analysis.content_digest_checks[0].signature_authenticated);
        assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.evidence.iter().any(|evidence| evidence
                    .attributes
                    .get("apk_content_digest_signature_authenticated")
                    .is_some_and(|value| value == "false")))
        );

        // Tamper with the actual local manifest payload, not the untrusted digest claim.
        let mut tampered = signed;
        tampered[30 + "AndroidManifest.xml".len()] ^= 1;
        let report = run(&tampered, "tampered-fixture.apk", 100).unwrap();
        assert_eq!(report.analysis.content_digest_checks.len(), 1);
        assert!(!report.analysis.content_digest_checks[0].matches);
    }

    #[test]
    fn reads_the_manifest_signers_and_code_urls_of_a_built_apk() {
        let (bytes, release, debug) = field_apk(8);
        let report = run(&bytes, "field.apk", 100).expect("apk");
        let analysis = &report.analysis;
        assert!(analysis.unread.is_empty(), "{:?}", analysis.unread);
        assert!(analysis.evasion_indicators.is_empty());
        let manifest = analysis.manifest.as_ref().expect("manifest decoded");
        assert_eq!(manifest.package.as_deref(), Some("com.example.field"));
        assert_eq!(manifest.deep_link_hosts, ["links.example.com"]);
        let digests: Vec<&str> = analysis.signers.iter().map(|s| s.sha256.as_str()).collect();
        assert_eq!(
            digests,
            [hex32(&sha256(&release)), hex32(&sha256(&debug))],
            "the v2 signer, then the v1 signer"
        );
        assert_eq!(analysis.code.urls, ["https://api.fieldtrack.io/v2/report"]);
        assert_eq!(
            analysis.code.trackers,
            [Tracker {
                name: "AppsFlyer".into(),
                category: "attribution".into()
            }],
            "the bundled SDK is named from the DEX type descriptors"
        );
        // The manifest is debuggable and permits cleartext, so the highest risk flag is HIGH.
        assert_eq!(
            risk::highest(&analysis.risk_flags),
            Some(crate::sf_correlate::Risk::High)
        );
        assert!(
            analysis
                .risk_flags
                .iter()
                .any(|flag| flag.id == "debuggable"),
            "{:?}",
            analysis.risk_flags
        );
        let document = &report.entities[0];
        assert_eq!(attr(document, "apk_package"), Some("com.example.field"));
        assert_eq!(attr(document, "apk_risk_highest"), Some("HIGH"));
        assert!(
            attr(document, "apk_risk_flags")
                .unwrap()
                .contains("HIGH debuggable"),
            "{:?}",
            attr(document, "apk_risk_flags")
        );
        assert_eq!(attr(document, "apk_target_sdk"), Some("34"));
        assert_eq!(attr(document, "apk_debuggable"), Some("true"));
        assert_eq!(
            attr(document, "apk_permissions"),
            Some("android.permission.INTERNET,android.permission.READ_SMS")
        );
        assert_eq!(attr(document, "apk_reachable_components"), Some("2"));
        assert_eq!(
            attr(document, "apk_bundled_sdks"),
            Some("AppsFlyer (attribution)")
        );
        assert_eq!(
            attr(document, "apk_signer_subject"),
            Some("CN=Field Apps, O=Example Pty Ltd, C=AU")
        );
        let values: Vec<(EntityKind, &str)> = report.entities[1..]
            .iter()
            .map(|entity| (entity.kind.clone(), entity.value.as_str()))
            .collect();
        assert!(
            values.contains(&(EntityKind::Other, "apk-native-buildid:cafebabe")),
            "{values:?}"
        );
        let release_pivot = format!("apk-signer-sha256:{}", hex32(&sha256(&release)));
        assert!(
            values.contains(&(EntityKind::Other, release_pivot.as_str())),
            "{values:?}"
        );
        // Each distinct signing key is its own pivot entity (two keys here).
        let key_pivots = values
            .iter()
            .filter(|(_, value)| value.starts_with("apk-signer-pubkey-sha256:"))
            .count();
        assert_eq!(
            key_pivots, 2,
            "one pubkey pivot per distinct key: {values:?}"
        );
        assert!(
            values.contains(&(EntityKind::Domain, "api.fieldtrack.io")),
            "{values:?}"
        );
        assert!(values.contains(&(EntityKind::Url, "https://api.fieldtrack.io/v2/report")));
        assert!(
            !values
                .iter()
                .any(|(_, value)| value.contains("example.com")),
            "a placeholder deep-link host is listed in the manifest but is no entity"
        );
        assert_eq!(report.outcomes[0].found, Some(report.entities.len()));
    }

    #[test]
    fn reads_the_native_libraries_build_ids_and_dependencies_of_a_built_apk() {
        let (bytes, ..) = field_apk(8);
        let report = run(&bytes, "field.apk", 100).expect("apk");
        assert_eq!(
            report.analysis.native_build_ids,
            [
                // Sorted by name: the dynamic-only engine library (SONAME + NEEDED, no build-id)
                // then the build-id-only library.
                NativeLibrary {
                    abi: "arm64-v8a".into(),
                    name: "libengine.so".into(),
                    build_id: String::new(),
                    soname: Some("libengine.so".into()),
                    needed: vec!["libflutter.so".into(), "libc.so".into()],
                },
                NativeLibrary {
                    abi: "arm64-v8a".into(),
                    name: "libfield.so".into(),
                    build_id: "cafebabe".into(),
                    soname: None,
                    needed: Vec::new(),
                },
            ],
            "the native libraries' build-id and SONAME/NEEDED are read from their ELF structures"
        );
        let document = &report.entities[0];
        assert_eq!(
            attr(document, "apk_native_build_ids"),
            Some("libfield.so (arm64-v8a): cafebabe"),
            "a library with no build-id is left out of the build-id line"
        );
        assert_eq!(
            attr(document, "apk_native_dependencies"),
            Some("libengine.so -> libflutter.so, libc.so")
        );
        // libengine.so links against libflutter.so, so the app is named a Flutter build.
        assert_eq!(report.analysis.native_frameworks, ["Flutter"]);
        assert_eq!(attr(document, "apk_native_frameworks"), Some("Flutter"));
        let values: Vec<&str> = report.entities[1..]
            .iter()
            .map(|entity| entity.value.as_str())
            .collect();
        assert!(
            values.contains(&"apk-native-buildid:cafebabe"),
            "{values:?}"
        );
        assert!(
            !values.contains(&"apk-native-buildid:"),
            "a library with no build-id must not create an empty build-id pivot: {values:?}"
        );
    }

    #[test]
    fn the_app_label_is_resolved_from_resources_arsc_when_the_manifest_references_it() {
        use axml::tests::{Axml, Val};
        let manifest = Axml::new(&["package"])
            .start("manifest", &[("package", Val::Str("com.example.field"))])
            .start("application", &[("label", Val::Ref(0x7f0e_0001))])
            .end("application")
            .end("manifest")
            .build();
        // resources.arsc resolves id 0x7f0e0001 (package 7f, type 0e, entry 1) to string index 2.
        let resources =
            arsc::tests::table(&["", "com.example.field", "Field Tracker"], 0x7f0e_0001, 2);
        let bytes = apk(
            &[
                part("AndroidManifest.xml", manifest, 8),
                part("resources.arsc", resources, 0),
            ],
            None,
        );
        let report = run(&bytes, "labelled.apk", 100).expect("apk");
        assert_eq!(
            report.analysis.app_label.as_deref(),
            Some("Field Tracker"),
            "the displayed name is resolved through the resource reference"
        );
        assert_eq!(
            attr(&report.entities[0], "apk_app_label"),
            Some("Field Tracker")
        );
    }

    #[test]
    fn resolves_only_the_manifest_referenced_network_policy_not_a_decoy_xml() {
        use axml::tests::{Axml, Val};
        let id = 0x7f0e_0002;
        let manifest = Axml::new(&["package", "networkSecurityConfig"])
            .start("manifest", &[("package", Val::Str("org.example.net"))])
            .start("application", &[("networkSecurityConfig", Val::Ref(id))])
            .end("application")
            .end("manifest")
            .build();
        let resources = arsc::tests::table(&["res/xml/actual.xml"], id, 0);
        let actual = Axml::new(&["cleartextTrafficPermitted"])
            .start("network-security-config", &[])
            .start(
                "base-config",
                &[("cleartextTrafficPermitted", Val::Bool(false))],
            )
            .end("base-config")
            .end("network-security-config")
            .build();
        let decoy = Axml::new(&["cleartextTrafficPermitted"])
            .start("network-security-config", &[])
            .start(
                "base-config",
                &[("cleartextTrafficPermitted", Val::Bool(true))],
            )
            .end("base-config")
            .end("network-security-config")
            .build();
        let bytes = apk(
            &[
                part("AndroidManifest.xml", manifest.clone(), 0),
                part("resources.arsc", resources.clone(), 0),
                part("res/xml/decoy.xml", decoy, 0),
                part("res/xml/actual.xml", actual.clone(), 8),
            ],
            None,
        );
        let report = run(&bytes, "network.apk", 100).unwrap();
        assert_eq!(
            report
                .analysis
                .manifest
                .as_ref()
                .unwrap()
                .network_security_config_resource_id,
            Some(id)
        );
        let policy = report.analysis.network_policy.as_ref().unwrap();
        assert_eq!(policy.resource_path, "res/xml/actual.xml");
        assert_eq!(policy.base_cleartext_permitted, Some(false));
        assert_eq!(
            attr(&report.entities[0], "apk_network_policy_base_cleartext"),
            Some("false")
        );
        assert!(
            report.analysis.unread.is_empty(),
            "{:?}",
            report.analysis.unread
        );

        // Duplicate names are ambiguous, even if both carry the same bytes.
        let duplicate = apk(
            &[
                part("AndroidManifest.xml", manifest, 0),
                part("resources.arsc", resources, 0),
                part("res/xml/actual.xml", actual.clone(), 0),
                part("res/xml/actual.xml", actual, 0),
            ],
            None,
        );
        let report = run(&duplicate, "duplicate.apk", 100).unwrap();
        assert!(report.analysis.network_policy.is_none());
        assert!(
            report
                .analysis
                .unread
                .iter()
                .any(|reason| reason.contains("duplicate ZIP path")),
            "{:?}",
            report.analysis.unread
        );
    }

    fn apk_with_declared_pin(domains: &[&str], pin: &str) -> Vec<u8> {
        use axml::tests::{Axml, Val};
        let id = 0x7f0e_0003;
        let manifest = Axml::new(&["package", "networkSecurityConfig"])
            .start("manifest", &[("package", Val::Str("org.example.pin"))])
            .start("application", &[("networkSecurityConfig", Val::Ref(id))])
            .end("application")
            .end("manifest")
            .build();
        let resources = arsc::tests::table(&["res/xml/pins.xml"], id, 0);
        let mut xml = Axml::new(&["digest", "expiration"]);
        xml.start("network-security-config", &[])
            .start("domain-config", &[]);
        for domain in domains {
            xml.start("domain", &[]).text(domain).end("domain");
        }
        xml.start("pin-set", &[("expiration", Val::Str("2030-01-01"))])
            .start("pin", &[("digest", Val::Str("SHA-256"))])
            .text(pin)
            .end("pin")
            .start("pin", &[("digest", Val::Str("SHA-256"))])
            .text("not-a-valid-digest")
            .end("pin")
            .end("pin-set")
            .end("domain-config")
            .end("network-security-config");
        apk(
            &[
                part("AndroidManifest.xml", manifest, 0),
                part("resources.arsc", resources, 0),
                part("res/xml/pins.xml", xml.build(), 0),
            ],
            None,
        )
    }

    #[test]
    fn tls_pin_graph_pivots_preserve_scopes_and_match_across_distinct_apks() {
        let pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let first = run(
            &apk_with_declared_pin(&["alpha.example.org", "beta.example.org"], pin),
            "first.apk",
            100,
        )
        .unwrap();
        let pivots: Vec<_> = first
            .entities
            .iter()
            .filter(|entity| entity.value.starts_with("apk-tls-spki-sha256:"))
            .collect();
        assert_eq!(pivots.len(), 1, "one entity for one valid pin digest");
        assert_eq!(
            pivots[0].value,
            format!("apk-tls-spki-sha256:{}", "00".repeat(32))
        );
        assert_eq!(
            attr(pivots[0], "declared_domains"),
            Some("alpha.example.org,beta.example.org")
        );
        assert!(
            attr(pivots[0], "declared_scopes")
                .unwrap()
                .contains("expiration=2030-01-01")
        );
        assert_eq!(attr(pivots[0], "pin_sha256_base64"), Some(pin));
        let second = run(
            &apk_with_declared_pin(&["other.example.net"], pin),
            "second.apk",
            101,
        )
        .unwrap();
        let other = second
            .entities
            .iter()
            .find(|entity| entity.value.starts_with("apk-tls-spki-sha256:"))
            .unwrap();
        assert_eq!(
            pivots[0].uid, other.uid,
            "same digest yields same pivot UID"
        );
        assert_eq!(attr(other, "declared_domains"), Some("other.example.net"));
        // Different 32-byte digests whose Base64 differs only in letter case
        // must never collapse under EntityKind::Other's lowercase normalisation.
        let case_variant = format!("a{}", &pin[1..]);
        let variant = run(
            &apk_with_declared_pin(&["case.example.net"], &case_variant),
            "variant.apk",
            102,
        )
        .unwrap();
        let variant_pivot = variant
            .entities
            .iter()
            .find(|entity| entity.value.starts_with("apk-tls-spki-sha256:"))
            .unwrap();
        assert_ne!(pivots[0].uid, variant_pivot.uid);
        assert_eq!(first.outcomes[0].found, Some(first.entities.len()));
    }

    #[test]
    fn rejects_unsafe_or_missing_network_policy_resource_paths() {
        assert!(!valid_network_xml_path("res/layout/not_policy.xml"));
        assert!(!valid_network_xml_path("res/xml/../not_policy.xml"));
        assert!(!valid_network_xml_path("/res/xml/not_policy.xml"));
        assert!(!valid_network_xml_path("res/xml/not_policy.xml/extra"));
        assert!(valid_network_xml_path("res/xml-v24/network.xml"));
    }

    #[test]
    fn an_unknown_compression_method_is_read_as_android_reads_it_and_flagged() {
        let (bytes, ..) = field_apk(0x6301);
        let report = run(&bytes, "evasive.apk", 100).expect("apk");
        assert_eq!(
            report
                .analysis
                .manifest
                .as_ref()
                .and_then(|m| m.package.as_deref()),
            Some("com.example.field")
        );
        assert_eq!(report.analysis.evasion_indicators.len(), 1);
        assert!(report.analysis.evasion_indicators[0].contains("compression method 25345"));
    }

    #[test]
    fn a_member_failing_its_crc_or_the_inflate_budget_is_reported_unread() {
        let (mut bytes, ..) = field_apk(0);
        // Flip a byte inside the stored manifest: its CRC-32 no longer matches.
        let at = 30 + "AndroidManifest.xml".len() + 40;
        bytes[at] ^= 0xff;
        let report = run(&bytes, "tampered.apk", 100).expect("apk");
        assert!(report.analysis.manifest.is_none());
        assert!(
            report
                .analysis
                .manifest_error
                .as_deref()
                .is_some_and(|e| e.contains("CRC-32")),
            "{:?}",
            report.analysis.manifest_error
        );
        assert_eq!(report.analysis.signers.len(), 2, "the rest is still read");

        let (bytes, ..) = field_apk(8);
        let (_, archive) = walk(&bytes).unwrap();
        let mut budget = 10;
        let manifest = archive.manifest.as_ref().unwrap();
        let refused =
            read_member(&bytes, manifest, MAX_APK_MANIFEST_BYTES, &mut budget).unwrap_err();
        assert!(refused.contains("budget"), "{refused}");
        let mut budget = MAX_APK_INFLATED_BYTES;
        let refused = read_member(&bytes, manifest, 16, &mut budget).unwrap_err();
        assert!(refused.contains("limit"), "{refused}");
        assert_eq!(
            budget, MAX_APK_INFLATED_BYTES,
            "a refused member spends nothing"
        );
    }
}
