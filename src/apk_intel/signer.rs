//! The certificates an APK is signed with, found where Android's verifier finds them: the X.509
//! certificates of each signer in an APK Signature Scheme v2/v3 block, and those of a v1 (JAR)
//! signature's PKCS#7 `SignedData` in `META-INF/*.RSA`, `.DSA` or `.EC`.
//!
//! Each certificate is identified by the SHA-256 digest of its DER encoding, the value
//! `apksigner verify --print-certs` prints as the "certificate SHA-256 digest" and app stores and
//! malware repositories index signers by, so two APKs signed by the same key pivot to each other.
//! Its subject, issuer, serial number and validity are read from the DER for the analyst. No
//! certificate-chain trust is established by extraction alone. Supported v2/v3 signed-data
//! signatures are checked separately against their declared public keys and APK content digests;
//! neither this nor a subject name proves ownership, CA trust or Android installability.

use serde::Serialize;

use crate::sha256::{hex32, sha256};

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const OID: u8 = 0x06;
const CONTEXT_0: u8 = 0xa0;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// A certificate name value longer than this is cut, with a marker.
const MAX_NAME_VALUE: usize = 256;
/// Certificates kept per signature; a real signer presents one, rarely a short chain.
const MAX_CERTIFICATES: usize = 8;

const NAME_ATTRIBUTES: [(&[u8], &str); 8] = [
    (&[0x55, 0x04, 0x03], "CN"),
    (&[0x55, 0x04, 0x0b], "OU"),
    (&[0x55, 0x04, 0x0a], "O"),
    (&[0x55, 0x04, 0x07], "L"),
    (&[0x55, 0x04, 0x08], "ST"),
    (&[0x55, 0x04, 0x06], "C"),
    (&[0x55, 0x04, 0x05], "SERIALNUMBER"),
    (
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01],
        "EMAIL",
    ),
];

/// One signing certificate as the archive presents it, unverified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Certificate {
    /// Where it was found: `v2`, `v3`, `v3.1` or the v1 signature file's name.
    pub scheme: String,
    /// SHA-256 of the certificate's DER bytes, as `apksigner --print-certs` prints it.
    pub sha256: String,
    /// SHA-256 of the `SubjectPublicKeyInfo` DER — the signing key's own identity, as
    /// `apksigner --print-certs` prints for the public key. Google Play keys app-signing identity
    /// and key rotation on this, so it pivots across certificates that re-wrap the same key.
    pub public_key_sha256: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    /// The subject and issuer are the same name: no CA vouched for it, as is usual on Android.
    pub self_signed: bool,
    /// The SDK's debug key (`CN=Android Debug`): a development build, not a store release.
    pub android_debug: bool,
}

/// A v3/v3.1 signing-certificate claim scoped to an Android SDK range.
/// These are structurally checked declarations, not authenticated signer selections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SdkSigner {
    pub scheme: String,
    pub signer_index: usize,
    pub min_sdk: u32,
    pub max_sdk: u32,
    pub certificate_sha256: String,
    pub public_key_sha256: String,
    pub authentication: &'static str,
}

/// One DER element: its tag, where it begins, and the range of its contents (which ends it).
#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    at: usize,
    start: usize,
    end: usize,
}

/// The element at `at`, inside `limit`. Indefinite lengths and multi-byte tags (neither of which
/// DER certificates use) are refused.
fn tlv(data: &[u8], at: usize, limit: usize) -> Option<Tlv> {
    let tag = *data.get(at)?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *data.get(at + 1)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(at + 2..at + 2 + count)?;
        let length = bytes
            .iter()
            .fold(0_usize, |sum, byte| (sum << 8) | usize::from(*byte));
        (length, 2 + count)
    };
    let start = at.checked_add(header)?;
    let end = start.checked_add(length)?;
    (end <= limit && end <= data.len()).then_some(Tlv {
        tag,
        at,
        start,
        end,
    })
}

/// The elements inside `outer`, in order; `None` if they do not exactly fill it.
fn children(data: &[u8], outer: Tlv) -> Option<Vec<Tlv>> {
    let mut at = outer.start;
    let mut list = Vec::new();
    while at < outer.end {
        let child = tlv(data, at, outer.end)?;
        at = child.end;
        list.push(child);
    }
    Some(list)
}

fn name_value(data: &[u8], value: Tlv) -> String {
    let raw = &data[value.start..value.end];
    let text = match value.tag {
        // BMPString is UTF-16BE.
        0x1e => {
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        // T61String is read as Latin-1, as most decoders do.
        0x14 => raw.iter().map(|byte| char::from(*byte)).collect(),
        _ => String::from_utf8_lossy(raw).into_owned(),
    };
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.chars().count() > MAX_NAME_VALUE {
        let cut: String = clean.chars().take(MAX_NAME_VALUE).collect();
        format!("{cut}… ({} characters)", clean.chars().count())
    } else {
        clean
    }
}

/// A distinguished name as `ATTR=value` pairs in the certificate's own order.
fn name(data: &[u8], name: Tlv) -> Option<String> {
    let mut parts = Vec::new();
    for set in children(data, name)? {
        for pair in children(data, set)? {
            let [oid, value] = children(data, pair)?[..] else {
                return None;
            };
            if oid.tag != OID {
                return None;
            }
            let oid = &data[oid.start..oid.end];
            let label = NAME_ATTRIBUTES
                .iter()
                .find(|(known, _)| *known == oid)
                .map_or_else(|| dotted(oid), |(_, label)| (*label).to_owned());
            parts.push(format!("{label}={}", name_value(data, value)));
        }
    }
    Some(parts.join(", "))
}

/// An object identifier in dotted form, for a name attribute without a short label.
fn dotted(oid: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value = 0_u64;
    for byte in oid {
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if arcs.is_empty() {
                let first = value.min(80) / 40;
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// A `UTCTime` or `GeneralizedTime` as `YYYY-MM-DDTHH:MM:SSZ`.
fn time(data: &[u8], time: Tlv) -> Option<String> {
    let text = std::str::from_utf8(&data[time.start..time.end]).ok()?;
    let digits = text.strip_suffix('Z')?;
    let full = match (time.tag, digits.len()) {
        (UTC_TIME, 12) => {
            let year: u32 = digits[..2].parse().ok()?;
            format!("{}{digits}", if year < 50 { "20" } else { "19" })
        }
        (GENERALIZED_TIME, 14) => digits.to_owned(),
        _ => return None,
    };
    if !full.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}T{}:{}:{}Z",
        &full[..4],
        &full[4..6],
        &full[6..8],
        &full[8..10],
        &full[10..12],
        &full[12..14]
    ))
}

/// The summary of the X.509 certificate `der`, or `None` if it is not one.
pub(super) fn certificate(der: &[u8], scheme: &str) -> Option<Certificate> {
    let outer = tlv(der, 0, der.len())?;
    if outer.tag != SEQUENCE || outer.end != der.len() {
        return None;
    }
    let tbs = *children(der, outer)?.first()?;
    if tbs.tag != SEQUENCE {
        return None;
    }
    let fields = children(der, tbs)?;
    // The version is optional ([0] EXPLICIT); the fields after it are in a fixed order.
    let skip = usize::from(fields.first()?.tag == CONTEXT_0);
    let [serial, _algorithm, issuer, validity, subject, spki, ..] = fields.get(skip..)? else {
        return None;
    };
    if serial.tag != INTEGER || validity.tag != SEQUENCE || spki.tag != SEQUENCE {
        return None;
    }
    let [not_before, not_after] = children(der, *validity)?[..] else {
        return None;
    };
    let subject_name = name(der, *subject)?;
    Some(Certificate {
        scheme: scheme.to_owned(),
        sha256: hex32(&sha256(der)),
        public_key_sha256: hex32(&sha256(der.get(spki.at..spki.end)?)),
        android_debug: subject_name
            .split(", ")
            .any(|part| part == "CN=Android Debug"),
        self_signed: der[issuer.start..issuer.end] == der[subject.start..subject.end],
        issuer: name(der, *issuer)?,
        subject: subject_name,
        serial: hex(&der[serial.start..serial.end]),
        not_before: time(der, not_before)?,
        not_after: time(der, not_after)?,
    })
}

/// The certificates of a v1 signature: the PKCS#7 `SignedData` in a `META-INF` signature file.
#[must_use]
pub fn pkcs7(der: &[u8], file: &str) -> Vec<Certificate> {
    let found = || -> Option<Vec<Certificate>> {
        let info = tlv(der, 0, der.len())?;
        let [oid, explicit] = children(der, info)?[..] else {
            return None;
        };
        if oid.tag != OID || &der[oid.start..oid.end] != SIGNED_DATA || explicit.tag != CONTEXT_0 {
            return None;
        }
        let signed = *children(der, explicit)?.first()?;
        // version, digestAlgorithms, contentInfo, then the optional [0] IMPLICIT certificates.
        let fields = children(der, signed)?;
        let [version, algorithms, _content, certificates, ..] = fields[..] else {
            return None;
        };
        if version.tag != INTEGER || algorithms.tag != SET || certificates.tag != CONTEXT_0 {
            return None;
        }
        Some(
            children(der, certificates)?
                .into_iter()
                .take(MAX_CERTIFICATES)
                .filter_map(|cert| certificate(&der[cert.at..cert.end], file))
                .collect(),
        )
    };
    found().unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

pub(super) fn le32(data: &[u8], at: usize) -> Option<usize> {
    let field = data.get(at..at.checked_add(4)?)?;
    usize::try_from(u32::from_le_bytes([field[0], field[1], field[2], field[3]])).ok()
}

/// One checked u32-length-prefixed item, without assuming later fields are prefixed.
/// v3/v3.1 interleave raw SDK integers with length-prefixed fields.
pub(super) fn prefixed_one(data: &[u8], at: usize, end: usize) -> Option<(usize, usize)> {
    let length = le32(data, at)?;
    let from = at.checked_add(4)?;
    let to = from.checked_add(length)?;
    (to <= end).then_some((from, to))
}

/// The u32-length-prefixed items exactly filling data[start..end].
pub(super) fn prefixed(data: &[u8], start: usize, end: usize) -> Option<Vec<(usize, usize)>> {
    let mut at = start;
    let mut items = Vec::new();
    while at < end {
        let item = prefixed_one(data, at, end)?;
        at = item.1;
        items.push(item);
    }
    Some(items)
}

/// Extract certificate claims only from a structurally consistent signer.
/// This does NOT verify its cryptographic signature or APK content digests.
fn signer_certificates(
    value: &[u8],
    signer_start: usize,
    signer_end: usize,
    scheme: &str,
) -> Option<Vec<Certificate>> {
    let (data_start, data_end) = prefixed_one(value, signer_start, signer_end)?;
    let (_, digests_end) = prefixed_one(value, data_start, data_end)?;
    let (certs_start, certs_end) = prefixed_one(value, digests_end, data_end)?;

    let (attrs_at, signatures_at) = match scheme {
        "v2" => (certs_end, data_end),
        "v3" | "v3.1" => {
            let inner_min = le32(value, certs_end)?;
            let inner_max = le32(value, certs_end.checked_add(4)?)?;
            let outer_min = le32(value, data_end)?;
            let outer_max = le32(value, data_end.checked_add(4)?)?;
            if inner_min > inner_max || (inner_min, inner_max) != (outer_min, outer_max) {
                return None;
            }
            (certs_end.checked_add(8)?, data_end.checked_add(8)?)
        }
        _ => return None,
    };

    let (_, attrs_end) = prefixed_one(value, attrs_at, data_end)?;
    if attrs_end != data_end {
        return None;
    }
    let (_, signatures_end) = prefixed_one(value, signatures_at, signer_end)?;
    let (key_start, key_end) = prefixed_one(value, signatures_end, signer_end)?;
    if key_end != signer_end {
        return None;
    }
    let declared_key_sha256 = hex32(&sha256(&value[key_start..key_end]));
    let mut certificates = Vec::new();
    for (index, (from, to)) in prefixed(value, certs_start, certs_end)?
        .into_iter()
        .enumerate()
    {
        let cert = certificate(&value[from..to], scheme)?;
        if index == 0 && cert.public_key_sha256 != declared_key_sha256 {
            return None;
        }
        if certificates.len() < MAX_CERTIFICATES {
            certificates.push(cert);
        }
    }
    Some(certificates)
}

/// Read SHA-256 chunked-content digest declarations from structurally consistent signers.
/// A digest declaration is NOT authenticated until the signed-data signature is verified.
/// Unsupported algorithms are omitted; malformed records reject the scheme's observations.
pub(super) fn sha256_digests(value: &[u8], scheme: &str) -> Option<Vec<(usize, u32, [u8; 32])>> {
    let [(start, end)] = prefixed(value, 0, value.len())?[..] else {
        return None;
    };
    let mut found = Vec::new();
    for (index, (signer_start, signer_end)) in prefixed(value, start, end)?.into_iter().enumerate()
    {
        signer_certificates(value, signer_start, signer_end, scheme)?;
        let (data_start, data_end) = prefixed_one(value, signer_start, signer_end)?;
        let (digests_start, digests_end) = prefixed_one(value, data_start, data_end)?;
        let mut seen = std::collections::BTreeSet::new();
        for (record_start, record_end) in prefixed(value, digests_start, digests_end)? {
            let algorithm = u32::try_from(le32(value, record_start)?).ok()?;
            let (value_start, value_end) =
                prefixed_one(value, record_start.checked_add(4)?, record_end)?;
            if value_end != record_end || !seen.insert(algorithm) {
                return None;
            }
            // Android's chunked SHA-256 signature algorithms. Verity digests and
            // SHA-512 have different formats and are intentionally not compared.
            if matches!(algorithm, 0x0101 | 0x0103 | 0x0201 | 0x0301) {
                let digest: [u8; 32] = value[value_start..value_end].try_into().ok()?;
                if found.len() >= 64 {
                    return None;
                }
                found.push((index, algorithm, digest));
            }
        }
    }
    Some(found)
}

/// Return the APK signing-record authentication state for a SHA-256 digest claim.
/// This verifies the signature over signed-data, not Android installability or a CA chain.
pub(super) fn verify_sha256_signature(
    value: &[u8],
    scheme: &str,
    signer_index: usize,
    algorithm_id: u32,
) -> &'static str {
    if !matches!(algorithm_id, 0x0101 | 0x0103 | 0x0201) {
        return "unsupported";
    }
    let Some(outer) = prefixed(value, 0, value.len()) else {
        return "malformed";
    };
    let [(start, end)] = outer.as_slice() else {
        return "malformed";
    };
    let Some(signers) = prefixed(value, *start, *end) else {
        return "malformed";
    };
    let Some((signer_start, signer_end)) = signers.get(signer_index).copied() else {
        return "malformed";
    };
    if signer_certificates(value, signer_start, signer_end, scheme)
        .is_none_or(|certs| certs.is_empty())
    {
        return "malformed";
    }
    let Some((data_start, data_end)) = prefixed_one(value, signer_start, signer_end) else {
        return "malformed";
    };
    let signatures_at = match scheme {
        "v2" => data_end,
        "v3" | "v3.1" => data_end.saturating_add(8),
        _ => return "unsupported",
    };
    let Some((signatures_start, signatures_end)) = prefixed_one(value, signatures_at, signer_end)
    else {
        return "malformed";
    };
    let Some((digests_start, digests_end)) = prefixed_one(value, data_start, data_end) else {
        return "malformed";
    };
    let digest_algorithms = algorithm_ids(value, digests_start, digests_end);
    let signature_algorithms = algorithm_ids(value, signatures_start, signatures_end);
    if digest_algorithms.is_none() || digest_algorithms != signature_algorithms {
        return "malformed";
    }
    let Some((key_start, key_end)) = prefixed_one(value, signatures_end, signer_end) else {
        return "malformed";
    };
    if key_end != signer_end {
        return "malformed";
    }
    let signature = match matching_signature(value, signatures_start, signatures_end, algorithm_id)
    {
        SignatureRecord::Found(bytes) => bytes,
        SignatureRecord::Missing => return "missing",
        SignatureRecord::Malformed => return "malformed",
    };
    let Some(public_key) = signing_public_key(&value[key_start..key_end], algorithm_id) else {
        return "unsupported";
    };
    let signed_data = &value[data_start..data_end];
    let valid = match algorithm_id {
        0x0101 => ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PSS_2048_8192_SHA256,
            public_key,
        )
        .verify(signed_data, signature)
        .is_ok(),
        0x0103 => ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            public_key,
        )
        .verify(signed_data, signature)
        .is_ok(),
        0x0201 => ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            public_key,
        )
        .verify(signed_data, signature)
        .is_ok(),
        _ => false,
    };
    if valid { "verified" } else { "invalid" }
}

/// Extract an algorithm-bound public key from DER `SubjectPublicKeyInfo`.
/// RSA uses the embedded PKCS#1 key; P-256 ECDSA uses its uncompressed point.
fn signing_public_key(spki: &[u8], algorithm_id: u32) -> Option<&[u8]> {
    let outer = tlv(spki, 0, spki.len())?;
    if outer.tag != SEQUENCE || outer.end != spki.len() {
        return None;
    }
    let fields = children(spki, outer)?;
    if fields.len() != 2 || fields[0].tag != SEQUENCE || fields[1].tag != 0x03 {
        return None;
    }
    let algorithm = children(spki, fields[0])?;
    let oid = algorithm.first()?;
    if oid.tag != OID {
        return None;
    }
    let name = spki.get(oid.start..oid.end)?;
    let rsa_oid = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let ec_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let p256_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let algorithm_matches = match algorithm_id {
        0x0101 | 0x0103 => {
            name == rsa_oid
                && (algorithm.len() == 1
                    || (algorithm.len() == 2
                        && algorithm[1].tag == 0x05
                        && algorithm[1].start == algorithm[1].end))
        }
        0x0201 => {
            name == ec_oid
                && algorithm.len() == 2
                && algorithm[1].tag == OID
                && spki.get(algorithm[1].start..algorithm[1].end)? == p256_oid
        }
        _ => false,
    };
    if !algorithm_matches {
        return None;
    }
    let bits = spki.get(fields[1].start..fields[1].end)?;
    let (unused, key) = bits.split_first()?;
    (*unused == 0 && !key.is_empty()).then_some(key)
}

/// Return the exact DER `SubjectPublicKeyInfo` from a well-formed X.509 certificate.
pub(super) fn certificate_spki(der: &[u8]) -> Option<&[u8]> {
    let outer = tlv(der, 0, der.len())?;
    if outer.tag != SEQUENCE || outer.end != der.len() {
        return None;
    }
    let tbs = *children(der, outer)?.first()?;
    if tbs.tag != SEQUENCE {
        return None;
    }
    let fields = children(der, tbs)?;
    let skip = usize::from(fields.first()?.tag == CONTEXT_0);
    let spki = *fields.get(skip.checked_add(5)?)?;
    (spki.tag == SEQUENCE).then(|| &der[spki.at..spki.end])
}

/// Verify a proof-of-rotation child node with its parent's certificate public key.
/// Unsupported algorithms fail closed rather than becoming authenticated identities.
pub(super) fn verify_rotation_signature(
    parent_der: &[u8],
    algorithm_id: u32,
    signed_data: &[u8],
    signature: &[u8],
) -> Option<bool> {
    let key = signing_public_key(certificate_spki(parent_der)?, algorithm_id)?;
    let verified = match algorithm_id {
        0x0101 => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PSS_2048_8192_SHA256, key)
                .verify(signed_data, signature)
                .is_ok()
        }
        0x0103 => ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key,
        )
        .verify(signed_data, signature)
        .is_ok(),
        0x0201 => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, key)
                .verify(signed_data, signature)
                .is_ok()
        }
        _ => return None,
    };
    Some(verified)
}

/// Android requires the ordered digest and signature algorithm lists to be identical.
fn algorithm_ids(value: &[u8], start: usize, end: usize) -> Option<Vec<u32>> {
    let records = prefixed(value, start, end)?;
    if records.len() > 64 {
        return None;
    }
    let mut ids = Vec::new();
    for (from, to) in records {
        let id = u32::try_from(le32(value, from)?).ok()?;
        let (_, payload_end) = prefixed_one(value, from.checked_add(4)?, to)?;
        if payload_end != to || ids.contains(&id) {
            return None;
        }
        ids.push(id);
    }
    Some(ids)
}

enum SignatureRecord<'a> {
    Malformed,
    Missing,
    Found(&'a [u8]),
}

/// Locate the signature with exactly the digest claim's algorithm identifier.
fn matching_signature(
    value: &[u8],
    start: usize,
    end: usize,
    algorithm_id: u32,
) -> SignatureRecord<'_> {
    let Some(records) = prefixed(value, start, end) else {
        return SignatureRecord::Malformed;
    };
    if records.len() > 64 {
        return SignatureRecord::Malformed;
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut found = None;
    for (from, to) in records {
        let Some(id) = le32(value, from).and_then(|n| u32::try_from(n).ok()) else {
            return SignatureRecord::Malformed;
        };
        let Some((bytes_start, bytes_end)) = from
            .checked_add(4)
            .and_then(|at| prefixed_one(value, at, to))
        else {
            return SignatureRecord::Malformed;
        };
        if bytes_end != to || !seen.insert(id) || bytes_end - bytes_start > 8192 {
            return SignatureRecord::Malformed;
        }
        if id == algorithm_id {
            found = Some(&value[bytes_start..bytes_end]);
        }
    }
    match found {
        Some(bytes) => SignatureRecord::Found(bytes),
        None => SignatureRecord::Missing,
    }
}

/// Certificates declared by v2/v3/v3.1 signers, with SDK-copy and public-key consistency
/// checks. Neither these checks nor certificate extraction authenticate the APK.
#[must_use]
pub fn signing_block(value: &[u8], scheme: &str) -> Vec<Certificate> {
    let found = || -> Option<Vec<Certificate>> {
        let [(start, end)] = prefixed(value, 0, value.len())?[..] else {
            return None;
        };
        let mut certificates = Vec::new();
        for (signer_start, signer_end) in prefixed(value, start, end)? {
            certificates.extend(signer_certificates(
                value,
                signer_start,
                signer_end,
                scheme,
            )?);
            certificates.truncate(MAX_CERTIFICATES);
        }
        Some(certificates)
    };
    found().unwrap_or_default()
}

/// Extract SDK-scoped v3/v3.1 signer identities without implying installation or
/// cryptographic verification. All signers in a scheme must be structurally valid;
/// malformed SDK copies, missing certificates or oversized lists withhold that scheme.
pub(super) fn sdk_signers(value: &[u8], scheme: &str) -> Vec<SdkSigner> {
    if !matches!(scheme, "v3" | "v3.1") {
        return Vec::new();
    }
    let read = || -> Option<Vec<SdkSigner>> {
        let [(start, end)] = prefixed(value, 0, value.len())?[..] else {
            return None;
        };
        let signers = prefixed(value, start, end)?;
        if signers.len() > MAX_CERTIFICATES {
            return None;
        }
        let mut result = Vec::new();
        for (index, (signer_start, signer_end)) in signers.into_iter().enumerate() {
            let certificates = signer_certificates(value, signer_start, signer_end, scheme)?;
            let certificate = certificates.first()?;
            let (data_start, data_end) = prefixed_one(value, signer_start, signer_end)?;
            let (_, digests_end) = prefixed_one(value, data_start, data_end)?;
            let (_, certs_end) = prefixed_one(value, digests_end, data_end)?;
            let min_sdk = u32::try_from(le32(value, certs_end)?).ok()?;
            let max_sdk = u32::try_from(le32(value, certs_end.checked_add(4)?)?).ok()?;
            result.push(SdkSigner {
                scheme: scheme.to_owned(),
                signer_index: index,
                min_sdk,
                max_sdk,
                certificate_sha256: certificate.sha256.clone(),
                public_key_sha256: certificate.public_key_sha256.clone(),
                authentication: "not_verified",
            });
        }
        Some(result)
    };
    read().unwrap_or_default()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn element(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match contents.len() {
            short @ 0..0x80 => out.push(u8::try_from(short).unwrap()),
            long @ 0x80..0x100 => out.extend_from_slice(&[0x81, u8::try_from(long).unwrap()]),
            long => {
                let bytes = u16::try_from(long).unwrap().to_be_bytes();
                out.extend_from_slice(&[0x82, bytes[0], bytes[1]]);
            }
        }
        out.extend_from_slice(contents);
        out
    }

    fn dn(pairs: &[(&[u8], &str)]) -> Vec<u8> {
        let mut sets = Vec::new();
        for (oid, value) in pairs {
            let mut pair = element(OID, oid);
            pair.extend(element(0x0c, value.as_bytes()));
            sets.extend(element(SET, &element(SEQUENCE, &pair)));
        }
        element(SEQUENCE, &sets)
    }

    /// A structurally complete self-signed X.509 certificate (its signature is filler, which
    /// nothing here checks).
    pub(crate) fn certificate_der(common_name: &str) -> Vec<u8> {
        let name = dn(&[
            (&[0x55, 0x04, 0x03], common_name),
            (&[0x55, 0x04, 0x0a], "Example Pty Ltd"),
            (&[0x55, 0x04, 0x06], "AU"),
        ]);
        let algorithm = element(
            SEQUENCE,
            &element(OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        );
        let mut validity = element(UTC_TIME, b"200101000000Z");
        validity.extend(element(GENERALIZED_TIME, b"20500101000000Z"));
        let mut tbs = element(CONTEXT_0, &element(INTEGER, &[2]));
        tbs.extend(element(INTEGER, &[0x01, 0xab]));
        tbs.extend(&algorithm);
        tbs.extend(&name);
        tbs.extend(element(SEQUENCE, &validity));
        tbs.extend(&name);
        // A stand-in SubjectPublicKeyInfo that carries the common name, so certificates with
        // different names have different public keys (as real distinct keys would).
        tbs.extend(element(SEQUENCE, common_name.as_bytes()));
        let mut cert = element(SEQUENCE, &tbs);
        cert.extend(&algorithm);
        cert.extend(element(0x03, &[0, 1, 2, 3]));
        element(SEQUENCE, &cert)
    }

    /// The PKCS#7 `SignedData` a v1 signature file holds, around `cert`.
    pub(crate) fn pkcs7_der(cert: &[u8]) -> Vec<u8> {
        let mut signed = element(INTEGER, &[1]);
        signed.extend(element(SET, &[]));
        signed.extend(element(
            SEQUENCE,
            &element(OID, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]),
        ));
        signed.extend(element(CONTEXT_0, cert));
        signed.extend(element(SET, &[]));
        let mut info = element(OID, SIGNED_DATA);
        info.extend(element(CONTEXT_0, &element(SEQUENCE, &signed)));
        element(SEQUENCE, &info)
    }

    fn prefix(items: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for item in items {
            out.extend_from_slice(&u32::try_from(item.len()).unwrap().to_le_bytes());
            out.extend_from_slice(item);
        }
        out
    }

    pub(crate) fn spki(cert: &[u8]) -> &[u8] {
        let outer = tlv(cert, 0, cert.len()).unwrap();
        let tbs = children(cert, outer).unwrap()[0];
        let fields = children(cert, tbs).unwrap();
        let skip = usize::from(fields[0].tag == CONTEXT_0);
        let key = fields[skip + 5];
        &cert[key.at..key.end]
    }

    /// Test-only certificate containing a genuine P-256 public key.
    pub(crate) fn p256_certificate(common_name: &str, point: &[u8]) -> Vec<u8> {
        let original = certificate_der(common_name);
        let outer = tlv(&original, 0, original.len()).unwrap();
        let parts = children(&original, outer).unwrap();
        let fields = children(&original, parts[0]).unwrap();
        let key_index = usize::from(fields[0].tag == CONTEXT_0) + 5;
        let mut algorithm = element(OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        algorithm.extend(element(
            OID,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        ));
        let mut bits = vec![0];
        bits.extend_from_slice(point);
        let mut key = element(SEQUENCE, &algorithm);
        key.extend(element(0x03, &bits));
        let spki = element(SEQUENCE, &key);
        let mut tbs = Vec::new();
        for (index, field) in fields.iter().enumerate() {
            if index == key_index {
                tbs.extend_from_slice(&spki);
            } else {
                tbs.extend_from_slice(&original[field.at..field.end]);
            }
        }
        let mut certificate = element(SEQUENCE, &tbs);
        for field in parts.iter().skip(1) {
            certificate.extend_from_slice(&original[field.at..field.end]);
        }
        element(SEQUENCE, &certificate)
    }

    /// A v2 signing-block value holding one signer with `cert`.
    pub(crate) fn signing_value(cert: &[u8]) -> Vec<u8> {
        let digests = prefix(&[]);
        let certs = prefix(&[cert]);
        let signed_data = prefix(&[&digests, &certs, &prefix(&[])]);
        let signer = prefix(&[&signed_data, &prefix(&[]), spki(cert)]);
        prefix(&[&prefix(&[&signer])])
    }

    /// A v3/v3.1 signer has raw SDK fields both inside and outside signed data.
    pub(crate) fn signing_value_v3(cert: &[u8], min_sdk: u32, max_sdk: u32) -> Vec<u8> {
        let digests = prefix(&[]);
        let certs = prefix(&[cert]);
        let mut signed_data = prefix(&[&digests, &certs]);
        signed_data.extend_from_slice(&min_sdk.to_le_bytes());
        signed_data.extend_from_slice(&max_sdk.to_le_bytes());
        signed_data.extend_from_slice(&prefix(&[&[]]));
        let mut signer = prefix(&[&signed_data]);
        signer.extend_from_slice(&min_sdk.to_le_bytes());
        signer.extend_from_slice(&max_sdk.to_le_bytes());
        signer.extend_from_slice(&prefix(&[&[], spki(cert)]));
        prefix(&[&prefix(&[&signer])])
    }

    /// Test-only structurally valid v2 signer with a declared SHA-256 digest.
    pub(crate) fn signing_value_with_sha256_digest(cert: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        let mut record = 0x0103_u32.to_le_bytes().to_vec();
        record.extend(prefix(&[digest]));
        let digests = prefix(&[&record]);
        let certs = prefix(&[cert]);
        let signed_data = prefix(&[&digests, &certs, &prefix(&[])]);
        let signer = prefix(&[&signed_data, &prefix(&[]), spki(cert)]);
        prefix(&[&prefix(&[&signer])])
    }

    /// A real P-256 signature authenticates the exact v2 signed-data bytes.
    #[test]
    fn ecdsa_signed_data_authenticates_and_tampering_fails() {
        use ring::signature::KeyPair as _;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let mut algorithm = element(OID, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        algorithm.extend(element(
            OID,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        ));
        let mut key_bits = vec![0];
        key_bits.extend_from_slice(keypair.public_key().as_ref());
        let mut spki_contents = element(SEQUENCE, &algorithm);
        spki_contents.extend(element(0x03, &key_bits));
        let spki = element(SEQUENCE, &spki_contents);

        let old = certificate_der("Authenticated P256");
        let outer = tlv(&old, 0, old.len()).unwrap();
        let parts = children(&old, outer).unwrap();
        let tbs_fields = children(&old, parts[0]).unwrap();
        let key_index = usize::from(tbs_fields[0].tag == CONTEXT_0) + 5;
        let mut tbs = Vec::new();
        for (index, field) in tbs_fields.iter().enumerate() {
            if index == key_index {
                tbs.extend_from_slice(&spki);
            } else {
                tbs.extend_from_slice(&old[field.at..field.end]);
            }
        }
        let mut cert_contents = element(SEQUENCE, &tbs);
        for part in parts.iter().skip(1) {
            cert_contents.extend_from_slice(&old[part.at..part.end]);
        }
        let cert = element(SEQUENCE, &cert_contents);
        let digest = [0x42; 32];
        let mut digest_record = 0x0201_u32.to_le_bytes().to_vec();
        digest_record.extend(prefix(&[&digest]));
        let signed_data = prefix(&[&prefix(&[&digest_record]), &prefix(&[&cert]), &prefix(&[])]);
        let signature = keypair.sign(&rng, &signed_data).unwrap();
        let mut signature_record = 0x0201_u32.to_le_bytes().to_vec();
        signature_record.extend(prefix(&[signature.as_ref()]));
        let signer = prefix(&[&signed_data, &prefix(&[&signature_record]), &spki]);
        let mut value = prefix(&[&prefix(&[&signer])]);
        assert_eq!(
            sha256_digests(&value, "v2"),
            Some(vec![(0, 0x0201, digest)])
        );
        assert_eq!(verify_sha256_signature(&value, "v2", 0, 0x0201), "verified");
        assert_eq!(
            verify_sha256_signature(&value, "v2", 0, 0x0301),
            "unsupported"
        );
        let at = value
            .windows(signature.as_ref().len())
            .position(|part| part == signature.as_ref())
            .unwrap();
        let mut mismatched_algorithms = value.clone();
        mismatched_algorithms[at - 8..at - 4].copy_from_slice(&0x0103_u32.to_le_bytes());
        assert_eq!(
            verify_sha256_signature(&mismatched_algorithms, "v2", 0, 0x0201),
            "malformed"
        );
        value[at] ^= 1;
        assert_eq!(verify_sha256_signature(&value, "v2", 0, 0x0201), "invalid");
    }

    #[test]
    fn chunked_sha256_declarations_are_bounded_and_not_signature_proofs() {
        let cert = certificate_der("Digest Claim");
        let digest = [0x42_u8; 32];
        let value = signing_value_with_sha256_digest(&cert, &digest);
        assert_eq!(
            sha256_digests(&value, "v2"),
            Some(vec![(0, 0x0103, digest)])
        );
        let mut corrupted = value;
        let record_at = corrupted
            .windows(4)
            .position(|part| part == 0x0103_u32.to_le_bytes())
            .expect("test record ID");
        corrupted[record_at + 4..record_at + 8].copy_from_slice(&31_u32.to_le_bytes());
        assert!(sha256_digests(&corrupted, "v2").is_none());
    }

    #[test]
    fn sdk_signer_ranges_preserve_v3_and_v31_identity_without_authentication() {
        let der = certificate_der("Rotated SDK Signer");
        for (scheme, min, max) in [("v3", 28, 32), ("v3.1", 33, u32::MAX)] {
            let value = signing_value_v3(&der, min, max);
            let records = sdk_signers(&value, scheme);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].scheme, scheme);
            assert_eq!((records[0].min_sdk, records[0].max_sdk), (min, max));
            assert_eq!(records[0].certificate_sha256, hex32(&sha256(&der)));
            assert_eq!(records[0].authentication, "not_verified");
            assert!(sdk_signers(&value, "v2").is_empty());

            let mut tampered = value.clone();
            let outer_sdk = 12 + le32(&tampered, 8).unwrap();
            tampered[outer_sdk..outer_sdk + 4].copy_from_slice(&(min + 1).to_le_bytes());
            assert!(sdk_signers(&tampered, scheme).is_empty());
            assert!(sdk_signers(&value[..value.len() - 1], scheme).is_empty());
        }
        assert!(sdk_signers(&signing_value(&der), "v3").is_empty());
    }

    #[test]
    fn v3_and_v31_signers_decode_with_matching_sdk_copies() {
        let der = certificate_der("Versioned Signer");
        let valid = signing_value_v3(&der, 24, 35);
        for scheme in ["v3", "v3.1"] {
            let found = signing_block(&valid, scheme);
            assert_eq!(found.len(), 1, "{scheme} must decode its raw SDK fields");
            assert_eq!(found[0].sha256, hex32(&sha256(&der)));
        }
        assert!(signing_block(&valid, "v2").is_empty());
        assert!(signing_block(&signing_value(&der), "v3").is_empty());
    }

    #[test]
    fn sdk_mismatch_and_invalid_ranges_withhold_v3_certificate_claims() {
        let der = certificate_der("Versioned Signer");
        let valid = signing_value_v3(&der, 24, 35);
        // 4-byte outer list prefix, 4-byte signer prefix, 4-byte signed-data prefix.
        let sdk_at = 12 + le32(&valid, 8).unwrap();
        let mut mismatched = valid.clone();
        mismatched[sdk_at..sdk_at + 4].copy_from_slice(&25_u32.to_le_bytes());
        assert!(signing_block(&mismatched, "v3").is_empty());

        let mut reversed = valid;
        reversed[sdk_at + 4..sdk_at + 8].copy_from_slice(&23_u32.to_le_bytes());
        assert!(signing_block(&reversed, "v3.1").is_empty());
    }

    #[test]
    fn mismatched_declared_public_key_withholds_signer_attribution() {
        let der = certificate_der("Signer Key");
        let mut v2 = signing_value(&der);
        let key_at = v2.len() - spki(&der).len();
        v2[key_at] ^= 1;
        assert!(signing_block(&v2, "v2").is_empty());

        let mut v3 = signing_value_v3(&der, 24, 35);
        let key_at = v3.len() - spki(&der).len();
        v3[key_at] ^= 1;
        assert!(signing_block(&v3, "v3").is_empty());
    }

    #[test]
    fn a_certificate_is_identified_by_the_digest_of_its_der_and_summarised() {
        let der = certificate_der("Field Apps");
        let found = signing_block(&signing_value(&der), "v2");
        assert_eq!(found.len(), 1);
        let cert = &found[0];
        assert_eq!(cert.sha256, hex32(&sha256(&der)));
        assert_eq!(cert.subject, "CN=Field Apps, O=Example Pty Ltd, C=AU");
        assert_eq!(cert.issuer, cert.subject);
        assert!(cert.self_signed);
        assert!(!cert.android_debug);
        assert_eq!(cert.serial, "01ab");
        assert_eq!(cert.not_before, "2020-01-01T00:00:00Z");
        assert_eq!(cert.not_after, "2050-01-01T00:00:00Z");
        assert_eq!(cert.scheme, "v2");
    }

    #[test]
    fn the_public_key_digest_is_distinct_per_key_and_separate_from_the_certificate_digest() {
        let field = certificate(&certificate_der("Field Apps"), "v2").expect("cert");
        let debug = certificate(&certificate_der("Android Debug"), "v2").expect("cert");
        // The public-key digest is a 64-hex SHA-256, and it is not the whole-certificate digest.
        assert_eq!(field.public_key_sha256.len(), 64);
        assert_ne!(field.public_key_sha256, field.sha256);
        // Different keys give different public-key digests; the same name gives the same digest.
        assert_ne!(field.public_key_sha256, debug.public_key_sha256);
        let field_again = certificate(&certificate_der("Field Apps"), "v3").expect("cert");
        assert_eq!(field.public_key_sha256, field_again.public_key_sha256);
    }

    #[test]
    fn a_v1_signature_file_yields_the_same_certificate() {
        let der = certificate_der("Android Debug");
        let found = pkcs7(&pkcs7_der(&der), "META-INF/CERT.RSA");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].sha256, hex32(&sha256(&der)));
        assert!(found[0].android_debug, "the SDK's debug key is named");
        assert_eq!(found[0].scheme, "META-INF/CERT.RSA");
    }

    #[test]
    fn malformed_structures_yield_nothing_rather_than_a_partial_certificate() {
        let der = certificate_der("Field Apps");
        for cut in [1, 10, der.len() / 2, der.len() - 1] {
            let rejected = certificate(&der[..cut], "v2").is_none();
            assert!(
                rejected,
                "a certificate truncated at {cut} bytes is rejected"
            );
        }
        assert!(
            pkcs7(b"\x30\x80\x00\x00", "x").is_empty(),
            "indefinite length"
        );
        let value = signing_value(&der);
        assert!(signing_block(&value[..value.len() - 2], "v2").is_empty());
        assert!(signing_block(&[0xff; 12], "v2").is_empty());
    }

    #[test]
    fn unlabelled_name_attributes_keep_their_dotted_oid() {
        assert_eq!(dotted(&[0x55, 0x04, 0x2a]), "2.5.4.42");
        assert_eq!(
            dotted(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]),
            "1.2.840.113549"
        );
    }
}
