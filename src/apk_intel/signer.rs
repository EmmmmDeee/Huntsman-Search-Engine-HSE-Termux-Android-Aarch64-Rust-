//! The certificates an APK is signed with, found where Android's verifier finds them: the X.509
//! certificates of each signer in an APK Signature Scheme v2/v3 block, and those of a v1 (JAR)
//! signature's PKCS#7 `SignedData` in `META-INF/*.RSA`, `.DSA` or `.EC`.
//!
//! Each certificate is identified by the SHA-256 digest of its DER encoding, the value
//! `apksigner verify --print-certs` prints as the "certificate SHA-256 digest" and app stores and
//! malware repositories index signers by, so two APKs signed by the same key pivot to each other.
//! Its subject, issuer, serial number and validity are read from the DER for the analyst. No
//! signature is verified: a certificate here is the one the archive presents, which says nothing
//! about whether its signature over the APK holds, and a subject name is whatever the key holder
//! (or anyone who made the certificate) typed.

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
fn certificate(der: &[u8], scheme: &str) -> Option<Certificate> {
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
    let [serial, _algorithm, issuer, validity, subject, ..] = fields.get(skip..)? else {
        return None;
    };
    if serial.tag != INTEGER || validity.tag != SEQUENCE {
        return None;
    }
    let [not_before, not_after] = children(der, *validity)?[..] else {
        return None;
    };
    let subject_name = name(der, *subject)?;
    Some(Certificate {
        scheme: scheme.to_owned(),
        sha256: hex32(&sha256(der)),
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

fn le32(data: &[u8], at: usize) -> Option<usize> {
    let field = data.get(at..at.checked_add(4)?)?;
    usize::try_from(u32::from_le_bytes([field[0], field[1], field[2], field[3]])).ok()
}

/// The `u32`-length-prefixed items filling `data[start..end]`, as the signing block nests them.
fn prefixed(data: &[u8], start: usize, end: usize) -> Option<Vec<(usize, usize)>> {
    let mut at = start;
    let mut items = Vec::new();
    while at < end {
        let length = le32(data, at)?;
        let from = at.checked_add(4)?;
        let to = from.checked_add(length)?;
        if to > end {
            return None;
        }
        items.push((from, to));
        at = to;
    }
    Some(items)
}

/// The certificates of each signer in a v2/v3 signing-block value: signers, then each signer's
/// signed data, whose first two items are its digests and its certificates.
#[must_use]
pub fn signing_block(value: &[u8], scheme: &str) -> Vec<Certificate> {
    let found = || -> Option<Vec<Certificate>> {
        let [(start, end)] = prefixed(value, 0, value.len())?[..] else {
            return None;
        };
        let mut certificates = Vec::new();
        for (signer_start, signer_end) in prefixed(value, start, end)? {
            let (data_start, data_end) = *prefixed(value, signer_start, signer_end)?.first()?;
            let fields = prefixed(value, data_start, data_end)?;
            let (certs_start, certs_end) = *fields.get(1)?;
            for (from, to) in prefixed(value, certs_start, certs_end)? {
                if certificates.len() < MAX_CERTIFICATES {
                    certificates.extend(certificate(&value[from..to], scheme));
                }
            }
        }
        Some(certificates)
    };
    found().unwrap_or_default()
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
        tbs.extend(element(SEQUENCE, &[]));
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

    /// A v2/v3 signing-block value holding one signer with `cert`.
    pub(crate) fn signing_value(cert: &[u8]) -> Vec<u8> {
        let digests = prefix(&[]);
        let certs = prefix(&[cert]);
        let signed_data = prefix(&[&digests, &certs, &prefix(&[])]);
        let signer = prefix(&[&signed_data, &prefix(&[]), b"public-key"]);
        prefix(&[&prefix(&[&signer])])
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
