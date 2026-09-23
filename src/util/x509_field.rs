//! A minimal, dependency-free DER field reader for one thing this crate needs
//! from a leaf certificate: the issuer's organisation name, to compare
//! against a small allow-list of public CAs (`core::outage`,
//! REQ-RESILIENCE-003).
//!
//! Not a general X.509 parser — no OID table, no chain validation. It DOES
//! walk the `Certificate.tbsCertificate` `SEQUENCE` structurally (RFC 5280
//! §4.1) far enough to find the byte range of the `issuer`/`subject` `Name`
//! field being asked about, then scans only inside that bounded range for
//! the target OID's `AttributeTypeAndValue`. That bound is load-bearing, not
//! cosmetic: `der` is the peer's own certificate, so every byte before the
//! issuer field — the version, the serial number, the signature algorithm —
//! is attacker-controlled when the peer is a self-signed interception proxy.
//! An earlier version of this scanner searched the *entire* buffer for the
//! OID byte sequence and returned the first hit; a MITM certificate could
//! plant a fake `organizationName` inside its own chosen serial-number bytes
//! (which precede the real issuer in the DER encoding) and have it read back
//! as an allow-listed CA, defeating the one check this module exists to
//! make honest. Structurally locating the issuer/subject field first closes
//! that: the only way to influence what this returns is to put the value in
//! the field actually being asked about, which is the thing being checked
//! either way.
//!
//! Same technique, independently reproduced (and, prior to this fix, the
//! identical unbounded-scan weakness), as
//! `modules::cert_intel::extract_field_from_der`; the two are not yet
//! consolidated onto one implementation (tracked, not silently duplicated —
//! see the module-level note in `core::outage`). That copy's output feeds
//! descriptive OSINT attributes rather than a security decision, so it does
//! not carry this module's spoofing severity, but the same structural bound
//! would benefit it too.

use std::ops::Range;

/// OID `2.5.4.3` — `commonName`, DER-encoded (no tag/length prefix).
pub const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
/// OID `2.5.4.10` — `organizationName`, DER-encoded.
pub const OID_O: &[u8] = &[0x55, 0x04, 0x0A];

/// Read a DER TLV header at `der[pos]` (`der[pos]` is the tag byte).
/// Returns `(header_len, content_len)` — the content bytes are
/// `der[pos + header_len .. pos + header_len + content_len]`, and that
/// range is verified in-bounds before returning. Definite-length form only
/// (short form `< 0x80`, or long form with 1-4 length-of-length bytes): a
/// DER certificate never uses BER's indefinite length. Returns `None` on
/// truncation, an indefinite/reserved form, or a length claim that would
/// read past the buffer — never panics, never reads out of bounds.
fn der_tlv(der: &[u8], pos: usize) -> Option<(usize, usize)> {
    let l0 = *der.get(pos + 1)?;
    let (header_len, content_len) = if l0 < 0x80 {
        (2usize, l0 as usize)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | usize::from(*der.get(pos + 2 + k)?);
        }
        (2 + n, len)
    };
    pos.checked_add(header_len)?
        .checked_add(content_len)
        .filter(|&end| end <= der.len())?;
    Some((header_len, content_len))
}

/// Locate the byte ranges of the `issuer` and `subject` `Name` fields inside
/// a leaf certificate's DER encoding, by walking `Certificate.tbsCertificate`
/// structurally:
/// `SEQUENCE { [0] version OPTIONAL, serialNumber INTEGER, signature
/// AlgorithmIdentifier, issuer Name, validity Validity, subject Name, ... }`
/// (RFC 5280 §4.1). Each range covers that field's own tag+length+content,
/// so a caller scanning inside it can never see a byte from a sibling field.
///
/// Returns `None` if `der` does not parse as this shape at all — never a
/// partial or best-guess range, since a wrong range would defeat the one
/// thing this function exists to make safe.
fn issuer_and_subject_ranges(der: &[u8]) -> Option<(Range<usize>, Range<usize>)> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    if der.first() != Some(&0x30) {
        return None;
    }
    let (hdr, _) = der_tlv(der, 0)?;
    let mut pos = hdr; // start of tbsCertificate

    // TBSCertificate ::= SEQUENCE { ... }
    if der.get(pos) != Some(&0x30) {
        return None;
    }
    let (tbs_hdr, _) = der_tlv(der, pos)?;
    pos += tbs_hdr; // start of TBSCertificate's own fields, in fixed order

    // [0] EXPLICIT Version DEFAULT v1 — OPTIONAL, context-specific constructed 0.
    if der.get(pos) == Some(&0xA0) {
        let (hdr, len) = der_tlv(der, pos)?;
        pos += hdr + len;
    }
    // serialNumber ::= INTEGER — fully attacker-chosen bytes on a self-signed
    // or freshly-minted interception certificate; never scanned for a value,
    // only skipped over.
    if der.get(pos) != Some(&0x02) {
        return None;
    }
    let (hdr, len) = der_tlv(der, pos)?;
    pos += hdr + len;

    // signature AlgorithmIdentifier ::= SEQUENCE
    if der.get(pos) != Some(&0x30) {
        return None;
    }
    let (hdr, len) = der_tlv(der, pos)?;
    pos += hdr + len;

    // issuer Name ::= SEQUENCE (RDNSequence)
    if der.get(pos) != Some(&0x30) {
        return None;
    }
    let (hdr, len) = der_tlv(der, pos)?;
    let issuer = pos..pos + hdr + len;
    pos += hdr + len;

    // validity Validity ::= SEQUENCE
    if der.get(pos) != Some(&0x30) {
        return None;
    }
    let (hdr, len) = der_tlv(der, pos)?;
    pos += hdr + len;

    // subject Name ::= SEQUENCE (RDNSequence)
    if der.get(pos) != Some(&0x30) {
        return None;
    }
    let (hdr, len) = der_tlv(der, pos)?;
    let subject = pos..pos + hdr + len;

    Some((issuer, subject))
}

/// Scan a byte range already known to be exactly one certificate `Name`
/// field's DER encoding for `oid`'s `AttributeTypeAndValue`, returning the
/// first matching string value in that range. A raw scan is safe here
/// (rather than a full RDN/`AttributeTypeAndValue` walk) only because the
/// caller has already bounded the search to the one field being asked
/// about — see [`issuer_and_subject_ranges`].
fn scan_oid_value(field: &[u8], oid: &[u8]) -> Option<String> {
    for i in 0..field.len().saturating_sub(oid.len()) {
        if &field[i..i + oid.len()] != oid {
            continue;
        }
        let after = i + oid.len();
        if after + 4 >= field.len() {
            continue;
        }
        let mut pos = after;
        while pos < field.len() && pos < after + 6 {
            let tag = field[pos];
            // 0x0C UTF8String, 0x13 PrintableString, 0x16 IA5String — the
            // three DirectoryString/IA5String forms a CA is free to pick for
            // an RDN value.
            if tag == 0x0C || tag == 0x13 || tag == 0x16 {
                let len = field.get(pos + 1).copied().unwrap_or(0) as usize;
                if pos + 2 + len <= field.len()
                    && let Ok(s) = std::str::from_utf8(&field[pos + 2..pos + 2 + len])
                {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
                break;
            }
            pos += 1;
        }
    }
    None
}

/// Read the string value of `oid`'s `AttributeTypeAndValue` from a
/// certificate's `issuer` (`first: true`) or `subject` (`first: false`)
/// `Name` field. Returns `None` when `der` does not parse as a well-formed
/// `Certificate`/`TBSCertificate` shape, or when the requested field has no
/// matching attribute — both read as "no signal either way", never as
/// "empty issuer confirmed"; callers must not treat `None` as a finding.
#[must_use]
pub fn extract_field_from_der(der: &[u8], oid: &[u8], first: bool) -> Option<String> {
    let (issuer, subject) = issuer_and_subject_ranges(der)?;
    let range = if first { issuer } else { subject };
    scan_oid_value(&der[range], oid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real OpenSSL-generated self-signed certificate — the same fixture
    // `modules::cert_intel`'s own DER tests drive against real ASN.1 rather
    // than a hand-built fragment. CN/O = "huntsman-test.example.com" /
    // "Huntsman SE Test" for both issuer and subject (self-signed).
    const SELF_SIGNED_DER: &[u8] = include_bytes!("../modules/cert_intel/testdata/selfsigned.der");

    #[test]
    fn empty_der_yields_none_never_a_panic() {
        assert!(extract_field_from_der(&[], OID_CN, true).is_none());
        assert!(extract_field_from_der(&[0x55], OID_CN, true).is_none());
    }

    #[test]
    fn real_cert_extracts_issuer_and_subject_common_name() {
        // Self-signed ⇒ issuer CN == subject CN, but each comes from its own
        // structurally-located field, not "first"/"last" in the whole buffer.
        assert_eq!(
            extract_field_from_der(SELF_SIGNED_DER, OID_CN, true).as_deref(),
            Some("huntsman-test.example.com"),
            "issuer CN from real DER"
        );
        assert_eq!(
            extract_field_from_der(SELF_SIGNED_DER, OID_CN, false).as_deref(),
            Some("huntsman-test.example.com"),
            "subject CN from real DER"
        );
    }

    #[test]
    fn real_cert_extracts_issuer_organisation() {
        assert_eq!(
            extract_field_from_der(SELF_SIGNED_DER, OID_O, true).as_deref(),
            Some("Huntsman SE Test"),
            "issuer O from real DER"
        );
    }

    // Minimal DER TLV builders for a synthetic certificate — long enough to
    // parse as `Certificate { TBSCertificate { serialNumber, signature,
    // issuer, validity, subject }, signatureAlgorithm, signatureValue }`,
    // with every field but the ones a test cares about left as an empty
    // stand-in of the right tag. Not a general DER writer — just enough
    // control to place bytes at an exact, chosen position without the
    // fragility of resizing a real fixture's nested length prefixes.
    fn der_len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else {
            let significant: Vec<u8> = n
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            let mut out = vec![0x80 | significant.len() as u8];
            out.extend(significant);
            out
        }
    }

    fn der_tlv_of(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn a_forged_organisation_name_planted_in_the_serial_number_is_not_returned() {
        // The attack this function exists to resist: an interception proxy
        // mints its own leaf certificate (so it freely chooses every byte
        // that precedes `issuer` in the DER encoding, including the
        // serialNumber INTEGER) and plants a fake `organizationName`
        // AttributeTypeAndValue ahead of its own real (unlisted) issuer. A
        // global byte-scan would return the planted value and wrongly clear
        // the certificate; the structural bound must reject it and return
        // the real issuer's org instead — a synthetic certificate (rather
        // than splicing the real fixture) keeps every byte position exact
        // without hand-recomputing three nested DER lengths.
        let mut forged_serial_content = vec![0x55, 0x04, 0x0A, 0x0C, 0x0C];
        forged_serial_content.extend_from_slice(b"DigiCert Inc");
        let serial = der_tlv_of(0x02, &forged_serial_content); // INTEGER

        let mut real_issuer_atv = vec![0x55, 0x04, 0x0A, 0x0C, 0x0F];
        real_issuer_atv.extend_from_slice(b"Evil MITM Proxy");
        let issuer = der_tlv_of(0x30, &der_tlv_of(0x30, &real_issuer_atv)); // Name

        let empty_seq = der_tlv_of(0x30, &[]); // stand-in AlgorithmIdentifier/Validity/subject

        let mut tbs_content = Vec::new();
        tbs_content.extend(serial);
        tbs_content.extend(empty_seq.clone()); // signature AlgorithmIdentifier
        tbs_content.extend(issuer);
        tbs_content.extend(empty_seq.clone()); // validity
        tbs_content.extend(empty_seq.clone()); // subject (empty: not under test here)
        let tbs = der_tlv_of(0x30, &tbs_content);

        let mut cert_content = Vec::new();
        cert_content.extend(tbs);
        cert_content.extend(empty_seq); // signatureAlgorithm
        cert_content.extend(der_tlv_of(0x03, &[0x00])); // signatureValue BIT STRING
        let cert = der_tlv_of(0x30, &cert_content);

        assert_eq!(
            extract_field_from_der(&cert, OID_O, true).as_deref(),
            Some("Evil MITM Proxy"),
            "the planted serial-number payload must not be read as the issuer org"
        );
    }

    #[test]
    fn a_length_that_would_read_past_the_buffer_is_refused_not_truncated() {
        // A short, non-certificate-shaped buffer whose declared length would
        // overrun it — must be refused by der_tlv's own bound check, not
        // panic and not silently truncate.
        let mut der = vec![0x30, 0x81, 200]; // SEQUENCE claiming 200 bytes of content
        der.extend_from_slice(b"abc");
        assert!(extract_field_from_der(&der, OID_O, true).is_none());
    }

    #[test]
    fn a_buffer_that_is_not_a_certificate_shape_yields_none_not_a_guess() {
        // Neither a hand-built OID fragment nor random bytes describe a real
        // Certificate/TBSCertificate SEQUENCE — this must fail closed rather
        // than fall back to an unbounded scan.
        let mut fragment = Vec::new();
        fragment.extend_from_slice(&[0x06, 0x03]);
        fragment.extend_from_slice(OID_CN);
        fragment.extend_from_slice(&[0x0C, 7]);
        fragment.extend_from_slice(b"Test CA");
        assert!(extract_field_from_der(&fragment, OID_CN, true).is_none());
        assert!(extract_field_from_der(&[0xFF; 32], OID_O, true).is_none());
    }
}
