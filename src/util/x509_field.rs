//! The crate's one reader of certificate `Name` attributes, minimal and
//! dependency-free: `core::outage` compares the issuer's organisation with a
//! small allow-list of public CAs (REQ-RESILIENCE-003), and
//! `modules::cert_intel` records the issuer, subject and issuer organisation
//! as evidence (REQ-CERTINTEL-002).
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
//! The bound also keeps legitimate certificates honest. `cert_intel` once had
//! its own whole-buffer copy, which reported the subject's organisation as
//! the issuer's whenever the issuer named none, and the last CN anywhere in
//! the certificate — one inside an extension included — as the subject.

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

/// Which of a certificate's two `Name` fields to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameField {
    /// `TBSCertificate.issuer` — the name of the CA that signed the certificate.
    Issuer,
    /// `TBSCertificate.subject` — the name the certificate was issued to.
    Subject,
}

/// Read the string value of `oid`'s `AttributeTypeAndValue` from the
/// certificate's `field` `Name`, and from no other part of the certificate.
/// Returns `None` when `der` does not parse as a well-formed
/// `Certificate`/`TBSCertificate` shape, or when that field has no matching
/// attribute — both read as "no signal either way", never as "empty issuer
/// confirmed"; callers must not treat `None` as a finding.
#[must_use]
pub fn extract_field_from_der(der: &[u8], oid: &[u8], field: NameField) -> Option<String> {
    let (issuer, subject) = issuer_and_subject_ranges(der)?;
    let range = match field {
        NameField::Issuer => issuer,
        NameField::Subject => subject,
    };
    scan_oid_value(&der[range], oid)
}

/// DER builders for synthetic certificates, shared by this module's tests and
/// `modules::cert_intel`'s so both consumers of this reader are tested against
/// one construction. Not a general DER writer: every field a test does not
/// care about is an empty stand-in of the right tag, which is all
/// [`issuer_and_subject_ranges`] needs to walk past it.
#[cfg(test)]
pub(crate) mod test_der {
    fn len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            return vec![n as u8];
        }
        let significant: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        let mut out = vec![0x80 | significant.len() as u8];
        out.extend(significant);
        out
    }

    /// One TLV: `tag`, a DER length, then `content`.
    pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(len(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// A `Name`: one single-valued RDN per `(oid, value)`, in order, each
    /// value a UTF8String.
    pub(crate) fn name(attrs: &[(&[u8], &str)]) -> Vec<u8> {
        let mut rdns = Vec::new();
        for (oid, value) in attrs {
            let mut atv = tlv(0x06, oid);
            atv.extend(tlv(0x0C, value.as_bytes()));
            rdns.extend(tlv(0x31, &tlv(0x30, &atv)));
        }
        tlv(0x30, &rdns)
    }

    /// A v3 `Certificate` whose serialNumber content is `serial`, with the
    /// given `issuer` and `subject` `Name`s, and `after_subject` placed
    /// verbatim where `subjectPublicKeyInfo` and `[3] extensions` sit.
    pub(crate) fn certificate(
        serial: &[u8],
        issuer: &[u8],
        subject: &[u8],
        after_subject: &[u8],
    ) -> Vec<u8> {
        let empty = tlv(0x30, &[]);
        let mut tbs = tlv(0xA0, &tlv(0x02, &[0x02])); // [0] EXPLICIT version: v3
        tbs.extend(tlv(0x02, serial));
        tbs.extend_from_slice(&empty); // signature AlgorithmIdentifier
        tbs.extend_from_slice(issuer);
        tbs.extend_from_slice(&empty); // validity
        tbs.extend_from_slice(subject);
        tbs.extend_from_slice(after_subject);
        let mut cert = tlv(0x30, &tbs);
        cert.extend_from_slice(&empty); // signatureAlgorithm
        cert.extend(tlv(0x03, &[0x00])); // signatureValue: empty BIT STRING
        tlv(0x30, &cert)
    }
}

#[cfg(test)]
mod tests {
    use super::test_der::{certificate, name, tlv};
    use super::*;

    // A real OpenSSL-generated self-signed certificate — the same fixture
    // `modules::cert_intel`'s own DER tests drive against real ASN.1 rather
    // than a hand-built fragment. CN/O = "huntsman-test.example.com" /
    // "Huntsman SE Test" for both issuer and subject (self-signed).
    const SELF_SIGNED_DER: &[u8] = include_bytes!("../modules/cert_intel/testdata/selfsigned.der");

    #[test]
    fn empty_der_yields_none_never_a_panic() {
        assert!(extract_field_from_der(&[], OID_CN, NameField::Issuer).is_none());
        assert!(extract_field_from_der(&[0x55], OID_CN, NameField::Issuer).is_none());
    }

    #[test]
    fn real_cert_extracts_issuer_and_subject_common_name() {
        // Self-signed ⇒ issuer CN == subject CN, but each comes from its own
        // structurally-located field, not "first"/"last" in the whole buffer.
        assert_eq!(
            extract_field_from_der(SELF_SIGNED_DER, OID_CN, NameField::Issuer).as_deref(),
            Some("huntsman-test.example.com"),
            "issuer CN from real DER"
        );
        assert_eq!(
            extract_field_from_der(SELF_SIGNED_DER, OID_CN, NameField::Subject).as_deref(),
            Some("huntsman-test.example.com"),
            "subject CN from real DER"
        );
    }

    #[test]
    fn real_cert_extracts_issuer_organisation() {
        assert_eq!(
            extract_field_from_der(SELF_SIGNED_DER, OID_O, NameField::Issuer).as_deref(),
            Some("Huntsman SE Test"),
            "issuer O from real DER"
        );
    }

    #[test]
    fn each_field_is_read_from_its_own_name() {
        // The self-signed fixture has issuer == subject, so it cannot tell the
        // two fields apart; distinct values here can.
        let cert = certificate(
            &[0x01],
            &name(&[(OID_CN, "Issuing CA"), (OID_O, "Issuer Org")]),
            &name(&[(OID_CN, "host.example.com"), (OID_O, "Subject Org")]),
            &[],
        );
        let read = |oid, field| extract_field_from_der(&cert, oid, field);
        assert_eq!(
            read(OID_CN, NameField::Issuer).as_deref(),
            Some("Issuing CA")
        );
        assert_eq!(
            read(OID_O, NameField::Issuer).as_deref(),
            Some("Issuer Org")
        );
        assert_eq!(
            read(OID_CN, NameField::Subject).as_deref(),
            Some("host.example.com")
        );
        assert_eq!(
            read(OID_O, NameField::Subject).as_deref(),
            Some("Subject Org")
        );
    }

    #[test]
    fn a_forged_organisation_name_planted_in_the_serial_number_is_not_returned() {
        // The attack this function exists to resist: an interception proxy
        // mints its own leaf certificate (so it freely chooses every byte
        // that precedes `issuer` in the DER encoding, including the
        // serialNumber INTEGER) and plants the byte shape a raw scanner
        // matches — `organizationName`'s OID then a UTF8String — ahead of its
        // own real (unlisted) issuer. A global byte-scan would return the
        // planted value and wrongly clear the certificate; the structural
        // bound must return the real issuer's org instead.
        let mut forged_serial = vec![0x55, 0x04, 0x0A, 0x0C, 0x0C];
        forged_serial.extend_from_slice(b"DigiCert Inc");
        let cert = certificate(
            &forged_serial,
            &name(&[(OID_O, "Evil MITM Proxy")]),
            &tlv(0x30, &[]),
            &[],
        );

        assert_eq!(
            extract_field_from_der(&cert, OID_O, NameField::Issuer).as_deref(),
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
        assert!(extract_field_from_der(&der, OID_O, NameField::Issuer).is_none());
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
        assert!(extract_field_from_der(&fragment, OID_CN, NameField::Issuer).is_none());
        assert!(extract_field_from_der(&[0xFF; 32], OID_O, NameField::Issuer).is_none());
    }
}
