//! The crate's one reader of certificate `Name` attributes, minimal and
//! dependency-free: `core::outage` compares the issuer's organisation with a
//! small allow-list of public CAs (REQ-RESILIENCE-003), and
//! `modules::cert_intel` records the issuer, subject and issuer organisation
//! as evidence (REQ-CERTINTEL-002).
//!
//! Not a general X.509 parser — no OID table, no chain validation — but
//! structural all the way down: it walks `Certificate.tbsCertificate` (RFC
//! 5280 §4.1) to the `issuer` or `subject` `Name` asked about, then that
//! Name's RDNs, and returns the value of the attribute whose type is exactly
//! the requested OID. It never searches bytes. `der` is the peer's own
//! certificate, so all of it is attacker-controlled when the peer is a
//! self-signed interception proxy, and searching for `organizationName`'s
//! bytes was defeated twice: across fields, by a serial number carrying them
//! ahead of the real issuer, and within a field, by a CN value carrying them
//! ahead of the real O. Each time an allow-listed CA name was read back as
//! the issuer's organisation.
//!
//! Searching also misread legitimate certificates. `cert_intel`'s old
//! whole-buffer copy reported the subject's organisation as the issuer's
//! whenever the issuer named none, and the last CN anywhere in the
//! certificate — one inside an extension included — as the subject.

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
/// so a caller reading inside it can never see a byte from a sibling field.
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

/// The `(tag, content)` of each TLV laid end to end in `der`, or `None` if any
/// of them does not parse or would read past `der`.
fn tlvs(der: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < der.len() {
        let (hdr, len) = der_tlv(der, pos)?;
        out.push((der[pos], &der[pos + hdr..pos + hdr + len]));
        pos += hdr + len;
    }
    Some(out)
}

/// The value of the first attribute whose type is exactly `oid` in `name`,
/// one `Name`'s whole DER encoding, walked as RFC 5280 defines it:
/// `SEQUENCE OF` RDN, each RDN a `SET OF` `AttributeTypeAndValue`, each of
/// those a `SEQUENCE { type OID, value }`. Values in the three string forms a
/// CA uses for these attributes (UTF8String, PrintableString, IA5String) are
/// read; anything that is not this structure is `None`, never a best guess.
fn name_attribute(name: &[u8], oid: &[u8]) -> Option<String> {
    let outer = tlvs(name)?;
    let &[(0x30, rdns)] = outer.as_slice() else {
        return None;
    };
    for (tag, rdn) in tlvs(rdns)? {
        if tag != 0x31 {
            return None;
        }
        for (tag, atv) in tlvs(rdn)? {
            if tag != 0x30 {
                return None;
            }
            let parts = tlvs(atv)?;
            let &[(0x06, attr_type), (value_tag, value)] = parts.as_slice() else {
                return None;
            };
            if attr_type != oid || !matches!(value_tag, 0x0C | 0x13 | 0x16) {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(value)
                && !s.trim().is_empty()
            {
                return Some(s.trim().to_string());
            }
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
    name_attribute(&der[range], oid)
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
    fn another_attributes_value_holding_the_oids_bytes_is_not_read_as_it() {
        // A valid UTF8String CN whose content is `organizationName`'s OID then
        // a string header, placed ahead of the real O inside the SAME field:
        // the field bound cannot separate them, only the attribute structure
        // can.
        let mut planted = vec![0x55, 0x04, 0x0A, 0x0C, 0x0C];
        planted.extend_from_slice(b"DigiCert Inc");
        let planted = String::from_utf8(planted).expect("control bytes are valid UTF-8");
        let cert = certificate(
            &[0x01],
            &name(&[(OID_CN, &planted), (OID_O, "Evil MITM Proxy")]),
            &tlv(0x30, &[]),
            &[],
        );

        assert_eq!(
            extract_field_from_der(&cert, OID_O, NameField::Issuer).as_deref(),
            Some("Evil MITM Proxy")
        );
    }

    #[test]
    fn an_attribute_type_merely_ending_in_the_oids_bytes_is_not_it() {
        // OID 1.2.3.85.4.10 is encoded `2A 03 55 04 0A`: it ends with
        // `organizationName`'s bytes, and it is not `organizationName`.
        let cert = certificate(
            &[0x01],
            &name(&[
                (&[0x2A, 0x03, 0x55, 0x04, 0x0A], "Fake Org"),
                (OID_O, "Real Org"),
            ]),
            &tlv(0x30, &[]),
            &[],
        );

        assert_eq!(
            extract_field_from_der(&cert, OID_O, NameField::Issuer).as_deref(),
            Some("Real Org")
        );
    }

    #[test]
    fn a_name_that_is_not_rdns_of_attributes_yields_none_not_a_guess() {
        // An `organizationName` attribute sitting directly in the Name
        // SEQUENCE, without the RDN SET around it: not a Name.
        let mut atv = tlv(0x06, OID_O);
        atv.extend(tlv(0x0C, b"Loose Org"));
        let cert = certificate(&[0x01], &tlv(0x30, &tlv(0x30, &atv)), &tlv(0x30, &[]), &[]);

        assert_eq!(
            extract_field_from_der(&cert, OID_O, NameField::Issuer),
            None
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
