//! A minimal, dependency-free DER field reader for one thing this crate needs
//! from a leaf certificate: the issuer's organisation name, to compare
//! against a small allow-list of public CAs (`core::outage`,
//! REQ-RESILIENCE-003).
//!
//! Not a general X.509 parser — no OID table, no chain validation, no
//! ASN.1 SEQUENCE walk. It scans the raw DER for a target OID byte sequence
//! and reads the printable string (UTF8String / PrintableString /
//! IA5String) that follows it in an RDN's `AttributeTypeAndValue`. That is
//! sufficient and safe for this module's one job — noticing an ISSUER that
//! is not on the allow-list — because a forger who wants to pass the check
//! must put a *matching* organisation name in that same position, which is
//! the thing being checked either way.
//!
//! Same technique, independently reproduced, as
//! `modules::cert_intel::extract_field_from_der`; the two are not yet
//! consolidated onto one implementation (tracked, not silently duplicated —
//! see the module-level note in `core::outage`).

/// OID `2.5.4.3` — `commonName`, DER-encoded (no tag/length prefix).
pub const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
/// OID `2.5.4.10` — `organizationName`, DER-encoded.
pub const OID_O: &[u8] = &[0x55, 0x04, 0x0A];

/// Find the OID byte sequence in `der` and read the string value encoded
/// immediately after it (within a few bytes, past the OID's own DER
/// length octet). `first: true` returns the FIRST match — in a standard
/// X.509 `TBSCertificate`, the `issuer` RDN sequence is encoded before
/// `subject`, so the first `commonName`/`organizationName` match is the
/// issuer's; `first: false` returns the LAST match (the subject's, by the
/// same encoding-order reasoning). This is a position heuristic, not a
/// structural parse — it is exactly what a real issuer/subject RDN
/// encodes, but nothing here proves the input several is a valid
/// certificate at all, so callers must treat a `None` as "no signal
/// either way", never as "empty issuer confirmed".
#[must_use]
pub fn extract_field_from_der(der: &[u8], oid: &[u8], first: bool) -> Option<String> {
    let mut last_match = None;
    for i in 0..der.len().saturating_sub(oid.len()) {
        if &der[i..i + oid.len()] == oid {
            let after = i + oid.len();
            if after + 4 < der.len() {
                let mut pos = after;
                while pos < der.len() && pos < after + 6 {
                    let tag = der[pos];
                    // 0x0C UTF8String, 0x13 PrintableString, 0x16 IA5String —
                    // the three DirectoryString/IA5String forms a CA is free to
                    // pick for an RDN value.
                    if tag == 0x0C || tag == 0x13 || tag == 0x16 {
                        let len = der.get(pos + 1).copied().unwrap_or(0) as usize;
                        if pos + 2 + len <= der.len()
                            && let Ok(s) = std::str::from_utf8(&der[pos + 2..pos + 2 + len])
                        {
                            let s = s.trim().to_string();
                            if !s.is_empty() {
                                if first {
                                    return Some(s);
                                }
                                last_match = Some(s);
                            }
                        }
                        break;
                    }
                    pos += 1;
                }
            }
        }
    }
    last_match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_der_yields_none_never_a_panic() {
        assert!(extract_field_from_der(&[], OID_CN, true).is_none());
        assert!(extract_field_from_der(&[0x55], OID_CN, true).is_none());
    }

    /// A minimal but structurally real two-RDN fragment: issuer CN "Test CA"
    /// (UTF8String) followed by subject CN "leaf.example" (PrintableString),
    /// each preceded by the `commonName` OID exactly as a DER
    /// `AttributeTypeAndValue` encodes it — enough to exercise the
    /// first-match/last-match position heuristic without a full ASN.1
    /// certificate.
    fn two_cn_fragment() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x06, 0x03]); // OID tag + length
        v.extend_from_slice(OID_CN);
        v.extend_from_slice(&[0x0C, 7]); // UTF8String, len 7
        v.extend_from_slice(b"Test CA");
        v.extend_from_slice(&[0x06, 0x03]);
        v.extend_from_slice(OID_CN);
        v.extend_from_slice(&[0x13, 12]); // PrintableString, len 12
        v.extend_from_slice(b"leaf.example");
        v
    }

    #[test]
    fn first_match_is_the_issuer_and_last_match_is_the_subject() {
        let der = two_cn_fragment();
        assert_eq!(
            extract_field_from_der(&der, OID_CN, true).as_deref(),
            Some("Test CA"),
            "encoding order: issuer's RDN sequence precedes subject's"
        );
        assert_eq!(
            extract_field_from_der(&der, OID_CN, false).as_deref(),
            Some("leaf.example")
        );
    }

    #[test]
    fn an_oid_present_with_no_following_string_tag_yields_none() {
        // The OID byte sequence appears (e.g. inside an unrelated extension
        // blob) but is not followed by a recognised string tag within the
        // scan window — must not fabricate a match from noise.
        let mut der = vec![0xFF; 4];
        der.extend_from_slice(OID_O);
        der.extend_from_slice(&[0xFF; 10]); // no 0x0C/0x13/0x16 in range
        assert!(extract_field_from_der(&der, OID_O, true).is_none());
    }

    #[test]
    fn a_length_that_would_read_past_the_buffer_is_refused_not_truncated() {
        let mut der = Vec::new();
        der.extend_from_slice(OID_O);
        der.extend_from_slice(&[0x0C, 200]); // claims 200 bytes; buffer has 3
        der.extend_from_slice(b"abc");
        assert!(
            extract_field_from_der(&der, OID_O, true).is_none(),
            "an over-length claim must not read (or panic on) memory past the buffer"
        );
    }
}
