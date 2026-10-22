//! X.509 certificates read from their DER, in-tree so no ASN.1 crate is needed.
//!
//! [`parse`] reads what an investigation uses, as Spiderfoot's `parseCert` reads it: the serial,
//! the subject and issuer names (each attribute, and the one-line form `C=US, O=Example, CN=…`),
//! the validity window, every subject alternative name (DNS names, email addresses, IP addresses
//! and URIs), the public key and signature algorithms, the CA flag and the certificate
//! transparency precertificate mark. [`pem`] writes the certificate as PEM text, Spiderfoot's
//! `SSL_CERTIFICATE_RAW`. Only the DER subset X.509 uses is read: one-byte tags and definite
//! lengths of up to four bytes.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::base64::base16_lower;

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
/// `[0] EXPLICIT`, the version.
const VERSION: u8 = 0xa0;
/// `[3] EXPLICIT`, the extensions.
const EXTENSIONS: u8 = 0xa3;

/// Why a DER body is not a certificate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum X509Error {
    #[error("certificate DER ends early")]
    Truncated,
    #[error("certificate DER: expected the {expected}, found tag {found:#04x}")]
    Unexpected { expected: &'static str, found: u8 },
    #[error("certificate DER: a tag or length form X.509 does not use")]
    Unsupported,
}

/// What a certificate says.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Certificate {
    /// The serial number in lowercase hex, without the sign octet DER adds.
    pub serial: String,
    /// The subject's attributes in order, each a short name (`CN`, `O`, `serialNumber`) or the
    /// dotted type of one without a name, and its value.
    pub subject: Vec<(String, String)>,
    /// The issuer's attributes, as [`Self::subject`].
    pub issuer: Vec<(String, String)>,
    /// Start of validity, `YYYY-MM-DDTHH:MM:SSZ`.
    pub not_before: Option<String>,
    /// End of validity, `YYYY-MM-DDTHH:MM:SSZ`.
    pub not_after: Option<String>,
    pub dns_names: Vec<String>,
    pub emails: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub uris: Vec<String>,
    /// `sha256WithRSAEncryption`, `ecdsa-with-SHA256`, or the dotted type of another.
    pub signature_algorithm: String,
    /// `RSA 2048`, `EC P-256`, `Ed25519`, or the dotted type of another.
    pub public_key: String,
    /// The basic-constraints CA flag.
    pub is_ca: bool,
    /// Carries the certificate transparency poison: a precertificate logged before issue.
    pub precertificate: bool,
}

impl Certificate {
    /// The subject in its one-line form. **Pure.**
    #[must_use]
    pub fn subject_line(&self) -> String {
        one_line(&self.subject)
    }

    /// The issuer in its one-line form. **Pure.**
    #[must_use]
    pub fn issuer_line(&self) -> String {
        one_line(&self.issuer)
    }

    /// The first value of the subject attribute `name`. **Pure.**
    #[must_use]
    pub fn subject_value(&self, name: &str) -> Option<&str> {
        self.subject
            .iter()
            .find(|(key, value)| key == name && !value.is_empty())
            .map(|(_, value)| value.as_str())
    }
}

/// Read one DER certificate. **Pure.**
///
/// # Errors
/// [`X509Error`] when `der` is not a certificate.
pub fn parse(der: &[u8]) -> Result<Certificate, X509Error> {
    let mut outer = Der(der);
    let mut certificate = Der(outer.expect(SEQUENCE, "certificate")?);
    let mut tbs = Der(certificate.expect(SEQUENCE, "certificate body")?);
    tbs.optional(VERSION)?;
    let serial = serial_hex(tbs.expect(INTEGER, "serial number")?);
    tbs.expect(SEQUENCE, "signature algorithm")?;
    let issuer = name(tbs.expect(SEQUENCE, "issuer")?)?;
    let mut validity = Der(tbs.expect(SEQUENCE, "validity")?);
    let not_before = time(validity.next()?);
    let not_after = time(validity.next()?);
    let subject = name(tbs.expect(SEQUENCE, "subject")?)?;
    let public_key = public_key(tbs.expect(SEQUENCE, "public key")?)?;
    let mut cert = Certificate {
        serial,
        subject,
        issuer,
        not_before,
        not_after,
        public_key,
        ..Certificate::default()
    };
    // The issuer and subject unique identifiers, [1] and [2], are skipped.
    while let Some(tag) = tbs.peek() {
        let (_, content) = tbs.next()?;
        if tag == EXTENSIONS {
            extensions(content, &mut cert)?;
        }
    }
    let mut algorithm = Der(certificate.expect(SEQUENCE, "signature algorithm")?);
    cert.signature_algorithm = signature_name(oid_text(algorithm.expect(OID, "algorithm")?));
    Ok(cert)
}

/// `der` as PEM: the base64 body in 64-character lines between the certificate markers. **Pure.**
#[must_use]
pub fn pem(der: &[u8]) -> String {
    let body = crate::base64::standard(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// A name's attributes in their one-line form: `KEY=value`, joined with `, `, a value quoted
/// when it holds a separator or a quote. **Pure.**
#[must_use]
pub fn one_line(attributes: &[(String, String)]) -> String {
    let mut out = String::new();
    for (key, value) in attributes {
        if !out.is_empty() {
            out.push_str(", ");
        }
        let special = value.contains([',', '+', '"', '\\', '=', ';', '<', '>'])
            || value.starts_with(' ')
            || value.ends_with(' ');
        if special {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            let _ = write!(out, "{key}=\"{escaped}\"");
        } else {
            let _ = write!(out, "{key}={value}");
        }
    }
    out
}

/// A DER reader over one element's contents.
#[derive(Clone, Copy)]
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The next element's tag and contents.
    fn next(&mut self) -> Result<(u8, &'a [u8]), X509Error> {
        let (&tag, rest) = self.0.split_first().ok_or(X509Error::Truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(X509Error::Unsupported);
        }
        let (&first, rest) = rest.split_first().ok_or(X509Error::Truncated)?;
        let (length, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let octets = usize::from(first & 0x7f);
            if octets == 0 || octets > 4 {
                return Err(X509Error::Unsupported);
            }
            if rest.len() < octets {
                return Err(X509Error::Truncated);
            }
            let (octets, rest) = rest.split_at(octets);
            let length = octets
                .iter()
                .fold(0_usize, |length, &octet| (length << 8) | usize::from(octet));
            (length, rest)
        };
        if rest.len() < length {
            return Err(X509Error::Truncated);
        }
        let (content, rest) = rest.split_at(length);
        self.0 = rest;
        Ok((tag, content))
    }

    /// The contents of the next element, which must have `tag`.
    fn expect(&mut self, tag: u8, expected: &'static str) -> Result<&'a [u8], X509Error> {
        match self.next()? {
            (found, content) if found == tag => Ok(content),
            (found, _) => Err(X509Error::Unexpected { expected, found }),
        }
    }

    /// The contents of the next element when it has `tag`; otherwise nothing is read.
    fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, X509Error> {
        if self.peek() == Some(tag) {
            self.next().map(|(_, content)| Some(content))
        } else {
            Ok(None)
        }
    }
}

/// An INTEGER's octets in lowercase hex, without a leading sign octet. **Pure.**
fn serial_hex(octets: &[u8]) -> String {
    let octets = match octets {
        [0, rest @ ..] if !rest.is_empty() => rest,
        all => all,
    };
    base16_lower(octets)
}

/// A name's attributes: each relative distinguished name's type and value, in order.
fn name(content: &[u8]) -> Result<Vec<(String, String)>, X509Error> {
    let mut names = Der(content);
    let mut out = Vec::new();
    while !names.is_empty() {
        let mut set = Der(names.expect(SET, "relative distinguished name")?);
        while !set.is_empty() {
            let mut pair = Der(set.expect(SEQUENCE, "attribute")?);
            let kind = oid_text(pair.expect(OID, "attribute type")?);
            let (tag, value) = pair.next()?;
            out.push((attribute_name(kind), string_value(tag, value)));
        }
    }
    Ok(out)
}

/// A directory string as text: UTF-8 and the ASCII forms as they are, Teletex as Latin-1, BMP as
/// UTF-16 and Universal as UTF-32; any other value as `#` and its hex. **Pure.**
fn string_value(tag: u8, value: &[u8]) -> String {
    match tag {
        0x0c | 0x12 | 0x13 | 0x16 | 0x1a => String::from_utf8_lossy(value).into_owned(),
        0x14 => value.iter().map(|&octet| char::from(octet)).collect(),
        0x1e => char::decode_utf16(
            value
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]])),
        )
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect(),
        0x1c => value
            .chunks_exact(4)
            .map(|quad| {
                char::from_u32(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
                    .unwrap_or(char::REPLACEMENT_CHARACTER)
            })
            .collect(),
        _ => format!("#{}", base16_lower(value)),
    }
}

/// An OBJECT IDENTIFIER in dotted form. **Pure.**
fn oid_text(octets: &[u8]) -> String {
    let mut arcs = Vec::new();
    let mut arc = 0_u64;
    for &octet in octets {
        arc = (arc << 7) | u64::from(octet & 0x7f);
        if octet & 0x80 == 0 {
            arcs.push(arc);
            arc = 0;
        }
    }
    let Some((&first, rest)) = arcs.split_first() else {
        return String::new();
    };
    let (top, second) = match first {
        0..40 => (0, first),
        40..80 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut out = format!("{top}.{second}");
    for arc in rest {
        let _ = write!(out, ".{arc}");
    }
    out
}

/// The short name of a name attribute type, as OpenSSL prints it. **Pure.**
fn attribute_name(kind: String) -> String {
    let short = match kind.as_str() {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.15" => "businessCategory",
        "2.5.4.17" => "postalCode",
        "2.5.4.42" => "GN",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        _ => return kind,
    };
    short.to_owned()
}

/// A signature algorithm's name, as OpenSSL prints it. **Pure.**
fn signature_name(kind: String) -> String {
    let name = match kind.as_str() {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "ED25519",
        "1.3.101.113" => "ED448",
        _ => return kind,
    };
    name.to_owned()
}

/// The key's algorithm and size: `RSA 2048`, `EC P-256`, `Ed25519`, or the dotted type.
fn public_key(content: &[u8]) -> Result<String, X509Error> {
    let mut info = Der(content);
    let mut algorithm = Der(info.expect(SEQUENCE, "key algorithm")?);
    let kind = oid_text(algorithm.expect(OID, "key algorithm")?);
    let parameter = algorithm.optional(OID)?.map(oid_text);
    let key = info.expect(BIT_STRING, "public key")?;
    Ok(match kind.as_str() {
        "1.2.840.113549.1.1.1" => {
            rsa_bits(key).map_or_else(|| "RSA".into(), |b| format!("RSA {b}"))
        }
        "1.2.840.10045.2.1" => match parameter.as_deref() {
            Some("1.2.840.10045.3.1.7") => "EC P-256".into(),
            Some("1.3.132.0.34") => "EC P-384".into(),
            Some("1.3.132.0.35") => "EC P-521".into(),
            Some(curve) => format!("EC {curve}"),
            None => "EC".into(),
        },
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        _ => kind,
    })
}

/// The bit length of an RSA key's modulus. **Pure.**
fn rsa_bits(bit_string: &[u8]) -> Option<usize> {
    let (_unused_bits, key) = bit_string.split_first()?;
    let mut sequence = Der(key);
    let mut key = Der(sequence.expect(SEQUENCE, "RSA key").ok()?);
    let modulus = key.expect(INTEGER, "modulus").ok()?;
    let start = modulus.iter().position(|&octet| octet != 0)?;
    let leading = usize::try_from(modulus[start].leading_zeros()).ok()?;
    Some((modulus.len() - start) * 8 - leading)
}

/// The extensions an investigation reads: the alternative names, the CA flag and the poison.
fn extensions(content: &[u8], cert: &mut Certificate) -> Result<(), X509Error> {
    let mut wrapper = Der(content);
    let mut list = Der(wrapper.expect(SEQUENCE, "extensions")?);
    while !list.is_empty() {
        let mut extension = Der(list.expect(SEQUENCE, "extension")?);
        let kind = oid_text(extension.expect(OID, "extension type")?);
        extension.optional(BOOLEAN)?;
        let value = extension.expect(OCTET_STRING, "extension value")?;
        match kind.as_str() {
            "2.5.29.17" => alternative_names(value, cert)?,
            "2.5.29.19" => cert.is_ca = is_ca(value),
            "1.3.6.1.4.1.11129.2.4.3" => cert.precertificate = true,
            _ => {}
        }
    }
    Ok(())
}

/// Each `rfc822Name`, `dNSName`, `uniformResourceIdentifier` and `iPAddress` of the alternative
/// names; the other forms are skipped.
fn alternative_names(value: &[u8], cert: &mut Certificate) -> Result<(), X509Error> {
    let mut wrapper = Der(value);
    let mut names = Der(wrapper.expect(SEQUENCE, "alternative names")?);
    while !names.is_empty() {
        let (tag, content) = names.next()?;
        let text = || String::from_utf8_lossy(content).into_owned();
        match tag {
            0x81 => cert.emails.push(text()),
            0x82 => cert.dns_names.push(text()),
            0x86 => cert.uris.push(text()),
            0x87 => {
                if let Ok(octets) = <[u8; 4]>::try_from(content) {
                    cert.ip_addresses.push(Ipv4Addr::from(octets).to_string());
                } else if let Ok(octets) = <[u8; 16]>::try_from(content) {
                    cert.ip_addresses.push(Ipv6Addr::from(octets).to_string());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The basic-constraints CA flag. **Pure.**
fn is_ca(value: &[u8]) -> bool {
    let mut wrapper = Der(value);
    let Ok(constraints) = wrapper.expect(SEQUENCE, "basic constraints") else {
        return false;
    };
    matches!(Der(constraints).optional(BOOLEAN), Ok(Some([flag])) if *flag != 0)
}

/// A `UTCTime` or `GeneralizedTime` in whole seconds as `YYYY-MM-DDTHH:MM:SSZ`. **Pure.**
fn time((tag, content): (u8, &[u8])) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?.strip_suffix('Z')?;
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (tag, text.len()) {
        (0x17, 12) => {
            let short: u32 = text[..2].parse().ok()?;
            (
                if short >= 50 {
                    1900 + short
                } else {
                    2000 + short
                },
                &text[2..],
            )
        }
        (0x18, 14) => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    let field = |from: usize| -> Option<u32> { rest.get(from..from + 2)?.parse().ok() };
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    // A leap second, 60, is accepted as rf::parse_iso8601_epoch accepts it, pending that decision.
    if !(1..=12).contains(&month)
        || !(1..=crate::timefmt::days_in_month(i32::try_from(year).ok()?, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some(format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    ))
}

#[cfg(test)]
pub(crate) mod tests;
