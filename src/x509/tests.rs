//! The parser read against two real certificates from the logs: an extended-validation RSA
//! certificate whose subject names its organisation, and a domain-validated EC wildcard.

use super::*;

/// `www.digicert.com`, extended validation, RSA 2048, as Cert Spotter returned it.
pub(crate) const EV_RSA: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIHgzCCBmugAwIBAgIQCH//w3kZ1shb8s3do+ArfTANBgkqhkiG9w0BAQsFADBE\n\
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMR4wHAYDVQQDExVE\n\
aWdpQ2VydCBFViBSU0EgQ0EgRzIwHhcNMjYwNzI4MDAwMDAwWhcNMjcwMjExMjM1\n\
OTU5WjCBwTETMBEGCysGAQQBgjc8AgEDEwJVUzEVMBMGCysGAQQBgjc8AgECEwRV\n\
dGFoMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjEVMBMGA1UEBRMMNTI5\n\
OTUzNy0wMTQyMQswCQYDVQQGEwJVUzENMAsGA1UECBMEVXRhaDENMAsGA1UEBxME\n\
TGVoaTEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xGTAXBgNVBAMTEHd3dy5kaWdp\n\
Y2VydC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCY3zNZwTun\n\
OIxdni/jz8vqUDo2/nenmFJNwsqUeI/m81ddOHfy09drpJBC93EeWGqSDZWRXzJx\n\
sZMc9dvgCtbSqNpvGoA5V03lr5dYUtGsQhjhmS9esL0dO/KMXoytp5n1pVHRYUpl\n\
qRcjnrsQhrU2nqozh4wAbyjsKlzZUU5cNAgkOo9hhaixj2yecn6hi4gxgQfolXUv\n\
KAkOkbT5LBx/xTQVXlm8IRxOo6x/skx25MSc2cHOVvOmBx9D8JrF3Qk/YHcn2A9V\n\
BZuC8vYgQAoFBGG51xHmJomVeNMgxW8JGdib4ZrYzeMyaRHOPwz+NMDKJUmdRdBn\n\
ftl4yQ40lYg5AgMBAAGjggPxMIID7TAfBgNVHSMEGDAWgBRqTlC/mGidW3sgddRZ\n\
AXlIZpIyBjAdBgNVHQ4EFgQU1DiwneJjUpHHggPwHwDO7qD6t5MwgbMGA1UdEQSB\n\
qzCBqIIQd3d3LmRpZ2ljZXJ0LmNvbYIMZGlnaWNlcnQuY29tghJhZG1pbi5kaWdp\n\
Y2VydC5jb22CEGFwaS5kaWdpY2VydC5jb22CFGNvbnRlbnQuZGlnaWNlcnQuY29t\n\
ghJsb2dpbi5kaWdpY2VydC5jb22CEm9yZGVyLmRpZ2ljZXJ0LmNvbYIPd3MuZGln\n\
aWNlcnQuY29tghFjYXJ0LmRpZ2ljZXJ0LmNvbTBKBgNVHSAEQzBBMAsGCWCGSAGG\n\
/WwCATAyBgVngQwBATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0\n\
LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\n\
BgEFBQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5odHRwOi8vY3JsMy5kaWdpY2VydC5j\n\
b20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMDSgMqAwhi5odHRwOi8vY3JsNC5kaWdp\n\
Y2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMHMGCCsGAQUFBwEBBGcwZTAk\n\
BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMD0GCCsGAQUFBzAC\n\
hjFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIu\n\
Y3J0MAwGA1UdEwEB/wQCMAAwggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB2AExj\n\
3JjlnB2riPYeij3ero+rRKM3e1+blMP7oZz8wb4mAAABn6oX+0YAAAQDAEcwRQIg\n\
Tf61ihrsjzJ8ho7sMZJVzDQo22bKocApc+9WmtrFzzQCIQC5VQc57AbXieUUND5Z\n\
esO4CWV7aebUjhOUAyq0UH9OkAB2AETCvQzpFA5kpclKAZMKWqG7NZcOAO4RFolo\n\
KhxE17VmAAABn6oX+3kAAAQDAEcwRQIgKMfJ8TrPPntxYUDmM3Q+8hQWSACgWMYJ\n\
RPIa7TN7o94CIQC/YuNA8IE04ZR3Yc8BkY/9byPO121bsNUiR482fIdhQgB2AByf\n\
aCzp+vBFaVD4G5aKh93bMhDYTObIsuOCUkrEz1mfAAABn6oX/CYAAAQDAEcwRQIg\n\
FGFuQQurCf39XvNgIbJ6i5yqEWzL9AesZUUoKJvDwS4CIQDv2SqBMSre2YP3zo9e\n\
8wXWLDmTPZuvffXQExB0uC7nPzANBgkqhkiG9w0BAQsFAAOCAQEAQvie6Y3zamkj\n\
xFKYbs0brkPm9aUzlF3vdnUxuIXhJb8u4E8vkr5UhTWu+rNmPAoP2LtHuXAg5PmY\n\
Z2B2S/dJwpXXiPKFZgbpUdq+jv0Pc2tDopWvxBEAWTsh1rPEO3ZEy+QiOiBfJOkw\n\
looOf07zelliOvvFZNP75M1qaIULUO2NngKLdw91ZCpmjNLgwhFsAJoMXnrmlfml\n\
n/YGXvF/XtVyPQnm9KzIcZh9626lbPmrGaO2eVhu3SqhnK8o4dvTpm5blzcntp3s\n\
lUf/+1c+nVHg4wTPo7YgS7vWHjhLXMbcvTWRKLqjVSKkDe1obG4PWL7M+1XvnWPs\n\
x6H6Tk9khg==\n\
-----END CERTIFICATE-----\n\
";

/// `*.acme.sslmate.com`, domain validated, EC P-256.
pub(crate) const DV_EC: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIEdjCCBBygAwIBAgIQearndXUfPNolKJBO5vqQrDAKBggqhkjOPQQDAjBgMQsw\n\
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5T\n\
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgRTM2MB4X\n\
DTI2MDIwNzAwMDAwMFoXDTI3MDMwOTIzNTk1OVowHTEbMBkGA1UEAwwSKi5hY21l\n\
LnNzbG1hdGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBd9V9mw8twPn\n\
gZnsGz48nCtlXtl0kqSv6FfyvzsCpUb9PobQJjXY2u0/eeWmVfWLXGXG9rXj/JAR\n\
/PTyEluPdaOCAvkwggL1MB8GA1UdIwQYMBaAFBeZqATBb+QtcKgKED0D0+kauCZj\n\
MB0GA1UdDgQWBBR9F+49vqJaaizx0QRlhJCG32/RijAOBgNVHQ8BAf8EBAMCB4Aw\n\
DAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDATBJBgNVHSAEQjBAMDQG\n\
CysGAQQBsjEBAgIHMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20v\n\
Q1BTMAgGBmeBDAECATCBhAYIKwYBBQUHAQEEeDB2ME8GCCsGAQUFBzAChkNodHRw\n\
Oi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNTZXJ2ZXJBdXRoZW50aWNh\n\
dGlvbkNBRFZFMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdv\n\
LmNvbTCCAY0GCisGAQQB1nkCBAIEggF9BIIBeQF3AHUAHJ9oLOn68EVpUPgbloqH\n\
3dsyENhM5siy44JSSsTPWZ8AAAGcNXaHpgAABAMARjBEAiBuMRvdlzFrSkdMoc4o\n\
05OEFlUGnbnK+Ilc1PQQckJnuAIgfvMPpoCThhpIOVQDkOyY+ZwX1yeWDb6dvEry\n\
7TqlTDEAfwCOykcLrN5q86IGsKR6hLdG/h/Gv5U+JeabTuQCSPPG6AAAAZw1dorR\n\
AAgAAAUAAmxeswQDAEgwRgIhAJ0ksiy9qk/R7obofoJoKGqvxzWAji0uKyjs+pUo\n\
inFCAiEAhflr5MKyA63hbQ2m+YZLF9OqwVyo0JMqgoc0i7eaTegAfQBZbmwzhpSy\n\
WXKiVsig6N2QSnboCD3ahzsBCDgoFDzuWQAAAZw1doo6AAgAAAUAACMExwQDAEYw\n\
RAIgRcXBvbFmneYlVlXniTGKroxP3Jg/XM4YHqZWQ/GtP+UCIHCtxpT6xFTv5DEp\n\
5vniIRw1VD1Vr/VIWhEkSLA/nyxwMB0GA1UdEQQWMBSCEiouYWNtZS5zc2xtYXRl\n\
LmNvbTAKBggqhkjOPQQDAgNIADBFAiAjVMz7HqSm4PUGqXbAFjTSCzIkkIoCf+Ww\n\
RjLMZ3TboAIhAJW2+vwR8HRFgHWOfiprNb7q0yIp5E4XoXybPc6T60PN\n\
-----END CERTIFICATE-----\n\
";

fn der(pem_text: &str) -> Vec<u8> {
    let body: String = pem_text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    crate::base64::decode_standard(&body).expect("fixture base64")
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn an_extended_validation_certificate_names_its_holder_as_openssl_reads_it() {
    let cert = parse(&der(EV_RSA)).expect("certificate");
    assert_eq!(cert.serial, "087fffc37919d6c85bf2cddda3e02b7d");
    assert_eq!(
        cert.subject,
        pairs(&[
            ("jurisdictionC", "US"),
            ("jurisdictionST", "Utah"),
            ("businessCategory", "Private Organization"),
            ("serialNumber", "5299537-0142"),
            ("C", "US"),
            ("ST", "Utah"),
            ("L", "Lehi"),
            ("O", "DigiCert, Inc."),
            ("CN", "www.digicert.com"),
        ])
    );
    assert_eq!(
        cert.subject_line(),
        "jurisdictionC=US, jurisdictionST=Utah, businessCategory=Private Organization, \
         serialNumber=5299537-0142, C=US, ST=Utah, L=Lehi, O=\"DigiCert, Inc.\", CN=www.digicert.com"
    );
    assert_eq!(cert.subject_value("O"), Some("DigiCert, Inc."));
    assert_eq!(
        cert.issuer_line(),
        "C=US, O=DigiCert Inc, CN=DigiCert EV RSA CA G2"
    );
    assert_eq!(cert.not_before.as_deref(), Some("2026-07-28T00:00:00Z"));
    assert_eq!(cert.not_after.as_deref(), Some("2027-02-11T23:59:59Z"));
    assert_eq!(
        cert.dns_names,
        [
            "www.digicert.com",
            "digicert.com",
            "admin.digicert.com",
            "api.digicert.com",
            "content.digicert.com",
            "login.digicert.com",
            "order.digicert.com",
            "ws.digicert.com",
            "cart.digicert.com",
        ]
    );
    assert!(cert.emails.is_empty() && cert.ip_addresses.is_empty() && cert.uris.is_empty());
    assert_eq!(cert.signature_algorithm, "sha256WithRSAEncryption");
    assert_eq!(cert.public_key, "RSA 2048");
    assert!(!cert.is_ca);
}

#[test]
fn an_ec_wildcard_certificate_reads_its_curve_and_signature() {
    let cert = parse(&der(DV_EC)).expect("certificate");
    assert_eq!(cert.serial, "79aae775751f3cda2528904ee6fa90ac");
    assert_eq!(cert.subject_line(), "CN=*.acme.sslmate.com");
    assert_eq!(cert.subject_value("O"), None);
    assert_eq!(
        cert.issuer_line(),
        "C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36"
    );
    assert_eq!(cert.not_before.as_deref(), Some("2026-02-07T00:00:00Z"));
    assert_eq!(cert.not_after.as_deref(), Some("2027-03-09T23:59:59Z"));
    assert_eq!(cert.dns_names, ["*.acme.sslmate.com"]);
    assert_eq!(cert.signature_algorithm, "ecdsa-with-SHA256");
    assert_eq!(cert.public_key, "EC P-256");
    assert!(!cert.is_ca);
}

#[test]
fn an_attribute_is_its_first_value_that_is_not_empty() {
    let name = pairs(&[
        ("O", ""),
        ("CN", "x"),
        ("O", "Example Ltd"),
        ("O", "Second"),
    ]);
    assert_eq!(attribute(&name, "O"), Some("Example Ltd"));
    assert_eq!(attribute(&name, "CN"), Some("x"));
    assert_eq!(attribute(&name, "L"), None);
    assert_eq!(attribute(&pairs(&[("O", "")]), "O"), None);
}

#[test]
fn pem_writes_the_der_back_as_openssl_does() {
    for fixture in [EV_RSA, DV_EC] {
        assert_eq!(pem(&der(fixture)), fixture);
    }
}

#[test]
fn a_cut_or_foreign_body_is_an_error_not_a_panic() {
    let whole = der(EV_RSA);
    for cut in [0, 1, 2, 10, 100, whole.len() / 2, whole.len() - 1] {
        assert!(parse(&whole[..cut]).is_err(), "cut at {cut}");
    }
    assert_eq!(
        parse(b"\x04\x00"),
        Err(X509Error::Unexpected {
            expected: "certificate",
            found: 0x04
        })
    );
    assert_eq!(
        parse(b"\x30\x85\x01\x02\x03\x04\x05"),
        Err(X509Error::Unsupported)
    );
    assert_eq!(parse(b"\x1f\x00"), Err(X509Error::Unsupported));
}

#[test]
fn names_quote_separators_and_decode_every_string_form() {
    assert_eq!(
        one_line(&pairs(&[
            ("O", "A \"B\" + C"),
            ("CN", " x"),
            ("L", "plain")
        ])),
        r#"O="A \"B\" + C", CN=" x", L=plain"#
    );
    assert_eq!(string_value(0x14, &[0x4d, 0xfc, 0x6c]), "Mül");
    assert_eq!(string_value(0x1e, &[0x00, 0x4d, 0x00, 0xfc]), "Mü");
    assert_eq!(string_value(0x1c, &[0, 0, 0, 0x4d, 0, 0, 0, 0xfc]), "Mü");
    assert_eq!(string_value(0x04, &[0xde, 0xad]), "#dead");
}

#[test]
fn identifiers_times_and_addresses_decode_by_their_rules() {
    assert_eq!(
        oid_text(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
        "1.2.840.113549.1.1.11"
    );
    assert_eq!(oid_text(&[0x55, 0x04, 0x03]), "2.5.4.3");
    assert_eq!(oid_text(&[0x09, 0x92, 0x26]), "0.9.2342");
    assert_eq!(
        time((0x17, b"491231235959Z")).as_deref(),
        Some("2049-12-31T23:59:59Z")
    );
    assert_eq!(
        time((0x17, b"500101000000Z")).as_deref(),
        Some("1950-01-01T00:00:00Z")
    );
    assert_eq!(
        time((0x18, b"20500101000000Z")).as_deref(),
        Some("2050-01-01T00:00:00Z")
    );
    assert_eq!(time((0x18, b"20500101000000.5Z")), None);
    assert_eq!(time((0x17, b"5001010000Z")), None);
    assert_eq!(
        time((0x18, b"20240229000000Z")).as_deref(),
        Some("2024-02-29T00:00:00Z")
    );
    for impossible in [
        &b"251301000000Z"[..],
        b"250229000000Z",
        b"251232256100Z",
        b"250101240000Z",
        b"250101006000Z",
    ] {
        assert_eq!(time((0x17, impossible)), None, "{impossible:?}");
    }
    assert_eq!(time((0x18, b"20250229000000Z")), None);
    assert_eq!(serial_hex(&[0x00, 0x80, 0x01]), "8001");
    assert_eq!(serial_hex(&[0x00]), "00");

    let mut cert = Certificate::default();
    let names = [
        &[0x30, 0x1f][..],
        &[0x81, 0x05],
        b"a@b.c",
        &[0x87, 0x04, 192, 0, 2, 1],
        &[
            0x87, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ],
    ]
    .concat();
    alternative_names(&names, &mut cert).expect("names");
    assert_eq!(cert.emails, ["a@b.c"]);
    assert_eq!(cert.ip_addresses, ["192.0.2.1", "2001:db8::1"]);
    assert!(is_ca(&[0x30, 0x03, 0x01, 0x01, 0xff]));
    assert!(!is_ca(&[0x30, 0x00]));
}

/// Every corruption of the two logged certificates (a byte, an extreme length, a cut, a repeated
/// stretch) is read or refused, and what is read is written out: none panics.
#[test]
fn a_corrupted_certificate_is_read_or_refused_never_a_panic() {
    for (name, certificate) in [("ev", der(EV_RSA)), ("dv", der(DV_EC))] {
        for (case, bytes) in crate::test_support::mutations(&certificate, 0xCE27_5EED, 5_000)
            .into_iter()
            .enumerate()
        {
            let outcome = std::panic::catch_unwind(|| {
                if let Ok(cert) = parse(&bytes) {
                    let _ = one_line(&cert.subject);
                    let _ = one_line(&cert.issuer);
                    let _ = attribute(&cert.subject, "CN");
                }
                let _ = pem(&bytes);
            });
            assert!(outcome.is_ok(), "{name} case {case} panicked");
        }
    }
}
