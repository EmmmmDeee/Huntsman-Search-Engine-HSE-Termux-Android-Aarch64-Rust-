//! A known DNS RDATA layout must consume its declared bytes, not silently discard a suffix.
use huntsman_recon::dns_wire::{self, Data, WireError};

fn answer(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    out.extend_from_slice(b"\x07example\x03com\x00");
    out.extend_from_slice(&[0, 1, 0, 1]);
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    out.extend_from_slice(
        &u16::try_from(data.len())
            .expect("small fixture")
            .to_be_bytes(),
    );
    out.extend_from_slice(data);
    out
}

fn decode(kind: u16, data: &[u8]) -> Result<dns_wire::Message, WireError> {
    dns_wire::parse(&answer(kind, data))
}

#[test]
fn a_single_name_cannot_silently_discard_extra_rdata() {
    for (kind, prefix) in [(2, 0), (5, 0), (12, 0), (39, 0), (15, 2), (33, 6)] {
        for name in [&[0xc0, 0x0c][..], &[0][..], b"\x02ns\x00".as_slice()] {
            let mut data = vec![0; prefix];
            data.extend_from_slice(name);
            assert!(
                decode(kind, &data).is_ok(),
                "the well-framed name is accepted"
            );
            for suffix in [&[0xff][..], &[0][..], &[0xc0, 0x0c][..]] {
                let mut malformed = data.clone();
                malformed.extend_from_slice(suffix);
                assert!(
                    decode(kind, &malformed).is_err(),
                    "a known single-name layout must consume every RDATA byte"
                );
            }
        }
    }
}

#[test]
fn soa_cannot_silently_discard_extra_rdata() {
    let mut data = vec![0xc0, 0x0c, 0xc0, 0x0c];
    data.extend_from_slice(&[0; 20]);
    assert!(decode(6, &data).is_ok());
    for suffix in [&[0xff][..], &[0][..], &[0; 20][..]] {
        let mut malformed = data.clone();
        malformed.extend_from_slice(suffix);
        assert!(
            decode(6, &malformed).is_err(),
            "SOA must contain exactly two names and five u32 values"
        );
    }
}

#[test]
fn valid_compression_targets_and_decoded_fields_are_preserved() {
    let parsed = decode(5, &[0xc0, 0x0c]).expect("valid compressed CNAME");
    assert!(matches!(&parsed.answers[0].data, Data::Name(name) if name == "example.com"));
    let parsed = decode(15, &[0, 10, 0xc0, 0x0c]).expect("valid MX");
    assert!(
        matches!(&parsed.answers[0].data, Data::Mx { preference: 10, exchange } if exchange == "example.com")
    );
    let parsed = decode(33, &[0, 1, 0, 2, 1, 187, 0xc0, 0x0c]).expect("valid SRV");
    assert!(
        matches!(&parsed.answers[0].data, Data::Srv { priority: 1, weight: 2, port: 443, target } if target == "example.com")
    );
    let mut soa = vec![0xc0, 0x0c, 0xc0, 0x0c];
    for number in 1u32..=5 {
        soa.extend_from_slice(&number.to_be_bytes());
    }
    let parsed = decode(6, &soa).expect("valid SOA");
    assert!(
        matches!(&parsed.answers[0].data, Data::Soa { mname, rname, serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 5 } if mname == "example.com" && rname == "example.com")
    );
}

#[test]
fn opaque_types_and_existing_short_record_refusals_are_preserved() {
    let raw = [0xc0, 0x0c, 0xff, 0, 10];
    let parsed = decode(65000, &raw).expect("unknown RDATA is opaque evidence");
    assert!(matches!(&parsed.answers[0].data, Data::Other(bytes) if bytes == &raw));
    for (kind, short) in [
        (5, &[0xc0][..]),
        (15, &[0][..]),
        (33, &[0; 5][..]),
        (6, &[0, 0][..]),
    ] {
        assert!(decode(kind, short).is_err());
    }
    assert!(decode(1, &[1, 2, 3, 4]).is_ok());
    assert!(decode(28, &[0; 16]).is_ok());
    assert!(decode(16, b"\x02ok").is_ok());
}
