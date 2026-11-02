//! Offline BER-TLV structure inspection. No card credentials, payload export,
//! Android NFC radio, payment emulation or transmission.
use serde::Serialize;

const MAX_BYTES: usize = 8192;
const MAX_FIELDS: usize = 128;
const MAX_DEPTH: usize = 8;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TlvInspection {
    pub byte_count: usize,
    pub fields: usize,
    pub constructed_fields: usize,
    pub tag_names_hex: Vec<String>,
}

fn inspect_values(data: &[u8], depth: usize, out: &mut TlvInspection) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("BER-TLV nesting limit exceeded".to_owned());
    }
    let mut pos = 0;
    while pos < data.len() {
        if out.fields >= MAX_FIELDS {
            return Err("BER-TLV field limit exceeded".to_owned());
        }
        let first = data[pos];
        pos += 1;
        if matches!(first, 0x00 | 0xff) {
            return Err("BER-TLV padding and reserved tag unsupported".to_owned());
        }
        let mut tag = vec![first];
        if first & 0x1f == 0x1f {
            let mut terminated = false;
            for _ in 0..3 {
                let byte = *data
                    .get(pos)
                    .ok_or_else(|| "truncated multi-byte BER tag".to_owned())?;
                pos += 1;
                tag.push(byte);
                if byte & 0x80 == 0 {
                    terminated = true;
                    break;
                }
            }
            if !terminated {
                return Err("BER-TLV tag too long".to_owned());
            }
        }
        let first_len = *data
            .get(pos)
            .ok_or_else(|| "BER-TLV length missing".to_owned())?;
        pos += 1;
        let count = if first_len & 0x80 == 0 {
            usize::from(first_len)
        } else {
            let width = usize::from(first_len & 0x7f);
            if width == 0 || width > 4 || data.len() - pos < width {
                return Err("unsupported BER-TLV long length".to_owned());
            }
            let mut n = 0_usize;
            for byte in &data[pos..pos + width] {
                n = n
                    .checked_mul(256)
                    .and_then(|x| x.checked_add(usize::from(*byte)))
                    .ok_or_else(|| "BER-TLV length overflow".to_owned())?;
            }
            pos += width;
            n
        };
        if count > data.len() - pos {
            return Err("BER-TLV record truncated".to_owned());
        }
        out.fields += 1;
        out.tag_names_hex.push(
            tag.iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>(),
        );
        if first & 0x20 != 0 {
            out.constructed_fields += 1;
            inspect_values(&data[pos..pos + count], depth + 1, out)?;
        }
        pos += count;
    }
    Ok(())
}

/// Inspect BER-TLV tag names and lengths without releasing any value bytes.
///
/// # Errors
/// Refuses malformed, truncated, indefinite, deeply nested or oversized frames.
pub fn inspect_tlv(data: &[u8]) -> Result<TlvInspection, String> {
    if data.is_empty() || data.len() > MAX_BYTES {
        return Err("BER-TLV input must contain 1-8192 bytes".to_owned());
    }
    let mut out = TlvInspection {
        byte_count: data.len(),
        fields: 0,
        constructed_fields: 0,
        tag_names_hex: Vec::new(),
    };
    inspect_values(data, 0, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_tlv_and_long_tag_are_inspected_without_contents() {
        let report = inspect_tlv(&[0x6f, 7, 0x84, 2, 0x12, 0x34, 0x50, 1, 0x41]).unwrap();
        assert_eq!(report.fields, 3);
        assert_eq!(report.constructed_fields, 1);
        assert_eq!(report.tag_names_hex, ["6F", "84", "50"]);
        assert!(!serde_json::to_string(&report).unwrap().contains("1234"));
        assert_eq!(
            inspect_tlv(&[0x9f, 0x33, 1, 0x11]).unwrap().tag_names_hex,
            ["9F33"]
        );
    }

    #[test]
    fn rejects_malformed_bounded_tlv_records() {
        for frame in [
            vec![0x5a, 0x80],
            vec![0x5a, 0x02, 0x01],
            vec![0x6f, 0x01, 0x84],
            vec![0x9f, 0x80],
            vec![0x00],
            vec![0xff],
            vec![0x5a, 0x84, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(inspect_tlv(&frame).is_err());
        }
    }
}
