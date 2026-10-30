//! Offline NFC / APDU record inspection for operator-provided bytes.
//! No radio access, card emulation, keys, PIN retries or transmission.
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApduInspection {
    pub kind: &'static str,
    pub byte_count: usize,
    pub instruction: Option<u8>,
    pub class: Option<u8>,
    pub data_bytes: usize,
    pub sw1: Option<u8>,
    pub sw2: Option<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NdefInspection {
    pub byte_count: usize,
    pub records: usize,
    pub record_types: Vec<String>,
    pub total_payload_bytes: usize,
}

/// Accept a bounded hex dump; never fetch or communicate with an NFC device.
///
/// # Errors
/// Refuses odd-length, invalid and oversized hexadecimal input.
pub fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let normalized: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-' | '\n' | '\t'))
        .collect();
    if normalized.is_empty() || !normalized.len().is_multiple_of(2) || normalized.len() > 16384 {
        return Err("hex input must contain 1-8192 complete bytes".to_owned());
    }
    normalized
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hex = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            u8::from_str_radix(hex, 16).map_err(|_| "invalid hex digit".to_owned())
        })
        .collect()
}

/// Summarise an ISO 7816-4 command or response without exposing payload bytes.
///
/// # Errors
/// Refuses truncated commands and invalid framing.
pub fn inspect_apdu(data: &[u8]) -> Result<ApduInspection, String> {
    if data.is_empty() || data.len() > 8192 {
        return Err("APDU must contain 1-8192 bytes".to_owned());
    }
    if data.len() == 2 {
        return Ok(ApduInspection {
            kind: "response_status",
            byte_count: data.len(),
            instruction: None,
            class: None,
            data_bytes: 0,
            sw1: Some(data[0]),
            sw2: Some(data[1]),
        });
    }
    if data.len() < 4 {
        return Err("command APDU is shorter than its four-byte header".to_owned());
    }
    let payload_size = match data.len() {
        4 | 5 => 0,
        _ if data[4] > 0 => {
            let lc = usize::from(data[4]);
            if data.len() != 5 + lc && data.len() != 6 + lc {
                return Err("short APDU length does not match Lc".to_owned());
            }
            lc
        }
        _ => return Err("extended APDU lengths are not supported".to_owned()),
    };
    Ok(ApduInspection {
        kind: "command",
        byte_count: data.len(),
        class: Some(data[0]),
        instruction: Some(data[1]),
        data_bytes: payload_size,
        sw1: None,
        sw2: None,
    })
}

/// Inspect one unencrypted, uncompressed NDEF message, validating its boundaries.
/// Payload contents are deliberately not exported.
///
/// # Errors
/// Refuses malformed headers, chunked payloads and truncated lengths.
pub fn inspect_ndef(data: &[u8]) -> Result<NdefInspection, String> {
    if data.is_empty() || data.len() > 8192 {
        return Err("NDEF message must contain 1-8192 bytes".to_owned());
    }
    let mut position = 0_usize;
    let mut first = true;
    let mut last = false;
    let mut types = Vec::new();
    let mut payload_total = 0_usize;
    while position < data.len() {
        if last || types.len() >= 100 || data.len() - position < 2 {
            return Err("NDEF has trailing or incomplete records".to_owned());
        }
        let flags = data[position];
        let type_len = usize::from(data[position + 1]);
        position += 2;
        let message_begin = flags & 0x80 != 0;
        let message_end = flags & 0x40 != 0;
        let chunked = flags & 0x20 != 0;
        let short_record = flags & 0x10 != 0;
        let has_id = flags & 0x08 != 0;
        if message_begin != first || chunked {
            return Err("invalid NDEF message-begin or unsupported chunking".to_owned());
        }
        let length_width = if short_record { 1 } else { 4 };
        if data.len() - position < length_width {
            return Err("truncated NDEF payload length".to_owned());
        }
        let payload_len = if short_record {
            usize::from(data[position])
        } else {
            usize::try_from(u32::from_be_bytes([
                data[position],
                data[position + 1],
                data[position + 2],
                data[position + 3],
            ]))
            .map_err(|_| "NDEF length exceeds platform range".to_owned())?
        };
        position += length_width;
        let id_len = if has_id {
            if position >= data.len() {
                return Err("missing NDEF ID length".to_owned());
            }
            let n = usize::from(data[position]);
            position += 1;
            n
        } else {
            0
        };
        let required = type_len
            .checked_add(id_len)
            .and_then(|x| x.checked_add(payload_len))
            .ok_or_else(|| "NDEF length overflow".to_owned())?;
        if data.len() - position < required {
            return Err("truncated NDEF record body".to_owned());
        }
        let name = if type_len > 0 {
            let t = &data[position..position + type_len];
            if t.iter().all(u8::is_ascii_graphic) {
                String::from_utf8_lossy(t).into_owned()
            } else {
                "binary_type".to_owned()
            }
        } else {
            "empty_type".to_owned()
        };
        types.push(name);
        payload_total += payload_len;
        position += required;
        first = false;
        last = message_end;
    }
    if !last {
        return Err("NDEF final record missing ME flag".to_owned());
    }
    Ok(NdefInspection {
        byte_count: data.len(),
        records: types.len(),
        record_types: types,
        total_payload_bytes: payload_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_commands_and_statuses() {
        let command = inspect_apdu(&decode_hex("00 A4 04 00 02 3F 00").unwrap()).unwrap();
        assert_eq!(command.kind, "command");
        assert_eq!(command.instruction, Some(0xa4));
        assert_eq!(command.data_bytes, 2);
        let status = inspect_apdu(&[0x90, 0x00]).unwrap();
        assert_eq!((status.sw1, status.sw2), (Some(0x90), Some(0)));
        assert!(inspect_apdu(&[0, 0xA4, 0, 0, 3, 0x01]).is_err());
    }

    #[test]
    fn ndef_text_record_is_counted_not_exposed() {
        // Single short-record NDEF text payload. Data contents remain private.
        let data = [0xD1, 0x01, 0x05, b'T', 0x02, b'e', b'n', b'H', b'i'];
        let report = inspect_ndef(&data).unwrap();
        assert_eq!(report.record_types, vec!["T"]);
        assert_eq!(report.total_payload_bytes, 5);
        assert_eq!(report.records, 1);
        assert!(inspect_ndef(&data[..7]).is_err());
    }

    #[test]
    fn impossible_and_chunked_ndef_are_rejected() {
        assert!(inspect_ndef(&[0xB1, 0x01, 0x00, b'T']).is_err());
        assert!(inspect_ndef(&[0x91, 0x01, 0x00, b'T']).is_err());
        assert!(decode_hex("0x01").is_err());
    }
}
