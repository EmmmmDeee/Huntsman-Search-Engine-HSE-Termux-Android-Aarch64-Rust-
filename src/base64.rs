//! Base64 (RFC 4648), the crate's one codec: the standard alphabet with padding, as the web
//! server's Content-Security-Policy hashes use it and as certificate transparency APIs carry a
//! certificate's DER, and the URL-safe alphabet without padding, as the HIBP OAuth PKCE values
//! (RFC 7636) use it.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The standard alphabet, padded with `=` to a multiple of four characters (RFC 4648 section 4).
#[must_use]
pub fn standard(bytes: &[u8]) -> String {
    encode(bytes, STANDARD, true)
}

/// The URL-safe alphabet without padding (RFC 4648 section 5).
#[must_use]
pub fn url_unpadded(bytes: &[u8]) -> String {
    encode(bytes, URL_SAFE, false)
}

/// Decode standard-alphabet Base64 with optional canonical padding and PEM whitespace.
/// Rejects invalid symbols, misplaced or incomplete padding, and nonzero unused pad bits.
/// Validation precedes allocation and decoding, so malformed input never yields partial data.
/// **Pure.**
#[must_use]
pub fn decode_standard(text: &str) -> Option<Vec<u8>> {
    let mut digits = 0_usize;
    let mut padding = 0_usize;
    for byte in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            padding += 1;
            if padding > 2 {
                return None;
            }
        } else {
            if padding != 0 || decode_digit(byte).is_none() {
                return None;
            }
            digits += 1;
        }
    }

    // Optional padding is accepted, but any present padding must be complete.
    // RFC 4648's final 2 or 3 digits carry exactly 1 or 2 decoded bytes.
    match (digits % 4, padding) {
        (0, 0) | (2, 0 | 2) | (3, 0 | 1) => {}
        _ => return None,
    }

    let extra = usize::from(digits % 4 == 2) + 2 * usize::from(digits % 4 == 3);
    let mut output = Vec::with_capacity(digits / 4 * 3 + extra);
    let (mut accumulator, mut pending) = (0_u32, 0_u32);

    for byte in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let value = decode_digit(byte)?;
        accumulator = (accumulator << 6) | u32::from(value);
        pending += 6;
        if pending >= 8 {
            pending -= 8;
            output.push(((accumulator >> pending) & 0xff) as u8);
        }
    }

    // Nonzero discarded bits permit multiple textual encodings of the same bytes.
    // They must be zero even when the input omits '=' padding.
    if pending != 0 && accumulator & ((1_u32 << pending) - 1) != 0 {
        return None;
    }
    Some(output)
}

fn decode_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn encode(bytes: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(table[usize::from(a >> 2)]));
        out.push(char::from(table[usize::from(((a & 3) << 4) | (b >> 4))]));
        if chunk.len() > 1 {
            out.push(char::from(table[usize::from(((b & 15) << 2) | (c >> 6))]));
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(table[usize::from(c & 63)]));
        } else if pad {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_matches_the_rfc_4648_test_vectors() {
        for (input, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(standard(input.as_bytes()), encoded, "{input:?}");
        }
    }

    #[test]
    fn decode_reverses_the_rfc_4648_test_vectors_and_skips_line_breaks() {
        for input in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let encoded = standard(input.as_bytes());
            assert_eq!(decode_standard(&encoded), Some(input.as_bytes().to_vec()));
            let unpadded = encoded.trim_end_matches('=');
            assert_eq!(decode_standard(unpadded), Some(input.as_bytes().to_vec()));
        }
        assert_eq!(decode_standard("Zm9v\nYmFy\r\n"), Some(b"foobar".to_vec()));
        assert_eq!(decode_standard("+/8="), Some(vec![0xfb, 0xff]));
        for bad in ["Zm9v-mFy", "Z", "Zg===", "Zg=a", "Zm9vY"] {
            assert_eq!(decode_standard(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn url_unpadded_drops_padding_and_swaps_the_last_two_symbols() {
        assert_eq!(url_unpadded(b"f"), "Zg");
        assert_eq!(url_unpadded(b"fo"), "Zm8");
        assert_eq!(standard(&[0xfb, 0xff]), "+/8=");
        assert_eq!(url_unpadded(&[0xfb, 0xff]), "-_8");
    }
    #[test]
    fn decoder_rejects_noncanonical_unused_bits_and_incomplete_padding() {
        for bad in [
            "Zh==", "Zh", "Zm9=", "Zm9", "Zg=", "Zm8==", "Zg===", "Zg=a",
            "Zg==A", "Zm8===", "Zg==\\0", "Zg==☃",
        ] {
            assert_eq!(decode_standard(bad), None, "{bad:?}");
        }
        assert_eq!(decode_standard("Zg=="), Some(b"f".to_vec()));
        assert_eq!(decode_standard("Zg"), Some(b"f".to_vec()));
        assert_eq!(decode_standard("Zm8="), Some(b"fo".to_vec()));
        assert_eq!(decode_standard("Zm8"), Some(b"fo".to_vec()));
        assert_eq!(decode_standard(" Zm9v\\r\\nYmFy\\t"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn standard_round_trip_all_byte_values() {
        let bytes: Vec<u8> = (0_u8..=u8::MAX).collect();
        for len in 0..=bytes.len() {
            let encoded = standard(&bytes[..len]);
            assert_eq!(decode_standard(&encoded), Some(bytes[..len].to_vec()), "{len}");
            assert_eq!(
                decode_standard(encoded.trim_end_matches('=')),
                Some(bytes[..len].to_vec()),
                "unpadded {len}"
            );
        }
    }
}
