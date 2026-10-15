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

/// The bytes of standard-alphabet text, padded or not; whitespace (a PEM body's line breaks) is
/// skipped. `None` for any other symbol, padding before the end, or a dangling sixth bit group.
/// **Pure.**
#[must_use]
pub fn decode_standard(text: &str) -> Option<Vec<u8>> {
    let symbols: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let data = symbols
        .iter()
        .rposition(|&byte| byte != b'=')
        .map_or(&symbols[..0], |last| &symbols[..=last]);
    if symbols.len() - data.len() > 2 || data.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 2);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for &symbol in data {
        let value = STANDARD.iter().position(|&known| known == symbol)?;
        buffer = (buffer << 6) | u32::try_from(value).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
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
}
