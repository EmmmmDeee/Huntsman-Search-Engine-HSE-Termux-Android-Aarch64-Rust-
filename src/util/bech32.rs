//! Shared BIP-173 bech32 checksum primitives — the polynomial checksum and
//! human-readable-prefix expansion both [`crate::core::crypto`] (SegWit
//! `bc1…`/`ltc1…` address validation) and [`crate::modules::nostr`] (`npub1…`
//! encode/decode) independently implemented before this module existed.
//! `core` may depend on `util` (never the reverse — see the crate's layering
//! doctrine), so this is the one place both can share it from.

/// bech32 checksum polynomial (BIP-173).
pub fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Expand a human-readable prefix into the bech32 checksum pre-image: the
/// high 3 bits of each byte, a zero separator, then the low 5 bits of each
/// byte — per BIP-173's `hrp_expand`.
pub fn hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.iter().map(|&c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.iter().map(|&c| c & 0x1f));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hrp_expand_matches_bip173_worked_example() {
        // BIP-173's own worked example for hrp "a".
        assert_eq!(hrp_expand(b"a"), vec![3, 0, 1]);
    }

    #[test]
    fn polymod_of_a_valid_bech32_checksum_input_is_one() {
        // "a12uel5l" is a BIP-173 test vector: a valid, empty-data bech32
        // string with hrp "a". Its full checksum pre-image (hrp_expand("a")
        // ++ decoded data-part symbols) must polymod to the bech32 constant 1.
        const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let data = "2uel5l";
        let mut values = hrp_expand(b"a");
        for c in data.bytes() {
            values.push(CHARSET.iter().position(|&x| x == c).expect("valid charset") as u8);
        }
        assert_eq!(polymod(&values), 1);
    }
}
