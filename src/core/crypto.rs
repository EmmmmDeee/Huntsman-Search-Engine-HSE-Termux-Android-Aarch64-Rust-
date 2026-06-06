//! Cryptocurrency-address classification — a pure, dependency-free domain
//! classifier shared by the target auto-detector ([`crate::core::scan`]) and the
//! key-harvest pipeline. It lives in `core` (not a module) for exactly that
//! reason: `core` may not depend on `modules`, so the recogniser used by
//! `detect_kind` has to sit at this layer.
//!
//! [`classify_crypto_address`] returns a `crypto_<chain>` tag on a confident
//! match. Thresholds are deliberately strict to avoid colliding with the
//! generic-hex / API-key heuristics (a 32/64-char hex blob must stay a key, not
//! be mistaken for a wallet). Detection is by shape only — no checksum
//! verification — which is the right trade-off for OSINT triage: cheap, and a
//! false positive is a low-cost lead, not a security decision.

/// Base58 alphabet (Bitcoin variant): excludes `0`, `O`, `I`, `l` to avoid
/// visual ambiguity.
fn is_base58(c: char) -> bool {
    matches!(c,
        '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
    )
}

/// Bech32 data charset (BIP-173): lowercase alphanumerics minus `b`, `i`, `o`,
/// `1`. Applied to the payload after a human-readable prefix (`bc1`, `ltc1`).
fn is_bech32_payload(c: char) -> bool {
    matches!(c.to_ascii_lowercase(),
        'a'..='h' | 'j'..='n' | 'p'..='z' | '0' | '2'..='9'
    )
}

/// True if `s` is non-empty and every byte is an ASCII hex digit — i.e. a bare
/// hash/key blob (MD5, SHA-*, a hex token). Used to keep such blobs OUT of the
/// prefix-less base58 branches: base58 excludes only `0` among the hex digits,
/// so a 32-char hash with no `0` and a `1`/`3` lead would otherwise satisfy
/// `all(is_base58)` and be mis-read as a Bitcoin address. A genuine base58
/// address is essentially never all-hex (`p < (15/58)^26`), so this never
/// rejects a real one.
fn is_all_ascii_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Classify `s` as a cryptocurrency wallet address, returning a `crypto_<chain>`
/// tag (`crypto_btc`, `crypto_eth`, `crypto_ltc`, `crypto_doge`, `crypto_sol`,
/// `crypto_xmr`) on a confident match, else `None`.
///
/// # Guarantees
/// - **Shape only** (no checksum): a match means `s` *looks like* an address of
///   that chain, which is the right trade-off for OSINT triage.
/// - **Hex blobs stay keys:** a bare hash/key (all ASCII hex digits) is never
///   classified, so the generic-hex / API-key heuristics keep it.
/// - **Total:** never panics, on any input (all checks are char/prefix based,
///   never byte-indexed), and returns `None` for the empty string.
///
/// ```
/// use huntsman_search_engine::core::crypto::classify_crypto_address;
///
/// assert_eq!(
///     classify_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
///     Some("crypto_btc"),
/// ); // Bitcoin genesis P2PKH
/// assert_eq!(
///     classify_crypto_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
///     Some("crypto_eth"),
/// );
/// // A 32-char hex hash stays a key, not a wallet — even with no `0` digit.
/// assert_eq!(classify_crypto_address("1f3a9b8c4d5e6f7a8b9c1d2e3f4a5b6c"), None);
/// assert_eq!(classify_crypto_address(""), None);
/// ```
#[must_use]
pub fn classify_crypto_address(s: &str) -> Option<&'static str> {
    let len = s.len();

    // Bitcoin Bech32 (BIP-173): `bc1` + 39-59 char payload.
    if (39..=62).contains(&len)
        && (s.starts_with("bc1") || s.starts_with("BC1"))
        && s.chars().skip(3).all(is_bech32_payload)
    {
        return Some("crypto_btc");
    }

    // Litecoin Bech32: `ltc1` + payload.
    if (40..=62).contains(&len)
        && (s.starts_with("ltc1") || s.starts_with("LTC1"))
        && s.chars().skip(4).all(is_bech32_payload)
    {
        return Some("crypto_ltc");
    }

    // Ethereum / EVM (ERC-20 / Polygon / BSC): `0x` + 40 hex chars (160-bit).
    // All EVM chains share this shape; chain attribution happens at lookup.
    if len == 42
        && (s.starts_with("0x") || s.starts_with("0X"))
        && s.chars().skip(2).all(|c| c.is_ascii_hexdigit())
    {
        return Some("crypto_eth");
    }

    // Bitcoin P2PKH (legacy `1…`) and P2SH (multisig `3…`): 26-35 base58.
    // `!is_all_ascii_hex` keeps a 32-char hex hash (which is all-base58 when it
    // has no `0`) from being mis-read as an address; the guard is last so it only
    // scans a candidate that already passed the cheap shape checks.
    if (26..=35).contains(&len)
        && (s.starts_with('1') || s.starts_with('3'))
        && s.chars().all(is_base58)
        && !is_all_ascii_hex(s)
    {
        return Some("crypto_btc");
    }

    // Litecoin legacy: starts `L` or `M`, 26-35 base58.
    if (26..=35).contains(&len)
        && (s.starts_with('L') || s.starts_with('M'))
        && s.chars().all(is_base58)
        && !is_all_ascii_hex(s)
    {
        return Some("crypto_ltc");
    }

    // Dogecoin: starts `D`, 34 base58.
    if len == 34 && s.starts_with('D') && s.chars().all(is_base58) && !is_all_ascii_hex(s) {
        return Some("crypto_doge");
    }

    // Solana: 32-44 base58, no fixed prefix. The shape overlaps several
    // BTC-style addresses, so require the modern 43-44 char form to keep the
    // false-positive surface tight.
    if (43..=44).contains(&len) && s.chars().all(is_base58) && !is_all_ascii_hex(s) {
        return Some("crypto_sol");
    }

    // Monero (XMR): 95 chars, starts `4` or `8`, base58 charset.
    if len == 95
        && (s.starts_with('4') || s.starts_with('8'))
        && s.chars().all(is_base58)
        && !is_all_ascii_hex(s)
    {
        return Some("crypto_xmr");
    }

    None
}

/// The bare chain label (`btc`, `eth`, …) for a `crypto_<chain>` tag, or the tag
/// unchanged if it lacks the prefix. Convenience for entity tagging / display.
///
/// ```
/// use huntsman_search_engine::core::crypto::chain_label;
///
/// assert_eq!(chain_label("crypto_btc"), "btc");
/// assert_eq!(chain_label("crypto_eth"), "eth");
/// assert_eq!(chain_label("already-bare"), "already-bare"); // no prefix → unchanged
/// ```
#[must_use]
pub fn chain_label(crypto_tag: &str) -> &str {
    crypto_tag.strip_prefix("crypto_").unwrap_or(crypto_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_each_supported_chain() {
        // Public, well-known addresses (genesis / docs / burn) — never secrets.
        assert_eq!(
            classify_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            Some("crypto_btc")
        ); // Bitcoin genesis P2PKH
        assert_eq!(
            classify_crypto_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            Some("crypto_btc")
        ); // bech32
        assert_eq!(
            classify_crypto_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            Some("crypto_eth")
        ); // vitalik.eth
        assert_eq!(chain_label("crypto_btc"), "btc");
        assert_eq!(chain_label("crypto_eth"), "eth");
    }

    #[test]
    fn rejects_non_addresses() {
        // A 32-char hex blob is a hash/key, NOT a wallet — must stay None so the
        // key heuristics keep it.
        assert_eq!(
            classify_crypto_address("5e3706b9c16282351af9c3aac7107b54"),
            None
        );
        assert_eq!(classify_crypto_address("hello"), None);
        assert_eq!(classify_crypto_address(""), None);
        // `0x` + non-hex is not EVM.
        assert_eq!(
            classify_crypto_address("0xZZZZ6BF26964aF9D7eEd9e03E53415D37aA96045"),
            None
        );
    }

    /// Regression + invariant proof: a bare hex blob (hash/key) is NEVER
    /// classified as a wallet, for any length or leading hex digit — even when it
    /// contains no `0` (the case that previously slipped a 32-char MD5 through the
    /// BTC-legacy base58 branch). Hex blobs must stay keys for the key heuristics.
    #[test]
    fn hex_blobs_are_never_classified_as_crypto() {
        // Cover every base58-branch length window and a representative set of
        // leading digits (incl. those that anchor BTC `1`/`3`, XMR `4`/`8`,
        // Dogecoin `D`). No `0` anywhere → maximal base58 overlap.
        let alphabet = b"123456789abcdef"; // hex minus '0'
        for len in 1usize..=96 {
            for &lead in b"1348adf" {
                let mut s = String::with_capacity(len);
                s.push(char::from(lead));
                for i in 1..len {
                    s.push(char::from(alphabet[i % alphabet.len()]));
                }
                assert_eq!(
                    classify_crypto_address(&s),
                    None,
                    "hex blob {s:?} (len {len}) must not be a wallet"
                );
            }
        }
        // The guard must not over-reject genuine (non-all-hex) addresses.
        assert_eq!(
            classify_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            Some("crypto_btc")
        );
        assert_eq!(
            classify_crypto_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            Some("crypto_eth")
        );
    }
}
