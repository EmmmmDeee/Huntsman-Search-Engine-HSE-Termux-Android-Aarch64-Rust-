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
    fn bech32_payload_excludes_the_full_b_i_o_1_set() {
        // BIP-173's data charset is qpzry9x8gf2tvdw0s3jn54khce6mua7l — it
        // contains no b/i/o and no digit 1. Every excluded symbol must be
        // rejected; every included one accepted. Guards the off-by-one that
        // let 'b' through ('a'..='h' spanned it).
        for excluded in ['b', 'i', 'o', '1', 'B', 'I', 'O'] {
            assert!(
                !is_bech32_payload(excluded),
                "{excluded} is not in the bech32 charset"
            );
        }
        for included in "qpzry9x8gf2tvdw0s3jn54khce6mua7l".chars() {
            assert!(
                is_bech32_payload(included),
                "{included} IS in the bech32 charset"
            );
        }
        // End to end: a bc1 string whose payload carries a 'b' is not a valid
        // bech32 address and must not be classified (the canonical genesis
        // bech32 address, which has no 'b', still classifies — see other tests).
        assert_eq!(
            classify_crypto_address("bc1qbbr0srrr7xfkvy5l643lydnw9re59gtzzwf5md"),
            None,
            "a 'b' in the payload is outside the bech32 charset"
        );
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

    // ── is_base58 ─────────────────────────────────────────────────────────────

    #[test]
    fn is_base58_accepts_alphabet_and_rejects_ambiguous_chars() {
        // Boundary members of each accepted span.
        for c in ['1', '9', 'A', 'H', 'J', 'N', 'P', 'Z', 'a', 'k', 'm', 'z'] {
            assert!(is_base58(c), "{c} should be base58");
        }
        // The four visually-ambiguous exclusions.
        for c in ['0', 'O', 'I', 'l'] {
            assert!(!is_base58(c), "{c} must be excluded");
        }
        // Non-alphanumerics are never base58.
        assert!(!is_base58('+'));
        assert!(!is_base58(' '));
    }

    // ── is_all_ascii_hex ──────────────────────────────────────────────────────

    #[test]
    fn is_all_ascii_hex_requires_nonempty_all_hex() {
        assert!(is_all_ascii_hex("deadBEEF0123"));
        assert!(!is_all_ascii_hex("")); // empty → false
        assert!(!is_all_ascii_hex("dead beef")); // space is not hex
        assert!(!is_all_ascii_hex("xyz")); // non-hex letters
    }
