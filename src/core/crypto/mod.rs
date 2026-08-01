//! Cryptocurrency-address classification — a domain classifier (depending only
//! on `sha2`, no `modules`) shared by the target auto-detector
//! ([`crate::core::scan`]) and the key-harvest pipeline. It lives in `core` (not
//! a module) for exactly that reason: `core` may not depend on `modules`, so the
//! recogniser used by `detect_kind` has to sit at this layer.
//!
//! [`classify_crypto_address`] returns a `crypto_<chain>` tag on a confident
//! match. Thresholds are deliberately strict to avoid colliding with the
//! generic-hex / API-key heuristics (a 32/64-char hex blob must stay a key, not
//! be mistaken for a wallet). Beyond shape, the checksummable chains are
//! **verified**: base58 forms (BTC/LTC/DOGE `1`/`3`/`L`/`M`/`D…`) by their
//! base58check double-SHA256 check digits, and SegWit `bc1…`/`ltc1…` by their
//! bech32 / bech32m polynomial checksum. A shape match whose check digits don't
//! hold — a typo, or random base58 in a breach blob — is rejected at the source,
//! so the universal [`crate::util::found_keys`] scan no longer mints those
//! false-positive wallets across every module. ETH (`0x…` — EIP-55 needs keccak,
//! and a lowercase address carries no checksum), Solana (raw base58, no checksum)
//! and Monero (keccak-based checksum) remain shape-only; for those a false
//! positive stays a low-cost OSINT lead.

use sha2::{Digest, Sha256};

// ─── Digest primitives (the single authoritative SHA-256 → hex helpers) ──────
//
// Deterministic hex-digest identifiers/fingerprints are computed in many places
// — entity/relation ids, scan/live ids, pooled-key ids, SSH-key fingerprints,
// STIX object ids. They used to hand-roll `hex::encode(Sha256::digest(..))` (or
// an incremental `Sha256::new()` + `update` loop) at each site — the same
// primitive written eight ways. These two functions are that primitive, owned
// once, so the hashing can never drift between the identifiers it mints. `core`
// is the correct home: it depends only on `sha2`, and both `core` and `util`
// (which is permitted to import `core`) plus every module can reach it.
//
// NOTE: `core::entity::derive_uid` deliberately does NOT route through here — it
// streams a kind's `Display` into the hasher through a `fmt::Write` shim to keep
// the per-entity hot path allocation-free, and length-prefixes the `Other`
// variant to disambiguate its preimage. That specialisation is a documented
// correctness/performance decision, not incidental duplication.

/// Lowercase hex of `SHA-256(bytes)` — the single authoritative "hash these
/// bytes to a stable 64-char hex digest" primitive. Prefix-takers slice the
/// result (`&sha256_hex(x)[..k]`, identical to hex-encoding the first `k/2`
/// digest bytes); multi-field identifiers use [`sha256_hex_parts`].
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Lowercase hex of `SHA-256(parts[0] ‖ parts[1] ‖ …)`, feeding each part to the
/// hasher in order **without** allocating a combined buffer — the multi-field
/// identifier primitive (a relation's `from|kind|to|scan`, a scan id's
/// keyed+timestamped tuple). Byte-identical to an incremental `update` loop, so
/// it is a drop-in for the hand-rolled ones without changing any minted id.
#[must_use]
pub fn sha256_hex_parts(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

/// Lowercase hex of `MD5(bytes)`. A **legacy, non-cryptographic** digest, used
/// only where an external contract dictates it (Gravatar's email-hash URL,
/// breach-dump digest tables) — never for a security decision. The shared
/// `Digest` trait is already in scope via `sha2`, so `md5::Md5` needs no import.
#[must_use]
pub fn md5_hex(bytes: &[u8]) -> String {
    hex::encode(md5::Md5::digest(bytes))
}

/// Lowercase hex of `SHA-1(bytes)`. A **legacy** digest, used only where an
/// external contract dictates it (HIBP range k-anonymity, breach-dump digest
/// tables) — never for a security decision. Callers that need the uppercase form
/// (HIBP) apply `.to_uppercase()` at the edge.
#[must_use]
pub fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(sha1::Sha1::digest(bytes))
}

/// Base58 alphabet (Bitcoin variant): excludes `0`, `O`, `I`, `l` to avoid
/// visual ambiguity.
fn is_base58(c: char) -> bool {
    matches!(c,
        '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
    )
}

/// Bech32 data charset (BIP-173): lowercase alphanumerics minus `b`, `i`, `o`,
/// `1`. Applied to the payload after a human-readable prefix (`bc1`, `ltc1`).
///
/// The canonical charset is `qpzry9x8gf2tvdw0s3jn54khce6mua7l` — note it
/// contains no `b`. The `'a'..='h'` span used previously silently re-admitted
/// `b`, so the payload check accepted a character the encoder can never emit,
/// widening the false-positive surface (a non-bech32 string carrying a `b` could
/// pass). `b` is now excluded as the doc and the spec require; no real address
/// contains it, so nothing valid is rejected.
fn is_bech32_payload(c: char) -> bool {
    matches!(c.to_ascii_lowercase(),
        'a' | 'c'..='h' | 'j'..='n' | 'p'..='z' | '0' | '2'..='9'
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

// ── Checksum verification (no new dependency: bech32 is pure arithmetic; ───────
//    base58check reuses the workspace `sha2`) ───────────────────────────────────

/// Decode a Base58 (Bitcoin alphabet) string to its raw bytes, big-endian, with
/// leading `1`s restored as leading zero bytes. `None` on a non-Base58 char.
/// Byte-array accumulator — no bignum crate, never panics.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for byte in &mut result {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            result.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Each leading '1' in Base58 is a leading 0x00 byte.
    for c in s.bytes() {
        if c == b'1' {
            result.push(0);
        } else {
            break;
        }
    }
    result.reverse();
    Some(result)
}

/// True if `s` is a valid base58check string: its trailing 4 bytes equal the
/// first 4 bytes of the double-SHA256 of the preceding version+payload. Confirms
/// BTC/LTC/DOGE legacy (`1`/`3`/`L`/`M`/`D`) addresses — version-agnostic, so it
/// validates any coin's base58check without enumerating version bytes.
fn base58check_valid(s: &str) -> bool {
    let Some(decoded) = base58_decode(s) else {
        return false;
    };
    // At least one version byte, a payload, and the 4-byte checksum.
    if decoded.len() < 5 {
        return false;
    }
    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let digest = Sha256::digest(Sha256::digest(payload));
    digest[..4] == *checksum
}

/// BIP-173 bech32 polynomial checksum over 5-bit groups.
fn bech32_polymod(values: &[u8]) -> u32 {
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

/// True if `s` carries a valid bech32 (SegWit v0) or bech32m (v1+/Taproot)
/// checksum: split on the final `1` separator, expand the human-readable prefix,
/// map the data part through the bech32 charset, and confirm the polymod equals
/// the bech32 (`1`) or bech32m (`0x2bc830a3`) constant. Case-folded first (a real
/// address is single-case; a typo fails the math regardless).
fn bech32_checksum_valid(s: &str) -> bool {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let lower = s.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let Some(sep) = lower.rfind('1') else {
        return false;
    };
    // Non-empty HRP, and a data part holding at least the 6-char checksum.
    if sep == 0 || bytes.len() < sep + 7 {
        return false;
    }
    let (hrp, data) = (&bytes[..sep], &bytes[sep + 1..]);
    let mut values: Vec<u8> = Vec::with_capacity(hrp.len() * 2 + 1 + data.len());
    values.extend(hrp.iter().map(|&c| c >> 5));
    values.push(0);
    values.extend(hrp.iter().map(|&c| c & 31));
    for &c in data {
        let Some(v) = CHARSET.iter().position(|&x| x == c) else {
            return false;
        };
        values.push(v as u8);
    }
    let pm = bech32_polymod(&values);
    pm == 1 || pm == 0x2bc8_30a3
}

/// Classify `s` as a cryptocurrency wallet address, returning a `crypto_<chain>`
/// tag (`crypto_btc`, `crypto_eth`, `crypto_ltc`, `crypto_doge`, `crypto_sol`,
/// `crypto_xmr`) on a confident match, else `None`.
///
/// # Guarantees
/// - **Checksum-verified where possible:** BTC/LTC/DOGE base58 forms and
///   `bc1`/`ltc1` SegWit forms must pass their base58check / bech32(m) checksum,
///   so a typo or random base58 blob is rejected. ETH/SOL/XMR remain shape-only
///   (no checksum primitive is available without adding a keccak dependency).
/// - **Hex blobs stay keys:** a bare hash/key (all ASCII hex digits) is never
///   classified, so the generic-hex / API-key heuristics keep it.
/// - **Total:** never panics on any input — the checksum helpers use safe
///   iteration (no panicking byte-indexing) — and returns `None` for the empty
///   string.
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

    // Bitcoin Bech32/Bech32m (BIP-173/350): `bc1` + payload, checksum-verified.
    if (39..=62).contains(&len)
        && (s.starts_with("bc1") || s.starts_with("BC1"))
        && s.chars().skip(3).all(is_bech32_payload)
        && bech32_checksum_valid(s)
    {
        return Some("crypto_btc");
    }

    // Litecoin Bech32: `ltc1` + payload, checksum-verified.
    if (40..=62).contains(&len)
        && (s.starts_with("ltc1") || s.starts_with("LTC1"))
        && s.chars().skip(4).all(is_bech32_payload)
        && bech32_checksum_valid(s)
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
        && base58check_valid(s)
    {
        return Some("crypto_btc");
    }

    // Litecoin legacy: starts `L` or `M`, 26-35 base58, checksum-verified.
    if (26..=35).contains(&len)
        && (s.starts_with('L') || s.starts_with('M'))
        && s.chars().all(is_base58)
        && !is_all_ascii_hex(s)
        && base58check_valid(s)
    {
        return Some("crypto_ltc");
    }

    // Dogecoin: starts `D`, 34 base58, checksum-verified.
    if len == 34
        && s.starts_with('D')
        && s.chars().all(is_base58)
        && !is_all_ascii_hex(s)
        && base58check_valid(s)
    {
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
    include!("tests.rs");
}
