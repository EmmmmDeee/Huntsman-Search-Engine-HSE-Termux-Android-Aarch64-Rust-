//! Non-API-key secret detectors: PEM private keys, crypto-wallet addresses,
//! and recursive base64 unwrapping (+ Shannon entropy). Pure, shape-anchored
//! classifiers split out of the harvester core. Parent items via `use super::*`.

use super::*;

/// Try to classify `s` as a PEM-encoded private-key block. Returns
/// `Some(service_tag)` when the BEGIN header matches a known class.
/// The trailing block (`-----END ... PRIVATE KEY-----`) is not
/// required — partial-paste in stealer dumps is common, and the
/// header alone is high-signal.
pub(super) fn identify_pem_private_key(s: &str) -> Option<&'static str> {
    // Header layout: `-----BEGIN <class> [PRIVATE KEY]-----`.
    // Examples:
    //   -----BEGIN RSA PRIVATE KEY-----
    //   -----BEGIN OPENSSH PRIVATE KEY-----
    //   -----BEGIN EC PRIVATE KEY-----
    //   -----BEGIN DSA PRIVATE KEY-----
    //   -----BEGIN PRIVATE KEY-----      (PKCS#8 generic)
    //   -----BEGIN ENCRYPTED PRIVATE KEY-----  (PKCS#8 encrypted)
    //   -----BEGIN PGP PRIVATE KEY BLOCK-----
    //   -----BEGIN PGP MESSAGE-----      (often wraps a key body)
    if !s.starts_with("-----BEGIN ") {
        return None;
    }
    // Sanity check on length — a real PEM body is at least 100 chars
    // of base64 even for the smallest key. This keeps a bare header
    // string with no body from being mis-classified.
    if s.len() < 80 {
        return None;
    }
    let header_line = s.lines().next().unwrap_or("");
    if header_line.starts_with("-----BEGIN RSA PRIVATE KEY") {
        return Some("pem_rsa_private");
    }
    if header_line.starts_with("-----BEGIN OPENSSH PRIVATE KEY") {
        return Some("pem_openssh_private");
    }
    if header_line.starts_with("-----BEGIN EC PRIVATE KEY") {
        return Some("pem_ec_private");
    }
    if header_line.starts_with("-----BEGIN DSA PRIVATE KEY") {
        return Some("pem_dsa_private");
    }
    if header_line.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY") {
        return Some("pem_pkcs8_encrypted");
    }
    if header_line.starts_with("-----BEGIN PRIVATE KEY") {
        return Some("pem_pkcs8_private");
    }
    if header_line.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK") {
        return Some("pem_pgp_private");
    }
    if header_line.starts_with("-----BEGIN PGP MESSAGE") {
        return Some("pem_pgp_message");
    }
    // Header was `-----BEGIN ` but didn't match a known class.
    // Don't tag as a specific service — return None and let the
    // caller fall through to other detectors.
    None
}

// ── Cryptocurrency wallet-address classifier ──────────────────────
//
// Stealer logs from clipboard-hijacker malware families
// (RedLine "ClipBanker" stage, Vidar "wallet stealer" module,
// AgentTesla "crypto-clipper" plugin) routinely carry these
// addresses in their `app_data` / `notes` / `extras` fields
// alongside the cracked credentials we already harvest.
//
// Each detection returns a `"crypto_<chain>"` service tag so
// downstream lookups can pivot to the right free public API:
//
//   * BTC      → blockchain.info / blockstream.info
//   * ETH      → blockscout.com / etherscan.io
//   * SOL      → solana.fm (free tier)
//   * XMR      → no public chain lookup; tag-only emission
//   * LTC      → blockchain.info LTC endpoint
//   * DOGE     → blockchain.info DOGE endpoint
//
// Address formats sourced from each chain's public docs +
// Wikipedia. Length + alphabet checks tight enough to avoid
// false-positives against random alphanumeric strings (which
// otherwise drift into the generic-hex catch-all). Real
// addresses pass entropy ≥ 3.5 trivially.

/// Try to classify a string as a cryptocurrency wallet address. Delegates to
/// the canonical, shared classifier in `core::crypto` (the same one the target
/// auto-detector uses) so the shape rules live in exactly one place.
pub(super) fn identify_crypto_address(s: &str) -> Option<&'static str> {
    crate::core::crypto::classify_crypto_address(s)
}

// ── Base64 decode-through scanning (keyhog port) ──────────────────
//
// Stealer logs, ad-hoc credential dumps and CI-pipeline leaks often
// wrap the raw secret in a single layer of base64 — sometimes to
// fit it into a JSON-string field with awkward chars, sometimes to
// hide it from the most superficial grep-based scanners. keyhog's
// contribution to the corpus is treating every harvested string as
// also-maybe-base64 and recursing through one or two layers of
// decode before giving up.
//
// Bounded recursion: a layered-base64 payload is fair game, but
// runaway recursion against a hostile blob isn't. Depth cap at 2
// covers the realistic encode-twice case without enabling a DoS.

pub(super) const BASE64_DECODE_MAX_DEPTH: u8 = 2;
const BASE64_MIN_ENCODED_LEN: usize = 24;
const BASE64_MAX_ENCODED_LEN: usize = 8192;

/// Cheap pre-check before attempting base64 decode. Filters obvious
/// non-candidates (too short, too long, contains chars outside the
/// unified standard + URL-safe alphabet) so the hot path doesn't
/// run `base64::decode` against every harvested field.
pub(super) fn looks_like_base64(s: &str) -> bool {
    if s.len() < BASE64_MIN_ENCODED_LEN || s.len() > BASE64_MAX_ENCODED_LEN {
        return false;
    }
    let stripped = s.trim_end_matches('=');
    if stripped.is_empty() {
        return false;
    }
    // Reject anything that doesn't sit inside the union of the
    // standard + URL-safe base64 alphabets. A single space, dot,
    // colon or slash-with-protocol stem disqualifies — that's
    // intentional: those characters reliably indicate the input
    // is something else (URL, sentence, path) and not a raw blob.
    stripped
        .as_bytes()
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_')
}

/// Attempt to decode `input` as base64 and recursively scan the
/// decoded UTF-8 form for an API key. Returns the detected service,
/// the decoded key value (owned, since the decode buffer doesn't
/// outlive the call) and the depth at which the hit was found.
///
/// Bounded by [`BASE64_DECODE_MAX_DEPTH`] to prevent layered-base64
/// DoS. Tries standard + URL-safe alphabets, with and without
/// padding — covers every conformant encoding variant.
pub(super) fn try_decode_through_scan(input: &str) -> Option<(&'static str, String, u8)> {
    decode_through_inner(input.trim(), 0)
}

pub(super) fn decode_through_inner(input: &str, depth: u8) -> Option<(&'static str, String, u8)> {
    use base64::Engine as _;
    if depth >= BASE64_DECODE_MAX_DEPTH {
        return None;
    }
    if !looks_like_base64(input) {
        return None;
    }
    // Padding state determines which engine succeeds. Try each in
    // sequence — they're cheap and short-circuit on first valid
    // decode. URL-safe alphabet is a strict superset of the chars
    // we admit, so the standard engine's first attempt covers
    // 99%+ of stealer-log dumps; URL-safe is reserved for tokens
    // copied out of OAuth callback URLs.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input))
        .ok()?;
    // The decode-through pipeline only chases UTF-8 payloads. A
    // raw binary blob (compiled program, image, encrypted bytes)
    // isn't going to round-trip back through identify_api_key.
    let decoded_str = std::str::from_utf8(&decoded).ok()?;
    let trimmed = decoded_str.trim();
    if trimmed.len() < 16 {
        return None;
    }
    if let Some((svc, key_val)) = identify_api_key(trimmed) {
        return Some((svc, key_val.to_string(), depth + 1));
    }
    // Layered base64 — recurse once. Beyond depth 2 is
    // pathological and we cap to keep the worst-case bounded.
    decode_through_inner(trimmed, depth + 1)
}

/// Shannon entropy in bits per character. Empty input returns 0.
/// Used as a coarse randomness check — real credentials sit at
/// ≥ 3.5 bits/char on alphanumeric-and-symbol charsets; English
/// prose sits around 1.5–2.0; padding/placeholder strings sit
/// even lower.
pub(super) fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<char, u32>::new();
    let len = value.chars().count() as f64;
    for c in value.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let mut h = 0.0_f64;
    for &n in counts.values() {
        let p = f64::from(n) / len;
        h -= p * p.log2();
    }
    h
}

/// Multi-factor behavioural credential score in `0.0..=1.0`, combining
/// [`shannon_entropy`] (30%), length profile (15%), character composition
/// (25%), consecutive-character repetition (10%), and a common-word penalty
/// (5%) — the entropy-based fallback [`super::try_entropy_detect`]
/// reaches for when pattern matching finds nothing. `0.0` for anything under
/// 8 chars (too short to carry a meaningful entropy signal).
#[must_use]
pub(super) fn credential_likelihood(text: &str) -> f64 {
    if text.is_empty() || text.len() < 8 {
        return 0.0;
    }

    let mut score: f64 = 0.0;

    // 1. ENTROPY: 30% weight
    let entropy = shannon_entropy(text);
    let entropy_score = if entropy >= 5.0 {
        1.0 // High entropy (>5 bits/char)
    } else if entropy >= 4.5 {
        0.7 // Moderate-high entropy
    } else if entropy >= 4.0 {
        0.3 // Natural language level
    } else {
        0.0 // Low entropy (repetitive)
    };
    score += entropy_score * 0.30;

    // 2. LENGTH: 15% weight (credentials have characteristic lengths)
    let length_score = match text.len() {
        16..=20 => 1.0,   // AWS key length
        32..=64 => 0.9,   // Common API key
        8..=15 => 0.6,    // Short token
        65..=128 => 0.8,  // Long token
        129..=512 => 0.5, // Bearer token
        _ => 0.0,         // Unusual length
    };
    score += length_score * 0.15;

    // 3. CHARACTER COMPOSITION: 25% weight
    let alphanumeric_ratio =
        text.chars().filter(char::is_ascii_alphanumeric).count() as f64 / text.len() as f64;

    let special_chars = text
        .chars()
        .filter(|c| matches!(c, '-' | '_' | '.' | ':' | '/'))
        .count() as f64
        / text.len() as f64;

    let space_ratio = text.chars().filter(|c| c.is_whitespace()).count() as f64 / text.len() as f64;

    // Credentials: high alphanumeric, some special chars, no spaces
    let composition_score = match (alphanumeric_ratio, special_chars, space_ratio) {
        (_, _, s) if s > 0.1 => 0.0,  // Contains spaces (unlikely credential)
        (a, _, _) if a < 0.7 => 0.0,  // Too many unusual chars
        (a, _, _) if a >= 0.9 => 0.9, // Pure alphanumeric (good credential)
        (a, sp, _) if a >= 0.8 && sp > 0.05 => 0.8, // Good mix with separators
        (a, _, _) if a >= 0.8 => 0.7, // Good alphanumeric ratio
        _ => 0.3,
    };
    score += composition_score * 0.25;

    // 4. REPETITION: 10% weight (credentials avoid character repetition)
    let max_consecutive = text
        .chars()
        .fold((0, 0, ' '), |(max, current, last), c| {
            if c == last {
                (max.max(current + 1), current + 1, c)
            } else {
                (max, 1, c)
            }
        })
        .0;

    let repetition_score = match max_consecutive {
        0..=1 => 1.0, // No repetition (good)
        2 => 0.8,     // Single double char
        3 => 0.5,     // Triple char (suspicious)
        _ => 0.0,     // Heavy repetition (not a credential)
    };
    score += repetition_score * 0.10;

    // 5. DICTIONARY WORD CHECK: 5% weight (credentials shouldn't be dict words)
    let dict_score = if is_common_word(text) { 0.0 } else { 1.0 };
    score += dict_score * 0.05;

    score.min(1.0)
}

/// True if `text` is a common English word associated with credential
/// fields — a field NAME/LABEL leaking into the value position rather than
/// a real secret (e.g. a form echoing back `"password"` itself).
fn is_common_word(text: &str) -> bool {
    matches!(
        text.to_ascii_lowercase().as_str(),
        "password"
            | "secret"
            | "token"
            | "key"
            | "credential"
            | "api"
            | "private"
            | "public"
            | "username"
            | "admin"
            | "default"
            | "example"
    )
}
