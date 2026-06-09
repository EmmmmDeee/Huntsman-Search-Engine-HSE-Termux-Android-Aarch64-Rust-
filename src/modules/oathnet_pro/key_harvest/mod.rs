use serde_json::Value;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::util::oathnet::val_str;

use super::SRC;

mod patterns;
mod service_domains;
use patterns::KEY_PATTERNS;
use service_domains::identify_service_from_url;

/// Public, serializable view of one entry in the `KEY_PATTERNS` table.
/// Exposed by `pattern_catalogue()` so the HTTP API can surface the
/// detector's coverage at `/api/v1/keys/patterns`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PatternEntry {
    pub prefix: &'static str,
    pub service: &'static str,
    pub min_len: usize,
}

/// Snapshot of the prefix-match table that drives `identify_api_key`.
/// Returns one entry per declared pattern in declaration order
/// (specific-before-generic), so callers can reason about override
/// priority. ~167 entries today; cheap to build (no allocations beyond
/// the Vec).
pub fn pattern_catalogue() -> Vec<PatternEntry> {
    KEY_PATTERNS
        .iter()
        .map(|p| PatternEntry {
            prefix: p.prefix,
            service: p.service,
            min_len: p.min_len,
        })
        .collect()
}

/// High-confidence, CHEAP key identification: recognised **vendor prefixes**,
/// **PEM** private-key blocks, and **crypto** addresses only. Deliberately
/// excludes the generic-hex / URL-param / `user:pass` heuristics.
///
/// For a token that matches none of these the cost is just prefix comparisons —
/// no Shannon-entropy pass, no lowercase allocation. That matters because the
/// universal response scanner (`util::found_keys`) runs key identification on
/// EVERY response body across every module: profiling showed the full
/// [`identify_api_key`] at ~2.8 MB/s, dominated by `is_likely_real_key`
/// (entropy + context exclusion) firing on every 32/64-char hex token — and
/// breach corpora are *full* of hex password hashes. Those hashes are already
/// captured as `Password` entities by the breach modules, so re-deriving them
/// here as "generic-hex API keys" was both slow and noisy. This function keeps
/// the universal scan fast and precise (real vendor keys only).
#[must_use]
pub fn identify_vendor_api_key(value: &str) -> Option<(&'static str, &str)> {
    let trimmed = value.trim();
    if trimmed.len() < 16 {
        return None;
    }
    // False-positive gate (entropy + context exclusion + UUID suppression) runs
    // only on an actual prefix MATCH — rare, so the common no-match token pays
    // nothing for it.
    for pat in KEY_PATTERNS {
        if trimmed.starts_with(pat.prefix) && trimmed.len() >= pat.min_len {
            if !is_likely_real_key(trimmed) {
                return None;
            }
            return Some((pat.service, trimmed));
        }
    }
    // PEM private-key blocks (id_rsa / id_ed25519 / OpenVPN configs in stealer
    // logs). Multi-line; checked separately from the single-token prefix table.
    if let Some(service) = identify_pem_private_key(trimmed) {
        return Some((service, trimmed));
    }
    // Cryptocurrency wallet addresses (clipboard-hijacker stealer logs carry
    // these in volume; lookup modules pivot from the emitted entities).
    if let Some(service) = identify_crypto_address(trimmed) {
        return Some((service, trimmed));
    }
    None
}

pub fn identify_api_key(value: &str) -> Option<(&'static str, &str)> {
    let trimmed = value.trim();
    if trimmed.len() < 16 {
        return None;
    }
    // High-confidence structured forms first (vendor prefix / PEM / crypto).
    if let Some(hit) = identify_vendor_api_key(trimmed) {
        return Some(hit);
    }
    // Generic hex key detection (32 or 64 char hex = potential API key). The
    // entropy/exclusion gate below is the expensive path — see
    // [`identify_vendor_api_key`] for why the universal scanner skips it.
    if (trimmed.len() == 32 || trimmed.len() == 64)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        if !is_likely_real_key(trimmed) {
            return None;
        }
        return Some(("generic_hex", trimmed));
    }

    // URL-embedded key extraction: ?key=VALUE, ?api_key=VALUE, ?token=VALUE
    for param in [
        "key=",
        "api_key=",
        "apikey=",
        "token=",
        "access_token=",
        "secret=",
    ] {
        if let Some(pos) = trimmed.find(param) {
            let start = pos + param.len();
            let rest = &trimmed[start..];
            let end = rest.find(['&', ' ', '"']).unwrap_or(rest.len());
            // Hard-cap the extracted value length. Without this, a
            // malicious stealer-log record with `?key=` followed by
            // hundreds of MB of base64-with-no-`&`-terminator would
            // cascade through `contains_excluded_context` (full-string
            // lowercase allocation) and `shannon_entropy` (full-string
            // iteration) per item — a cheap DoS surface. 4 KiB is well
            // above any real-world API-key length (longest known is
            // GitLab's ~256 chars).
            let end = end.min(EXTRACTED_VALUE_MAX);
            // Snap to a char boundary: `rest` is untrusted stealer data, so a
            // multi-byte UTF-8 char straddling the 4 KiB cap would panic a raw
            // byte slice (caught by the dispatch guard, but it silently voids the
            // whole harvest for the scan).
            let val = crate::util::str_util::truncate_safe(rest, end);
            if val.len() >= 16 {
                if let Some(hit) = identify_api_key(val) {
                    return Some(hit);
                }
                if val.len() >= 20
                    && val
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Some(("url_param_key", val));
                }
            }
        }
    }

    // user:password format — extract the password portion
    if trimmed.contains(':') && !trimmed.starts_with("http") {
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2 && parts[1].len() >= 16 {
            // Same DoS cap as above — recurse on at most 4 KiB (char-boundary safe).
            let pw = crate::util::str_util::truncate_safe(parts[1], EXTRACTED_VALUE_MAX);
            if let Some(hit) = identify_api_key(pw) {
                return Some(hit);
            }
        }
    }
    None
}

/// Hard cap for the extracted `val` / `password` substring length
/// in [`identify_api_key`]'s URL-param and user:pass fallbacks.
/// Bounds the recursive cost on hostile or malformed inputs without
/// rejecting any plausible real-world credential (longest known
/// vendor key is ~256 chars; even base64-wrapped variants stay
/// well under 4 KiB).
const EXTRACTED_VALUE_MAX: usize = 4096;

/// Scan a JSON record for API key patterns in password / URL-param / extra
/// fields. Public so peer modules like `see_know` can use the same harvest
/// pipeline against their own response schemas.
pub fn extract_api_keys_from_item(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let fields = [
        // Core credential fields (breach + stealer common)
        "password",
        "password_hash",
        "pass",
        "pwd",
        "passwd",
        "hash",
        "api_key",
        "apikey",
        "key",
        "token",
        "secret",
        "access_key",
        "auth_token",
        "api_token",
        "credential",
        "private_key",
        "secret_key",
        "access_token",
        "refresh_token",
        "bearer",
        // Stealer-log-specific fields (RedLine / Vidar / Raccoon /
        // StealC dumps). Catches modern OAuth / PAT / Discord / app-
        // password tokens that don't land in the `password` field.
        "bearer_token",
        "client_secret",
        "oauth_token",
        "personal_access_token",
        "pat",
        "webhook_secret",
        "app_password",
        "discord_token",
        "telegram_session",
        "cookie",
        "session_token",
        "note",
        "notes",
        "app_data",
        // `.env` dumps from desktop file-grabbers — handled by the
        // multi-line parser below; included here so a single-line
        // env file still routes through the same scan.
        "env_content",
        "env",
        "dotenv",
    ];

    for field in &fields {
        if let Some(val) = val_str(item, field) {
            if let Some((service, key_val)) = identify_api_key(&val) {
                let db = val_str(item, "dbname").unwrap_or_default();
                let source = if db.is_empty() {
                    format!("{field} field")
                } else {
                    format!("breach ({db})")
                };
                emit_key(service, key_val, &source, scan_id, seen, result);
            }
            // Decode-through pass: same field, treat the value as
            // base64 of a key and recurse through `identify_api_key`.
            // Catches stealer-log entries that wrap the secret to
            // sneak it past lazy regex scanners, plus genuine
            // base64-encoded-credential field schemas.
            if let Some((service, decoded_key, depth)) = try_decode_through_scan(&val) {
                let pre = result.entities.len();
                let source = format!("{field} (base64-decoded, depth={depth})");
                emit_key(service, &decoded_key, &source, scan_id, seen, result);
                if result.entities.len() > pre
                    && let Some(last) = result.entities.last_mut()
                {
                    last.tag("via-base64");
                    last.tag(format!("base64_depth:{depth}"));
                }
            }
        }
    }

    // Multi-line `.env` parser — stealer logs commonly dump entire
    // `.env` files into a single string field. Split on newlines,
    // extract `KEY=VALUE` pairs, and scan each value through the
    // same `identify_api_key` pipeline.
    for env_field in ["env_content", "env", "dotenv", "note", "notes"] {
        if let Some(blob) = val_str(item, env_field)
            && blob.contains('\n')
        {
            for line in blob.lines() {
                let trimmed = line.trim().trim_start_matches("export ");
                if let Some((_, raw_val)) = trimmed.split_once('=') {
                    let val = raw_val
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim_matches('`');
                    if val.len() >= 16
                        && let Some((service, key_val)) = identify_api_key(val)
                    {
                        emit_key(service, key_val, "dotenv line", scan_id, seen, result);
                    }
                }
            }
        }
    }

    // Scan username field — some stealer logs store API keys as usernames
    if let Some(user) = val_str(item, "username")
        && let Some((service, key_val)) = identify_api_key(&user)
    {
        emit_key(service, key_val, "username field", scan_id, seen, result);
    }

    // Scan URL query parameters — stealer URLs often embed API keys:
    // https://api.shodan.io/host/1.1.1.1?key=ACTUAL_KEY
    for url_field in ["url", "url_str"] {
        if let Some(url) = val_str(item, url_field)
            && let Some(qmark) = url.find('?')
        {
            for param in url[qmark + 1..].split('&') {
                if let Some((_, pval)) = param.split_once('=')
                    && pval.len() >= 16
                    && let Some((service, key_val)) = identify_api_key(pval)
                {
                    emit_key(
                        service,
                        key_val,
                        "URL query parameter",
                        scan_id,
                        seen,
                        result,
                    );
                }
            }
        }
    }

    if let Some(extra) = item.get("extra").and_then(|v| v.as_object()) {
        for (_, eval) in extra {
            if let Some(s) = eval.as_str()
                && s.len() >= 16
                && let Some((service, key_val)) = identify_api_key(s)
            {
                emit_key(service, key_val, "extra field", scan_id, seen, result);
            }
        }
    }

    // Cookie arrays — stealer logs export browser cookies as
    // `[{ name, value, domain, expires, ... }, ...]`. Cookie values
    // sized like JWT / OAuth tokens get routed through the same
    // pipeline; the domain field gives us the service-tag context.
    if let Some(cookies) = item.get("cookies").and_then(|v| v.as_array()) {
        for cookie in cookies {
            let Some(obj) = cookie.as_object() else {
                continue;
            };
            let name = val_str(&Value::Object(obj.clone()), "name").unwrap_or_default();
            let Some(value) = val_str(&Value::Object(obj.clone()), "value") else {
                continue;
            };
            if value.len() < 16 {
                continue;
            }
            if let Some((service, key_val)) = identify_api_key(&value) {
                let source = if name.is_empty() {
                    "cookie".to_string()
                } else {
                    format!("cookie:{name}")
                };
                emit_key(service, key_val, &source, scan_id, seen, result);
            }
        }
    }
}

// ── False-positive filtering (APIKeyScanner port) ──────────────────────
//
// Three independent gates a candidate string must pass before
// `identify_api_key` considers it a real key:
//
//   1. **Context exclusion** — a substring (case-insensitive) from
//      [`CONTEXT_EXCLUSIONS`] anywhere in the string. Catches
//      `your_api_key_here`, `example_token_xxx`, `placeholder`,
//      and ~40 sibling patterns from APIKeyScanner.
//   2. **UUID suppression** — strict 8-4-4-4-12 hex layout rejects
//      formatted GUIDs that otherwise look credential-like.
//   3. **Shannon entropy** — threshold 3.5 bits/char rejects
//      strings whose character distribution is too regular to be
//      a high-randomness secret.
//
// The gate is OPT-IN-OUT: if any of the three trips, the candidate
// is dropped. Real keys (high entropy, no context flags, not a
// UUID) sail through.

/// Substrings whose appearance anywhere in a candidate string
/// disqualifies it as a real key. Case-insensitive comparison.
/// Sourced from APIKeyScanner's 40+ exclusion list plus a handful
/// of empirical additions from HSE's breach corpus.
const CONTEXT_EXCLUSIONS: &[&str] = &[
    // Documentation placeholders
    "example",
    "your_",
    "your-",
    "yourkey",
    "yourtoken",
    "yoursecret",
    "yourapi",
    "placeholder",
    "dummy",
    "fake",
    "sample",
    "changeme",
    "todo",
    "xxxx",
    "test_key",
    "test-key",
    "test_token",
    "demo_key",
    "demo-key",
    // Documentation field names
    "public_key",
    "public_token",
    "api_version",
    "secret_name",
    "key_name",
    "token_name",
    "primary_key",
    "foreign_key",
    "schema_key",
    "sequence_key",
    "key_code",
    "key_alias",
    "key_id_name",
    // Common English-word collisions with key-like substrings
    "keyboard",
    "monkey",
    "donkey",
    "keystone",
    "keystore",
    "keyword",
    "keymap",
    "keypress",
    "keyup",
    "keydown",
    "tokenize",
    "tokenizer",
];

/// True if the candidate value is plausibly a real credential.
/// Wraps the three FP gates so callers stay clean.
fn is_likely_real_key(value: &str) -> bool {
    !contains_excluded_context(value) && !is_uuid(value) && shannon_entropy(value) >= 3.5
}

/// True if `value` contains any [`CONTEXT_EXCLUSIONS`] substring
/// (case-insensitive). The lowercased comparison string is built
/// once per call to keep the inner loop hot.
fn contains_excluded_context(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    CONTEXT_EXCLUSIONS.iter().any(|pat| lower.contains(pat))
}

/// True if `value` matches the canonical UUID v1-v5 layout
/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (8-4-4-4-12 hex,
/// 36 chars total including the four dashes). UUIDs are
/// suppressed by default because they collide with several
/// vendor key formats (Heroku, Pinecone, etc.) without being
/// real credentials — the vendor-specific prefix check is
/// where those should land.
fn is_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && value
            .chars()
            .filter(|c| *c != '-')
            .all(|c| c.is_ascii_hexdigit())
}

// ── PEM private-key block classifier (KeyFinder port) ─────────────
//
// Stealer logs that dump `id_rsa`, `id_ed25519`, OpenVPN configs,
// PGP keychains, or Bitcoin wallet WIF backups deliver these
// verbatim into the `app_data` / `notes` / `extras` payloads.
// Detection is shape-anchored on the BEGIN header — strict enough
// that a base64 blob in the body alone won't false-positive.

/// Try to classify `s` as a PEM-encoded private-key block. Returns
/// `Some(service_tag)` when the BEGIN header matches a known class.
/// The trailing block (`-----END ... PRIVATE KEY-----`) is not
/// required — partial-paste in stealer dumps is common, and the
/// header alone is high-signal.
fn identify_pem_private_key(s: &str) -> Option<&'static str> {
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

/// True if `c` is a Base58 character (Bitcoin-style; excludes
/// Try to classify a string as a cryptocurrency wallet address. Delegates to
/// the canonical, shared classifier in `core::crypto` (the same one the target
/// auto-detector uses) so the shape rules live in exactly one place.
fn identify_crypto_address(s: &str) -> Option<&'static str> {
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

const BASE64_DECODE_MAX_DEPTH: u8 = 2;
const BASE64_MIN_ENCODED_LEN: usize = 24;
const BASE64_MAX_ENCODED_LEN: usize = 8192;

/// Cheap pre-check before attempting base64 decode. Filters obvious
/// non-candidates (too short, too long, contains chars outside the
/// unified standard + URL-safe alphabet) so the hot path doesn't
/// run `base64::decode` against every harvested field.
fn looks_like_base64(s: &str) -> bool {
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
fn try_decode_through_scan(input: &str) -> Option<(&'static str, String, u8)> {
    decode_through_inner(input.trim(), 0)
}

fn decode_through_inner(input: &str, depth: u8) -> Option<(&'static str, String, u8)> {
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
fn shannon_entropy(value: &str) -> f64 {
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

fn emit_key(
    service: &'static str,
    key_val: &str,
    source: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // A cryptocurrency wallet address is NOT an API key — `identify_*` groups
    // it here only because both are high-entropy tokens. Emit it as a
    // first-class CryptoAddress (chain-tagged) and skip the API-key/ROI/key-pool
    // machinery entirely: it can't authenticate anything.
    if let Some(chain) = service.strip_prefix("crypto_") {
        if seen.insert(format!("@crypto:{key_val}")) {
            let mut e = Entity::new(EntityKind::CryptoAddress, key_val, 0.80, scan_id);
            e.tag("crypto-address");
            e.tag(format!("chain:{chain}"));
            e.add_evidence(
                Evidence::new(SRC, format!("{chain} wallet address from {source}"))
                    .with_attr("chain", chain),
            );
            result.push(e);
        }
        return;
    }
    let dedup = format!(
        "@apikey:{service}:{}",
        crate::util::str_util::truncate_safe(key_val, 16)
    );
    if !seen.insert(dedup) {
        return;
    }
    let mut entity = Entity::new(EntityKind::ApiKey, key_val, 0.80, scan_id);
    entity.tag("api-key");
    entity.tag(format!("service:{service}"));
    entity.tag("oathnet-pro");
    entity.tag("auto-discovered");
    // Tag with ROI tier so operators can prioritise multiplier keys.
    // Multiplier-tier keys discover infrastructure/identities that
    // cascade into MORE keys via web_crawler and search_engines.
    let roi = crate::util::key_roi::classify(service);
    entity.tag(format!("roi:{}", roi.label()));
    if roi == crate::util::key_roi::KeyRoi::Multiplier {
        entity.tag("force-multiplier");
    }
    entity.add_evidence(
        Evidence::new(SRC, format!("API key ({service}) from {source}"))
            .with_attr("service", service)
            .with_attr("roi_tier", roi.label())
            .with_attr(
                "key_prefix",
                crate::util::str_util::truncate_safe(key_val, 8),
            )
            .with_attr("key_length", key_val.len().to_string()),
    );
    result.push(entity);

    // Skip the global key-pool side-effect when called from unit
    // tests. The pool is persisted to `~/.huntsman/key_pool.json`,
    // so unconditionally writing in tests pollutes state across
    // test binaries (`cargo test` runs each crate in its own
    // process, but the on-disk pool is shared). Conservatively
    // gate on a scan_id `"test"` / `"scan"` prefix — both used by
    // the test orchestrators in this module and the smoke crate.
    if scan_id == "test" || scan_id.starts_with("test-") || scan_id == "scan" {
        return;
    }

    let pool = crate::util::key_pool::global_pool();
    let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
    entry.notes = Some(format!(
        "Auto-discovered {service} key from {source} ({} tier)",
        roi.label()
    ));
    pool.add(service, entry);
    crate::util::key_pool::save_pool_best_effort(&pool);
}

pub fn store_api_credential_from_item(item: &Value) {
    store_api_credential(item);
}

/// Same as `store_api_credential_from_item` but pub for peer-module use.
/// Routes a stealer/breach record to the key pool when the URL matches
/// a known service domain.
pub fn store_api_credential(item: &Value) {
    let url = val_str(item, "url")
        .or_else(|| val_str(item, "url_str"))
        .or_else(|| val_str(item, "domain"))
        .unwrap_or_default();
    let username = val_str(item, "username")
        .or_else(|| val_str(item, "email"))
        .or_else(|| val_str(item, "login"))
        .unwrap_or_default();
    let password = val_str(item, "password")
        .or_else(|| val_str(item, "pass"))
        .or_else(|| val_str(item, "pwd"))
        .or_else(|| val_str(item, "passwd"))
        .or_else(|| val_str(item, "credential"))
        .or_else(|| val_str(item, "api_key"))
        .or_else(|| val_str(item, "token"))
        .or_else(|| val_str(item, "secret"))
        .unwrap_or_default();

    if password.is_empty() || password.contains("***") || password.contains("UPGRADE") {
        return;
    }

    let service = if !url.is_empty() {
        let svc = identify_service_from_url(&url);
        if svc != "unknown" {
            svc
        } else {
            return;
        }
    } else if !username.is_empty() && username.contains('@') {
        let domain = username.split('@').nth(1).unwrap_or("");
        let svc = identify_service_from_url(domain);
        if svc != "unknown" {
            svc
        } else {
            return;
        }
    } else {
        return;
    };

    let pool = crate::util::key_pool::global_pool();

    let mut entry = crate::util::key_pool::KeyEntry::new(&password);
    entry.notes = Some(format!(
        "OathNet stealer: user={} url={}",
        &crate::util::str_util::truncate_safe(&username, 30),
        &crate::util::str_util::truncate_safe(&url, 60)
    ));
    if pool.add(service, entry) {
        crate::util::key_pool::save_pool_best_effort(&pool);
    }

    let user_entry = crate::util::key_pool::KeyEntry::new(format!("{username}:{password}"));
    pool.add(&format!("{service}_login"), user_entry);
    crate::util::key_pool::save_pool_best_effort(&pool);
}

#[cfg(test)]
mod tests;
