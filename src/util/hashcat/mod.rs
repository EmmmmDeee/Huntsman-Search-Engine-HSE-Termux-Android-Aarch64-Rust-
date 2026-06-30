//! Offline hash intelligence — a "hashcat-lite" for Termux aarch64 (no GPU, no
//! network, no root). Three pure, synergistic enrichments of a raw breach-record
//! password hash:
//!
//! 1. [`identify_hash`] classifies the digest's algorithm and crackability — a
//!    fast unsalted MD5/SHA-family digest (≈ plaintext once cracked) versus a slow
//!    adaptive KDF (bcrypt / argon2 / scrypt / *crypt). [`is_salted`] flags a
//!    digest carrying an appended salt (rainbow tables don't apply). This ranks a
//!    subject's credential exposure without touching the secret.
//!
//! 2. [`crack_common`] resolves a fast unsalted digest to its plaintext when — and
//!    only when — it is the MD5 / SHA-1 / SHA-256 / SHA-512 of one of the most
//!    common passwords, via an offline reverse-lookup table built once at first
//!    use. No cracking happens at scan time beyond a hash-map probe, and only
//!    already-public weak passwords resolve; a salted or strong hash returns
//!    `None`.
//!
//! 3. [`is_common_collision`] is the *noise-reduction* corollary: a hash whose
//!    plaintext is a common password is a POOR identity-linking key — the same
//!    `md5("password")` recurs for countless unrelated people — so the credential
//!    correlator skips linking on it. Hash intelligence here removes false links,
//!    not just adds data.
//!
//! Conceptually this is MITRE ATT&CK **T1110.002 (Password Cracking)** applied to a
//! reconnaissance goal (**T1589.001**, Gather Victim Identity Information:
//! Credentials) — entirely offline and deterministic. Pure; no I/O.

use std::collections::HashMap;
use std::sync::LazyLock;

// One shared `digest::Digest` (re-exported by md-5 / sha1 / sha2 0.11) backs all
// four algorithms, so a single import drives every `D::digest` call below.
use sha2::Digest;

/// Classify a password hash by `(algorithm, fast_to_crack)`. `fast` ⇒ an unsalted
/// MD5/SHA-family digest that falls to a GPU/rainbow attack ≈ instantly; `false`
/// ⇒ a deliberately-slow adaptive KDF. `None` when `s` is not a recognised hash.
///
/// The single definition every breach provider shares (OathNet's classifier
/// delegates here), so the algorithm/crackability semantics can't drift.
#[must_use]
pub fn identify_hash(s: &str) -> Option<(&'static str, bool)> {
    let h = s.trim();
    // Adaptive / salted KDF + crypt(3) formats — slow to crack by design.
    for (prefix, algo) in [
        ("$2a$", "bcrypt"),
        ("$2b$", "bcrypt"),
        ("$2y$", "bcrypt"),
        ("$2x$", "bcrypt"),
        ("$argon2", "argon2"),
        ("$6$", "sha512crypt"),
        ("$5$", "sha256crypt"),
        ("$1$", "md5crypt"),
        ("$P$", "phpass"),
        ("$H$", "phpass"),
        ("$7$", "scrypt"),
        ("$scrypt$", "scrypt"),
        ("$pbkdf2", "pbkdf2"),
        ("pbkdf2_", "pbkdf2"),
    ] {
        if h.starts_with(prefix) {
            return Some((algo, false));
        }
    }
    // MySQL 4.1+: `*` followed by 40 hex — a fast SHA1(SHA1(pw)).
    if let Some(rest) = h.strip_prefix('*')
        && rest.len() == 40
        && rest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Some(("mysql", true));
    }
    // Bare hex digest, optionally with an appended salt: classify by the LEADING
    // hex run's length so a packed `"<digest> <salt>"` / `"<digest>:<salt>"` form
    // still resolves; the remainder, if any, must begin at a separator so a token
    // that merely starts with hex isn't misread as a digest.
    let hex_len = h.bytes().take_while(u8::is_ascii_hexdigit).count();
    if hex_len > 0 {
        let rest = &h[hex_len..];
        if rest.is_empty() || rest.starts_with([' ', '\t', ':', ',', ';', '|']) {
            return match hex_len {
                32 => Some(("md5", true)),
                40 => Some(("sha1", true)),
                56 => Some(("sha224", true)),
                64 => Some(("sha256", true)),
                96 => Some(("sha384", true)),
                128 => Some(("sha512", true)),
                _ => None,
            };
        }
    }
    None
}

/// Whether `s` is a bare hex digest carrying an APPENDED salt (`"<hex> <salt>"`,
/// `"<hex>:<salt>"`, …). A salt defeats rainbow tables even for a fast hash, so
/// such a digest can't be reverse-looked-up. A prefixed KDF (`$2a$…`) carries its
/// own salt and is already classified slow, so it is not the concern here.
#[must_use]
pub fn is_salted(s: &str) -> bool {
    let h = s.trim();
    h.starts_with(|c: char| c.is_ascii_hexdigit())
        && h.split_once([' ', '\t', ':', ',', ';', '|'])
            .is_some_and(|(digest, rest)| {
                digest.bytes().all(|b| b.is_ascii_hexdigit()) && !rest.trim().is_empty()
            })
}

/// The plaintext of `hash` when it is the unsalted MD5 / SHA-1 / SHA-256 / SHA-512
/// digest of one of the [`COMMON_PASSWORDS`], else `None`. Offline: a single probe
/// of a reverse-lookup table precomputed once at first use. Only the LEADING hex
/// run is considered (so a `"<digest> <salt>"` form is handled — a genuinely
/// salted digest simply won't be in the table). Strong, salted, or unknown hashes
/// return `None`. No network, no GPU.
#[must_use]
pub fn crack_common(hash: &str) -> Option<&'static str> {
    let h = hash.trim();
    let hex_len = h.bytes().take_while(u8::is_ascii_hexdigit).count();
    if !matches!(hex_len, 32 | 40 | 64 | 128) {
        return None;
    }
    let digest = h[..hex_len].to_ascii_lowercase();
    RAINBOW.get(digest.as_str()).copied()
}

/// Whether `hash`'s plaintext is a known common (weak, high-collision) password —
/// i.e. [`crack_common`] resolves it. Such a hash is a POOR identity-linking key:
/// the same `md5("password")` recurs for countless unrelated people, so a
/// correlator must NOT treat sharing it as an identity link.
#[must_use]
pub fn is_common_collision(hash: &str) -> bool {
    crack_common(hash).is_some()
}

fn md5_hex(s: &str) -> String {
    hex::encode(md5::Md5::digest(s.as_bytes()))
}
fn sha1_hex(s: &str) -> String {
    hex::encode(sha1::Sha1::digest(s.as_bytes()))
}
fn sha256_hex(s: &str) -> String {
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}
fn sha512_hex(s: &str) -> String {
    hex::encode(sha2::Sha512::digest(s.as_bytes()))
}

/// Reverse-lookup table: lower-hex digest → the common password that produced it.
/// Built once from [`COMMON_PASSWORDS`] across the four fast unsalted algorithms a
/// breach dump stores in the clear (≈ `4 × COMMON_PASSWORDS.len()` entries).
static RAINBOW: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::with_capacity(COMMON_PASSWORDS.len() * 4);
    for &pw in COMMON_PASSWORDS {
        for digest in [md5_hex(pw), sha1_hex(pw), sha256_hex(pw), sha512_hex(pw)] {
            m.entry(digest).or_insert(pw);
        }
    }
    m
});

/// The most common breach passwords (public knowledge — the perennial tops of
/// rockyou / SecLists / annual "worst passwords" lists). Kept small and
/// high-precision: these resolve the trivially-weak unsalted hashes that dominate
/// old dumps, without bloating the binary. Lower-cased and de-duplicated.
pub const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "696969",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "121212",
    "000000",
    "qazwsx",
    "123qwe",
    "killer",
    "trustno1",
    "jordan",
    "jennifer",
    "zxcvbnm",
    "asdfgh",
    "hunter",
    "buster",
    "soccer",
    "harley",
    "batman",
    "andrew",
    "tigger",
    "sunshine",
    "iloveyou",
    "2000",
    "charlie",
    "robert",
    "thomas",
    "hockey",
    "ranger",
    "daniel",
    "starwars",
    "klaster",
    "112233",
    "george",
    "computer",
    "michelle",
    "jessica",
    "pepper",
    "1111",
    "zxcvbn",
    "555555",
    "11111111",
    "131313",
    "freedom",
    "777777",
    "pass",
    "maggie",
    "159753",
    "aaaaaa",
    "ginger",
    "princess",
    "joshua",
    "cheese",
    "amanda",
    "summer",
    "love",
    "ashley",
    "nicole",
    "chelsea",
    "biteme",
    "matthew",
    "access",
    "yankees",
    "987654321",
    "dallas",
    "austin",
    "thunder",
    "taylor",
    "matrix",
    "mobilemail",
    "monitor",
    "hannah",
    "anthony",
    "hello",
    "whatever",
    "money",
    "naruto",
    "test",
    "password1",
    "password123",
    "abcdef",
    "abcd1234",
    "qwerty123",
    "1q2w3e4r",
    "admin",
    "welcome",
    "login",
    "passw0rd",
    "p@ssw0rd",
    "secret",
    "google",
    "samsung",
    "internet",
    "service",
    "fuckyou",
    "fuckme",
    "asshole",
    "liverpool",
    "arsenal",
    "chelsea123",
    "abc12345",
    "qwe123",
    "qwerty1",
    "123abc",
    "a123456",
    "1q2w3e",
    "qweasd",
    "asdf1234",
    "loveme",
    "flower",
    "diamond",
    "freddy",
    "snoopy",
    "boomer",
    "cookie",
    "ncc1701",
    "victoria",
    "midnight",
    "scooter",
    "happy",
    "spider",
    "ferrari",
    "porsche",
    "corvette",
    "blink182",
    "metallica",
    "guitar",
    "rangers",
    "edward",
    "william",
    "samantha",
    "nathan",
    "raiders",
    "steelers",
    "cowboys",
    "lakers",
    "1234qwer",
    "q1w2e3r4",
    "zaq12wsx",
    "asdfasdf",
    "qwertyui",
    "11223344",
    "555666",
    "147258369",
    "987654",
    "789456123",
    "159357",
    "00000000",
    "12121212",
    "samuel",
    "andrea",
    "joseph",
    "patrick",
    "robert1",
    "michael1",
    "loveyou",
    "forever",
    "angel",
    "iloveu",
    "kitten",
    "purple",
    "orange",
    "rainbow",
];

#[cfg(test)]
mod tests;
