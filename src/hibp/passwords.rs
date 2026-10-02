//! Legacy SHA-1 / NTLM hashing for HIBP range lookup only, never for password storage.

use super::error::HibpError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordHashMode {
    Sha1,
    Ntlm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeEntry {
    pub suffix: String,
    pub count: u64,
}

/// Reject malformed ranges rather than interpreting corrupt data as absence.
pub fn parse_range(
    body: &[u8],
    mode: PasswordHashMode,
    drop_padding: bool,
) -> Result<Vec<RangeEntry>, HibpError> {
    let invalid = || HibpError::Decode("invalid password range".into());
    let text = std::str::from_utf8(body).map_err(|_| invalid())?;
    let length = match mode {
        PasswordHashMode::Sha1 => 35,
        PasswordHashMode::Ntlm => 27,
    };
    let mut entries = Vec::new();
    for line in text.lines() {
        let (suffix, count) = line.trim().split_once(':').ok_or_else(invalid)?;
        if suffix.len() != length || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        let count = count.parse().map_err(|_| invalid())?;
        if count != 0 || !drop_padding {
            entries.push(RangeEntry {
                suffix: suffix.to_ascii_uppercase(),
                count,
            });
        }
    }
    if text.is_empty() {
        return Err(invalid());
    }
    Ok(entries)
}

pub fn hash_password(password: &str, mode: PasswordHashMode) -> String {
    match mode {
        PasswordHashMode::Sha1 => sha1_hex(password.as_bytes()),
        PasswordHashMode::Ntlm => {
            let bytes: Vec<_> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
            hex(&super::md4::md4(&bytes))
        }
    }
}

#[must_use]
pub fn count_for(entries: &[RangeEntry], suffix: &str) -> u64 {
    entries
        .iter()
        .find(|entry| entry.suffix.eq_ignore_ascii_case(suffix))
        .map_or(0, |entry| entry.count)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

// FIPS 180-4 SHA-1, required by HIBP's protocol (not a security primitive here).
#[allow(clippy::many_single_char_names)] // FIPS register and round names.
pub(super) fn sha1_hex(data: &[u8]) -> String {
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(data.len() as u64).wrapping_mul(8).to_be_bytes());
    let mut state = [
        0x6745_2301_u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for block in message.chunks_exact(64) {
        let mut words = [0_u32; 80];
        for (i, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("four-byte word"));
        }
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, word) in words.into_iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (s, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(value);
        }
    }
    hex(&state
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>())
}
