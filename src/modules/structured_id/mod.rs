//! Free, **offline** intelligence decoded from structured identifiers.
//!
//! Some widely-used IDs embed metadata that the systems emitting them rarely
//! intend to leak. This module decodes it from the ID alone — no API, no key,
//! no network — extending the deterministic-decode pattern of
//! [`crate::modules::discord_snowflake`]:
//!
//! * **UUID version 1** carries the *generating machine's MAC address* (the
//!   node field) and the *generation timestamp*. A leaked v1 UUID therefore
//!   deanonymises the host that minted it — a genuine, well-known OSINT
//!   technique — and dates it. (A v1 UUID with the multicast bit set used a
//!   random node, not a real MAC, so that case yields a time but no MAC.)
//! * **MongoDB ObjectID** encodes its creation time in the leading 4 bytes, so
//!   a leaked ObjectID dates the record/account it identifies.
//! * **ULID** and **KSUID** (record IDs, tokens, request IDs) each embed a
//!   creation timestamp, so a leaked one dates whatever it identifies.
//!
//! These formats are unambiguous by shape (hyphenated 36-char UUID with a `1`
//! version nibble; bare 24-hex ObjectID; 26-char Crockford-base32 ULID; 27-char
//! base62 KSUID), so — unlike a bare decimal snowflake
//! — there is no platform ambiguity. Every decoded time is range-validated to
//! `[2000-01-01, now]` so a random hex/UUID-v4 string yields nothing rather than
//! a fabricated timestamp. No mock: the data is read straight out of the ID.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence, unix_now},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "structured_id";

/// 100-ns intervals between the UUID epoch (1582-10-15) and the Unix epoch.
const UUID_TICKS_BETWEEN_EPOCHS: u64 = 122_192_928_000_000_000;
/// Plausibility floor — 2000-01-01. A decode outside `[floor, now]` is rejected.
const PLAUSIBLE_FLOOR_SECS: i64 = 946_684_800;
const DAY_SECS: i64 = 86_400;

pub struct StructuredId;

#[async_trait]
impl Module for StructuredId {
    fn name(&self) -> &'static str {
        "structured_id"
    }

    fn description(&self) -> &'static str {
        "Offline structured-ID decode — unmasks UUIDv1 to MAC + time and MongoDB ObjectID to time"
    }

    fn priority(&self) -> u8 {
        103
    }

    fn is_passive(&self) -> bool {
        // Pure offline decoding — no network, no I/O, no key.
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        // UUIDs / ObjectIDs fall to the residual Username kind. Kind-only so the
        // dispatch index stays consistent; the format gate is in process().
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::MacAddress];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // The Social-category default (T1593.001 Social Media + T1589.003 Employee
        // Names) is wrong for both legs: this module does not search social media —
        // it decodes a structured ID OFFLINE — and emits no real-name `Person`. Its
        // signal is the generating machine's MAC address embedded in a UUIDv1: host
        // hardware identification, so it maps to T1592.001 (Gather Victim Host
        // Information: Hardware), not the inherited social-presence pair.
        &["T1592.001"]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let v = target.value.trim();
        let plausible =
            |secs: i64| (PLAUSIBLE_FLOOR_SECS..=unix_now() as i64 + DAY_SECS).contains(&secs);

        // UUID version 1 — generation time + (real) node MAC.
        if let Some((secs, mac)) = decode_uuid_v1(v)
            && plausible(secs)
        {
            let date = utc_date(secs);
            let mut e = target.to_entity(0.60, &ctx.scan_id);
            e.tag("uuid-v1");
            e.tag("derived");
            e.tag("account-age");
            let mut ev = Evidence::new(SRC, format!("UUIDv1 generated {date} (decoded offline)"))
                .with_attr("uuid_created_date", date.as_str())
                .with_attr("uuid_version", "1");
            if let Some(ref m) = mac {
                ev = ev.with_attr("uuid_node_mac", m.as_str());
            }
            e.add_evidence(ev);
            result.push(e);

            // The node MAC is a real device fingerprint — emit it first-class.
            if let Some(m) = mac {
                let mut me = Entity::new(EntityKind::MacAddress, &m, 0.70, &ctx.scan_id);
                me.tag("uuid-v1");
                me.tag("derived");
                me.add_evidence(
                    Evidence::new(SRC, format!("Node MAC embedded in UUIDv1 `{v}`"))
                        .with_attr("source_uuid", v),
                );
                result.push(me);
            }
            return Ok(result);
        }

        // Other timestamp-embedding IDs, each unambiguous by shape: MongoDB
        // ObjectID, ULID, and KSUID all carry their own creation time.
        for (decode, tag, attr, label) in [
            (
                decode_objectid as fn(&str) -> Option<i64>,
                "mongodb-objectid",
                "objectid_created_date",
                "MongoDB ObjectID",
            ),
            (decode_ulid, "ulid", "ulid_created_date", "ULID"),
            (decode_ksuid, "ksuid", "ksuid_created_date", "KSUID"),
        ] {
            if let Some(secs) = decode(v)
                && plausible(secs)
            {
                emit_creation(target, &ctx.scan_id, tag, attr, label, secs, &mut result);
                break;
            }
        }

        Ok(result)
    }
}

/// Decode a version-1 UUID into `(unix_seconds, Some(mac) if a real node MAC)`.
/// `None` for any string that isn't a syntactically valid v1 UUID.
fn decode_uuid_v1(s: &str) -> Option<(i64, Option<String>)> {
    let b = s.as_bytes();
    if b.len() != 36 || b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return None;
    }
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // Version nibble (13th hex digit) must be `1`.
    if hex.as_bytes()[12] != b'1' {
        return None;
    }
    let time_low = u64::from_str_radix(&hex[0..8], 16).ok()?;
    let time_mid = u64::from_str_radix(&hex[8..12], 16).ok()?;
    let time_hi = u64::from_str_radix(&hex[12..16], 16).ok()? & 0x0FFF;
    let ticks = (time_hi << 48) | (time_mid << 32) | time_low;
    let unix_secs = (ticks.checked_sub(UUID_TICKS_BETWEEN_EPOCHS)? / 10_000_000) as i64;

    let node = &hex[20..32];
    let first_octet = u8::from_str_radix(&node[0..2], 16).ok()?;
    // The multicast/locally-administered bit (bit 0 of the first octet) is set
    // when the node is random, not a hardware MAC — so only a unicast node is a
    // real device address.
    let mac = (first_octet & 0x01 == 0).then(|| {
        format!(
            "{}:{}:{}:{}:{}:{}",
            &node[0..2],
            &node[2..4],
            &node[4..6],
            &node[6..8],
            &node[8..10],
            &node[10..12]
        )
    });
    Some((unix_secs, mac))
}

/// Decode a MongoDB ObjectID's creation time (its leading 4 bytes are a
/// big-endian Unix-seconds timestamp). `None` if `s` isn't a 24-hex ObjectID.
fn decode_objectid(s: &str) -> Option<i64> {
    if s.len() != 24 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    i64::from_str_radix(&s[0..8], 16).ok()
}

/// Crockford base32 alphabet (no `I`, `L`, `O`, `U`) — the ULID encoding.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Base62 alphabet — the KSUID encoding.
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// KSUID epoch (2014-05-13T16:53:20Z) as a Unix-seconds offset.
const KSUID_EPOCH_SECS: i64 = 1_400_000_000;

/// One Crockford base32 digit → value (case-insensitive; the ambiguous letters
/// `I`/`L` map to 1 and `O` to 0 per the spec). `None` for a non-base32 char.
fn crockford_val(c: u8) -> Option<u64> {
    match c.to_ascii_uppercase() {
        b'O' => Some(0),
        b'I' | b'L' => Some(1),
        u => CROCKFORD.iter().position(|&x| x == u).map(|p| p as u64),
    }
}

/// Decode a ULID's creation time. A ULID is 26 Crockford-base32 chars whose
/// leading 10 chars encode a 48-bit millisecond timestamp. `None` if `s` is not
/// a 26-char all-base32 ULID (so a random/non-ULID string is rejected).
fn decode_ulid(s: &str) -> Option<i64> {
    if s.len() != 26 {
        return None;
    }
    let mut ms: u64 = 0;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        let v = crockford_val(b)?;
        if i < 10 {
            ms = (ms << 5) | v;
        }
    }
    Some(((ms & 0xFFFF_FFFF_FFFF) / 1000) as i64)
}

/// Decode a KSUID's creation time. A KSUID is 27 base62 chars decoding to a
/// 20-byte value whose leading 4 bytes are a big-endian seconds offset from the
/// KSUID epoch. `None` if `s` is not a valid 27-char base62 KSUID.
fn decode_ksuid(s: &str) -> Option<i64> {
    if s.len() != 27 {
        return None;
    }
    // base62-decode into a 20-byte big-endian bignum.
    let mut bytes = [0u8; 20];
    for &c in s.as_bytes() {
        let mut carry = BASE62.iter().position(|&x| x == c)? as u32;
        for b in bytes.iter_mut().rev() {
            let acc = u32::from(*b) * 62 + carry;
            *b = (acc & 0xFF) as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return None; // overflows 20 bytes — not a KSUID
        }
    }
    let ts = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Some(i64::from(ts) + KSUID_EPOCH_SECS)
}

/// Enrich the seed ID with its decoded creation date — shared by the
/// ObjectID / ULID / KSUID timestamp-only decoders.
fn emit_creation(
    target: &Target,
    scan_id: &str,
    tag: &str,
    date_attr: &str,
    label: &str,
    secs: i64,
    result: &mut ModuleResult,
) {
    let date = utc_date(secs);
    let mut e = target.to_entity(0.55, scan_id);
    e.tag(tag);
    e.tag("derived");
    e.tag("account-age");
    e.add_evidence(
        Evidence::new(SRC, format!("{label} created {date} (decoded offline)"))
            .with_attr(date_attr, date.as_str())
            .with_attr("decoder", tag),
    );
    result.push(e);
}

/// UTC `YYYY-MM-DD` from Unix seconds — Hinnant's `civil_from_days`. Pure,
/// dependency-free, deterministic.
fn utc_date(ts: i64) -> String {
    let z = ts.div_euclid(DAY_SECS) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
