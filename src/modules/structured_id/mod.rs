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
//!
//! Both formats are unambiguous by shape (hyphenated 36-char UUID with a `1`
//! version nibble; bare 24-hex ObjectID), so — unlike a bare decimal snowflake
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
        "Offline decode of structured IDs (UUIDv1 → MAC + time, MongoDB ObjectID → time)"
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

        // MongoDB ObjectID — record creation time.
        if let Some(secs) = decode_objectid(v)
            && plausible(secs)
        {
            let date = utc_date(secs);
            let mut e = target.to_entity(0.55, &ctx.scan_id);
            e.tag("mongodb-objectid");
            e.tag("derived");
            e.tag("account-age");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("MongoDB ObjectID created {date} (decoded offline)"),
                )
                .with_attr("objectid_created_date", date.as_str())
                .with_attr("source", "objectid-decode"),
            );
            result.push(e);
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
