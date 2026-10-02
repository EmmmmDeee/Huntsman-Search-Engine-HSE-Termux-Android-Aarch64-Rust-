//! Free, **offline** Discord account-age intelligence from a snowflake ID.
//!
//! A Discord ID (a "snowflake") deterministically encodes the account's
//! creation time in its high bits: `created_ms = (id >> 22) + DISCORD_EPOCH`.
//! So an account's creation date — a genuine OSINT / fraud-trust signal
//! (account age is a first-class new-account-risk indicator) — is derivable
//! from the **ID alone**, with no API, no key, and no network. This is the
//! free, offline emulation of the creation-date half of SeekNow's paid
//! `discord/user` endpoint. No mock: the timestamp is read straight out of the
//! ID's bit layout.
//!
//! ## Only an explicitly-Discord value is decoded
//!
//! The decode needs an ID that is *known* to be Discord's, because the
//! snowflake layout is not Discord's invention and not Discord's alone:
//! Twitter/X, Instagram, Mastodon and others issue 64-bit IDs with the **same**
//! `timestamp << 22 | worker | sequence` shape. Only the epoch constant
//! differs, and the epoch is not recoverable from the number — so decoding a
//! foreign snowflake with Discord's epoch does not fail, it silently returns a
//! **wrong date that still looks right**.
//!
//! Measured, for Twitter/X (epoch 2010-11-04, `1288834974657`): reading one of
//! its IDs with Discord's epoch shifts the answer by a fixed
//! `DISCORD_EPOCH − TWITTER_EPOCH` = **+1518.93 days** (≈4.16 years). Every
//! Twitter/X ID issued between **2010-11-04 and 2022-07-24** therefore decodes
//! into the `[2015-01-01, now]` plausibility window below — 17–20 digits, no
//! leading zero, dead inside range:
//!
//! | tweet date | digits | decoded as "created" |
//! |---|---|---|
//! | 2011-01-01 | 17 | 2015-02-27 |
//! | 2013-06-01 | 18 | 2017-07-28 |
//! | 2016-06-01 | 18 | 2020-07-28 |
//! | 2019-06-01 | 19 | 2023-07-28 |
//! | 2022-07-01 | 19 | 2026-08-27 |
//!
//! That is the bulk of Twitter/X's snowflake era, and a bare 17–20 digit run is
//! `TargetKind::Username` by `detect`'s fallback (too long for
//! `is_phone_shaped`'s 7–15 digits, no dot for `is_domain_shaped`), so
//! `hse scan 1542659245470646272` reached this module directly. No shape rule
//! can separate the two — the Steam ID64 carve-out this module used to carry
//! worked only because Steam's `7656119…` is a literal constant prefix, and
//! Twitter/X has no equivalent to exclude on.
//!
//! So the value must **arrive already identified as Discord's**: this module
//! decodes `discord:<snowflake>` and nothing else. That prefix is minted by the
//! two extractors that read a breach/SeekNow record's explicitly-named
//! `discord_id` / `discordid` field — [`crate::modules::see_know`]'s extractor
//! and [`crate::modules::oathnet_pro`]'s breach parser — which is real Discord
//! context, not a guess from digits. A bare number yields **nothing** rather
//! than a fabricated date, which is what the safety claim always said and now
//! is true. (A `discord:`-prefixed value is trusted even when it also looks
//! like a Steam ID64: the prefix is evidence, the shape is not.)
//!
//! Every decoded date is still range-validated to `[2015-01-01, now]` before
//! any finding is minted, so a corrupt or truncated `discord_id` field yields
//! nothing too.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence, unix_now},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    timeline::utc_date,
};

const SRC: &str = "discord_snowflake";

/// The `discord:` marker an upstream extractor stamps on a value it read from a
/// record's own Discord-ID field. The one admission ticket into the decode.
const DISCORD_PREFIX: &str = "discord:";

/// Discord epoch — 2015-01-01T00:00:00 UTC — in milliseconds. Snowflake
/// timestamps are measured from here.
const DISCORD_EPOCH_MS: u64 = 1_420_070_400_000;
/// The same epoch in whole seconds, for the plausibility floor.
const DISCORD_EPOCH_SECS: i64 = 1_420_070_400;
const DAY_SECS: i64 = 86_400;

pub struct DiscordSnowflake;

#[async_trait]
impl Module for DiscordSnowflake {
    fn name(&self) -> &'static str {
        "discord_snowflake"
    }

    fn description(&self) -> &'static str {
        "Discord snowflake decode — offline recovery of an account-creation date from a snowflake ID (no API/key)"
    }

    fn priority(&self) -> u8 {
        104
    }

    fn is_passive(&self) -> bool {
        // Pure offline bit-math — no network, no I/O, no key.
        true
    }

    /// Pure transform of data already in the graph — no observation of its
    /// own, so its evidence never counts as a corroborating source (see
    /// `Module::is_derivation` / `ENRICHMENT_ONLY_SOURCES`).
    fn is_derivation(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index (built from `consumes()`) stays
        // consistent with `accepts()` and the module is actually indexed for
        // Username; the `discord:` requirement is applied in `process()`.
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default carries T1589.003 (Employee Names), but this module
        // derives a Discord account's creation date from its snowflake ID and emits
        // only that `Username` — never a real-name `Person` — so T1589.003 is
        // over-claimed. Discord account intelligence is T1593.001 (Social Media).
        &["T1593.001"]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let v = target.value.trim();
        let Some(id) = snowflake_candidate(v) else {
            return Ok(result);
        };

        let created_ms = (id >> 22) + DISCORD_EPOCH_MS;
        let created_secs = (created_ms / 1000) as i64;
        // Plausibility window: a real Discord account is created in
        // [2015-01-01, now]. A corrupt or truncated `discord_id` decodes
        // outside it — emit nothing rather than a fabricated creation date.
        let now_secs = unix_now() as i64;
        if created_secs < DISCORD_EPOCH_SECS || created_secs > now_secs + DAY_SECS {
            return Ok(result);
        }
        let date = utc_date(created_secs);

        // Enrich the seed Discord-ID Username with its derived creation date.
        // The decode is exact arithmetic, but it attests only that the number
        // is Discord's, never that the account is the subject's. The engine
        // merges by uid with GREATEST semantics, so at the former
        // `confidence::HIGH_PLUSPLUS` this re-emission lifted every upstream
        // `discord:` handle (minted at 0.55 / 0.60 by the breach extractors) to
        // 0.80, promoting a Probable attribution to Verified from arithmetic
        // alone (REQ-DISCORDSNOWFLAKE-002). The annotation is therefore passed
        // through the shared `Entity::demote_to_candidate`, which is the ONE
        // authority for its rung: it caps the confidence at the candidate rung
        // (below `SEED_PRESENT_RUNG`, the `disposable_check` precedent,
        // REQ-CANARY-003) and stamps `candidate`, so the merge adds the
        // temporal evidence and tags but neither raises the handle's confidence
        // nor clears a quarantine an upstream extractor stamped
        // (`Entity::absorb` drops `candidate` only for a non-candidate side).
        // The value it is constructed at is immaterial for that reason.
        let mut e = Entity::new(EntityKind::Username, v, confidence::VERY_LOW, &ctx.scan_id);
        e.demote_to_candidate();
        e.tag("discord");
        e.tag("derived");
        e.tag("account-age");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("Discord account created {date} (decoded from snowflake)"),
            )
            .with_attr("discord_created_date", date.as_str())
            .with_attr("discord_created_unix_ms", created_ms.to_string())
            .with_attr("source", "snowflake-decode"),
        );
        result.push(e);

        Ok(result)
    }
}

/// Returns the snowflake to decode if `v` is a `discord:`-prefixed 17–20 digit
/// ID, else `None`.
///
/// The prefix is **mandatory**, not an optional hint: it is the only evidence
/// that the number is Discord's rather than Twitter/X's, Instagram's or any
/// other issuer sharing the snowflake layout, and the module header records the
/// measured Twitter/X window (2010-11-04 → 2022-07-24) that a bare-number rule
/// admits. A shape gate cannot substitute for it.
fn snowflake_candidate(v: &str) -> Option<u64> {
    let digits = v.strip_prefix(DISCORD_PREFIX)?;
    let len = digits.len();
    if !(17..=20).contains(&len)
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.starts_with('0')
    {
        return None;
    }
    digits.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
