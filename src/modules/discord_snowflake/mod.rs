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
//! ## Safety against mis-attribution
//!
//! A 17-digit Steam ID64 also decodes to a deceptively plausible ~2015
//! timestamp, so any value that looks like a Steam ID (17 digits, `7656119…`)
//! is excluded, and every decoded date is range-validated to
//! `[2015-01-01, now]` before any finding is minted — a number that isn't a
//! real Discord snowflake yields **nothing** rather than a fabricated date.

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

/// Discord epoch — 2015-01-01T00:00:00 UTC — in milliseconds. Snowflake
/// timestamps are measured from here.
const DISCORD_EPOCH_MS: u64 = 1_420_070_400_000;
/// The same epoch in whole seconds, for the plausibility floor.
const DISCORD_EPOCH_SECS: i64 = 1_420_070_400;
const DAY_SECS: i64 = 86_400;

/// Confidence for a creation date derived from a value already identified as a
/// Discord ID upstream (a `discord:`-prefixed handle from the extractor).
const PREFIXED_CONF: f64 = confidence::HIGH_PLUSPLUS;
/// Confidence for a bare numeric handle that is a valid, plausible, non-Steam
/// snowflake — likely Discord, but it carried no explicit Discord context.
const BARE_CONF: f64 = confidence::MEDIUM_PLUS;

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

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index (built from `consumes()`) stays
        // consistent with `accepts()` and the module is actually indexed for
        // Username; the snowflake validation is applied in `process()`.
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
        let Some((id, prefixed)) = snowflake_candidate(v) else {
            return Ok(result);
        };

        let created_ms = (id >> 22) + DISCORD_EPOCH_MS;
        let created_secs = (created_ms / 1000) as i64;
        // Plausibility window: a real Discord account is created in
        // [2015-01-01, now]. A number that isn't a snowflake decodes outside it
        // — emit nothing rather than a fabricated creation date.
        let now_secs = unix_now() as i64;
        if created_secs < DISCORD_EPOCH_SECS || created_secs > now_secs + DAY_SECS {
            return Ok(result);
        }
        let date = utc_date(created_secs);

        // Enrich the seed Discord-ID Username with its derived creation date.
        // GREATEST-merge means this only ever *adds* the temporal evidence and
        // never lowers an existing higher confidence on the same handle.
        let conf = if prefixed { PREFIXED_CONF } else { BARE_CONF };
        let mut e = Entity::new(EntityKind::Username, v, conf, &ctx.scan_id);
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

/// Returns `(snowflake, was_discord_prefixed)` if `v` is a plausible Discord
/// snowflake to decode, else `None`. Strips an optional `discord:` prefix.
/// Rejects Steam ID64s (17 digits, `7656119…`), which also 17-digit-decode to a
/// deceptively plausible ~2015 date.
fn snowflake_candidate(v: &str) -> Option<(u64, bool)> {
    let (digits, prefixed) = match v.strip_prefix("discord:") {
        Some(rest) => (rest, true),
        None => (v, false),
    };
    let len = digits.len();
    if !(17..=20).contains(&len)
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.starts_with('0')
    {
        return None;
    }
    // Steam ID64 exclusion (only for an unprefixed bare number): a 17-digit
    // `7656119…` is a Steam account, not Discord.
    if !prefixed && len == 17 && digits.starts_with("7656119") {
        return None;
    }
    digits.parse::<u64>().ok().map(|id| (id, prefixed))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
