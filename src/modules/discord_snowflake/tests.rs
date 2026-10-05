use super::*;

/// Twitter/X's own snowflake epoch, 2010-11-04T01:42:54.657Z, in ms. Used
/// ONLY to synthesise authentic-shaped Twitter IDs for the cross-issuer
/// regression below — never by production code.
const TWITTER_EPOCH_MS: u64 = 1_288_834_974_657;

/// The ID Twitter/X would have issued at `created_ms`. Same bit layout as
/// Discord's (`timestamp << 22`), which is exactly the problem.
fn twitter_id_at(created_ms: u64) -> String {
    ((created_ms - TWITTER_EPOCH_MS) << 22).to_string()
}

#[test]
fn utc_date_matches_known_unix_dates() {
    assert_eq!(utc_date(0), "1970-01-01");
    assert_eq!(utc_date(DISCORD_EPOCH_SECS), "2015-01-01");
    assert_eq!(utc_date(1_577_836_800), "2020-01-01");
}

#[test]
fn decode_round_trips_a_known_date() {
    // Build the snowflake for 2020-01-01 and confirm `(id >> 22) + epoch` and
    // the date formatter recover it exactly — catches an off-by-shift / wrong
    // epoch.
    let created_ms = 1_577_836_800_000u64; // 2020-01-01T00:00:00Z
    let id = (created_ms - DISCORD_EPOCH_MS) << 22;
    let decoded_ms = (id >> 22) + DISCORD_EPOCH_MS;
    assert_eq!(decoded_ms, created_ms);
    assert_eq!(utc_date((decoded_ms / 1000) as i64), "2020-01-01");
}

#[test]
fn candidate_requires_explicit_discord_context() {
    assert_eq!(
        snowflake_candidate("discord:123456789012345678"),
        Some(123_456_789_012_345_678u64)
    );
    // A bare number is refused however Discord-shaped it looks. This assertion
    // was inverted (REQ-DISCORDSNOWFLAKE-001): it previously read
    // `assert!(snowflake_candidate("175928847299117063").is_some()); // 18-digit ID`
    // — treating 17–20 digits as proof of issuer. It is not: Twitter/X,
    // Instagram and Mastodon mint the same shape, and the module header
    // records the whole 2010-11-04 → 2022-07-24 Twitter window that rule let
    // through. `cross_issuer_snowflakes_are_never_decoded` is the lock.
    assert!(snowflake_candidate("175928847299117063").is_none());
    // Steam ID64 (17-digit `7656119…`) — refused like any other bare number.
    // The dedicated `7656119` carve-out is gone: it is subsumed, not lost.
    assert!(snowflake_candidate("76561197960265728").is_none());
    // …but an explicit `discord:` prefix is evidence where shape is not, so it
    // is trusted even on a Steam-looking body.
    assert!(snowflake_candidate("discord:76561197960265728").is_some());

    // Shape rejects — asserted on PREFIXED values so they still exercise the
    // 17–20-digit / all-digit / no-leading-zero gate. Asserting them bare
    // would now pass vacuously on the missing prefix alone and the shape gate
    // would go unchecked.
    let mut admitted: Vec<&str> = Vec::new();
    for bad in [
        "discord:1234567890123456",        // 16 digits
        "discord:123456789012345678901",   // 21 digits
        "discord:0123456789012345678",     // leading zero
        "discord:alice1234567890123",      // non-digit
        "discord:",                        // prefix with no body
        "Discord:123456789012345678",      // prefix is case-sensitive
        "discord :123456789012345678",     // not the exact marker
    ] {
        if snowflake_candidate(bad).is_some() {
            admitted.push(bad);
        }
    }
    assert!(
        admitted.is_empty(),
        "shape gate admitted malformed prefixed values: {admitted:?}"
    );
}

/// The regression this module's safety claim rests on: a snowflake minted by a
/// DIFFERENT issuer must never be decoded, because Discord's epoch applied to
/// it yields a plausible-looking but fabricated date.
///
/// Twitter/X is the measured case. Its epoch sits 1518.93 days before
/// Discord's, so a Twitter ID read as a Discord one reports a creation date
/// ~4.16 years late — and for every Twitter ID issued from 2010-11-04 to
/// 2022-07-24 that late answer still lands inside `[2015-01-01, now]`. This
/// sweeps a month at a time across that whole window (and past it) and
/// collects EVERY survivor, so a partial re-admission (a digit-length rule, a
/// prefix carve-out, a range tweak) is named rather than masked by the first
/// failure.
#[test]
fn cross_issuer_snowflakes_are_never_decoded() {
    // 2011-01 .. 2025-12, monthly. ~30.44-day months are close enough — the
    // property is "no month anywhere in the era decodes", not calendar exactness.
    const MONTH_MS: u64 = 2_629_746_000;
    let start = 1_293_840_000_000u64; // 2011-01-01T00:00:00Z
    let mut decoded: Vec<(String, String)> = Vec::new();
    let mut checked = 0usize;
    let mut in_window = 0usize;
    for m in 0..180u64 {
        let tweet_ms = start + m * MONTH_MS;
        let id = twitter_id_at(tweet_ms);
        if !(17..=20).contains(&id.len()) {
            continue;
        }
        checked += 1;
        // How the baseline would have read it — recorded so a survivor's
        // message shows the fabricated date, not just the ID.
        let as_discord = (id.parse::<u64>().expect("synthesised id fits u64") >> 22)
            + DISCORD_EPOCH_MS;
        let secs = (as_discord / 1000) as i64;
        if (DISCORD_EPOCH_SECS..=unix_now() as i64 + DAY_SECS).contains(&secs) {
            in_window += 1;
        }
        if snowflake_candidate(&id).is_some() {
            decoded.push((id, utc_date(secs)));
        }
    }
    // Vacuity guards: the sweep must actually have produced snowflake-shaped
    // Twitter IDs, and a real majority of them must fall inside the
    // plausibility window — otherwise "none decoded" would prove nothing.
    assert!(
        checked >= 150,
        "sweep produced only {checked} snowflake-shaped Twitter IDs — fixture is wrong"
    );
    assert!(
        in_window >= 100,
        "only {in_window} of {checked} Twitter IDs land in the plausibility window; \
         the premise this test locks has evaporated — re-measure before relaxing it"
    );
    assert!(
        decoded.is_empty(),
        "{} Twitter/X IDs were accepted as Discord snowflakes, e.g. {:?}",
        decoded.len(),
        &decoded[..decoded.len().min(5)]
    );
}

#[test]
fn is_free_passive_social() {
    let m = DiscordSnowflake;
    assert!(m.is_passive()); // pure offline compute, no network
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Social);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(
        TargetKind::Username,
        "discord:123456789012345678"
    )));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    // accepts() is kind-only — it is still true for a bare numeric handle. The
    // `discord:` requirement is enforced in snowflake_candidate / process()
    // (pinned by candidate_requires_explicit_discord_context), so a bare value
    // is dispatched and then yields nothing.
    assert!(m.accepts(&Target::new(TargetKind::Username, "175928847299117063")));
}

fn test_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

#[tokio::test]
async fn process_enriches_discord_id_with_creation_date() {
    // Fully offline + deterministic (no network) — runs in CI, not ignored.
    let id = format!(
        "discord:{}",
        (1_577_836_800_000u64 - DISCORD_EPOCH_MS) << 22
    );
    let ctx = test_ctx();
    let target = Target::new(TargetKind::Username, &id);
    let r = DiscordSnowflake
        .process(&target, &ctx)
        .await
        .expect("offline decode never errors");
    let e = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("a username entity enriched with the creation date");
    assert!(e.has_tag("discord") && e.has_tag("account-age"));
    // The enriched entity keeps the seed's exact `discord:`-prefixed value so
    // the GREATEST-merge lands on the extractor's own entity rather than
    // forking a second handle.
    assert_eq!(e.value, id, "enrichment must key on the seed value");
    assert!(
        e.evidence
            .iter()
            .any(|ev| ev.summary.contains("2020-01-01")),
        "decoded date must reach the evidence"
    );
}

/// `process` is the reachable production surface, so the refusal is asserted
/// there too — not only on the private helper. A bare Twitter/X ID is the
/// exact value `hse scan 1542659245470646272` produces (`detect` falls through
/// to Username for a 17–20 digit run), so this is the end-to-end case.
#[tokio::test]
async fn process_emits_nothing_for_a_bare_cross_issuer_snowflake() {
    let ctx = test_ctx();
    let mut emitted: Vec<(String, usize)> = Vec::new();
    for tweet_ms in [
        1_293_840_000_000u64, // 2011-01-01
        1_370_044_800_000,    // 2013-06-01
        1_464_739_200_000,    // 2016-06-01
        1_559_347_200_000,    // 2019-06-01
        1_656_633_600_000,    // 2022-07-01
    ] {
        let id = twitter_id_at(tweet_ms);
        let target = Target::new(TargetKind::Username, &id);
        let r = DiscordSnowflake
            .process(&target, &ctx)
            .await
            .expect("offline decode never errors");
        if !r.entities.is_empty() {
            emitted.push((id, r.entities.len()));
        }
    }
    assert!(
        emitted.is_empty(),
        "bare Twitter/X IDs minted Discord findings: {emitted:?}"
    );
}

/// The `discord:<id>` a breach extractor minted, decoded by the module and
/// merged back the way the engine folds module output (`existing.merge`).
async fn merged_onto(mut found: Entity) -> Entity {
    let id = found.value.clone();
    let r = DiscordSnowflake
        .process(&Target::new(TargetKind::Username, &id), &test_ctx())
        .await
        .expect("offline decode never errors");
    assert!(!r.entities.is_empty(), "premise: the decode fired");
    for e in r.entities {
        found.merge(e);
    }
    found
}

fn discord_2020() -> String {
    format!("discord:{}", (1_577_836_800_000u64 - DISCORD_EPOCH_MS) << 22)
}

/// REQ-DISCORDSNOWFLAKE-002: the decode proves the number is Discord's, not
/// that the account is the subject's. At 0.80 it lifted oathnet_pro's 0.55
/// handle to 0.80 under GREATEST-merge — Probable to Verified from arithmetic.
#[tokio::test]
async fn the_decode_annotates_but_never_raises_the_handle() {
    let found = Entity::new(
        EntityKind::Username,
        discord_2020(),
        confidence::MEDIUM_HIGH,
        "t",
    );
    let merged = merged_onto(found).await;
    assert!(
        merged.confidence <= confidence::MEDIUM_HIGH + 1e-9,
        "decode raised the handle to {}",
        merged.confidence
    );
    // Over-correction guard: the annotation still lands — date and tags merge.
    assert!(
        merged
            .evidence
            .iter()
            .any(|ev| ev.attributes.contains_key("discord_created_date")),
        "the creation date must still reach the handle"
    );
    assert!(merged.has_tag("discord") && merged.has_tag("account-age"));
    // And a genuine upstream handle is not newly quarantined by it.
    assert!(!merged.has_tag(crate::core::tags::CANDIDATE));
}

/// A stranger's `discord:` ID from a non-matching breach row is quarantined
/// at the candidate rung; the decode must not lift it out of quarantine.
#[tokio::test]
async fn the_decode_never_releases_a_quarantined_handle() {
    let mut found = Entity::new(
        EntityKind::Username,
        discord_2020(),
        confidence::MEDIUM_HIGH,
        "t",
    );
    found.demote_to_candidate();
    let before = found.confidence;
    let merged = merged_onto(found).await;
    assert!(
        merged.has_tag(crate::core::tags::CANDIDATE),
        "decode cleared the candidate quarantine"
    );
    assert!(
        merged.confidence <= before + 1e-9,
        "decode raised a quarantined handle to {}",
        merged.confidence
    );
}
