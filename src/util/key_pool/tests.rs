use std::collections::HashMap;

use super::*;

#[test]
fn export_import_roundtrips_and_is_idempotent() {
    let src = KeyPool::new();
    let mut a = KeyEntry::new("key-a");
    a.environment = Some("prod".into());
    src.add("shodan", a);
    src.add("intelx", KeyEntry::new("key-b")); // default env

    let json = src.export_json(None).unwrap();
    let dst = KeyPool::new();
    assert_eq!(
        dst.import_json(&json, None).unwrap(),
        2,
        "both keys imported"
    );
    // Re-import is idempotent (dedup by value).
    assert_eq!(dst.import_json(&json, None).unwrap(), 0, "no duplicates");
    // Environment survives the round-trip.
    let snap = dst.snapshot();
    assert_eq!(snap.services["shodan"][0].environment(), "prod");
    assert_eq!(snap.services["intelx"][0].environment(), "default");
}

#[test]
fn export_filters_by_environment() {
    let pool = KeyPool::new();
    let mut p = KeyEntry::new("prod-key");
    p.environment = Some("prod".into());
    pool.add("shodan", p);
    pool.add("shodan", KeyEntry::new("default-key")); // default env

    let only_prod = pool.export_json(Some("prod")).unwrap();
    assert!(only_prod.contains("prod-key"));
    assert!(
        !only_prod.contains("default-key"),
        "env filter must exclude other environments"
    );
}

#[test]
fn revoke_and_rotate_by_id_reference_keys_without_plaintext() {
    let pool = KeyPool::new();
    let mut p = KeyEntry::new("old-secret");
    p.environment = Some("prod".into());
    pool.add("shodan", p);
    let id = key_id("old-secret");
    assert_ne!(id, "old-secret", "id is a hash, not the value");

    // Rotate by id: old revoked (retained), new added in the same env, served.
    assert!(pool.rotate_by_id("shodan", &id, "new-secret"));
    let snap = pool.snapshot();
    let entries = &snap.services["shodan"];
    let old = entries.iter().find(|e| e.value == "old-secret").unwrap();
    let new = entries.iter().find(|e| e.value == "new-secret").unwrap();
    assert_eq!(old.status, KeyStatus::Revoked);
    assert_eq!(new.environment(), "prod");
    assert_eq!(pool.next_key("shodan").as_deref(), Some("new-secret"));

    // Revoke the new key by its id.
    assert!(pool.revoke_by_id("shodan", &key_id("new-secret")));
    assert_eq!(pool.next_key("shodan"), None);
    // Unknown id is a no-op.
    assert!(!pool.revoke_by_id("shodan", "00ff00ff00ff"));
    assert!(!pool.rotate_by_id("shodan", "00ff00ff00ff", "x"));
}

#[test]
fn revoke_makes_a_key_unusable_but_retained() {
    let pool = KeyPool::new();
    pool.add("shodan", KeyEntry::new("compromised"));
    assert_eq!(pool.next_key("shodan").as_deref(), Some("compromised"));
    assert!(pool.revoke("shodan", "compromised"));
    // Retained for audit…
    assert_eq!(pool.snapshot().services["shodan"].len(), 1);
    assert_eq!(
        pool.snapshot().services["shodan"][0].status,
        KeyStatus::Revoked
    );
    // …but never selected again.
    assert_eq!(
        pool.next_key("shodan"),
        None,
        "revoked key must not be used"
    );
    assert!(!pool.revoke("shodan", "nonexistent"));
}

#[test]
fn rotate_revokes_old_adds_new_carrying_environment() {
    let pool = KeyPool::new();
    let mut old = KeyEntry::new("old-key");
    old.environment = Some("prod".into());
    old.notes = Some("primary".into());
    pool.add("shodan", old);

    assert!(pool.rotate("shodan", "old-key", "new-key"));
    let snap = pool.snapshot();
    let entries = &snap.services["shodan"];
    let old_e = entries.iter().find(|e| e.value == "old-key").unwrap();
    let new_e = entries.iter().find(|e| e.value == "new-key").unwrap();
    assert_eq!(old_e.status, KeyStatus::Revoked, "old key revoked");
    assert_eq!(new_e.environment(), "prod", "new key inherits environment");
    assert_eq!(
        new_e.notes.as_deref(),
        Some("primary"),
        "provenance carried"
    );
    assert!(new_e.rotated_at.is_some(), "rotation timestamp stamped");
    // The pool now serves the new key, not the revoked old one.
    assert_eq!(pool.next_key("shodan").as_deref(), Some("new-key"));
    // Rotating a missing key is a no-op.
    assert!(!pool.rotate("shodan", "ghost", "x"));
}

#[test]
fn add_and_cycle() {
    let pool = KeyPool::new();
    assert!(pool.add("shodan", KeyEntry::new("key-a")));
    assert!(pool.add("shodan", KeyEntry::new("key-b")));
    assert!(!pool.add("shodan", KeyEntry::new("key-a")));

    assert_eq!(pool.service_count("shodan"), 2);

    let k1 = pool.next_key("shodan").unwrap();
    let k2 = pool.next_key("shodan").unwrap();
    let k3 = pool.next_key("shodan").unwrap();
    assert_eq!(k1, "key-a");
    assert_eq!(k2, "key-b");
    assert_eq!(k3, "key-a");
}

#[test]
fn skips_invalid_keys() {
    let pool = KeyPool::new();
    pool.add("intelx", KeyEntry::new("good"));
    pool.add("intelx", KeyEntry::new("bad"));
    pool.mark_status("intelx", "bad", KeyStatus::Invalid);

    let k1 = pool.next_key("intelx").unwrap();
    let k2 = pool.next_key("intelx").unwrap();
    assert_eq!(k1, "good");
    assert_eq!(k2, "good");
}

#[test]
fn mark_validated() {
    let pool = KeyPool::new();
    pool.add("shodan", KeyEntry::new("test-key"));
    pool.mark_validated("shodan", "test-key", true);

    let snap = pool.snapshot();
    let entry = &snap.services["shodan"][0];
    assert_eq!(entry.status, KeyStatus::Active);
    assert!(entry.last_validated.is_some());
}

#[test]
fn remove_key() {
    let pool = KeyPool::new();
    pool.add("shodan", KeyEntry::new("k1"));
    pool.add("shodan", KeyEntry::new("k2"));
    assert!(pool.remove("shodan", "k1"));
    assert_eq!(pool.service_count("shodan"), 1);
    assert!(!pool.remove("shodan", "k1"));
}

#[test]
fn empty_service_returns_none() {
    let pool = KeyPool::new();
    assert!(pool.next_key("nonexistent").is_none());
}

#[test]
fn case_insensitive_service() {
    let pool = KeyPool::new();
    pool.add("Shodan", KeyEntry::new("k1"));
    assert!(pool.next_key("shodan").is_some());
    assert!(pool.next_key("SHODAN").is_some());
}

#[test]
fn merge_fills_gaps() {
    let pool = KeyPool::new();
    pool.add("shodan", KeyEntry::new("pool-key"));

    let mut keys = HashMap::new();
    merge_pool_into_env(&pool, &mut keys);
    assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap(), "pool-key");
}

#[test]
fn merge_does_not_override_existing() {
    let pool = KeyPool::new();
    pool.add("shodan", KeyEntry::new("pool-key"));

    let mut keys = HashMap::new();
    keys.insert("HUNTSMAN_SHODAN_KEY".to_string(), "env-key".to_string());
    merge_pool_into_env(&pool, &mut keys);
    assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap(), "env-key");
}

#[test]
fn all_services_defined() {
    let defs = crate::util::service_defs::service_defs();
    assert!(defs.len() >= 24);
    for d in defs {
        assert!(d.env_var.starts_with("HUNTSMAN_"));
        assert!(!d.test_url.is_empty());
    }
}

#[test]
fn find_service_works() {
    assert!(crate::util::service_defs::find_service("shodan").is_some());
    assert!(crate::util::service_defs::find_service("intelx").is_some());
    assert!(crate::util::service_defs::find_service("nonexistent").is_none());
}

#[test]
fn tier_ordering() {
    assert!(KeyTier::Premium > KeyTier::Standard);
    assert!(KeyTier::Standard > KeyTier::Basic);
    assert!(KeyTier::Basic > KeyTier::Trial);
}

#[test]
fn load_pool_from_backs_up_an_unreadable_file_instead_of_silently_dropping_it() {
    // Regression: a pool file that EXISTS but can't be read (here: invalid UTF-8
    // corruption) must be preserved as `.json.bak` and warned about — not
    // silently discarded (the old blanket `Err(_) => KeyPool::new()`) and then
    // clobbered by the next atomic save. A genuinely MISSING file stays a quiet
    // fresh start with no backup.
    use super::persistence::load_pool_from;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("hse_kp_{}_{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("key_pool.json");
    let bak = path.with_extension("json.bak");

    // (1) Missing file → empty pool, NO backup.
    assert_eq!(load_pool_from(&path).total_keys(), 0);
    assert!(
        !bak.exists(),
        "a missing file is a fresh start, not a corruption backup"
    );

    // (2) Present but unreadable (invalid UTF-8) → empty pool, file preserved as .bak.
    std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01, 0x80]).unwrap();
    assert_eq!(load_pool_from(&path).total_keys(), 0);
    assert!(
        !path.exists(),
        "the unreadable file is renamed aside, not left to be clobbered"
    );
    assert!(
        bak.exists(),
        "the unreadable file is preserved as .json.bak"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn next_key_prefers_higher_tier() {
    let pool = KeyPool::new();
    let mut basic = KeyEntry::new("basic-key");
    basic.tier = KeyTier::Basic;
    basic.status = KeyStatus::Active;
    let mut premium = KeyEntry::new("premium-key");
    premium.tier = KeyTier::Premium;
    premium.status = KeyStatus::Active;
    pool.add("shodan", basic);
    pool.add("shodan", premium);

    let k = pool.next_key("shodan").unwrap();
    assert_eq!(k, "premium-key", "should prefer higher-tier key");
}

#[test]
fn next_key_avoids_error_prone_key() {
    let pool = KeyPool::new();
    let mut good = KeyEntry::new("good-key");
    good.status = KeyStatus::Active;
    good.error_count = 0;
    let mut bad = KeyEntry::new("bad-key");
    bad.status = KeyStatus::Active;
    bad.error_count = 50;
    pool.add("shodan", good);
    pool.add("shodan", bad);

    let k = pool.next_key("shodan").unwrap();
    assert_eq!(k, "good-key", "should prefer key with fewer errors");
}

#[test]
fn next_key_spreads_load_rather_than_hammering_the_single_best() {
    // Two healthy, same-tier keys differing only by a single past error (below the
    // back-off threshold, so both stay healthy). The old selector always returned
    // the zero-error key — hammering it to its rate limit; the load-balancer fans
    // requests out evenly so neither key is over-used.
    let pool = KeyPool::new();
    let mut a = KeyEntry::new("key-a");
    a.status = KeyStatus::Active;
    a.error_count = 1;
    let mut b = KeyEntry::new("key-b");
    b.status = KeyStatus::Active;
    pool.add("shodan", a);
    pool.add("shodan", b);

    let picks: Vec<String> = (0..4).filter_map(|_| pool.next_key("shodan")).collect();
    assert_eq!(
        picks.iter().filter(|k| *k == "key-a").count(),
        2,
        "load is split, not hammered: {picks:?}"
    );
    assert_eq!(
        picks.iter().filter(|k| *k == "key-b").count(),
        2,
        "{picks:?}"
    );
}

#[test]
fn just_recovered_key_yields_to_a_healthy_peer() {
    // A key that came back from a rate-limit one second ago is still usable, but is
    // held one band lower during the grace window so the pool leans on the fresh
    // key — easing the throttled credential back in instead of re-hammering it.
    let pool = KeyPool::new();
    let mut fresh = KeyEntry::new("fresh");
    fresh.status = KeyStatus::Active;
    let mut recovered = KeyEntry::new("recovered");
    recovered.status = KeyStatus::RateLimited;
    recovered.rate_limit_reset = Some(crate::core::entity::unix_now().saturating_sub(1));
    pool.add("shodan", fresh);
    pool.add("shodan", recovered);

    assert_eq!(pool.next_key("shodan").as_deref(), Some("fresh"));
}

#[test]
fn selecting_a_recovered_key_flips_it_back_to_active() {
    // When a rate-limited key's cooldown has well elapsed and it's the only one
    // usable, the pool serves it AND updates its status to Active so the telemetry
    // reflects reality (no more perpetual "rate_limited" on a recovered key).
    let pool = KeyPool::new();
    let mut k = KeyEntry::new("k");
    k.status = KeyStatus::RateLimited;
    k.rate_limit_reset = Some(crate::core::entity::unix_now().saturating_sub(60));
    pool.add("shodan", k);

    assert_eq!(pool.next_key("shodan").as_deref(), Some("k"));
    assert_eq!(
        pool.snapshot().services["shodan"][0].status,
        KeyStatus::Active,
        "a recovered key is marked Active on use"
    );
}

#[test]
fn add_rejects_non_poolable_services() {
    // The pool only holds reusable provider keys; the harvest catch-alls
    // (generic_hex, crypto_*, jwt_token, <svc>_login) must never enter it,
    // regardless of which ingest path calls add() — this is the chokepoint
    // that stopped a 6 MB generic_hex pool.
    let pool = KeyPool::new();
    assert!(
        pool.add("shodan", KeyEntry::new("real")),
        "provider key pools"
    );
    assert!(!pool.add("generic_hex", KeyEntry::new("deadbeefdeadbeef")));
    assert!(!pool.add("crypto_sol", KeyEntry::new("So11111111111111")));
    assert!(!pool.add("shodan_login", KeyEntry::new("user:pass")));
    assert_eq!(pool.service_count("generic_hex"), 0);
    assert_eq!(pool.service_count("shodan"), 1);
}

#[test]
fn record_error_increments() {
    let pool = KeyPool::new();
    pool.add("shodan", KeyEntry::new("k1"));
    pool.record_error("shodan", "k1");
    pool.record_error("shodan", "k1");
    let snap = pool.snapshot();
    assert_eq!(snap.services["shodan"][0].error_count, 2);
}

#[test]
fn success_rate_calculation() {
    let mut e = KeyEntry::new("k");
    assert!((e.success_rate() - 1.0).abs() < 1e-9, "unused key = 100%");
    e.use_count = 10;
    e.error_count = 3;
    assert!((e.success_rate() - 0.7).abs() < 1e-9);
}

#[test]
fn prune_degraded_removes_bad_keys() {
    let pool = KeyPool::new();
    let mut good = KeyEntry::new("good");
    good.use_count = 100;
    good.error_count = 5;
    let mut bad = KeyEntry::new("bad");
    bad.use_count = 100;
    bad.error_count = 90;
    pool.add("shodan", good);
    pool.add("shodan", bad);

    let pruned = pool.prune_degraded(0.50, 10);
    assert_eq!(pruned, 1);
    assert_eq!(pool.service_count("shodan"), 1);
    assert!(pool.next_key("shodan").unwrap() == "good");
}

#[test]
fn prune_degraded_spares_low_use_keys() {
    let pool = KeyPool::new();
    let mut new_key = KeyEntry::new("new");
    new_key.use_count = 2;
    new_key.error_count = 2;
    pool.add("shodan", new_key);

    let pruned = pool.prune_degraded(0.50, 10);
    assert_eq!(pruned, 0, "keys below min_uses should be spared");
}

#[test]
fn entry_status_reports_pooled_key_verdict() {
    let pool = KeyPool::new();
    pool.add("shodan", KeyEntry::new("k1"));
    // Newly added keys are Untested until validated.
    assert_eq!(pool.entry_status("shodan", "k1"), Some(KeyStatus::Untested));
    // Case-insensitive service lookup, like the rest of the pool API.
    pool.mark_validated("shodan", "k1", true);
    assert_eq!(pool.entry_status("SHODAN", "k1"), Some(KeyStatus::Active));
    // Absent keys / services report None.
    assert_eq!(pool.entry_status("shodan", "nope"), None);
    assert_eq!(pool.entry_status("censys", "k1"), None);
}

#[test]
fn prune_degraded_always_retains_high_value_keys() {
    let pool = KeyPool::new();

    // A degraded Basic key (10 uses, all errors → 0% success): prunable.
    let mut basic = KeyEntry::new("basic-bad");
    basic.tier = KeyTier::Basic;
    basic.use_count = 10;
    basic.error_count = 10;
    pool.add("shodan", basic);

    // An equally-degraded Premium key: must be retained regardless.
    let mut premium = KeyEntry::new("premium-bad");
    premium.tier = KeyTier::Premium;
    premium.use_count = 10;
    premium.error_count = 10;
    pool.add("shodan", premium);

    // A degraded Standard key: also retained (high-value floor is Standard).
    let mut standard = KeyEntry::new("standard-bad");
    standard.tier = KeyTier::Standard;
    standard.use_count = 10;
    standard.error_count = 10;
    pool.add("shodan", standard);

    let pruned = pool.prune_degraded(0.5, 1);
    assert_eq!(pruned, 1, "only the Basic key should prune");
    assert_eq!(pool.entry_status("shodan", "basic-bad"), None);
    assert_eq!(
        pool.entry_status("shodan", "premium-bad"),
        Some(KeyStatus::Untested),
        "Premium key retained"
    );
    assert_eq!(
        pool.entry_status("shodan", "standard-bad"),
        Some(KeyStatus::Untested),
        "Standard key retained"
    );
}

#[test]
fn prune_degraded_still_drops_unused_low_value_keys_only_when_degraded() {
    let pool = KeyPool::new();
    // Under min_uses → retained (not enough signal to judge).
    let mut fresh = KeyEntry::new("fresh");
    fresh.tier = KeyTier::Basic;
    fresh.use_count = 0;
    pool.add("shodan", fresh);
    let pruned = pool.prune_degraded(0.5, 5);
    assert_eq!(pruned, 0);
    assert!(pool.entry_status("shodan", "fresh").is_some());
}

#[test]
fn health_score_fresh_active_key_scores_near_one() {
    // A brand-new key that has never failed: success_rate() is the optimistic
    // 1.0 prior and nothing is throttled, so health is at (or essentially at) the
    // top of the band. Untested and Active both qualify as live, non-terminal.
    let now = crate::core::entity::unix_now();
    for status in [KeyStatus::Untested, KeyStatus::Active] {
        let mut k = KeyEntry::new("fresh");
        k.status = status;
        k.tier = KeyTier::Premium; // top tier → full capacity bonus
        let h = k.health_score(now);
        assert!(
            (h - 1.0).abs() < 1e-9,
            "fresh top-tier {status:?} key should score ~1.0, got {h}"
        );
    }
    // Even a fresh BASIC key (smaller tier bonus) should still read as very
    // healthy — comfortably in the top fraction of the range.
    let mut basic = KeyEntry::new("fresh-basic");
    basic.status = KeyStatus::Active;
    basic.tier = KeyTier::Basic;
    let h = basic.health_score(now);
    assert!(
        h > 0.9,
        "a fresh Active Basic key should be very healthy: {h}"
    );
}

#[test]
fn health_score_terminal_states_score_zero() {
    // Revoked / Invalid / Exhausted are dead credentials: zero health regardless
    // of an otherwise spotless history (never used → success_rate 1.0, top tier).
    let now = crate::core::entity::unix_now();
    for status in [KeyStatus::Revoked, KeyStatus::Invalid, KeyStatus::Exhausted] {
        let mut k = KeyEntry::new("dead");
        k.status = status;
        k.tier = KeyTier::Premium;
        let h = k.health_score(now);
        assert!(
            h.abs() < 1e-9,
            "terminal {status:?} key must score ~0.0, got {h}"
        );
    }
}

#[test]
fn health_score_rate_limited_in_cooldown_scores_low() {
    // Anchor `now` away from the epoch so we can place a reset both in the future
    // (still cooling) and far in the past (fully recovered) without underflow.
    let now = 1_000_000u64;

    // A key still inside its rate-limit cooldown is long-run healthy but useless
    // right now: the availability multiplier pulls its score well down — far below
    // an otherwise-identical fresh key, yet strictly above a terminal 0.0 so an
    // operator can still distinguish "throttled" from "dead".
    let mut limited = KeyEntry::new("throttled");
    limited.status = KeyStatus::RateLimited;
    limited.rate_limit_reset = Some(now + 300); // 5 min left on the clock
    let limited_h = limited.health_score(now);

    let mut healthy = KeyEntry::new("ok");
    healthy.status = KeyStatus::Active;
    let healthy_h = healthy.health_score(now);

    assert!(limited_h > 0.0, "throttled key is not dead: {limited_h}");
    assert!(
        limited_h < 0.25,
        "in-cooldown key should score low, got {limited_h}"
    );
    assert!(
        limited_h < healthy_h,
        "throttled ({limited_h}) must be worse than fresh ({healthy_h})"
    );

    // With the reset far in the past (cooldown AND grace window well elapsed) the
    // same key is fully available again and recovers a high score.
    let mut recovered = limited.clone();
    recovered.rate_limit_reset = Some(now - 10_000);
    let recovered_h = recovered.health_score(now);
    assert!(
        recovered_h > limited_h,
        "a recovered key should out-score its in-cooldown self: {recovered_h} vs {limited_h}"
    );
    assert!(
        recovered_h > 0.9,
        "fully past the grace window it is healthy again: {recovered_h}"
    );
}

#[test]
fn health_score_error_prone_key_lands_between() {
    // A key with a poor success rate but no throttle sits between a fresh key and
    // a dead one: reliability is the dominant term, so a high error rate drags the
    // score down without zeroing it.
    let now = crate::core::entity::unix_now();
    let mut bad = KeyEntry::new("flaky");
    bad.status = KeyStatus::Active;
    bad.use_count = 10;
    bad.error_count = 8; // 20% success
    let h = bad.health_score(now);
    assert!(
        h > 0.0 && h < 0.5,
        "an error-prone Active key should land in between, got {h}"
    );
}

#[test]
fn health_report_aggregates_per_service_and_is_ordered() {
    let pool = KeyPool::new();

    // shodan: one healthy Active key + one Revoked (dead) key.
    let mut good = KeyEntry::new("shodan-good");
    good.status = KeyStatus::Active;
    pool.add("shodan", good);
    let mut revoked = KeyEntry::new("shodan-revoked");
    revoked.status = KeyStatus::Active;
    pool.add("shodan", revoked);
    assert!(pool.revoke("shodan", "shodan-revoked"));

    // intelx: a single fresh Active key.
    let mut solo = KeyEntry::new("intelx-key");
    solo.status = KeyStatus::Active;
    pool.add("intelx", solo);

    let report = pool.health_report();

    // Deterministically ordered by service name: intelx before shodan.
    let services: Vec<&str> = report.iter().map(|s| s.service.as_str()).collect();
    assert_eq!(services, vec!["intelx", "shodan"], "sorted by service name");

    let intelx = &report[0];
    assert_eq!(intelx.total, 1);
    assert_eq!(intelx.usable, 1);
    assert_eq!(intelx.breakdown.active, 1);
    assert!(
        (intelx.avg_health - intelx.min_health).abs() < 1e-9,
        "single-key service: avg equals min"
    );
    assert!(intelx.min_health > 0.9, "lone fresh key is healthy");

    let shodan = &report[1];
    assert_eq!(shodan.total, 2);
    assert_eq!(shodan.usable, 1, "only the non-revoked key is usable");
    assert_eq!(shodan.breakdown.active, 1);
    assert_eq!(shodan.breakdown.revoked, 1);
    // One key ~1.0 and one ~0.0 → average ~0.5, minimum ~0.0 (the revoked floor
    // the average alone would hide).
    assert!(
        (shodan.avg_health - 0.5).abs() < 0.1,
        "avg of one healthy + one dead key ~= 0.5, got {}",
        shodan.avg_health
    );
    assert!(
        shodan.min_health.abs() < 1e-9,
        "the revoked key sets the floor at ~0.0, got {}",
        shodan.min_health
    );

    // Empty pool → empty report (no panics on the 0/0 path).
    assert!(KeyPool::new().health_report().is_empty());
}

#[test]
fn health_report_is_value_free_and_serializable() {
    // The report must never carry key plaintext and must serialise cleanly for the
    // dashboard/API.
    let pool = KeyPool::new();
    let mut k = KeyEntry::new("super-secret-value");
    k.status = KeyStatus::Active;
    pool.add("shodan", k);

    let report = pool.health_report();
    let json = serde_json::to_string(&report).expect("ServiceHealth serialises");
    assert!(
        !json.contains("super-secret-value"),
        "health report must not leak key plaintext"
    );
    assert!(json.contains("\"avg_health\""));
    assert!(json.contains("\"min_health\""));
    assert!(json.contains("\"breakdown\""));
}

#[test]
fn key_status_as_str_matches_snake_case_serde_wire_form() {
    // as_str() must agree with the `#[serde(rename_all = "snake_case")]` form so
    // the API/UI status string and the persisted JSON never drift. RateLimited →
    // rate_limited is the multi-word case most prone to skew.
    let cases = [
        (KeyStatus::Untested, "untested"),
        (KeyStatus::Active, "active"),
        (KeyStatus::Exhausted, "exhausted"),
        (KeyStatus::Invalid, "invalid"),
        (KeyStatus::RateLimited, "rate_limited"),
        (KeyStatus::Revoked, "revoked"),
    ];
    for (status, want) in cases {
        assert_eq!(status.as_str(), want);
        let wire = serde_json::to_value(status).unwrap();
        assert_eq!(wire, serde_json::Value::String(want.to_string()));
    }
}

#[test]
fn key_tier_as_str_matches_snake_case_serde_wire_form() {
    let cases = [
        (KeyTier::Trial, "trial"),
        (KeyTier::Basic, "basic"),
        (KeyTier::Standard, "standard"),
        (KeyTier::Premium, "premium"),
    ];
    for (tier, want) in cases {
        assert_eq!(tier.as_str(), want);
        let wire = serde_json::to_value(tier).unwrap();
        assert_eq!(wire, serde_json::Value::String(want.to_string()));
    }
}
