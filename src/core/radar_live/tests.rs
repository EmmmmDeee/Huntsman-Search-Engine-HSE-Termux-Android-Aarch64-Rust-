//! Live-radar reducer tests. Every case feeds synthetic [`SweepObservation`]
//! vectors — no Bluetooth radio, no terminal — so the whole state machine and
//! its defensive invariants run identically on this dev host and in CI, exactly
//! as `radar_track`'s gated tests already do.

use super::*;

/// Universally-administered (0x3C, U/L bit clear) — a real trackable device.
/// The same fixtures `radar_track`'s tests use, so the two models share one
/// notion of "trackable hardware".
const HW1: &str = "3C:5A:B4:11:22:33";
const HW2: &str = "3C:5A:B4:44:55:66";
/// Locally-administered (0x36, U/L bit set) — a rotating privacy address.
const RND: &str = "36:32:62:36:31:33";

fn obs(mac: &str) -> SweepObservation {
    SweepObservation {
        mac: mac.to_string(),
        name: None,
        bonded: false,
    }
}

fn named(mac: &str, name: &str) -> SweepObservation {
    SweepObservation {
        mac: mac.to_string(),
        name: Some(name.to_string()),
        bonded: false,
    }
}

fn bonded(mac: &str) -> SweepObservation {
    SweepObservation {
        mac: mac.to_string(),
        name: None,
        bonded: true,
    }
}

fn lc(mac: &str) -> String {
    mac.to_lowercase()
}

// ── the discrete-increment state machine ────────────────────────────────────

#[test]
fn a_trackable_device_walks_new_present_missing_departed() {
    let mut r = BtRadarState::default();

    // Tick 1: first sighting → New.
    let d1 = r.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
    assert_eq!(d1.new, vec![lc(HW1)], "first sighting is reported as new");
    assert!(d1.present.is_empty() && d1.missing.is_empty() && d1.departed.is_empty());
    assert_eq!(r.presence_of(HW1), Some(Presence::New));

    // Tick 2: seen again → Present (a continuing presence, not a fresh new).
    let d2 = r.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
    assert!(d2.new.is_empty(), "a continuing device is not new");
    assert_eq!(d2.present, vec![lc(HW1)]);
    assert_eq!(r.presence_of(HW1), Some(Presence::Present));

    // Tick 3: a read that does not see it → Missing(1), still tracked.
    let d3 = r.apply_tick(&[], BtReadOutcome::Read);
    assert_eq!(d3.missing, vec![lc(HW1)]);
    assert!(d3.departed.is_empty(), "one missed read is not a departure");
    assert_eq!(r.presence_of(HW1), Some(Presence::Missing(1)));

    // Tick 4: a second consecutive missed read → Departed, dropped from the map.
    let d4 = r.apply_tick(&[], BtReadOutcome::Read);
    assert_eq!(d4.departed, vec![lc(HW1)]);
    assert!(
        d4.missing.is_empty(),
        "a departure is not also reported as missing"
    );
    assert_eq!(
        r.presence_of(HW1),
        None,
        "a departed device is removed from the active map"
    );
}

#[test]
fn a_missing_device_seen_again_recovers_to_present() {
    // A single dropped BLE inquiry (advertising is bursty) must not lose a
    // stationary device: Missing → Present on the next read that sees it.
    let mut r = BtRadarState::default();
    r.apply_tick(&[obs(HW1)], BtReadOutcome::Read); // New
    r.apply_tick(&[], BtReadOutcome::Read); // Missing(1)
    assert_eq!(r.presence_of(HW1), Some(Presence::Missing(1)));

    let d = r.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
    assert_eq!(d.present, vec![lc(HW1)]);
    assert_eq!(r.presence_of(HW1), Some(Presence::Present));
}

#[test]
fn a_departed_device_reappearing_reads_as_new_again() {
    // Departed devices are forgotten, so a later re-sighting is a fresh New — a
    // bounded, correct re-track (never a lost observation).
    let mut r = BtRadarState::default();
    r.apply_tick(&[obs(HW1)], BtReadOutcome::Read); // New
    r.apply_tick(&[], BtReadOutcome::Read); // Missing(1)
    r.apply_tick(&[], BtReadOutcome::Read); // Departed → removed
    assert_eq!(r.presence_of(HW1), None);

    let d = r.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
    assert_eq!(d.new, vec![lc(HW1)], "a returned device re-enters as new");
    assert_eq!(r.presence_of(HW1), Some(Presence::New));
}

// ── the load-bearing defensive invariant ────────────────────────────────────

#[test]
fn randomized_mac_never_gets_a_persistent_track() {
    // A randomized privacy address rotates ~every 15 min, so tracking one across
    // ticks is meaningless AND a surveillance hazard. It is only ever counted as
    // an anonymous aggregate, never given a followable track — mirrors
    // radar_track::ignores_a_recurring_randomized_address.
    let mut r = BtRadarState::default();

    let d1 = r.apply_tick(&[obs(RND)], BtReadOutcome::Read);
    assert!(d1.new.is_empty() && d1.present.is_empty());
    assert_eq!(
        d1.randomized_seen, 1,
        "counted only as an anonymous aggregate"
    );
    assert!(r.is_empty(), "a randomized MAC is never a persistent track");

    let d2 = r.apply_tick(&[obs(RND)], BtReadOutcome::Read);
    assert_eq!(d2.randomized_seen, 1);
    assert!(r.is_empty());
    assert_eq!(
        r.presence_of(RND),
        None,
        "a randomized address is never plotted as a followable device"
    );
}

#[test]
fn a_bonded_device_is_the_operators_own_kit_not_a_track() {
    // The operator's paired car/earbuds/watch recur trivially and must never be
    // surfaced as a foreign device to follow.
    let mut r = BtRadarState::default();
    let d = r.apply_tick(&[bonded(HW1)], BtReadOutcome::Read);
    assert!(d.new.is_empty() && d.present.is_empty());
    assert_eq!(
        d.randomized_seen, 0,
        "own kit is not a rotating address either"
    );
    assert!(r.is_empty(), "a bonded device earns no track");
}

// ── read-vs-empty: absence of a reading is not absence of a device ───────────

#[test]
fn bt_not_read_is_distinct_from_nothing_nearby() {
    let mut r = BtRadarState::default();
    r.apply_tick(&[obs(HW1)], BtReadOutcome::Read); // HW1 New
    assert_eq!(r.presence_of(HW1), Some(Presence::New));

    // A tick where the radio was NOT read changes NOTHING — it must not age a
    // present device toward missing (the radios simply were not listened to).
    let dnr = r.apply_tick(&[], BtReadOutcome::NotRead);
    assert_eq!(dnr.read, BtReadOutcome::NotRead);
    assert!(
        dnr.new.is_empty()
            && dnr.present.is_empty()
            && dnr.missing.is_empty()
            && dnr.departed.is_empty()
            && dnr.randomized_seen == 0,
        "a not-read tick observes nothing and changes nothing: {dnr:?}"
    );
    assert_eq!(
        r.presence_of(HW1),
        Some(Presence::New),
        "not-read must not age the device"
    );

    // A genuine read that sees nothing DOES age it — this is the real empty.
    let dr = r.apply_tick(&[], BtReadOutcome::Read);
    assert_eq!(dr.read, BtReadOutcome::Read);
    assert_eq!(
        dr.missing,
        vec![lc(HW1)],
        "a read that sees nothing ages a previously-present device"
    );
    assert_eq!(r.presence_of(HW1), Some(Presence::Missing(1)));
}

// ── enrichment + ordering + bounds ───────────────────────────────────────────

#[test]
fn a_track_carries_vendor_class_and_a_cleaned_name() {
    let mut r = BtRadarState::default();
    // A real name is kept; the `<unknown>` placeholder and blanks are dropped
    // (matching radar_track's name filter).
    r.apply_tick(
        &[named(HW1, "Pixel Buds"), named(HW2, "<unknown>")],
        BtReadOutcome::Read,
    );

    let ranked = r.tracks_ranked();
    let hw1 = ranked
        .iter()
        .find(|t| t.mac == lc(HW1))
        .expect("HW1 tracked");
    assert_eq!(hw1.name.as_deref(), Some("Pixel Buds"));
    assert!(
        hw1.vendor.is_some(),
        "a registered OUI classifies to a vendor"
    );
    assert!(hw1.device_class.is_some());

    let hw2 = ranked
        .iter()
        .find(|t| t.mac == lc(HW2))
        .expect("HW2 tracked");
    assert_eq!(hw2.name, None, "the <unknown> placeholder is dropped");
}

#[test]
fn tracks_are_ranked_most_persistent_first() {
    let mut r = BtRadarState::default();
    // HW1 seen twice, HW2 once → HW1 ranks first (higher sweeps_seen).
    r.apply_tick(&[obs(HW1)], BtReadOutcome::Read);
    r.apply_tick(&[obs(HW1), obs(HW2)], BtReadOutcome::Read);

    let ranked = r.tracks_ranked();
    assert_eq!(ranked.len(), 2);
    assert_eq!(
        ranked[0].mac,
        lc(HW1),
        "the more-persistent device ranks first"
    );
    assert_eq!(ranked[0].sweeps_seen, 2);
    assert_eq!(ranked[1].mac, lc(HW2));
    assert_eq!(ranked[1].sweeps_seen, 1);
}

#[test]
fn the_track_map_never_exceeds_capacity() {
    // A dense environment (a station concourse, a stadium) can present far more
    // distinct devices AT ONCE than the cap; the map must stay bounded (evicting
    // oldest-first) rather than OOM the phone.
    //
    // All devices are presented in a SINGLE tick on purpose: spreading them over
    // successive ticks would age each one out via the missed-read/departure path
    // (which is itself correct, and is what keeps a *moving* session bounded), so
    // it would never actually exercise the capacity ceiling this test is for.
    let cap = 8;
    let mut r = BtRadarState::with_capacity(cap);
    // Distinct universally-administered MACs (the 0x3C first octet keeps the U/L
    // bit clear, so every one is trackable hardware).
    let macs: Vec<String> = (0..(cap as u32) * 20)
        .map(|i| {
            format!(
                "3C:5A:B4:{:02X}:{:02X}:{:02X}",
                (i >> 16) & 0xFF,
                (i >> 8) & 0xFF,
                i & 0xFF
            )
        })
        .collect();
    let sightings: Vec<SweepObservation> = macs.iter().map(|m| obs(m)).collect();

    r.apply_tick(&sightings, BtReadOutcome::Read);
    assert_eq!(
        r.len(),
        cap,
        "a saturated map sits exactly at capacity, not {}",
        r.len()
    );
}

#[test]
fn a_moving_session_stays_bounded_as_devices_are_left_behind() {
    // The other half of bounding, and the common case on foot/in traffic: each
    // tick presents a different device, so the previous ones age out through
    // Missing → Departed and are dropped. The map self-limits well below the cap
    // without ever evicting a device that is still in view.
    let mut r = BtRadarState::with_capacity(4_096);
    for i in 0..200u32 {
        let mac = format!(
            "3C:5A:B4:{:02X}:{:02X}:{:02X}",
            (i >> 16) & 0xFF,
            (i >> 8) & 0xFF,
            i & 0xFF
        );
        r.apply_tick(&[obs(&mac)], BtReadOutcome::Read);
        assert!(
            r.len() <= 2,
            "a passed-by device must depart, not accumulate: {} tracked at i={i}",
            r.len()
        );
    }
}

#[test]
#[should_panic(expected = "zero-capacity")]
fn zero_capacity_is_rejected_in_every_build() {
    let _ = BtRadarState::with_capacity(0);
}

#[test]
fn blank_and_null_macs_are_ignored() {
    let mut r = BtRadarState::default();
    let d = r.apply_tick(&[obs("   "), obs("")], BtReadOutcome::Read);
    assert!(
        d.new.is_empty() && r.is_empty(),
        "blank MACs are never tracked"
    );
}
