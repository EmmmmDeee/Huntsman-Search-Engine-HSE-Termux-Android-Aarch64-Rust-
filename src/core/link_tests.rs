// Tests for the disruption review. Plain `//`: `include!`d into a `mod tests`.

use super::*;

const AP: &str = "00:1a:2b:3c:4d:5e";
const OTHER: &str = "00:1a:2b:3c:4d:99";

fn connected(scan: &str, ts: u64, heard_dbm: f64) -> LinkSweep {
    LinkSweep {
        scan_id: scan.to_string(),
        ts,
        link: LinkState {
            connected: true,
            ssid: Some("LabNet".to_string()),
            bssid: Some(AP.to_string()),
            signal_dbm: Some(heard_dbm),
            ip: Some("192.168.1.20".to_string()),
            link_speed_mbps: Some(433),
            supplicant_state: Some("COMPLETED".to_string()),
            observed_epoch: Some(i64::try_from(ts).unwrap()),
        },
        heard: vec![HeardAp {
            bssid: AP.to_string(),
            ssid: Some("LabNet".to_string()),
            signal_dbm: Some(heard_dbm),
        }],
    }
}

fn off(scan: &str, ts: u64, heard: Option<f64>) -> LinkSweep {
    LinkSweep {
        scan_id: scan.to_string(),
        ts,
        link: LinkState::disconnected(Some(i64::try_from(ts).unwrap())),
        heard: heard
            .map(|d| {
                vec![HeardAp {
                    bssid: AP.to_string(),
                    ssid: Some("LabNet".to_string()),
                    signal_dbm: Some(d),
                }]
            })
            .unwrap_or_default(),
    }
}

fn kinds(r: &DisruptionReport) -> Vec<&'static str> {
    r.findings
        .iter()
        .map(|f| match f {
            Disruption::ForcedDisconnect { .. } => "forced",
            Disruption::DeauthSuspected { .. } => "deauth",
            Disruption::EvilTwinSuspected { .. } => "twin",
            Disruption::PeriodicOutage { .. } => "periodic",
            Disruption::Outage { .. } => "outage",
        })
        .collect()
}

#[test]
fn a_drop_while_the_access_point_is_still_loud_is_forced_and_a_fade_is_only_an_outage() {
    // Connected, then off with the AP heard at −50: cut, not faded.
    let r = review(&[connected("s1", 100, -45.0), off("s2", 200, Some(-50.0))]);
    assert_eq!(kinds(&r), ["forced", "outage"], "{r:?}");
    assert!(matches!(
        &r.findings[0],
        Disruption::ForcedDisconnect { at: 200, bssid, heard_dbm, ssid: Some(s), .. }
            if bssid == AP && *heard_dbm == -50.0 && s == "LabNet"
    ));
    assert_eq!((r.sweeps, r.connected_sweeps, r.disconnected_sweeps), (2, 1, 1));

    // CONTROL: off with the AP heard at −85 (below FORCED_MIN_DBM) — a fade.
    let r = review(&[connected("s1", 100, -45.0), off("s2", 200, Some(-85.0))]);
    assert_eq!(kinds(&r), ["outage"], "{r:?}");
    // CONTROL: off with the AP not heard at all — out of range.
    let r = review(&[connected("s1", 100, -45.0), off("s2", 200, None)]);
    assert_eq!(kinds(&r), ["outage"], "{r:?}");
}

#[test]
fn three_forced_drops_within_an_hour_are_a_deauthentication_pattern_and_spread_out_they_are_not() {
    let mut sweeps = Vec::new();
    for (i, t) in [100u64, 700, 1300].iter().enumerate() {
        sweeps.push(connected(&format!("c{i}"), *t, -45.0));
        sweeps.push(off(&format!("o{i}"), t + 60, Some(-48.0)));
    }
    let r = review(&sweeps);
    assert!(
        r.findings.iter().any(|f| matches!(f, Disruption::DeauthSuspected { count: 3, bssid, .. } if bssid == AP)),
        "{r:?}"
    );
    // CONTROL: the same three, four hours apart.
    let mut sweeps = Vec::new();
    for (i, t) in [100u64, 15_000, 30_000].iter().enumerate() {
        sweeps.push(connected(&format!("c{i}"), *t, -45.0));
        sweeps.push(off(&format!("o{i}"), t + 60, Some(-48.0)));
    }
    let r = review(&sweeps);
    assert!(!kinds(&r).contains(&"deauth"), "{r:?}");
    assert_eq!(kinds(&r).iter().filter(|k| **k == "forced").count(), 3);
}

#[test]
fn a_known_name_from_a_new_louder_address_is_a_twin_and_a_known_second_address_is_not() {
    let mut twin = connected("s2", 200, -60.0);
    twin.heard.push(HeardAp {
        bssid: OTHER.to_string(),
        ssid: Some("LabNet".to_string()),
        signal_dbm: Some(-40.0),
    });
    let r = review(&[connected("s1", 100, -60.0), twin.clone()]);
    assert_eq!(kinds(&r), ["twin"], "{r:?}");
    assert!(matches!(
        &r.findings[0],
        Disruption::EvilTwinSuspected { new_bssid, known_bssid, new_dbm, known_dbm, .. }
            if new_bssid == OTHER && known_bssid == AP && *new_dbm == -40.0 && *known_dbm == -60.0
    ));

    // CONTROL: the second address was heard before (a mesh, a second AP) —
    // nothing new is impersonating anything.
    let mut first = connected("s1", 100, -60.0);
    first.heard.push(HeardAp {
        bssid: OTHER.to_string(),
        ssid: Some("LabNet".to_string()),
        signal_dbm: Some(-70.0),
    });
    let r = review(&[first, twin.clone()]);
    assert!(kinds(&r).is_empty(), "{r:?}");

    // CONTROL: new but weaker than the known one — a far site, not a lure.
    let mut weak = connected("s2", 200, -50.0);
    weak.heard.push(HeardAp {
        bssid: OTHER.to_string(),
        ssid: Some("LabNet".to_string()),
        signal_dbm: Some(-80.0),
    });
    let r = review(&[connected("s1", 100, -50.0), weak]);
    assert!(kinds(&r).is_empty(), "{r:?}");
}

#[test]
fn outages_that_begin_on_a_schedule_are_periodic_and_irregular_ones_are_not() {
    // Every 600 s ± a little: c/o pairs whose outage starts sit at 700, 1290, 1910, 2500.
    let mut sweeps = vec![connected("c0", 100, -45.0)];
    for (i, t) in [700u64, 1290, 1910, 2500].iter().enumerate() {
        sweeps.push(off(&format!("o{i}"), *t, None));
        sweeps.push(connected(&format!("c{}", i + 1), t + 100, -45.0));
    }
    let r = review(&sweeps);
    assert!(
        r.findings.iter().any(|f| matches!(f, Disruption::PeriodicOutage { period_secs, occurrences: 4, .. } if (590..=620).contains(period_secs))),
        "{r:?}"
    );
    // CONTROL: 600, 1800, 300 apart — no schedule.
    let mut sweeps = vec![connected("c0", 100, -45.0)];
    for (i, t) in [700u64, 1300, 3100, 3400].iter().enumerate() {
        sweeps.push(off(&format!("o{i}"), *t, None));
        sweeps.push(connected(&format!("c{}", i + 1), t + 100, -45.0));
    }
    let r = review(&sweeps);
    assert!(!kinds(&r).contains(&"periodic"), "{r:?}");
}

#[test]
fn the_review_orders_sweeps_itself_and_counts_the_timeline() {
    // Newest first in, and a history that starts off the network.
    let r = review(&[
        connected("s3", 300, -45.0),
        off("s2", 200, None),
        off("s1", 100, None),
    ]);
    assert_eq!((r.sweeps, r.connected_sweeps, r.disconnected_sweeps), (3, 1, 2));
    assert_eq!(kinds(&r), ["outage"]);
    assert!(matches!(
        r.findings[0],
        Disruption::Outage { from: 100, to: 200, sweeps: 2 }
    ));
    assert!(review(&[]).findings.is_empty());

    // The same second: `ts` cannot order these, so the order GIVEN is kept —
    // a drop after a connected sweep is forced; the reverse order is a
    // history that begins off the network and then connects.
    let r = review(&[connected("a", 500, -45.0), off("b", 500, Some(-45.0))]);
    assert_eq!(kinds(&r), ["forced", "outage"], "{r:?}");
    let r = review(&[off("b", 500, Some(-45.0)), connected("a", 500, -45.0)]);
    assert_eq!(kinds(&r), ["outage"], "{r:?}");
}

#[test]
fn every_finding_carries_advice_and_serialises_by_kind() {
    let r = review(&[connected("s1", 100, -45.0), off("s2", 200, Some(-50.0))]);
    for f in &r.findings {
        assert!(!f.advice().is_empty());
    }
    let json = serde_json::to_value(&r.findings[0]).unwrap();
    assert_eq!(json["kind"], "forced_disconnect");
    assert_eq!(json["bssid"], AP);
}
