//! `hse signal` — read the RF sighting database.
//!
//! A thin presenter over `storage::signal`: it resolves which scan to read,
//! picks a view, and formats. Every aggregate is computed in SQL, so this file
//! holds no analysis of its own and cannot disagree with what a direct query
//! would return.

use crate::core::error::Result;
use crate::core::link::{Disruption, DisruptionReport, HeardAp, LinkSweep, review};
use crate::core::port::StoragePort as _;
use crate::core::rf::{RadioKind, RfDeviceRow, RfSummary};
use crate::storage::Store;

/// Which view the flags selected. Resolved once so the precedence between
/// mutually-exclusive-ish flags is stated in one place rather than implied by
/// the order of a chain of `if`s.
enum View {
    Summary,
    Devices { trackable_only: bool },
    Names,
    Track(String),
}

/// Format a signal level for a column, or `—` where the receiver reported none.
/// A missing reading is not zero: 0 dBm would be an implausibly strong signal.
fn dbm(v: Option<f64>) -> String {
    v.map_or_else(|| "—".to_string(), |s| format!("{s:.0}"))
}

/// Clip to a column width on a char boundary. A vendor name from the IEEE
/// registry can be far wider than the column and may contain multi-byte
/// characters, so slicing by byte index would panic.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    s.chars().take(width.saturating_sub(1)).collect::<String>() + "…"
}

fn radio_label(r: RadioKind) -> &'static str {
    match r {
        RadioKind::Wifi => "wifi",
        RadioKind::Ble => "ble",
        RadioKind::BtClassic => "bt",
        RadioKind::Cellular => "cell",
    }
}

/// `fixed` / `random` / `—`, the distinction that decides whether recurrence
/// across sightings means anything at all (AU-122).
fn address_label(la: Option<bool>) -> &'static str {
    match la {
        Some(true) => "random",
        Some(false) => "fixed",
        None => "—",
    }
}

/// The JSON shape of one device row — THE one presenter, shared by
/// `hse signal --devices --json` and `GET /api/v1/radar/signals`, so the CLI
/// and the web reader cannot disagree about a field's name or spelling. The
/// SPA's Radar view reads these names; a rename here is an API change.
#[must_use]
pub fn device_json(d: &RfDeviceRow) -> serde_json::Value {
    serde_json::json!({
        "network_id": d.network_id,
        "radio": radio_label(d.radio),
        "address": address_label(d.locally_administered),
        "oui": d.oui,
        "vendor": d.vendor,
        "device_class": d.device_class,
        "name": d.name,
        "sightings": d.sightings,
        "distinct_fixes": d.distinct_fixes,
        "best_signal_dbm": d.best_signal_dbm,
        "worst_signal_dbm": d.worst_signal_dbm,
        "latitude": d.best_latitude,
        "longitude": d.best_longitude,
        "first_epoch": d.first_epoch,
        "last_epoch": d.last_epoch,
    })
}

/// The JSON shape of a scan's sighting summary — shared by `hse signal --json`
/// and `GET /api/v1/radar/signals` the same way as [`device_json`].
#[must_use]
pub fn summary_json(scan_id: &str, s: &RfSummary) -> serde_json::Value {
    serde_json::json!({
        "scan_id": scan_id,
        "sightings": s.sightings,
        "devices": s.devices,
        "wifi": s.wifi, "ble": s.ble, "bt": s.bt, "cellular": s.cellular,
        "fixed_address": s.fixed_address,
        "randomised_address": s.randomised_address,
        "named": s.named,
        "with_position": s.with_position,
        "first_epoch": s.first_epoch,
        "last_epoch": s.last_epoch,
    })
}

fn print_devices(rows: &[RfDeviceRow], limit: usize, json: bool) {
    if json {
        let out: Vec<_> = rows.iter().take(limit).map(device_json).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string())
        );
        return;
    }
    println!(
        "  {:<18} {:<5} {:<7} {:>5} {:>5}  {:<26} NAME",
        "NETWORK ID", "RADIO", "ADDRESS", "DBM", "SEEN", "VENDOR"
    );
    for d in rows.iter().take(limit) {
        println!(
            "  {:<18} {:<5} {:<7} {:>5} {:>5}  {:<26} {}",
            d.network_id,
            radio_label(d.radio),
            address_label(d.locally_administered),
            dbm(d.best_signal_dbm),
            d.sightings,
            // The source-reported device class where there is one, else the
            // vendor. They answer different questions — what the device IS
            // versus who made it — but only one column fits, and a class is the
            // more specific answer when available.
            truncate(d.device_class.as_deref().or(d.vendor).unwrap_or("—"), 26,),
            d.name.as_deref().unwrap_or("—"),
        );
    }
    // Never let a cap read as completeness: say what was withheld.
    if rows.len() > limit {
        println!("  … and {} more (raise --limit)", rows.len() - limit);
    }
}

/// The sweep history as the disruption review reads it — one [`LinkSweep`]
/// per radar sweep that recorded a link, with the access points it heard —
/// plus the count of sweeps that recorded none (from before the record
/// existed, or without `device_sensors`), which are left out rather than
/// guessed. ONE assembly, shared by `hse signal --disruptions` and
/// `GET /api/v1/radar/disruptions`, so the shell and the page review the
/// same sweeps.
pub fn link_sweeps_from_history(
    store: &dyn crate::core::StoragePort,
    limit: usize,
) -> Result<(Vec<LinkSweep>, usize)> {
    let scans = store.radar_history(limit.max(1))?;
    let mut sweeps: Vec<LinkSweep> = Vec::with_capacity(scans.len());
    let mut unrecorded = 0usize;
    // The history is newest first with creation order breaking a same-second
    // tie; reversed, it is the order the review keeps for equal seconds.
    for scan in scans.iter().rev() {
        let Some(link) = store.wifi_link_for_scan(&scan.id)? else {
            unrecorded += 1;
            continue;
        };
        let heard: Vec<HeardAp> = store
            .rf_devices_for_scan(&scan.id)?
            .into_iter()
            .filter(|d| d.radio == RadioKind::Wifi)
            .map(|d| HeardAp {
                bssid: d.network_id,
                ssid: d.name,
                signal_dbm: d.best_signal_dbm,
            })
            .collect();
        sweeps.push(LinkSweep {
            scan_id: scan.id.clone(),
            ts: scan.started_at,
            link,
            heard,
        });
    }
    Ok((sweeps, unrecorded))
}

/// The review as JSON — the report's counts, `unrecorded_sweeps`, and every
/// finding with its `advice` beside it. THE one shape, for `--json` and the
/// API alike.
#[must_use]
pub fn disruption_report_json(report: &DisruptionReport, unrecorded: usize) -> serde_json::Value {
    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut v = serde_json::to_value(f).unwrap_or(serde_json::Value::Null);
            if let serde_json::Value::Object(m) = &mut v {
                m.insert(
                    "advice".to_string(),
                    serde_json::Value::String(f.advice().to_string()),
                );
            }
            v
        })
        .collect();
    serde_json::json!({
        "sweeps": report.sweeps,
        "connected_sweeps": report.connected_sweeps,
        "disconnected_sweeps": report.disconnected_sweeps,
        "unrecorded_sweeps": unrecorded,
        "findings": findings,
        "count": report.findings.len(),
    })
}

/// `hse signal --disruptions` (REQ-RESILIENCE-002), plus the live
/// network-path check (REQ-RESILIENCE-003) when `live` is set — the same
/// opt-in gate `hse doctor --live` uses, since this is a live network probe,
/// not a database read: the default `--disruptions` run stays offline.
async fn print_disruptions(store: &Store, limit: usize, live: bool, json: bool) -> Result<()> {
    let (sweeps, unrecorded) = link_sweeps_from_history(store, limit)?;
    let report = review(&sweeps);
    let outage = if live {
        Some(crate::core::outage::classify(
            &crate::app::outage::collect().await,
        ))
    } else {
        None
    };
    if json {
        let mut v = disruption_report_json(&report, unrecorded);
        if let Some(o) = &outage
            && let serde_json::Value::Object(m) = &mut v
        {
            m.insert(
                "outage".to_string(),
                crate::app::outage::outage_report_json(o),
            );
        }
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(());
    }
    if let Some(o) = &outage {
        println!("Network path: {:?} — {}", o.kind, o.evidence);
        if o.kind != crate::core::outage::OutageKind::Clear {
            println!("  {}", o.advice());
        }
    }
    println!(
        "Wi-Fi link across {} sweep(s): {} connected, {} off the network{}",
        report.sweeps,
        report.connected_sweeps,
        report.disconnected_sweeps,
        if unrecorded > 0 {
            format!(" ({unrecorded} older sweep(s) recorded no link and are not reviewed)")
        } else {
            String::new()
        }
    );
    if report.findings.is_empty() {
        println!("  No disruption found.");
        return Ok(());
    }
    for f in &report.findings {
        let line = match f {
            Disruption::ForcedDisconnect {
                at,
                bssid,
                ssid,
                heard_dbm,
                ..
            } => format!(
                "FORCED DISCONNECT  epoch {at}: off {} ({bssid}) while it was still heard at {heard_dbm:.0} dBm",
                ssid.as_deref().unwrap_or("?")
            ),
            Disruption::DeauthSuspected {
                from,
                to,
                count,
                bssid,
                ssid,
            } => format!(
                "DEAUTH SUSPECTED   {count} forced disconnections from {} ({bssid}) between epoch {from} and {to}",
                ssid.as_deref().unwrap_or("?")
            ),
            Disruption::EvilTwinSuspected {
                at,
                ssid,
                new_bssid,
                new_dbm,
                known_bssid,
                known_dbm,
                ..
            } => format!(
                "EVIL TWIN?         epoch {at}: {ssid} from new {new_bssid} at {new_dbm:.0} dBm, louder than known {known_bssid} at {known_dbm:.0} dBm"
            ),
            Disruption::PeriodicOutage {
                period_secs,
                occurrences,
                from,
                to,
            } => format!(
                "PERIODIC OUTAGE    {occurrences} outages every ~{period_secs} s, epoch {from} → {to}"
            ),
            Disruption::Outage { from, to, sweeps } => {
                format!("outage             {sweeps} sweep(s) off the network, epoch {from} → {to}")
            }
        };
        println!("  {line}");
        println!("      {}", f.advice());
    }
    Ok(())
}

/// CLI entry.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub async fn cmd_signal(
    scan_id: Option<String>,
    devices: bool,
    trackable: bool,
    names: bool,
    track: Option<String>,
    disruptions: bool,
    live: bool,
    limit: usize,
    json: bool,
) -> Result<()> {
    let store = Store::open(&crate::default_db_path())?;

    // The disruption review is over the sweep HISTORY, not one scan, so it
    // resolves no scan id and outranks every per-scan view.
    if disruptions {
        return print_disruptions(&store, limit, live, json).await;
    }

    let sid = match scan_id {
        Some(s) => s,
        None => match store.rf_latest_scan_id()? {
            Some(s) => s,
            None => {
                println!(
                    "No RF sightings recorded yet. Import a wardriving capture \
                     (`hse import <file.kml>`) or run a radar sweep first."
                );
                return Ok(());
            }
        },
    };

    // `--track` names one device and so outranks the list views; `--trackable`
    // narrows `--devices` rather than competing with it.
    let view = match (track, devices || trackable, names) {
        (Some(id), _, _) => View::Track(id),
        (None, true, _) => View::Devices {
            trackable_only: trackable,
        },
        (None, false, true) => View::Names,
        (None, false, false) => View::Summary,
    };

    match view {
        View::Summary => {
            let s = store.rf_summary(&sid)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary_json(&sid, &s)).unwrap_or_default()
                );
                return Ok(());
            }
            println!("RF sightings — scan {sid}");
            println!("  Sightings: {}", s.sightings);
            println!("  Devices:   {}", s.devices);
            println!(
                "  Radios:    {} wifi, {} ble, {} bt, {} cellular",
                s.wifi, s.ble, s.bt, s.cellular
            );
            println!(
                "  Address:   {} fixed hardware, {} randomised (rotating, not followable)",
                s.fixed_address, s.randomised_address
            );
            println!("  Named:     {}", s.named);
            println!("  Located:   {} with a usable fix", s.with_position);
            if let (Some(a), Some(b)) = (s.first_epoch, s.last_epoch) {
                println!("  Window:    epoch {a} → {b} ({} s)", b - a);
            }
        }
        View::Devices { trackable_only } => {
            let rows = if trackable_only {
                store.rf_trackable_devices(&sid)?
            } else {
                store.rf_devices_for_scan(&sid)?
            };
            print_devices(&rows, limit, json);
        }
        View::Names => {
            let rows = store.rf_shared_names(&sid)?;
            if json {
                let out: Vec<_> = rows
                    .iter()
                    .take(limit)
                    .map(|(n, c)| serde_json::json!({ "name": n, "radios": c }))
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string())
                );
                return Ok(());
            }
            println!("  {:>6}  NAME", "RADIOS");
            for (name, radios) in rows.iter().take(limit) {
                println!("  {radios:>6}  {name}");
            }
            if rows.len() > limit {
                println!("  … and {} more (raise --limit)", rows.len() - limit);
            }
        }
        View::Track(id) => {
            let rows = store.rf_sightings_for_device(&sid, &id)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
                );
                return Ok(());
            }
            if rows.is_empty() {
                println!("No sightings of {id} in scan {sid}.");
                return Ok(());
            }
            println!("Sighting track — {id} in scan {sid}");
            println!(
                "  {:<26} {:>6}  {:>11} {:>11}  NAME",
                "OBSERVED AT", "DBM", "LATITUDE", "LONGITUDE"
            );
            for s in rows.iter().take(limit) {
                println!(
                    "  {:<26} {:>6}  {:>11} {:>11}  {}",
                    s.observed_at.as_deref().unwrap_or("—"),
                    dbm(s.signal_dbm),
                    s.latitude.map_or_else(|| "—".into(), |v| format!("{v:.6}")),
                    s.longitude
                        .map_or_else(|| "—".into(), |v| format!("{v:.6}")),
                    s.name.as_deref().unwrap_or("—"),
                );
            }
            if rows.len() > limit {
                println!("  … and {} more (raise --limit)", rows.len() - limit);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("signal_tests.rs");
}
