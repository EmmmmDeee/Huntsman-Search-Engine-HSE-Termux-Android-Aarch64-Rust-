//! `hse signal` — read the RF sighting database.
//!
//! A thin presenter over `storage::signal`: it resolves which scan to read,
//! picks a view, and formats. Every aggregate is computed in SQL, so this file
//! holds no analysis of its own and cannot disagree with what a direct query
//! would return.

use crate::core::error::Result;
use crate::core::rf::RadioKind;
use crate::storage::{RfDeviceRow, Store};

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

fn print_devices(rows: &[RfDeviceRow], limit: usize, json: bool) {
    if json {
        let out: Vec<_> = rows
            .iter()
            .take(limit)
            .map(|d| {
                serde_json::json!({
                    "network_id": d.network_id,
                    "radio": radio_label(d.radio),
                    "address": address_label(d.locally_administered),
                    "oui": d.oui,
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
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".to_string())
        );
        return;
    }
    println!(
        "  {:<18} {:<5} {:<7} {:>5} {:>5} {:>5}  {:<14} NAME",
        "NETWORK ID", "RADIO", "ADDRESS", "DBM", "SEEN", "FIXES", "CLASS"
    );
    for d in rows.iter().take(limit) {
        println!(
            "  {:<18} {:<5} {:<7} {:>5} {:>5} {:>5}  {:<14} {}",
            d.network_id,
            radio_label(d.radio),
            address_label(d.locally_administered),
            dbm(d.best_signal_dbm),
            d.sightings,
            d.distinct_fixes,
            d.device_class.as_deref().unwrap_or("—"),
            d.name.as_deref().unwrap_or("—"),
        );
    }
    // Never let a cap read as completeness: say what was withheld.
    if rows.len() > limit {
        println!("  … and {} more (raise --limit)", rows.len() - limit);
    }
}

/// CLI entry.
pub async fn cmd_signal(
    scan_id: Option<String>,
    devices: bool,
    trackable: bool,
    names: bool,
    track: Option<String>,
    limit: usize,
    json: bool,
) -> Result<()> {
    let store = Store::open(&crate::default_db_path())?;

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
                    serde_json::to_string_pretty(&serde_json::json!({
                        "scan_id": sid,
                        "sightings": s.sightings,
                        "devices": s.devices,
                        "wifi": s.wifi, "ble": s.ble, "bt": s.bt, "cellular": s.cellular,
                        "fixed_address": s.fixed_address,
                        "randomised_address": s.randomised_address,
                        "named": s.named,
                        "with_position": s.with_position,
                        "first_epoch": s.first_epoch,
                        "last_epoch": s.last_epoch,
                    }))
                    .unwrap_or_default()
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
