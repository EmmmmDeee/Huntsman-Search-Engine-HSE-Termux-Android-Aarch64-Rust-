//! `GET /api/v1/radar` — real-time signal environment snapshot.
//!
//! Runs five sensor probes in parallel via [`tokio::join!`] and returns a
//! [`RadarSnapshot`] JSON object with WiFi APs, Bluetooth devices, cell
//! towers, LAN hosts from `/proc/net/arp`, and the current GPS fix.
//!
//! All probes are best-effort: a missing permission, absent tool, or timeout
//! silently yields an empty list/`null` for that section rather than failing
//! the whole request.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use serde_json::Value;

use crate::util::termux::termux_cmd;

// ─── Response types ────────────────────────────────────────────────────────

/// A single WiFi access point returned by `termux-wifi-scaninfo`.
#[derive(Debug, Serialize)]
pub struct WifiAp {
    /// BSSID (MAC address of the access point).
    pub bssid: String,
    /// Human-readable network name, or `<hidden>` when not broadcast.
    pub ssid: String,
    /// Received signal strength in dBm (higher is better; e.g. -50 is excellent).
    pub rssi: i32,
    /// Channel centre frequency in MHz (e.g. 2412 for 2.4 GHz ch 1).
    pub frequency_mhz: u32,
    /// Channel bandwidth in MHz (20/40/80/160).
    pub channel_width_mhz: u32,
}

/// A single Bluetooth device returned by `termux-bluetooth-scaninfo`.
#[derive(Debug, Serialize)]
pub struct BtDevice {
    /// Bluetooth MAC address.
    pub address: String,
    /// Advertised device name, or `<unknown>`.
    pub name: String,
    /// Device class string (e.g. `CLASSIC`, `LE`, `DUAL`).
    pub device_type: String,
    /// Pairing state (`NONE`, `BONDING`, `BONDED`).
    pub bond_state: String,
}

/// A single cell tower entry returned by `termux-telephony-cellinfo`.
#[derive(Debug, Serialize)]
pub struct CellTower {
    /// Radio technology string in lowercase (e.g. `lte`, `nr`, `gsm`).
    pub technology: String,
    /// Whether this is the serving (registered) cell.
    pub registered: bool,
    /// Mobile Country Code.
    pub mcc: Option<i64>,
    /// Mobile Network Code.
    pub mnc: Option<i64>,
    /// Cell Identity (LTE CI or GSM CID).
    pub cid: Option<i64>,
    /// Location Area Code (GSM) / Tracking Area Code (LTE/NR).
    pub lac_tac: Option<i64>,
    /// Signal strength in dBm.
    pub dbm: Option<i32>,
    /// Android signal level 0–4.
    pub level: Option<i32>,
}

/// A host visible in `/proc/net/arp` (complete ARP entries only).
#[derive(Debug, Serialize)]
pub struct LanHost {
    /// IPv4 address.
    pub ip: String,
    /// Hardware (MAC) address.
    pub mac: String,
}

/// GPS/network location fix from `termux-location`.
#[derive(Debug, Serialize)]
pub struct GpsFix {
    /// WGS-84 latitude in decimal degrees.
    pub latitude: f64,
    /// WGS-84 longitude in decimal degrees.
    pub longitude: f64,
    /// Altitude in metres above the WGS-84 ellipsoid, if available.
    pub altitude: Option<f64>,
    /// Horizontal accuracy radius in metres (68% confidence), if available.
    pub accuracy_m: Option<f64>,
    /// Location provider (`gps`, `network`, `passive`, …).
    pub provider: String,
}

/// Aggregated signal-environment snapshot returned by `GET /api/v1/radar`.
#[derive(Debug, Serialize)]
pub struct RadarSnapshot {
    /// WiFi access points visible to the device.
    pub wifi_aps: Vec<WifiAp>,
    /// Bluetooth devices discovered during the scan window.
    pub bluetooth_devices: Vec<BtDevice>,
    /// Cell towers reported by the modem.
    pub cell_towers: Vec<CellTower>,
    /// LAN hosts with complete ARP entries in `/proc/net/arp`.
    pub lan_hosts: Vec<LanHost>,
    /// Best available location fix, or `null` when unavailable.
    pub gps: Option<GpsFix>,
    /// Unix timestamp (seconds) when this snapshot was collected.
    pub scanned_at: u64,
}

// ─── Parsers ──────────────────────────────────────────────────────────────

fn parse_wifi(stdout: &[u8]) -> Vec<WifiAp> {
    let aps: Vec<Value> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for ap in aps {
        let bssid = ap["bssid"].as_str().unwrap_or("").to_string();
        if bssid.is_empty() || bssid == "00:00:00:00:00:00" || bssid == "02:00:00:00:00:00" {
            continue;
        }
        out.push(WifiAp {
            bssid,
            ssid: ap["ssid"].as_str().unwrap_or("<hidden>").to_string(),
            rssi: ap["rssi"].as_i64().unwrap_or(-100) as i32,
            frequency_mhz: ap["frequency"].as_u64().unwrap_or(0) as u32,
            channel_width_mhz: ap["channel_width"].as_u64().unwrap_or(0) as u32,
        });
    }
    out
}

fn parse_bluetooth(stdout: &[u8]) -> Vec<BtDevice> {
    let devs: Vec<Value> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for d in devs {
        let addr = d["address"].as_str().unwrap_or("").to_string();
        if addr.is_empty() || addr == "00:00:00:00:00:00" {
            continue;
        }
        out.push(BtDevice {
            address: addr,
            name: d["name"].as_str().unwrap_or("<unknown>").to_string(),
            device_type: d["type"].as_str().unwrap_or("UNKNOWN").to_string(),
            bond_state: d["bondState"].as_str().unwrap_or("NONE").to_string(),
        });
    }
    out
}

fn val_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn parse_cell(stdout: &[u8]) -> Vec<CellTower> {
    let cells: Vec<Value> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for c in cells {
        let mcc = val_as_i64(&c["mcc"]);
        let mnc = val_as_i64(&c["mnc"]);
        // skip entries with no usable network identifier
        if mcc.is_none() && mnc.is_none() {
            continue;
        }
        let cid = val_as_i64(&c["ci"]).or_else(|| val_as_i64(&c["cid"]));
        let lac_tac = val_as_i64(&c["tac"]).or_else(|| val_as_i64(&c["lac"]));
        out.push(CellTower {
            technology: c["type"].as_str().unwrap_or("unknown").to_lowercase(),
            registered: c["registered"].as_bool().unwrap_or(false),
            mcc,
            mnc,
            cid,
            lac_tac,
            dbm: c["dbm"].as_i64().map(|n| n as i32),
            level: c["level"].as_i64().map(|n| n as i32),
        });
    }
    out
}

fn parse_arp(text: &str) -> Vec<LanHost> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        // Format: IP  HW_TYPE  FLAGS  MAC  MASK  IFACE
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = parts[0];
        let flags = parts[2];
        let mac = parts[3];
        // 0x2 = ATF_COM (complete entry)
        if flags != "0x2" || mac == "00:00:00:00:00:00" {
            continue;
        }
        out.push(LanHost {
            ip: ip.to_owned(),
            mac: mac.to_owned(),
        });
    }
    out
}

fn parse_gps(stdout: &[u8]) -> Option<GpsFix> {
    let v: Value = serde_json::from_slice(stdout).ok()?;
    let lat = v["latitude"].as_f64()?;
    let lon = v["longitude"].as_f64()?;
    // Sanity-check: valid WGS-84 range.
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some(GpsFix {
        latitude: lat,
        longitude: lon,
        altitude: v["altitude"].as_f64(),
        accuracy_m: v["accuracy"].as_f64(),
        provider: v["provider"].as_str().unwrap_or("unknown").to_string(),
    })
}

// ─── Handler ──────────────────────────────────────────────────────────────

/// `GET /api/v1/radar` — collect a real-time signal-environment snapshot.
///
/// All five probes run concurrently via [`tokio::join!`]. Unavailable sensors
/// (missing Termux permission, no GPS fix, no Bluetooth adapter) return empty
/// lists / `null` without failing the request. The full response is a
/// [`RadarSnapshot`] JSON object.
pub async fn radar_scan() -> impl IntoResponse {
    let (wifi_raw, bt_raw, cell_raw, arp_result, gps_raw) = tokio::join!(
        termux_cmd("termux-wifi-scaninfo", &[], 8_000),
        termux_cmd("termux-bluetooth-scaninfo", &[], 10_000),
        termux_cmd("termux-telephony-cellinfo", &[], 5_000),
        tokio::fs::read_to_string("/proc/net/arp"),
        termux_cmd("termux-location", &["-p", "gps", "-r", "once"], 12_000),
    );

    let wifi_aps = wifi_raw.as_deref().map(parse_wifi).unwrap_or_default();
    let bluetooth_devices = bt_raw.as_deref().map(parse_bluetooth).unwrap_or_default();
    let cell_towers = cell_raw.as_deref().map(parse_cell).unwrap_or_default();
    let lan_hosts = arp_result.as_deref().map(parse_arp).unwrap_or_default();
    let gps = gps_raw.as_deref().and_then(parse_gps);

    let scanned_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let snapshot = RadarSnapshot {
        wifi_aps,
        bluetooth_devices,
        cell_towers,
        lan_hosts,
        gps,
        scanned_at,
    };

    (StatusCode::OK, Json(snapshot)).into_response()
}
