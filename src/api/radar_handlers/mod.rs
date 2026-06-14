//! `GET /api/v1/radar` — real-time RF + LAN + GPS snapshot.
//!
//! Runs all sensor sub-scans in parallel via [`tokio::join!`] and returns a
//! single [`RadarSnapshot`] JSON object. Falls back gracefully when
//! Termux-API is absent or a permission has not been granted — the relevant
//! field is simply `null` / an empty array.
//!
//! Typical latency: bounded by the slowest sub-scan (GPS at 10 s maximum);
//! WiFi and cell are done by the 5 s mark, BT by 8 s.

use axum::Json;
use serde::Serialize;
use serde_json::Value;

use crate::util::termux::termux_cmd;

// ── Response structs ──────────────────────────────────────────────────────────

/// Top-level payload returned by `GET /api/v1/radar`.
#[derive(Serialize)]
pub struct RadarSnapshot {
    /// Nearby WiFi access points (from `termux-wifi-scaninfo`).
    pub wifi: Vec<WifiAp>,
    /// Nearby Bluetooth devices (from `termux-bluetooth-scaninfo`).
    pub bluetooth: Vec<BtDevice>,
    /// Visible cellular towers (from `termux-telephony-cellinfo`).
    pub cell: Vec<CellTower>,
    /// Hosts visible on the local network (from `/proc/net/arp`).
    pub lan: Vec<LanHost>,
    /// Best available GPS fix (from `termux-location -p network -r once`),
    /// or `None` when location permission is denied or no fix is available.
    pub gps: Option<GpsFix>,
}

/// One WiFi access point record.
#[derive(Serialize)]
pub struct WifiAp {
    /// BSSID (MAC address of the AP).
    pub bssid: String,
    /// SSID (human-readable network name).
    pub ssid: String,
    /// Received signal strength in dBm (e.g. -65). Lower (more negative) is weaker.
    pub rssi: i32,
    /// Channel frequency in MHz (e.g. 2437 for ch. 6, 5180 for 5 GHz ch. 36).
    pub frequency_mhz: i32,
}

/// One Bluetooth device record.
#[derive(Serialize)]
pub struct BtDevice {
    /// MAC address of the Bluetooth device.
    pub address: String,
    /// Advertised device name (may be empty).
    pub name: String,
    /// Received signal strength in dBm, or 0 when not reported.
    pub rssi: i32,
}

/// One cellular tower record.
#[derive(Serialize)]
pub struct CellTower {
    /// Radio access technology: `"LTE"`, `"NR"`, `"WCDMA"`, `"GSM"`, etc.
    pub cell_type: String,
    /// Mobile Country Code (3 digits, e.g. `"505"` for Australia).
    pub mcc: String,
    /// Mobile Network Code (2-3 digits, identifies the carrier).
    pub mnc: String,
    /// Cell identity (CI/CID). `0` when not available.
    pub cid: i64,
    /// Signal strength dBm or ASU. Negative = dBm (LTE/NR/WCDMA); positive = ASU (GSM).
    pub signal: i32,
}

/// One ARP-table entry — host visible on the local-area network.
#[derive(Serialize)]
pub struct LanHost {
    /// IPv4 address.
    pub ip: String,
    /// Hardware (MAC) address.
    pub mac: String,
    /// Network interface (e.g. `"wlan0"`).
    pub interface: String,
}

/// A GPS or network-location fix from `termux-location`.
#[derive(Serialize)]
pub struct GpsFix {
    /// Decimal degrees, WGS-84.
    pub latitude: f64,
    /// Decimal degrees, WGS-84.
    pub longitude: f64,
    /// Estimated horizontal accuracy radius in metres.
    pub accuracy: f64,
    /// Location provider used (`"gps"`, `"network"`, `"fused"`, …).
    pub provider: String,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// `GET /api/v1/radar` — run all sub-scans in parallel and return a snapshot.
pub async fn radar_scan() -> Json<RadarSnapshot> {
    let (wifi_raw, bt_raw, cell_raw, gps_raw, arp_raw) = tokio::join!(
        termux_cmd("termux-wifi-scaninfo", &[], 5_000),
        termux_cmd("termux-bluetooth-scaninfo", &[], 8_000),
        termux_cmd("termux-telephony-cellinfo", &[], 5_000),
        termux_cmd("termux-location", &["-p", "network", "-r", "once"], 10_000),
        tokio::fs::read("/proc/net/arp"),
    );

    Json(RadarSnapshot {
        wifi: parse_wifi(wifi_raw),
        bluetooth: parse_bt(bt_raw),
        cell: parse_cell(cell_raw),
        lan: parse_arp(arp_raw.ok()),
        gps: parse_gps(gps_raw),
    })
}

// ── Parsers ───────────────────────────────────────────────────────────────────

fn parse_wifi(raw: Option<Vec<u8>>) -> Vec<WifiAp> {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return vec![],
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return vec![];
    };
    let Ok(Value::Array(arr)) = serde_json::from_str(text) else {
        return vec![];
    };
    arr.into_iter()
        .map(|v| WifiAp {
            bssid: v["bssid"].as_str().unwrap_or("").to_string(),
            ssid: v["ssid"].as_str().unwrap_or("").to_string(),
            rssi: v["rssi"].as_i64().unwrap_or(-100) as i32,
            frequency_mhz: v["frequency"].as_i64().unwrap_or(0) as i32,
        })
        .collect()
}

fn parse_bt(raw: Option<Vec<u8>>) -> Vec<BtDevice> {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return vec![],
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return vec![];
    };
    let Ok(Value::Array(arr)) = serde_json::from_str(text) else {
        return vec![];
    };
    arr.into_iter()
        .map(|v| BtDevice {
            address: v["address"].as_str().unwrap_or("").to_string(),
            name: v["name"].as_str().unwrap_or("").to_string(),
            rssi: v["rssi"].as_i64().unwrap_or(0) as i32,
        })
        .collect()
}

fn parse_cell(raw: Option<Vec<u8>>) -> Vec<CellTower> {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return vec![],
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return vec![];
    };
    let Ok(Value::Array(arr)) = serde_json::from_str(text) else {
        return vec![];
    };
    arr.into_iter()
        .map(|v| {
            // Termux returns "type" as the radio technology string.
            let cell_type = v["type"].as_str().unwrap_or("unknown").to_string();
            // MCC/MNC may be integers or strings depending on Android version.
            let mcc = v["mcc"]
                .as_str()
                .map(str::to_string)
                .or_else(|| v["mcc"].as_i64().map(|n| n.to_string()))
                .unwrap_or_default();
            let mnc = v["mnc"]
                .as_str()
                .map(str::to_string)
                .or_else(|| v["mnc"].as_i64().map(|n| n.to_string()))
                .unwrap_or_default();
            let cid = v["cid"].as_i64().unwrap_or(0);
            // Signal may be under "dbm" (LTE/NR) or "asu" (GSM) or "strength".
            let signal = v["dbm"]
                .as_i64()
                .or_else(|| v["strength"].as_i64())
                .or_else(|| v["asu"].as_i64())
                .unwrap_or(0) as i32;
            CellTower {
                cell_type,
                mcc,
                mnc,
                cid,
                signal,
            }
        })
        .collect()
}

/// Parse `/proc/net/arp` into a list of LAN hosts.
///
/// The file format is:
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
/// ```
fn parse_arp(raw: Option<Vec<u8>>) -> Vec<LanHost> {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return vec![],
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return vec![];
    };
    text.lines()
        .skip(1) // skip header
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let ip = cols.next()?.to_string();
            let _hw_type = cols.next()?;
            let flags = cols.next()?;
            let mac = cols.next()?.to_string();
            let _mask = cols.next()?;
            let iface = cols.next()?.to_string();
            // Skip incomplete entries (flags == 0x0 means stale/no ARP reply).
            if flags == "0x0" {
                return None;
            }
            // Skip the all-zeros MAC that appears for the host itself.
            if mac == "00:00:00:00:00:00" {
                return None;
            }
            Some(LanHost {
                ip,
                mac,
                interface: iface,
            })
        })
        .collect()
}

fn parse_gps(raw: Option<Vec<u8>>) -> Option<GpsFix> {
    let bytes = raw?;
    if bytes.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let v: Value = serde_json::from_str(text).ok()?;
    // Termux returns "error" key when permission is denied or no fix.
    if v["error"].is_string() {
        return None;
    }
    Some(GpsFix {
        latitude: v["latitude"].as_f64()?,
        longitude: v["longitude"].as_f64()?,
        accuracy: v["accuracy"].as_f64().unwrap_or(0.0),
        provider: v["provider"].as_str().unwrap_or("unknown").to_string(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wifi_empty() {
        assert!(parse_wifi(None).is_empty());
        assert!(parse_wifi(Some(vec![])).is_empty());
    }

    #[test]
    fn test_parse_wifi_valid() {
        let json = br#"[{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","rssi":-65,"frequency":2437}]"#;
        let aps = parse_wifi(Some(json.to_vec()));
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(aps[0].ssid, "MyNet");
        assert_eq!(aps[0].rssi, -65);
        assert_eq!(aps[0].frequency_mhz, 2437);
    }

    #[test]
    fn test_parse_bt_empty() {
        assert!(parse_bt(None).is_empty());
    }

    #[test]
    fn test_parse_bt_valid() {
        let json = br#"[{"address":"11:22:33:44:55:66","name":"Headphones","rssi":-70}]"#;
        let devs = parse_bt(Some(json.to_vec()));
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].address, "11:22:33:44:55:66");
        assert_eq!(devs[0].name, "Headphones");
        assert_eq!(devs[0].rssi, -70);
    }

    #[test]
    fn test_parse_cell_empty() {
        assert!(parse_cell(None).is_empty());
    }

    #[test]
    fn test_parse_cell_valid() {
        let json = br#"[{"type":"LTE","mcc":"505","mnc":"01","cid":12345,"dbm":-85}]"#;
        let towers = parse_cell(Some(json.to_vec()));
        assert_eq!(towers.len(), 1);
        assert_eq!(towers[0].cell_type, "LTE");
        assert_eq!(towers[0].mcc, "505");
        assert_eq!(towers[0].signal, -85);
        assert_eq!(towers[0].cid, 12345);
    }

    #[test]
    fn test_parse_arp_empty() {
        assert!(parse_arp(None).is_empty());
    }

    #[test]
    fn test_parse_arp_valid() {
        let arp = b"IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n\
                    192.168.1.2      0x1         0x0         00:11:22:33:44:55     *        wlan0\n";
        let hosts = parse_arp(Some(arp.to_vec()));
        // Only the 0x2 entry should survive (0x0 is skipped)
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.1");
        assert_eq!(hosts[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(hosts[0].interface, "wlan0");
    }

    #[test]
    fn test_parse_gps_none() {
        assert!(parse_gps(None).is_none());
        assert!(parse_gps(Some(vec![])).is_none());
    }

    #[test]
    fn test_parse_gps_error() {
        let json = br#"{"error":"Location permission not granted"}"#;
        assert!(parse_gps(Some(json.to_vec())).is_none());
    }

    #[test]
    fn test_parse_gps_valid() {
        let json =
            br#"{"latitude":-27.4705,"longitude":153.0260,"accuracy":15.0,"provider":"network"}"#;
        let fix = parse_gps(Some(json.to_vec())).expect("should parse");
        assert!((fix.latitude - -27.4705).abs() < 1e-4);
        assert_eq!(fix.provider, "network");
    }
}
