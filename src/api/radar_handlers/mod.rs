//! Signal radar API handler — GET /api/v1/radar
//!
//! Returns a snapshot of all locally-detectable signals (WiFi APs, Bluetooth
//! devices, cell towers, GPS fix, LAN hosts) without creating a stored scan.
//! All sensor commands run in parallel; off-device returns empty lists.

use axum::{Json, extract::State};
use serde::Serialize;
use std::sync::Arc;

use crate::api::AppState;
use crate::util::termux::termux_cmd;

#[derive(Serialize, Default)]
pub struct RadarSnapshot {
    pub timestamp_ms: u64,
    pub wifi_aps: Vec<WifiAp>,
    pub bluetooth_devices: Vec<BtDevice>,
    pub cell_towers: Vec<CellTower>,
    pub lan_hosts: Vec<LanHost>,
    pub gps: Option<GpsFix>,
}

#[derive(Serialize)]
pub struct WifiAp {
    pub bssid: String,
    pub ssid: String,
    pub rssi_dbm: i32,
    pub frequency_mhz: u32,
    pub band: String,
    pub confidence: f64,
}

#[derive(Serialize)]
pub struct BtDevice {
    pub address: String,
    pub name: String,
    pub device_type: String,
    pub bond_state: String,
}

#[derive(Serialize)]
pub struct CellTower {
    pub id: String,
    pub technology: String,
    pub mcc: Option<i64>,
    pub mnc: Option<i64>,
    pub cid: Option<i64>,
    pub lac_tac: Option<i64>,
    pub signal_dbm: i32,
    pub registered: bool,
}

#[derive(Serialize)]
pub struct LanHost {
    pub ip: String,
    pub mac: String,
    pub open_ports: Vec<u16>,
}

#[derive(Serialize)]
pub struct GpsFix {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_m: f64,
    pub provider: String,
    pub confidence: f64,
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn parse_wifi(raw: Option<Vec<u8>>) -> Vec<WifiAp> {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return Vec::new(),
    };
    let arr: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(list) = arr.as_array() else { return Vec::new(); };
    let mut out = Vec::with_capacity(list.len());
    for ap in list {
        let bssid = ap["bssid"].as_str().unwrap_or("").to_string();
        if bssid.is_empty() || bssid == "00:00:00:00:00:00" || bssid == "02:00:00:00:00:00" {
            continue;
        }
        let rssi = ap["rssi"].as_i64().unwrap_or(-100) as i32;
        let freq = ap["frequency"].as_u64().unwrap_or(0) as u32;
        let band = match freq {
            2400..=2500 => "2.4 GHz",
            4900..=5900 => "5 GHz",
            5925..=7125 => "6 GHz",
            _ => "unknown",
        };
        let confidence = if rssi >= -50 {
            0.90
        } else if rssi >= -70 {
            0.75
        } else if rssi >= -85 {
            0.60
        } else {
            0.45
        };
        out.push(WifiAp {
            bssid,
            ssid: ap["ssid"].as_str().unwrap_or("<hidden>").to_string(),
            rssi_dbm: rssi,
            frequency_mhz: freq,
            band: band.to_string(),
            confidence,
        });
    }
    // Strongest signal first
    out.sort_by(|a, b| b.rssi_dbm.cmp(&a.rssi_dbm));
    out
}

fn parse_bt(raw: Option<Vec<u8>>) -> Vec<BtDevice> {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return Vec::new(),
    };
    let arr: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(list) = arr.as_array() else { return Vec::new(); };
    let mut out = Vec::with_capacity(list.len());
    for dev in list {
        let addr = dev["address"].as_str().unwrap_or("").to_string();
        if addr.is_empty() || addr == "00:00:00:00:00:00" {
            continue;
        }
        out.push(BtDevice {
            address: addr,
            name: dev["name"].as_str().unwrap_or("<unknown>").to_string(),
            device_type: dev["type"].as_str().unwrap_or("unknown").to_string(),
            bond_state: dev["bondState"].as_str().unwrap_or("NONE").to_string(),
        });
    }
    out
}

fn parse_cell(raw: Option<Vec<u8>>) -> Vec<CellTower> {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return Vec::new(),
    };
    let arr: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(list) = arr.as_array() else { return Vec::new(); };
    let mut out = Vec::with_capacity(list.len());

    fn val_i64(v: &serde_json::Value) -> Option<i64> {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    }

    for cell in list {
        let mcc = val_i64(&cell["mcc"]);
        let mnc = val_i64(&cell["mnc"]);
        let cid = val_i64(&cell["ci"])
            .or_else(|| val_i64(&cell["cid"]));
        let lac_tac = val_i64(&cell["tac"])
            .or_else(|| val_i64(&cell["lac"]));

        let id = match (mcc, mnc, cid) {
            (Some(m), Some(n), Some(c)) => format!(
                "{m}-{n}-{}-{c}",
                lac_tac.map(|l| l.to_string()).unwrap_or_default()
            ),
            (Some(m), Some(n), None) => format!("{m}-{n}"),
            _ => continue,
        };

        let tech = cell["type"].as_str().unwrap_or("unknown").to_uppercase();
        out.push(CellTower {
            id,
            technology: tech,
            mcc,
            mnc,
            cid,
            lac_tac,
            signal_dbm: cell["dbm"].as_i64().unwrap_or(-120) as i32,
            registered: cell["registered"].as_bool().unwrap_or(false),
        });
    }
    out
}

fn parse_gps(raw: Option<Vec<u8>>) -> Option<GpsFix> {
    let bytes = raw?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let lat = v["latitude"].as_f64()?;
    let lon = v["longitude"].as_f64()?;
    if !crate::util::geo::is_valid_coords(lat, lon) {
        return None;
    }
    let accuracy = v["accuracy"].as_f64().unwrap_or(0.0);
    let provider = v["provider"].as_str().unwrap_or("network");
    let ceiling = if provider == "gps" { 0.90_f64 } else { 0.65_f64 };
    let confidence = if accuracy > 0.0 {
        (ceiling - (accuracy / 1000.0).min(0.35)).clamp(0.30, 0.90)
    } else {
        ceiling
    };
    Some(GpsFix {
        latitude: lat,
        longitude: lon,
        accuracy_m: accuracy,
        provider: provider.to_string(),
        confidence,
    })
}

async fn parse_arp_hosts(raw: Result<Vec<u8>, std::io::Error>) -> Vec<LanHost> {
    let bytes = match raw {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut hosts: Vec<(String, String)> = Vec::new();
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = parts[0];
        let flags = parts[2];
        let mac = parts[3];
        if flags != "0x2" || mac == "00:00:00:00:00:00" {
            continue;
        }
        hosts.push((ip.to_owned(), mac.to_owned()));
    }

    // TCP connect sweep in parallel (400ms per port)
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    const PORTS: &[u16] = &[22, 80, 443, 8080, 8443];

    let tasks: Vec<_> = hosts
        .into_iter()
        .map(|(ip, mac)| {
            tokio::spawn(async move {
                let mut open_ports = Vec::new();
                for &port in PORTS {
                    let addr_str = format!("{ip}:{port}");
                    let Ok(addr) = addr_str.parse::<SocketAddr>() else { continue; };
                    if timeout(Duration::from_millis(400), TcpStream::connect(addr))
                        .await
                        .is_ok_and(|r| r.is_ok())
                    {
                        open_ports.push(port);
                    }
                }
                LanHost { ip, mac, open_ports }
            })
        })
        .collect();

    let mut result = Vec::new();
    for task in tasks {
        if let Ok(host) = task.await {
            result.push(host);
        }
    }
    result
}

pub async fn radar_scan(State(_s): State<Arc<AppState>>) -> Json<RadarSnapshot> {
    let ts = timestamp_ms();

    let (wifi_raw, bt_raw, cell_raw, gps_raw, arp_raw) = tokio::join!(
        termux_cmd("termux-wifi-scaninfo", &[], 8_000),
        termux_cmd("termux-bluetooth-scaninfo", &[], 10_000),
        termux_cmd("termux-telephony-cellinfo", &[], 5_000),
        termux_cmd("termux-location", &["-p", "gps", "-r", "once"], 12_000),
        tokio::fs::read("/proc/net/arp"),
    );

    let (wifi_aps, bluetooth_devices, cell_towers, gps, lan_hosts) = tokio::join!(
        async { parse_wifi(wifi_raw) },
        async { parse_bt(bt_raw) },
        async { parse_cell(cell_raw) },
        async { parse_gps(gps_raw) },
        parse_arp_hosts(arp_raw),
    );

    Json(RadarSnapshot {
        timestamp_ms: ts,
        wifi_aps,
        bluetooth_devices,
        cell_towers,
        lan_hosts,
        gps,
    })
}
