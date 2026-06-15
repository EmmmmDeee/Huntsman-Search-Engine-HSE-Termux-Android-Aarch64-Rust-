//! `hse wigle-export` — export the local `wigle_au` corpus in WiGLE-native
//! formats (WiGLE CSV or KML) for round-tripping back to WiGLE or any
//! wardriving tool that accepts WiGLE's own export format.

use std::io::{BufWriter, Write};

use rusqlite::{Connection, OpenFlags};

use crate::{core::error::Result, default_db_path};

pub struct WigleExportArgs {
    /// Output format: "wigle-csv" (default) or "kml"
    pub format: String,
    /// Write to this file path (default: stdout)
    pub output: Option<String>,
    /// Filter by kind: "wifi", "cell", "bluetooth" (default: all)
    pub kind: Option<String>,
    /// Filter to bounding box: "lat1,lon1,lat2,lon2"
    pub bbox: Option<String>,
    /// Max rows to export (0 = all)
    pub limit: u64,
}

pub fn cmd_wigle_export(args: WigleExportArgs) -> Result<()> {
    let db_path = default_db_path();
    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?;

    // Check the table exists.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='wigle_au'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !table_exists {
        eprintln!("[wigle-export] wigle_au table not found. Run hse wigle-harvest first.");
        return Ok(());
    }

    // Parse bbox if provided.
    let bbox = args.bbox.as_deref().map(parse_bbox).transpose()?;

    // Build query.
    let (sql, params_bbox, limit) = build_query(args.kind.as_deref(), bbox, args.limit);

    // Open output writer.
    if let Some(ref path) = args.output {
        let file = std::fs::File::create(path)
            .map_err(|e| crate::core::error::Error::Other(format!("open output: {e}")))?;
        let mut w = BufWriter::new(file);
        run_export(&conn, &args.format, &sql, &params_bbox, limit, &mut w)?;
    } else {
        let stdout = std::io::stdout();
        let mut w = BufWriter::new(stdout.lock());
        run_export(&conn, &args.format, &sql, &params_bbox, limit, &mut w)?;
    }

    Ok(())
}

// ─── bbox ───────────────────────────────────────────────────────────────────

struct Bbox {
    lat1: f64,
    lon1: f64,
    lat2: f64,
    lon2: f64,
}

fn parse_bbox(s: &str) -> Result<Bbox> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 4 {
        return Err(crate::core::error::Error::Other(
            "--bbox must be lat1,lon1,lat2,lon2".into(),
        ));
    }
    let nums: Vec<f64> = parts
        .iter()
        .map(|p| {
            p.trim()
                .parse::<f64>()
                .map_err(|_| crate::core::error::Error::Other(format!("invalid bbox value: {p}")))
        })
        .collect::<Result<_>>()?;
    Ok(Bbox {
        lat1: nums[0],
        lon1: nums[1],
        lat2: nums[2],
        lon2: nums[3],
    })
}

// ─── query building ──────────────────────────────────────────────────────────

fn build_query(kind: Option<&str>, bbox: Option<Bbox>, limit: u64) -> (String, Option<Bbox>, u64) {
    let mut sql = String::from(
        "SELECT netid, ssid, encryption, first_seen, channel, lat, lon, posalt, accuracy, kind, last_seen, vendor, tags \
         FROM wigle_au WHERE 1=1",
    );
    if kind.is_some() {
        sql.push_str(" AND kind = ?1");
    }
    if bbox.is_some() {
        let (p_lat1, p_lat2, p_lon1, p_lon2) = if kind.is_some() {
            ("?2", "?3", "?4", "?5")
        } else {
            ("?1", "?2", "?3", "?4")
        };
        sql.push_str(&format!(
            " AND lat BETWEEN {p_lat1} AND {p_lat2} AND lon BETWEEN {p_lon1} AND {p_lon2}"
        ));
    }
    if limit > 0 {
        sql.push_str(&format!(" LIMIT {limit}"));
    }
    (sql, bbox, limit)
}

// ─── export dispatch ─────────────────────────────────────────────────────────

fn run_export<W: Write>(
    conn: &Connection,
    format: &str,
    sql: &str,
    bbox: &Option<Bbox>,
    _limit: u64,
    w: &mut W,
) -> Result<()> {
    match format {
        "wigle-csv" => export_wigle_csv(conn, sql, bbox, w),
        "kml" => export_kml(conn, sql, bbox, w),
        other => Err(crate::core::error::Error::Other(format!(
            "unknown format '{other}'. Use wigle-csv or kml"
        ))),
    }
}

// ─── WiGLE CSV ───────────────────────────────────────────────────────────────

fn export_wigle_csv<W: Write>(
    conn: &Connection,
    sql: &str,
    bbox: &Option<Bbox>,
    w: &mut W,
) -> Result<()> {
    // Line 1: WiGLE metadata header (CRLF).
    write!(
        w,
        "WigleWifi-1.4,appRelease=HSE,model=Termux,release=Android,device=aarch64,\
         display=HSE,board=HSE,brand=Huntsman,star=Sol,body=3,subBody=0\r\n"
    )
    .map_err(io_err)?;
    // Line 2: column headers (CRLF).
    write!(
        w,
        "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,\
         AltitudeMeters,AccuracyMeters,Type\r\n"
    )
    .map_err(io_err)?;

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?;

    let mut process = |row: &rusqlite::Row<'_>| -> rusqlite::Result<()> {
        let netid: String = row.get(0).unwrap_or_default();
        let ssid: Option<String> = row.get(1)?;
        let encryption: Option<String> = row.get(2)?;
        let first_seen: Option<String> = row.get(3)?;
        let channel: Option<i64> = row.get(4)?;
        let lat: Option<f64> = row.get(5)?;
        let lon: Option<f64> = row.get(6)?;
        let posalt: Option<f64> = row.get(7)?;
        let accuracy: Option<f64> = row.get(8)?;
        let kind: Option<String> = row.get(9)?;

        let ssid_str = ssid.unwrap_or_default();
        let auth_mode = map_encryption(encryption.as_deref());
        let first_seen_str = convert_first_seen(first_seen.as_deref());
        let channel_val = channel.unwrap_or(0);
        let lat_val = lat.unwrap_or(0.0);
        let lon_val = lon.unwrap_or(0.0);
        let posalt_val = posalt.unwrap_or(0.0);
        let accuracy_val = accuracy.unwrap_or(0.0);
        let type_val = map_kind_upper(kind.as_deref());

        // RFC 4180 CSV quoting for SSID.
        let ssid_csv = csv_quote(&ssid_str);

        // Write data row with CRLF.
        // netid is a MAC — no quoting needed; other fields are safe numeric/enum.
        let _ = write!(
            w,
            "{netid},{ssid_csv},{auth_mode},{first_seen_str},{channel_val},0,\
             {lat_val:.6},{lon_val:.6},{posalt_val:.1},{accuracy_val:.1},{type_val}\r\n"
        );
        Ok(())
    };

    if let Some(bb) = bbox {
        stmt.query_map(
            rusqlite::params![bb.lat1, bb.lat2, bb.lon1, bb.lon2],
            |row| {
                process(row)?;
                Ok(())
            },
        )
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?
        .for_each(drop);
    } else {
        stmt.query_map([], |row| {
            process(row)?;
            Ok(())
        })
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?
        .for_each(drop);
    }

    w.flush().map_err(io_err)?;
    Ok(())
}

// ─── KML ─────────────────────────────────────────────────────────────────────

fn export_kml<W: Write>(
    conn: &Connection,
    sql: &str,
    bbox: &Option<Bbox>,
    w: &mut W,
) -> Result<()> {
    write!(
        w,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>WiGLE AU Export — HSE</name>
    <description>Exported from wigle_au corpus by Huntsman Search Engine</description>
    <Style id="wifi"><IconStyle><Icon><href>http://maps.google.com/mapfiles/kml/shapes/wifi.png</href></Icon></IconStyle></Style>
    <Style id="cell"><IconStyle><Icon><href>http://maps.google.com/mapfiles/kml/shapes/phone.png</href></Icon></IconStyle></Style>
    <Style id="bt"><IconStyle><Icon><href>http://maps.google.com/mapfiles/kml/shapes/pal4/icon57.png</href></Icon></IconStyle></Style>
"#
    )
    .map_err(io_err)?;

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?;

    let mut process = |row: &rusqlite::Row<'_>| -> rusqlite::Result<()> {
        let netid: String = row.get(0).unwrap_or_default();
        let ssid: Option<String> = row.get(1)?;
        let encryption: Option<String> = row.get(2)?;
        let first_seen: Option<String> = row.get(3)?;
        let channel: Option<i64> = row.get(4)?;
        let lat: Option<f64> = row.get(5)?;
        let lon: Option<f64> = row.get(6)?;
        let posalt: Option<f64> = row.get(7)?;
        let _accuracy: Option<f64> = row.get(8)?;
        let kind: Option<String> = row.get(9)?;
        let last_seen: Option<String> = row.get(10)?;
        let vendor: Option<String> = row.get(11)?;
        let tags: Option<String> = row.get(12)?;

        let ssid_str = ssid.unwrap_or_default();
        let name = if ssid_str.is_empty() {
            xml_escape(&netid)
        } else {
            xml_escape(&ssid_str)
        };
        let kind_str = kind.as_deref().unwrap_or("wifi");
        let style_id = map_kind_kml(kind_str);
        let lon_val = lon.unwrap_or(0.0);
        let lat_val = lat.unwrap_or(0.0);
        let posalt_val = posalt.unwrap_or(0.0);

        let _ = write!(
            w,
            "    <Placemark>\n      <name>{name}</name>\n\
                   <description><![CDATA[\n\
             MAC: {netid}<br/>\n\
             SSID: {ssid_str}<br/>\n\
             Encryption: {enc}<br/>\n\
             Channel: {ch}<br/>\n\
             First seen: {fs}<br/>\n\
             Last seen: {ls}<br/>\n\
             Vendor: {vendor}<br/>\n\
             Tags: {tags}\n\
             ]]></description>\n\
             <styleUrl>#{style_id}</styleUrl>\n\
             <Point><coordinates>{lon_val},{lat_val},{posalt_val}</coordinates></Point>\n\
             </Placemark>\n",
            enc = xml_escape(encryption.as_deref().unwrap_or("")),
            ch = channel.unwrap_or(0),
            fs = xml_escape(first_seen.as_deref().unwrap_or("")),
            ls = xml_escape(last_seen.as_deref().unwrap_or("")),
            vendor = xml_escape(vendor.as_deref().unwrap_or("")),
            tags = xml_escape(tags.as_deref().unwrap_or("")),
        );
        Ok(())
    };

    if let Some(bb) = bbox {
        stmt.query_map(
            rusqlite::params![bb.lat1, bb.lat2, bb.lon1, bb.lon2],
            |row| {
                process(row)?;
                Ok(())
            },
        )
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?
        .for_each(drop);
    } else {
        stmt.query_map([], |row| {
            process(row)?;
            Ok(())
        })
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?
        .for_each(drop);
    }

    write!(w, "  </Document>\n</kml>\n").map_err(io_err)?;
    w.flush().map_err(io_err)?;
    Ok(())
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn map_encryption(enc: Option<&str>) -> &'static str {
    match enc.unwrap_or("").to_uppercase().as_str() {
        "WPA3" => "[WPA3-SAE-CCMP][ESS]",
        "WPA2" => "[WPA2-PSK-CCMP][ESS]",
        "WPA" => "[WPA-PSK-CCMP][ESS]",
        "WEP" => "[WEP][ESS]",
        _ => "[ESS]",
    }
}

fn convert_first_seen(s: Option<&str>) -> String {
    match s {
        None => String::new(),
        Some(v) => {
            // "YYYY-MM-DDTHH:MM:SSZ" → "YYYY-MM-DD HH:MM:SS"
            let trimmed = v.trim_end_matches('Z');
            trimmed.replacen('T', " ", 1)
        }
    }
}

fn map_kind_upper(kind: Option<&str>) -> &'static str {
    match kind.unwrap_or("wifi").to_lowercase().as_str() {
        "wifi" => "WIFI",
        "cell" => "CELL",
        "bluetooth" | "bt" => "BT",
        "wimax" => "WIMAX",
        _ => "WIFI",
    }
}

fn map_kind_kml(kind: &str) -> &'static str {
    match kind.to_lowercase().as_str() {
        "cell" => "cell",
        "bluetooth" | "bt" => "bt",
        _ => "wifi",
    }
}

/// RFC 4180 CSV quoting: wrap in double-quotes if the field contains a comma,
/// double-quote, or newline; escape internal double-quotes as `""`.
fn csv_quote(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

/// Escape `&`, `<`, `>` for XML attribute/text content.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn io_err(e: std::io::Error) -> crate::core::error::Error {
    crate::core::error::Error::Other(e.to_string())
}
