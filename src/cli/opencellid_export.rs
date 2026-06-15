//! `hse opencellid-export` — export the local `opencellid_au` corpus in
//! OpenCelliD's exact bulk CSV format (`cell_towers.csv`), byte-compatible
//! with the OpenCelliD bulk download so any tool that accepts that format can
//! consume this output directly.

use std::io::{BufWriter, Write};

use rusqlite::{Connection, OpenFlags};

use crate::{core::error::Result, default_db_path};

pub struct OpencellidExportArgs {
    /// Write to this file path (default: stdout)
    pub output: Option<String>,
    /// Filter by radio type: GSM, LTE, UMTS, NR
    pub radio: Option<String>,
    /// Max rows to export (0 = all)
    pub limit: u64,
}

pub fn cmd_opencellid_export(args: OpencellidExportArgs) -> Result<()> {
    let db_path = default_db_path();
    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?;

    // Check the table exists.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='opencellid_au'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !table_exists {
        eprintln!(
            "[opencellid-export] opencellid_au table not found. Run hse opencellid-harvest first."
        );
        return Ok(());
    }

    let sql = build_query(args.radio.as_deref(), args.limit);

    if let Some(ref path) = args.output {
        let file = std::fs::File::create(path)
            .map_err(|e| crate::core::error::Error::Other(format!("open output: {e}")))?;
        let mut w = BufWriter::new(file);
        run_export(&conn, &sql, args.radio.as_deref(), &mut w)?;
    } else {
        let stdout = std::io::stdout();
        let mut w = BufWriter::new(stdout.lock());
        run_export(&conn, &sql, args.radio.as_deref(), &mut w)?;
    }

    Ok(())
}

fn build_query(radio: Option<&str>, limit: u64) -> String {
    let mut sql = String::from(
        "SELECT radio, mcc, mnc, lac, cid, lon, lat, range_m, samples, changeable, \
         created, updated, avg_signal \
         FROM opencellid_au WHERE 1=1",
    );
    if radio.is_some() {
        sql.push_str(" AND radio = ?1");
    }
    if limit > 0 {
        sql.push_str(&format!(" LIMIT {limit}"));
    }
    sql
}

fn run_export<W: Write>(
    conn: &Connection,
    sql: &str,
    radio: Option<&str>,
    w: &mut W,
) -> Result<()> {
    // OpenCelliD header — LF line endings.
    writeln!(w, "radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal")
        .map_err(io_err)?;

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?;

    let mut process = |row: &rusqlite::Row<'_>| -> rusqlite::Result<()> {
        let radio_val: String = row.get(0).unwrap_or_default();
        let mcc: Option<i64> = row.get(1)?;
        let mnc: Option<i64> = row.get(2)?;
        let lac: Option<i64> = row.get(3)?;
        let cid: Option<i64> = row.get(4)?;
        let lon: Option<f64> = row.get(5)?;
        let lat: Option<f64> = row.get(6)?;
        let range_m: Option<i64> = row.get(7)?;
        let samples: Option<i64> = row.get(8)?;
        let changeable: Option<i64> = row.get(9)?;
        let created: Option<i64> = row.get(10)?;
        let updated: Option<i64> = row.get(11)?;
        let avg_signal: Option<i64> = row.get(12)?;

        let _ = writeln!(
            w,
            "{radio},{mcc},{net},{area},{cell},0,{lon:.7},{lat:.7},{range},{samples},{changeable},{created},{updated},{avg_signal}",
            radio = radio_val,
            mcc = mcc.unwrap_or(0),
            net = mnc.unwrap_or(0),
            area = lac.unwrap_or(0),
            cell = cid.unwrap_or(0),
            lon = lon.unwrap_or(0.0),
            lat = lat.unwrap_or(0.0),
            range = range_m.unwrap_or(0),
            samples = samples.unwrap_or(0),
            changeable = changeable.unwrap_or(1),
            created = created.unwrap_or(0),
            updated = updated.unwrap_or(0),
            avg_signal = avg_signal.unwrap_or(0),
        );
        Ok(())
    };

    if let Some(r) = radio {
        stmt.query_map(rusqlite::params![r], |row| {
            process(row)?;
            Ok(())
        })
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

fn io_err(e: std::io::Error) -> crate::core::error::Error {
    crate::core::error::Error::Other(e.to_string())
}
