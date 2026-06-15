//! `hse wigle-enrich` — enrich the local `wigle_au` SQLite corpus with
//! derived data that requires zero API calls.
//!
//! Steps (all idempotent, all local-only):
//! 1. Schema migration — add enrichment columns if absent.
//! 2. OUI vendor resolution — resolve BSSIDs/Bluetooth MACs to vendor strings.
//! 3. SSID pattern tagging — classify SSIDs into semantic tag buckets.
//! 4. OpenCelliD cross-reference — match cell netids against `opencellid_au`.
//! 5. Stale flag — mark records unseen for >180 days as `needs_refresh=1`.

use rusqlite::{Connection, params};

use crate::core::error::{Error, Result};
use crate::util::oui;

const SRC: &str = "wigle-enrich";

/// Arguments for the `wigle-enrich` command.
pub struct WigleEnrichArgs {
    /// Print counts; make no DB writes.
    pub dry_run: bool,
    /// Run only the OUI vendor-resolution step.
    pub vendor: bool,
    /// Run only the SSID classification/tagging step.
    pub tags: bool,
    /// Run only the OpenCelliD cell cross-reference step.
    pub cell_xref: bool,
    /// Run only the stale-record flagging step.
    pub stale: bool,
}

impl WigleEnrichArgs {
    /// Returns `true` when no step flag is set (run all steps).
    fn run_all(&self) -> bool {
        !self.vendor && !self.tags && !self.cell_xref && !self.stale
    }
}

pub async fn cmd_wigle_enrich(args: WigleEnrichArgs) -> Result<()> {
    let db_path = crate::default_db_path();
    let conn = Connection::open(&db_path)
        .map_err(|e| Error::Other(format!("cannot open DB at {db_path:?}: {e}")))?;

    // WAL mode for safe concurrent reads.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .map_err(|e| Error::Other(format!("PRAGMA: {e}")))?;

    // Step 1: schema migration (always runs before data steps).
    migrate_schema(&conn)?;

    let run_all = args.run_all();

    if run_all || args.vendor {
        step_oui_vendor(&conn, args.dry_run)?;
    }
    if run_all || args.tags {
        step_ssid_tags(&conn, args.dry_run)?;
    }
    if run_all || args.cell_xref {
        step_cell_xref(&conn, args.dry_run)?;
    }
    if run_all || args.stale {
        step_stale_flag(&conn, args.dry_run)?;
    }

    eprintln!("[{SRC}] Done.");
    Ok(())
}

// ── Step 1: schema migration ─────────────────────────────────────────────────

fn migrate_schema(conn: &Connection) -> Result<()> {
    // SQLite does not support `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, so we
    // attempt each ALTER and ignore "duplicate column name" errors.
    let alters = [
        "ALTER TABLE wigle_au ADD COLUMN vendor TEXT",
        "ALTER TABLE wigle_au ADD COLUMN tags TEXT",
        "ALTER TABLE wigle_au ADD COLUMN needs_refresh INTEGER DEFAULT 0",
        "ALTER TABLE wigle_au ADD COLUMN oci_range_m INTEGER",
        "ALTER TABLE wigle_au ADD COLUMN oci_samples INTEGER",
    ];
    for sql in &alters {
        match conn.execute_batch(sql) {
            Ok(()) => {}
            // "duplicate column name" → column already exists; safe to skip.
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(Error::Other(format!("schema migration: {e}"))),
        }
    }
    Ok(())
}

// ── Step 2: OUI vendor resolution ────────────────────────────────────────────

fn step_oui_vendor(conn: &Connection, dry_run: bool) -> Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT netid FROM wigle_au \
             WHERE kind IN ('wifi','bluetooth') AND vendor IS NULL",
        )
        .map_err(|e| Error::Other(format!("OUI SELECT prepare: {e}")))?;

    let netids: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| Error::Other(format!("OUI SELECT query: {e}")))?
        .filter_map(|r| r.ok())
        .collect();

    let total = netids.len();

    if dry_run {
        eprintln!("[{SRC}] OUI: {total} rows would be updated (dry-run)");
        return Ok(());
    }

    let mut updated = 0usize;

    // Batch in groups of 1 000 to limit per-transaction size.
    for chunk in netids.chunks(1000) {
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| Error::Other(format!("OUI tx begin: {e}")))?;
        {
            let mut update = tx
                .prepare_cached("UPDATE wigle_au SET vendor=?1 WHERE netid=?2")
                .map_err(|e| Error::Other(format!("OUI UPDATE prepare: {e}")))?;

            for netid in chunk {
                if let Some(info) = oui::classify_mac(netid) {
                    update
                        .execute(params![info.vendor, netid])
                        .map_err(|e| Error::Other(format!("OUI UPDATE: {e}")))?;
                    updated += 1;
                }
            }
        }
        tx.commit()
            .map_err(|e| Error::Other(format!("OUI tx commit: {e}")))?;
    }

    eprintln!("[{SRC}] OUI: {updated} rows updated");
    Ok(())
}

// ── Step 3: SSID pattern tagging ─────────────────────────────────────────────

/// Build the JSON tag array for a given SSID and network kind.
fn classify_ssid(ssid: &str, kind: &str) -> String {
    let lower = ssid.to_lowercase();
    let mut tags: Vec<&'static str> = Vec::new();

    // ISP default SSIDs (case-insensitive substring match).
    const ISP_KEYWORDS: &[&str] = &[
        "telstra",
        "optus",
        "vodafone",
        "tpg",
        "iinet",
        "internode",
        "belong",
        "aussie broadband",
        "nbn",
        "dodo",
        "spintel",
        "myrepublic",
        "exetel",
        "superloop",
    ];
    if ISP_KEYWORDS.iter().any(|k| lower.contains(k)) {
        tags.push("isp_default");
    }

    // Corporate: AU TLD suffixes or company-name patterns.
    const AU_TLDS: &[&str] = &[".com.au", ".net.au", ".org.au", ".gov.au"];
    const CORP_PATTERNS: &[&str] = &["pty ltd", "p/l", "pty. ltd."];
    if AU_TLDS.iter().any(|t| lower.ends_with(t)) || CORP_PATTERNS.iter().any(|p| lower.contains(p))
    {
        tags.push("corporate");
    }

    // IoT device SSIDs.
    const IOT_PATTERNS: &[&str] = &[
        "esp_", "esp32", "tuya", "fritz!", "ring-", "nest-", "wyze", "shelly", "tasmota", "sonoff",
    ];
    if IOT_PATTERNS.iter().any(|p| lower.contains(p)) {
        tags.push("iot_device");
    }

    // Residential: wifi with no other category matched.
    if tags.is_empty() && kind == "wifi" {
        tags.push("residential");
    }

    // Serialise as a compact JSON array.
    let inner = tags
        .iter()
        .map(|t| format!("\"{}\"", t))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{inner}]")
}

fn step_ssid_tags(conn: &Connection, dry_run: bool) -> Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT netid, ssid, kind FROM wigle_au \
             WHERE ssid IS NOT NULL AND tags IS NULL",
        )
        .map_err(|e| Error::Other(format!("SSID SELECT prepare: {e}")))?;

    // Collect to avoid holding the borrow over the write phase.
    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| Error::Other(format!("SSID SELECT query: {e}")))?
        .filter_map(|r| r.ok())
        .collect();

    let total = rows.len();

    if dry_run {
        eprintln!("[{SRC}] SSID tags: {total} rows would be updated (dry-run)");
        return Ok(());
    }

    let mut updated = 0usize;

    for chunk in rows.chunks(1000) {
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| Error::Other(format!("SSID tx begin: {e}")))?;
        {
            let mut update = tx
                .prepare_cached("UPDATE wigle_au SET tags=?1 WHERE netid=?2")
                .map_err(|e| Error::Other(format!("SSID UPDATE prepare: {e}")))?;

            for (netid, ssid, kind) in chunk {
                let tag_json = classify_ssid(ssid, kind);
                update
                    .execute(params![tag_json, netid])
                    .map_err(|e| Error::Other(format!("SSID UPDATE: {e}")))?;
                updated += 1;
            }
        }
        tx.commit()
            .map_err(|e| Error::Other(format!("SSID tx commit: {e}")))?;
    }

    eprintln!("[{SRC}] SSID tags: {updated} rows updated");
    Ok(())
}

// ── Step 4: OpenCelliD cross-reference ───────────────────────────────────────

/// Parse a WiGLE cell netid of the form `MCC-MNC-LAC-CID`.
fn parse_cell_netid(netid: &str) -> Option<(i64, i64, i64, i64)> {
    let parts: Vec<&str> = netid.splitn(4, '-').collect();
    if parts.len() != 4 {
        return None;
    }
    let mcc: i64 = parts[0].trim().parse().ok()?;
    let mnc: i64 = parts[1].trim().parse().ok()?;
    let lac: i64 = parts[2].trim().parse().ok()?;
    let cid: i64 = parts[3].trim().parse().ok()?;
    Some((mcc, mnc, lac, cid))
}

fn step_cell_xref(conn: &Connection, dry_run: bool) -> Result<()> {
    // Check that opencellid_au exists; if not, skip gracefully.
    let oci_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type='table' AND name='opencellid_au'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;

    if !oci_exists {
        eprintln!(
            "[{SRC}] Cell cross-ref: opencellid_au table not found \
             — run `hse opencellid-harvest` first"
        );
        return Ok(());
    }

    let mut stmt = conn
        .prepare("SELECT netid FROM wigle_au WHERE kind='cell' AND oci_range_m IS NULL")
        .map_err(|e| Error::Other(format!("cell SELECT prepare: {e}")))?;

    let netids: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| Error::Other(format!("cell SELECT query: {e}")))?
        .filter_map(|r| r.ok())
        .collect();

    let total = netids.len();

    if dry_run {
        eprintln!("[{SRC}] Cell cross-ref: {total} rows would be checked (dry-run)");
        return Ok(());
    }

    let mut matched = 0usize;

    // Batch in groups of 500 for transaction efficiency.
    for chunk in netids.chunks(500) {
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| Error::Other(format!("cell tx begin: {e}")))?;
        {
            let mut update = tx
                .prepare_cached("UPDATE wigle_au SET oci_range_m=?1, oci_samples=?2 WHERE netid=?3")
                .map_err(|e| Error::Other(format!("cell UPDATE prepare: {e}")))?;

            for netid in chunk {
                let Some((mcc, mnc, lac, cid)) = parse_cell_netid(netid) else {
                    continue;
                };

                let result: Option<(Option<i64>, Option<i64>)> = conn
                    .query_row(
                        "SELECT range_m, samples FROM opencellid_au \
                         WHERE mcc=?1 AND mnc=?2 AND lac=?3 AND cid=?4 LIMIT 1",
                        params![mcc, mnc, lac, cid],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .ok();

                if let Some((range_m, samples)) = result {
                    update
                        .execute(params![range_m, samples, netid])
                        .map_err(|e| Error::Other(format!("cell UPDATE: {e}")))?;
                    matched += 1;
                }
            }
        }
        tx.commit()
            .map_err(|e| Error::Other(format!("cell tx commit: {e}")))?;
    }

    eprintln!("[{SRC}] Cell cross-ref: {matched} rows matched");
    Ok(())
}

// ── Step 5: stale flag ───────────────────────────────────────────────────────

fn step_stale_flag(conn: &Connection, dry_run: bool) -> Result<()> {
    if dry_run {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wigle_au \
                 WHERE needs_refresh = 0 \
                   AND harvest_count = 1 \
                   AND last_updated < datetime('now', '-180 days')",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        eprintln!("[{SRC}] Stale flags: {count} rows would be marked (dry-run)");
        return Ok(());
    }

    let n = conn
        .execute(
            "UPDATE wigle_au SET needs_refresh = 1 \
             WHERE needs_refresh = 0 \
               AND harvest_count = 1 \
               AND last_updated < datetime('now', '-180 days')",
            [],
        )
        .map_err(|e| Error::Other(format!("stale UPDATE: {e}")))?;

    eprintln!("[{SRC}] Stale flags: {n} rows marked");
    Ok(())
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ssid_isp_default() {
        let t = classify_ssid("Telstra12345", "wifi");
        assert!(t.contains("isp_default"), "{t}");
    }

    #[test]
    fn classify_ssid_residential() {
        let t = classify_ssid("MyHomeNetwork", "wifi");
        assert!(t.contains("residential"), "{t}");
    }

    #[test]
    fn classify_ssid_corporate_tld() {
        let t = classify_ssid("acme.com.au", "wifi");
        assert!(t.contains("corporate"), "{t}");
    }

    #[test]
    fn classify_ssid_iot() {
        let t = classify_ssid("ESP_DEADBEEF", "wifi");
        assert!(t.contains("iot_device"), "{t}");
    }

    #[test]
    fn classify_ssid_non_wifi_no_residential() {
        let t = classify_ssid("SomeName", "bluetooth");
        assert!(!t.contains("residential"), "{t}");
    }

    #[test]
    fn parse_cell_netid_valid() {
        assert_eq!(
            parse_cell_netid("505-1-2000-12345"),
            Some((505, 1, 2000, 12345))
        );
    }

    #[test]
    fn parse_cell_netid_invalid_short() {
        assert!(parse_cell_netid("505-1-2000").is_none());
    }

    #[test]
    fn parse_cell_netid_invalid_non_numeric() {
        assert!(parse_cell_netid("abc-def-ghi-jkl").is_none());
    }
}
