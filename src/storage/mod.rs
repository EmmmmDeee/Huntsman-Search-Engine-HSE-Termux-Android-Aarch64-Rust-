// SQLite WAL store. Unified module: scan, entity, correlation, and event
// persistence plus the observation junction table.

use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::core::{
    correlator::Correlation, entity::Entity, error::Result, event::Event, relation::Relation,
    scan::Scan,
};

mod archive; // `impl Store`: inter-scan entity cache (`raw_archive`)
mod entities; // `impl Store`: entity persistence + FTS query
mod stealer_rows; // `impl Store`: paired stealer-log credential row persistence
mod templates; // `impl Store`: cross-scan pathway-template learning

pub use entities::EvidenceAnomaly;

pub struct Store {
    conn: Mutex<Connection>,
}

/// Logical schema version stamped into `PRAGMA user_version` on first open.
/// Increment this when a future non-additive migration is introduced so older
/// binaries can warn rather than silently misread a newer schema.
const SCHEMA_VERSION: i32 = 1;

/// Static schema (tables + indexes), `CREATE … IF NOT EXISTS` so it's safe to
/// run on every open. Kept as a constant so [`Store::open`] reads as a short
/// orchestrator and the schema lives in one greppable place. Executed in the
/// same batch as the (env-tunable) pragmas, so the resulting database is
/// byte-for-byte what the previous inline DDL produced.
const SCHEMA_DDL: &str = "
            CREATE TABLE IF NOT EXISTS scans (
                id           TEXT PRIMARY KEY,
                target_kind  TEXT NOT NULL,
                target_value TEXT NOT NULL,
                status       TEXT NOT NULL,
                started_at   INTEGER NOT NULL,
                finished_at  INTEGER,
                entity_count INTEGER NOT NULL DEFAULT 0,
                error        TEXT,
                data_json    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entities (
                uid           TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL,
                kind          TEXT NOT NULL,
                value         TEXT NOT NULL,
                confidence    REAL NOT NULL,
                corroboration INTEGER NOT NULL DEFAULT 1,
                observed_at   INTEGER NOT NULL,
                data_json     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS correlations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                rule_id     TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL,
                entity_uids TEXT NOT NULL,
                ts          INTEGER NOT NULL,
                data_json   TEXT NOT NULL,
                UNIQUE(scan_id, rule_id, description)
            );

            CREATE TABLE IF NOT EXISTS entity_observations (
                entity_uid  TEXT NOT NULL,
                scan_id     TEXT NOT NULL,
                observed_at INTEGER NOT NULL,
                PRIMARY KEY (entity_uid, scan_id)
            );

            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                ts          INTEGER NOT NULL,
                event_type  TEXT NOT NULL,
                data_json   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS relations (
                id          TEXT PRIMARY KEY,
                scan_id     TEXT NOT NULL,
                from_uid    TEXT NOT NULL,
                to_uid      TEXT NOT NULL,
                kind        TEXT NOT NULL,
                confidence  REAL NOT NULL,
                observed_at INTEGER NOT NULL,
                data_json   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_entities_scan ON entities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_corr_scan     ON correlations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_scan      ON entity_observations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_entity    ON entity_observations(entity_uid);
            CREATE INDEX IF NOT EXISTS idx_events_scan   ON events(scan_id, id);
            CREATE INDEX IF NOT EXISTS idx_events_type   ON events(event_type, id);
            CREATE INDEX IF NOT EXISTS idx_relations_scan ON relations(scan_id);

            -- Paired stealer-log credential rows (Stealer Logs Viewer,
            -- `core::stealer_row::StealerRow`). Persisted ALONGSIDE the
            -- generic entity graph, not instead of it: `entities` flattens a
            -- credential into independent Email/Username/Credential rows for
            -- correlation, which loses the login/password/domain pairing an
            -- operator browsing a stolen-credential dump actually wants back.
            CREATE TABLE IF NOT EXISTS stealer_rows (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id  TEXT NOT NULL,
                log_id   TEXT,
                domain   TEXT,
                login    TEXT,
                password TEXT,
                pwned_at TEXT,
                row_kind TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_stealer_rows_scan ON stealer_rows(scan_id);
            CREATE INDEX IF NOT EXISTS idx_stealer_rows_log  ON stealer_rows(scan_id, log_id);

            -- Inter-scan entity cache (C9 / SOL-CACHE-INTERSCAN). Keyed by
            -- `module:target_kind:normalised_target` so a repeat scan of the
            -- same target by the same module can replay archived entities
            -- without re-querying the provider. `archived_at + ttl_secs` is
            -- the expiry wall-clock; expired rows are ignored on lookup and
            -- overwritten on the next successful query.
            CREATE TABLE IF NOT EXISTS raw_archive (
                id          TEXT PRIMARY KEY,
                archived_at INTEGER NOT NULL,
                ttl_secs    INTEGER NOT NULL,
                result_json TEXT NOT NULL
            );

            -- Cross-scan pathway-template learning (C1 universal linking). Each
            -- row is a direction-canonical attribution route confirmed by one or
            -- more scans; `seen_count` is the number of scans that produced it. A
            -- route learned in one scan thus lifts every later scan: when a new
            -- scan reproduces a known template, the engine credits the connection
            -- as historically corroborated.
            CREATE TABLE IF NOT EXISTS pathway_templates (
                template    TEXT PRIMARY KEY,
                seen_count  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL
            );

            -- Full-text index over entity values. Contentless-external FTS5
            -- table keyed by the entities.rowid; kept synchronized inside the
            -- same transaction as every entity write (see
            -- merge_and_persist_entity) so the index never drifts from the
            -- graph (the 'always-synchronized index' invariant). `prefix`
            -- indexes make 2/3-char prefix queries cheap on aarch64.
            CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
                value,
                kind UNINDEXED,
                content='entities',
                content_rowid='rowid',
                prefix='2 3',
                tokenize='unicode61'
            );
            ";

/// Idempotent backfill of the observation junction table from `entities`.
const BACKFILL_OBSERVATIONS_SQL: &str =
    "INSERT OR IGNORE INTO entity_observations(entity_uid, scan_id, observed_at)
     SELECT uid, scan_id, observed_at FROM entities;";

/// Read an `i64` from an environment variable, falling back to `default` when
/// unset or unparseable. Used for the env-tunable SQLite performance pragmas.
fn env_i64(var: &str, default: i64) -> i64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Escape the LIKE metacharacters in `s` for a query using `ESCAPE '\'`.
///
/// The escape character `\` is escaped FIRST, then `%` and `_`, so all three
/// LIKE metacharacters are matched literally. Escaping `\` first is essential:
/// otherwise a backslash in the input would consume the following character (a
/// `\` query would match a literal `%`, missing real backslashes). Callers wrap
/// the result in `%…%` for a substring match.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Best-effort `chmod 0600` on each of the store's on-disk files. Failure must
/// not block [`Store::open`] — a transient or permission-denied chmod is not
/// fatal — but, mirroring the FTS-rebuild best-effort/never-silent pattern in
/// `open`, must not be silent either: the store holds PII + harvested
/// third-party keys, so a failed chmod left at the process umask (often
/// 0644, world-readable) is a real, if lower-severity, exposure worth a
/// trace to debug from.
#[cfg(unix)]
fn restrict_to_owner_only(paths: &[String]) {
    use std::os::unix::fs::PermissionsExt;
    let owner_only = std::fs::Permissions::from_mode(0o600);
    for p in paths {
        if let Err(e) = std::fs::set_permissions(p, owner_only.clone()) {
            tracing::warn!(
                path = %p,
                error = %e,
                "failed to restrict a store file to owner-only (0600) — it may be left world-readable at the process umask"
            );
        }
    }
}

/// Collect a `query_map` iterator, logging (not silently dropping) any row
/// that fails SQL-level extraction. In practice this means genuine DB
/// corruption (a `NOT NULL TEXT` column somehow unreadable as a `String`) —
/// rare next to a JSON-deserialize failure (see [`deserialize_rows`]), but
/// every multi-row reader used to swallow it identically via `filter_map(...
/// .ok())` with zero trace, the same "search is broken with no diagnostic"
/// failure mode the FTS-rebuild path above already treats as unacceptable.
fn collect_rows<T>(rows: impl Iterator<Item = rusqlite::Result<T>>, context: &str) -> Vec<T> {
    rows.filter_map(|r| match r {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(
                context,
                error = %e,
                "failed to read a stored row — dropped from result set"
            );
            None
        }
    })
    .collect()
}

/// Deserialize a batch of raw `data_json` rows, logging (not silently
/// dropping) any row that fails to parse — a corrupted value, or a struct
/// field added/removed since the row was written. Every multi-row reader
/// (`list_scans`, `*_for_scan`, `entities_filtered`, `search_entities`) used
/// to chain `.filter_map(|s| serde_json::from_str(&s).ok())` and vanish a bad
/// row with no trace, unlike the single-row getters (`get_scan`, `get_entity`)
/// which already propagate a deserialize error via `?` — this brings every
/// multi-row reader to the same standard without failing the whole page over
/// one bad row.
fn deserialize_rows<T: serde::de::DeserializeOwned>(raw: Vec<String>, context: &str) -> Vec<T> {
    raw.into_iter()
        .filter_map(|s| match serde_json::from_str(&s) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(
                    context,
                    error = %e,
                    "failed to deserialize a stored row — dropped from result set"
                );
                None
            }
        })
        .collect()
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        // Performance pragmas are env-tunable (low-RAM Termux devices may want a
        // smaller page cache / mmap); the schema itself is static (SCHEMA_DDL).
        let cache_kb = env_i64("HSE_SQLITE_CACHE_KB", 2000);
        let mmap = env_i64("HSE_SQLITE_MMAP", 67_108_864);

        let conn = Connection::open(path)?;
        conn.execute_batch(&format!(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            -- Bound the WAL explicitly (512 pages ~2 MB at the 4 KB page size)
            -- rather than SQLite's implicit 1000-page default, so the live -wal
            -- footprint stays bounded under a long-lived `serve`/`live` process on
            -- aarch64/4 GB. PASSIVE (never blocks writers, never shrinks the file);
            -- the file is reset to zero at scan boundaries via checkpoint_truncate().
            PRAGMA wal_autocheckpoint=512;
            PRAGMA temp_store=MEMORY;
            PRAGMA foreign_keys=ON;
            PRAGMA cache_size=-{cache_kb};
            PRAGMA mmap_size={mmap};
            {SCHEMA_DDL}"
        ))?;

        // Schema versioning: stamp on first open; warn on forward-compatibility break.
        {
            let ver: i32 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap_or(0);
            if ver > SCHEMA_VERSION {
                tracing::warn!(
                    db_version = ver,
                    binary_version = SCHEMA_VERSION,
                    "DB schema version is newer than this binary — open with a newer `hse` or use a fresh database"
                );
            }
            if ver < SCHEMA_VERSION {
                conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
            }
        }

        // Idempotent backfill: populate entity_observations for stores created
        // before that table existed (and for any rows missing an observation).
        conn.execute_batch(BACKFILL_OBSERVATIONS_SQL)?;

        // Backfill the FTS index for any pre-existing rows (first run after the
        // index was introduced, or an externally-restored DB). Idempotent: the
        // 'rebuild' command repopulates from the content table deterministically.
        let fts_count: i64 = conn
            .query_row("SELECT count(*) FROM entities_fts", [], |r| r.get(0))
            .unwrap_or(0);
        let ent_count: i64 = conn
            .query_row("SELECT count(*) FROM entities", [], |r| r.get(0))
            .unwrap_or(0);
        if fts_count == 0 && ent_count > 0 {
            // If this fails the FTS index stays empty and search silently returns
            // nothing — the exact "search is broken with no diagnostic" failure
            // mode HSE exists to avoid. Best-effort (a missing index must not
            // block startup), but never silent: leave a trace to debug from.
            if let Err(e) =
                conn.execute_batch("INSERT INTO entities_fts(entities_fts) VALUES('rebuild');")
            {
                tracing::warn!(
                    error = %e,
                    entities = ent_count,
                    "FTS rebuild failed at init — full-text search may return no results until the index is rebuilt"
                );
            } else {
                tracing::info!(
                    entities = ent_count,
                    "rebuilt empty FTS index from existing rows"
                );
            }
        }

        // Query-planner statistics refresh — purely advisory; a failure costs at
        // most a suboptimal plan, never correctness, so it stays best-effort.
        if let Err(e) = conn.execute_batch("PRAGMA optimize;") {
            tracing::debug!(error = %e, "PRAGMA optimize failed (non-fatal)");
        }

        // Restrict the store to owner-only (0600): it holds PII + harvested
        // third-party keys, but SQLite creates the db / `-wal` / `-shm` with the
        // process umask (often 0644). Best-effort, unix-only — and inline `std`
        // (no `storage → util` edge) (PROBLEM_TREE §7 S3). The `-wal`/`-shm` exist
        // by now (WAL mode + the schema write above created them).
        #[cfg(unix)]
        restrict_to_owner_only(&[
            path.to_string(),
            format!("{path}-wal"),
            format!("{path}-shm"),
        ]);

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Checkpoint the WAL and truncate the `-wal` file back to zero bytes.
    ///
    /// `PRAGMA wal_autocheckpoint` runs in PASSIVE mode, which folds committed
    /// pages back into the main database but never shrinks the on-disk `-wal`
    /// file — so under a long-lived process the file high-water-marks and
    /// stays there. This runs an explicit `TRUNCATE` checkpoint at a safe
    /// boundary (a completed scan), resetting the `-wal` to zero and bounding
    /// its footprint. Best-effort: a busy checkpoint (a concurrent reader
    /// holding the WAL) returns `SQLITE_BUSY`, which is surfaced as `Err` for
    /// the caller to log and ignore — the next boundary will retry.
    pub fn checkpoint_truncate(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Run SQLite's `PRAGMA integrity_check` and return whatever it reports.
    ///
    /// A healthy database returns exactly one row, `"ok"`; a corrupt one
    /// returns a row per problem found. Surfaced by `hse doctor` so on-disk
    /// corruption (interrupted write, bad sector, truncated WAL) is detected
    /// explicitly rather than manifesting later as silently missing or wrong
    /// scan results (FTA finding E5.1 / top event T5). Read-only — safe to run
    /// against a live database.
    pub fn integrity_check(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("PRAGMA integrity_check;")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    // ── Scans ──────────────────────────────────────────────────────────────

    pub fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        let json = serde_json::to_string(scan)?;
        let conn = self.conn.lock();
        conn.prepare_cached(
            "INSERT INTO scans(id, target_kind, target_value, status, started_at, finished_at, entity_count, error, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               status       = excluded.status,
               finished_at  = excluded.finished_at,
               entity_count = excluded.entity_count,
               error        = excluded.error,
               data_json    = excluded.data_json",
        )?
        .execute(params![
                scan.id,
                scan.target.kind.canonical_str(),
                scan.target.value,
                scan.status.as_str(),
                scan.started_at as i64,
                scan.finished_at.map(|t| t as i64),
                scan.entity_count as i64,
                scan.error,
                json,
            ],
        )?;
        Ok(())
    }

    pub fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        let json: Option<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached("SELECT data_json FROM scans WHERE id = ?1")?;
            let mut rows = stmt.query(params![id])?;
            rows.next()?.map(|r| r.get(0)).transpose()?
        };
        json.map(|j| serde_json::from_str(&j))
            .transpose()
            .map_err(Into::into)
    }

    pub fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                // `started_at` is 1-second resolution, so a unique secondary
                // key (`id`, the PRIMARY KEY) is required for a deterministic
                // order when scans tie on the same second.
                "SELECT data_json FROM scans ORDER BY started_at DESC, id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
            collect_rows(rows, "list_scans")
        };
        Ok(deserialize_rows(raw, "list_scans"))
    }

    /// Chronological (newest-first) list of past **radar sweeps** — scans
    /// whose target is one of `radar_scan_spec`'s two sentinel anchors
    /// (`Coordinates "0,0"` or `MacAddress "00:00:00:00:00:00"`; the sensors
    /// ignore the value, so it is never a real target). Filters at the SQL
    /// layer with the same `json_extract` technique as
    /// [`Store::latest_finished_scan`], so a deployment with thousands of
    /// ordinary scans doesn't pay to deserialise every one just to find the
    /// radar-tagged handful.
    ///
    /// Sourced entirely from the persisted `scans` table — unlike the
    /// in-memory `LiveSession` bookkeeping (cleared on every restart), this
    /// survives a `hse serve` restart, so an operator reviewing what was
    /// around them earlier can do so without remembering a session id. This
    /// is the query behind `GET /api/v1/radar/history`.
    pub fn radar_history(&self, limit: usize) -> Result<Vec<Scan>> {
        // The raw "0,0"/"00:00:00:00:00:00" `radar_scan_spec` passes to
        // `Target::new` is NOT what ends up persisted: coordinate normalisation
        // (`core::entity::normalise`) rounds to 6 decimal places, so the stored
        // value is `RADAR_SENTINEL_COORD_NORMALISED` — the MAC sentinel is
        // already normalised-form (lowercase, colon-sep, all-zero) and passes
        // through unchanged. Sourced from `core::scan`'s single-defined
        // constants (not re-hardcoded) so this query can't silently drift from
        // what `radar_scan_spec` / `cli::radar` actually seed a sweep with.
        let query = format!(
            "SELECT data_json FROM scans
             WHERE (json_extract(data_json, '$.target.kind') = 'coordinates'
                    AND json_extract(data_json, '$.target.value') = '{}')
                OR (json_extract(data_json, '$.target.kind') = 'mac_address'
                    AND json_extract(data_json, '$.target.value') = '{}')
             ORDER BY started_at DESC, id DESC LIMIT ?1",
            crate::core::scan::RADAR_SENTINEL_COORD_NORMALISED,
            crate::core::scan::RADAR_SENTINEL_MAC,
        );
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(&query)?;
            let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
            collect_rows(rows, "radar_history")
        };
        Ok(deserialize_rows(raw, "radar_history"))
    }

    /// Return the most recent scan in a **terminal state that carries final
    /// data** — `complete` or `aborted` (the lower-case canonical forms from
    /// ScanStatus::as_str). Filters at the SQL layer with a JSON-extract probe
    /// so we don't deserialise dozens of non-matching rows to find one. Used by
    /// `hse export/diff/audit latest …` and the SPA's "open latest scan".
    ///
    /// `aborted` is included deliberately: an operator-cancelled scan keeps the
    /// entities and correlations produced before the stop, "persisted as for a
    /// `Complete` scan" (see [`ScanStatus::Aborted`]), and
    /// [`scan_incompleteness_warning`](crate::app::runtime) already reports its
    /// data as final. Excluding it made `latest` silently skip a perfectly good
    /// aborted scan — the exact scenario a wall-time budget or an operator
    /// cancel produces — and resolve to an older complete one (or none). `failed`
    /// is NOT included: it has no usable entities (its `entity_count` is 0).
    /// Non-terminal states (`pending`/`running`) are excluded because their rows
    /// are still changing.
    ///
    /// Returns `Ok(None)` only when no such scan exists — a genuine SQL failure
    /// or a corrupted `data_json` on the matched row propagates as `Err`, exactly
    /// like [`Store::get_scan`], so a corrupt row is never misreported as "no
    /// finished scans" to `resolve_scan_id`'s callers (`export`/`diff`/`audit
    /// latest`).
    pub fn latest_finished_scan(&self) -> Result<Option<Scan>> {
        let json: Option<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                // Deterministic tie-break on `id` (PRIMARY KEY): `started_at` is
                // 1-second resolution, so without it two scans finishing in the
                // same second make `latest` non-deterministic — `export/diff/audit
                // latest` could resolve to a different scan on identical state.
                "SELECT data_json FROM scans
                 WHERE json_extract(data_json, '$.status') IN ('complete', 'aborted')
                 ORDER BY started_at DESC, id DESC LIMIT 1",
            )?;
            let mut rows = stmt.query(params![])?;
            rows.next()?.map(|r| r.get(0)).transpose()?
        };
        json.map(|j| serde_json::from_str(&j))
            .transpose()
            .map_err(Into::into)
    }

    // ── Correlations ───────────────────────────────────────────────────────

    pub fn upsert_correlation(&self, c: &Correlation) -> Result<()> {
        use std::collections::HashSet;
        let json = serde_json::to_string(c)?;
        let uids = serde_json::to_string(&c.entity_uids)?;
        let conn = self.conn.lock();

        // Set-containment dedup so an aggregate correlation whose member set
        // GROWS across expansion rounds is not persisted once per round.
        // Entities are never removed mid-scan, so a cluster only grows: a new
        // correlation whose member set is a strict superset of an existing one
        // (same scan + rule) supersedes it; a subset/equal is a stale earlier
        // emission and is skipped; disjoint sets (distinct clusters, or distinct
        // pair-rule findings) coexist as separate rows. Without this, AU-002 /
        // AU-013 / AU-018 / AU-019 … each re-fired with a larger uid set and a
        // new count-bearing description every round, defeating both the
        // in-memory (rule_id+uids) and DB (rule_id+description) dedup keys.
        let new_set: HashSet<&str> = c.entity_uids.iter().map(String::as_str).collect();
        // Stream the candidate rows and fold the set-containment decision in a
        // single pass: no intermediate `Vec<(rowid, Vec<String>)>` is
        // materialised, and each old uid list is parsed into a transient
        // `HashSet` that is dropped before the next row (only the small
        // `superseded` rowid list survives the loop). Behaviourally identical to
        // collect-then-scan: a subset/equal match still short-circuits with
        // `Ok(())`, and every old set that is a subset of `new_set` is recorded.
        let mut superseded: Vec<i64> = Vec::new();
        let early_return = {
            let mut stmt = conn.prepare_cached(
                "SELECT rowid, entity_uids FROM correlations WHERE scan_id = ?1 AND rule_id = ?2",
            )?;
            let mut rows = stmt.query(params![c.scan_id, c.rule_id])?;
            let mut already_represented = false;
            while let Some(row) = rows.next()? {
                let rowid: i64 = row.get(0)?;
                let j: String = row.get(1)?;
                let old_uids = serde_json::from_str::<Vec<String>>(&j).unwrap_or_default();
                let old_set: HashSet<&str> = old_uids.iter().map(String::as_str).collect();
                if new_set.is_subset(&old_set) {
                    // Subset of (or equal to) a stored correlation — already represented.
                    already_represented = true;
                    break;
                }
                if old_set.is_subset(&new_set) {
                    superseded.push(rowid);
                }
            }
            already_represented
        };
        if early_return {
            return Ok(());
        }
        // Atomic supersede: delete the superseded rows AND insert the
        // replacement in one transaction, so a crash or mid-statement error
        // (SQLITE_FULL/BUSY, OOM-kill) can't leave the cluster's predecessors
        // deleted with no replacement — that would silently drop a finding.
        // Mirrors delete_scan / upsert_entities_batch. Rolls back on drop if a
        // statement errors (the `?` returns before commit).
        let tx = conn.unchecked_transaction()?;
        {
            // One prepared DELETE reused across all superseded rows.
            let mut del = tx.prepare_cached("DELETE FROM correlations WHERE rowid = ?1")?;
            for rowid in superseded {
                del.execute(params![rowid])?;
            }
        }
        tx.execute(
            "INSERT INTO correlations(scan_id, rule_id, severity, description, entity_uids, ts, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(scan_id, rule_id, description) DO NOTHING",
            params![
                c.scan_id,
                c.rule_id,
                c.severity.as_canonical(),
                c.description,
                uids,
                c.ts as i64,
                json,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            // SQL pre-orders by severity (keeps rows that predate the `rank`
            // field, which deserialize with rank 0.0, in a sane order); the
            // authoritative ranking is applied in Rust below using the
            // persisted `rank` (severity × max child C_eff), which SQL can't
            // see inside `data_json` without a column + migration.
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM correlations WHERE scan_id = ?1
                 ORDER BY CASE severity
                     WHEN 'critical' THEN 0
                     WHEN 'high'     THEN 1
                     WHEN 'medium'   THEN 2
                     WHEN 'low'      THEN 3
                     ELSE 4
                 END, id",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            collect_rows(rows, "correlations_for_scan")
        };
        let mut corrs: Vec<Correlation> = deserialize_rows(raw, "correlations_for_scan");
        // Rank desc: severity × max child C_eff (computed at correlator-run
        // time). Stable tie-break on severity then rule_id, matching the
        // correlator's own ordering so CLI and API agree.
        corrs.sort_by(|a, b| {
            b.rank
                .partial_cmp(&a.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.severity.cmp(&a.severity))
                .then(a.rule_id.cmp(&b.rule_id))
        });
        Ok(corrs)
    }

    // ── Relations ──────────────────────────────────────────────────────────
    // Typed entity-to-entity edges. Idempotent on the deterministic `id` so a
    // re-scan that re-derives the same edge does not duplicate it.

    pub fn upsert_relation(&self, r: &Relation) -> Result<()> {
        let json = serde_json::to_string(r)?;
        let conn = self.conn.lock();
        conn.prepare_cached(
            "INSERT INTO relations(id, scan_id, from_uid, to_uid, kind, confidence, observed_at, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO NOTHING",
        )?
        .execute(params![
                r.id,
                r.scan_id,
                r.from_uid,
                r.to_uid,
                r.kind.as_str(),
                r.confidence,
                r.observed_at as i64,
                json,
            ],
        )?;
        Ok(())
    }

    /// Batch-insert relations in ONE transaction (one autocommit → one fsync
    /// instead of one per edge at finalise). All-or-nothing; the caller falls
    /// back to per-relation [`Self::upsert_relation`] on error. Returns
    /// `rels.len()`. Same `ON CONFLICT(id) DO NOTHING` idempotence as the
    /// single-row path, so a re-scan re-deriving the same edge never duplicates.
    pub fn upsert_relations_batch(&self, rels: &[Relation]) -> Result<usize> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        for r in rels {
            let json = serde_json::to_string(r)?;
            tx.prepare_cached(
                "INSERT INTO relations(id, scan_id, from_uid, to_uid, kind, confidence, observed_at, data_json)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO NOTHING",
            )?
            .execute(params![
                r.id,
                r.scan_id,
                r.from_uid,
                r.to_uid,
                r.kind.as_str(),
                r.confidence,
                r.observed_at as i64,
                json,
            ])?;
        }
        tx.commit()?;
        Ok(rels.len())
    }

    pub fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM relations WHERE scan_id = ?1 ORDER BY kind, id",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            collect_rows(rows, "relations_for_scan")
        };
        Ok(deserialize_rows(raw, "relations_for_scan"))
    }

    // ── Delete (cascade) ───────────────────────────────────────────────────

    pub fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let n = tx.execute("DELETE FROM scans WHERE id = ?1", params![scan_id])?;
        if n == 0 {
            if let Err(e) = tx.rollback() {
                tracing::warn!(error = %e, "rollback failed during delete_scan");
            }
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM correlations WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM entity_observations WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute("DELETE FROM events WHERE scan_id = ?1", params![scan_id])?;
        tx.execute("DELETE FROM relations WHERE scan_id = ?1", params![scan_id])?;
        // `stealer_rows` is scan-scoped like every table above and holds the most
        // sensitive payload in the store — stolen login/password pairs. It has no
        // other prune path, so omitting it here left a deleted scan's credentials
        // live on disk (and `stealer_rows_for_scan` still returns them) and let the
        // table grow unbounded. A cascade delete must reach it too.
        tx.execute(
            "DELETE FROM stealer_rows WHERE scan_id = ?1",
            params![scan_id],
        )?;
        // FTS sync: a contentless-external FTS5 index never observes a bare
        // DELETE on its content table, so each orphaned row's text must be
        // removed with an explicit 'delete' command BEFORE the row goes away.
        // Without this the stale posting outlives the row, and once SQLite
        // reuses the freed rowid for a NEW entity, a full-text search for the
        // deleted value silently returns that unrelated entity — breaking the
        // 'always-synchronized index' invariant the write path maintains
        // (see merge_and_persist_entity).
        let orphans: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare_cached(
                "SELECT rowid, value, kind FROM entities e
                 WHERE NOT EXISTS (SELECT 1 FROM entity_observations o WHERE o.entity_uid = e.uid)",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        // Reuse one prepared 'delete' statement across all orphans rather than
        // re-compiling the same SQL once per row — the orphan set can be large
        // after deleting a high-yield scan, and statement compilation is pure
        // overhead on aarch64.
        {
            let mut del_fts = tx.prepare_cached(
                "INSERT INTO entities_fts(entities_fts, rowid, value, kind)
                 VALUES('delete', ?1, ?2, ?3)",
            )?;
            for (rowid, value, kind) in orphans {
                del_fts.execute(params![rowid, value, kind])?;
            }
        }
        tx.execute(
            "DELETE FROM entities
             WHERE NOT EXISTS (SELECT 1 FROM entity_observations o WHERE o.entity_uid = entities.uid)",
            [],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Prune events older than `max_age_secs` and limit total rows to
    /// `max_rows`. Prevents unbounded database growth from long-running
    /// or repeated scans. Called automatically at startup.
    pub fn prune_events(&self, max_age_secs: u64, max_rows: usize) -> Result<usize> {
        let conn = self.conn.lock();
        let cutoff = crate::core::entity::unix_now().saturating_sub(max_age_secs);
        let aged = conn.execute("DELETE FROM events WHERE ts < ?1", params![cutoff as i64])?;
        let excess = conn.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?1)",
            params![max_rows as i64],
        )?;
        let total = aged + excess;
        if total > 0 {
            tracing::info!("pruned {total} old events ({aged} aged, {excess} excess)");
        }
        Ok(total)
    }
}

// Entity persistence + FTS query live in the `entities` submodule (impl Store).

// ── Event log ─────────────────────────────────────────────────────────────

impl Store {
    pub fn insert_event(&self, event: &Event) -> Result<()> {
        let event_type = event.kind.event_type_str();
        let json = serde_json::to_string(event)?;
        let conn = self.conn.lock();
        conn.prepare_cached(
            "INSERT INTO events(scan_id, ts, event_type, data_json)
             VALUES(?1, ?2, ?3, ?4)",
        )?
        .execute(params![event.scan_id, event.ts as i64, event_type, json])?;
        Ok(())
    }

    /// Batch-insert events in ONE transaction. The db-writer coalesces up to 64
    /// events per drain; committing them as 64 autocommit INSERTs meant 64
    /// BEGIN/COMMIT + fsync round-trips on the phone's flash filesystem. All-or-
    /// nothing; the caller falls back to per-event [`Self::insert_event`] on
    /// error. Returns `events.len()`.
    pub fn insert_events_batch(&self, events: &[Event]) -> Result<usize> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        for event in events {
            let event_type = event.kind.event_type_str();
            let json = serde_json::to_string(event)?;
            tx.prepare_cached(
                "INSERT INTO events(scan_id, ts, event_type, data_json)
                 VALUES(?1, ?2, ?3, ?4)",
            )?
            .execute(params![event.scan_id, event.ts as i64, event_type, json])?;
        }
        tx.commit()?;
        Ok(events.len())
    }

    pub fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM events WHERE scan_id = ?1 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            collect_rows(rows, "events_for_scan")
        };
        Ok(deserialize_rows(raw, "events_for_scan"))
    }

    /// The most recent `ModuleDone`/`ModuleError` events **across all scans**,
    /// newest first, bounded by `limit` — the raw substrate for the per-source
    /// health signal (`PROBLEM_TREE` T2.7 / `SOLUTION_TREE` SOL-HEALTH-SIGNAL,
    /// see [`crate::util::scraper_health`]). Filtered at the SQL layer (not by
    /// the caller) so a health check never has to wade through
    /// `ModuleStart`/`ModuleSkipped`/entity/correlation rows to find the two
    /// kinds it cares about. Naturally a ROLLING window: `events` is already
    /// pruned to [`crate::core::port::EVENTS_RETENTION_SECS`] /
    /// [`crate::core::port::EVENTS_MAX_ROWS`] (see [`Self::prune_events`]), so
    /// this reflects recent scans only, not full history — a source that
    /// broke and was never scanned again ages out rather than staying flagged
    /// forever.
    pub fn recent_module_outcome_events(&self, limit: usize) -> Result<Vec<Event>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM events
                 WHERE event_type IN ('module_done', 'module_error')
                 ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
            collect_rows(rows, "recent_module_outcome_events")
        };
        Ok(deserialize_rows(raw, "recent_module_outcome_events"))
    }
}

impl crate::core::port::StoragePort for Store {
    fn checkpoint_truncate(&self) -> Result<()> {
        Store::checkpoint_truncate(self)
    }

    fn integrity_check(&self) -> Result<Vec<String>> {
        Store::integrity_check(self)
    }

    fn prune_events(&self, max_age_secs: u64, max_rows: usize) -> Result<usize> {
        Store::prune_events(self, max_age_secs, max_rows)
    }

    fn prune_raw_archive(&self, max_rows: usize) -> Result<usize> {
        Store::prune_raw_archive(self, max_rows)
    }

    fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        Store::upsert_scan(self, scan)
    }

    fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        Store::get_scan(self, id)
    }

    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        Store::list_scans(self, limit)
    }

    fn radar_history(&self, limit: usize) -> Result<Vec<Scan>> {
        Store::radar_history(self, limit)
    }

    fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        Store::delete_scan(self, scan_id)
    }

    fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        Store::upsert_entity(self, entity)
    }

    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize> {
        Store::upsert_entities_batch(self, entities)
    }

    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
        Store::entities_for_scan(self, scan_id)
    }

    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>> {
        Store::entities_filtered(self, scan_id, kind, min_confidence, value_contains)
    }

    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
        Store::entity_facets(self, scan_id)
    }

    fn get_entity(&self, uid: &str) -> Result<Option<Entity>> {
        Store::get_entity(self, uid)
    }

    fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
        Store::search_entities(self, query, limit)
    }

    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
        Store::scan_ids_for_entity(self, entity_uid)
    }

    fn observation_count(&self, entity_uid: &str) -> Result<usize> {
        Store::observation_count(self, entity_uid)
    }

    fn upsert_correlation(&self, c: &Correlation) -> Result<()> {
        Store::upsert_correlation(self, c)
    }

    fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        Store::correlations_for_scan(self, scan_id)
    }

    fn upsert_relation(&self, r: &Relation) -> Result<()> {
        Store::upsert_relation(self, r)
    }

    fn upsert_relations_batch(&self, rels: &[Relation]) -> Result<usize> {
        Store::upsert_relations_batch(self, rels)
    }

    fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>> {
        Store::relations_for_scan(self, scan_id)
    }

    fn insert_event(&self, event: &Event) -> Result<()> {
        Store::insert_event(self, event)
    }

    fn insert_events_batch(&self, events: &[Event]) -> Result<usize> {
        Store::insert_events_batch(self, events)
    }

    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>> {
        Store::events_for_scan(self, scan_id)
    }

    fn recent_module_outcome_events(&self, limit: usize) -> Result<Vec<Event>> {
        Store::recent_module_outcome_events(self, limit)
    }

    fn archive_module_result(&self, key: &str, ttl_secs: u64, entities: &[Entity]) -> Result<()> {
        Store::archive_module_result(self, key, ttl_secs, entities)
    }

    fn lookup_module_result_fresh(&self, key: &str) -> Result<Option<Vec<Entity>>> {
        Store::lookup_module_result_fresh(self, key)
    }

    fn record_pathway_template(&self, template: &str) -> Result<()> {
        Store::record_pathway_template(self, template)
    }

    fn pathway_template_count(&self, template: &str) -> Result<u32> {
        Store::pathway_template_count(self, template)
    }

    fn insert_stealer_rows_batch(
        &self,
        scan_id: &str,
        rows: &[crate::core::stealer_row::StealerRow],
    ) -> Result<usize> {
        Store::insert_stealer_rows_batch(self, scan_id, rows)
    }

    fn stealer_rows_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<crate::core::stealer_row::StealerRow>> {
        Store::stealer_rows_for_scan(self, scan_id)
    }
}

// ── Tests (from store/mod.rs) ─────────────────────────────────────────────

#[cfg(test)]
mod tests;
