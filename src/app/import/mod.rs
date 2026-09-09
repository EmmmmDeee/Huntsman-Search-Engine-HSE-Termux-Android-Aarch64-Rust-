//! `hse import` — ingest OathNet JSON/HTML/stealer-TXT exports and breach/
//! dossier compilations as first-class scans. This module holds the format
//! dispatcher, the web-upload entry point and the shared persistence /
//! stats / entity-construction helpers; one submodule per file format owns
//! its parser, reaching the shared helpers through `use super::*`.

use crate::core::error::{Error, Result};

mod combined;
mod combolist;
mod csv;
mod dossier;
mod html;
mod json;
mod kml;
mod local;
mod oathnet_report;
mod sql_dump;
mod stealer;
#[cfg(test)]
mod tests;
mod txt;

// Format parsers live in the per-format submodules; pull their entry points
// into scope for the dispatcher, the web-upload router and the tests.
use crate::core::confidence;
use combined::{cmd_import_combined, looks_like_combined_search, parse_combined_search};
use combolist::{cmd_import_combolist, looks_like_combolist, parse_combolist};
use csv::{
    cmd_import_csv, cmd_import_hse_csv, looks_like_dehashed_csv, looks_like_hse_csv,
    parse_dehashed_csv, parse_hse_csv,
};
use dossier::{cmd_import_dossier, parse_dossier};
use html::{cmd_import_html, parse_oathnet_html};
use json::{import_json_output, parse_oathnet_json};
use local::cmd_import_local_dir;
use oathnet_report::{cmd_import_oathnet_report, looks_like_oathnet_report, parse_oathnet_report};
use sql_dump::{cmd_import_sql_dump, looks_like_sql_dump, parse_sql_dump};
use stealer::{cmd_import_stealerlogs, looks_like_stealerlogs, parse_stealerlogs};
use txt::{cmd_import_txt, parse_oathnet_txt};

/// `hse import`: parse one file (or scrape a directory) into a new scan.
///
/// `forced` is the operator's `--input-format`: `Some` bypasses content
/// detection and dispatches straight to that format's parser — for a file the
/// detector cannot classify (a combolist of bare usernames with no
/// email-shaped line scores 0% on the combolist heuristic and would fall to
/// the TXT catch-all as zero entities) or classifies wrongly. It applies to a
/// single file only: a directory scrape detects each file's format from its
/// content by design, so forcing one format across a tree is refused
/// explicitly rather than silently ignored.
pub async fn cmd_import(path: &str, output: &str, forced: Option<ImportFormat>) -> Result<()> {
    // File-size cap before read_to_string — mirrors MAX_UPLOAD_BYTES in the API
    // upload handler (16 MB) so both paths enforce the same memory bound.
    const MAX_IMPORT_BYTES: u64 = 16 * 1024 * 1024;
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| Error::Other(format!("cannot stat {path}: {e}")))?;
    // A directory path is a LOCAL-STORAGE SCRAPE: every recognised artifact under
    // the tree (scan/dossier/stealer-log/breach export/debug bundle) is imported
    // through the same content-based dispatcher and aggregated into one scan.
    // Offline — reads local files only — so it works on a Termux install with no
    // connectivity. Bounded by depth/count/size in `cmd_import_local_dir`.
    if meta.is_dir() {
        if let Some(f) = forced {
            return Err(Error::Other(format!(
                "--input-format {} applies to a single file, but {path} is a directory \
                 (a directory scrape detects each file's format from its content)",
                f.label()
            )));
        }
        return cmd_import_local_dir(path, output).await;
    }
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(Error::Other(format!(
            "file too large ({} bytes > 16 MB): {path}",
            meta.len()
        )));
    }
    let body = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| Error::Other(format!("cannot read {path}: {e}")))?;

    // Dispatch on the shared, CONTENT-based detector so a file imports the same
    // whether it arrives via the CLI (here) or the browser
    // (`entities_from_upload`). The previous code gated the combined / dossier /
    // stealer / OathNet-report text formats behind a `.txt` extension, so a
    // breach/dossier export saved under any other name (or none) was mis-routed
    // to the JSON parser and rejected as "invalid JSON" — silently dropping a
    // legitimate import the UI accepted fine.
    // A UTF-8 BOM (U+FEFF) is NOT whitespace, so the detector's `trim_start` leaves
    // it in place and a BOM-prefixed CSV/JSON export (common from Excel / Windows
    // tools) misroutes to the wrong parser → every entity silently dropped. Strip it
    // once so BOTH detection and the parser below see clean text.
    let body = body
        .strip_prefix('\u{feff}')
        .map(str::to_string)
        .unwrap_or(body);
    let format = match forced {
        Some(f) => {
            note(
                output,
                format!(
                    "Input format forced to `{}` by --input-format (content detection bypassed)",
                    f.label()
                ),
            );
            f
        }
        None => detect_import_format(path, &body),
    };
    match format {
        ImportFormat::OathnetHtml => cmd_import_html(&body, output).await,
        ImportFormat::OathnetJson => {
            let doc: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| Error::Other(format!("invalid JSON: {e}")))?;
            let export_info = doc.get("exportInfo").and_then(|v| v.as_object());
            let query = export_info
                .and_then(|ei| ei.get("query"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let date = export_info
                .and_then(|ei| ei.get("exportDate"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            note(
                output,
                format!("Importing OathNet JSON export: query=\"{query}\", date={date}"),
            );
            let sid = format!("import-{}", crate::core::entity::unix_now());
            let (mut entities, stats) = parse_oathnet_json(&doc, &sid).await;
            deduplicate_by_uid(&mut entities);
            print_import_stats(&stats, entities.len(), output);
            persist_and_report(&sid, &entities, output).await;
            import_json_output(&entities, &stats, query, date, path, output)
        }
        ImportFormat::CombinedSearch => cmd_import_combined(&body, output).await,
        ImportFormat::Dossier => cmd_import_dossier(&body, output).await,
        ImportFormat::Stealerlogs => cmd_import_stealerlogs(&body, output).await,
        ImportFormat::OathnetReport => cmd_import_oathnet_report(&body, output).await,
        ImportFormat::HseCsv => cmd_import_hse_csv(&body, output).await,
        ImportFormat::DehashedCsv => cmd_import_csv(&body, output).await,
        ImportFormat::Kml => kml::cmd_import_kml(&body, output).await,
        ImportFormat::Combolist => cmd_import_combolist(&body, output).await,
        ImportFormat::SqlDump => cmd_import_sql_dump(&body, output).await,
        ImportFormat::OathnetTxt => cmd_import_txt(&body, output).await,
    }
}

/// The detected import format — one variant per parser. The single source of
/// truth both the CLI ([`cmd_import`]) and the web upload ([`entities_from_upload`])
/// dispatch on, so the two can never drift on which format a file is.
///
/// Also the operator-facing spelling of every format: the clap `ValueEnum`
/// derive names each variant in kebab-case (`sql-dump`, `oathnet-txt`, …) —
/// what `hse import --input-format` accepts, what the web upload's `?format=`
/// query parameter accepts, and (via [`Self::label`]) what both report back.
/// One enum, one spelling; a test locks `label` to the derived names, and the
/// web UI's selector to this list, so no second copy can drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ImportFormat {
    /// An OathNet HTML export.
    OathnetHtml,
    /// An OathNet JSON export (a Combined Search JSON is recognised by its shape).
    OathnetJson,
    /// A Combined Search text export (numbered records with a source/db field and identity fields).
    CombinedSearch,
    /// A breach/dossier compilation (`Entry #N:` blocks and `EMAILS:`/`PASSWORDS:` lists).
    Dossier,
    /// A `Module: Stealerlogs` victim export (`Victims:` blocks with `Log Id:` and `Credentials:`).
    Stealerlogs,
    /// An OathNet SEARCH REPORT (`=== DATABASE LOGS ===` sections).
    OathnetReport,
    /// HSE's own `hse export --format csv` entity CSV, re-ingested.
    HseCsv,
    /// A DeHashed-style breach CSV (an identity column plus `database_name` / `hashed_password*`).
    DehashedCsv,
    /// A WiGLE-style KML wardriving export.
    ///
    /// The native output of the capture device, previously unrecognised and
    /// therefore swallowed by the TXT catch-all, which extracted nothing from it.
    Kml,
    /// A raw `identity:secret` combolist — one leaked login per line, no header, no envelope.
    ///
    /// The most common real-world breach-data shape; without this variant it
    /// fell through to `OathnetTxt` and parsed as nothing.
    Combolist,
    /// A leaked breach SQL dump — `INSERT INTO ... (cols) VALUES (...);` statements.
    ///
    /// The shape a `mysqldump`-style export of a compromised user table takes.
    /// Without this variant it fell through to `OathnetTxt` and parsed as nothing.
    SqlDump,
    /// An OathNet stealer-log TXT export — also the catch-all for any unrecognised plain text.
    OathnetTxt,
}

impl ImportFormat {
    /// The operator-facing name of this format: the label the web upload and
    /// the CLI report, and the spelling `--input-format` / `?format=` accept.
    /// Hand-written so it is `'static`; a test locks every arm to the clap
    /// `ValueEnum` spelling, so the two can never disagree.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::OathnetHtml => "oathnet-html",
            Self::OathnetJson => "oathnet-json",
            Self::CombinedSearch => "combined-search",
            Self::Dossier => "dossier",
            Self::Stealerlogs => "stealerlogs",
            Self::OathnetReport => "oathnet-report",
            Self::HseCsv => "hse-csv",
            Self::DehashedCsv => "dehashed-csv",
            Self::Kml => "kml",
            Self::Combolist => "combolist",
            Self::SqlDump => "sql-dump",
            Self::OathnetTxt => "oathnet-txt",
        }
    }

    /// Parse an operator-supplied format name — the `--input-format` /
    /// `?format=` spelling, case-insensitive, surrounding whitespace ignored.
    /// The error names every accepted spelling, so a typo is actionable
    /// rather than a bare rejection (and never a silent fall back to
    /// detection, which is exactly what the operator asked to bypass).
    pub(crate) fn parse_name(name: &str) -> std::result::Result<Self, String> {
        <Self as clap::ValueEnum>::from_str(name.trim(), true).map_err(|_| {
            let accepted: Vec<&'static str> = <Self as clap::ValueEnum>::value_variants()
                .iter()
                .copied()
                .map(Self::label)
                .collect();
            format!(
                "unknown import format `{}`; expected one of: {}",
                name.trim(),
                accepted.join(", ")
            )
        })
    }
}

/// Classify an import body by CONTENT (never by extension alone), so a breach
/// export imports identically under any filename. `path` only contributes the
/// `.html`/`.csv` hints layered on top of the content checks; pass `""` when
/// there is no file (the web upload). Pure — no I/O — so the whole detection
/// matrix is unit-tested directly.
pub(crate) fn detect_import_format(path: &str, body: &str) -> ImportFormat {
    // A UTF-8 BOM (U+FEFF) is NOT whitespace, so `trim_start` won't drop it; strip
    // it first so a BOM-prefixed export is classified by its real first token rather
    // than misrouted. (The cmd_import / entities_from_upload callers also strip it
    // from the body they hand the PARSER, since serde_json etc. reject a leading BOM.)
    let head = body.trim_start_matches('\u{feff}').trim_start();
    // KML before the HTML check: a KML document opens `<?xml …`, which the HTML
    // test below does not match, so without this it fell through every text
    // heuristic to the TXT catch-all and yielded nothing. Detected by the OGC
    // namespace or the root element, never by the `.kml` extension alone.
    if kml::looks_like_kml(head) {
        return ImportFormat::Kml;
    }
    // HTML first (by content or the `.html` hint).
    if path.ends_with(".html") || head.starts_with("<!") || head.starts_with("<html") {
        return ImportFormat::OathnetHtml;
    }
    // A JSON object before the text heuristics, so a JSON body can never be
    // mis-keyed by a `looks_like_*` substring match.
    if head.starts_with('{') {
        return ImportFormat::OathnetJson;
    }
    if looks_like_combined_search(body) {
        return ImportFormat::CombinedSearch;
    }
    if looks_like_dossier(body) {
        return ImportFormat::Dossier;
    }
    if looks_like_stealerlogs(body) {
        return ImportFormat::Stealerlogs;
    }
    if looks_like_oathnet_report(body) {
        return ImportFormat::OathnetReport;
    }
    if looks_like_hse_csv(body) {
        return ImportFormat::HseCsv;
    }
    if path.ends_with(".csv") || looks_like_dehashed_csv(body) {
        return ImportFormat::DehashedCsv;
    }
    // A SQL dump's `INSERT INTO ... VALUES` structure is distinctive enough
    // to check ahead of the combolist fallback (which needs a majority-line
    // heuristic — a single real match here is already unambiguous).
    if looks_like_sql_dump(body) {
        return ImportFormat::SqlDump;
    }
    // Fallback, checked last: only claims what every more specific format
    // above already declined, and only when it is overwhelmingly
    // combolist-shaped (see `looks_like_combolist`'s doc comment).
    if looks_like_combolist(body) {
        return ImportFormat::Combolist;
    }
    ImportFormat::OathnetTxt
}

/// Render parsed import entities to stdout for the text-import paths (HTML / TXT
/// / breach-dossier), which all share the `{ "entities": [...] }` JSON shape: one
/// JSON document under `--output json` (so `| jq` works), else a 50-row
/// human-readable table with an "… and N more" footer. One definition so the
/// JSON shape and the table format can't drift between the three callers.
fn render_import_entities(entities: &[crate::core::entity::Entity], output: &str) {
    if output == "json" {
        let out = serde_json::json!({ "entities": entities });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for e in entities.iter().take(50) {
            println!(
                "  [{:.2}] {:15} {}",
                e.confidence,
                e.kind.to_string(),
                crate::util::str_util::truncate_safe(&e.value, 70)
            );
        }
        if entities.len() > 50 {
            println!("  ... and {} more", entities.len() - 50);
        }
    }
}

/// Heuristic: does this text look like a breach/dossier compilation (the
/// `Entry #N:` + `• key: value` + `USERNAMES:`/`EMAILS:`/`PASSWORDS:` format)
/// rather than an OathNet stealer-log TXT? Any one strong marker is enough.
pub(crate) fn looks_like_dossier(body: &str) -> bool {
    body.contains("Entry #")
        || body.contains('\u{2022}') // the `•` bullet that prefixes entry fields
        || ((body.contains("USERNAMES:")
            || body.contains("EMAILS:")
            || body.contains("PASSWORDS:"))
            && body.contains("->"))
}

/// Detect an uploaded file's format from its CONTENT and parse it into finalised
/// (deduplicated, evidence/tag-canonicalised) entities for `sid`, returning the
/// entities plus a format label. This is the single entry the WEB upload uses,
/// so EVERY import format the CLI supports — OathNet JSON/HTML/stealer-TXT and
/// the breach/dossier compilation — is reachable from the Termux UI, parsed by
/// the exact same `parse_*` functions the CLI calls (they can never drift).
/// `async` because the JSON path opportunistically validates discovered keys.
/// `forced` (the upload's `?format=`, the CLI's `--input-format`) bypasses
/// detection and dispatches straight to that format's parser.
pub(crate) async fn entities_from_upload(
    body: &str,
    sid: &str,
    forced: Option<ImportFormat>,
) -> Result<(Vec<crate::core::entity::Entity>, &'static str)> {
    // Same content-based detector the CLI dispatches on (no path → content only),
    // so the browser upload and `hse import` can never disagree on a file's format
    // — unless the operator forces one, which bypasses detection identically on
    // both surfaces.
    // Strip a leading UTF-8 BOM (U+FEFF) — not whitespace, so the detector's
    // trim_start misses it — before both detection and parsing, or a BOM-prefixed
    // upload misroutes and silently drops every entity.
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    let format = forced.unwrap_or_else(|| detect_import_format("", body));
    let label = format.label();
    let (mut entities, label) = match format {
        ImportFormat::OathnetHtml => (parse_oathnet_html(body, sid), label),
        ImportFormat::OathnetJson => {
            let doc: serde_json::Value = serde_json::from_str(body)
                .map_err(|e| Error::Other(format!("invalid JSON: {e}")))?;
            // A `{`-body is routed here whether it is an OathNet-native export or a
            // Combined Search JSON (`{ "modules": [ … ] }`); `parse_oathnet_json`
            // dispatches on the shape, so label it by the same discriminator and the
            // UI reports the format it actually parsed.
            let label = if doc.get("modules").and_then(|v| v.as_array()).is_some() {
                "combined-search-json"
            } else {
                label
            };
            (parse_oathnet_json(&doc, sid).await.0, label)
        }
        ImportFormat::CombinedSearch => (parse_combined_search(body, sid).0, label),
        ImportFormat::Dossier => (parse_dossier(body, sid).0, label),
        ImportFormat::Stealerlogs => (parse_stealerlogs(body, sid).0, label),
        ImportFormat::OathnetReport => (parse_oathnet_report(body, sid).0, label),
        ImportFormat::HseCsv => (parse_hse_csv(body, sid).0, label),
        ImportFormat::DehashedCsv => (parse_dehashed_csv(body, sid).0, label),
        ImportFormat::Kml => (kml::parse_kml(body, sid).0, label),
        ImportFormat::Combolist => (parse_combolist(body, sid).0, label),
        ImportFormat::SqlDump => (parse_sql_dump(body, sid).0, label),
        ImportFormat::OathnetTxt => (parse_oathnet_txt(body, sid).0, label),
    };
    deduplicate_by_uid(&mut entities);
    Ok((entities, label))
}

/// Case-insensitive exact match of a header `column` against one of
/// `candidates` — the shared column-name authority for a breach export whose
/// schema is NOT fixed (an arbitrary compromised database's own naming, unlike
/// DeHashed's own fixed CSV header): a real column named `email_address`,
/// `user_name` or `mobile` is exactly as likely as `email`/`username`/`phone`,
/// and matching only the single canonical name silently drops a present field
/// with no warning — the same silent-breach-data-loss class this whole import
/// surface exists to close. Originally private to the SQL-dump parser; promoted
/// here (mirroring `util::extract::split_identity_secret`'s promotion out of
/// `comb_search` earlier in this same effort) once the DeHashed CSV parser was
/// found to need the identical tolerance for the identical reason — reproduced
/// live: a CSV row identical but for using `email_address`/`user_name`/`pass`/
/// `mobile`/`street_address` instead of DeHashed's own names silently dropped
/// every one of those fields while still reporting "Imported 2 entities", no
/// quarantine, no warning.
fn column_matches(column: &str, candidates: &[&str]) -> bool {
    let lower = column.to_ascii_lowercase();
    candidates.iter().any(|c| lower == *c)
}

/// Find the first header column matching one of `candidates` (see
/// [`column_matches`]).
fn find_column(columns: &[String], candidates: &[&str]) -> Option<usize> {
    columns.iter().position(|c| column_matches(c, candidates))
}

#[derive(Default)]
struct ImportStats {
    breach_records: usize,
    stealer_docs: usize,
    victim_records: usize,
    emails: usize,
    phones: usize,
    ips: usize,
    domains: usize,
    subdomains: usize,
    urls: usize,
    usernames: usize,
    coordinates: usize,
    addresses: usize,
    /// Wi-Fi network names and hardware BSSIDs recovered from a wardriving
    /// export. Counted separately because a survey's yield is networks-per-run,
    /// and rolling them into `machines` (stealer-log victim hosts) would report
    /// a wardrive as a breach.
    ssids: usize,
    bssids: usize,
    holehe: usize,
    machines: usize,
    device_users: usize,
    hwids: usize,
    discord_ids: usize,
    admin_paths: usize,
    api_keys: usize,
    api_keys_valid: usize,
    persons: usize,
    organisations: usize,
    credentials: usize,
    /// Structurally malformed input units quarantined and skipped rather than
    /// aborting the whole import: for the combolist importer, a line that
    /// failed to parse as `identity:secret` (no delimiter, an empty identity,
    /// or an empty secret); for the SQL-dump importer, a value tuple that
    /// failed to close cleanly or whose value count didn't match its column
    /// list. Every other format either has no line/row-oriented shape to
    /// malform, or already drops unparseable rows silently (unchanged
    /// behaviour).
    malformed_lines: usize,
    date_range: String,
}

pub(crate) fn deduplicate_by_uid(entities: &mut Vec<crate::core::entity::Entity>) {
    // Shared finalization step for all three import parsers (JSON/HTML/TXT).
    // Drop documentation/reserved IPs (192.0.2.x / 198.51.100.x / 203.0.113.x /
    // 0.x / 240.0.0.0/4 / 2001:db8::/32) lifted out of exported data — they can
    // never be real hosts and would otherwise pollute the graph and fire
    // correlations. This mirrors the scan path's admission guard
    // (engine::finalise_module_result) for the import path, which builds
    // entities directly. RFC1918 private / loopback are intentionally kept —
    // they can be genuine local findings in a stealer log.
    //
    // Combined with the domain check below into a single retain pass (the two
    // predicates apply to disjoint entity kinds, so this is behaviour-identical)
    // to avoid a second full traversal + element shift on large imports.
    //
    // Domain branch: drop IP literals mis-classified as domains — the HTML/TXT
    // parsers' domain regex matches dotted-decimal IPs (8.8.8.8, 192.0.2.1) and
    // emits them as Domain entities, which both duplicates the real ip_address
    // entity and smuggles bogus documentation IPs past the IP-kind filter. A real
    // domain never parses as an IP address, so this has no false positives.
    entities.retain(|e| {
        // Mirror the scan-path admission guard for EVERY importer in one place:
        // drop documentation/template placeholders (example.com,
        // firstname@gmail.com, John Doe) and truncated fragments (@gmail, a
        // dotless "gmail" domain). Most parsers already filter these at
        // construction, but the HTML/JSON parsers did not, so a centralised pass
        // keeps them from leaking in. Both predicates exempt secrets internally,
        // so a real password/API-key/credential value is never dropped here.
        if crate::core::validation::is_placeholder_entity(&e.kind, &e.value)
            || crate::core::validation::is_fragment_value(&e.kind, &e.value)
        {
            return false;
        }
        if e.kind == crate::core::entity::EntityKind::IpAddress {
            !crate::core::validation::is_bogus_ip(&e.value)
        } else if e.kind == crate::core::entity::EntityKind::Domain {
            e.value.parse::<std::net::IpAddr>().is_err()
        } else {
            true
        }
    });
    // Fold duplicate-uid entities together — MERGE their evidence (GREATEST
    // semantics), don't drop the later ones. A record that recurs across breach
    // entries — most importantly one reused password hash appearing under several
    // different emails — must retain EVERY record it appeared in, or the
    // cross-account reuse signal (the link that connects separate accounts,
    // AU-047) is silently discarded. First-seen order is preserved.
    let mut order: Vec<String> = Vec::new();
    let mut by_uid: std::collections::HashMap<String, crate::core::entity::Entity> =
        std::collections::HashMap::new();
    for e in entities.drain(..) {
        match by_uid.get_mut(&e.uid) {
            Some(existing) => existing.merge(e),
            None => {
                order.push(e.uid.clone());
                by_uid.insert(e.uid.clone(), e);
            }
        }
    }
    *entities = order
        .into_iter()
        .filter_map(|uid| by_uid.remove(&uid))
        .collect();
    // `merge` appends evidence in arrival order; the union of two canonical
    // orderings is not itself canonical. Canonicalise here so every caller —
    // CLI and web — emits the same byte-identical representation regardless of
    // the order entities arrived in the source file.
    for e in entities.iter_mut() {
        e.canonicalize_order();
    }
}

/// Persist a parsed import as a completed scan in the default store — the CLI
/// counterpart to the web `scan_import` handler — so `hse import` is no longer a
/// print-and-discard: the imported scan appears in `hse list`, every view/export
/// (entities, dossier, debug bundle, GEXF) works on it, and expansion seeds can
/// later re-scan its pivots. Derives the deterministic entity relations and runs
/// the correlator, exactly as the live scan finalise does, so an imported dossier
/// carries the same graph a live scan would. Best-effort on relations and
/// correlations: an import whose entities already persisted must not fail on a
/// hiccup there. Returns `(relations, correlations)` persisted, for the summary.
///
/// The store-opening / finalise body is the shared [`crate::app::persist`] use
/// case — `hse ingest --auto-scan` persists document-extracted entities through
/// the exact same path, so the two can never drift on how a batch becomes a scan.
async fn persist_import(
    sid: &str,
    entities: &[crate::core::entity::Entity],
) -> Result<(usize, usize, bool)> {
    use crate::core::scan::TargetKind;

    // A readable scan label: the strongest identity in the file, else generic —
    // matches the web upload handler so the two paths label imports identically.
    let label = crate::app::persist::strongest_identity_label(entities, "imported dossier");
    crate::app::persist::persist_entities_as_scan(sid, label, TargetKind::FullName, entities).await
}

/// Persist a parsed import and emit a one-line summary on the appropriate stream.
/// Shared tail for every CLI import path so persistence and its reporting can't
/// drift between formats. A persistence failure is surfaced as a warning, never
/// fatal — the entities were already rendered to the operator.
async fn persist_and_report(sid: &str, entities: &[crate::core::entity::Entity], output: &str) {
    match persist_import(sid, entities).await {
        Ok((relations, correlations, enriched)) => {
            note(
                output,
                format!(
                    "  Stored:    scan {sid} ({} entities, {relations} relations, {correlations} correlations) — view with `hse list`",
                    entities.len()
                ),
            );
            if !enriched {
                note(
                    output,
                    format!(
                        "  Note:      relations/correlations skipped — {} entities exceeds the \
                         {}-entity enrichment cap (device-safety bound on the pairwise \
                         correlator pass); every entity is still stored",
                        entities.len(),
                        crate::app::persist::PERSIST_ENRICH_MAX_ENTITIES
                    ),
                );
            }
        }
        Err(e) => note(
            output,
            format!("  Warning:   could not persist import: {e}"),
        ),
    }
}

/// Persist RF sightings for `sid`, best-effort — a failure here must never
/// affect the entities `persist_and_report` already persisted, exactly as for
/// stealer rows. A no-op when there is nothing to store.
pub(super) async fn persist_rf_sightings_best_effort(
    sid: &str,
    rows: &[crate::core::rf::RfSighting],
    output: &str,
) {
    if rows.is_empty() {
        return;
    }
    use crate::core::StoragePort;
    let store: std::sync::Arc<dyn StoragePort> =
        match crate::storage::Store::open(&crate::default_db_path()) {
            Ok(s) => std::sync::Arc::new(s),
            Err(e) => {
                note(
                    output,
                    format!("  Warning:   could not persist RF sightings: {e}"),
                );
                return;
            }
        };
    match store.insert_rf_sightings_batch(sid, rows) {
        Ok(n) => note(
            output,
            format!("  Signal:    {n} RF sighting(s) — query with `hse signal --scan-id {sid}`"),
        ),
        Err(e) => note(
            output,
            format!("  Warning:   could not persist RF sightings: {e}"),
        ),
    }
}

/// Persist paired stealer-log credential rows for `sid`, best-effort — a
/// failure here must never affect the entities `persist_and_report` already
/// persisted. Called only by the Stealerlogs importer; a no-op when there's
/// nothing to store.
async fn persist_stealer_rows_best_effort(
    sid: &str,
    rows: &[crate::core::stealer_row::StealerRow],
    output: &str,
) {
    if rows.is_empty() {
        return;
    }
    use crate::core::StoragePort;
    let store: std::sync::Arc<dyn StoragePort> =
        match crate::storage::Store::open(&crate::default_db_path()) {
            Ok(s) => std::sync::Arc::new(s),
            Err(e) => {
                note(
                    output,
                    format!("  Warning:   could not persist stealer rows: {e}"),
                );
                return;
            }
        };
    match store.insert_stealer_rows_batch(sid, rows) {
        Ok(n) => note(
            output,
            format!("  Stored:    {n} stealer credential row(s) for the Stealer Logs Viewer"),
        ),
        Err(e) => note(
            output,
            format!("  Warning:   could not persist stealer rows: {e}"),
        ),
    }
}

/// Web-upload counterpart to `entities_from_upload`, scoped to the paired
/// stealer-log credential rows `entities_from_upload` itself discards (its
/// signature returns `(entities, format_label)` and is destructured at many
/// non-web call sites — CLI, tests — so it is deliberately not widened for
/// this web-only need). Returns empty for any non-stealer body from a cheap
/// format check alone; re-parses the body a second time only in the stealer
/// case, an accepted, bounded, one-time-per-upload cost.
///
/// `forced` (the upload's `?format=`) governs the format decision here exactly
/// as it does in `entities_from_upload`, so the two parses of one upload never
/// disagree about what the file is. Without this, a `?format=stealerlogs`
/// upload whose body content-detection would MISS — an export with a
/// `Credentials:` list but no `Log Id:` line, which `looks_like_stealerlogs`
/// rejects yet `parse_stealerlogs` reads fine — kept its entities but silently
/// lost its paired rows (the same silent-data-loss class the override exists to
/// close); and a body forced to a NON-stealer format would still have emitted
/// stealer rows the operator overrode. When `forced` is `None` (auto-detect,
/// the CLI/no-hint path) this is exactly the previous content check.
pub(crate) fn stealer_rows_from_upload(
    body: &str,
    forced: Option<ImportFormat>,
) -> Vec<crate::core::stealer_row::StealerRow> {
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    let is_stealer = match forced {
        Some(f) => f == ImportFormat::Stealerlogs,
        None => looks_like_stealerlogs(body),
    };
    if !is_stealer {
        return Vec::new();
    }
    parse_stealerlogs(body, "").2
}

fn detect_and_create_api_key_entity(
    pw: &str,
    sid: &str,
    source_label: &str,
) -> Option<(&'static str, crate::core::entity::Entity)> {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::util::key_harvest::identify_api_key;

    let (service, _key_val) = identify_api_key(pw)?;

    let char_len = pw.chars().count();
    let prefix: String = pw.chars().take(8).collect();
    let suffix: String = pw.chars().skip(char_len.saturating_sub(4)).collect();
    let display = format!("{service}:{prefix}...{suffix}");
    let mut e = Entity::new(EntityKind::ApiKey, &display, confidence::HIGH_PLUSPLUS, sid);
    e.tag("api-key");
    e.tag(format!("service:{service}"));
    e.tag("import");
    e.add_evidence(
        Evidence::new(
            source_label,
            format!("API key pattern ({service}) in stealer data"),
        )
        .with_attr("service", service)
        .with_attr("key_length", pw.len().to_string()),
    );
    Some((service, e))
}

/// Extract WiFi BSSIDs / MAC addresses from `text` and push them as
/// `MacAddress` entities — a victim's router BSSID lifted from a stealer log or
/// breach record becomes a geolocation seed that `mylnikov` / `wigle` can turn
/// into coordinates. [`crate::util::extract::macs`] already dedupes, so every
/// distinct BSSID found is emitted — no arbitrary cap. Returns the number
/// emitted.
fn push_macs(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut n = 0;
    for mac in crate::util::extract::macs(text) {
        let mut e = Entity::new(EntityKind::MacAddress, &mac, confidence::MEDIUM_HIGH, sid);
        e.tag("import");
        e.tag(source_tag);
        e.tag("bssid");
        e.add_evidence(
            Evidence::new(
                "import:mac",
                format!("WiFi BSSID / MAC `{mac}` — geolocatable via mylnikov/wigle"),
            )
            .with_attr("mac", &mac),
        );
        entities.push(e);
        n += 1;
    }
    n
}

/// Extract validated crypto wallet addresses from `text` and push them as
/// `CryptoAddress` entities — stealer logs and breach dumps routinely carry a
/// victim's BTC/ETH/… wallets, and a recovered address is a chain-analysis seed
/// (`chain_intel`). Every candidate token is checksum-validated by
/// [`crate::core::crypto::classify_crypto_address`], so noise (hashes, API keys)
/// is rejected; every distinct validated address is emitted — no arbitrary cap.
/// Returns the number emitted.
fn push_crypto(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut seen = std::collections::HashSet::new();
    let mut n = 0;
    for raw in text.split(|c: char| c.is_whitespace() || "\"',;:|<>()[]{}=".contains(c)) {
        let tok = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if !(26..=64).contains(&tok.len()) {
            continue;
        }
        let Some(chain) = crate::core::crypto::classify_crypto_address(tok) else {
            continue;
        };
        if !seen.insert(tok.to_string()) {
            continue;
        }
        let coin = chain.strip_prefix("crypto_").unwrap_or(chain);
        let mut e = Entity::new(EntityKind::CryptoAddress, tok, confidence::HIGH_PLUS, sid);
        e.tag("import");
        e.tag(source_tag);
        e.tag("crypto-address");
        e.tag(format!("chain:{coin}"));
        e.add_evidence(
            Evidence::new(
                "import:crypto",
                format!(
                    "{} wallet address `{tok}` in {source_tag} data",
                    crate::core::crypto::chain_label(chain)
                ),
            )
            .with_attr("chain", chain),
        );
        entities.push(e);
        n += 1;
    }
    n
}

/// Scan `text` for leaked API keys / tokens anywhere in a breach or stealer
/// dump — not just in a recognised `service: key` field — and emit each as an
/// `ApiKey` entity (masked display, full key stashed in the key pool for
/// reuse/validation). Every candidate is gated by the canonical
/// `identify_api_key`, so only real vendor-key shapes (AWS `AKIA…`, GitHub
/// `ghp_…`, Slack `xox…`, Stripe `sk_live_…`, Google `AIza…`, …) are kept.
/// Capped at 50/import. Returns the number emitted.
///
/// Persists the pool to disk itself (once, only if it actually added a key)
/// rather than leaving that to the caller: the in-memory `pool.add` inside
/// `store_key_in_pool` is invisible on disk until `save_pool`/
/// `save_pool_best_effort` runs, and most of this function's 7 callers never
/// called it at all — every key this scanner found (its whole point: keys
/// outside a recognised `service: key` field) was silently lost on process
/// exit. A single choke point here fixes every caller at once and can't
/// drift back out of sync the way 7 separate call-site edits could.
fn push_api_keys(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    let label = format!("import:{source_tag}");
    let mut seen = std::collections::HashSet::new();
    let mut n = 0;
    for raw in text.split(|c: char| c.is_whitespace() || "\"',;|<>(){}[]".contains(c)) {
        let tok = raw.trim_matches(|c: char| matches!(c, '\'' | '"' | '`' | '='));
        if !(16..=240).contains(&tok.len()) || !seen.insert(tok.to_string()) {
            continue;
        }
        if let Some((service, mut e)) = detect_and_create_api_key_entity(tok, sid, &label) {
            e.tag(source_tag);
            entities.push(e);
            store_key_in_pool(
                service,
                tok,
                format!("{source_tag} import: leaked {service} key"),
            );
            n += 1;
            if n >= 50 {
                break;
            }
        }
    }
    if n > 0 {
        crate::util::key_pool::save_pool_best_effort(&crate::util::key_pool::global_pool());
    }
    n
}

/// Extract checksum-valid IBANs (international bank accounts) from `text` and
/// push them as `Other("iban")` financial-intel entities — a victim's bank
/// account recovered from a breach/stealer dump. [`crate::util::extract::ibans`]
/// already dedupes, so every distinct IBAN found is emitted — no arbitrary cap.
fn push_ibans(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut n = 0;
    for iban in crate::util::extract::ibans(text) {
        let mut e = Entity::new(
            EntityKind::Other("iban".into()),
            &iban,
            confidence::NOTABLE,
            sid,
        );
        e.tag("import");
        e.tag(source_tag);
        e.tag("iban");
        e.tag("financial");
        e.add_evidence(
            Evidence::new(
                "import:iban",
                format!("Bank account (IBAN) `{iban}` in {source_tag} data"),
            )
            .with_attr("iban", &iban),
        );
        entities.push(e);
        n += 1;
    }
    n
}

/// Extract labelled WiFi SSIDs from `text` and push them as `Ssid` entities —
/// a victim's network names from a stealer log. A *unique* SSID then dispatches
/// to `wigle`'s SSID search, which returns where the network was observed,
/// placing the owner. [`crate::util::extract::labeled_ssids`] already dedupes,
/// so every distinct SSID found is emitted — no arbitrary cap.
fn push_ssids(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut n = 0;
    for ssid in crate::util::extract::labeled_ssids(text) {
        let mut e = Entity::new(EntityKind::Ssid, &ssid, confidence::MEDIUM_PLUS, sid);
        e.tag("import");
        e.tag(source_tag);
        e.tag("wifi-network");
        e.add_evidence(
            Evidence::new(
                "import:ssid",
                format!("WiFi network `{ssid}` in {source_tag} data — geolocatable via WiGLE"),
            )
            .with_attr("ssid", &ssid),
        );
        entities.push(e);
        n += 1;
    }
    n
}

fn store_key_in_pool(service: &str, key: &str, notes: String) {
    let pool = crate::util::key_pool::global_pool();
    let mut entry = crate::util::key_pool::KeyEntry::new(key);
    entry.notes = Some(notes);
    pool.add(service, entry);
}

struct GeoFields<'a> {
    ip: &'a str,
    lat: Option<f64>,
    lon: Option<f64>,
    city: &'a str,
    region: &'a str,
    country: &'a str,
    isp: &'a str,
}

fn create_geolocation_entities(
    geo: &GeoFields<'_>,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
) {
    use crate::core::confidence;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    if let (Some(la), Some(lo)) = (geo.lat, geo.lon)
        && la.abs() > 0.01
        && lo.abs() > 0.01
    {
        let coords = format!("{la:.4},{lo:.4}");
        let mut ce = Entity::new(EntityKind::Coordinates, &coords, confidence::HIGH_PLUS, sid);
        ce.tag("geoint");
        ce.tag("import");
        ce.add_evidence(Evidence::new(
            "import:oathnet",
            format!(
                "IP {}: {}, {}, {} ({})",
                geo.ip, geo.city, geo.region, geo.country, geo.isp
            ),
        ));
        entities.push(ce);
        stats.coordinates += 1;
    }
    if !geo.city.is_empty() {
        let addr = format!("{}, {}, {}", geo.city, geo.region, geo.country);
        let mut ae = Entity::new(EntityKind::Address, &addr, confidence::HIGH, sid);
        ae.tag("import");
        entities.push(ae);
        stats.addresses += 1;
    }
}

/// Parse the `=== OSINT ENRICHMENT ===` IP-geolocation section that the OathNet
/// stealer-log TXT and the OathNet SEARCH REPORT both carry — a run of `IP:` /
/// `lat:` / `lon:` / `city:` / `regionName:` / `country:` / `isp:` blocks — into
/// `Coordinates` + `Address` entities. Shared by `txt.rs` and
/// `oathnet_report.rs` so the two formats geolocate identically and the block
/// can never drift between them. A no-op when the section is absent.
fn parse_osint_enrichment(
    body: &str,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
) {
    let Some(os) = body.find("=== OSINT ENRICHMENT") else {
        return;
    };
    let osint_section = &body[os..];
    let mut current_ip = String::new();
    let mut lat: Option<f64> = None;
    let mut lon: Option<f64> = None;
    let mut city = String::new();
    let mut region = String::new();
    let mut country = String::new();
    let mut isp = String::new();

    for line in osint_section.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("IP: ") {
            if !current_ip.is_empty() {
                create_geolocation_entities(
                    &GeoFields {
                        ip: &current_ip,
                        lat,
                        lon,
                        city: &city,
                        region: &region,
                        country: &country,
                        isp: &isp,
                    },
                    sid,
                    entities,
                    stats,
                );
            }
            current_ip = rest.trim().to_string();
            lat = None;
            lon = None;
            city.clear();
            region.clear();
            country.clear();
            isp.clear();
        } else if let Some(rest) = trimmed.strip_prefix("lat: ") {
            lat = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("lon: ") {
            lon = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("city: ") {
            city = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("regionName: ") {
            region = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("country: ") {
            country = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("isp: ") {
            isp = rest.trim().to_string();
        }
    }
    if !current_ip.is_empty() {
        create_geolocation_entities(
            &GeoFields {
                ip: &current_ip,
                lat,
                lon,
                city: &city,
                region: &region,
                country: &country,
                isp: &isp,
            },
            sid,
            entities,
            stats,
        );
    }
}

/// Everything a per-format parser hands the shared CLI import runner
/// ([`run_import`]) to persist and report: the entities and their stats, plus
/// the extras only some formats carry — a key pool to save (stealer-log /
/// OathNet exports leak API keys), the paired stealer-credential rows or the RF
/// sightings that live in their own side tables. Built by the per-format
/// `cmd_import_*` adapters and consumed once by [`run_import`], so the
/// dedupe → stats → persist → render lifecycle exists in exactly one place
/// instead of once per format.
struct ParsedImport {
    entities: Vec<crate::core::entity::Entity>,
    stats: ImportStats,
    /// Save the global API-key pool afterwards (gated on keys actually found).
    save_key_pool: bool,
    /// Also print the `Pool: N keys stored` line — the TXT importer alone does.
    note_pool: bool,
    stealer_rows: Vec<crate::core::stealer_row::StealerRow>,
    rf_sightings: Vec<crate::core::rf::RfSighting>,
}

impl ParsedImport {
    fn new(entities: Vec<crate::core::entity::Entity>, stats: ImportStats) -> Self {
        Self {
            entities,
            stats,
            save_key_pool: false,
            note_pool: false,
            stealer_rows: Vec::new(),
            rf_sightings: Vec::new(),
        }
    }

    /// Save the discovered API-key pool after import (stealer / OathNet report).
    fn saving_key_pool(mut self) -> Self {
        self.save_key_pool = true;
        self
    }

    /// Save the pool AND print the `Pool: N keys` summary line (TXT importer).
    fn noting_key_pool(mut self) -> Self {
        self.save_key_pool = true;
        self.note_pool = true;
        self
    }

    fn with_stealer_rows(mut self, rows: Vec<crate::core::stealer_row::StealerRow>) -> Self {
        self.stealer_rows = rows;
        self
    }

    fn with_rf_sightings(mut self, rows: Vec<crate::core::rf::RfSighting>) -> Self {
        self.rf_sightings = rows;
        self
    }
}

/// The one CLI import lifecycle every simple per-format runner shares: announce
/// the format, mint the scan id, parse (the `parse` closure receives that freshly
/// minted sid), then dedupe → print stats → optionally save/announce the key
/// pool → persist → persist any side table (stealer rows / RF sightings, each a
/// no-op when empty) → render. `cmd_import_html` (a custom summary, no stats) and
/// the OathNet-JSON arm of [`cmd_import`] (an async parse plus a JSON output tail)
/// keep their own bodies; every other `cmd_import_*` is a one-line adapter over
/// this. Behaviour is identical to the hand-written runners it replaced, pinned
/// by a golden before/after CLI diff across every format.
async fn run_import(
    banner: &str,
    tag: &str,
    output: &str,
    parse: impl FnOnce(&str) -> ParsedImport,
) -> Result<()> {
    note(output, banner);
    let sid = format!("import-{tag}-{}", crate::core::entity::unix_now());
    let ParsedImport {
        mut entities,
        stats,
        save_key_pool,
        note_pool,
        stealer_rows,
        rf_sightings,
    } = parse(&sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    if stats.api_keys > 0 {
        if note_pool {
            note(
                output,
                format!(
                    "  Pool:      {} keys stored for automatic use",
                    stats.api_keys
                ),
            );
        }
        if save_key_pool {
            crate::util::key_pool::save_pool_best_effort(&crate::util::key_pool::global_pool());
        }
    }
    persist_and_report(&sid, &entities, output).await;
    persist_stealer_rows_best_effort(&sid, &stealer_rows, output).await;
    persist_rf_sightings_best_effort(&sid, &rf_sightings, output).await;
    render_import_entities(&entities, output);
    Ok(())
}

/// Emit a human-readable progress/summary line on the stream appropriate to the
/// output mode: stderr under `--output json` (so stdout stays pure JSON for
/// `| jq`), stdout otherwise (where the summary IS the operator-facing output).
fn note(output: &str, line: impl AsRef<str>) {
    if output == "json" {
        eprintln!("{}", line.as_ref());
    } else {
        println!("{}", line.as_ref());
    }
}

fn print_import_stats(stats: &ImportStats, entity_count: usize, output: &str) {
    // Route every line through `note` so a `--output json` run keeps stdout free
    // of this summary (it goes to stderr); a table run prints it to stdout.
    macro_rules! row {
        ($($a:tt)*) => { note(output, format!($($a)*)) };
    }
    row!("Imported {} entities:", entity_count);
    row!(
        "  Identity:  {} emails, {} phones, {} usernames, {} persons, {} orgs, {} device users, {} Discord IDs",
        stats.emails,
        stats.phones,
        stats.usernames,
        stats.persons,
        stats.organisations,
        stats.device_users,
        stats.discord_ids
    );
    if stats.credentials > 0 {
        row!("  Creds:     {} password hashes", stats.credentials);
    }
    row!(
        "  Network:   {} IPs, {} domains, {} subdomains, {} URLs, {} admin paths",
        stats.ips,
        stats.domains,
        stats.subdomains,
        stats.urls,
        stats.admin_paths
    );
    row!(
        "  Geo:       {} coordinates, {} addresses",
        stats.coordinates,
        stats.addresses
    );
    // Only meaningful for a wardriving import; suppressed otherwise so every
    // other format's summary keeps the shape it had.
    if stats.ssids > 0 || stats.bssids > 0 {
        row!(
            "  Wireless:  {} SSIDs, {} BSSIDs",
            stats.ssids,
            stats.bssids
        );
    }
    row!(
        "  Device:    {} HWIDs, {} machine log IDs",
        stats.hwids,
        stats.machines
    );
    row!("  Keys:      {} API keys detected", stats.api_keys);
    row!("  Verified:  {} holehe platform checks", stats.holehe);
    row!(
        "  Source:    {} breach, {} stealer docs, {} victims",
        stats.breach_records,
        stats.stealer_docs,
        stats.victim_records
    );
    if !stats.date_range.is_empty() {
        row!("  Timeline:  {}", stats.date_range);
    }
    if stats.malformed_lines > 0 {
        row!(
            "  Quarantine: {} malformed lines skipped (parsing continued)",
            stats.malformed_lines
        );
    }
    if stats.api_keys > 0 {
        row!(
            "  Pool:      {} API keys detected, {} validated active",
            stats.api_keys,
            stats.api_keys_valid
        );
    }
}
