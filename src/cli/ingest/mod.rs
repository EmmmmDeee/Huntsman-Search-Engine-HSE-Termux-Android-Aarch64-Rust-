//! `hse ingest` command: Parse documents → extract entities → output JSONL batch.
//!
//! With `--auto-scan`, the extracted entities are ALSO persisted as a completed,
//! correlated scan (via [`crate::app::persist`], the same use case `hse import`
//! runs) — so they appear in `hse list` and every view/export works on them — in
//! addition to being written to the chosen output. This is a deterministic,
//! offline persist-and-correlate: no modules are dispatched and no network is
//! touched. The engine seeds from a single live target, so feeding a whole batch
//! of document-extracted entities into it as seeds is deliberately NOT what this
//! does; auto-launching network reconnaissance against every entity found in an
//! arbitrary document would be both non-deterministic and a footgun.

mod converter;

use crate::util::document_parse::{DocumentFormat, DocumentResult};
use crate::util::entity_extractor::EntityExtractor;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tracing::info;

/// Scan id stamped on entities emitted by the `hse` output format.
///
/// Ingest runs outside any scan, so there is no real id to carry. A fixed,
/// obvious placeholder is better than a fabricated-looking one: whoever loads
/// these entities re-stamps them with the scan that adopts them.
const PENDING_SCAN_ID: &str = "ingest-pending";

/// Arguments for `hse ingest`. Populated from the `Command::Ingest` clap variant
/// in `cli::command`, which owns the flags and short-names — this is a plain
/// data-transfer struct, NOT a parser, so it carries no clap attributes.
#[derive(Debug)]
pub struct IngestArgs {
    /// Input file path (image, PDF, CSV, JSON, JSONL, text)
    pub file: PathBuf,

    /// Output format: jsonl (default), json, csv, table, hse
    pub output_format: String,

    /// Minimum confidence threshold (0.0-1.0)
    pub min_confidence: f64,

    /// Persist the extracted entities as a completed, correlated scan (offline;
    /// no module dispatch) in addition to writing them to the output.
    pub auto_scan: bool,

    /// Output file (default: stdout)
    pub output: Option<PathBuf>,

    /// Extract EXIF geolocation from images
    pub extract_geolocation: bool,

    /// Generate reverse image search variants for detected images
    pub generate_reverse_search_variants: bool,

    /// Output directory for reverse image search variants
    pub image_variant_output_dir: Option<PathBuf>,
}

/// Execute `hse ingest` command.
pub async fn run(args: IngestArgs) -> DocumentResult<()> {
    // Detect file format
    let format = DocumentFormat::from_path(&args.file).ok_or_else(|| {
        crate::util::document_parse::DocumentParseError::UnsupportedFormat(
            args.file.to_string_lossy().to_string(),
        )
    })?;

    info!("Ingesting {:?} from {}", format, args.file.display());

    // Parse document
    let raw_text = match format {
        DocumentFormat::Image => {
            crate::util::document_parse::ocr::ocr_image(&args.file, 60)
                .await
                .unwrap_or_else(|_| {
                    // Fallback if OCR unavailable
                    crate::util::document_parse::RawDocumentText {
                        text: format!("OCR unavailable for {}", args.file.display()),
                        source_format: format,
                        confidence: 0.0,
                        metadata: crate::util::document_parse::DocumentMetadata {
                            source_file: Some(args.file.to_string_lossy().to_string()),
                            extraction_method: "ocr_fallback".to_string(),
                            ..Default::default()
                        },
                    }
                })
        }
        DocumentFormat::Pdf => crate::util::document_parse::pdf_parse::parse_pdf(&args.file)?,
        DocumentFormat::Csv => {
            let csv_data = crate::util::document_parse::csv_parse::parse_csv(&args.file)?;
            csv_data.raw_text
        }
        DocumentFormat::Json => crate::util::document_parse::json_parse::parse_json(&args.file)?,
        DocumentFormat::Jsonl => crate::util::document_parse::json_parse::parse_jsonl(&args.file)?,
        DocumentFormat::Text => {
            let text = fs::read_to_string(&args.file)?;
            let character_count = text.len();
            crate::util::document_parse::RawDocumentText {
                text,
                source_format: format,
                confidence: 0.50,
                metadata: crate::util::document_parse::DocumentMetadata {
                    source_file: Some(args.file.to_string_lossy().to_string()),
                    character_count,
                    extraction_method: "text_read".to_string(),
                    ..Default::default()
                },
            }
        }
        // Phase 5: Extended formats (read as text, similar to Text format)
        DocumentFormat::Yaml => {
            let text = fs::read_to_string(&args.file)?;
            let character_count = text.len();
            crate::util::document_parse::RawDocumentText {
                text,
                source_format: format,
                confidence: 0.45, // Config files slightly lower confidence (may contain noise)
                metadata: crate::util::document_parse::DocumentMetadata {
                    source_file: Some(args.file.to_string_lossy().to_string()),
                    character_count,
                    extraction_method: "yaml_parse".to_string(),
                    ..Default::default()
                },
            }
        }
        DocumentFormat::Toml => {
            let text = fs::read_to_string(&args.file)?;
            let character_count = text.len();
            crate::util::document_parse::RawDocumentText {
                text,
                source_format: format,
                confidence: 0.45,
                metadata: crate::util::document_parse::DocumentMetadata {
                    source_file: Some(args.file.to_string_lossy().to_string()),
                    character_count,
                    extraction_method: "toml_parse".to_string(),
                    ..Default::default()
                },
            }
        }
        DocumentFormat::Env => {
            let text = fs::read_to_string(&args.file)?;
            let character_count = text.len();
            crate::util::document_parse::RawDocumentText {
                text,
                source_format: format,
                confidence: 0.55, // Env files often contain secrets/credentials
                metadata: crate::util::document_parse::DocumentMetadata {
                    source_file: Some(args.file.to_string_lossy().to_string()),
                    character_count,
                    extraction_method: "env_parse".to_string(),
                    ..Default::default()
                },
            }
        }
        DocumentFormat::Xml => {
            let text = fs::read_to_string(&args.file)?;
            let character_count = text.len();
            crate::util::document_parse::RawDocumentText {
                text,
                source_format: format,
                confidence: 0.48,
                metadata: crate::util::document_parse::DocumentMetadata {
                    source_file: Some(args.file.to_string_lossy().to_string()),
                    character_count,
                    extraction_method: "xml_parse".to_string(),
                    ..Default::default()
                },
            }
        }
    };

    info!(
        "Extracted {} chars from {}, confidence: {}",
        raw_text.metadata.character_count,
        args.file.display(),
        raw_text.confidence
    );

    // Extract entities
    let extractor = EntityExtractor::new(args.min_confidence)?;
    let entities = extractor.extract_from_text(&raw_text.text);

    info!("Found {} entities", entities.len());

    // Phase 6: Image processing (geolocation + reverse image search)
    if matches!(raw_text.source_format, DocumentFormat::Image) {
        // Extract EXIF geolocation if requested
        if args.extract_geolocation {
            match crate::util::document_parse::image_geolocation::extract_image_geolocation(
                &args.file,
            ) {
                Ok(geo_metadata) => {
                    if let Some(coords) = &geo_metadata.coordinates {
                        info!(
                            "Image geolocation: {:.6}°, {:.6}° (confidence: {:.2})",
                            coords.latitude, coords.longitude, coords.confidence
                        );
                    }
                    if let Some(datetime) = &geo_metadata.datetime {
                        info!("Image capture datetime: {}", datetime);
                    }
                    if let Some(camera) = &geo_metadata.camera_model {
                        info!("Camera model: {}", camera);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to extract geolocation: {}", e);
                }
            }
        }

        // Generate reverse image search variants if requested
        if args.generate_reverse_search_variants {
            match crate::util::document_parse::image_reverse_search::generate_reverse_image_variants(
                &args.file,
            ) {
                Ok(search_set) => {
                    info!(
                        "Generated {} reverse image search variants ({}x{})",
                        search_set.variants.len(),
                        search_set.original_dimensions.0,
                        search_set.original_dimensions.1
                    );

                    // Save variants to disk if output directory specified
                    if let Some(output_dir) = &args.image_variant_output_dir {
                        fs::create_dir_all(output_dir)?;
                        let base_name = args
                            .file
                            .file_stem()
                            .and_then(|n| n.to_str())
                            .unwrap_or("image");

                        for variant in &search_set.variants {
                            let variant_path = output_dir.join(format!(
                                "{}_{}_{}.{}",
                                base_name, variant.engine, variant.dimensions.0, variant.format
                            ));
                            fs::write(&variant_path, &variant.data)?;
                            info!(
                                "Saved {} variant to {}",
                                variant.engine,
                                variant_path.display()
                            );
                        }

                        // Save metadata summary
                        let metadata_path =
                            output_dir.join(format!("{base_name}_reverse_search_metadata.json"));
                        let metadata_json = serde_json::json!({
                            "original_dimensions": search_set.original_dimensions,
                            "variant_count": search_set.variants.len(),
                            "variants": search_set.variants.iter().map(|v| serde_json::json!({
                                "engine": v.engine,
                                "dimensions": v.dimensions,
                                "format": v.format,
                                "quality": v.quality,
                                "file_size_bytes": v.file_size_bytes,
                            })).collect::<Vec<_>>(),
                            "primary_variant": search_set.primary_variant,
                            "image_hash": search_set.image_hash,
                        });
                        fs::write(
                            &metadata_path,
                            serde_json::to_string_pretty(&metadata_json)?,
                        )?;
                        info!(
                            "Saved reverse search metadata to {}",
                            metadata_path.display()
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to generate reverse image search variants: {}", e);
                }
            }
        }
    }

    // The file the entities came from — recorded on each entity's evidence chain
    // (via the `hse` converter) so a persisted or exported entity is attributable
    // back to its source document. Needed by `--auto-scan` below and the output
    // formatter, so it is computed once here.
    let document_source = args
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ingest");

    // --auto-scan: persist the extracted entities as a completed, correlated
    // scan (offline — no module dispatch, no network) so they land in `hse list`
    // and every view/export, in ADDITION to the extraction output written below.
    // Best-effort, exactly like the import path: the entities are still emitted,
    // so a persistence hiccup must warn, never fail the ingest.
    if args.auto_scan {
        match run_auto_scan(&entities, document_source).await {
            Ok((sid, n, relations, correlations)) => info!(
                "auto-scan: stored scan {sid} ({n} entities, {relations} relations, \
                 {correlations} correlations) — view with `hse list`"
            ),
            Err(e) => {
                tracing::warn!("auto-scan: could not persist extracted entities: {e}");
            }
        }
    }

    // Format output
    let output_text = format_output(&entities, &args.output_format, document_source)?;

    // Write output
    if let Some(output_path) = args.output {
        fs::write(&output_path, output_text)?;
        info!("Wrote output to {}", output_path.display());
    } else {
        println!("{output_text}");
    }

    Ok(())
}

/// Persist the extracted `entities` as a completed, correlated scan — the
/// `--auto-scan` action.
///
/// Converts each [`ExtractedEntity`](crate::util::entity_extractor::ExtractedEntity)
/// to a core [`Entity`](crate::core::entity::Entity) (attributed to
/// `document_source`) under a fresh, collision-free `ingest-<uid>` scan id, then
/// delegates to
/// the shared [`crate::app::persist`] use case that `hse import` also runs —
/// offline geospatial enrichment, deterministic relation derivation, and
/// correlation. Store construction lives in that application-layer use case, not
/// here, so the CLI never opens the store directly (`tests/architecture.rs`).
///
/// Returns the new scan id and its `(entities, relations, correlations)` counts.
/// Entirely offline and deterministic: no module dispatch, no network.
async fn run_auto_scan(
    entities: &[crate::util::entity_extractor::ExtractedEntity],
    document_source: &str,
) -> crate::core::error::Result<(String, usize, usize, usize)> {
    // A unique id per call: `unix_now()` has one-second resolution, so two
    // `hse ingest --auto-scan` runs in the same second would collide and the
    // second would overwrite the first's scan row + entities. `uid::scan_id`
    // mixes a monotonic counter into the hash so every call is distinct; the
    // `ingest-` prefix keeps the scan attributable to this path.
    let sid = format!(
        "ingest-{}",
        crate::util::uid::scan_id("document", document_source)
    );
    let converted: Vec<crate::core::entity::Entity> = entities
        .iter()
        .map(|e| converter::extracted_to_hse_entity(e, &sid, document_source))
        .collect();
    let label = crate::app::persist::strongest_identity_label(
        &converted,
        format!("ingested document: {document_source}"),
    );
    let (relations, correlations) = crate::app::persist::persist_entities_as_scan(
        &sid,
        label,
        crate::core::scan::TargetKind::FullName,
        &converted,
    )
    .await?;
    Ok((sid, converted.len(), relations, correlations))
}

/// Format entities as JSONL, JSON, CSV, HSE entities, or human-readable table.
///
/// `document_source` names the file the entities came from; it is recorded on
/// the evidence chain of the `hse` format so a downstream scan can attribute
/// each entity back to the document that produced it.
fn format_output(
    entities: &[crate::util::entity_extractor::ExtractedEntity],
    format: &str,
    document_source: &str,
) -> DocumentResult<String> {
    match format {
        // Fully-formed `core::entity::Entity` records — kind mapped onto HSE's
        // taxonomy, confidence carried across, and an evidence chain naming the
        // source document and matching pattern. This is the shape
        // `storage::Store::upsert_entities_batch` consumes, so the output can be
        // fed straight into a scan rather than re-parsed from the flat formats.
        "hse" | "entities" => {
            let converted: Vec<_> = entities
                .iter()
                .map(|e| converter::extracted_to_hse_entity(e, PENDING_SCAN_ID, document_source))
                .collect();
            Ok(serde_json::to_string_pretty(&converted)?)
        }
        "jsonl" => Ok(entities
            .iter()
            .map(|e| {
                json!({
                    "kind": e.kind.to_str(),
                    "value": e.value,
                    "confidence": e.confidence,
                    "source_pattern": e.source_pattern,
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")),

        "json" => Ok(json!(
            entities
                .iter()
                .map(|e| json!({
                    "kind": e.kind.to_str(),
                    "value": e.value,
                    "confidence": e.confidence,
                    "source_pattern": e.source_pattern,
                    "boost_reason": e.boost_reason,
                }))
                .collect::<Vec<_>>()
        )
        .to_string()),

        // Emit through the same `csv` crate that `csv_parse` reads with, so the
        // output round-trips. The previous hand-rolled writer replaced only `,`
        // with `\,` and left `"`, `\n`, and `\r` untouched — which HSE's own
        // `csv::Reader` parses as extra fields (and a newline in a value splits
        // the row), so `hse ingest -f csv` produced CSV that `hse` could not
        // re-ingest. `csv::Writer` RFC-4180-quotes only the fields that need it,
        // so plain values (emails, IPs) are unchanged.
        // `csv::Writer` makes the output structurally valid, but it does not —
        // and should not — know about spreadsheet formula injection. Ingest's
        // input is an UNTRUSTED document, so a value beginning `=`/`+`/`-`/`@`/
        // CR/TAB executes as a formula the moment the operator opens the export
        // in Excel or LibreOffice. The scan-export path has always defanged
        // that; this one did not, so each field goes through the shared
        // [`formula_guard`] first. Only the guard is shared, not the whole of
        // `csv_escape`: that also RFC-4180-quotes, which would double-quote
        // everything `csv::Writer` is about to quote itself.
        "csv" => {
            use crate::api::scan_export::formula_guard;
            let mut wtr = csv::Writer::from_writer(Vec::new());
            wtr.write_record(["kind", "value", "confidence", "source_pattern"])?;
            for e in entities {
                let confidence = e.confidence.to_string();
                wtr.write_record([
                    formula_guard(e.kind.to_str()).as_ref(),
                    formula_guard(&e.value).as_ref(),
                    formula_guard(&confidence).as_ref(),
                    formula_guard(&e.source_pattern).as_ref(),
                ])?;
            }
            let bytes = wtr.into_inner().map_err(csv::IntoInnerError::into_error)?;
            Ok(String::from_utf8(bytes)?)
        }

        "table" => {
            let mut table = String::from("Kind\t\tValue\t\t\tConfidence\tPattern\n");
            table.push_str("----\t\t-----\t\t\t----------\t-------\n");
            for e in entities {
                // Truncate by CHARACTERS, not bytes: `&s[..20]` panics when
                // byte 20 lands inside a multibyte UTF-8 scalar (accented names,
                // CJK, emoji all occur in real ingested values).
                let value: String = e.value.chars().take(20).collect();
                table.push_str(&format!(
                    "{:<15}\t{value:<20}\t{:.2}\t\t{}\n",
                    e.kind.to_str(),
                    e.confidence,
                    e.source_pattern
                ));
            }
            Ok(table)
        }

        other => Err(
            crate::util::document_parse::DocumentParseError::UnsupportedFormat(format!(
                "output format: {other}"
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::entity_extractor::EntityKind;

    fn sample() -> Vec<crate::util::entity_extractor::ExtractedEntity> {
        vec![crate::util::entity_extractor::ExtractedEntity {
            kind: EntityKind::Email,
            value: "test@example.com".to_string(),
            confidence: 0.85,
            context: None,
            source_pattern: "email_rfc5322".to_string(),
            boost_reason: None,
        }]
    }

    #[test]
    fn format_jsonl() {
        let output = format_output(&sample(), "jsonl", "notes.txt").expect("should succeed");
        assert!(output.contains("test@example.com"));
        assert!(output.contains("email"));
    }

    #[tokio::test]
    async fn auto_scan_converts_and_persists_the_extracted_batch() {
        // --auto-scan is wired end to end: the extracted batch is converted to
        // core entities and persisted (via app::persist) as a fresh
        // `ingest-<uid>` scan — `run_auto_scan` only returns Ok if that
        // persistence succeeded. Before this wiring the flag merely warned and
        // this function did not exist. Under cfg(test) the store is rooted in a
        // temp dir, so this touches no real ~/.huntsman.
        let (sid, n, _relations, _correlations) = run_auto_scan(&sample(), "notes.txt")
            .await
            .expect("auto-scan should persist the extracted entities");
        assert!(
            sid.starts_with("ingest-"),
            "the scan id must mark it as an ingest-originated scan: {sid}"
        );
        assert_eq!(
            n, 1,
            "the one extracted entity must be converted and counted"
        );
    }

    #[tokio::test]
    async fn auto_scan_ids_are_unique_across_calls_in_the_same_second() {
        // Regression: the id was `ingest-{unix_now()}` (one-second resolution),
        // so two back-to-back runs collided and the second overwrote the first's
        // scan row + entities. The unique `uid::scan_id` generator (monotonic
        // counter mixed into the hash) must give every call a distinct id while
        // keeping the `ingest-` attribution prefix. Both calls here run well
        // within the same wall-clock second.
        let (sid_a, _, _, _) = run_auto_scan(&sample(), "notes.txt")
            .await
            .expect("first auto-scan persists");
        let (sid_b, _, _, _) = run_auto_scan(&sample(), "notes.txt")
            .await
            .expect("second auto-scan persists");
        assert!(sid_a.starts_with("ingest-") && sid_b.starts_with("ingest-"));
        assert_ne!(
            sid_a, sid_b,
            "two ingests must not collide on one scan id (would overwrite data)"
        );
    }

    /// Build a one-entity sample carrying `value`, for the CSV escaping tests.
    fn sample_valued(value: &str) -> Vec<crate::util::entity_extractor::ExtractedEntity> {
        vec![crate::util::entity_extractor::ExtractedEntity {
            kind: EntityKind::Url,
            value: value.to_string(),
            confidence: 0.8,
            context: None,
            source_pattern: "url_http".to_string(),
            boost_reason: None,
        }]
    }

    /// Split one CSV record the way a conforming RFC-4180 reader does: fields
    /// separated by commas, except inside a `"`-quoted field, where `""` is a
    /// literal quote. Deliberately a local reader rather than the crate's own
    /// importer, so this pins the *interchange* contract (what any spreadsheet
    /// or `csv` library sees) and not merely round-tripping through HSE.
    fn rfc4180_fields(record: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut chars = record.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if in_quotes && chars.peek() == Some(&'"') => {
                    chars.next();
                    cur.push('"');
                }
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
        out.push(cur);
        out
    }

    #[test]
    fn format_csv_keeps_a_comma_bearing_value_in_one_field() {
        // Regression: the emitter used `value.replace(',', "\\,")`, which is not
        // RFC 4180 — a conforming reader saw `https://example.com/path\` +
        // `with\` + `commas` as three fields, so this row carried 6 columns
        // against a 4-column header and every later column shifted.
        let out = format_output(
            &sample_valued("https://example.com/path,with,commas"),
            "csv",
            "notes.txt",
        )
        .expect("csv formatting must succeed");

        let mut lines = out.lines();
        let header = rfc4180_fields(lines.next().expect("header row"));
        let row = rfc4180_fields(lines.next().expect("data row"));

        assert_eq!(header.len(), 4, "header is kind,value,confidence,pattern");
        assert_eq!(
            row.len(),
            header.len(),
            "a comma inside a value must not create extra columns: {row:?}"
        );
        assert_eq!(row[1], "https://example.com/path,with,commas");
        assert!(
            !out.contains("\\,"),
            "backslash-escaping is not CSV and must not reappear"
        );
    }

    #[test]
    fn format_csv_survives_quotes_and_newlines_in_a_value() {
        let out = format_output(
            &sample_valued("say \"hi\"\nsecond line"),
            "csv",
            "notes.txt",
        )
        .expect("csv formatting must succeed");
        // The embedded LF is inside a quoted field, so the record spans two
        // physical lines; parse the whole body after the header as one record.
        let body = out
            .split_once('\n')
            .expect("header then body")
            .1
            .trim_end_matches('\n');
        let row = rfc4180_fields(body);
        assert_eq!(row.len(), 4, "quotes/newlines must stay inside one field");
        assert_eq!(row[1], "say \"hi\"\nsecond line");
    }

    #[test]
    fn format_csv_defangs_a_spreadsheet_formula_from_an_ingested_document() {
        // Ingest's input is an untrusted document, so a value beginning `=`
        // would execute on open in Excel/LibreOffice. The shared escaper's
        // apostrophe guard must apply here exactly as it does on the API
        // export path — the old local rule skipped it entirely.
        let out = format_output(&sample_valued("=cmd|'/c calc'!A1"), "csv", "notes.txt")
            .expect("csv formatting must succeed");
        let row = rfc4180_fields(out.lines().nth(1).expect("data row"));
        assert!(
            row[1].starts_with('\''),
            "a leading `=` must be neutralised with the apostrophe guard: {:?}",
            row[1]
        );
    }

    #[test]
    fn format_hse_emits_scannable_entities() {
        let output = format_output(&sample(), "hse", "notes.txt").expect("should succeed");
        let parsed: Vec<crate::core::entity::Entity> =
            serde_json::from_str(&output).expect("hse output must round-trip as core entities");

        assert_eq!(parsed.len(), 1);
        let entity = &parsed[0];
        assert_eq!(entity.kind, crate::core::entity::EntityKind::Email);
        assert_eq!(entity.value, "test@example.com");
        assert!(
            entity.tags.iter().any(|t| t == "document-ingestion"),
            "entities must be attributable to the ingest path"
        );
        assert!(
            entity
                .evidence
                .iter()
                .any(|e| e.source.contains("notes.txt")),
            "evidence must name the source document"
        );
    }

    #[test]
    fn format_csv_round_trips_through_the_csv_reader() {
        // The old hand-rolled writer escaped only `,` as `\,` and left `"` and
        // `\n` untouched, so HSE's own `csv::Reader` re-parsed the row into the
        // wrong number of fields (and a newline split it into two rows). A value
        // carrying all three delimiter hazards must survive extract -> csv ->
        // re-read byte-for-byte.
        let mut ents = sample();
        ents[0].value = "a,b\"c\nd".to_string();
        let csv = format_output(&ents, "csv", "notes.txt").expect("csv format should succeed");

        let mut reader = csv::ReaderBuilder::new().from_reader(csv.as_bytes());
        let headers = reader.headers().expect("must have a header row").clone();
        assert_eq!(
            headers.iter().collect::<Vec<_>>(),
            ["kind", "value", "confidence", "source_pattern"]
        );
        let records: Vec<_> = reader
            .records()
            .collect::<Result<_, _>>()
            .expect("every row must parse as exactly one record");
        assert_eq!(records.len(), 1, "one entity must yield exactly one row");
        assert_eq!(&records[0][0], "email");
        assert_eq!(
            &records[0][1], "a,b\"c\nd",
            "value must survive the CSV round-trip unchanged"
        );
        assert_eq!(&records[0][3], "email_rfc5322");
    }

    #[test]
    fn format_json_emits_a_parseable_array_carrying_boost_reason() {
        // "json" (distinct from the newline-delimited "jsonl") was the only
        // output format with no test. Unlike jsonl it also carries
        // `boost_reason`; assert the whole is one parseable array and that the
        // boost reason survives.
        let mut ents = sample();
        ents[0].boost_reason = Some("RFC 5322 compliant".to_string());
        let output = format_output(&ents, "json", "notes.txt").expect("json format should succeed");

        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("json output must parse as JSON");
        let arr = parsed.as_array().expect("json output must be a JSON array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["kind"], "email");
        assert_eq!(arr[0]["value"], "test@example.com");
        assert_eq!(arr[0]["confidence"], 0.85);
        assert_eq!(arr[0]["source_pattern"], "email_rfc5322");
        assert_eq!(arr[0]["boost_reason"], "RFC 5322 compliant");
    }

    #[test]
    fn format_rejects_unknown_output_format() {
        assert!(format_output(&sample(), "yaml", "notes.txt").is_err());
    }

    #[test]
    fn format_table_truncates_multibyte_values_without_panicking() {
        // Regression: the table renderer sliced `&value[..value.len().min(20)]`,
        // which panics when byte 20 falls inside a multibyte UTF-8 scalar.
        // Truncation must be char-based. Each 🎯 is 4 bytes, so byte 20 lands
        // mid-scalar — the old code panicked here.
        let mut ents = sample();
        ents[0].value = "🎯".repeat(25); // 25 chars / 100 bytes
        let output = format_output(&ents, "table", "notes.txt")
            .expect("table format must not panic on a multibyte value");
        assert!(
            output.contains(&"🎯".repeat(20)),
            "value should be truncated to its first 20 characters"
        );
        assert!(
            !output.contains(&"🎯".repeat(21)),
            "value must be cut at 20 characters, not more"
        );
    }
}
