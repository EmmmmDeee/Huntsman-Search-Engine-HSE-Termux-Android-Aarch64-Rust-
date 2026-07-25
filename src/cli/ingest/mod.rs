//! `hse ingest` command: Parse documents → extract entities → output JSONL batch.
//!
//! Supports auto-scan: extracted entities can optionally be fed into the HSE scan pipeline
//! for automatic recursive expansion and cross-correlation. Phase 4 integration.

mod converter;

use crate::util::document_parse::{DocumentFormat, DocumentResult};
use crate::util::entity_extractor::EntityExtractor;
use clap::Parser;
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

#[derive(Parser, Debug)]
pub struct IngestArgs {
    /// Input file path (image, PDF, CSV, JSON, JSONL, text)
    #[arg(short, long, value_name = "PATH")]
    pub file: PathBuf,

    /// Output format: jsonl (default), json, csv, table, hse
    ///
    /// Short flag is `-F`: `-f` is the input file and `-o` the output file,
    /// and clap panics at startup on a duplicate short name.
    #[arg(short = 'F', long, default_value = "jsonl")]
    pub output_format: String,

    /// Minimum confidence threshold (0.0-1.0)
    #[arg(long, default_value = "0.30")]
    pub min_confidence: f64,

    /// Auto-scan extracted entities (not yet implemented)
    #[arg(long)]
    pub auto_scan: bool,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Extract EXIF geolocation from images
    #[arg(long)]
    pub extract_geolocation: bool,

    /// Generate reverse image search variants for detected images
    #[arg(long)]
    pub generate_reverse_search_variants: bool,

    /// Output directory for reverse image search variants
    #[arg(long, value_name = "DIR")]
    pub image_variant_output_dir: Option<PathBuf>,
}

/// Execute `hse ingest` command.
pub async fn run(args: IngestArgs) -> DocumentResult<()> {
    // Detect file format
    let format = DocumentFormat::from_path(&args.file)
        .ok_or_else(|| crate::util::document_parse::DocumentParseError::UnsupportedFormat(
            args.file.to_string_lossy().to_string(),
        ))?;

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
        raw_text.metadata.character_count, args.file.display(), raw_text.confidence
    );

    // Extract entities
    let extractor = EntityExtractor::new(args.min_confidence)?;
    let entities = extractor.extract_from_text(&raw_text.text);

    info!("Found {} entities", entities.len());

    // Phase 6: Image processing (geolocation + reverse image search)
    if matches!(raw_text.source_format, DocumentFormat::Image) {
        // Extract EXIF geolocation if requested
        if args.extract_geolocation {
            match crate::util::document_parse::image_geolocation::extract_image_geolocation(&args.file) {
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
            match crate::util::document_parse::image_reverse_search::generate_reverse_image_variants(&args.file) {
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
                        let base_name = args.file
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
                        let metadata_path = output_dir.join(format!("{base_name}_reverse_search_metadata.json"));
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
                        fs::write(&metadata_path, serde_json::to_string_pretty(&metadata_json)?)?;
                        info!("Saved reverse search metadata to {}", metadata_path.display());
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to generate reverse image search variants: {}", e);
                }
            }
        }
    }

    // Phase 4: Auto-scan integration (when --auto-scan flag is set)
    // Future: Wire extracted entities into HSE scan pipeline via:
    // 1. Convert ExtractedEntity → core::entity::Entity using converter::extracted_to_hse_entity()
    // 2. Create or use existing scan record with unique scan_id
    // 3. Call storage::Store::upsert_entities_batch(&entities, &scan_id)
    // 4. Execute engine::ScanEngine::run() with the extracted entities as seeds
    // 5. Return scan results to user with "auto-scan" tag
    if args.auto_scan {
        info!("Auto-scan flag set; implementation pending Phase 4 engine integration");
        // Auto-scan wiring deferred: requires Store/Engine context not available at CLI level
    }

    // Format output
    let document_source = args
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ingest");
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

        "json" => Ok(json!(entities.iter().map(|e| json!({
            "kind": e.kind.to_str(),
            "value": e.value,
            "confidence": e.confidence,
            "source_pattern": e.source_pattern,
            "boost_reason": e.boost_reason,
        })).collect::<Vec<_>>()).to_string()),

        "csv" => {
            let mut csv = String::from("kind,value,confidence,source_pattern\n");
            for e in entities {
                csv.push_str(&format!(
                    "{},{},{},{}\n",
                    e.kind.to_str(),
                    e.value.replace(',', "\\,"),
                    e.confidence,
                    e.source_pattern
                ));
            }
            Ok(csv)
        }

        "table" => {
            let mut table = String::from("Kind\t\tValue\t\t\tConfidence\tPattern\n");
            table.push_str("----\t\t-----\t\t\t----------\t-------\n");
            for e in entities {
                table.push_str(&format!(
                    "{:<15}\t{:<20}\t{:.2}\t\t{}\n",
                    e.kind.to_str(),
                    &e.value[..e.value.len().min(20)],
                    e.confidence,
                    e.source_pattern
                ));
            }
            Ok(table)
        }

        other => Err(crate::util::document_parse::DocumentParseError::UnsupportedFormat(
            format!("output format: {other}"),
        )),
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
        let output = format_output(&sample(), "jsonl", "notes.txt").unwrap();
        assert!(output.contains("test@example.com"));
        assert!(output.contains("email"));
    }

    #[test]
    fn format_hse_emits_scannable_entities() {
        let output = format_output(&sample(), "hse", "notes.txt").unwrap();
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
            entity.evidence.iter().any(|e| e.source.contains("notes.txt")),
            "evidence must name the source document"
        );
    }

    #[test]
    fn format_rejects_unknown_output_format() {
        assert!(format_output(&sample(), "yaml", "notes.txt").is_err());
    }
}
