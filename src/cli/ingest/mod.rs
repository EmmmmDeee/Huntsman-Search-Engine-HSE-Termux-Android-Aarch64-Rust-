//! `hse ingest` command: Parse documents → extract entities → output JSONL batch.
//!
//! Supports auto-scan: extracted entities can optionally be fed into the HSE scan pipeline
//! for automatic recursive expansion and cross-correlation. Phase 4 integration.

mod converter;

use crate::util::document_parse::{DocumentFormat, DocumentResult};
use crate::util::entity_extractor::{EntityExtractor, EntityKind};
use clap::Parser;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
pub struct IngestArgs {
    /// Input file path (image, PDF, CSV, JSON, JSONL, text)
    #[arg(short, long, value_name = "PATH")]
    pub file: PathBuf,

    /// Output format: jsonl (default), json, csv, table
    #[arg(short, long, default_value = "jsonl")]
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
    let output_text = format_output(&entities, &args.output_format)?;

    // Write output
    if let Some(output_path) = args.output {
        fs::write(&output_path, output_text)?;
        info!("Wrote output to {}", output_path.display());
    } else {
        println!("{}", output_text);
    }

    Ok(())
}

/// Format entities as JSONL, JSON, CSV, or human-readable table.
fn format_output(entities: &[crate::util::entity_extractor::ExtractedEntity], format: &str) -> DocumentResult<String> {
    match format {
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
            format!("output format: {}", other),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_jsonl() {
        let entities = vec![crate::util::entity_extractor::ExtractedEntity {
            kind: EntityKind::Email,
            value: "test@example.com".to_string(),
            confidence: 0.85,
            context: None,
            source_pattern: "email_rfc5322".to_string(),
            boost_reason: None,
        }];

        let output = format_output(&entities, "jsonl").unwrap();
        assert!(output.contains("test@example.com"));
        assert!(output.contains("email"));
    }
}
