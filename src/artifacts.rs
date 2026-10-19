//! Deterministic bounded artifacts rendered from one final analysis state.

use serde::{Deserialize, Serialize};

use crate::analysis::InvestigationReport;
use crate::error::Error;
use crate::gexf;
use crate::graph::Graph;
use crate::json;
use crate::ledger::LedgerEntry;
use crate::metrics;
use crate::navigator;
use crate::pipeline::{AnalysisSnapshot, PipelineLimits};
use crate::snake_graph;
use crate::stix;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ArtifactPayload {
    Ready(Vec<u8>),
    OmittedTooLarge { required_bytes: usize, limit: usize },
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineArtifacts {
    pub report_json: ArtifactPayload,
    pub gexf: ArtifactPayload,
    pub snake_graph: ArtifactPayload,
    pub stix: ArtifactPayload,
    pub navigator: ArtifactPayload,
    pub truncated: bool,
}

fn omitted(payload: &ArtifactPayload) -> bool {
    matches!(payload, ArtifactPayload::OmittedTooLarge { .. })
}

fn canonical_json(
    value: &serde_json::Value,
    limit: usize,
) -> Result<ArtifactPayload, Error> {
    json::to_canonical_bounded(value, limit)
        .map(|result| match result {
            Ok(bytes) => ArtifactPayload::Ready(bytes),
            Err(required_bytes) => ArtifactPayload::OmittedTooLarge {
                required_bytes,
                limit,
            },
        })
        .map_err(|error| Error::Store(error.to_string()))
}

/// Render all selected outputs from the same immutable snapshot/report.
///
/// Structured output is omitted whole when it exceeds the export budget; it is never
/// byte-truncated into invalid JSON/XML.
///
/// # Errors
/// Returns serialization failures.
pub fn render_artifacts(
    snapshot: &AnalysisSnapshot,
    report: &InvestigationReport,
    ledger: &[LedgerEntry],
    limits: &PipelineLimits,
) -> Result<PipelineArtifacts, Error> {
    let report_value =
        serde_json::to_value(report).map_err(|error| Error::Store(error.to_string()))?;
    let report_json = canonical_json(&report_value, limits.max_export_bytes)?;
    let gexf = match gexf::to_gexf_bounded(
        &snapshot.entities,
        &snapshot.relations,
        limits.max_export_bytes,
    ) {
        Ok(xml) => ArtifactPayload::Ready(xml.into_bytes()),
        Err(required_bytes) => ArtifactPayload::OmittedTooLarge {
            required_bytes,
            limit: limits.max_export_bytes,
        },
    };
    let graph = Graph::build(&snapshot.entities, &snapshot.relations);
    let snake_graph = metrics::subject_uid(&snapshot.entities)
        .or_else(|| snapshot.entities.first().map(|entity| entity.uid.as_str()))
        .and_then(|root| {
            snake_graph::render_snake_graph_bounded(&graph, root, limits.max_export_bytes)
        })
        .map_or(ArtifactPayload::NotApplicable, |result| match result {
            Ok(text) => ArtifactPayload::Ready(text.into_bytes()),
            Err(required_bytes) => ArtifactPayload::OmittedTooLarge {
                required_bytes,
                limit: limits.max_export_bytes,
            },
        });
    let stix = canonical_json(&stix::bundle(ledger), limits.max_export_bytes)?;
    let navigator = canonical_json(&navigator::layer(ledger), limits.max_export_bytes)?;
    let truncated = snapshot.truncated
        || report.truncated
        || [&report_json, &gexf, &snake_graph, &stix, &navigator]
            .into_iter()
            .any(omitted);
    Ok(PipelineArtifacts {
        report_json,
        gexf,
        snake_graph,
        stix,
        navigator,
        truncated,
    })
}
