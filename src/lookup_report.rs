//! The text report of an identifier lookup: the entities found, the outcome of each source, and the
//! lineage of the observations behind them. The email and username front-ends print this report,
//! so their formats cannot drift apart.

use std::fmt::Write as _;

use crate::entity::Entity;
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{lineage_tsv_line, observations_from, resolve_with_lineage};
use crate::source_outcome::SourceExecutionOutcome;

/// The report of one lookup. The first line is `entities=N`. Each entity follows as a
/// tab-separated line (kind, value, confidence, tags), then each source outcome (module, kind,
/// found count), and the lineage block closes the report.
///
/// # Errors
/// The first formatting or lineage-resolution error, as text.
pub fn render(entities: &[Entity], outcomes: &[SourceExecutionOutcome]) -> Result<String, String> {
    let mut out = format!("entities={}\n", entities.len());
    for entity in entities {
        writeln!(
            out,
            "{}\t{}\t{:.2}\t{}",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        )
        .map_err(|err| err.to_string())?;
    }
    for outcome in outcomes {
        let found = outcome
            .found
            .map_or_else(|| "none".to_owned(), |count| count.to_string());
        let kind = serde_json::to_value(outcome.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".into());
        writeln!(out, "{}\t{kind}\tfound={found}", outcome.module)
            .map_err(|err| err.to_string())?;
    }
    append_lineage(entities, &mut out)?;
    Ok(out)
}

fn append_lineage(entities: &[Entity], out: &mut String) -> Result<(), String> {
    let observations = observations_from(entities);
    if observations.is_empty() {
        return Ok(());
    }
    let resolution = resolve_with_lineage(observations, Vec::new(), AutoMergePolicy::default())
        .map_err(|err| err.to_string())?;
    writeln!(out, "lineage={}", resolution.observations.len()).map_err(|err| err.to_string())?;
    for item in &resolution.observations {
        writeln!(out, "{}", lineage_tsv_line(item)).map_err(|err| err.to_string())?;
    }
    Ok(())
}
