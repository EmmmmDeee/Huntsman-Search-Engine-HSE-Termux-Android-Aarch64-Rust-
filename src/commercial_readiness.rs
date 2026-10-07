//! Machine-checkable capability and benchmark manifests.
//!
//! This module deliberately separates demonstrated capability claims from
//! performance claims. A benchmark is admitted only when a complete receipt is
//! present; an empty benchmark manifest therefore means "not measured", not
//! "zero" and not "fast".

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

const CAPABILITIES_JSON: &str = include_str!("../capabilities.json");
const BENCHMARKS_JSON: &str = include_str!("../benchmarks.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CapabilityManifest {
    pub schema_version: u32,
    pub product: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Capability {
    pub id: String,
    pub name: String,
    pub status: CapabilityStatus,
    pub implementation: Vec<String>,
    pub proof: Vec<String>,
    pub interfaces: Vec<String>,
    pub platforms: Vec<String>,
    pub benchmark: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityStatus {
    Demonstrated,
    Partial,
    Planned,
}

impl CapabilityStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Demonstrated => "demonstrated",
            Self::Partial => "partial",
            Self::Planned => "planned",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchmarkManifest {
    pub schema_version: u32,
    pub policy: BenchmarkPolicy,
    pub benchmarks: Vec<BenchmarkReceipt>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchmarkPolicy {
    pub claim_rule: String,
    pub regression_gate: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchmarkReceipt {
    pub id: String,
    pub capability: String,
    pub workload: String,
    pub platform: String,
    pub build_profile: String,
    pub repetitions: u32,
    pub metric: String,
    pub value: f64,
    pub unit: String,
}

pub fn manifest() -> Result<CapabilityManifest, String> {
    let parsed: CapabilityManifest = serde_json::from_str(CAPABILITIES_JSON)
        .map_err(|error| format!("capabilities.json: {error}"))?;
    validate_capabilities(&parsed)?;
    Ok(parsed)
}

pub fn benchmarks() -> Result<BenchmarkManifest, String> {
    let capabilities = manifest()?;
    let parsed: BenchmarkManifest = serde_json::from_str(BENCHMARKS_JSON)
        .map_err(|error| format!("benchmarks.json: {error}"))?;
    validate_benchmarks(&parsed, &capabilities)?;
    Ok(parsed)
}

pub fn readiness_markdown() -> Result<String, String> {
    let capabilities = manifest()?;
    let benchmarks = benchmarks()?;

    let demonstrated = capabilities
        .capabilities
        .iter()
        .filter(|capability| capability.status == CapabilityStatus::Demonstrated)
        .count();
    let partial = capabilities
        .capabilities
        .iter()
        .filter(|capability| capability.status == CapabilityStatus::Partial)
        .count();
    let planned = capabilities
        .capabilities
        .iter()
        .filter(|capability| capability.status == CapabilityStatus::Planned)
        .count();

    let mut output = format!(
        concat!(
            "# Generated commercial-readiness report\n\n",
            "Schema: {}. Product: {}.\n\n",
            "Demonstrated: **{}**. Partial: **{}**. ",
            "Planned: **{}**. Benchmark receipts: **{}**.\n\n",
            "| Capability | Status | Interfaces | Platforms | Benchmark |\n",
            "| --- | --- | --- | --- | --- |\n"
        ),
        capabilities.schema_version,
        capabilities.product,
        demonstrated,
        partial,
        planned,
        benchmarks.benchmarks.len()
    );

    for capability in &capabilities.capabilities {
        writeln!(
            &mut output,
            "| {} | {} | {} | {} | {} |",
            capability.name,
            capability.status.as_str(),
            capability.interfaces.join(", "),
            capability.platforms.join(", "),
            capability.benchmark.as_deref().unwrap_or("not measured")
        )
        .expect("writing to a String cannot fail");
    }

    output.push_str(
        "\nGenerated from capabilities.json and benchmarks.json;          not a valuation or revenue claim.\n",
    );

    Ok(output)
}

fn validate_capabilities(manifest: &CapabilityManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err("capabilities.json: unsupported schema_version".into());
    }
    if manifest.product != "huntsman-recon" {
        return Err("capabilities.json: unexpected product".into());
    }

    let mut ids = BTreeSet::new();
    for capability in &manifest.capabilities {
        require_nonempty("capability id", &capability.id)?;
        require_nonempty("capability name", &capability.name)?;
        if !ids.insert(capability.id.as_str()) {
            return Err(format!(
                "capabilities.json: duplicate capability id {}",
                capability.id
            ));
        }
        if capability.implementation.is_empty() {
            return Err(format!(
                "capability {} has no implementation paths",
                capability.id
            ));
        }
        if capability.proof.is_empty() {
            return Err(format!("capability {} has no proof paths", capability.id));
        }
        if capability.interfaces.is_empty() {
            return Err(format!("capability {} has no interfaces", capability.id));
        }
        if capability.platforms.is_empty() {
            return Err(format!("capability {} has no platforms", capability.id));
        }
        if capability.status == CapabilityStatus::Demonstrated && capability.limitations.is_empty()
        {
            return Err(format!(
                "demonstrated capability {} must state limitations",
                capability.id
            ));
        }
    }

    Ok(())
}

fn validate_benchmarks(
    manifest: &BenchmarkManifest,
    capabilities: &CapabilityManifest,
) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err("benchmarks.json: unsupported schema_version".into());
    }
    require_nonempty("benchmark claim_rule", &manifest.policy.claim_rule)?;
    require_nonempty(
        "benchmark regression_gate",
        &manifest.policy.regression_gate,
    )?;

    let capability_ids: BTreeSet<_> = capabilities
        .capabilities
        .iter()
        .map(|capability| capability.id.as_str())
        .collect();
    let mut receipt_ids = BTreeSet::new();

    for receipt in &manifest.benchmarks {
        for (field, value) in [
            ("benchmark id", receipt.id.as_str()),
            ("benchmark capability", receipt.capability.as_str()),
            ("benchmark workload", receipt.workload.as_str()),
            ("benchmark platform", receipt.platform.as_str()),
            ("benchmark build_profile", receipt.build_profile.as_str()),
            ("benchmark metric", receipt.metric.as_str()),
            ("benchmark unit", receipt.unit.as_str()),
        ] {
            require_nonempty(field, value)?;
        }

        if !receipt_ids.insert(receipt.id.as_str()) {
            return Err(format!(
                "benchmarks.json: duplicate receipt id {}",
                receipt.id
            ));
        }
        if !capability_ids.contains(receipt.capability.as_str()) {
            return Err(format!(
                "benchmark {} references unknown capability {}",
                receipt.id, receipt.capability
            ));
        }
        if receipt.repetitions == 0 {
            return Err(format!(
                "benchmark {} must have at least one repetition",
                receipt.id
            ));
        }
        if !receipt.value.is_finite() {
            return Err(format!("benchmark {} has non-finite value", receipt.id));
        }
    }

    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}
