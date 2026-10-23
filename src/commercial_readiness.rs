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
        "\nGenerated from capabilities.json and benchmarks.json; not a valuation or revenue claim.\n",
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

    // A capability's benchmark is a claim like any other: it stands only on its receipt.
    for capability in &capabilities.capabilities {
        if let Some(benchmark) = capability.benchmark.as_deref() {
            let receipted = manifest
                .benchmarks
                .iter()
                .any(|receipt| receipt.id == benchmark && receipt.capability == capability.id);
            if !receipted {
                return Err(format!(
                    "capability {} names benchmark {benchmark} with no receipt",
                    capability.id
                ));
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped() -> (BenchmarkManifest, CapabilityManifest) {
        (
            serde_json::from_str(BENCHMARKS_JSON).unwrap(),
            serde_json::from_str(CAPABILITIES_JSON).unwrap(),
        )
    }

    #[test]
    fn the_shipped_manifests_pass() {
        let (benchmarks, capabilities) = shipped();
        assert_eq!(validate_benchmarks(&benchmarks, &capabilities), Ok(()));
    }

    /// One way to break a valid manifest.
    type Break<T> = fn(&mut T);

    fn receipt(capabilities: &CapabilityManifest) -> BenchmarkReceipt {
        BenchmarkReceipt {
            id: "receipt-1".into(),
            capability: capabilities.capabilities[0].id.clone(),
            workload: "workload".into(),
            platform: "aarch64-linux-android".into(),
            build_profile: "release".into(),
            repetitions: 1,
            metric: "p50".into(),
            value: 1.0,
            unit: "ms".into(),
        }
    }

    #[test]
    fn every_capability_rejection_names_its_rule() {
        let cases: &[(&str, Break<CapabilityManifest>)] = &[
            ("unsupported schema_version", |m| m.schema_version = 2),
            ("unexpected product", |m| m.product = "other".into()),
            ("capability id must not be empty", |m| {
                m.capabilities[0].id = " ".into();
            }),
            ("capability name must not be empty", |m| {
                m.capabilities[0].name.clear();
            }),
            ("duplicate capability id", |m| {
                let first = m.capabilities[0].clone();
                m.capabilities.push(first);
            }),
            ("has no implementation paths", |m| {
                m.capabilities[0].implementation.clear();
            }),
            ("has no proof paths", |m| {
                m.capabilities[0].proof.clear();
            }),
            ("has no interfaces", |m| {
                m.capabilities[0].interfaces.clear();
            }),
            ("has no platforms", |m| {
                m.capabilities[0].platforms.clear();
            }),
            ("must state limitations", |m| {
                m.capabilities[0].status = CapabilityStatus::Demonstrated;
                m.capabilities[0].limitations.clear();
            }),
        ];
        for (want, break_it) in cases {
            let (_, mut capabilities) = shipped();
            assert_eq!(validate_capabilities(&capabilities), Ok(()));
            break_it(&mut capabilities);
            let error = validate_capabilities(&capabilities).unwrap_err();
            assert!(error.contains(want), "{want}: {error}");
        }
    }

    #[test]
    fn every_receipt_rejection_names_its_rule() {
        let cases: &[(&str, Break<BenchmarkManifest>)] = &[
            ("unsupported schema_version", |m| m.schema_version = 0),
            ("benchmark claim_rule must not be empty", |m| {
                m.policy.claim_rule.clear();
            }),
            ("benchmark regression_gate must not be empty", |m| {
                m.policy.regression_gate = " ".into();
            }),
            ("benchmark id must not be empty", |m| {
                m.benchmarks[0].id.clear();
            }),
            ("benchmark capability must not be empty", |m| {
                m.benchmarks[0].capability.clear();
            }),
            ("benchmark workload must not be empty", |m| {
                m.benchmarks[0].workload.clear();
            }),
            ("benchmark platform must not be empty", |m| {
                m.benchmarks[0].platform.clear();
            }),
            ("benchmark build_profile must not be empty", |m| {
                m.benchmarks[0].build_profile.clear();
            }),
            ("benchmark metric must not be empty", |m| {
                m.benchmarks[0].metric.clear();
            }),
            ("benchmark unit must not be empty", |m| {
                m.benchmarks[0].unit.clear();
            }),
            ("duplicate receipt id", |m| {
                let first = m.benchmarks[0].clone();
                m.benchmarks.push(first);
            }),
            ("references unknown capability", |m| {
                m.benchmarks[0].capability = "no-such-capability".into();
            }),
            ("must have at least one repetition", |m| {
                m.benchmarks[0].repetitions = 0;
            }),
            ("has non-finite value", |m| m.benchmarks[0].value = f64::NAN),
        ];
        for (want, break_it) in cases {
            let (mut benchmarks, capabilities) = shipped();
            benchmarks.benchmarks.push(receipt(&capabilities));
            assert_eq!(validate_benchmarks(&benchmarks, &capabilities), Ok(()));
            break_it(&mut benchmarks);
            let error = validate_benchmarks(&benchmarks, &capabilities).unwrap_err();
            assert!(error.contains(want), "{want}: {error}");
        }
    }

    #[test]
    fn a_benchmark_a_capability_names_needs_its_receipt() {
        let (benchmarks, mut capabilities) = shipped();
        capabilities.capabilities[0].benchmark = Some("p50 3 ms".into());
        let error = validate_benchmarks(&benchmarks, &capabilities).unwrap_err();
        assert!(error.contains("with no receipt"), "{error}");
    }
}
