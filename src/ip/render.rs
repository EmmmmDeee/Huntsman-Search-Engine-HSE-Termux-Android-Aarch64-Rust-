//! Shared renderers for IP investigation output.

use std::fmt::Write as _;

use super::IpInvestigation;

/// Serialize the complete investigation state as stable, pretty JSON.
pub fn render_json(investigation: &IpInvestigation) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(investigation)
}

/// Render the investigation as concise human-readable text.
#[must_use]
pub fn render_text(investigation: &IpInvestigation) -> String {
    render_text_impl(investigation, false)
}

/// Render the same investigation facts with additional provenance detail.
#[must_use]
pub fn render_text_with_evidence(investigation: &IpInvestigation) -> String {
    render_text_impl(investigation, true)
}

fn render_text_impl(investigation: &IpInvestigation, evidence: bool) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "target={} scope={:?}",
        investigation.target.canonical(),
        investigation.target.scope
    );

    let _ = writeln!(output, "observations={}", investigation.observations.len());
    for observation in &investigation.observations {
        let _ = writeln!(
            output,
            "observation kind={:?} provider={} summary={}",
            observation.kind, observation.provider_id, observation.summary
        );
    }

    let _ = writeln!(output, "failures={}", investigation.failures.len());
    for failure in &investigation.failures {
        let _ = writeln!(
            output,
            "failure provider={} kind={:?} detail={}",
            failure.provider_id, failure.kind, failure.detail
        );
    }

    let _ = writeln!(output, "claims={}", investigation.claims.len());
    for claim in &investigation.claims {
        let _ = writeln!(
            output,
            "claim kind={} state={:?} temporal={:?}",
            claim.kind.as_str(),
            claim.state,
            claim.temporal
        );
    }

    let _ = writeln!(
        output,
        "budget calls={} actions={} max_depth={}",
        investigation.budget_used.calls,
        investigation.budget_used.actions,
        investigation.budget_used.max_depth_reached
    );
    let _ = writeln!(
        output,
        "termination={}",
        investigation
            .termination_reason
            .as_deref()
            .unwrap_or("none")
    );

    if evidence {
        output.push_str("evidence: claim_states_unchanged=true\n");
        for observation in &investigation.observations {
            let _ = writeln!(
                output,
                "evidence: observation_id={} source_family={} provider={} observed_at={} retrieved_at={} raw_digest={}",
                observation.id,
                observation.source_family,
                observation.provider_id,
                observation
                    .observed_at_unix
                    .map_or_else(|| "unknown".into(), |value| value.to_string()),
                observation.retrieved_at_unix,
                observation.raw_digest.as_deref().unwrap_or("none")
            );
        }
        for claim in &investigation.claims {
            let _ = writeln!(
                output,
                "evidence: claim={} support_ids={} contradiction_ids={} dependency_ids={}",
                claim.kind.as_str(),
                claim.support_ids.join(","),
                claim.contradiction_ids.join(","),
                claim.dependency_ids.join(",")
            );
        }
        for action in &investigation.actions_considered {
            let _ = writeln!(
                output,
                "evidence: action provider={} id={} executed={} reason={}",
                action.provider_id, action.action_id, action.executed, action.reason
            );
        }
    }

    output
}
