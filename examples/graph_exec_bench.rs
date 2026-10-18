//! Reproducible, entirely offline DAG scheduling benchmark.
//! Run: cargo run --locked --example graph_exec_bench

use std::sync::{Arc, atomic::AtomicBool};
use std::thread;
use std::time::Duration;

use huntsman_recon::graph_exec::{
    ExecutionComparison, ExecutionPolicy, GraphDefinition, GraphExecutor, HandlerRegistry,
    RunTermination, TaskContext, TaskOutput, TaskRole, TaskSpec, ValueSchema, VerificationRecord,
    VerificationState,
};
use serde_json::json;

fn task(id: &str) -> TaskSpec {
    TaskSpec {
        id: id.into(),
        objective: format!("sleep-bound synthetic work {id}"),
        role: TaskRole::Producer,
        input: json!({}),
        input_schema: ValueSchema::Any,
        output_schema: ValueSchema::Boolean,
        dependencies: Vec::new(),
        exclusive_resources: Vec::new(),
        rate_limit: None,
        idempotency_key: None,
        requires_idempotency: false,
        timeout_ms: 1_000,
        max_retries: 0,
        resource_units: 1,
    }
}

fn policy(concurrency: usize) -> ExecutionPolicy {
    ExecutionPolicy {
        max_concurrency: concurrency,
        max_total_resource_units: 16,
        max_output_bytes: 1_024,
        run_timeout_ms: 2_000,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ids = ["a", "b", "c", "d"];
    let definition = GraphDefinition {
        run_id: "offline-graph-benchmark".into(),
        tasks: ids.iter().map(|id| task(id)).collect(),
    };
    let mut handlers = HandlerRegistry::new();
    for id in ids {
        handlers.insert(
            id.into(),
            Arc::new(|context: TaskContext| {
                thread::sleep(Duration::from_millis(30));
                Ok(TaskOutput {
                    value: json!(true),
                    evidence: Vec::new(),
                    verification: VerificationRecord {
                        state: VerificationState::Unresolved,
                        producer_id: context.task_id,
                        reviewer_id: "not-reviewed".into(),
                        basis: "synthetic workload, no external evidence".into(),
                        evidence_refs: Vec::new(),
                    },
                })
            }),
        );
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let sequential = GraphExecutor::new(policy(1)).execute(&definition, &handlers, &cancelled)?;
    let parallel = GraphExecutor::new(policy(4)).execute(&definition, &handlers, &cancelled)?;
    if sequential.termination != Some(RunTermination::Completed)
        || parallel.termination != Some(RunTermination::Completed)
        || sequential.summary().succeeded != ids.len()
        || parallel.summary().succeeded != ids.len()
    {
        return Err("benchmark tasks did not all succeed".into());
    }
    let comparison = ExecutionComparison::from_measured_sequential_baseline(
        sequential.duration_ms.ok_or("missing sequential duration")?,
        &parallel,
    );
    let output = json!({
        "workload": "4 independent local 30ms tasks; no network, APIs or models",
        "sequential_wall_clock_ms": comparison.sequential_wall_clock_ms,
        "graph_wall_clock_ms": comparison.graph_wall_clock_ms,
        "speedup_ratio_milli": comparison.speedup_ratio_milli,
        "sequential_summary": sequential.summary(),
        "graph_summary": parallel.summary(),
        "external_api_calls": 0,
        "model_calls": 0,
        "actual_external_api_cost_usd": 0.0,
        "runner_compute_cost_usd": null,
        "real_provider_benchmark": false
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
