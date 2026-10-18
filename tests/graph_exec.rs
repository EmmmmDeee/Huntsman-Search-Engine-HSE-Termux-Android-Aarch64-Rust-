use std::sync::{Arc, atomic::AtomicBool};
use std::thread;
use std::time::{Duration, Instant};

use huntsman_recon::graph_exec::{
    ExecutionComparison, ExecutionPolicy, GraphDefinition, GraphExecutor, HandlerRegistry,
    RunTermination, TaskContext, TaskFailure, TaskOutput, TaskRole, TaskSpec, TaskState,
    ValueSchema, VerificationRecord, VerificationState,
};
use serde_json::json;

#[test]
fn exported_graph_executor_runs_a_task_through_the_public_api() {
    let definition = GraphDefinition {
        run_id: "public-api-smoke".into(),
        tasks: vec![TaskSpec {
            id: "public-api".into(),
            objective: "exercise the exported graph executor".into(),
            role: TaskRole::Producer,
            input: json!({}),
            input_schema: ValueSchema::Any,
            output_schema: ValueSchema::Any,
            dependencies: vec![],
            exclusive_resources: vec![],
            rate_limit: None,
            idempotency_key: None,
            requires_idempotency: false,
            timeout_ms: 1_000,
            max_retries: 0,
            resource_units: 1,
        }],
    };

    let mut handlers = HandlerRegistry::new();
    handlers.insert(
        "public-api".into(),
        Arc::new(|context: TaskContext| -> Result<TaskOutput, TaskFailure> {
            Ok(TaskOutput {
                value: json!({"ok": true}),
                evidence: vec![],
                verification: VerificationRecord {
                    state: VerificationState::Unresolved,
                    producer_id: context.task_id,
                    reviewer_id: "independent-reviewer".into(),
                    basis: "public API integration smoke test".into(),
                    evidence_refs: vec![],
                },
            })
        }),
    );

    let report = GraphExecutor::new(ExecutionPolicy::default())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();

    assert_eq!(report.tasks["public-api"].state, TaskState::Succeeded);
    assert_eq!(report.termination, Some(RunTermination::Completed));
}

fn simulated_blocking_lookup() -> serde_json::Value {
    // Deterministic output and fixed simulated transport latency; no external API or charge.
    thread::sleep(Duration::from_millis(35));
    json!({"text": "synthetic finding", "entities": [], "outcomes": []})
}

#[test]
fn measured_sequential_vs_bounded_graph_synthetic_io() {
    const TASK_COUNT: usize = 4;
    let sequential_start = Instant::now();
    let sequential: Vec<_> = (0..TASK_COUNT)
        .map(|_| simulated_blocking_lookup())
        .collect();
    let sequential_ms = u64::try_from(sequential_start.elapsed().as_millis()).unwrap();

    let definition = GraphDefinition {
        run_id: "synthetic-io-comparison".into(),
        tasks: (0..TASK_COUNT)
            .map(|i| TaskSpec {
                id: format!("lookup-{i:04}"),
                objective: "simulate an independent blocking provider lookup".into(),
                role: TaskRole::Producer,
                input: json!({}),
                input_schema: ValueSchema::Any,
                output_schema: ValueSchema::Any,
                dependencies: vec![],
                exclusive_resources: vec![],
                rate_limit: None,
                idempotency_key: None,
                requires_idempotency: false,
                timeout_ms: 5_000,
                max_retries: 0,
                resource_units: 1,
            })
            .collect(),
    };
    let mut handlers = HandlerRegistry::new();
    for task in &definition.tasks {
        handlers.insert(
            task.id.clone(),
            Arc::new(|context: TaskContext| -> Result<TaskOutput, TaskFailure> {
                context.check_deadline()?;
                Ok(TaskOutput {
                    value: simulated_blocking_lookup(),
                    evidence: vec![],
                    verification: VerificationRecord {
                        state: VerificationState::Unresolved,
                        producer_id: context.task_id,
                        reviewer_id: "not-reviewed".into(),
                        basis: "synthetic workload only; no source evidence".into(),
                        evidence_refs: vec![],
                    },
                })
            }),
        );
    }
    let graph = GraphExecutor::new(ExecutionPolicy {
        max_concurrency: 2,
        max_total_resource_units: 4,
        max_output_bytes: 8192,
        run_timeout_ms: 5_000,
    })
    .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
    .unwrap();
    assert_eq!(graph.termination, Some(RunTermination::Completed));
    assert!(
        graph
            .tasks
            .values()
            .all(|task| task.state == TaskState::Succeeded)
    );
    let parallel: Vec<_> = graph
        .tasks
        .values()
        .map(|task| task.output.as_ref().unwrap().value.clone())
        .collect();
    assert_eq!(parallel, sequential);

    let comparison = ExecutionComparison::from_measured_sequential_baseline(sequential_ms, &graph);
    assert_eq!(comparison.task_count, TASK_COUNT);
    assert_eq!(comparison.graph_summary.succeeded, TASK_COUNT);
    eprintln!(
        "{}",
        json!({
            "benchmark": "synthetic_four_independent_blocking_lookups",
            "sequential_wall_clock_ms": comparison.sequential_wall_clock_ms,
            "graph_wall_clock_ms": comparison.graph_wall_clock_ms,
            "speedup_ratio_milli": comparison.speedup_ratio_milli,
            "tasks_succeeded": comparison.graph_summary.succeeded,
            "tasks_failed": comparison.graph_summary.failed,
            "observed_external_api_calls": 0,
            "observed_model_calls": 0,
            "observed_external_cost_usd": 0,
            "scope": "synthetic; not a production provider throughput claim",
        })
    );
}
