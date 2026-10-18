use std::sync::{Arc, atomic::AtomicBool};

use huntsman_recon::graph_exec::{
    ExecutionPolicy, GraphDefinition, GraphExecutor, HandlerRegistry, RunTermination, TaskContext,
    TaskFailure, TaskOutput, TaskRole, TaskSpec, TaskState, ValueSchema, VerificationRecord,
    VerificationState,
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
