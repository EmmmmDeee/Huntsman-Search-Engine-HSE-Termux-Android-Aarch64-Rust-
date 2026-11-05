use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

fn schema_any() -> ValueSchema {
    ValueSchema::Any
}

fn spec(id: &str, dependencies: &[&str]) -> TaskSpec {
    TaskSpec {
        id: id.into(),
        objective: format!("execute {id}"),
        role: TaskRole::Producer,
        input: json!({}),
        input_schema: schema_any(),
        output_schema: schema_any(),
        dependencies: dependencies
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        exclusive_resources: Vec::new(),
        rate_limit: None,
        idempotency_key: None,
        requires_idempotency: false,
        timeout_ms: 1_000,
        max_retries: 0,
        resource_units: 1,
    }
}

fn output(value: Value, producer: &str) -> TaskOutput {
    TaskOutput {
        value,
        evidence: Vec::new(),
        verification: VerificationRecord {
            state: VerificationState::Unresolved,
            producer_id: producer.into(),
            reviewer_id: "independent-reviewer".into(),
            basis: "result retained pending evidence review".into(),
            evidence_refs: Vec::new(),
        },
    }
}

fn handler<F>(f: F) -> TaskHandler
where
    F: Fn(TaskContext) -> Result<TaskOutput, TaskFailure> + Send + Sync + 'static,
{
    Arc::new(f)
}

/// The instant the scheduler admitted this attempt, plus the task's timeout: the attempt's
/// deadline. The tests that read it give every task one timeout and end far inside the run
/// deadline, so two attempts' deadlines are exactly as far apart as their admissions, the
/// instants a rate limit spaces. A clock read inside the handler is not: it also counts the
/// time before the handler ran, which differs per attempt on a loaded machine.
fn admitted_plus_timeout(context: &TaskContext) -> Instant {
    context.deadline
}

fn policy() -> ExecutionPolicy {
    ExecutionPolicy {
        max_concurrency: 4,
        max_total_resource_units: 100,
        max_output_bytes: 1024 * 1024,
        run_timeout_ms: 10_000,
    }
}

#[test]
fn rejects_missing_dependencies_and_cycles_before_dispatch() {
    let missing = GraphDefinition {
        run_id: "run-1".into(),
        tasks: vec![spec("a", &["missing"])],
    };
    assert!(missing.validate().is_err());
    let cycle = GraphDefinition {
        run_id: "run-2".into(),
        tasks: vec![spec("a", &["b"]), spec("b", &["a"])],
    };
    assert!(cycle.validate().unwrap_err().to_string().contains("cycle"));
}

#[test]
fn side_effecting_task_requires_an_idempotency_key() {
    let mut task = spec("side-effect", &[]);
    task.requires_idempotency = true;
    let graph = GraphDefinition {
        run_id: "idempotency-run".into(),
        tasks: vec![task.clone()],
    };
    assert!(graph.validate().is_err());
    task.idempotency_key = Some("stable-operation-1".into());
    assert!(
        GraphDefinition {
            run_id: "idempotency-run".into(),
            tasks: vec![task],
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn rejects_duplicate_idempotency_keys_and_invalid_input_schema() {
    let mut a = spec("a", &[]);
    let mut b = spec("b", &[]);
    a.idempotency_key = Some("same-operation".into());
    b.idempotency_key = Some("same-operation".into());
    assert!(
        GraphDefinition {
            run_id: "run-3".into(),
            tasks: vec![a, b]
        }
        .validate()
        .is_err()
    );
    let mut bad = spec("bad", &[]);
    bad.input = json!("not an object");
    bad.input_schema = ValueSchema::Object {
        required: BTreeMap::new(),
        allow_additional: false,
    };
    assert!(
        GraphDefinition {
            run_id: "run-4".into(),
            tasks: vec![bad]
        }
        .validate()
        .is_err()
    );
}

#[test]
fn independent_tasks_overlap_but_outputs_reduce_deterministically() {
    let definition = GraphDefinition {
        run_id: "parallel-run".into(),
        tasks: vec![spec("b", &[]), spec("a", &[])],
    };
    let barrier = Arc::new(Barrier::new(2));
    let mut handlers = HandlerRegistry::new();
    for id in ["a", "b"] {
        let barrier = Arc::clone(&barrier);
        handlers.insert(
            id.into(),
            handler(move |_| {
                barrier.wait();
                Ok(output(json!({"task": id}), id))
            }),
        );
    }
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["a"].state, TaskState::Succeeded);
    assert_eq!(report.tasks["b"].state, TaskState::Succeeded);
    assert_eq!(
        report.tasks["a"].output.as_ref().unwrap().value,
        json!({"task":"a"})
    );
    assert_eq!(
        report.tasks["b"].output.as_ref().unwrap().value,
        json!({"task":"b"})
    );
}

#[test]
fn synthetic_sequential_baseline_measures_graph_speedup() {
    let ids = ["a", "b", "c", "d"];
    let definition = GraphDefinition {
        run_id: "synthetic-benchmark".into(),
        tasks: ids.iter().map(|id| spec(id, &[])).collect(),
    };
    let mut handlers = HandlerRegistry::new();
    for id in ids {
        handlers.insert(
            id.into(),
            handler(move |_| {
                thread::sleep(Duration::from_millis(25));
                Ok(output(json!(true), id))
            }),
        );
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    let sequential_start = Instant::now();
    for id in ids {
        let context = TaskContext {
            task_id: id.into(),
            input: json!({}),
            dependency_outputs: BTreeMap::new(),
            attempt: 1,
            idempotency_key: None,
            deadline: Instant::now() + Duration::from_secs(1),
            cancelled: Arc::clone(&cancelled),
        };
        let handler = handlers.get(id).expect("benchmark handler");
        handler(context).expect("synthetic sequential task");
    }
    let sequential_ms = u64::try_from(sequential_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let graph_report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &cancelled)
        .unwrap();
    let comparison =
        ExecutionComparison::from_measured_sequential_baseline(sequential_ms, &graph_report);
    assert_eq!(comparison.task_count, ids.len());
    assert!(comparison.speedup_ratio_milli.is_some());
}

#[test]
fn dependent_task_receives_only_completed_dependency_output() {
    let definition = GraphDefinition {
        run_id: "dependency-run".into(),
        tasks: vec![spec("child", &["parent"]), spec("parent", &[])],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert("parent".into(), handler(|_| Ok(output(json!(7), "parent"))));
    handlers.insert(
        "child".into(),
        handler(|context| {
            let value = context.dependency_outputs["parent"]
                .value
                .as_i64()
                .unwrap_or_default();
            Ok(output(json!(value + 1), "child"))
        }),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(
        report.tasks["child"].output.as_ref().unwrap().value,
        json!(8)
    );
}

#[test]
fn malformed_output_is_a_failed_task_not_an_empty_success() {
    let mut task = spec("malformed", &[]);
    task.output_schema = ValueSchema::Boolean;
    let definition = GraphDefinition {
        run_id: "output-schema-run".into(),
        tasks: vec![task],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert(
        "malformed".into(),
        handler(|_| Ok(output(json!({}), "malformed"))),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["malformed"].state, TaskState::Failed);
    assert!(
        report.tasks["malformed"]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("output schema mismatch"))
    );
    assert!(report.tasks["malformed"].output.is_none());
}

#[test]
fn failed_dependency_blocks_descendants_without_hiding_the_failure() {
    let definition = GraphDefinition {
        run_id: "failure-run".into(),
        tasks: vec![spec("root", &[]), spec("child", &["root"])],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert(
        "root".into(),
        handler(|_| Err(TaskFailure::permanent("fixture failure"))),
    );
    handlers.insert(
        "child".into(),
        handler(|_| Ok(output(json!(true), "child"))),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["root"].state, TaskState::Failed);
    assert_eq!(report.tasks["child"].state, TaskState::Blocked);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("fixture failure"))
    );
}

#[test]
fn retries_are_bounded_and_counted() {
    let definition = GraphDefinition {
        run_id: "retry-run".into(),
        tasks: vec![{
            let mut value = spec("retry", &[]);
            value.max_retries = 2;
            value
        }],
    };
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    let attempts_for_handler = Arc::clone(&attempts);
    handlers.insert(
        "retry".into(),
        handler(move |_| {
            attempts_for_handler.fetch_add(1, Ordering::SeqCst);
            Err(TaskFailure::transient("retry me"))
        }),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert_eq!(report.tasks["retry"].attempts, 3);
    assert_eq!(report.tasks["retry"].state, TaskState::Failed);
}

#[test]
fn late_handler_is_recorded_as_timed_out() {
    let mut task = spec("slow", &[]);
    task.timeout_ms = 5;
    let definition = GraphDefinition {
        run_id: "timeout-run".into(),
        tasks: vec![task],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert(
        "slow".into(),
        handler(|_| {
            thread::sleep(Duration::from_millis(20));
            Ok(output(json!(true), "slow"))
        }),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["slow"].state, TaskState::TimedOut);
    assert!(
        report.tasks["slow"]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("deadline"))
    );
}

#[test]
fn pre_cancelled_run_does_not_dispatch_tasks() {
    let definition = GraphDefinition {
        run_id: "cancelled-run".into(),
        tasks: vec![spec("never-started", &[])],
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    let calls_for_handler = Arc::clone(&calls);
    handlers.insert(
        "never-started".into(),
        handler(move |_| {
            calls_for_handler.fetch_add(1, Ordering::SeqCst);
            Ok(output(json!(true), "never-started"))
        }),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(true)))
        .unwrap();
    assert_eq!(report.termination, Some(RunTermination::Cancelled));
    assert_eq!(report.tasks["never-started"].state, TaskState::Cancelled);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn resource_budget_exhaustion_is_explicit() {
    let mut task = spec("expensive", &[]);
    task.resource_units = 2;
    let definition = GraphDefinition {
        run_id: "resource-budget-run".into(),
        tasks: vec![task],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert(
        "expensive".into(),
        handler(|_| Ok(output(json!(true), "expensive"))),
    );
    let mut constrained = policy();
    constrained.max_total_resource_units = 1;
    let report = GraphExecutor::new(constrained)
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["expensive"].state, TaskState::Blocked);
    assert_eq!(report.termination, Some(RunTermination::ResourceLimit));
    assert_eq!(report.consumed_resource_units, 0);
}

#[test]
fn run_summary_accounts_for_results_and_retries() {
    let definition = GraphDefinition {
        run_id: "summary-run".into(),
        tasks: vec![{
            let mut value = spec("retry", &[]);
            value.max_retries = 1;
            value
        }],
    };
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    let attempts_for_handler = Arc::clone(&attempts);
    handlers.insert(
        "retry".into(),
        handler(move |_| {
            if attempts_for_handler.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(TaskFailure::transient("retry once"))
            } else {
                Ok(output(json!([]), "retry"))
            }
        }),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    let summary = report.summary();
    assert_eq!(summary.total_tasks, 1);
    assert_eq!(summary.succeeded, 1);
    assert_eq!(summary.retry_attempts, 1);
    assert_eq!(summary.evidence_references, 0);
    assert_eq!(summary.consumed_resource_units, 1);
}

#[test]
fn empty_success_is_not_confused_with_failure() {
    let definition = GraphDefinition {
        run_id: "empty-run".into(),
        tasks: vec![spec("empty", &[])],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert("empty".into(), handler(|_| Ok(output(json!([]), "empty"))));
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["empty"].state, TaskState::Succeeded);
    assert_eq!(
        report.tasks["empty"].output.as_ref().unwrap().value,
        json!([])
    );
}

#[test]
fn verified_claim_requires_distinct_reviewer_and_linked_evidence() {
    let mut value = output(json!({"claim":"x"}), "producer");
    value.verification.state = VerificationState::Verified;
    value.verification.reviewer_id = "producer".into();
    let mut verifier = spec("reviewer", &["producer"]);
    verifier.role = TaskRole::Verifier;
    assert!(validate_output(&verifier, &value, 1024).is_err());
    value.verification.reviewer_id = "reviewer".into();
    value.evidence.push(EvidenceReference {
        id: "ev-1".into(),
        source_id: "public-source".into(),
        locator: "https://example.invalid/evidence".into(),
        provenance: "captured fixture".into(),
        observed_at_unix: 1,
        content_sha256: None,
    });
    value.verification.evidence_refs = vec!["ev-1".into()];
    assert!(validate_output(&verifier, &value, 1024).is_ok());
}

#[test]
fn exclusive_resource_serializes_conflicting_tasks() {
    let mut a = spec("a", &[]);
    let mut b = spec("b", &[]);
    a.exclusive_resources = vec!["shared-store".into()];
    b.exclusive_resources = vec!["shared-store".into()];
    let definition = GraphDefinition {
        run_id: "resource-run".into(),
        tasks: vec![a, b],
    };
    let inside = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let lock = Arc::new(Mutex::new(()));
    let mut handlers = HandlerRegistry::new();
    for id in ["a", "b"] {
        let inside = Arc::clone(&inside);
        let peak = Arc::clone(&peak);
        let lock = Arc::clone(&lock);
        handlers.insert(
            id.into(),
            handler(move |_| {
                let _guard = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let current = inside.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(10));
                inside.fetch_sub(1, Ordering::SeqCst);
                Ok(output(json!(true), id))
            }),
        );
    }
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["a"].state, TaskState::Succeeded);
    assert_eq!(report.tasks["b"].state, TaskState::Succeeded);
    assert_eq!(peak.load(Ordering::SeqCst), 1);
}

#[test]
fn rate_limit_group_spaces_task_start_times() {
    let mut first = spec("first", &[]);
    let mut second = spec("second", &[]);
    let limit = RateLimit {
        key: "public-provider".into(),
        min_interval_ms: 40,
    };
    first.rate_limit = Some(limit.clone());
    second.rate_limit = Some(limit);
    let definition = GraphDefinition {
        run_id: "rate-limit-run".into(),
        tasks: vec![first, second],
    };
    let starts = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let mut handlers = HandlerRegistry::new();
    for id in ["first", "second"] {
        let observed_starts = Arc::clone(&starts);
        handlers.insert(
            id.into(),
            handler(move |context| {
                observed_starts
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(admitted_plus_timeout(&context));
                Ok(output(json!(true), id))
            }),
        );
    }
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.tasks["first"].state, TaskState::Succeeded);
    assert_eq!(report.tasks["second"].state, TaskState::Succeeded);
    let observed = starts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(observed.len(), 2);
    assert!(observed[1].duration_since(observed[0]) >= Duration::from_millis(40));
}

#[test]
fn checkpoint_sink_saves_wave_state_for_safe_resume() {
    let definition = GraphDefinition {
        run_id: "checkpoint-wave-run".into(),
        tasks: vec![spec("child", &["parent"]), spec("parent", &[])],
    };
    let parent_calls = Arc::new(AtomicUsize::new(0));
    let child_calls = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    let parent_counter = Arc::clone(&parent_calls);
    handlers.insert(
        "parent".into(),
        handler(move |_| {
            parent_counter.fetch_add(1, Ordering::SeqCst);
            Ok(output(json!("parent-result"), "parent"))
        }),
    );
    let child_counter = Arc::clone(&child_calls);
    handlers.insert(
        "child".into(),
        handler(move |_| {
            child_counter.fetch_add(1, Ordering::SeqCst);
            Ok(output(json!("child-result"), "child"))
        }),
    );
    let checkpoints = Arc::new(Mutex::new(Vec::<ExecutionCheckpoint>::new()));
    let sink_records = Arc::clone(&checkpoints);
    let sink_calls = Arc::new(AtomicUsize::new(0));
    let sink_calls_for_callback = Arc::clone(&sink_calls);
    let executor = GraphExecutor::new(policy());
    let first = executor
        .execute_checkpointed(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            move |checkpoint| {
                sink_records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(checkpoint.clone());
                if sink_calls_for_callback.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err("simulate checkpoint sink interruption".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
    assert_eq!(first.tasks["parent"].state, TaskState::Succeeded);
    assert_eq!(first.tasks["child"].state, TaskState::Blocked);
    assert_eq!(first.termination, Some(RunTermination::Failed));
    let saved = checkpoints
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let partial = saved
        .iter()
        .find(|checkpoint| {
            checkpoint.report.tasks["parent"].state == TaskState::Succeeded
                && checkpoint.report.tasks["child"].state == TaskState::Pending
        })
        .cloned()
        .expect("checkpoint after parent wave");
    let resumed = executor
        .resume_checkpointed(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            partial,
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(resumed.tasks["child"].state, TaskState::Succeeded);
    assert_eq!(parent_calls.load(Ordering::SeqCst), 1);
    assert_eq!(child_calls.load(Ordering::SeqCst), 1);
    assert!(saved.len() >= 2);
}

#[test]
fn resume_rejects_successful_child_with_failed_dependency_in_checkpoint() {
    let definition = GraphDefinition {
        run_id: "tampered-checkpoint-run".into(),
        tasks: vec![spec("child", &["parent"]), spec("parent", &[])],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert(
        "parent".into(),
        handler(|_| Ok(output(json!("parent"), "parent"))),
    );
    handlers.insert(
        "child".into(),
        handler(|_| Ok(output(json!("child"), "child"))),
    );
    let executor = GraphExecutor::new(policy());
    let report = executor
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    let mut checkpoint = ExecutionCheckpoint::from_report(report);
    let parent = checkpoint.report.tasks.get_mut("parent").unwrap();
    parent.state = TaskState::Failed;
    parent.output = None;
    parent.error = Some("simulated persisted failure".into());
    checkpoint.report.termination = Some(RunTermination::Failed);

    assert!(matches!(
        executor.resume(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            checkpoint,
        ),
        Err(GraphError::CheckpointMismatch)
    ));
}

#[test]
fn checkpoint_round_trip_and_resume_preserve_success() {
    let definition = GraphDefinition {
        run_id: "checkpoint-run".into(),
        tasks: vec![spec("done", &[]), spec("later", &[])],
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    for id in ["done", "later"] {
        let calls = Arc::clone(&calls);
        handlers.insert(
            id.into(),
            handler(move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(output(json!(id), id))
            }),
        );
    }
    let executor = GraphExecutor::new(policy());
    let first = executor
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    let checkpoint = ExecutionCheckpoint::from_report(first.clone());
    let bytes = checkpoint.encode().unwrap();
    let decoded = ExecutionCheckpoint::decode(&bytes).unwrap();
    let resumed = executor
        .resume(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            decoded,
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(resumed.tasks["done"].state, TaskState::Succeeded);
    assert_eq!(resumed.tasks["later"].state, TaskState::Succeeded);
}
#[test]
fn task_declaration_order_has_stable_fingerprint_and_resume() {
    let ordered = GraphDefinition {
        run_id: "canonical-order".into(),
        tasks: vec![spec("a", &[]), spec("b", &["a"])],
    };
    let reversed = GraphDefinition {
        run_id: "canonical-order".into(),
        tasks: vec![spec("b", &["a"]), spec("a", &[])],
    };
    let fingerprint = ordered.validate().unwrap().fingerprint;
    assert_eq!(fingerprint, reversed.validate().unwrap().fingerprint);
    let mut handlers = HandlerRegistry::new();
    handlers.insert("a".into(), handler(|_| Ok(output(json!(1), "a"))));
    handlers.insert("b".into(), handler(|_| Ok(output(json!(2), "b"))));
    let executor = GraphExecutor::new(policy());
    let original = executor
        .execute(&reversed, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    let resumed = executor
        .resume(
            &ordered,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            ExecutionCheckpoint::from_report(original),
        )
        .unwrap();
    assert_eq!(resumed.graph_fingerprint, fingerprint);
    assert_eq!(resumed.summary().succeeded, 2);
}

#[test]
fn legacy_ordered_checkpoint_can_resume_with_canonical_fingerprint() {
    let definition = GraphDefinition {
        run_id: "legacy-order".into(),
        tasks: vec![spec("b", &[]), spec("a", &[])],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert("a".into(), handler(|_| Ok(output(json!(1), "a"))));
    handlers.insert("b".into(), handler(|_| Ok(output(json!(2), "b"))));
    let executor = GraphExecutor::new(policy());
    let report = executor
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    let mut legacy = ExecutionCheckpoint::from_report(report);
    let old_hash = crate::sha256::hex32(&crate::sha256::sha256(
        &serde_json::to_vec(&definition).unwrap(),
    ));
    assert_ne!(legacy.graph_fingerprint, old_hash);
    legacy.graph_fingerprint = old_hash.clone();
    legacy.report.graph_fingerprint = old_hash;
    let resumed = executor
        .resume(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            legacy,
        )
        .unwrap();
    assert_eq!(resumed.summary().succeeded, 2);
    assert_eq!(
        resumed.graph_fingerprint,
        definition.validate().unwrap().fingerprint
    );
}

#[test]
fn checkpoint_resume_retains_provider_rate_limit_and_rejects_unknown_groups() {
    let limit = RateLimit {
        key: "checkpoint-provider".into(),
        min_interval_ms: 220,
    };
    let mut first = spec("first", &[]);
    first.rate_limit = Some(limit.clone());
    let mut second = spec("second", &["first"]);
    second.rate_limit = Some(limit);
    let definition = GraphDefinition {
        run_id: "checkpoint-provider-spacing".into(),
        tasks: vec![first, second],
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    let first_calls = Arc::clone(&calls);
    handlers.insert(
        "first".into(),
        handler(move |_| {
            first_calls.fetch_add(1, Ordering::SeqCst);
            Ok(output(json!("first"), "first"))
        }),
    );
    let second_calls = Arc::clone(&calls);
    handlers.insert(
        "second".into(),
        handler(move |_| {
            second_calls.fetch_add(1, Ordering::SeqCst);
            Ok(output(json!("second"), "second"))
        }),
    );
    let captured = Arc::new(Mutex::new(None::<ExecutionCheckpoint>));
    let to_capture = Arc::clone(&captured);
    let executor = GraphExecutor::new(policy());
    let interrupted = executor
        .execute_checkpointed(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            move |checkpoint| {
                let mut slot = to_capture.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(checkpoint.clone());
                }
                Err("deliberately pause after the first wave".into())
            },
        )
        .unwrap();
    assert_eq!(interrupted.tasks["first"].state, TaskState::Succeeded);
    assert_eq!(interrupted.tasks["second"].state, TaskState::Blocked);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let checkpoint = captured.lock().unwrap().clone().unwrap();
    assert_eq!(checkpoint.report.tasks["second"].state, TaskState::Pending);
    assert!(
        checkpoint
            .report
            .rate_limit_last_start_unix_ms
            .contains_key("checkpoint-provider")
    );
    let mut checkpoint = ExecutionCheckpoint::decode(&checkpoint.encode().unwrap()).unwrap();

    let mut invalid = checkpoint.clone();
    invalid
        .report
        .rate_limit_last_start_unix_ms
        .insert("unknown-provider".into(), clock::unix_now_millis());
    assert!(matches!(
        executor.resume(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            invalid
        ),
        Err(GraphError::CheckpointMismatch)
    ));

    // Make the persisted start recent, independent of the CI runner's setup delays. The clock
    // starts first, so a stall before the start is planted only lengthens what it measures.
    let resumed_at = Instant::now();
    checkpoint
        .report
        .rate_limit_last_start_unix_ms
        .insert("checkpoint-provider".into(), clock::unix_now_millis());
    let resumed = executor
        .resume(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            checkpoint,
        )
        .unwrap();
    assert!(
        resumed_at.elapsed() >= Duration::from_millis(150),
        "resuming a recent provider start bypassed the persisted rate limit"
    );
    assert_eq!(resumed.summary().succeeded, 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(resumed.tasks["first"].attempts, 1);
    assert_eq!(resumed.tasks["second"].attempts, 1);
}

#[test]
fn legacy_checkpoint_recovers_latest_provider_completion() {
    let limit = RateLimit {
        key: "legacy-provider".into(),
        min_interval_ms: 250,
    };
    let mut first = spec("a", &[]);
    first.rate_limit = Some(limit.clone());
    let mut second = spec("b", &["a"]);
    second.rate_limit = Some(limit);
    let graph = GraphDefinition {
        run_id: "legacy-provider-history".into(),
        tasks: vec![first, second],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert("a".into(), handler(|_| Ok(output(json!(1), "a"))));
    handlers.insert("b".into(), handler(|_| Ok(output(json!(2), "b"))));
    let saved = Arc::new(Mutex::new(None::<ExecutionCheckpoint>));
    let recorder = Arc::clone(&saved);
    let executor = GraphExecutor::new(policy());
    let _ = executor
        .execute_checkpointed(
            &graph,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            move |checkpoint| {
                let mut slot = recorder.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(checkpoint.clone());
                }
                Err("interrupted before dependent lookup".into())
            },
        )
        .unwrap();
    let checkpoint = saved.lock().unwrap().clone().unwrap();
    let mut serialized = serde_json::to_value(checkpoint).unwrap();
    serialized["report"]
        .as_object_mut()
        .unwrap()
        .remove("rate_limit_last_start_unix_ms");
    let mut legacy: ExecutionCheckpoint = serde_json::from_value(serialized).unwrap();
    // A legacy checkpoint dates the provider call by its task's finish second. Date it now,
    // after the clock starts, so setup time since the real call cannot shorten the wait.
    let resumed_at = Instant::now();
    legacy
        .report
        .tasks
        .get_mut("a")
        .expect("the first wave recorded its task")
        .finished_at_unix = Some(clock::unix_now());
    let result = executor
        .resume(&graph, &handlers, &Arc::new(AtomicBool::new(false)), legacy)
        .unwrap();
    assert_eq!(result.summary().succeeded, 2);
    assert!(
        resumed_at.elapsed() >= Duration::from_millis(150),
        "legacy checkpoints must not bypass a recently completed provider call"
    );
    assert!(
        result
            .rate_limit_last_start_unix_ms
            .contains_key("legacy-provider")
    );
}

#[test]
fn cancellation_during_running_handler_preserves_its_completed_output() {
    let definition = GraphDefinition {
        run_id: "cancel-running-retain-output".into(),
        tasks: vec![spec("running", &[])],
    };
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let mut handlers = HandlerRegistry::new();
    let receiver = Mutex::new(release_rx);
    handlers.insert(
        "running".into(),
        handler(move |_| {
            started_tx.send(()).unwrap();
            receiver.lock().unwrap().recv().unwrap();
            Ok(output(json!("retained"), "running"))
        }),
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancelled);
    let stopper = thread::spawn(move || {
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        flag.store(true, Ordering::Release);
        release_tx.send(()).unwrap();
    });
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &cancelled)
        .unwrap();
    stopper.join().unwrap();
    assert_eq!(report.tasks["running"].state, TaskState::Succeeded);
    assert_eq!(
        report.tasks["running"].output.as_ref().unwrap().value,
        json!("retained")
    );
}

#[test]
fn cancellation_interrupts_provider_rate_wait_without_dispatching_next_task() {
    let limit = RateLimit {
        key: "interruptible-provider".into(),
        min_interval_ms: 1_500,
    };
    let mut first = spec("a", &[]);
    first.rate_limit = Some(limit.clone());
    let mut second = spec("b", &[]);
    second.rate_limit = Some(limit);
    let graph = GraphDefinition {
        run_id: "provider-cancel-wait".into(),
        tasks: vec![first, second],
    };
    let first_called = Arc::new(AtomicBool::new(false));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    let signal = Arc::clone(&first_called);
    handlers.insert(
        "a".into(),
        handler(move |_| {
            signal.store(true, Ordering::Release);
            Ok(output(json!(true), "a"))
        }),
    );
    let second_observed = Arc::clone(&second_calls);
    handlers.insert(
        "b".into(),
        handler(move |_| {
            second_observed.fetch_add(1, Ordering::SeqCst);
            Ok(output(json!(true), "b"))
        }),
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_flag = Arc::clone(&cancelled);
    let observed_first = Arc::clone(&first_called);
    let stopper = thread::spawn(move || {
        while !observed_first.load(Ordering::Acquire) {
            thread::yield_now();
        }
        thread::sleep(Duration::from_millis(100));
        cancel_flag.store(true, Ordering::Release);
    });
    let started = Instant::now();
    let report = GraphExecutor::new(policy())
        .execute(&graph, &handlers, &cancelled)
        .unwrap();
    stopper.join().unwrap();
    assert_eq!(report.tasks["a"].state, TaskState::Succeeded);
    assert_eq!(report.tasks["b"].state, TaskState::Cancelled);
    assert_eq!(report.termination, Some(RunTermination::Cancelled));
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "cancellation was delayed by the provider rate-limit wait"
    );
}

#[test]
fn provider_rate_limit_applies_to_each_retry_and_next_task() {
    let limit = RateLimit {
        key: "provider-retries".into(),
        min_interval_ms: 65,
    };
    let mut first = spec("a", &[]);
    first.max_retries = 1;
    first.rate_limit = Some(limit.clone());
    let mut second = spec("b", &[]);
    second.rate_limit = Some(limit);
    let definition = GraphDefinition {
        run_id: "provider-retry-starts".into(),
        tasks: vec![first, second],
    };
    let observed = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handlers = HandlerRegistry::new();
    let first_observed = Arc::clone(&observed);
    let first_calls = Arc::clone(&calls);
    handlers.insert(
        "a".into(),
        handler(move |context| {
            first_observed
                .lock()
                .unwrap()
                .push(admitted_plus_timeout(&context));
            if first_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(TaskFailure::transient("retry"))
            } else {
                Ok(output(json!(true), "a"))
            }
        }),
    );
    let second_observed = Arc::clone(&observed);
    handlers.insert(
        "b".into(),
        handler(move |context| {
            second_observed
                .lock()
                .unwrap()
                .push(admitted_plus_timeout(&context));
            Ok(output(json!(true), "b"))
        }),
    );
    let report = GraphExecutor::new(policy())
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(report.summary().succeeded, 2);
    assert_eq!(report.tasks["a"].attempts, 2);
    let starts = observed.lock().unwrap();
    assert_eq!(starts.len(), 3);
    for window in starts.windows(2) {
        assert!(window[1].duration_since(window[0]) >= Duration::from_millis(65));
    }
}
#[test]
fn verified_claim_requires_evidence_from_its_producer() {
    let mut reviewer = spec("reviewer", &["producer"]);
    reviewer.role = TaskRole::Verifier;
    let definition = GraphDefinition {
        run_id: "lineage-review".into(),
        tasks: vec![spec("producer", &[]), reviewer],
    };
    let producer_evidence = EvidenceReference {
        id: "producer-source".into(),
        source_id: "fixture".into(),
        locator: "https://example.invalid/original".into(),
        provenance: "captured for test".into(),
        observed_at_unix: 1,
        content_sha256: None,
    };
    let mut handlers = HandlerRegistry::new();
    let original = producer_evidence.clone();
    handlers.insert(
        "producer".into(),
        handler(move |_| {
            let mut result = output(json!({"claim":"x"}), "producer");
            result.evidence.push(original.clone());
            Ok(result)
        }),
    );
    let forged = producer_evidence.clone();
    handlers.insert(
        "reviewer".into(),
        handler(move |_| {
            let mut result = output(json!({"claim":"x"}), "producer");
            result.verification.state = VerificationState::Verified;
            result.verification.reviewer_id = "reviewer".into();
            let mut different = forged.clone();
            different.locator = "https://example.invalid/unrelated".into();
            result.evidence.push(different);
            result
                .verification
                .evidence_refs
                .push("producer-source".into());
            Ok(result)
        }),
    );
    let executor = GraphExecutor::new(policy());
    let rejected = executor
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(rejected.tasks["producer"].state, TaskState::Succeeded);
    assert_eq!(rejected.tasks["reviewer"].state, TaskState::Failed);
    assert!(
        rejected.tasks["reviewer"]
            .error
            .as_deref()
            .unwrap()
            .contains("matching producer evidence")
    );

    let verified_evidence = producer_evidence.clone();
    handlers.insert(
        "reviewer".into(),
        handler(move |_| {
            let mut result = output(json!({"claim":"x"}), "producer");
            result.verification.state = VerificationState::Verified;
            result.verification.reviewer_id = "reviewer".into();
            result.evidence.push(verified_evidence.clone());
            result
                .verification
                .evidence_refs
                .push("producer-source".into());
            Ok(result)
        }),
    );
    let accepted = executor
        .execute(&definition, &handlers, &Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(accepted.tasks["reviewer"].state, TaskState::Succeeded);
    assert_eq!(accepted.summary().verified_results, 1);
    let mut forged_checkpoint = ExecutionCheckpoint::from_report(accepted);
    let result = forged_checkpoint
        .report
        .tasks
        .get_mut("reviewer")
        .unwrap()
        .output
        .as_mut()
        .unwrap();
    result.evidence[0].locator = "https://example.invalid/unrelated".into();
    assert!(matches!(
        executor.resume(
            &definition,
            &handlers,
            &Arc::new(AtomicBool::new(false)),
            forged_checkpoint,
        ),
        Err(GraphError::CheckpointMismatch)
    ));
}

#[test]
fn overflowing_resource_totals_never_dispatch_over_budget_tasks() {
    for concurrency in [1, 2, 4] {
        for costs in [
            vec![u64::MAX, 1],
            vec![u64::MAX - 1, 1, 1],
            vec![u64::MAX - 1, 2],
            vec![u64::MAX / 2 + 1, u64::MAX / 2 + 1],
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let tasks: Vec<_> = costs
                .iter()
                .enumerate()
                .map(|(index, &cost)| {
                    let mut task = spec(&format!("task-{index}"), &[]);
                    task.resource_units = cost;
                    task
                })
                .collect();
            let mut handlers = HandlerRegistry::new();
            for task in &tasks {
                let calls = Arc::clone(&calls);
                handlers.insert(
                    task.id.clone(),
                    handler(move |context| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(output(json!(true), &context.task_id))
                    }),
                );
            }
            let expected = if costs.len() == 3 { 2 } else { 1 };
            let graph = GraphDefinition {
                run_id: "overflowing-resource-total".into(),
                tasks,
            };
            let report = GraphExecutor::new(ExecutionPolicy {
                max_concurrency: concurrency,
                max_total_resource_units: u64::MAX,
                ..policy()
            })
            .execute(&graph, &handlers, &Arc::new(AtomicBool::new(false)))
            .unwrap();

            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected,
                "over-budget dispatch: concurrency={concurrency}, costs={costs:?}"
            );
            assert_eq!(report.summary().succeeded, expected);
            assert_eq!(report.summary().blocked, costs.len() - expected);
            assert_eq!(report.termination, Some(RunTermination::ResourceLimit));
            let admitted: u128 = report
                .tasks
                .iter()
                .filter(|(_, record)| record.attempts > 0)
                .map(|(id, _)| {
                    let task = graph.tasks.iter().find(|task| &task.id == id).unwrap();
                    u128::from(task.resource_units)
                })
                .sum();
            assert!(admitted <= u128::from(u64::MAX));
            assert_eq!(u128::from(report.consumed_resource_units), admitted);
        }
    }
}

fn permanent_failure_after_transient_is_not_resumed(panics: bool) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut task = spec("lookup", &[]);
    task.max_retries = 2;
    task.output_schema = ValueSchema::Number;
    let definition = GraphDefinition {
        run_id: "permanent-after-transient".into(),
        tasks: vec![task],
    };
    let mut handlers = HandlerRegistry::new();
    let observed_calls = Arc::clone(&calls);
    handlers.insert(
        "lookup".into(),
        handler(
            move |context| match observed_calls.fetch_add(1, Ordering::SeqCst) {
                0 => Err(TaskFailure::transient("temporary transport error")),
                1 if panics => panic!("permanent handler panic"),
                1 => Ok(output(json!("not a number"), &context.task_id)),
                _ => Ok(output(json!(3), &context.task_id)),
            },
        ),
    );
    let executor = GraphExecutor::new(policy());
    let cancelled = Arc::new(AtomicBool::new(false));
    let report = executor
        .execute(&definition, &handlers, &cancelled)
        .unwrap();
    let resumed = executor
        .resume(
            &definition,
            &handlers,
            &cancelled,
            ExecutionCheckpoint::from_report(report.clone()),
        )
        .unwrap();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a permanent failure must not inherit retry permission"
    );
    assert_eq!(report.tasks["lookup"].state, TaskState::Failed);
    assert_eq!(report.tasks["lookup"].attempts, 2);
    assert!(!report.tasks["lookup"].retryable);
    assert_eq!(resumed.tasks, report.tasks);
    assert_eq!(resumed.termination, Some(RunTermination::Failed));
    assert_eq!(
        resumed.consumed_resource_units,
        report.consumed_resource_units
    );
}

#[test]
fn panic_after_transient_failure_is_not_resumed() {
    permanent_failure_after_transient_is_not_resumed(true);
}

#[test]
fn malformed_output_after_transient_failure_is_not_resumed() {
    permanent_failure_after_transient_is_not_resumed(false);
}

fn saved_parent_wave(
    parent_cost: u64,
    budget: u64,
    child_calls: &Arc<AtomicUsize>,
) -> (GraphDefinition, HandlerRegistry, ExecutionCheckpoint) {
    let mut parent = spec("parent", &[]);
    parent.resource_units = parent_cost;
    let definition = GraphDefinition {
        run_id: "checkpoint-resource-accounting".into(),
        tasks: vec![parent, spec("child", &["parent"])],
    };
    let mut handlers = HandlerRegistry::new();
    handlers.insert(
        "parent".into(),
        handler(|_| Ok(output(json!(true), "parent"))),
    );
    let observed_calls = Arc::clone(child_calls);
    handlers.insert(
        "child".into(),
        handler(move |_| {
            observed_calls.fetch_add(1, Ordering::SeqCst);
            Ok(output(json!(true), "child"))
        }),
    );
    let snapshots = Mutex::new(Vec::new());
    GraphExecutor::new(ExecutionPolicy {
        max_total_resource_units: budget,
        ..policy()
    })
    .execute_checkpointed(
        &definition,
        &handlers,
        &Arc::new(AtomicBool::new(false)),
        |checkpoint| {
            snapshots.lock().unwrap().push(checkpoint.clone());
            Ok(())
        },
    )
    .unwrap();
    let saved = snapshots
        .into_inner()
        .unwrap()
        .into_iter()
        .find(|checkpoint| {
            checkpoint.report.tasks["parent"].state == TaskState::Succeeded
                && checkpoint.report.tasks["child"].state == TaskState::Pending
        })
        .expect("checkpoint after the parent wave");
    assert_eq!(saved.report.consumed_resource_units, parent_cost);
    (definition, handlers, saved)
}

#[test]
fn checkpoint_cannot_understate_spent_resources_to_dispatch_extra_work() {
    let child_calls = Arc::new(AtomicUsize::new(0));
    let (definition, handlers, mut saved) = saved_parent_wave(1, 1, &child_calls);
    let executor = GraphExecutor::new(ExecutionPolicy {
        max_total_resource_units: 1,
        ..policy()
    });
    let cancelled = Arc::new(AtomicBool::new(false));
    let valid = executor
        .resume(&definition, &handlers, &cancelled, saved.clone())
        .unwrap();
    assert_eq!(valid.tasks["child"].state, TaskState::Blocked);
    assert_eq!(valid.termination, Some(RunTermination::ResourceLimit));
    assert_eq!(child_calls.load(Ordering::SeqCst), 0);

    saved.report.consumed_resource_units = 0;
    let result = executor.resume(&definition, &handlers, &cancelled, saved);
    assert_eq!(
        child_calls.load(Ordering::SeqCst),
        0,
        "an understated checkpoint must fail before dispatch"
    );
    assert!(matches!(result, Err(GraphError::CheckpointMismatch)));
}

#[test]
fn checkpoint_rejects_overflowing_minimum_attempted_resource_cost() {
    let child_calls = Arc::new(AtomicUsize::new(0));
    let (definition, handlers, mut saved) = saved_parent_wave(u64::MAX, u64::MAX, &child_calls);
    let child = saved.report.tasks.get_mut("child").unwrap();
    child.state = TaskState::Failed;
    child.attempts = 1;
    child.error = Some("recorded attempt".into());

    let result = GraphExecutor::new(ExecutionPolicy {
        max_total_resource_units: u64::MAX,
        ..policy()
    })
    .resume(
        &definition,
        &handlers,
        &Arc::new(AtomicBool::new(false)),
        saved,
    );

    assert!(matches!(result, Err(GraphError::CheckpointMismatch)));
    assert_eq!(child_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn checkpoint_preserves_conservative_extra_resource_reservations() {
    let child_calls = Arc::new(AtomicUsize::new(0));
    let (definition, handlers, mut saved) = saved_parent_wave(1, 2, &child_calls);
    let calls_before_resume = child_calls.load(Ordering::SeqCst);
    saved.report.consumed_resource_units = 2;

    let report = GraphExecutor::new(ExecutionPolicy {
        max_total_resource_units: 2,
        ..policy()
    })
    .resume(
        &definition,
        &handlers,
        &Arc::new(AtomicBool::new(false)),
        saved,
    )
    .unwrap();

    assert_eq!(report.consumed_resource_units, 2);
    assert_eq!(report.tasks["child"].state, TaskState::Blocked);
    assert_eq!(child_calls.load(Ordering::SeqCst), calls_before_resume);
}
