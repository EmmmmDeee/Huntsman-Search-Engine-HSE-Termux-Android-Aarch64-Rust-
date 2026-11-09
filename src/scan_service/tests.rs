use super::*;
use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
use crate::source_outcome::SourceOutcomeKind;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn failed_scan_log_write_remains_observable_after_successful_status_update() {
    let (service, dir) = with_lookup(
        "log-persistence-error",
        Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
    );
    let (record, _) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();

    // A directory at the log path fails writes regardless of runner privileges.
    // The scan row is still writable, so subsequent status updates must not
    // conceal the earlier evidence-persistence failure.
    let log = dir.join(&record.id).join("log.jsonl");
    if log.is_file() {
        std::fs::remove_file(&log).unwrap();
    }
    std::fs::create_dir(&log).unwrap();
    // stop() owns the state lock while logging; a failed append must not
    // acquire that same mutex a second time and deadlock.
    let state = service.state();
    service.log(&record.id, "test", LogLevel::Info, "must be retained");
    drop(state);
    // Scan detail readers must not expose an apparently healthy row after
    // the underlying log evidence write was lost.
    assert!(matches!(
        service.record(&record.id),
        Err(ServiceError::Store(message)) if message.contains("unable to persist log entry")
    ));
    let error = service.wait(&record.id, Instant::now()).unwrap_err();
    assert!(
        matches!(error, ServiceError::Store(message) if message.contains("unable to persist log entry"))
    );
    service
        .set_status(
            &record.id,
            ScanStatus::ErrorFailed,
            Some(clock::unix_now_millis()),
        )
        .unwrap();
    assert!(service.log_failure(&record.id).is_some());

    // Restoring the path does not retroactively recover the missing entry.
    std::fs::remove_dir(&log).unwrap();
    assert!(service.wait(&record.id, Instant::now()).is_err());
    service.delete(&record.id).unwrap();
    assert!(service.log_failure(&record.id).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_checkpoint_retries_identical_progress_after_storage_recovers() {
    let (service, dir) = with_lookup(
        "checkpoint-retry",
        Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
    );
    let (record, scan_plan) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let options = record.options.clone();
    let selection = chosen(&options).unwrap();
    let mut collector = ScanCollector::new(&service, &record.id, &scan_plan, &options, &selection);

    let entities = vec![
        Entity::builder(EntityKind::IpAddress, "8.8.8.8", 0.95, "test")
            .evidence(Evidence::new(
                EvidenceProvenance::for_scan("checkpoint-test", "scan"),
                "observed address",
            ))
            .build(),
    ];
    let outcomes = vec![SourceExecutionOutcome::success("checkpoint-test", 1, 1)];
    let progress = CrawlProgress {
        entities: &entities,
        edges: &[],
        outcomes: &outcomes,
        generation: 0,
        dispatches: 1,
    };

    // A directory at the destination prevents the atomic rename, even
    // when tests run as root. Restoring the path makes the next save work.
    let blocker = dir.join(&record.id).join("results.json");
    std::fs::create_dir(&blocker).unwrap();
    collector.progressed(&progress);
    assert_eq!(
        collector.checkpointed,
        (0, 0),
        "a failed result write must never be counted as durable"
    );
    std::fs::remove_dir(&blocker).unwrap();
    assert!(service.store().results(&record.id).unwrap().is_none());

    // The exact same wave must retry without requiring an extra lookup.
    collector.progressed(&progress);
    assert_eq!(collector.checkpointed, (1, 1));
    let saved = service.store().results(&record.id).unwrap().unwrap();
    assert_eq!(saved.entities.len(), 1);
    assert_eq!(saved.outcomes.len(), 1);
    assert_eq!(saved.outcomes[0].module, "checkpoint-test");
    assert_eq!(
        service.store().get(&record.id).unwrap().modules_run,
        ["checkpoint-test"]
    );
    let logs = service.store().log(&record.id).unwrap();
    assert!(
        logs.iter().any(|entry| entry
            .message
            .contains("could not save what the scan has found")),
        "the transient failure must also be observable"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explicit_ssid_is_exact_through_saved_scan_planning_and_persistence() {
    let original = "ssid: Cafe Guest ";
    let scan_plan = plan(original, Some("network")).expect("network scan plan");
    assert_eq!(scan_plan.kind, ScanKind::Network);
    assert_eq!(scan_plan.target, original);
    assert_eq!(
        plan(" Cafe Guest ", Some("network"))
            .expect("legacy bare network name")
            .target,
        "Cafe Guest"
    );

    let (service, dir) = with_lookup(
        "exact-ssid-persistence",
        Arc::new(|_, _, _| Ok(LookupOutput::default())),
    );
    let (record, planned) = service
        .create(&ScanRequest {
            target: original.into(),
            kind: Some("network".into()),
            ..ScanRequest::default()
        })
        .expect("create exact-name network scan");
    assert_eq!(planned.target, original);
    assert_eq!(record.target, original);
    assert_eq!(record.name, original);
    assert_eq!(service.store().get(&record.id).unwrap().target, original);
    assert_eq!(service.rerun_request(&record.id).unwrap().target, original);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn full_scan_store_is_a_conflict_not_a_bad_request() {
    let error = ServiceError::from(StoreError::Capacity(crate::scan_store::MAX_SCANS));
    assert_eq!(error.status(), 409);
    assert!(matches!(error, ServiceError::Conflict(_)));
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hse-scan-service-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A report kept from outside the lookups is a `FINISHED` scan of its target: its row, log,
/// elements (the target carrying the report's fields as raw evidence, its findings as children)
/// and module list are a scan's, every entity names the scan, and running it again is refused
/// because nothing can run it.
#[test]
fn a_kept_report_is_a_finished_scan_that_cannot_be_rerun() {
    let (service, dir) = with_lookup("kept", Arc::new(|_, _, _| Err("no lookup".into())));
    let provenance = || EvidenceProvenance::new("exif");
    let document = Entity::builder(EntityKind::Document, "holiday.jpg", 0.9, "exif")
        .evidence(
            Evidence::new(provenance(), "holiday.jpg with 2 fields")
                .with_attr("Make", "Fixture")
                .with_attr("file_sha256", "ab"),
        )
        .build();
    let position = Entity::builder(EntityKind::Coordinates, "48.850000,2.333333", 0.9, "exif")
        .evidence(Evidence::new(provenance(), "GPS position"))
        .build();
    let found = LookupOutput {
        text: "holiday.jpg: 2 entities\n".into(),
        entities: vec![document, position],
        outcomes: vec![
            SourceExecutionOutcome::success("exif", 1, 2),
            SourceExecutionOutcome::failed(
                "docmeta",
                1,
                SourceOutcomeKind::ParserDrift,
                None,
                "not a PDF",
            ),
        ],
    };
    let record = service
        .keep("holiday.jpg", "HSE_DOCUMENT", INSPECT_KIND, found)
        .unwrap();
    assert_eq!(
        (
            record.status,
            record.target.as_str(),
            record.target_type.as_str(),
            record.kind.as_str(),
            record.name.as_str()
        ),
        (
            ScanStatus::Finished,
            "holiday.jpg",
            "HSE_DOCUMENT",
            "inspect",
            "holiday.jpg"
        )
    );
    assert!(
        record.started.is_some() && record.ended >= record.started,
        "{record:?}"
    );
    assert_eq!(record.errors, 1, "{record:?}");
    assert_eq!(record.modules_run, ["docmeta", "exif"]);
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert_eq!(record.elements, results.elements.len() - 1, "{record:?}");
    assert_eq!(results.termination, Some(TerminationReason::FixedPoint));
    assert!(results.lineage.is_empty(), "{:?}", results.lineage);
    assert_kept_elements(&results, &record.id);
    let log = service.store().log(&record.id).unwrap();
    let messages: Vec<&str> = log.iter().map(|entry| entry.message.as_str()).collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("kept from the inspect command's report"))
            && messages.iter().any(|message| {
                message.contains("scan finished: 2 entities and 2 source outcomes kept")
            }),
        "{messages:?}"
    );
    let refused = service.rerun(&record.id).unwrap_err();
    assert_eq!(
            refused,
            ServiceError::BadRequest(
                "an inspected file is kept as a scan but its bytes are not; inspect the file again to read it anew"
                    .into()
            )
        );
    assert_eq!(service.store().list().unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

/// A kept report's elements: every entity and record names scan `id`; the target carries the
/// report's fields as its own raw evidence under the root; each finding is the target's child.
fn assert_kept_elements(results: &ScanResults, id: &str) {
    for entity in &results.entities {
        assert_eq!(entity.scan_id, id, "{entity:?}");
        for evidence in &entity.evidence {
            assert_eq!(
                evidence.provenance.scan_id.as_deref(),
                Some(id),
                "{evidence:?}"
            );
        }
    }
    let elements: Vec<(&str, &str, Option<&str>)> = results
        .elements
        .iter()
        .map(|element| {
            (
                element.kind.as_str(),
                element.data.as_str(),
                element.source.as_deref(),
            )
        })
        .collect();
    let root = results
        .elements
        .iter()
        .find(|element| element.kind == "ROOT")
        .unwrap();
    let file = results
        .elements
        .iter()
        .find(|element| element.kind == "HSE_DOCUMENT")
        .unwrap();
    assert_eq!(
        file.source.as_deref(),
        Some(root.id.as_str()),
        "{elements:?}"
    );
    assert!(
        file.raw.to_string().contains("Fixture"),
        "the file's fields are its own raw evidence: {}",
        file.raw
    );
    let position = results
        .elements
        .iter()
        .find(|element| element.kind == "PHYSICAL_COORDINATES")
        .unwrap();
    assert_eq!(
        position.source.as_deref(),
        Some(file.id.as_str()),
        "{elements:?}"
    );
}

/// Running a scan publishes its status transitions to the service's event hub, so `serve` can
/// stream them live. The id is the scan's; no target text is published.
#[test]
fn scan_status_transitions_are_published_to_the_event_hub() {
    use std::time::Duration;
    let (service, dir) = with_lookup(
        "events",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
    );
    let mut sub = service.events().subscribe();
    let record = service
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::Finished);
    let mut statuses = Vec::new();
    loop {
        let batch = sub.recv(Duration::from_millis(50));
        if batch.events.is_empty() {
            break;
        }
        for event in batch.events {
            match event {
                crate::serve_events::Event::Scan { id, status, .. } => {
                    assert_eq!(id, record.id, "the scan id, never the target");
                    statuses.push(status);
                }
                crate::serve_events::Event::Alert { .. } => {
                    panic!("a scan run raises no alert event")
                }
            }
        }
    }
    assert_eq!(
        statuses,
        ["STARTING", "RUNNING", "FINISHED"],
        "each committed transition, in order"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn found(kind: ScanKind, selector: &str) -> LookupOutput {
    let evidence = Evidence::new(EvidenceProvenance::for_scan("internetdb", "s"), "ports")
        .with_attr("ports", "22,443");
    LookupOutput {
        text: format!("{} {selector}\n", kind.command()),
        entities: vec![
            Entity::builder(EntityKind::IpAddress, selector, 0.9, "s")
                .evidence(evidence)
                .build(),
        ],
        outcomes: vec![
            SourceExecutionOutcome::success("internetdb", 1, 1),
            SourceExecutionOutcome::valid_zero("greynoise", 1),
        ],
    }
}

fn with_lookup(tag: &str, lookup: ScanLookup) -> (Arc<ScanService>, PathBuf) {
    let dir = scratch(tag);
    (
        ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
        dir,
    )
}

#[test]
fn missing_or_corrupt_scan_configuration_never_dispatches_default_lookups() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "missing-scan-options",
        Arc::new(move |_, _, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(LookupOutput::default())
        }),
    );
    for corrupt in [false, true] {
        let request = ScanRequest {
            target: "example.org".into(),
            kind: Some("domain".into()),
            options: ScanOptions {
                modules: vec!["crtsh".into()],
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        };
        let (record, plan) = service.create(&request).unwrap();
        let row = dir.join(&record.id).join("scan.json");
        if corrupt {
            std::fs::write(&row, b"not json").unwrap();
        } else {
            std::fs::remove_file(&row).unwrap();
        }
        service.collect(&record.id, &plan);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "unreadable scan options must never result in network calls"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_thread_admission_rejects_overload_without_creating_a_row() {
    let (service, dir) = with_lookup(
        "bounded-scan-workers",
        Arc::new(|_, _, _| Ok(LookupOutput::default())),
    );
    let permits: Vec<_> = (0..MAX_SCAN_WORKERS)
        .map(|_| service.reserve_worker().unwrap())
        .collect();
    assert_eq!(
        service.worker_slots.load(Ordering::Acquire),
        MAX_SCAN_WORKERS
    );
    let rejected = service.start(&ScanRequest {
        target: "example.com".into(),
        ..ScanRequest::default()
    });
    assert!(matches!(rejected, Err(ServiceError::Conflict(_))));
    assert!(service.store().list().unwrap().is_empty());

    drop(permits);
    assert_eq!(service.worker_slots.load(Ordering::Acquire), 0);
    let started = service
        .start(&ScanRequest {
            target: "example.com".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let finished = service
        .wait(&started.id, Instant::now() + Duration::from_secs(10))
        .unwrap();
    assert!(!finished.status.is_active());
    for _ in 0..200 {
        if service.worker_slots.load(Ordering::Acquire) == 0 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(service.worker_slots.load(Ordering::Acquire), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn spiderfoot_rules_correlate_a_scan_and_again_after_a_false_positive() {
    let dir = scratch("rules");
    let rule = Rule::parse(
            "open_port",
            "id: open_port\nversion: 1\nmeta:\n  name: Open port\n  description: Any open port.\n  risk: MEDIUM\ncollections:\n  - collect:\n      - method: exact\n        field: type\n        value: TCP_PORT_OPEN\naggregation:\n  field: data\nheadline: \"Open port: {data}\"\n",
            "mine.yaml",
        )
        .unwrap();
    let broken = RuleError {
        rule: "broken".into(),
        reason: "not a mapping".into(),
    };
    let service = ScanService::with_rules(
        ScanStore::open(&dir).unwrap(),
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
        vec![rule],
        vec![broken],
    );
    let record = service
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let mine = |correlations: &[ScanCorrelation]| -> Vec<String> {
        correlations
            .iter()
            .filter(|correlation| correlation.origin == "mine.yaml")
            .map(|correlation| correlation.title.clone())
            .collect()
    };
    let mut results = service.store().results(&record.id).unwrap().unwrap();
    assert_eq!(
        mine(&results.correlations),
        ["Open port: 1.1.1.1:22", "Open port: 1.1.1.1:443"]
    );
    let medium = |correlations: &[ScanCorrelation]| {
        correlations
            .iter()
            .filter(|correlation| correlation.risk == Risk::Medium)
            .count()
    };
    assert_eq!(record.correlations.medium, medium(&results.correlations));
    let log = service.store().log(&record.id).unwrap();
    assert!(log.iter().any(|entry| entry.level == LogLevel::Warning
        && entry.message == "correlation rule broken: not a mapping"));
    for element in &mut results.elements {
        element.fp |= element.data == "1.1.1.1:22";
    }
    service.store().save_results(&results).unwrap();
    let again = service.correlate(&record.id).unwrap();
    assert_eq!(mine(&again), ["Open port: 1.1.1.1:443"]);
    let saved = service.store().results(&record.id).unwrap().unwrap();
    assert_eq!(saved.correlations, again);
    assert_eq!(
        service.store().get(&record.id).unwrap().correlations.medium,
        medium(&again)
    );
    assert!(matches!(
        service.correlate("nope"),
        Err(ServiceError::NotFound(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Footprint and Investigate choose modules by category, as the New Scan page describes them,
/// so they spend less than All and differ from each other; a use case never widens a choice.
#[test]
fn a_use_case_keeps_the_scan_to_its_modules() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "usecase",
        Arc::new(move |kind: ScanKind, selector: &str, chosen: &Selection| {
            let asked: Vec<&str> = ["rdap", "spamhaus", "github_user", "oathnet"]
                .into_iter()
                .filter(|module| chosen.runs(module))
                .collect();
            seen.lock().unwrap().push(format!(
                "{} {selector} asks {}",
                kind.command(),
                asked.join(",")
            ));
            Ok(found(kind, selector))
        }),
    );
    let scan = |usecase: &str, modules: &[&str]| {
        service.run(&ScanRequest {
            target: "1.1.1.1".into(),
            options: ScanOptions {
                usecase: usecase.into(),
                modules: modules.iter().map(|module| (*module).to_owned()).collect(),
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
    };
    let asked = || {
        let asked = calls.lock().unwrap().clone();
        calls.lock().unwrap().clear();
        asked
    };
    let all = scan("all", &[]).unwrap();
    assert_eq!(all.status, ScanStatus::Finished);
    assert_eq!(
        asked(),
        ["ip 1.1.1.1 asks rdap,spamhaus,github_user,oathnet"]
    );
    assert_eq!(scan("footprint", &[]).unwrap().options.usecase, "footprint");
    assert_eq!(asked(), ["ip 1.1.1.1 asks rdap,github_user,oathnet"]);
    scan("Investigate", &[]).unwrap();
    assert_eq!(asked(), ["ip 1.1.1.1 asks rdap,spamhaus,oathnet"]);
    scan("investigate", &["rdap", "github_user"]).unwrap();
    assert_eq!(asked(), ["ip 1.1.1.1 asks rdap"]);
    // A use case that leaves the chosen modules nothing to ask is refused before the scan is
    // saved, naming the modules as they were chosen.
    let refused = service
        .run(&ScanRequest {
            target: "ada@example.com".into(),
            kind: Some("exposure".into()),
            options: ScanOptions {
                usecase: "footprint".into(),
                modules: vec!["spamhaus".into()],
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap_err();
    assert!(
        matches!(&refused, ServiceError::BadRequest(why) if why.starts_with("none of the chosen modules (spamhaus) looks up the target: the exposure lookup asks hibp,")),
        "{refused:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Passive asks no keyed breach source in any lookup, so no paid service is told the target:
/// not by an address's or an email's own lookup, and not by a breach pass beside it.
#[test]
fn passive_asks_no_keyed_breach_source_in_any_lookup() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "passive",
        Arc::new(move |kind: ScanKind, selector: &str, chosen: &Selection| {
            let asked: Vec<&str> = ["rdap", "spamhaus", "github_user", "oathnet"]
                .into_iter()
                .filter(|module| chosen.runs(module))
                .collect();
            seen.lock().unwrap().push(format!(
                "{} {selector} asks {}",
                kind.command(),
                asked.join(",")
            ));
            Ok(found(kind, selector))
        }),
    );
    let scan = |usecase: &str| {
        service.run(&ScanRequest {
            target: "1.1.1.1".into(),
            options: ScanOptions {
                usecase: usecase.into(),
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
    };
    let asked = || {
        let asked = calls.lock().unwrap().clone();
        calls.lock().unwrap().clear();
        asked
    };
    // Passive asks no keyed breach source in any lookup: OathNet is never told the target.
    scan("passive").unwrap();
    assert_eq!(asked(), ["ip 1.1.1.1 asks rdap,spamhaus,github_user"]);
    // An email's own lookup asks no breach source under Passive either, and no breach pass
    // follows it, where All runs both.
    let email = |usecase: &str| {
        service.run(&ScanRequest {
            target: "ada@example.com".into(),
            options: ScanOptions {
                usecase: usecase.into(),
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
    };
    email("all").unwrap();
    assert_eq!(
        asked(),
        [
            "email ada@example.com asks rdap,spamhaus,github_user,oathnet",
            "exposure ada@example.com asks rdap,spamhaus,github_user,oathnet",
        ]
    );
    let passive = email("passive").unwrap();
    assert_eq!(
        asked(),
        ["email ada@example.com asks rdap,spamhaus,github_user"]
    );
    // No breach pass is even queued for it, so its log names no breach lookup it skipped.
    let log = service.store().log(&passive.id).unwrap();
    assert!(
        !log.iter().any(|entry| entry
            .message
            .starts_with("no chosen module looks up exposure")),
        "a passive scan queued a breach pass"
    );
    // A breach scan under Passive has nothing to ask, so it is refused by name.
    let refused = service
        .run(&ScanRequest {
            target: "ada@example.com".into(),
            kind: Some("exposure".into()),
            options: ScanOptions {
                usecase: "passive".into(),
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap_err();
    assert!(
        matches!(&refused, ServiceError::BadRequest(why) if why.starts_with("the passive use case runs none of the modules the exposure lookup asks")),
        "{refused:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_scan_asks_only_the_modules_chosen_and_skips_lookups_that_ask_none() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "modules",
        Arc::new(move |kind: ScanKind, selector: &str, chosen: &Selection| {
            let asked: Vec<&str> = ["crtsh", "spamhaus", "shodan"]
                .into_iter()
                .filter(|module| chosen.runs(module))
                .collect();
            seen.lock().unwrap().push(format!(
                "{} {selector} asks {}",
                kind.command(),
                asked.join(",")
            ));
            let address = Entity::builder(EntityKind::IpAddress, "8.8.8.8", 0.9, "s")
                .evidence(Evidence::new(
                    EvidenceProvenance::for_scan("crtsh", "s"),
                    "found",
                ))
                .build();
            Ok(LookupOutput {
                text: format!("{} {selector}\n", kind.command()),
                entities: vec![address],
                outcomes: vec![SourceExecutionOutcome::success("crtsh", 1, 1)],
            })
        }),
    );
    let scan = |target: &str, modules: &[&str]| {
        service.run(&ScanRequest {
            target: target.into(),
            options: ScanOptions {
                modules: modules.iter().map(|module| (*module).to_owned()).collect(),
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
    };
    // Only crt.sh: the domain's lookup asks it alone, and no chosen module looks up the
    // address it found, so that lookup is skipped, not failed.
    let record = scan("example.org", &[" CRTSH "]).unwrap();
    assert_eq!(record.status, ScanStatus::Finished);
    assert_eq!(record.options.modules, ["crtsh"]);
    assert_eq!(record.errors, 0);
    assert_eq!(*calls.lock().unwrap(), ["domain example.org asks crtsh"]);
    let log = service.store().log(&record.id).unwrap();
    assert!(log.iter().any(|entry| entry.level == LogLevel::Info
        && entry.message == "no chosen module looks up ip, so 8.8.8.8 was not looked up"));
    // A Spiderfoot name chooses the module doing its work, which also looks up addresses.
    calls.lock().unwrap().clear();
    let record = scan("example.org", &["SFP_SPAMHAUS"]).unwrap();
    assert_eq!(record.options.modules, ["sfp_spamhaus"]);
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "domain example.org asks spamhaus",
            "ip 8.8.8.8 asks spamhaus"
        ]
    );
    // A name no module answers to, and a target none of the chosen modules looks up, are
    // refused before the scan is saved.
    let unknown = scan("example.org", &["crtsh", "sfp_spider"]).unwrap_err();
    assert!(
        matches!(&unknown, ServiceError::BadRequest(why) if why.starts_with("no module is named sfp_spider;")),
        "{unknown:?}"
    );
    let elsewhere = scan("1.1.1.1", &["crtsh"]).unwrap_err();
    assert!(
        matches!(&elsewhere, ServiceError::BadRequest(why) if why.starts_with("none of the chosen modules (crtsh) looks up the target: the ip lookup asks dnsresolve, rdap,")),
        "{elsewhere:?}"
    );
    assert_eq!(service.store().list().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_deeper_scan_looks_up_what_it_finds_and_links_each_element_to_its_finder() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "depth",
        Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
            seen.lock()
                .unwrap()
                .push(format!("{} {selector}", kind.command()));
            let entity = |kind: EntityKind, value: &str, source: &str| {
                Entity::builder(kind, value, 0.9, "s")
                    .evidence(Evidence::new(
                        EvidenceProvenance::for_scan(source, "s"),
                        "found",
                    ))
                    .build()
            };
            Ok(match kind {
                ScanKind::Domain => LookupOutput {
                    text: format!("domain {selector}\n"),
                    entities: vec![entity(EntityKind::IpAddress, "8.8.8.8", "dns")],
                    outcomes: vec![SourceExecutionOutcome::success("dns", 1, 1)],
                },
                ScanKind::Ip => {
                    let mut output = found(kind, selector);
                    output.entities.push(entity(
                        EntityKind::Domain,
                        "cohost.example.net",
                        "hackertarget",
                    ));
                    output
                }
                _ => LookupOutput::default(),
            })
        }),
    );
    let record = service
        .run(&ScanRequest {
            target: "example.org".into(),
            options: ScanOptions {
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::Finished);
    assert_eq!(record.options.depth, 1);
    // The co-hosted domain would be the third hop's lookup; depth 1 stops before it.
    assert_eq!(*calls.lock().unwrap(), ["domain example.org", "ip 8.8.8.8"]);
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert_eq!(results.termination, Some(TerminationReason::MaxDepth));
    assert_eq!(results.text, "domain example.org\n\nip 8.8.8.8\n");
    assert!(
        results
            .lineage
            .iter()
            .any(|edge| edge.from_selector == "8.8.8.8"
                && edge.to_value == "cohost.example.net"
                && edge.generation == 1)
    );
    let element = |data: &str| {
        results
            .elements
            .iter()
            .find(|element| element.data == data && element.kind != "ROOT")
            .unwrap()
    };
    let target = element("example.org");
    let address = element("8.8.8.8");
    assert_eq!(address.source.as_deref(), Some(target.id.as_str()));
    // Found by the address's lookup, so the address's element is its source.
    assert_eq!(
        element("cohost.example.net").source.as_deref(),
        Some(address.id.as_str())
    );
    // A port hangs off the address element its own record made.
    let port_source = element("8.8.8.8:22").source.clone().unwrap();
    assert!(
        results
            .elements
            .iter()
            .any(|element| element.id == port_source
                && element.data == "8.8.8.8"
                && element.module == "internetdb")
    );
    let log = service.store().log(&record.id).unwrap();
    assert!(log.iter().any(|entry| entry.message
            == "2 lookups over 2 generations found 2 entities; stopped (max_depth): depth 1 reached; a deeper scan would look up more of its findings"));
    let rerun = service.rerun_request(&record.id).unwrap();
    assert_eq!(rerun.options.depth, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A lookup mints a private scan id for what it builds. Saved, every observation names the
/// saved scan instead, so a raw record's provenance leads to a scan in the list, and an
/// observation a merge kept that differed only by that private id is not kept twice.
#[test]
fn saved_observations_name_the_saved_scan_not_the_lookups_private_id() {
    let (service, dir) = with_lookup(
        "stamp",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| {
            let mut output = found(kind, selector);
            let evidence = &mut output.entities[0].evidence[0];
            let mut again = evidence.provenance.clone();
            again.scan_id = Some("t".into());
            evidence.merged_provenance.push(again);
            let mut other_source = evidence.provenance.clone();
            other_source.source = "greynoise".into();
            other_source.scan_id = Some("u".into());
            evidence.merged_provenance.push(other_source);
            Ok(output)
        }),
    );
    let record = service
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::Finished);
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert!(!results.entities.is_empty());
    for (index, entity) in results.entities.iter().enumerate() {
        assert_eq!(entity.scan_id, record.id, "entity {index}");
        for evidence in &entity.evidence {
            assert_eq!(
                evidence.provenance.scan_id.as_deref(),
                Some(record.id.as_str())
            );
            for observation in &evidence.merged_provenance {
                assert_eq!(observation.scan_id.as_deref(), Some(record.id.as_str()));
                assert_ne!(observation, &evidence.provenance);
            }
        }
    }
    let merged = &results.entities[0].evidence[0].merged_provenance;
    assert_eq!(merged.len(), 1, "{merged:?}");
    assert_eq!(merged[0].source, "greynoise");
    assert!(
        !serde_json::to_string(&results)
            .unwrap()
            .contains("\"scan_id\":\"s\""),
        "no private lookup id survives in what is saved"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_run_saves_elements_counts_log_and_finishes() {
    let (service, dir) = with_lookup(
        "run",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
    );
    let record = service
        .run(&ScanRequest {
            target: " 1.1.1.1 ".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::Finished);
    assert_eq!(record.kind, "ip");
    assert_eq!(record.target_type, "IP_ADDRESS");
    assert_eq!(record.name, "1.1.1.1");
    assert_eq!(record.options.usecase, "all");
    assert_eq!(record.modules_run, ["greynoise", "internetdb"]);
    assert!(record.started.is_some() && record.ended.is_some());
    let results = service.store().results(&record.id).unwrap().unwrap();
    let ports: Vec<&str> = results
        .elements
        .iter()
        .filter(|element| element.kind == "TCP_PORT_OPEN")
        .map(|element| element.data.as_str())
        .collect();
    assert_eq!(ports, ["1.1.1.1:22", "1.1.1.1:443"]);
    assert_eq!(record.elements, results.elements.len() - 1);
    let log = service.store().log(&record.id).unwrap();
    assert!(
        log.iter()
            .any(|entry| entry.component == "greynoise" && entry.message.starts_with("valid_zero"))
    );
    assert!(log.last().unwrap().message.contains("FINISHED"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_email_scan_runs_the_breach_lookup_unless_the_email_lookup_ran_a_breach_source() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "email",
        Arc::new(move |kind: ScanKind, _selector: &str, _: &Selection| {
            seen.lock().unwrap().push(kind.command());
            Ok(LookupOutput::default())
        }),
    );
    service
        .run(&ScanRequest {
            target: "jane@example.org".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), ["email", "exposure"]);
    calls.lock().unwrap().clear();
    let (service2, dir2) = with_lookup(
        "email2",
        Arc::new({
            let seen = Arc::clone(&calls);
            move |kind: ScanKind, _selector: &str, _: &Selection| {
                seen.lock().unwrap().push(kind.command());
                // The row the HIBP leg writes, `hibp_account`, is the `hibp` module's.
                Ok(LookupOutput {
                    outcomes: vec![SourceExecutionOutcome::valid_zero(
                        crate::hibp::ACCOUNT_SOURCE,
                        1,
                    )],
                    ..LookupOutput::default()
                })
            }
        }),
    );
    service2
        .run(&ScanRequest {
            target: "jane@example.org".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), ["email"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn a_lookup_that_cannot_run_fails_the_scan_with_the_reason_logged() {
    let (service, dir) = with_lookup(
        "fail",
        Arc::new(
            |_kind: ScanKind, _selector: &str, _: &Selection| Err("egress refused".to_owned()),
        ),
    );
    let record = service
        .run(&ScanRequest {
            target: "example.com".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::ErrorFailed);
    assert_eq!(record.errors, 1);
    let log = service.store().log(&record.id).unwrap();
    assert!(log.iter().any(
            |entry| entry.level == LogLevel::Error && entry.message.contains("egress refused")
        ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_targets_kinds_and_options_are_refused_before_anything_is_saved() {
    let (service, dir) = with_lookup(
        "bad",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
    );
    for request in [
        ScanRequest::default(),
        ScanRequest {
            target: "example.com".into(),
            kind: Some("nope".into()),
            ..ScanRequest::default()
        },
        ScanRequest {
            target: "example.com".into(),
            options: ScanOptions {
                usecase: "everything".into(),
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        },
        ScanRequest {
            target: "example.com".into(),
            options: ScanOptions {
                types: vec!["NOT_A_TYPE".into()],
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        },
    ] {
        assert!(
            matches!(service.run(&request), Err(ServiceError::BadRequest(_))),
            "{request:?}"
        );
    }
    assert!(service.store().list().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn requested_types_keep_only_those_elements_and_the_target() {
    let (service, dir) = with_lookup(
        "types",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
    );
    let record = service
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            options: ScanOptions {
                types: vec!["tcp_port_open".into()],
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.options.types, ["TCP_PORT_OPEN"]);
    let results = service.store().results(&record.id).unwrap().unwrap();
    let kinds: BTreeSet<&str> = results
        .elements
        .iter()
        .map(|element| element.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        BTreeSet::from(["IP_ADDRESS", "ROOT", "TCP_PORT_OPEN"])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Ticking only `COUNTRY_NAME` keeps the `GEOINFO` element the country was found from, so no saved
/// element points at a source that was not saved: the Source Data Element, the graph edge and
/// the discovery path stay whole.
#[test]
fn requested_types_keep_each_kept_elements_ancestry() {
    let (service, dir) = with_lookup(
        "types-ancestry",
        Arc::new(|_: ScanKind, selector: &str, _: &Selection| {
            let evidence = Evidence::new(EvidenceProvenance::for_scan("pulsedive", "s"), "geo")
                .with_attr("city", "Sydney")
                .with_attr("country", "AU");
            Ok(LookupOutput {
                text: format!("ip {selector}\n"),
                entities: vec![
                    Entity::builder(EntityKind::IpAddress, selector, 0.9, "s")
                        .evidence(evidence)
                        .build(),
                ],
                outcomes: vec![SourceExecutionOutcome::success("pulsedive", 1, 1)],
            })
        }),
    );
    let record = service
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            options: ScanOptions {
                types: vec!["COUNTRY_NAME".into()],
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    let results = service.store().results(&record.id).unwrap().unwrap();
    let kinds: BTreeSet<&str> = results
        .elements
        .iter()
        .map(|element| element.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        BTreeSet::from(["COUNTRY_NAME", "GEOINFO", "IP_ADDRESS", "ROOT"]),
        "the country keeps the GEOINFO it was found from"
    );
    let ids: BTreeSet<&str> = results
        .elements
        .iter()
        .map(|element| element.id.as_str())
        .collect();
    for element in &results.elements {
        if let Some(source) = &element.source {
            assert!(
                ids.contains(source.as_str()),
                "{} {} points at an unsaved source",
                element.kind,
                element.data
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A scan whose process Android stopped while the server stayed up: Stop succeeds (the row
/// reads ABORTED), Delete succeeds, and reading it says ABORTED with the owner named in its log,
/// instead of a RUNNING row that answers 409 to both until the next restart.
#[cfg(target_os = "linux")]
#[test]
fn a_scan_whose_process_died_can_be_stopped_deleted_and_reads_aborted() {
    let (service, dir) = with_lookup(
        "dead-owner",
        Arc::new(|_, _, _| Ok(LookupOutput::default())),
    );
    let orphan = |tag: &str| {
        let mut row = placeholder(&new_id(tag, 1, 0));
        row.status = ScanStatus::Running;
        // No process has this pid, so the owner that recorded it is gone.
        row.owner = Some(u32::MAX);
        service.store().create(&row).unwrap();
        row.id
    };
    let stopped = orphan("stop");
    assert_eq!(service.stop(&stopped).unwrap().status, ScanStatus::Aborted);
    assert_eq!(
        service.store().get(&stopped).unwrap().status,
        ScanStatus::Aborted
    );
    let deleted = orphan("delete");
    service.delete(&deleted).unwrap();
    assert!(service.store().get(&deleted).is_err());
    let read = orphan("read");
    assert_eq!(service.record(&read).unwrap().status, ScanStatus::Aborted);
    assert!(
        service
            .records()
            .unwrap()
            .iter()
            .all(|row| row.status == ScanStatus::Aborted)
    );
    let log = service.store().log(&read).unwrap();
    assert!(
        log.iter()
            .any(|entry| entry.message.contains(&format!("pid {}", u32::MAX))),
        "{log:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn failed_status_persistence_is_reported_without_overwriting_the_saved_row() {
    let (service, dir) = with_lookup(
        "status-persistence-failure",
        Arc::new(|_, _, _| Ok(LookupOutput::default())),
    );
    let (created, _) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let error = service.set_status_with(&created.id, ScanStatus::Finished, Some(123), |_| {
        Err(StoreError::Io("synthetic disk write failure".into()))
    });
    assert!(matches!(error, Err(ServiceError::Store(_))));
    assert_eq!(
        service.store().get(&created.id).unwrap().status,
        ScanStatus::Created
    );
    let observed = service.wait(&created.id, Instant::now() + Duration::from_millis(20));
    assert!(matches!(observed, Err(ServiceError::Store(ref message))
            if message.contains("synthetic disk write failure")));
    service.delete(&created.id).unwrap_err();
    // A persistence fault stays observable until a successful recovery or deletion.
    assert!(service.state().status_failures.contains_key(&created.id));

    service
        .set_status(&created.id, ScanStatus::Finished, Some(456))
        .unwrap();
    assert!(!service.state().status_failures.contains_key(&created.id));
    let recovered = service
        .wait(&created.id, Instant::now() + Duration::from_millis(20))
        .unwrap();
    assert_eq!(recovered.status, ScanStatus::Finished);
    assert_eq!(recovered.ended, Some(456));
    service.delete(&created.id).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cancellation_is_monotonic_across_worker_start_and_finish() {
    let (service, dir) = with_lookup(
        "monotonic-status",
        Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
    );
    let (created, _) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let stop = service.stop(&created.id).unwrap();
    assert_eq!(stop.status, ScanStatus::AbortRequested);

    // The queued worker may observe the stop after starting. Neither transition
    // may erase the operator's cancellation request or invent a start time.
    service
        .set_status(&created.id, ScanStatus::Starting, None)
        .unwrap();
    service
        .set_status(&created.id, ScanStatus::Running, Some(123))
        .unwrap();
    let row = service.store().get(&created.id).unwrap();
    assert_eq!(row.status, ScanStatus::AbortRequested);
    assert!(row.started.is_none());

    // A worker that chose FINISHED just before stop() acquired the state lock
    // must still commit ABORTED when it eventually updates its row.
    service
        .set_status(&created.id, ScanStatus::Finished, Some(456))
        .unwrap();
    let row = service.store().get(&created.id).unwrap();
    assert_eq!(row.status, ScanStatus::Aborted);
    assert_eq!(row.ended, Some(456));
    service
        .set_status(&created.id, ScanStatus::Running, Some(789))
        .unwrap();
    assert_eq!(
        service.store().get(&created.id).unwrap().status,
        ScanStatus::Aborted,
        "a completed scan must never be resurrected by a late worker transition"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_request_does_not_join_a_row_this_instance_no_longer_runs() {
    let (service, dir) = with_lookup(
        "stranded-join",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
    );
    let request = ScanRequest {
        target: "1.1.1.1".into(),
        ..ScanRequest::default()
    };
    let (stranded, _) = service.create(&request).unwrap();
    // An active row under this process that the service no longer owns, as a worker that
    // gave up without ending its row used to leave behind.
    service.owned().remove(&stranded.id);

    let joined = service.start_or_join(&request).unwrap();

    assert_ne!(
        joined.id, stranded.id,
        "a request must not wait on a row that no worker runs"
    );
    let ended = service
        .wait(&joined.id, Instant::now() + Duration::from_secs(10))
        .unwrap();
    assert_eq!(ended.status, ScanStatus::Finished);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_request_does_not_join_a_scan_whose_status_could_not_be_saved() {
    let (service, dir) = with_lookup(
        "unsaved-status-join",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
    );
    let request = ScanRequest {
        target: "1.1.1.1".into(),
        ..ScanRequest::default()
    };
    let (failing, _) = service.create(&request).unwrap();
    // Still owned, but its worker could not save its first transition: a joiner would only
    // be handed that error.
    let _ = service.set_status_with(&failing.id, ScanStatus::Starting, None, |_| {
        Err(StoreError::Io("synthetic disk write failure".into()))
    });

    let joined = service.start_or_join(&request).unwrap();

    assert_ne!(joined.id, failing.id);
    let ended = service
        .wait(&joined.id, Instant::now() + Duration::from_secs(10))
        .unwrap();
    assert_eq!(ended.status, ScanStatus::Finished);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_request_joins_the_scan_this_instance_is_running() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let entered_tx = Mutex::new(entered_tx);
    let (service, dir) = with_lookup(
        "running-join",
        Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
            let _ = entered_tx.lock().unwrap().send(());
            // Every lookup after the release finds the channel closed and goes straight on.
            let _ = release_rx.lock().unwrap().recv();
            Ok(found(kind, selector))
        }),
    );
    let request = ScanRequest {
        target: "1.1.1.1".into(),
        ..ScanRequest::default()
    };
    let first = service.start_or_join(&request).unwrap();
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    let second = service.start_or_join(&request).unwrap();

    assert_eq!(
        second.id, first.id,
        "a lookup reloaded mid-scan waits on the scan under way"
    );
    drop(release_tx);
    let ended = service
        .wait(&first.id, Instant::now() + Duration::from_secs(10))
        .unwrap();
    assert_eq!(ended.status, ScanStatus::Finished);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_scan_its_worker_gives_up_on_is_ended_and_can_be_deleted() {
    let (service, dir) = with_lookup("released", Arc::new(|_, _, _| Ok(LookupOutput::default())));
    let (record, _) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    // The worker's first transition could not be saved, so the row is still CREATED.
    let _ = service.set_status_with(&record.id, ScanStatus::Starting, None, |_| {
        Err(StoreError::Io("synthetic disk write failure".into()))
    });

    service.release(&record.id, false);

    let row = service.store().get(&record.id).unwrap();
    assert_eq!(row.status, ScanStatus::ErrorFailed);
    assert!(row.ended.is_some());
    assert!(!service.owned().contains(&record.id));
    assert!(!service.state().status_failures.contains_key(&record.id));
    assert!(
        service
            .store()
            .log(&record.id)
            .unwrap()
            .iter()
            .any(|entry| entry.message.contains("marked ERROR_FAILED"))
    );
    service.delete(&record.id).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_running_scan_whose_row_cannot_be_read_is_not_deleted() {
    let (service, dir) = with_lookup(
        "unreadable-delete",
        Arc::new(|_, _, _| Ok(LookupOutput::default())),
    );
    // `create` registers the scan as this service's, as a running scan is.
    let (record, _) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let scan_dir = dir.join(&record.id);
    std::fs::write(scan_dir.join("scan.json"), b"not a scan row").unwrap();

    let error = service.delete(&record.id).unwrap_err();

    assert!(matches!(error, ServiceError::Conflict(_)), "{error}");
    assert!(scan_dir.join("scan.json").exists());
    // Once no worker runs it, an unreadable row is deleted as before.
    service.owned().remove(&record.id);
    service.delete(&record.id).unwrap();
    assert!(!scan_dir.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stopping_a_foreign_owned_scan_is_an_explicit_conflict() {
    let (service, dir) = with_lookup(
        "foreign-stop",
        Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
    );
    let (mut record, _) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    record.status = ScanStatus::Running;
    // The test runner's parent is alive for as long as this test runs, so the owner is a
    // live foreign process, not one whose death reconciles the row to ABORTED. Its recorded
    // start time must be that process's own, or the row reads as a reused pid.
    let parent = std::os::unix::process::parent_id();
    record.owner = Some(parent);
    record.owner_started = crate::scan_store::process_start_ticks(parent);
    service.store().update(&record).unwrap();
    let controller = ScanService::new(service.store().clone(), Arc::clone(&service.lookup));
    let cancellation = controller.graph_cancellation(&record.id);
    let before = std::fs::read(dir.join(&record.id).join("scan.json")).unwrap();
    let before_log = service.store().log(&record.id).unwrap();

    let error = controller.stop(&record.id).unwrap_err();
    assert!(matches!(error, ServiceError::Conflict(_)));
    assert_eq!(error.status(), 409);
    assert!(error.to_string().contains("owning process"));
    assert_eq!(
        std::fs::read(dir.join(&record.id).join("scan.json")).unwrap(),
        before
    );
    assert!(!controller.state().aborts.contains(&record.id));
    assert!(!cancellation.load(Ordering::Acquire));
    assert_eq!(service.store().log(&record.id).unwrap(), before_log);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn same_process_different_service_cannot_acknowledge_foreign_stop() {
    let (owner, dir) = with_lookup(
        "same-process-service-stop",
        Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
    );
    let (mut record, _) = owner
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    record.status = ScanStatus::Running;
    owner.store().update(&record).unwrap();
    let other = ScanService::new(owner.store().clone(), Arc::clone(&owner.lookup));
    let signal = other.graph_cancellation(&record.id);
    let before = std::fs::read(dir.join(&record.id).join("scan.json")).unwrap();
    let before_log = owner.store().log(&record.id).unwrap();

    // Both instances have the same PID, but only the creator can signal the scan.
    assert_eq!(record.owner, Some(std::process::id()));
    #[cfg(target_os = "linux")]
    assert_eq!(
        record.owner_started,
        crate::scan_store::process_start_ticks(std::process::id())
    );
    assert!(owner.owned().contains(&record.id));
    assert!(!other.owned().contains(&record.id));
    let error = other.stop(&record.id).unwrap_err();
    assert!(matches!(error, ServiceError::Conflict(_)));
    assert_eq!(error.status(), 409);
    assert!(error.to_string().contains("owning service"));
    assert_eq!(
        std::fs::read(dir.join(&record.id).join("scan.json")).unwrap(),
        before
    );
    assert_eq!(owner.store().log(&record.id).unwrap(), before_log);
    assert!(!other.state().aborts.contains(&record.id));
    assert!(!signal.load(Ordering::Acquire));

    // Its actual owning instance can still deliver the request.
    let stopped = owner.stop(&record.id).unwrap();
    assert_eq!(stopped.status, ScanStatus::AbortRequested);
    assert!(owner.state().aborts.contains(&record.id));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stopping_a_scan_without_a_known_owner_is_an_explicit_conflict() {
    let (service, dir) = with_lookup(
        "unknown-owner-stop",
        Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
    );
    let (mut record, _) = service
        .create(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    record.owner = None;
    service.store().update(&record).unwrap();

    let error = service.stop(&record.id).unwrap_err();
    assert!(matches!(error, ServiceError::Conflict(_)));
    assert_eq!(error.status(), 409);
    assert_eq!(service.store().get(&record.id).unwrap(), record);
    assert!(!service.state().aborts.contains(&record.id));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stop_while_running_aborts_after_the_lookup_and_keeps_its_results() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let entered_tx = Mutex::new(entered_tx);
    let (service, dir) = with_lookup(
        "stop",
        Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
            entered_tx.lock().unwrap().send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            Ok(found(kind, selector))
        }),
    );
    let record = service
        .start(&ScanRequest {
            target: "jane@example.org".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::Created);
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(
        service.store().get(&record.id).unwrap().status,
        ScanStatus::Running
    );
    assert!(matches!(
        service.delete(&record.id),
        Err(ServiceError::Conflict(_))
    ));
    let stopping = service.stop(&record.id).unwrap();
    assert_eq!(stopping.status, ScanStatus::AbortRequested);
    release_tx.send(()).unwrap();
    let mut status = ScanStatus::AbortRequested;
    for _ in 0..200 {
        status = service.store().get(&record.id).unwrap().status;
        if !status.is_active() {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(status, ScanStatus::Aborted);
    // The email lookup's results are kept; the breach lookup never started.
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert!(!results.entities.is_empty());
    assert_eq!(results.termination, Some(TerminationReason::Cancelled));
    let log = service.store().log(&record.id).unwrap();
    assert!(log.iter().any(|entry| {
        entry
            .message
            .contains("stopped (cancelled): stop requested; the lookups still queued did not run")
    }));
    assert!(
        !log.iter()
            .any(|entry| entry.message.contains("running the exposure"))
    );
    assert!(matches!(
        service.stop(&record.id),
        Err(ServiceError::Conflict(_))
    ));
    service.delete(&record.id).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_running_scan_checkpoints_what_it_has_found_before_the_next_wave() {
    // A depth-1 crawl: the domain lookup answers at once with three addresses and every
    // address lookup blocks. While they block, the scan must already have saved the domain
    // wave's findings, so a process that dies now leaves a scan that shows them. Baseline:
    // nothing is written until the whole crawl ends, and a killed scan recovers empty.
    let (entered_tx, entered_rx) = mpsc::channel::<String>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let (service, dir) = with_lookup(
        "checkpoint",
        Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
            if kind == ScanKind::Domain {
                let evidence = Evidence::new(
                    EvidenceProvenance::for_scan("test", "seed"),
                    "discovered address",
                );
                return Ok(LookupOutput {
                    text: "domain report".into(),
                    entities: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
                        .into_iter()
                        .map(|ip| {
                            Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                .evidence(evidence.clone())
                                .build()
                        })
                        .collect(),
                    outcomes: vec![SourceExecutionOutcome::success("crtsh", 1, 3)],
                });
            }
            entered_tx
                .lock()
                .unwrap()
                .send(selector.to_owned())
                .unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            Ok(LookupOutput {
                text: format!("completed-{selector}"),
                ..LookupOutput::default()
            })
        }),
    );
    let record = service
        .start(&ScanRequest {
            target: "example.org".into(),
            kind: Some("domain".into()),
            options: ScanOptions {
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    let _entered = entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // The address lookups are blocked: the scan runs, and generation 0 is on disk.
    let row = service.store().get(&record.id).unwrap();
    assert_eq!(row.status, ScanStatus::Running);
    let partial = service
        .store()
        .results(&record.id)
        .unwrap()
        .expect("the domain wave is saved before the address wave runs");
    assert_eq!(
        partial.termination, None,
        "a checkpoint claims no stop reason"
    );
    let addresses: BTreeSet<&str> = partial
        .elements
        .iter()
        .filter(|element| element.kind == "IP_ADDRESS")
        .map(|element| element.data.as_str())
        .collect();
    assert_eq!(addresses, BTreeSet::from(["1.1.1.1", "8.8.8.8", "9.9.9.9"]));
    assert_eq!(partial.text, "domain report");
    assert_eq!(partial.outcomes.len(), 1);
    assert!(
        partial.correlations.is_empty(),
        "the rules run once, when the crawl ends"
    );
    let shown = partial
        .elements
        .iter()
        .filter(|element| element.kind != "ROOT")
        .count();
    assert!(shown >= 3, "{shown} elements shown for three addresses");
    assert_eq!(
        (row.elements, row.modules_run.as_slice()),
        (shown, ["crtsh".to_owned()].as_slice()),
        "the row counts the checkpoint while the scan runs"
    );
    // Every address lookup finishes: the final save supersedes the checkpoint.
    for _ in 0..3 {
        release_tx.send(()).unwrap();
    }
    let done = service
        .wait(&record.id, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(done.status, ScanStatus::Finished);
    let whole = service.store().results(&record.id).unwrap().unwrap();
    assert!(whole.termination.is_some(), "the final save names the stop");
    assert!(whole.text.contains("completed-1.1.1.1"), "{}", whole.text);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn stopping_active_graph_batch_signals_cancellation_and_retains_results() {
    let (entered_tx, entered_rx) = mpsc::channel::<String>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "stop-graph-batch",
        Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
            if kind == ScanKind::Domain {
                let evidence = Evidence::new(
                    EvidenceProvenance::for_scan("test", "seed"),
                    "discovered address",
                );
                return Ok(LookupOutput {
                    entities: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
                        .into_iter()
                        .map(|ip| {
                            Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                .evidence(evidence.clone())
                                .build()
                        })
                        .collect(),
                    ..LookupOutput::default()
                });
            }
            observed_calls.fetch_add(1, Ordering::SeqCst);
            entered_tx
                .lock()
                .unwrap()
                .send(selector.to_owned())
                .unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            Ok(LookupOutput {
                text: format!("completed-{selector}"),
                ..LookupOutput::default()
            })
        }),
    );
    let record = service
        .start(&ScanRequest {
            target: "example.org".into(),
            kind: Some("domain".into()),
            options: ScanOptions {
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    let first = entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let second = entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_ne!(first, second);
    let cancellation = {
        let state = service.state();
        Arc::clone(
            state
                .graph_cancellations
                .get(&record.id)
                .expect("running graph must register cancellation"),
        )
    };
    assert!(!cancellation.load(Ordering::Acquire));
    service.stop(&record.id).unwrap();
    assert!(cancellation.load(Ordering::Acquire));
    release_tx.send(()).unwrap();
    release_tx.send(()).unwrap();
    let finished = service
        .wait(&record.id, Instant::now() + Duration::from_secs(10))
        .unwrap();
    assert_eq!(finished.status, ScanStatus::Aborted);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert!(results.text.contains(&format!("completed-{first}")));
    assert!(results.text.contains(&format!("completed-{second}")));
    assert_eq!(results.termination, Some(TerminationReason::Cancelled));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stopping_active_graph_batch_preserves_completed_lookup_failures() {
    let (entered_tx, entered_rx) = mpsc::channel::<String>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let (service, dir) = with_lookup(
        "stop-graph-failures",
        Arc::new(move |kind: ScanKind, selector: &str, _: &Selection| {
            if kind == ScanKind::Domain {
                let evidence = Evidence::new(
                    EvidenceProvenance::for_scan("test", "seed"),
                    "discovered address",
                );
                return Ok(LookupOutput {
                    entities: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
                        .into_iter()
                        .map(|ip| {
                            Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                .evidence(evidence.clone())
                                .build()
                        })
                        .collect(),
                    ..LookupOutput::default()
                });
            }
            observed_calls.fetch_add(1, Ordering::SeqCst);
            entered_tx
                .lock()
                .unwrap()
                .send(selector.to_owned())
                .unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            Err(format!("synthetic provider outage for {selector}"))
        }),
    );
    let record = service
        .start(&ScanRequest {
            target: "example.org".into(),
            kind: Some("domain".into()),
            options: ScanOptions {
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    let first = entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let second = entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_ne!(first, second);
    service.stop(&record.id).unwrap();
    release_tx.send(()).unwrap();
    release_tx.send(()).unwrap();
    let finished = service
        .wait(&record.id, Instant::now() + Duration::from_secs(10))
        .unwrap();
    assert_eq!(finished.status, ScanStatus::Aborted);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(finished.errors, 2);
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert_eq!(results.termination, Some(TerminationReason::Cancelled));
    assert_eq!(results.outcomes.len(), 2);
    assert!(results.outcomes.iter().all(|outcome| {
        outcome.module == "graph_exec"
            && outcome.kind == SourceOutcomeKind::Inconclusive
            && outcome.found.is_none()
    }));
    for selector in [first, second] {
        let diagnostic = format!("synthetic provider outage for {selector}");
        assert!(results.outcomes.iter().any(|outcome| {
            outcome
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains(&diagnostic))
        }));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rerun_is_a_new_scan_with_the_same_target_and_options() {
    let (service, dir) = with_lookup(
        "rerun",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| Ok(found(kind, selector))),
    );
    let first = service
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            name: Some("office".into()),
            kind: Some("ip".into()),
            options: ScanOptions {
                usecase: "footprint".into(),
                ..ScanOptions::default()
            },
        })
        .unwrap();
    let second = service.rerun(&first.id).unwrap();
    assert_ne!(second.id, first.id);
    assert_eq!(
        (
            second.name.as_str(),
            second.target.as_str(),
            second.kind.as_str()
        ),
        ("office", "1.1.1.1", "ip")
    );
    assert_eq!(second.options, first.options);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_panicking_lookup_fails_the_scan_and_frees_its_place() {
    let (service, dir) = with_lookup(
        "panic",
        Arc::new(
            |_kind: ScanKind, _selector: &str, _: &Selection| -> Result<LookupOutput, String> {
                panic!("lookup bug")
            },
        ),
    );
    for _ in 0..=MAX_RUNNING {
        let record = service
            .run(&ScanRequest {
                target: "example.com".into(),
                ..ScanRequest::default()
            })
            .unwrap();
        assert_eq!(record.status, ScanStatus::ErrorFailed);
        service.delete(&record.id).unwrap();
    }
    assert_eq!(service.state().running, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn graph_scan_envelopes_reject_missing_or_wrongly_typed_fields() {
    assert!(lookup_input_schema().accepts(&json!({
        "kind": "email", "selector": "jane@example.org"
    })));
    assert!(!lookup_input_schema().accepts(&json!({
        "kind": 42, "selector": "jane@example.org"
    })));
    assert!(
        lookup_output_schema().accepts(&serde_json::to_value(LookupOutput::default()).unwrap())
    );
    assert!(!lookup_output_schema().accepts(&json!({
        "text": "", "entities": []
    })));
    assert!(!lookup_output_schema().accepts(&json!({
        "text": "", "entities": {}, "outcomes": []
    })));
}

#[test]
fn graph_batch_admission_separates_dependent_and_independent_targets() {
    let (service, dir) = with_lookup(
        "batch-admission",
        Arc::new(|_, _, _| Ok(LookupOutput::default())),
    );
    let options = ScanOptions::default();
    let selection = chosen(&options).unwrap();
    let scan_plan = plan("jane@example.org", Some("email")).unwrap();
    let collector = ScanCollector::new(
        &service,
        "batch-admission",
        &scan_plan,
        &options,
        &selection,
    );
    let email = CrawlTarget {
        kind: ScanKind::Email,
        selector: "jane@example.org".into(),
    };
    let exposure = CrawlTarget {
        kind: ScanKind::Exposure,
        selector: email.selector.clone(),
    };
    assert!(!collector.may_batch(&[email], &exposure));
    let first_ip = CrawlTarget {
        kind: ScanKind::Ip,
        selector: "1.1.1.1".into(),
    };
    let next_ip = CrawlTarget {
        kind: ScanKind::Ip,
        selector: "8.8.8.8".into(),
    };
    assert!(collector.may_batch(&[first_ip], &next_ip));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sequential_lookup_error_persists_an_inconclusive_outcome() {
    let (service, dir) = with_lookup(
        "persist-sequential-failure",
        Arc::new(|_, _, _| Err("synthetic source outage".into())),
    );
    let record = service
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            kind: Some("ip".into()),
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::ErrorFailed);
    assert_eq!(record.errors, 1);
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert!(results.entities.is_empty());
    assert_eq!(results.outcomes.len(), 1);
    assert_eq!(results.outcomes[0].module, "scan_lookup");
    assert_eq!(results.outcomes[0].kind, SourceOutcomeKind::Inconclusive);
    assert!(results.outcomes[0].found.is_none());
    let diagnostic = results.outcomes[0].detail.as_deref().unwrap();
    assert!(diagnostic.contains("synthetic source outage"));
    assert!(
        results.outcomes[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("ip lookup on 1.1.1.1")
    );
    let log = service.store().log(&record.id).unwrap();
    assert!(
        log.iter()
            .any(|entry| entry.message.contains("synthetic source outage"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn graph_lookup_error_persists_alongside_a_valid_zero_result() {
    let (service, dir) = with_lookup(
        "persist-graph-failure",
        Arc::new(|kind: ScanKind, selector: &str, _: &Selection| {
            if kind == ScanKind::Domain {
                let evidence = Evidence::new(
                    EvidenceProvenance::for_scan("test", "seed"),
                    "discovered address",
                );
                return Ok(LookupOutput {
                    entities: ["1.1.1.1", "8.8.8.8"]
                        .into_iter()
                        .map(|ip| {
                            Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                .evidence(evidence.clone())
                                .build()
                        })
                        .collect(),
                    ..LookupOutput::default()
                });
            }
            if selector == "1.1.1.1" {
                return Err("synthetic provider failure".into());
            }
            Ok(LookupOutput {
                outcomes: vec![SourceExecutionOutcome::valid_zero("fixture", 42)],
                ..LookupOutput::default()
            })
        }),
    );
    let record = service
        .run(&ScanRequest {
            target: "example.org".into(),
            kind: Some("domain".into()),
            options: ScanOptions {
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::Finished);
    assert_eq!(record.errors, 1);
    let results = service.store().results(&record.id).unwrap().unwrap();
    assert_eq!(results.outcomes.len(), 2);
    let failure = results
        .outcomes
        .iter()
        .find(|outcome| outcome.module == "graph_exec")
        .unwrap();
    assert_eq!(failure.kind, SourceOutcomeKind::Inconclusive);
    assert!(failure.found.is_none());
    assert!(failure.detail.as_deref().unwrap().contains("1.1.1.1"));
    assert!(
        failure
            .detail
            .as_deref()
            .unwrap()
            .contains("synthetic provider failure")
    );
    let zero = results
        .outcomes
        .iter()
        .find(|outcome| outcome.module == "fixture")
        .unwrap();
    assert_eq!(zero.kind, SourceOutcomeKind::ValidZero);
    assert_eq!(zero.found, Some(0));
    assert!(record.modules_run.contains(&"graph_exec".to_owned()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn graph_schema_failure_is_not_misreported_as_empty_success() {
    let target = CrawlTarget {
        kind: ScanKind::Ip,
        selector: "1.1.1.1".into(),
    };
    let failure = failed_lookup_step(
        &target,
        "graph_exec",
        SourceOutcomeKind::SchemaDrift,
        "task lookup-0000: missing output envelope",
    );
    assert!(failure.entities.is_empty());
    assert_eq!(failure.outcomes.len(), 1);
    assert_eq!(failure.outcomes[0].kind, SourceOutcomeKind::SchemaDrift);
    assert!(failure.outcomes[0].found.is_none());
    assert!(!failure.outcomes[0].kind.is_accepted());
}

#[test]
fn independent_recursive_lookups_use_bounded_graph_concurrency() {
    use std::sync::atomic::AtomicUsize;

    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (service, dir) = with_lookup(
        "graph-concurrency",
        Arc::new({
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            move |kind: ScanKind, selector: &str, _: &Selection| {
                if kind == ScanKind::Domain {
                    let evidence = Evidence::new(
                        EvidenceProvenance::for_scan("test", "seed"),
                        "discovered address",
                    );
                    return Ok(LookupOutput {
                        entities: ["1.1.1.1", "8.8.8.8"]
                            .into_iter()
                            .map(|ip| {
                                Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                    .evidence(evidence.clone())
                                    .build()
                            })
                            .collect(),
                        ..LookupOutput::default()
                    });
                }
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(100));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(LookupOutput {
                    text: format!("{} {selector}", kind.command()),
                    ..LookupOutput::default()
                })
            }
        }),
    );
    let record = service
        .run(&ScanRequest {
            target: "example.org".into(),
            kind: Some("domain".into()),
            options: ScanOptions {
                depth: 1,
                ..ScanOptions::default()
            },
            ..ScanRequest::default()
        })
        .unwrap();
    assert_eq!(record.status, ScanStatus::Finished);
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    let log = service.store().log(&record.id).unwrap();
    assert!(log.iter().any(|entry| entry.component == "graph_exec"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn graph_reducer_distinguishes_stop_from_actual_task_failure() {
    let (service, dir) = with_lookup(
        "graph-cancel-reduction",
        Arc::new(|_: ScanKind, _: &str, _: &Selection| Ok(LookupOutput::default())),
    );
    let (record, _) = service
        .create(&ScanRequest {
            target: "example.org".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let options = ScanOptions::default();
    let selection = chosen(&options).unwrap();
    let scan_plan = plan("example.org", Some("domain")).unwrap();
    let target = CrawlTarget {
        kind: ScanKind::Ip,
        selector: "1.1.1.1".into(),
    };
    let mut collector = ScanCollector::new(&service, &record.id, &scan_plan, &options, &selection);
    service.state().aborts.insert(record.id.clone());
    let cancelled = crate::graph_exec::TaskRecord {
        state: TaskState::Cancelled,
        error: Some("scan cancelled before dispatch".into()),
        ..crate::graph_exec::TaskRecord::default()
    };
    let stopped = collector.reduce_graph_record(&target, "lookup-0000", &cancelled);
    assert!(stopped.entities.is_empty());
    assert!(stopped.outcomes.is_empty());
    assert_eq!(collector.errors, 0);
    assert_eq!(collector.ran, 0);
    let log = service.store().log(&record.id).unwrap();
    assert!(
        log.iter()
            .any(|entry| entry.message.contains("cancelled by scan stop"))
    );

    service.state().aborts.remove(&record.id);
    let failed = crate::graph_exec::TaskRecord {
        state: TaskState::Failed,
        error: Some("synthetic execution failure".into()),
        ..crate::graph_exec::TaskRecord::default()
    };
    let outcome = collector.reduce_graph_record(&target, "lookup-0001", &failed);
    assert_eq!(collector.errors, 1);
    assert_eq!(outcome.outcomes.len(), 1);
    assert_eq!(outcome.outcomes[0].kind, SourceOutcomeKind::Inconclusive);
    assert!(
        outcome.outcomes[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("synthetic execution failure")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_scans_share_lookup_capacity_without_disabling_graph_parallelism() {
    use std::sync::atomic::AtomicUsize;

    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (service, dir) = with_lookup(
        "shared-lookup-capacity",
        Arc::new({
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let calls = Arc::clone(&calls);
            move |kind: ScanKind, selector: &str, _: &Selection| {
                if kind == ScanKind::Domain {
                    let evidence = Evidence::new(
                        EvidenceProvenance::for_scan("test", "seed"),
                        "discovered address",
                    );
                    return Ok(LookupOutput {
                        entities: ["1.1.1.1", "8.8.8.8"]
                            .into_iter()
                            .map(|ip| {
                                Entity::builder(EntityKind::IpAddress, ip, 0.95, "test")
                                    .evidence(evidence.clone())
                                    .build()
                            })
                            .collect(),
                        ..LookupOutput::default()
                    });
                }
                let inside = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(inside, Ordering::SeqCst);
                calls.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(80));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(LookupOutput {
                    text: format!("completed-{selector}"),
                    ..LookupOutput::default()
                })
            }
        }),
    );
    let request = |target: &str| ScanRequest {
        target: target.into(),
        kind: Some("domain".into()),
        options: ScanOptions {
            depth: 1,
            ..ScanOptions::default()
        },
        ..ScanRequest::default()
    };
    let first = service.start(&request("first.example.org")).unwrap();
    let second = service.start(&request("second.example.org")).unwrap();
    for id in [&first.id, &second.id] {
        let record = service
            .wait(id, Instant::now() + Duration::from_secs(15))
            .unwrap();
        assert_eq!(record.status, ScanStatus::Finished);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(peak.load(Ordering::SeqCst) <= MAX_ACTIVE_LOOKUPS);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn targets_route_to_kinds_and_spiderfoot_types() {
    for (target, kind, kind_word, sf_type) in [
        ("example.com", None, "domain", "INTERNET_NAME"),
        ("1.1.1.1", None, "ip", "IP_ADDRESS"),
        ("2606:4700:4700::1111", None, "ip", "IPV6_ADDRESS"),
        ("jane@example.org", None, "email", "EMAILADDR"),
        ("+61412345678", None, "phone", "PHONE_NUMBER"),
        ("Jane Citizen", None, "people", "HUMAN_NAME"),
        (
            "jane@example.org",
            Some("exposure"),
            "exposure",
            "EMAILADDR",
        ),
        ("00:11:22:33:44:55", None, "network", "HSE_MAC_ADDRESS"),
    ] {
        let planned = plan(target, kind).unwrap_or_else(|error| panic!("{target}: {error}"));
        assert_eq!(planned.kind.command(), kind_word, "{target}");
        assert_eq!(planned.target_type, sf_type, "{target}");
    }
    assert!(plan("x".repeat(MAX_TARGET_BYTES + 1).as_str(), None).is_err());
    let _ = SourceOutcomeKind::Success;
}

#[test]
fn a_skipped_keyed_source_is_logged_as_information_and_is_not_a_scan_error() {
    for outcome in [
        SourceExecutionOutcome::valid_zero("fixture", 7),
        SourceExecutionOutcome::not_configured("fixture", 7),
    ] {
        assert!(!is_error_outcome(&outcome), "{outcome:?}");
        assert_eq!(outcome_log_level(&outcome), LogLevel::Info, "{outcome:?}");
    }
    for kind in [
        SourceOutcomeKind::AuthRequired,
        SourceOutcomeKind::RateLimited,
        SourceOutcomeKind::Inconclusive,
    ] {
        let outcome = SourceExecutionOutcome::failed("fixture", 7, kind, None, "failure");
        assert!(is_error_outcome(&outcome), "{outcome:?}");
        assert_eq!(outcome_log_level(&outcome), LogLevel::Error, "{outcome:?}");
    }
}

#[test]
fn contradictory_source_counts_are_errors_across_scan_paths_and_logs() {
    for (kind, found) in [
        (SourceOutcomeKind::Success, Some(0)),
        (SourceOutcomeKind::ValidZero, Some(2)),
    ] {
        let outcome = SourceExecutionOutcome::observed(
            "provider",
            7,
            kind,
            Some(200),
            found,
            "count mismatch",
        );
        assert!(!outcome.is_accepted(), "{outcome:?}");
        assert!(is_error_outcome(&outcome), "{outcome:?}");
        assert_eq!(outcome_log_level(&outcome), LogLevel::Error);
        let log = outcome_line(&outcome);
        assert!(log.contains("outcome_count_conflict=true"), "{log}");
        assert!(log.contains("count mismatch"), "{log}");
    }
    let accepted = SourceExecutionOutcome::success("provider", 7, 2);
    assert!(!is_error_outcome(&accepted));
    assert_eq!(outcome_log_level(&accepted), LogLevel::Info);
    assert!(!outcome_line(&accepted).contains("outcome_count_conflict"));
}
