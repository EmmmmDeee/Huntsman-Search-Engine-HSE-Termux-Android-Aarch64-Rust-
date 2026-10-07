//! Offline self-acceptance gates for the `huntsman-recon check` command.
//!
//! Kept separate from CLI dispatch so acceptance logic can evolve and be tested
//! without further growing the binary entrypoint.

use super::{
    ArtifactId, AutoMergePolicy, Candidate, CandidateOutcome, Claim, Classification, EgressPolicy,
    Evidence, EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceLevel, EvidenceNodeId,
    EvidenceProvenance, ExecuteRecord, ExitCode, FalsifyRecord, FrontierState, HoldReason,
    IdentityResolutionDecision, IndependenceBasis, IndependenceEvidence, MergeOutcome, Observation,
    Path, PersonRecord, ResolutionState, Session, SourceHealthAction, SourceOutcomeKind, Status,
    TerminationSignals, VerifyRecord, EX_IOERR, MAX_ARTIFACT_BYTES, append, bundle,
    chain_intact, classify_fetch, classify_response, decide_termination, directive_lock, effective,
    engineering_command, fail, geohash, haversine_m, is_configured_value, is_valid_abn,
    layer, load_chain, origin_of, parse_latlon, recommended_action, redact_url, resolve,
    resolve_with_lineage, save_chain, scrub_secrets, search_response, seal, write_atomic,
};

/// Self-acceptance. Each gate has its own exit code; every artifact is regenerated, never left stale.
pub(super) fn check() -> ExitCode {
    match run_check() {
        Ok(meters) => {
            println!("command_hierarchy=accepted");
            println!("selftest_admitted_techniques=0");
            println!("brisbane_sydney_m={meters:.0}");
            ExitCode::SUCCESS
        }
        Err((code, msg)) => fail(code, &format!("check failed: {msg}")),
    }
}

type Gate = Result<(), (u8, String)>;

fn gate(code: u8, ok: bool, msg: &str) -> Gate {
    if ok {
        Ok(())
    } else {
        Err((code, msg.to_owned()))
    }
}

fn run_check() -> Result<f64, (u8, String)> {
    engineering_command::validate().map_err(|message| (12, message.to_owned()))?;
    if Path::new(directive_lock::CANONICAL).is_file() {
        directive_lock::verify_at(Path::new(".")).map_err(|message| (12, message))?;
    }
    let (blat, blon) = parse_latlon("-27.4698,153.0251").map_err(|e| (2, e.to_string()))?;
    let (slat, slon) = parse_latlon("-33.8688,151.2093").map_err(|e| (2, e.to_string()))?;
    let meters = haversine_m(blat, blon, slat, slon);
    gate(
        2,
        (700_000.0..760_000.0).contains(&meters),
        "brisbane-sydney outside band",
    )?;

    check_offline_gates()?;

    let geo = seal(&Claim {
        claim: format!("brisbane-sydney haversine {meters:.0} m inside band"),
        source: "published city centroids".into(),
        component: "src/geoint.rs".into(),
        technique_id: Some("T1591".into()),
        status: Status::Verified,
        evidence_level: EvidenceLevel::DirectObservation,
        does_not_show: "not T1591 and not a survey".into(),
    });
    let wall = append(
        &geo.hash,
        &Claim {
            claim: "challenge page is not a result".into(),
            source: "src/classify.rs".into(),
            component: "src/classify.rs".into(),
            technique_id: None,
            status: Status::Verified,
            evidence_level: EvidenceLevel::Reproduction,
            does_not_show: "does not bypass the wall".into(),
        },
    );
    let entries = vec![geo, wall];
    gate(9, chain_intact(&entries), "fresh chain not intact")?;

    let nav = layer(&entries);
    gate(
        7,
        nav["techniques"].as_array().is_some_and(Vec::is_empty),
        "self-labeled technique entered Navigator",
    )?;
    let stix = bundle(&entries);
    gate(
        8,
        stix["objects"].as_array().is_some_and(Vec::is_empty),
        "self-labeled technique entered STIX",
    )?;

    let ledger_path = Path::new("var/ledger.json");
    save_chain(ledger_path, &entries).map_err(|e| (9, e.to_string()))?;
    let reloaded = load_chain(ledger_path).map_err(|e| (9, e.to_string()))?;
    gate(9, reloaded == entries, "ledger round-trip mismatch")?;
    let tip = entries.last().map_or("", |e| e.hash.as_str());

    check_session(meters, tip)?;

    for (name, value) in [
        ("var/navigator.json", &nav),
        ("var/stix-bundle.json", &stix),
    ] {
        let body = serde_json::to_vec_pretty(value).map_err(|e| (EX_IOERR, e.to_string()))?;
        write_atomic(Path::new(name), &body, MAX_ARTIFACT_BYTES)
            .map_err(|e| (EX_IOERR, e.to_string()))?;
    }
    Ok(meters)
}

/// Classifier, search, and identity gates. Decided without a network.
fn check_offline_gates() -> Gate {
    gate(
        3,
        !classify_response(200, "<html>just a moment cloudflare</html>").is_result(),
        "challenge scored as result",
    )?;
    gate(
        3,
        !classify_response(429, "challenges.cloudflare.com").is_wall(),
        "429 classified as wall",
    )?;
    gate(
        3,
        search_response(
            200,
            "<html>just a moment cloudflare</html>",
            "brisbane",
            "remote",
        )
        .is_empty(),
        "challenge page produced a hit",
    )?;

    let people = resolve(&[
        PersonRecord {
            id: "a".into(),
            name: "Same".into(),
            emails: vec!["a@ex.com".into()],
            handles: vec![],
        },
        PersonRecord {
            id: "b".into(),
            name: "Same".into(),
            emails: vec!["b@ex.com".into()],
            handles: vec![],
        },
    ]);
    gate(4, people.len() == 2, "shared name merged identities")?;
    check_overlay_gates()?;
    check_rebuilt_gates()?;
    check_network_gates()
}

/// Rebuilt monolith utilities: strict identifiers, geohash round-trip, weak sources
/// do not reach Verified, overlapping secrets leave no fragment.
fn check_rebuilt_gates() -> Gate {
    gate(
        10,
        is_valid_abn("51 824 753 556") && !is_valid_abn("5182 hello 4753556"),
        "ABN grouping not strict",
    )?;
    let hash = geohash::encode(-27.4698, 153.0251, 9).map_err(|e| (10, e.to_string()))?;
    let cell = geohash::decode(&hash).map_err(|e| (10, e.to_string()))?;
    gate(
        10,
        cell.contains(-27.4698, 153.0251),
        "geohash cell misses its point",
    )?;
    gate(
        10,
        Classification::from_effective(effective(0.05, 5)) == Classification::Candidate,
        "weak sources reached a tier",
    )?;
    let scrubbed = scrub_secrets("xxabcdefyy", &["abcd", "cdef"]);
    gate(
        10,
        scrubbed == "xx[redacted]yy",
        "secret fragment survived scrubbing",
    )
}

/// Network layer, decided without a socket: egress refuses the operator's own
/// network, credentials never reach a foreign origin, placeholders are not keys.
fn check_network_gates() -> Gate {
    let refused = [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "::1",
        "fd00::1",
        "::ffff:192.168.0.1",
    ];
    gate(
        11,
        refused.iter().all(|s| {
            s.parse()
                .is_ok_and(|ip| !EgressPolicy::PublicOnly.permits(ip))
        }) && EgressPolicy::PublicOnly.permits(std::net::IpAddr::from([1, 1, 1, 1])),
        "egress policy admits a private address or refuses a public one",
    )?;
    gate(
        11,
        origin_of("https://a.example/x") != origin_of("https://a.example.evil.test/x")
            && origin_of("https://a.example/x") != origin_of("http://a.example/x"),
        "origins not distinguished",
    )?;
    gate(
        11,
        !is_configured_value("insert_key_here") && is_configured_value("k3y-8f2a91"),
        "credential placeholder accepted as configured",
    )?;
    let with_userinfo = format!("https://{}@a.example/x?{}=v", "user:pw", "api_key");
    gate(
        11,
        redact_url(&with_userinfo) == "https://a.example/x?[redacted]",
        "url redaction leaks userinfo or query",
    )
}

/// Refactor-overlay foundations: a WAF is not an auth failure, mirrors count once,
/// delayed work is not a fixed point.
fn check_overlay_gates() -> Gate {
    let waf = classify_fetch(403, "<html>checking your browser cloudflare</html>");
    gate(
        5,
        waf == SourceOutcomeKind::BotWaf,
        "403 challenge not classified as bot/WAF",
    )?;
    gate(
        5,
        recommended_action(waf) != SourceHealthAction::RequireCredential,
        "WAF demanded credentials",
    )?;

    check_lineage_gate()?;
    check_ancestry_graph_gate()?;

    let delayed = FrontierState {
        delayed_retry_work: 1,
        ..FrontierState::default()
    };
    gate(
        5,
        decide_termination(delayed, TerminationSignals::default()).is_none(),
        "delayed work called a fixed point",
    )?;
    Ok(())
}

/// Gate 5, lineage half: family labels come from response fields, not collectors.
/// They remain useful diagnostics but cannot by themselves prove independent routes.
/// Every observation and candidate comes back, and lineage-only pairs stay held.
fn check_lineage_gate() -> Gate {
    let record = |id: &str, collector: &str, field: &str, value: &str| Observation {
        id: id.into(),
        evidence: Evidence::new(EvidenceProvenance::new(collector), "fixture record")
            .with_attr(field, value),
    };
    let observations = vec![
        record("hibp-1", "hibp", "breach", "Adobe 2013"),
        record("dehashed-1", "dehashed", "dbname", "ADOBE  2013"),
        record("abr-1", "abn_lookup", "registry", "company registry"),
    ];
    let mirrors = IdentityResolutionDecision {
        left_entity_uid: "a".into(),
        right_entity_uid: "b".into(),
        state: ResolutionState::Match,
        probability: Some(0.99),
        supporting: vec!["hibp-1".into(), "dehashed-1".into()],
        contradicting: vec![],
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 0,
    };
    let disjoint_labels = IdentityResolutionDecision {
        supporting: vec!["dehashed-1".into(), "abr-1".into()],
        ..mirrors.clone()
    };
    let unscored = IdentityResolutionDecision {
        probability: None,
        ..disjoint_labels.clone()
    };
    let nan = IdentityResolutionDecision {
        probability: Some(f64::NAN),
        ..disjoint_labels.clone()
    };
    let resolution = resolve_with_lineage(
        observations.clone(),
        vec![mirrors, disjoint_labels, unscored, nan],
        AutoMergePolicy::default(),
    )
    .map_err(|e| (5, e.to_string()))?;
    let [mirrors, disjoint_labels, unscored, nan] = resolution.candidates.as_slice() else {
        return Err((5, "a merge candidate was dropped".into()));
    };
    gate(
        5,
        mirrors.independent_families.len() == 1 && mirrors.outcome != MergeOutcome::AutoMerge,
        "mirrors manufactured corroboration",
    )?;
    let held_for = |candidate: &CandidateOutcome, want: fn(&HoldReason) -> bool| matches!(&candidate.outcome, MergeOutcome::Held { reasons } if reasons.iter().any(want));
    gate(
        5,
        disjoint_labels.independent_families.len() == 2
            && held_for(disjoint_labels, |reason| {
                *reason
                    == HoldReason::InsufficientIndependentFamilies {
                        found: 1,
                        required: 2,
                    }
            }),
        "lineage labels manufactured independence",
    )?;
    gate(
        5,
        held_for(unscored, |reason| *reason == HoldReason::ProbabilityMissing)
            && held_for(nan, |reason| {
                matches!(reason, HoldReason::ProbabilityInvalid { .. })
            }),
        "merge without a valid probability",
    )?;
    gate(
        5,
        resolution
            .observations
            .iter()
            .map(|observation| &observation.observation)
            .eq(&observations),
        "observation dropped or re-attributed",
    )
}

/// Gate 5, graph half: the hand-built ancestry graph exercises both failure and success.
/// Shared ancestry is dependent; disjoint roots are still unknown until an explicit,
/// versioned independence record backed by an artifact is inserted.
fn check_ancestry_graph_gate() -> Gate {
    let mut graph = EvidenceAncestryGraph::default();
    let nodes: [(&str, &str, &[&str]); 4] = [
        ("dump", "Adobe 2013", &[]),
        ("mirror-a", "provider-a", &["dump"]),
        ("mirror-b", "provider-b", &["dump"]),
        ("registry", "company registry", &[]),
    ];
    for (id, family, parents) in nodes {
        graph
            .insert(EvidenceAncestryNode {
                id: id.into(),
                source_family: family.into(),
                parents: parents.iter().copied().map(EvidenceNodeId::from).collect(),
                derived: !parents.is_empty(),
            })
            .map_err(|error| (5, error.to_string()))?;
    }
    let mirrors = IdentityResolutionDecision {
        left_entity_uid: "a".into(),
        right_entity_uid: "b".into(),
        state: ResolutionState::Match,
        probability: Some(0.99),
        supporting: vec!["mirror-a".into(), "mirror-b".into()],
        contradicting: vec![],
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 0,
    };
    gate(
        5,
        !mirrors.allows_automatic_merge(&graph, AutoMergePolicy::default()),
        "mirrors manufactured corroboration (ancestry graph)",
    )?;
    let independent = IdentityResolutionDecision {
        supporting: vec!["mirror-a".into(), "registry".into()],
        ..mirrors
    };
    gate(
        5,
        !independent.allows_automatic_merge(&graph, AutoMergePolicy::default()),
        "unproven disjoint roots auto-merged (ancestry graph)",
    )?;
    graph
        .insert_independence_evidence(IndependenceEvidence {
            left_root: "dump".into(),
            right_root: "registry".into(),
            basis: IndependenceBasis::ExplicitUpstreamProvenance,
            method_id: "check:explicit-upstream".into(),
            method_version: 1,
            supporting_artifact_ids: [ArtifactId::from("sha256:check-provenance")]
                .into_iter()
                .collect(),
            observed_at_unix: 1,
        })
        .map_err(|error| (5, error.to_string()))?;
    gate(
        5,
        independent.allows_automatic_merge(&graph, AutoMergePolicy::default()),
        "explicitly proven independent roots refused (ancestry graph)",
    )
}

/// RCVF recorder gate: full terminate refuses an empty tip and binds to the real one.
fn check_session(meters: f64, tip: &str) -> Gate {
    let mut session = Session::new("check");
    session.apply_recover(
        "local-first core",
        "chain bound to session",
        "network only through the guarded fetch layer",
        "terminate only with tip",
    );
    let recorded = session
        .add_candidate(Candidate {
            statement: "hash chain".into(),
            alternatives: vec!["independent hashes".into()],
            reverse_observation: "reorder undetected".into(),
        })
        .and_then(|()| {
            session.add_falsify(FalsifyRecord {
                attack: "terminate without tip".into(),
                test: "full terminate empty tip".into(),
                result: "refused".into(),
            })
        })
        .and_then(|()| {
            session.add_execute(ExecuteRecord {
                action: "check".into(),
                observed: format!("{meters:.0}"),
                component: "src/geoint.rs".into(),
            })
        })
        .and_then(|()| {
            session.add_verify(VerifyRecord {
                claim: "tip binds the session".into(),
                status: Status::Verified,
                evidence_level: EvidenceLevel::DirectObservation,
                does_not_show: "not a live collection".into(),
            })
        });
    recorded.map_err(|e| (6, e.to_string()))?;
    gate(
        6,
        session
            .terminate("no handset run".into(), false, "")
            .is_err(),
        "terminate accepted empty tip",
    )?;
    session
        .terminate("no handset run".into(), false, tip)
        .map_err(|e| (6, e.to_string()))?;
    gate(6, session.bound_to(tip), "session not bound to tip")?;
    Ok(())
}
