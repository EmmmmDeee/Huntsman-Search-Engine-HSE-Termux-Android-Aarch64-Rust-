//! End-to-end acceptance for the reconstructed crate.

use std::fs;

use huntsman_recon::classify::classify_response;
use huntsman_recon::ledger::{seal, Claim};
use huntsman_recon::navigator::layer;
use huntsman_recon::session::{Candidate, FalsifyRecord, Session, VerifyRecord};
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle;
use huntsman_recon::store::Store;
use huntsman_recon::Error;

#[test]
fn terminate_refuses_empty_and_store_roundtrip() {
    let mut empty = Session::new("empty");
    let err = empty.terminate("still unknown".into(), false).expect_err("refuse");
    assert!(matches!(err, Error::TerminateRefused(_)));
    let err = empty.terminate("  ".into(), true).expect_err("residual");
    assert!(matches!(err, Error::MissingField(_)));

    let mut session = Session::new("full");
    session.apply_recover("obj", "out", "no network", "terminate");
    session.add_candidate(Candidate {
        statement: "json store".into(),
        alternatives: vec!["sqlite".into()],
        reverse_observation: "lost after restart".into(),
    }).unwrap();
    session.add_falsify(FalsifyRecord {
        attack: "empty terminate".into(),
        test: "terminate".into(),
        result: "refused".into(),
    }).unwrap();
    session.add_verify(VerifyRecord {
        claim: "gate holds".into(),
        status: Status::Verified,
        evidence_level: EvidenceLevel::DirectObservation,
        does_not_show: "not the monolith".into(),
    }).unwrap();
    session.terminate("egress blocked".into(), false).unwrap();

    let root = std::env::temp_dir().join(format!("huntsman-recon-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let store = Store::new(&root);
    store.save(&session).unwrap();
    let loaded = store.load(&session.id).unwrap();
    assert!(loaded.termination.is_some());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn navigator_and_stix_drop_challenge_and_catalog() {
    let wall = classify_response(403, "<html>checking your browser cloudflare</html>");
    assert!(wall.is_wall());
    let admitted = seal(&Claim {
        claim: "challenge is not a result".into(),
        source: "src/classify.rs tests".into(),
        component: "src/classify.rs".into(),
        technique_id: Some("T1592".into()),
        status: Status::Verified,
        evidence_level: EvidenceLevel::Reproduction,
        does_not_show: "does not bypass the wall".into(),
    });
    let catalog = seal(&Claim {
        claim: "mapped only".into(),
        source: "attack catalog".into(),
        component: "none".into(),
        technique_id: Some("T1595".into()),
        status: Status::Verified,
        evidence_level: EvidenceLevel::Assertion,
        does_not_show: "no runnable method".into(),
    });
    let nav = layer(&[admitted.clone(), catalog.clone()]);
    let ids: Vec<&str> = nav["techniques"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["techniqueID"].as_str())
        .collect();
    assert_eq!(ids, vec!["T1592"]);
    assert_eq!(bundle(&[admitted, catalog])["objects"].as_array().unwrap().len(), 1);
}
