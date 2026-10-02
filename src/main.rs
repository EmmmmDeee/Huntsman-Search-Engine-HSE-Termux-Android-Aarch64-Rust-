//! Acceptance runner. Writes the ledger-derived Navigator and STIX next to the crate.
//! Exit 0 only if the interop gate keeps unverified rows out.

use std::fs;
use std::process::ExitCode;

use huntsman_recon::classify::classify_response;
use huntsman_recon::geoint::{colocated, haversine_m, parse_latlon, Fix};
use huntsman_recon::identity::{resolve, PersonRecord};
use huntsman_recon::ledger::{seal, Claim};
use huntsman_recon::navigator::layer;
use huntsman_recon::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle;

fn main() -> ExitCode {
    let mut session = Session::new("reconstruction");
    session.apply_recover(
        "strongest verifiable offline OSINT core",
        "ledger-gated identity, geoint, stix, navigator",
        "no network, no credentials, no active scan",
        "cargo test pass and gate excludes unverified",
    );
    if session.add_candidate(Candidate {
        statement: "single offline crate".into(),
        alternatives: vec!["absorb HSE monolith".into()],
        reverse_observation: "monolith requires keys and live providers".into(),
    }).is_err() {
        return ExitCode::from(1);
    }
    let _ = session.add_falsify(FalsifyRecord {
        attack: "catalog row scores as verified".into(),
        test: "navigator layer on assertion".into(),
        result: "technique absent".into(),
    });
    let _ = session.add_execute(ExecuteRecord {
        action: "haversine brisbane-sydney".into(),
        observed: "inside 700-760km band".into(),
        component: "src/geoint.rs".into(),
    });
    let (blat, blon) = parse_latlon("-27.4698,153.0251").expect("latlon");
    let (slat, slon) = parse_latlon("-33.8688,151.2093").expect("latlon");
    let meters = haversine_m(blat, blon, slat, slon);
    if !(700_000.0..760_000.0).contains(&meters) {
        return ExitCode::from(2);
    }
    let geo = seal(&Claim {
        claim: format!("brisbane-sydney haversine {meters:.0} m inside band"),
        source: "published city centroids".into(),
        component: "src/geoint.rs".into(),
        technique_id: Some("T1591".into()),
        status: Status::Verified,
        evidence_level: EvidenceLevel::DirectObservation,
        does_not_show: "not a survey and not a live collection".into(),
    });
    let catalog = seal(&Claim {
        claim: "SeekNow keyless search".into(),
        source: "docs/KEYLESS_RETRIEVAL_2026-10-02.md".into(),
        component: "not applicable".into(),
        technique_id: Some("T1592".into()),
        status: Status::NotApplicable,
        evidence_level: EvidenceLevel::PrimaryEvidence,
        does_not_show: "no hidden keyless endpoint".into(),
    });
    let wall = classify_response(200, "<html>just a moment cloudflare</html>");
    if wall.is_result() {
        return ExitCode::from(3);
    }
    let people = resolve(&[
        PersonRecord { id: "a".into(), name: "Same".into(), emails: vec!["a@ex.com".into()], handles: vec![] },
        PersonRecord { id: "b".into(), name: "Same".into(), emails: vec!["b@ex.com".into()], handles: vec![] },
    ]);
    if people.len() != 2 {
        return ExitCode::from(4);
    }
    let fixes = [
        Fix { id: "p".into(), lat: blat, lon: blon, at_unix: 10 },
        Fix { id: "q".into(), lat: slat, lon: slon, at_unix: 10 },
    ];
    if !colocated(&fixes, 1_000.0, 60).is_empty() {
        return ExitCode::from(5);
    }
    let _ = session.add_verify(VerifyRecord {
        claim: geo.claim.claim.clone(),
        status: Status::Verified,
        evidence_level: EvidenceLevel::DirectObservation,
        does_not_show: "not survey grade".into(),
    });
    if session.terminate("live retrieval still blocked".into(), false).is_err() {
        return ExitCode::from(6);
    }
    let entries = vec![geo, catalog];
    let nav = layer(&entries);
    let stix = bundle(&entries);
    if nav["techniques"].as_array().map(|a| a.len()) != Some(1) {
        return ExitCode::from(7);
    }
    if stix["objects"].as_array().map(|a| a.len()) != Some(1) {
        return ExitCode::from(8);
    }
    let _ = fs::create_dir_all("/workspace/artifacts/huntsman-recon/var");
    let _ = fs::write(
        "/workspace/artifacts/huntsman-recon/var/navigator.json",
        serde_json::to_string_pretty(&nav).unwrap_or_default(),
    );
    let _ = fs::write(
        "/workspace/artifacts/huntsman-recon/var/stix-bundle.json",
        serde_json::to_string_pretty(&stix).unwrap_or_default(),
    );
    println!("accepted techniques={}", nav["techniques"].as_array().map_or(0, Vec::len));
    println!("brisbane_sydney_m={meters:.0}");
    ExitCode::SUCCESS
}
