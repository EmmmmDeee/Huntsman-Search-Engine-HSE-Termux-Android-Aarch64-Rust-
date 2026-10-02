//! Operable offline binary. No hardcoded workspace path.
//! `check` fails if a self-labeled technique enters Navigator.

use std::env;
use std::fs;
use std::process::ExitCode;

use huntsman_recon::classify::classify_response;
use huntsman_recon::geoint::{haversine_m, parse_latlon};
use huntsman_recon::identity::{resolve, PersonRecord};
use huntsman_recon::ledger::{append, chain_intact, load_chain, save_chain, seal, Claim};
use huntsman_recon::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use huntsman_recon::navigator::layer;
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("geo") => geo(args.next(), args.next()),
        Some("classify") => classify(args.next(), args.next()),
        Some("check") | None => check(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            ExitCode::from(64)
        }
    }
}

fn geo(a: Option<String>, b: Option<String>) -> ExitCode {
    let (Some(a), Some(b)) = (a, b) else {
        eprintln!("usage: huntsman-recon geo LAT,LON LAT,LON");
        return ExitCode::from(64);
    };
    let Ok((lat1, lon1)) = parse_latlon(&a) else {
        eprintln!("bad coordinate: {a}");
        return ExitCode::from(65);
    };
    let Ok((lat2, lon2)) = parse_latlon(&b) else {
        eprintln!("bad coordinate: {b}");
        return ExitCode::from(65);
    };
    println!("{:.0}", haversine_m(lat1, lon1, lat2, lon2));
    ExitCode::SUCCESS
}

fn classify(status: Option<String>, body: Option<String>) -> ExitCode {
    let (Some(status), Some(body)) = (status, body) else {
        eprintln!("usage: huntsman-recon classify STATUS BODY");
        return ExitCode::from(64);
    };
    let Ok(status) = status.parse::<u16>() else {
        eprintln!("bad status");
        return ExitCode::from(65);
    };
    let outcome = classify_response(status, &body);
    println!("{outcome:?}");
    ExitCode::SUCCESS
}

fn check() -> ExitCode {
    let (blat, blon) = parse_latlon("-27.4698,153.0251").expect("latlon");
    let (slat, slon) = parse_latlon("-33.8688,151.2093").expect("latlon");
    let meters = haversine_m(blat, blon, slat, slon);
    if !(700_000.0..760_000.0).contains(&meters) {
        return ExitCode::from(2);
    }
    if classify_response(200, "<html>just a moment cloudflare</html>").is_result() {
        return ExitCode::from(3);
    }
    if classify_response(429, "challenges.cloudflare.com").is_wall() {
        return ExitCode::from(3);
    }
    let people = resolve(&[
        PersonRecord { id: "a".into(), name: "Same".into(), emails: vec!["a@ex.com".into()], handles: vec![] },
        PersonRecord { id: "b".into(), name: "Same".into(), emails: vec!["b@ex.com".into()], handles: vec![] },
    ]);
    if people.len() != 2 {
        return ExitCode::from(4);
    }
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
    if !chain_intact(&entries) {
        return ExitCode::from(9);
    }
    let nav = layer(&entries);
    if nav["techniques"].as_array().is_none_or(|a| !a.is_empty()) {
        return ExitCode::from(7);
    }
    if !bundle(&entries)["objects"].as_array().is_none_or(Vec::is_empty) {
        return ExitCode::from(8);
    }
    let _ = fs::create_dir_all("var");
    let path = std::path::Path::new("var/ledger.json");
    if save_chain(path, &entries).is_err() {
        return ExitCode::from(9);
    }
    if load_chain(path).ok().as_deref() != Some(entries.as_slice()) {
        return ExitCode::from(9);
    }
    let tip = entries.last().map(|e| e.hash.as_str()).unwrap_or("");
    let mut session = Session::new("check");
    session.apply_recover(
        "offline core",
        "chain bound to session",
        "no network",
        "terminate only with tip",
    );
    if session.add_candidate(Candidate {
        statement: "hash chain".into(),
        alternatives: vec!["independent hashes".into()],
        reverse_observation: "reorder undetected".into(),
    }).is_err() {
        return ExitCode::from(6);
    }
    let _ = session.add_falsify(FalsifyRecord {
        attack: "terminate without tip".into(),
        test: "full terminate empty tip".into(),
        result: "refused".into(),
    });
    let _ = session.add_execute(ExecuteRecord {
        action: "check".into(),
        observed: format!("{meters:.0}"),
        component: "src/geoint.rs".into(),
    });
    let _ = session.add_verify(VerifyRecord {
        claim: "tip binds the session".into(),
        status: Status::Verified,
        evidence_level: EvidenceLevel::DirectObservation,
        does_not_show: "not a live collection".into(),
    });
    if session.terminate("no handset run".into(), false, "").is_ok() {
        return ExitCode::from(6);
    }
    if session.terminate("no handset run".into(), false, tip).is_err() || !session.bound_to(tip) {
        return ExitCode::from(6);
    }
    let _ = fs::write("var/navigator.json", serde_json::to_string_pretty(&nav).unwrap_or_default());
    println!("accepted techniques=0");
    println!("brisbane_sydney_m={meters:.0}");
    ExitCode::SUCCESS
}
