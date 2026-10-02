//! Operable offline binary. No hardcoded workspace path.
//! `check` fails if a self-labeled technique enters Navigator.

use std::env;
use std::fs;
use std::process::ExitCode;

use huntsman_recon::classify::classify_response;
use huntsman_recon::geoint::{haversine_m, parse_latlon};
use huntsman_recon::identity::{resolve, PersonRecord};
use huntsman_recon::ledger::{append, chain_intact, seal, Claim};
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
    let _ = fs::write("var/navigator.json", serde_json::to_string_pretty(&nav).unwrap_or_default());
    println!("accepted techniques=0");
    println!("brisbane_sydney_m={meters:.0}");
    ExitCode::SUCCESS
}
