//! Operable offline binary. No hardcoded workspace path.
//! `check` fails if a self-labeled technique enters Navigator or STIX.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::classify::classify_response;
use huntsman_recon::fsio::write_atomic;
use huntsman_recon::geoint::{haversine_m, parse_latlon};
use huntsman_recon::identity::{PersonRecord, resolve};
use huntsman_recon::ledger::{Claim, admitted, append, chain_intact, load_chain, save_chain, seal};
use huntsman_recon::navigator::layer;
use huntsman_recon::search::{Document, load_dir, search, search_response};
use huntsman_recon::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle;

const USAGE: &str = "usage: huntsman-recon [check | geo LAT,LON LAT,LON | search QUERY [DIR] | classify STATUS BODY | verify LEDGER]";
const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_NOINPUT: u8 = 66;
const EX_IOERR: u8 = 74;
const MAX_ARTIFACT_BYTES: u64 = 1_048_576;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("geo") => geo(args.next(), args.next()),
        Some("search") => search_cmd(args.next(), args.next()),
        Some("classify") => classify(args.next(), args.next()),
        Some("verify") => verify(args.next()),
        Some("check") | None => check(),
        Some("help" | "-h" | "--help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => fail(EX_USAGE, &format!("unknown command: {other}\n{USAGE}")),
    }
}

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(code)
}

fn geo(a: Option<String>, b: Option<String>) -> ExitCode {
    let (Some(a), Some(b)) = (a, b) else {
        return fail(EX_USAGE, "usage: huntsman-recon geo LAT,LON LAT,LON");
    };
    let Ok((lat1, lon1)) = parse_latlon(&a) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {a}"));
    };
    let Ok((lat2, lon2)) = parse_latlon(&b) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {b}"));
    };
    println!("{:.0}", haversine_m(lat1, lon1, lat2, lon2));
    ExitCode::SUCCESS
}

fn search_cmd(query: Option<String>, dir: Option<String>) -> ExitCode {
    let Some(query) = query else {
        return fail(EX_USAGE, "usage: huntsman-recon search QUERY [DIR]");
    };
    let docs = if let Some(dir) = dir {
        match load_dir(Path::new(&dir)) {
            Ok(loaded) => {
                for skipped in &loaded.skipped {
                    eprintln!("skipped\t{}\t{}", skipped.path, skipped.reason);
                }
                loaded.docs
            }
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        }
    } else {
        vec![
            Document {
                id: "brisbane".into(),
                body: "Brisbane port radar sighting".into(),
                source: "fixture".into(),
            },
            Document {
                id: "sydney".into(),
                body: "Sydney harbour note".into(),
                source: "fixture".into(),
            },
        ]
    };
    let hits = search(&docs, &query);
    if hits.is_empty() {
        println!("hits=0");
    }
    for hit in &hits {
        println!("{}\t{}\t{}", hit.score, hit.id, hit.source);
    }
    ExitCode::SUCCESS
}

fn classify(status: Option<String>, body: Option<String>) -> ExitCode {
    let (Some(status), Some(body)) = (status, body) else {
        return fail(EX_USAGE, "usage: huntsman-recon classify STATUS BODY");
    };
    let Ok(status) = status.parse::<u16>() else {
        return fail(EX_DATAERR, "bad status");
    };
    println!("{:?}", classify_response(status, &body));
    ExitCode::SUCCESS
}

fn verify(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        return fail(EX_USAGE, "usage: huntsman-recon verify LEDGER");
    };
    match load_chain(Path::new(&path)) {
        Ok(entries) => {
            println!("entries={}", entries.len());
            println!("admitted={}", admitted(&entries).len());
            println!("tip={}", entries.last().map_or("none", |e| e.hash.as_str()));
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &e.to_string()),
    }
}

/// Self-acceptance. Each gate has its own exit code; every artifact is regenerated, never left stale.
fn check() -> ExitCode {
    match run_check() {
        Ok(meters) => {
            println!("accepted techniques=0");
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

/// Classifier, search, and identity gates. No network.
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
    Ok(())
}

/// RCVF recorder gate: full terminate refuses an empty tip and binds to the real one.
fn check_session(meters: f64, tip: &str) -> Gate {
    let mut session = Session::new("check");
    session.apply_recover(
        "offline core",
        "chain bound to session",
        "no network",
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
