//! Operable binary. No hardcoded workspace path.
//! `check` fails if a self-labeled technique enters Navigator or STIX.

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use huntsman_recon::au_id::{Identifier, classify as classify_id, is_valid_abn};
use huntsman_recon::classifier::classify as classify_indicator;
use huntsman_recon::classify::classify_response;
use huntsman_recon::confidence::{Classification, effective};
use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::egress::EgressPolicy;
use huntsman_recon::entity::{Evidence, EvidenceProvenance};
use huntsman_recon::error::Error;
use huntsman_recon::evidence_ancestry::{
    EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId,
};
use huntsman_recon::fetch::{Credential, FetchOptions, fetch};
use huntsman_recon::fetch_cli::{FETCH_USAGE, FetchArgs};
use huntsman_recon::fsio::write_atomic;
use huntsman_recon::geohash;
use huntsman_recon::geoint::{haversine_m, parse_latlon};
use huntsman_recon::http::{
    Request, TransportConfig, UreqTransport, origin_of, parse_http_uri, redact_url,
};
use huntsman_recon::identity::{PersonRecord, resolve};
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, HoldReason, IdentityResolutionDecision, ResolutionState,
};
use huntsman_recon::keys::{Keys, is_configured_value};
use huntsman_recon::ledger::{Claim, admitted, append, chain_intact, load_chain, save_chain, seal};
use huntsman_recon::lineage::{CandidateOutcome, MergeOutcome, Observation, resolve_with_lineage};
use huntsman_recon::navigator::layer;
use huntsman_recon::redact::{coarsen_latlon, scrub_secrets};
use huntsman_recon::search::{Document, load_dir, search, search_response, tokenize};
use huntsman_recon::session::{Candidate, ExecuteRecord, FalsifyRecord, Session, VerifyRecord};
use huntsman_recon::source_outcome::{
    SourceHealthAction, SourceOutcomeKind, classify_fetch, recommended_action,
};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle;
use huntsman_recon::termination::{FrontierState, TerminationSignals, decide_termination};

const USAGE: &str = "usage: huntsman-recon [check | geo LAT,LON LAT,LON | geohash LAT,LON [PRECISION] | coarsen LAT,LON | id TOKEN | search QUERY [DIR] | sources QUERY | classify STATUS BODY | fetch URL [options] | keys FILE | verify LEDGER]";
const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_NOINPUT: u8 = 66;
const EX_UNAVAILABLE: u8 = 69;
const EX_NOPERM: u8 = 77;
const EX_IOERR: u8 = 74;
const MAX_ARTIFACT_BYTES: u64 = 1_048_576;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("geo") => geo(args.next(), args.next()),
        Some("geohash") => geohash_cmd(args.next(), args.next().as_deref()),
        Some("coarsen") => coarsen_cmd(args.next()),
        Some("id") => id_cmd(args.next()),
        Some("search") => search_cmd(args.next(), args.next()),
        Some("sources") => sources_cmd(args.next()),
        Some("classify") => classify(args.next(), args.next()),
        Some("fetch") => fetch_cmd(&args.collect::<Vec<_>>()),
        Some("keys") => keys_cmd(args.next()),
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

fn geohash_cmd(pair: Option<String>, precision: Option<&str>) -> ExitCode {
    let Some(pair) = pair else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon geohash LAT,LON [PRECISION]",
        );
    };
    let Ok((lat, lon)) = parse_latlon(&pair) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {pair}"));
    };
    let precision = match precision.map(str::parse::<usize>) {
        None => 7,
        Some(Ok(p)) => p,
        Some(Err(_)) => return fail(EX_DATAERR, "bad precision"),
    };
    match geohash::encode(lat, lon, precision) {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &e.to_string()),
    }
}

fn coarsen_cmd(pair: Option<String>) -> ExitCode {
    let Some(pair) = pair else {
        return fail(EX_USAGE, "usage: huntsman-recon coarsen LAT,LON");
    };
    match coarsen_latlon(&pair) {
        Some(coarse) => {
            println!("{coarse}");
            ExitCode::SUCCESS
        }
        None => fail(EX_DATAERR, &format!("bad coordinate: {pair}")),
    }
}

fn id_cmd(token: Option<String>) -> ExitCode {
    let Some(token) = token else {
        return fail(EX_USAGE, "usage: huntsman-recon id TOKEN");
    };
    match classify_id(&token) {
        Ok(Identifier::Abn { bare, acn }) => {
            println!("abn={bare}");
            println!("acn={}", acn.as_deref().unwrap_or("none"));
        }
        Ok(Identifier::Acn { bare }) => println!("acn={bare}"),
        Ok(Identifier::Bsb { bare, institution }) => {
            println!("bsb={bare}");
            println!("institution={}", institution.unwrap_or("unknown"));
        }
        Err(e) => return fail(EX_DATAERR, &e.to_string()),
    }
    ExitCode::SUCCESS
}

fn fetch_cmd(args: &[String]) -> ExitCode {
    let parsed = match FetchArgs::parse(args) {
        Ok(p) => p,
        Err(e) => return fail(EX_USAGE, &format!("{e}\n{FETCH_USAGE}")),
    };
    let credential = match build_credential(&parsed) {
        Ok(c) => c,
        Err(e) => return fail(EX_NOINPUT, &e.to_string()),
    };
    let transport = UreqTransport::new(&TransportConfig {
        timeout: parsed.timeout,
        egress: if parsed.allow_private {
            EgressPolicy::Unrestricted
        } else {
            EgressPolicy::PublicOnly
        },
        ..TransportConfig::default()
    });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let fetched = match fetch(
        &transport,
        Request::get(parsed.url.clone()),
        credential.as_ref(),
        &FetchOptions {
            max_redirects: parsed.max_redirects,
        },
        "cli",
        now,
    ) {
        Ok(f) => f,
        Err(e) => return fail(EX_NOPERM, &e.to_string()),
    };
    let kind = fetched.outcome.kind;
    println!(
        "status={} outcome={} action={} redirects={} url={}",
        fetched
            .outcome
            .http_status
            .map_or_else(|| "none".into(), |s| s.to_string()),
        serde_json::to_value(kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        serde_json::to_value(recommended_action(kind))
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        fetched.redirects,
        fetched.final_url,
    );
    if let Some(detail) = &fetched.outcome.detail {
        println!("detail={detail}");
    }
    if let Some(fp) = &fetched.credential_sent {
        println!("credential={}", &fp.as_str()[..12]);
    }
    match fetched.response {
        Some(response) => {
            if parsed.print_body {
                println!("{}", response.text());
            }
            ExitCode::SUCCESS
        }
        None => ExitCode::from(EX_UNAVAILABLE),
    }
}

fn build_credential(args: &FetchArgs) -> Result<Option<Credential>, Error> {
    let Some((slot, style)) = &args.auth else {
        return Ok(None);
    };
    let resolved = Keys::resolve(args.keys_file.as_deref(), env::var_os("HOME").as_deref())?;
    if let Some(warning) = &resolved.warning {
        eprintln!("{warning}");
    }
    let keys = resolved.keys;
    let secret = keys
        .get(slot)
        .ok_or_else(|| Error::Invalid(format!("credential {slot} is not configured")))?;
    let host = parse_http_uri(&args.url)?
        .host()
        .unwrap_or_default()
        .to_owned();
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: host,
        credential_slot: slot.clone(),
        approved_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        approval_provenance: "operator supplied --bearer/--header on the command line".into(),
    })?;
    Ok(Some(Credential::new(authority, secret, style.clone())?))
}

fn keys_cmd(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        return fail(EX_USAGE, "usage: huntsman-recon keys FILE");
    };
    match Keys::load(Path::new(&path)) {
        Ok(keys) => {
            for slot in keys.slots() {
                if let Some(secret) = keys.get(slot) {
                    println!(
                        "{slot} fingerprint={}",
                        &secret.fingerprint().as_str()[..12]
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_NOINPUT, &e.to_string()),
    }
}

fn search_cmd(query: Option<String>, dir: Option<String>) -> ExitCode {
    let Some(query) = query else {
        return fail(EX_USAGE, "usage: huntsman-recon search QUERY [DIR]");
    };
    if tokenize(&query).is_empty() {
        return fail(
            EX_USAGE,
            "query has no searchable term (words need two or more letters or digits)",
        );
    }
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

fn sources_cmd(query: Option<String>) -> ExitCode {
    let Some(query) = query else {
        return fail(EX_USAGE, "usage: huntsman-recon sources QUERY");
    };
    let classified = classify_indicator(&query);
    // Residual and unsupported kinds have no descriptors, so the empty-route check
    // is the gate. A confidence floor here would drop low-confidence but routable
    // kinds such as `@handle` usernames.
    let routes = routes_for(&classified.kind, &classified.value);
    if routes.is_empty() {
        return fail(EX_DATAERR, "no actionable source routes");
    }
    println!(
        "kind={} confidence={:.3} routes={}",
        classified.kind.as_str(),
        classified.confidence,
        routes.len()
    );
    for route in routes {
        println!(
            "source={} execution={} access={} url={}",
            route.source_id,
            route.execution.as_str(),
            route.access.as_str(),
            route.url
        );
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
    let kind = classify_fetch(status, &body);
    println!("{:?}", classify_response(status, &body));
    println!(
        "outcome={}",
        serde_json::to_value(kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    );
    println!(
        "action={}",
        serde_json::to_value(recommended_action(kind))
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    );
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

/// Gate 5, lineage half: families come from the response fields, not the collector.
/// Two collectors relaying one dump are one family and cannot auto-merge; a dump plus
/// an independent registry can, but only with a present, in-range probability.
/// Every observation and candidate comes back.
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
    let independent = IdentityResolutionDecision {
        supporting: vec!["dehashed-1".into(), "abr-1".into()],
        ..mirrors.clone()
    };
    let unscored = IdentityResolutionDecision {
        probability: None,
        ..independent.clone()
    };
    let nan = IdentityResolutionDecision {
        probability: Some(f64::NAN),
        ..independent.clone()
    };
    let resolution = resolve_with_lineage(
        observations.clone(),
        vec![mirrors, independent, unscored, nan],
        AutoMergePolicy::default(),
    )
    .map_err(|e| (5, e.to_string()))?;
    let [mirrors, independent, unscored, nan] = resolution.candidates.as_slice() else {
        return Err((5, "a merge candidate was dropped".into()));
    };
    gate(
        5,
        mirrors.independent_families.len() == 1 && mirrors.outcome != MergeOutcome::AutoMerge,
        "mirrors manufactured corroboration",
    )?;
    gate(
        5,
        independent.outcome == MergeOutcome::AutoMerge,
        "independent roots refused",
    )?;
    let held_for = |c: &CandidateOutcome, want: fn(&HoldReason) -> bool| matches!(&c.outcome, MergeOutcome::Held { reasons } if reasons.iter().any(want));
    gate(
        5,
        held_for(unscored, |r| *r == HoldReason::ProbabilityMissing)
            && held_for(nan, |r| matches!(r, HoldReason::ProbabilityInvalid { .. })),
        "merge without a valid probability",
    )?;
    gate(
        5,
        resolution
            .observations
            .iter()
            .map(|o| &o.observation)
            .eq(&observations),
        "observation dropped or re-attributed",
    )
}

/// Gate 5, graph half: the hand-built ancestry graph and `allows_automatic_merge`, the
/// exact path `resolve::automatic_clusters` takes in production. Unlike the lineage
/// graph (one root plus relay nodes), it has an explicit parent chain and a root that
/// supports a candidate directly. Two mirrors of one dump are one family; a mirror plus
/// an independent registry root are two.
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
            .map_err(|e| (5, e.to_string()))?;
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
        independent.allows_automatic_merge(&graph, AutoMergePolicy::default()),
        "independent roots refused (ancestry graph)",
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
