use super::*;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

#[test]
fn source_summary_never_accepts_contradictory_saved_counts() {
    let outcomes = [
        SourceExecutionOutcome::valid_zero("valid", 1),
        SourceExecutionOutcome::observed(
            "bad_zero",
            2,
            SourceOutcomeKind::ValidZero,
            Some(200),
            Some(3),
            "positive count contradicts a verified zero",
        ),
        SourceExecutionOutcome::observed(
            "bad_success",
            3,
            SourceOutcomeKind::Success,
            Some(200),
            Some(0),
            "empty count contradicts a success",
        ),
    ];
    let summary = source_execution_summary(&outcomes);
    assert_eq!(summary["total"], 3);
    assert_eq!(summary["accepted"], 1);
    assert_eq!(summary["valid_zero"], 1);
    assert_eq!(summary["unresolved"], 2);
    assert_eq!(summary["inconsistent_accepted_count"], 2);
    assert_eq!(summary["all_recorded_sources_accepted"], false);
    let contradictory = source_execution_row(&outcomes[1]);
    assert_eq!(contradictory["outcome"], "valid_zero");
    assert_eq!(contradictory["outcome_count_conflict"], true);
    assert_eq!(contradictory["found"], 3);
    let ordinary = source_execution_row(&outcomes[0]);
    assert_eq!(ordinary["outcome_count_conflict"], false);
}

use crate::module_selection::Selection;
use crate::scan_route::ScanKind;
use crate::scan_service::LookupOutput;
use crate::scan_store::ScanStore;
use crate::source_outcome::SourceExecutionOutcome;
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hse-scan-api-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn api(tag: &str) -> (ScanApi, PathBuf) {
    api_holding(tag, &[crate::environment::SHODAN_KEY_ENV])
}

/// A scan API whose Settings read only the slots in `held` as holding a key.
fn api_holding(tag: &str, held: &'static [&'static str]) -> (ScanApi, PathBuf) {
    let dir = scratch(tag);
    let lookup = Arc::new(|_kind: ScanKind, selector: &str, _: &Selection| {
        let evidence = Evidence::new(EvidenceProvenance::for_scan("internetdb", "s"), "ports")
            .with_attr("ports", "22,443")
            .with_attr("vulns", "CVE-2021-44228,CVE-2014-0160");
        Ok(LookupOutput {
            text: "report".into(),
            entities: vec![
                Entity::builder(EntityKind::IpAddress, selector, 0.9, "s")
                    .evidence(evidence)
                    .build(),
            ],
            outcomes: vec![SourceExecutionOutcome::success("internetdb", 1, 1)],
        })
    });
    let service = ScanService::new(ScanStore::open(&dir).unwrap(), lookup);
    let slots: SlotCheck = Arc::new(move |slot: &str| held.contains(&slot));
    (
        ScanApi::new(service, Some(slots)).with_own_multi_export(),
        dir,
    )
}

fn body(response: &ApiResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

/// A scan whose process is gone reads ABORTED from the list and the scan page, and Stop
/// answers 202 rather than 409, so the page never shows a RUNNING row nobody can act on.
#[cfg(target_os = "linux")]
#[test]
fn a_scan_whose_process_died_lists_as_aborted_and_can_be_stopped() {
    let (api, dir) = api("dead-owner-api");
    let finished = api
        .service()
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap();
    let mut orphan = api.service().store().get(&finished.id).unwrap();
    orphan.status = ScanStatus::Running;
    orphan.ended = None;
    // No process has this pid, so the owner that recorded it is gone.
    orphan.owner = Some(u32::MAX);
    orphan.owner_started = None;
    api.service().store().update(&orphan).unwrap();
    let listed = body(&api.handle("GET", "/api/scans", ""));
    assert_eq!(listed[0]["status"], "ABORTED", "{listed}");
    let shown = body(&api.handle("GET", &format!("/api/scans/{}", finished.id), ""));
    assert_eq!(shown["status"], "ABORTED", "{shown}");
    let log = body(&api.handle("GET", &format!("/api/scans/{}/log", finished.id), ""));
    assert!(
        log.as_array().unwrap().iter().any(|entry| {
            entry["message"]
                .as_str()
                .is_some_and(|m| m.contains(&format!("pid {}", u32::MAX)))
        }),
        "{log}"
    );
    // A second orphan: Stop settles it instead of refusing it.
    let mut again = api.service().store().get(&finished.id).unwrap();
    again.status = ScanStatus::Running;
    again.ended = None;
    again.owner = Some(u32::MAX);
    api.service().store().update(&again).unwrap();
    let stopped = api.handle("POST", &format!("/api/scans/{}/stop", finished.id), "");
    assert_eq!(
        stopped.status,
        202,
        "{}",
        String::from_utf8_lossy(&stopped.body)
    );
    assert_eq!(body(&stopped)["status"], "ABORTED");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The Settings page reads a module as set by [`slots_set`]: `WiGLE`'s two modules need both
/// of its slots, HIBP's two may be set through `HIBP_API_KEY` alone.
#[test]
fn settings_read_a_module_as_set_only_with_every_slot_it_needs() {
    use crate::environment::{HIBP_API_KEY_ENV, WIGLE_USER_ENV};
    let (api, dir) = api_holding("settings-slots", &[WIGLE_USER_ENV, HIBP_API_KEY_ENV]);
    let settings = body(&api.handle("GET", "/api/settings", ""));
    let configured = |name: &str| {
        settings["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|module| module["name"] == name)
            .unwrap_or_else(|| panic!("no module {name}"))["configured"]
            .clone()
    };
    for (name, set) in [
        ("wigle", false),
        ("wigle_bluetooth", false),
        ("hibp", true),
        ("hibp_account", true),
        ("shodan", false),
    ] {
        assert_eq!(configured(name), set, "{name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A setting the binary adds follows the store's own in Global Settings, as given.
#[test]
fn a_global_setting_the_binary_adds_follows_the_stores_own() {
    let (api, dir) = api_holding("settings-global", &[]);
    let before = body(&api.handle("GET", "/api/settings", ""));
    let before = before["global"].as_array().unwrap();
    assert!(before.iter().all(|entry| entry["key"] != "continuous"));
    let api = api.with_global(
        "continuous",
        "continuous normalisation while serve runs",
        "off",
    );
    let settings = body(&api.handle("GET", "/api/settings", ""));
    let global = settings["global"].as_array().unwrap();
    assert_eq!(global.len(), before.len() + 1);
    assert_eq!(&global[..before.len()], &before[..]);
    let added = global.last().unwrap();
    assert_eq!(added["key"], "continuous");
    assert_eq!(
        added["description"],
        "continuous normalisation while serve runs"
    );
    assert_eq!(added["value"], "off");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `WiGLE` is set up only with both of its slots; HIBP's one slot may be set through its alias.
#[test]
fn a_module_is_set_only_when_every_slot_it_needs_holds_a_key() {
    use crate::environment::{
        HIBP_API_KEY_ENV, HUNTSMAN_HIBP_KEY_ENV, SHODAN_KEY_ENV, WIGLE_TOKEN_ENV, WIGLE_USER_ENV,
    };
    let wigle = [WIGLE_USER_ENV, WIGLE_TOKEN_ENV];
    let hibp = [HUNTSMAN_HIBP_KEY_ENV, HIBP_API_KEY_ENV];
    let with = |held: &'static [&'static str]| move |slot: &str| held.contains(&slot);
    assert!(!slots_set(&wigle, with(&[WIGLE_USER_ENV])));
    assert!(!slots_set(&wigle, with(&[WIGLE_TOKEN_ENV])));
    assert!(slots_set(&wigle, with(&[WIGLE_USER_ENV, WIGLE_TOKEN_ENV])));
    assert!(slots_set(&hibp, with(&[HUNTSMAN_HIBP_KEY_ENV])));
    assert!(slots_set(&hibp, with(&[HIBP_API_KEY_ENV])));
    assert!(!slots_set(&hibp, with(&[SHODAN_KEY_ENV])));
    assert!(slots_set(&[SHODAN_KEY_ENV], with(&[SHODAN_KEY_ENV])));
    assert!(!slots_set(&[SHODAN_KEY_ENV], with(&[])));
}

fn finished(api: &ScanApi) -> String {
    api.service()
        .run(&ScanRequest {
            target: "1.1.1.1".into(),
            ..ScanRequest::default()
        })
        .unwrap()
        .id
}

#[test]
fn an_element_names_the_lookup_a_scan_of_its_value_runs() {
    // The page opens New Scan of an element with the row's `scan_kind`. Detection reads a bare
    // handle as a domain (`jane.doe`), an AS (`1337`) or a name (`john_smith`), and refuses
    // `janedoe`, so a USERNAME element must name its lookup.
    let element = |kind: &str, data: &str| crate::sf_elements::DataElement {
        id: format!("{kind}-{data}"),
        kind: kind.to_owned(),
        data: data.to_owned(),
        source: None,
        module: "test".to_owned(),
        confidence: 100,
        created: 0,
        fp: false,
        entity: None,
        raw: Value::Null,
    };
    let expected = [
        ("USERNAME", "jane.doe", Some("username")),
        ("PHONE_NUMBER", "+61400000000", Some("phone")),
        ("PHYSICAL_ADDRESS", "1 Example St", Some("geocode")),
        (
            "HSE_CRYPTO_ADDRESS",
            "sol:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            Some("crypto"),
        ),
        ("HUMAN_NAME", "Jane Doe", Some("people")),
        // A value found beside a target names the lookup of its kind of value, where
        // detection would read a co-hosted site with a phone number for a name as a phone.
        ("DOMAIN_NAME", "example.com", Some("domain")),
        ("CO_HOSTED_SITE", "0412345678.com.au", Some("domain")),
        ("BGP_AS_MEMBER", "AS13335", Some("asn")),
        ("NETBLOCK_MEMBER", "93.184.216.0/24", Some("netblock")),
        ("AFFILIATE_IPADDR", "93.184.216.34", Some("ip")),
        ("EMAILADDR_GENERIC", "abuse@example.com", Some("email")),
        ("PHYSICAL_COORDINATES", "-33.8688,151.2093", Some("network")),
        // A value its type's lookup refuses runs the lookup its own form names: a breach
        // record's `username` that is an address or a number, a host name that is an address.
        ("USERNAME", "jane.doe@yahoo.com", Some("email")),
        ("USERNAME", "+61412345678", Some("phone")),
        ("INTERNET_NAME", "93.184.216.34", Some("ip")),
        // Nothing takes it as what it is, so New Scan is not offered, never a people search.
        ("DOMAIN_NAME", "foo_bar.example.com", None),
        ("LINKED_URL_EXTERNAL", "https://example.com/", None),
    ];
    let elements = expected
        .iter()
        .map(|(kind, data, _)| element(kind, data))
        .collect();
    let results = ScanResults {
        format_version: crate::scan_store::FORMAT_VERSION,
        scan_id: "s".into(),
        text: String::new(),
        entities: Vec::new(),
        outcomes: Vec::new(),
        elements,
        correlations: Vec::new(),
        lineage: Vec::new(),
        termination: None,
    };
    let rows = element_rows(&results, results.elements.iter());
    for ((kind, data, lookup), row) in expected.iter().zip(&rows) {
        assert_eq!(
            row["scan_kind"],
            lookup.map_or(Value::Null, Value::from),
            "{kind} {data}"
        );
        // The page submits the kind it was given, so the API must take it for the value.
        if let Some(lookup) = lookup {
            assert!(plan(data, Some(lookup)).is_ok(), "{kind} {data}");
        }
    }
    // Each mapped type's kind is one the scan form and the API accept, and it routes the
    // value as its type, where detection would not.
    for handle in ["jane.doe", "janedoe", "1337", "john_smith"] {
        let planned = crate::scan_service::plan(handle, rows[0]["scan_kind"].as_str())
            .expect("a handle is a username target");
        assert_eq!(planned.kind, ScanKind::Username, "{handle}");
    }
    assert!(
        !matches!(
            crate::scan_service::plan("jane.doe", Some("auto")),
            Ok(plan) if plan.kind == ScanKind::Username
        ),
        "detection reads a bare handle as something else"
    );
}

#[test]
fn single_export_limits_input_before_deserializing_and_keeps_small_exports() {
    let (api, dir) = api("single-export-budget");
    let id = finished(&api);
    let path = dir.join(&id).join("results.json");
    let saved = std::fs::metadata(&path).unwrap().len();
    assert!(saved > 1);

    let csv = Params(vec![("format".into(), "csv".into())]);
    let refused = api.export_with_budget(&id, &csv, saved - 1);
    assert_eq!(refused.status, 413, "{}", refused.text());

    let normal = api.handle("GET", &format!("/api/scans/{id}/export"), "format=csv");
    assert_eq!(normal.status, 200, "{}", normal.text());
    assert!(
        normal
            .body
            .starts_with(b"Updated,Type,Module,Source,F/P,Data")
    );

    // A corrupt saved file must not be parsed for an invalid format.
    std::fs::write(&path, b"not JSON").unwrap();
    let invalid = Params(vec![("format".into(), "unknown".into())]);
    let refused = api.export_with_budget(&id, &invalid, 1);
    assert_eq!(refused.status, 400, "{}", refused.text());
    assert!(
        refused
            .text()
            .contains("unsupported single-scan export format")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn single_export_rejects_oversized_output_without_returning_partial_bytes() {
    let (api, dir) = api("single-export-output-budget");
    let id = finished(&api);
    // Missing optional results is a valid, zero-byte input. Use it to
    // exercise the HTML output limit independently of the input budget:
    // a large saved JSON fixture may be bigger than rendered HTML.
    std::fs::remove_file(dir.join(&id).join("results.json")).unwrap();
    let path = format!("/api/scans/{id}/export");
    let normal = api.handle("GET", &path, "format=html");
    assert_eq!(normal.status, 200, "{}", normal.text());
    let body_bytes = u64::try_from(normal.body.len()).unwrap();
    assert!(body_bytes > 1, "HTML report must contain output bytes");

    let html = Params(vec![("format".into(), "html".into())]);
    let limited = api.export_with_budget(&id, &html, body_bytes - 1);
    assert_eq!(limited.status, 413, "{}", limited.text());
    assert!(limited.text().contains("export output budget exceeded"));
    assert_eq!(limited.content_type, JSON);
    assert!(limited.filename.is_none());

    let accepted = api.export_with_budget(&id, &html, body_bytes);
    assert_eq!(accepted.status, 200, "{}", accepted.text());
    assert_eq!(accepted.body, normal.body);

    let _ = std::fs::remove_dir_all(&dir);
}

/// One multi-export runs at a time, whichever thread runs it: a second is refused with 503
/// while another thread holds the permit, as a request served beside it would, and admitted
/// once it is released. Another API's permit, as another test's, refuses none.
#[test]
fn a_second_multi_export_is_refused_while_one_runs() {
    let (other_api, other_dir) = api("multi-export-permit-other");
    let (api, dir) = api("multi-export-permit");
    // The served API's permit is the process's one; this test's API has its own.
    assert!(std::ptr::eq(
        ScanApi::new(Arc::clone(&api.service), None).multi_export,
        std::ptr::addr_of!(MULTI_EXPORT_ACTIVE)
    ));
    let id = finished(&api);
    let export = || api.handle("GET", "/api/scans/export", &format!("ids={id}"));
    let flag = api.multi_export;
    let (took, taken) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        let permit = MultiExportPermit::try_acquire(flag);
        took.send(permit.is_some()).unwrap();
        released.recv().unwrap();
        drop(permit);
    });
    assert!(taken.recv().unwrap(), "no export was running");
    let refused = export();
    assert_eq!(refused.status, 503, "{}", refused.text());
    release.send(()).unwrap();
    other.join().unwrap();
    assert_eq!(export().status, 200);
    let held = MultiExportPermit::try_acquire(other_api.multi_export).expect("its own permit");
    assert_eq!(export().status, 200);
    drop(held);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other_dir);
}

#[test]
fn multi_export_enforces_aggregate_serialized_input_budget() {
    let (api, dir) = api("multi-export-budget");
    let id = finished(&api);
    let saved = std::fs::metadata(dir.join(&id).join("results.json"))
        .unwrap()
        .len();
    assert!(saved > 1);
    let one = Params(vec![("ids".into(), id.clone())]);
    let too_small = api.export_many_with_budget(&one, saved - 1);
    assert_eq!(too_small.status, 413, "{}", too_small.text());
    let repeated = Params(vec![("ids".into(), format!("{id},{id}"))]);
    let aggregate = api.export_many_with_budget(&repeated, saved);
    assert_eq!(aggregate.status, 413, "{}", aggregate.text());
    // Existing duplicate-ID SpiderFoot export semantics are preserved.
    assert_eq!(
        api.handle("GET", "/api/scans/export", &format!("ids={id},{id}"))
            .status,
        200
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bounded_multi_export_xlsx_preserves_download_and_rejects_tiny_budget() {
    let (api, dir) = api("multi-export-xlsx");
    let id = finished(&api);
    let params = Params(vec![
        ("ids".into(), id.clone()),
        ("format".into(), "xlsx".into()),
    ]);
    let small = api.export_many_with_budget(&params, 1024);
    assert_eq!(small.status, 413, "{}", small.text());
    let normal = api.handle("GET", "/api/scans/export", &format!("ids={id}&format=xlsx"));
    assert_eq!(normal.status, 200, "{}", normal.text());
    assert_eq!(normal.filename.as_deref(), Some("1.1.1.1-Huntsman.xlsx"));
    assert!(normal.body.starts_with(b"PK\x03\x04"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn multi_export_rejects_invalid_format_before_loading_saved_results() {
    let (api, dir) = api("multi-export-invalid-format");
    let id = finished(&api);
    let path = dir.join(&id).join("results.json");
    // Deliberately corrupt saved evidence. An invalid format must be rejected
    // before attempting to parse or load the evidence file.
    std::fs::write(&path, b"not valid JSON").unwrap();
    let invalid = Params(vec![
        ("ids".into(), id.clone()),
        ("format".into(), "unsupported".into()),
    ]);
    let response = api.export_many_with_budget(&invalid, 1024);
    assert_eq!(response.status, 400, "{}", response.text());
    assert!(
        response
            .text()
            .contains("unsupported multi-scan export format"),
        "{}",
        response.text()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spiderfoot's search box over one scan or all of them: text anywhere, a wildcard as the
/// whole value, a regex anywhere, in the data, the source's data or the module.
#[test]
fn search_reads_spiderfoots_forms_over_one_scan_or_every_scan() {
    let (api, dir) = api("search");
    let first = finished(&api);
    let second = api
        .service()
        .run(&ScanRequest {
            target: "8.8.8.8".into(),
            ..ScanRequest::default()
        })
        .unwrap()
        .id;
    let search = |query: &str| api.handle("GET", "/api/scans/search", query);
    let rows = |query: &str| -> Vec<Value> {
        let answer = search(query);
        assert_eq!(answer.status, 200, "{query}: {}", answer.text());
        body(&answer).as_array().unwrap().clone()
    };
    let scans = |rows: &[Value]| -> BTreeSet<String> {
        rows.iter()
            .map(|row| row["scan_id"].as_str().unwrap().to_owned())
            .collect()
    };
    let text = |row: &Value, key: &str| row[key].as_str().unwrap().to_owned();
    let ports = rows("value=443&type=tcp_port_open");
    assert_eq!(
        scans(&ports),
        BTreeSet::from([first.clone(), second.clone()])
    );
    for row in &ports {
        assert_eq!(row["type"], "TCP_PORT_OPEN");
        assert!(text(row, "data").contains("443") || text(row, "source_data").contains("443"));
        assert!(row["scan_name"].is_string() && row["scan_target"].is_string());
        assert!(row["description"].is_string(), "{row}");
        // Each port was found from its scan's address, which the row names.
        assert_eq!(row["source_data"], row["scan_target"], "{row}");
    }
    let one = rows(&format!("value=443&ids={first}"));
    assert!(!one.is_empty());
    assert_eq!(scans(&one), BTreeSet::from([first.clone()]));
    // A wildcard is the whole value: 8.8.8.8 and what was found from it, never 1.1.1.1's.
    let google = rows("value=8.8.*");
    assert_eq!(scans(&google), BTreeSet::from([second.clone()]));
    assert!(
        google
            .iter()
            .all(|row| text(row, "data").starts_with("8.8.")
                || text(row, "source_data").starts_with("8.8."))
    );
    let cves = rows("value=/^cve-2021-/");
    assert!(!cves.is_empty());
    assert!(
        cves.iter()
            .all(|row| text(row, "data").starts_with("CVE-2021-"))
    );
    // A type alone lists it everywhere; the root is never a hit.
    let every_port: usize = [&first, &second]
        .iter()
        .map(|id| {
            body(&api.handle(
                "GET",
                &format!("/api/scans/{id}/elements"),
                "type=TCP_PORT_OPEN",
            ))
            .as_array()
            .unwrap()
            .len()
        })
        .sum();
    assert!(every_port > ports.len());
    assert_eq!(rows("type=TCP_PORT_OPEN").len(), every_port);
    assert!(
        rows("value=1.1.1.1")
            .iter()
            .all(|row| row["type"] != "ROOT")
    );
    assert_eq!(search("").status, 400);
    assert_eq!(search("value=/(a/").status, 400);
    assert_eq!(search("value=x&ids=0000000000000000").status, 404);
    assert_eq!(
        api.handle("POST", "/api/scans/search", "value=x").status,
        405
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_scans_of_one_target_alert_only_on_what_is_new() {
    let (api, dir) = api("alert");
    let earlier = finished(&api);
    let later = api
        .service()
        .run(&ScanRequest {
            target: api.service().store().get(&earlier).unwrap().target,
            ..ScanRequest::default()
        })
        .unwrap()
        .id;
    let answer = api.handle("GET", "/api/scans/alert", &format!("ids={earlier},{later}"));
    assert_eq!(answer.status, 200, "{}", answer.text());
    let decided = body(&answer);
    assert_eq!(decided["earlier"], earlier.as_str());
    assert_eq!(decided["alert"]["raised"], false);
    let bad_risk = api.handle(
        "GET",
        "/api/scans/alert",
        &format!("ids={earlier},{later}&min_risk=urgent"),
    );
    assert_eq!(bad_risk.status, 400);
    assert_eq!(
        api.handle("GET", "/api/scans/alert", &format!("ids={earlier}"))
            .status,
        400
    );
    let other = api
        .service()
        .run(&ScanRequest {
            target: "8.8.8.8".into(),
            ..ScanRequest::default()
        })
        .unwrap()
        .id;
    let refused = api.handle("GET", "/api/scans/alert", &format!("ids={earlier},{other}"));
    assert_eq!(refused.status, 400);
    assert_eq!(
        api.handle(
            "POST",
            "/api/scans/alert",
            &format!("ids={earlier},{later}")
        )
        .status,
        405
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_alert_history_is_served_as_it_is_kept() {
    let (api, dir) = api("alert-history");
    let empty = api.handle("GET", "/api/scans/alerts", "");
    assert_eq!(empty.status, 200, "{}", empty.text());
    assert_eq!(body(&empty), json!([]));
    scan_alert::append_history(
        &dir.join(scan_alert::HISTORY_FILE),
        &json!({ "at": 1, "raised": true, "reasons": [] }),
    )
    .unwrap();
    let kept = api.handle("GET", "/api/scans/alerts", "");
    assert_eq!(kept.status, 200);
    assert_eq!(body(&kept)[0]["raised"], true);
    assert_eq!(api.handle("POST", "/api/scans/alerts", "").status, 405);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_scans_compare_by_value_and_export_their_changes() {
    let (api, dir) = api("compare");
    let earlier = finished(&api);
    let later = api
        .service()
        .run(&ScanRequest {
            target: "8.8.8.8".into(),
            ..ScanRequest::default()
        })
        .unwrap()
        .id;
    let answer = api.handle(
        "GET",
        "/api/scans/compare",
        &format!("ids={earlier},{later}"),
    );
    assert_eq!(answer.status, 200, "{}", answer.text());
    let compared = body(&answer);
    assert_eq!(compared["base"]["id"], earlier.as_str());
    assert_eq!(compared["other"]["id"], later.as_str());
    assert_eq!(compared["unchanged"], false);
    assert_eq!(compared["source_execution"]["earlier"]["success"], 1);
    assert_eq!(compared["source_execution"]["later"]["success"], 1);
    assert_eq!(compared["source_execution_changed"], false);
    assert_eq!(compared["source_execution"]["changed_modules"], json!([]));
    let data = |list: &Value| -> Vec<String> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|row| row["data"].as_str().unwrap().to_owned())
            .collect()
    };
    // Each address is its own scan's; the vulnerabilities both found are kept, not listed.
    assert!(data(&compared["added"]).contains(&"8.8.8.8".to_owned()));
    assert!(data(&compared["removed"]).contains(&"1.1.1.1".to_owned()));
    assert!(
        !data(&compared["added"])
            .iter()
            .any(|value| value.starts_with("CVE-"))
    );
    let types = compared["types"].as_array().unwrap();
    let ip = types
        .iter()
        .find(|row| row["type"] == "IP_ADDRESS")
        .unwrap();
    assert_eq!(
        (
            ip["added"].as_u64(),
            ip["removed"].as_u64(),
            ip["kept"].as_u64()
        ),
        (Some(1), Some(1), Some(0))
    );
    assert!(
        types.iter().any(|row| row["kept"].as_u64() > Some(0)),
        "{types:?}"
    );
    // Rows carry what /elements carries, so the page shows them alike.
    let row = &compared["added"][0];
    assert!(
        row["description"].is_string()
            && row["source_data"].is_string()
            && row.get("raw").is_some(),
        "{row}"
    );
    assert!(compared["correlations"]["added"].is_array());
    let csv = api.handle(
        "GET",
        "/api/scans/compare",
        &format!("ids={earlier},{later}&format=csv"),
    );
    assert_eq!(csv.status, 200, "{}", csv.text());
    assert!(
        csv.text()
            .starts_with("Change,Scan Name,Updated,Type,Module,Source,F/P,Data\r\n")
    );
    assert_eq!(
        csv.filename.as_deref(),
        Some(format!("{earlier}-vs-{later}-Huntsman.csv").as_str())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn comparison_keeps_identical_findings_distinct_from_changed_execution_coverage() {
    let (api, dir) = api("compare-coverage");
    let earlier = finished(&api);
    let later = finished(&api);
    let mut results = api.service().store().results(&later).unwrap().unwrap();
    results.outcomes.push(SourceExecutionOutcome::failed(
        "hibp",
        1,
        SourceOutcomeKind::NotConfigured,
        None,
        "no key configured",
    ));
    api.service().store().save_results(&results).unwrap();
    let value = body(&api.handle(
        "GET",
        "/api/scans/compare",
        &format!("ids={earlier},{later}"),
    ));
    assert_eq!(value["unchanged"], true);
    assert_eq!(value["source_execution_changed"], true);
    assert_eq!(value["source_execution"]["earlier"]["accepted"], 1);
    assert_eq!(value["source_execution"]["earlier"]["not_configured"], 0);
    assert_eq!(value["source_execution"]["later"]["accepted"], 1);
    assert_eq!(value["source_execution"]["later"]["not_configured"], 1);
    assert_eq!(
        value["source_execution"]["changed_modules"],
        json!(["hibp"])
    );
    assert_eq!(
        value["source_execution"]["later"]["all_recorded_sources_accepted"],
        false
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_comparison_takes_two_saved_scans_and_a_table_format() {
    let (api, dir) = api("compare-refused");
    let earlier = finished(&api);
    let later = finished(&api);
    assert_eq!(
        api.handle("GET", "/api/scans/compare", &format!("ids={earlier}"))
            .status,
        400
    );
    assert_eq!(
        api.handle(
            "GET",
            "/api/scans/compare",
            &format!("ids={earlier},{later}&format=gexf")
        )
        .status,
        400
    );
    assert_eq!(
        api.handle(
            "GET",
            "/api/scans/compare",
            &format!("ids={earlier},0000000000000000")
        )
        .status,
        404
    );
    assert_eq!(
        api.handle(
            "POST",
            "/api/scans/compare",
            &format!("ids={earlier},{later}")
        )
        .status,
        405
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A rule file that did not load is in the rules answer, after the rules that did, as a row
/// named by the id its file would have given it, whose origin is `not loaded` and whose error
/// is the reason, so the Settings panel can show it where its results would have been; the
/// loaded rules are unchanged by it.
#[test]
fn a_rule_that_did_not_load_is_named_in_the_rules_answer() {
    let dir = scratch("broken-rule");
    let rules_dir = dir.join("correlations");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(
        rules_dir.join("broken.yaml"),
        "id: broken\nversion: 1\nmeta:\n  name: [unterminated\n",
    )
    .unwrap();
    let (rules, errors) = crate::sf_correlate::with_dir(&rules_dir);
    assert_eq!(errors.len(), 1, "{errors:?}");
    let lookup = Arc::new(|_kind: ScanKind, selector: &str, _: &Selection| {
        Ok(LookupOutput {
            text: "report".into(),
            entities: vec![Entity::builder(EntityKind::IpAddress, selector, 0.9, "s").build()],
            outcomes: vec![SourceExecutionOutcome::success("internetdb", 1, 1)],
        })
    });
    let service = ScanService::with_rules(
        ScanStore::open(&dir.join("scans")).unwrap(),
        lookup,
        rules,
        errors,
    );
    let api = ScanApi::new(service, None);
    let answer = body(&api.handle("GET", "/api/correlationrules", ""));
    let rows = answer.as_array().unwrap();
    let (broken, loaded): (Vec<&Value>, Vec<&Value>) =
        rows.iter().partition(|row| row["origin"] == "not loaded");
    assert_eq!(loaded.len(), rule_catalog().len() + 37);
    assert!(loaded.iter().all(|row| row.get("error").is_none()));
    assert_eq!(broken.len(), 1, "{broken:?}");
    let broken = broken[0];
    assert_eq!(broken["id"], "broken", "{broken}");
    assert_eq!(broken["name"], broken["id"]);
    assert!(!broken["error"].as_str().unwrap().is_empty(), "{broken}");
    assert_eq!(broken["descr"], broken["error"]);
    assert_eq!(broken["risk"], "");
    assert_eq!(broken["logic"], "");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn correlation_rules_are_listed_rerun_and_exported() {
    let (api, dir) = api("correlate");
    assert!(ScanApi::handles("/api/correlationrules"));
    let rules = body(&api.handle("GET", "/api/correlationrules", ""));
    let rules = rules.as_array().unwrap();
    assert_eq!(rules.len(), rule_catalog().len() + 37);
    assert_eq!(rules[0]["origin"], "huntsman");
    assert!(
        rules
            .iter()
            .all(|rule| !rule["descr"].as_str().unwrap().is_empty())
    );
    let database = rules
        .iter()
        .find(|rule| rule["id"] == "database_exposed")
        .unwrap();
    assert_eq!(database["risk"], "HIGH");
    assert_eq!(database["origin"], "spiderfoot");
    assert!(
        database["logic"]
            .as_str()
            .unwrap()
            .starts_with("id: database_exposed\n")
    );
    let id = finished(&api);
    let saved = body(&api.handle("GET", &format!("/api/scans/{id}/correlations"), ""));
    let titles: Vec<&str> = saved
        .as_array()
        .unwrap()
        .iter()
        .map(|correlation| correlation["title"].as_str().unwrap())
        .collect();
    assert!(
        titles.contains(&"Multiple medium/low vulnerabilities found on 1.1.1.1"),
        "{titles:?}"
    );
    let rerun = api.handle("POST", &format!("/api/scans/{id}/correlate"), "");
    assert_eq!(rerun.status, 200, "{}", rerun.text());
    assert_eq!(body(&rerun), saved);
    let csv = api.handle(
        "GET",
        &format!("/api/scans/{id}/correlations"),
        "format=csv",
    );
    assert_eq!(csv.status, 200);
    assert!(
        csv.text()
            .starts_with("Rule Name,Correlation,Risk,Description,Rule,Origin,Elements\r\n")
    );
    assert_eq!(csv.text().matches("\r\n").count(), titles.len() + 1);
    assert!(
        csv.filename
            .unwrap()
            .ends_with("-Huntsman-correlations.csv")
    );
    let refused = |method: &str, path: &str, query: &str| api.handle(method, path, query).status;
    assert_eq!(
        refused(
            "GET",
            &format!("/api/scans/{id}/correlations"),
            "format=gexf"
        ),
        400
    );
    assert_eq!(
        refused("GET", &format!("/api/scans/{id}/correlate"), ""),
        405
    );
    assert_eq!(refused("POST", "/api/correlationrules", ""), 405);
    assert_eq!(refused("POST", "/api/scans/nope/correlate", ""), 404);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_scan_started_with_a_depth_keeps_it_and_a_bad_depth_is_refused() {
    let (api, dir) = api("depth");
    let bad = api.handle("POST", "/api/scans", "target=1.1.1.1&depth=deep");
    assert_eq!(bad.status, 400, "{}", bad.text());
    let started = api.handle("POST", "/api/scans", "target=1.1.1.1&depth=2");
    assert_eq!(started.status, 202, "{}", started.text());
    assert_eq!(body(&started)["options"]["depth"], 2);
    let id = body(&started)["id"].as_str().unwrap().to_owned();
    for _ in 0..200 {
        if !api.service().store().get(&id).unwrap().status.is_active() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_scan_started_with_modules_keeps_them_and_refuses_what_none_of_them_takes() {
    let (api, dir) = api("modules");
    let unknown = api.handle("POST", "/api/scans", "target=1.1.1.1&modules=nonesuch");
    assert_eq!(unknown.status, 400, "{}", unknown.text());
    assert!(
        unknown.text().contains("no module is named nonesuch"),
        "{}",
        unknown.text()
    );
    let unasked = api.handle("POST", "/api/scans", "target=1.1.1.1&modules=sfp_gravatar");
    assert_eq!(unasked.status, 400, "{}", unasked.text());
    assert!(
        unasked
            .text()
            .contains("none of the chosen modules (sfp_gravatar)"),
        "{}",
        unasked.text()
    );
    let started = api.handle("POST", "/api/scans", "target=1.1.1.1&modules=sfp_ripe,RDAP");
    assert_eq!(started.status, 202, "{}", started.text());
    assert_eq!(
        body(&started)["options"]["modules"],
        json!(["sfp_ripe", "rdap"])
    );
    // The label a Sources table shows for a module's leg chooses that module: hibp_account
    // is HIBP's account search, wigle_bluetooth WiGLE's Bluetooth search.
    let by_label = api.handle(
        "POST",
        "/api/scans",
        "target=ada@example.com&modules=hibp_account",
    );
    assert_eq!(by_label.status, 202, "{}", by_label.text());
    let bluetooth = api.handle(
        "POST",
        "/api/scans",
        "target=00:11:22:33:44:55&modules=wigle_bluetooth",
    );
    assert_eq!(bluetooth.status, 202, "{}", bluetooth.text());
    let ids: Vec<String> = [&started, &by_label, &bluetooth]
        .iter()
        .map(|response| body(response)["id"].as_str().unwrap().to_owned())
        .collect();
    for _ in 0..200 {
        if ids
            .iter()
            .all(|id| !api.service().store().get(id).unwrap().status.is_active())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let shown = body(&api.handle("GET", &format!("/api/scans/{}", ids[0]), ""));
    assert_eq!(shown["honoured"]["modules"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn source_coverage_distinguishes_confirmed_negatives_from_missing_keys_and_failures() {
    let outcomes = [
        SourceExecutionOutcome::success("gravatar", 1, 1),
        SourceExecutionOutcome::valid_zero("bluesky_user", 1).with_http_status(400),
        SourceExecutionOutcome::failed(
            "hibp_account",
            1,
            SourceOutcomeKind::NotConfigured,
            None,
            "no key configured",
        ),
        SourceExecutionOutcome::failed(
            "provider",
            1,
            SourceOutcomeKind::Upstream5xx,
            Some(502),
            "temporary outage",
        ),
        SourceExecutionOutcome::failed(
            "crt_sh",
            1,
            SourceOutcomeKind::RefusedBeforeSending,
            None,
            "egress-policy refused the destination",
        ),
    ];
    // A request refused before it was sent was never attempted, and is not unresolved.
    assert_eq!(
        source_execution_summary(&outcomes),
        json!({
            "unit": "source_execution",
            "total": 5,
            "attempted": 3,
            "accepted": 2,
            "success": 1,
            "valid_zero": 1,
            "inconsistent_accepted_count": 0,
            "not_configured": 1,
            "refused_before_sending": 1,
            "unresolved": 1,
            "all_recorded_sources_accepted": false,
        })
    );
    assert_eq!(
        source_execution_summary(&[])["all_recorded_sources_accepted"],
        false
    );
}

#[test]
fn a_started_scan_is_listed_and_finishes() {
    let (api, dir) = api("start");
    let started = api.handle(
        "POST",
        "/api/scans",
        "target=1.1.1.1&name=resolver&usecase=footprint",
    );
    assert_eq!(started.status, 202, "{}", started.text());
    let id = body(&started)["id"].as_str().unwrap().to_owned();
    let mut status = String::new();
    for _ in 0..200 {
        status = body(&api.handle("GET", &format!("/api/scans/{id}"), ""))["status"]
            .as_str()
            .unwrap()
            .to_owned();
        if status == "FINISHED" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert_eq!(status, "FINISHED");
    let list = body(&api.handle("GET", "/api/scans", ""));
    assert_eq!(list[0]["id"], id);
    assert_eq!(list[0]["name"], "resolver");
    assert_eq!(list[0]["options"]["usecase"], "footprint");
    let row = body(&api.handle("GET", &format!("/api/scans/{id}"), ""));
    assert_eq!(row["sources"][0]["module"], "internetdb");
    assert_eq!(row["report"], "report");
    assert_eq!(row["source_execution_summary"]["success"], 1);
    assert_eq!(row["source_execution_summary"]["accepted"], 1);
    assert_eq!(row["sources"][0]["observed_at_unix"], 1);
    assert_eq!(row["uncertainty_register"]["recorded_executions"], 1);
    assert_eq!(row["uncertainty_register"]["unresolved_executions"], 0);
    assert_eq!(
        row["uncertainty_register"]["discovery_completeness"],
        "unverified"
    );
    assert!(
        row["uncertainty_register"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "scope:exhaustiveness_unverified")
    );
    assert_eq!(
        row["source_execution_summary"]["all_recorded_sources_accepted"],
        true
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_scan_analysis_is_read_only_and_distinguishes_derived_from_collected_evidence() {
    let (api, dir) = api("saved-analysis");
    let id = finished(&api);
    let original = api.service().store().results(&id).unwrap().unwrap();
    let saved_path = dir.join(&id).join("results.json");
    let original_bytes = std::fs::read(&saved_path).unwrap();

    let path = format!("/api/scans/{id}/analyze");
    let response = api.handle("GET", &path, "");
    assert_eq!(response.status, 200, "{}", response.text());
    let value = body(&response);
    assert_eq!(value["scan"]["id"], id);
    assert_eq!(value["scan"]["status"], "FINISHED");
    assert_eq!(value["source"], "saved_scan_entities");
    assert_eq!(value["counts"]["saved_entities"], original.entities.len());
    assert_eq!(value["counts"]["source_outcomes"], original.outcomes.len());
    assert_eq!(value["limitations"]["scan_complete"], true);
    assert_eq!(
        value["limitations"]["false_positive_annotations"],
        "none_present"
    );
    assert_eq!(value["counts"]["flagged_elements"], 0);
    assert_eq!(
        value["limitations"]["provider_coverage"],
        "not_reconstructed"
    );
    assert_eq!(
        value["limitations"]["evidence_ancestry"],
        "not_reconstructed"
    );
    assert_eq!(
        value["limitations"]["original_evidence"],
        "retained_in_saved_results"
    );
    assert!(value["report"].is_object());
    assert!(
        value["report"]["synergy"]["links"].is_array(),
        "saved scans must expose the same source-join contract as live lookups"
    );
    assert_eq!(api.service().store().results(&id).unwrap(), Some(original));
    assert_eq!(std::fs::read(&saved_path).unwrap(), original_bytes);
    assert_eq!(api.handle("POST", &path, "").status, 405);

    // Model an admitted but not yet started scan using the public store API.
    // The test must not call ScanService's private worker-creation helper.
    let mut created = api.service().store().get(&id).unwrap();
    created.id = crate::scan_store::new_id("pending", 1919, 0);
    created.status = ScanStatus::Created;
    created.started = None;
    created.ended = None;
    api.service().store().create(&created).unwrap();
    assert_eq!(
        api.handle("GET", &format!("/api/scans/{}/analyze", created.id), "")
            .status,
        409
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn saved_scan_analysis_rejects_flagged_evidence_without_modifying_results() {
    let (api, dir) = api("saved-analysis-flagged");
    let id = finished(&api);
    let store = api.service().store();
    let mut results = store.results(&id).unwrap().unwrap();
    let element = results
        .elements
        .iter_mut()
        .find(|element| element.entity.is_some() && element.kind != "ROOT")
        .unwrap();
    element.fp = true;
    store.save_results(&results).unwrap();

    let path = dir.join(&id).join("results.json");
    let before = std::fs::read(&path).unwrap();
    let response = api.handle("GET", &format!("/api/scans/{id}/analyze"), "");
    assert_eq!(response.status, 409, "{}", response.text());
    assert!(response.text().contains("false-positive"));
    assert_eq!(store.results(&id).unwrap(), Some(results));
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn entity_reality_reports_attributions_but_never_claims_identity_proof() {
    let (api, dir) = api("entity-reality");
    let id = finished(&api);
    let store = api.service().store();
    let results = store.results(&id).unwrap().unwrap();
    let entity = &results.entities[0];
    let original = std::fs::read(dir.join(&id).join("results.json")).unwrap();
    let route = format!("/api/scans/{id}/reality");
    let response = api.handle("GET", &route, &format!("uid={}", entity.uid));
    assert_eq!(response.status, 200, "{}", response.text());
    let value = body(&response);
    assert_eq!(value["entity"]["uid"], entity.uid);
    assert_eq!(
        value["entity"]["identity_status"],
        "not_established_by_identifier_or_source_attribution"
    );
    assert_eq!(value["entity"]["assertions"][0]["dimension"], "capability");
    assert_eq!(value["independent_source_proof"], "not_reconstructed");
    assert_eq!(value["source_authenticity"], "not_established");
    assert_eq!(api.handle("GET", &route, "").status, 400);
    assert_eq!(api.handle("GET", &route, "uid=missing").status, 404);
    assert_eq!(api.handle("POST", &route, "uid=missing").status, 405);
    assert_eq!(
        std::fs::read(dir.join(&id).join("results.json")).unwrap(),
        original
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn entity_reality_refuses_flagged_saved_evidence() {
    let (api, dir) = api("entity-reality-fp");
    let id = finished(&api);
    let store = api.service().store();
    let mut results = store.results(&id).unwrap().unwrap();
    let uid = results.entities[0].uid.clone();
    results.elements[0].fp = true;
    store.save_results(&results).unwrap();
    assert_eq!(
        api.handle(
            "GET",
            &format!("/api/scans/{id}/reality"),
            &format!("uid={uid}")
        )
        .status,
        409
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn matrix_reads_a_stopped_scan_as_json_or_raw_without_writing() {
    let (api, dir) = api("matrix");
    let id = finished(&api);
    let original = std::fs::read(dir.join(&id).join("results.json")).unwrap();
    let route = format!("/api/scans/{id}/matrix");
    let json = api.handle("GET", &route, "");
    assert_eq!(json.status, 200, "{}", json.text());
    assert_eq!(
        json.filename.as_deref(),
        Some(format!("{id}-matrix.json").as_str())
    );
    assert!(body(&json).is_object());
    let raw = api.handle("GET", &route, "format=raw");
    assert_eq!(raw.status, 200, "{}", raw.text());
    assert_eq!(raw.content_type, "text/plain; charset=utf-8");
    assert_eq!(
        raw.filename.as_deref(),
        Some(format!("{id}-matrix.txt").as_str())
    );
    assert_eq!(api.handle("GET", &route, "format=csv").status, 400);
    assert_eq!(api.handle("POST", &route, "").status, 405);
    assert_eq!(
        api.handle("GET", "/api/scans/0123456789abcdef/matrix", "")
            .status,
        404
    );
    assert_eq!(
        std::fs::read(dir.join(&id).join("results.json")).unwrap(),
        original
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn summary_elements_graph_and_log_read_the_saved_scan() {
    let (api, dir) = api("read");
    let id = finished(&api);
    let summary = body(&api.handle("GET", &format!("/api/scans/{id}/summary"), ""));
    let ports = summary
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "TCP_PORT_OPEN")
        .unwrap();
    assert_eq!(
        (ports["total"].as_u64(), ports["unique"].as_u64()),
        (Some(2), Some(2))
    );
    let elements = body(&api.handle(
        "GET",
        &format!("/api/scans/{id}/elements"),
        "type=VULNERABILITY_GENERAL",
    ));
    assert_eq!(elements[0]["data"], "CVE-2021-44228");
    assert_eq!(elements[0]["source_data"], "1.1.1.1");
    assert_eq!(elements[0]["description"], "Vulnerability - General");
    let all = body(&api.handle("GET", &format!("/api/scans/{id}/elements"), ""));
    let target = all
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "IP_ADDRESS")
        .unwrap();
    assert_eq!(
        target["raw"][0]["evidence"]["attributes"]["ports"],
        "22,443"
    );
    // The raw record's provenance names the scan it is read from, not the lookup's private id.
    assert_eq!(target["raw"][0]["evidence"]["provenance"]["scan_id"], id);
    let graph = body(&api.handle("GET", &format!("/api/scans/{id}/graph"), ""));
    assert_eq!(
        graph["edges"].as_array().unwrap().len() + 1,
        graph["nodes"].as_array().unwrap().len()
    );
    let errors = body(&api.handle("GET", &format!("/api/scans/{id}/log"), "level=error"));
    assert_eq!(errors, json!([]));
    assert_eq!(
        api.handle("GET", &format!("/api/scans/{id}/log"), "level=loud")
            .status,
        400
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn false_positive_flags_persist_and_filter() {
    let (api, dir) = api("fp");
    let id = finished(&api);
    let all = body(&api.handle(
        "GET",
        &format!("/api/scans/{id}/elements"),
        "type=TCP_PORT_OPEN",
    ));
    let first = all[0]["id"].as_str().unwrap().to_owned();
    let set = api.handle(
        "POST",
        &format!("/api/scans/{id}/fp"),
        &format!("ids={first}&fp=1"),
    );
    assert_eq!(set.status, 200, "{}", set.text());
    let shown = body(&api.handle(
        "GET",
        &format!("/api/scans/{id}/elements"),
        "type=TCP_PORT_OPEN&hidefp=1",
    ));
    assert_eq!(shown.as_array().unwrap().len(), 1);
    assert_eq!(
        api.handle(
            "POST",
            &format!("/api/scans/{id}/fp"),
            "ids=ffffffffffffffff&fp=1"
        )
        .status,
        404
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spiderfoot's `resultsetfp`: flagging an element flags every element found from it, and an
/// element under a flagged parent cannot be unflagged on its own.
#[test]
fn a_false_positive_carries_to_everything_found_from_it() {
    let (api, dir) = api("fp-tree");
    let id = finished(&api);
    let graph = || body(&api.handle("GET", &format!("/api/scans/{id}/graph"), ""));
    let edges: Vec<(String, String)> = graph()["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| {
            (
                edge["source"].as_str().unwrap().to_owned(),
                edge["target"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let root = graph()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["type"] == "ROOT")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // An element below the root that others were found from, and everything below it.
    let parent = edges
        .iter()
        .map(|(source, _)| source)
        .find(|source| **source != root)
        .unwrap()
        .clone();
    let mut below = BTreeSet::new();
    let mut queue = vec![parent.clone()];
    while let Some(next) = queue.pop() {
        for (source, target) in &edges {
            if *source == next && below.insert(target.clone()) {
                queue.push(target.clone());
            }
        }
    }
    let child = below.iter().next().unwrap().clone();
    let flagged = || -> BTreeSet<String> {
        graph()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|node| node["fp"] == true)
            .map(|node| node["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let fp = |ids: &str, on: &str| {
        api.handle(
            "POST",
            &format!("/api/scans/{id}/fp"),
            &format!("ids={ids}&fp={on}"),
        )
    };
    let set = fp(&parent, "1");
    assert_eq!(set.status, 200, "{}", set.text());
    let mut subtree = below.clone();
    subtree.insert(parent.clone());
    assert_eq!(flagged(), subtree);
    assert_eq!(body(&set)["ids"].as_array().unwrap().len(), subtree.len());
    // The child cannot leave its flagged parent behind, and nothing changes.
    let refused = fp(&child, "0");
    assert_eq!(refused.status, 409, "{}", refused.text());
    assert!(refused.text().contains(&child), "{}", refused.text());
    assert_eq!(flagged(), subtree);
    // Unflagging the parent, alone or with the child, unflags the whole branch.
    let both = fp(&format!("{parent},{child}"), "0");
    assert_eq!(both.status, 200, "{}", both.text());
    assert!(flagged().is_empty());
    assert_eq!(fp(&parent, "1").status, 200);
    assert_eq!(fp(&parent, "0").status, 200);
    assert!(flagged().is_empty());
    // The root is the target, never a false positive.
    assert_eq!(fp(&root, "1").status, 404);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exports_carry_a_file_name_and_spiderfoots_layout() {
    let (api, dir) = api("export");
    let id = finished(&api);
    let csv = api.handle("GET", &format!("/api/scans/{id}/export"), "format=csv");
    assert_eq!(csv.status, 200);
    assert!(
        csv.text()
            .starts_with("Updated,Type,Module,Source,F/P,Data\r\n")
    );
    assert_eq!(csv.filename.as_deref(), Some("1.1.1.1-Huntsman.csv"));
    let book = api.handle("GET", &format!("/api/scans/{id}/export"), "format=xlsx");
    assert_eq!(book.status, 200);
    assert_eq!(book.content_type, crate::xlsx::CONTENT_TYPE);
    assert_eq!(book.filename.as_deref(), Some("1.1.1.1-Huntsman.xlsx"));
    assert!(book.body.starts_with(b"PK\x03\x04"));
    assert!(crate::xlsx::tests::sheet_names(&book.body).contains(&"TCP_PORT_OPEN".to_owned()));
    let many = api.handle("GET", "/api/scans/export", &format!("ids={id},{id}"));
    assert_eq!(many.status, 200);
    assert!(body(&many).as_array().unwrap().len() > 2);
    let many = api.handle(
        "GET",
        "/api/scans/export",
        &format!("ids={id},{id}&format=csv&type=TCP_PORT_OPEN"),
    );
    assert_eq!(many.filename.as_deref(), Some("Huntsman.csv"));
    assert!(
        many.text()
            .starts_with("Scan Name,Updated,Type,Module,Source,F/P,Data\r\n")
    );
    let book = api.handle(
        "GET",
        "/api/scans/export",
        &format!("ids={id}&format=excel"),
    );
    assert_eq!(book.status, 200, "{}", book.text());
    assert_eq!(book.filename.as_deref(), Some("1.1.1.1-Huntsman.xlsx"));
    assert!(book.body.starts_with(b"PK\x03\x04"));
    let correlations = api.handle(
        "GET",
        &format!("/api/scans/{id}/correlations"),
        "format=xlsx",
    );
    assert_eq!(correlations.status, 200);
    assert_eq!(correlations.content_type, crate::xlsx::CONTENT_TYPE);
    assert_eq!(
        api.handle("GET", &format!("/api/scans/{id}/export"), "format=pdf")
            .status,
        400
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stop_delete_and_rerun_follow_the_scan_state() {
    let (api, dir) = api("lifecycle");
    let id = finished(&api);
    assert_eq!(
        api.handle("POST", &format!("/api/scans/{id}/stop"), "")
            .status,
        409
    );
    let rerun = api.handle("POST", &format!("/api/scans/{id}/rerun"), "");
    assert_eq!(rerun.status, 202);
    assert_ne!(body(&rerun)["id"], id);
    assert_eq!(
        api.handle("POST", &format!("/api/scans/{id}/delete"), "")
            .status,
        200
    );
    assert_eq!(
        api.handle("GET", &format!("/api/scans/{id}"), "").status,
        404
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stop on a running scan answers 202 with the row `ABORT-REQUESTED`; the scan settles
/// `ABORTED`, with its end time, once the lookup it was in returns; and a second Stop is the
/// 409 a finished scan's is. The page's Stop buttons act on the first answer and poll for the
/// second, so both are locked here, not only the refusal.
#[test]
fn stop_on_a_running_scan_answers_202_and_the_scan_settles_aborted() {
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let entered_tx = Mutex::new(entered_tx);
    let dir = scratch("stop-running");
    let lookup = Arc::new(move |_kind: ScanKind, selector: &str, _: &Selection| {
        entered_tx.lock().unwrap().send(()).unwrap();
        release_rx.lock().unwrap().recv().unwrap();
        Ok(LookupOutput {
            text: "report".into(),
            entities: vec![Entity::builder(EntityKind::IpAddress, selector, 0.9, "s").build()],
            outcomes: vec![SourceExecutionOutcome::success("internetdb", 1, 1)],
        })
    });
    let api = ScanApi::new(
        ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
        None,
    );
    let started = api.handle("POST", "/api/scans", "target=1.1.1.1");
    assert_eq!(
        started.status,
        202,
        "{}",
        String::from_utf8_lossy(&started.body)
    );
    let id = body(&started)["id"].as_str().unwrap().to_owned();
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let stopping = api.handle("POST", &format!("/api/scans/{id}/stop"), "");
    assert_eq!(
        stopping.status,
        202,
        "{}",
        String::from_utf8_lossy(&stopping.body)
    );
    assert_eq!(body(&stopping)["status"], "ABORT-REQUESTED");
    release_tx.send(()).unwrap();
    let mut row = Value::Null;
    for _ in 0..400 {
        row = body(&api.handle("GET", &format!("/api/scans/{id}"), ""));
        if row["status"] != "ABORT-REQUESTED" && row["status"] != "RUNNING" {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(row["status"], "ABORTED", "{row}");
    assert!(row["ended"].is_u64(), "{row}");
    assert_eq!(
        api.handle("POST", &format!("/api/scans/{id}/stop"), "")
            .status,
        409
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn methods_paths_and_bad_input_get_their_status() {
    let (api, dir) = api("errors");
    assert_eq!(api.handle("DELETE", "/api/scans", "").status, 405);
    assert_eq!(
        api.handle("GET", "/api/scans/0123456789abcdef/stop", "")
            .status,
        405
    );
    assert_eq!(
        api.handle("POST", "/api/scans/0123456789abcdef/summary", "")
            .status,
        405
    );
    assert_eq!(api.handle("GET", "/api/scans/../../etc", "").status, 404);
    assert_eq!(
        api.handle("GET", "/api/scans/0123456789abcdef", "").status,
        404
    );
    assert_eq!(
        api.handle("GET", "/api/scans/0123456789abcdef/nope", "")
            .status,
        404
    );
    assert_eq!(api.handle("POST", "/api/scans", "").status, 400);
    assert_eq!(api.handle("POST", "/api/scans", "target=%zz").status, 400);
    assert_eq!(
        api.handle("POST", "/api/scans", "target=x.com&usecase=all-out")
            .status,
        400
    );
    assert!(ScanApi::handles("/api/scans/abc/log"));
    assert!(ScanApi::handles("/api/eventtypes"));
    assert!(!ScanApi::handles("/api/scansx"));
    assert!(!ScanApi::handles("/api/lookup"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn event_types_and_settings_describe_the_catalogue_and_key_status_without_values() {
    let (api, dir) = api("settings");
    let types = body(&api.handle("GET", "/api/eventtypes", ""));
    assert_eq!(types.as_array().unwrap().len(), sf_types::all().count());
    assert_eq!(types[0]["type"], "ROOT");
    let settings = body(&api.handle("GET", "/api/settings", ""));
    let shodan = settings["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["name"] == "shodan")
        .unwrap();
    assert_eq!(shodan["key_env"][0], crate::environment::SHODAN_KEY_ENV);
    assert_eq!(shodan["configured"], true);
    let robtex = settings["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["name"] == "robtex")
        .unwrap();
    assert_eq!(robtex["key_env"], json!([]));
    assert_eq!(robtex["configured"], Value::Null);
    // A keyless source's optional key slot is listed and checked too.
    let certspotter = settings["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["name"] == "certspotter")
        .unwrap();
    assert_eq!(
        certspotter["key_env"],
        json!([crate::environment::CERTSPOTTER_KEY_ENV])
    );
    assert_eq!(certspotter["configured"], false);
    assert!(settings["global"].as_array().unwrap().len() >= 3);
    // Each module names the lookups that ask it, as New Scan's By Module list shows.
    let modules = settings["modules"].as_array().unwrap();
    assert!(modules.iter().all(|module| module["lookups"].is_array()));
    assert!(
        modules
            .iter()
            .all(|module| module["attack_techniques"].is_array())
    );
    let dns = modules
        .iter()
        .find(|module| module["name"] == "ripestat")
        .unwrap();
    assert!(
        dns["attack_techniques"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| {
                id.as_str()
                    .is_some_and(|name| crate::attack::technique(name).is_some())
            })
    );
    let ripestat = modules.iter().find(|module| module["name"] == "ripestat");
    assert_eq!(
        ripestat.unwrap()["lookups"],
        json!(["ip", "netblock", "asn"])
    );
    // An offline module no lookup asks still names the lookups that run it over the target,
    // as the Sources table of a phone scan shows phone_intl and phone_au.
    let phone_intl = modules
        .iter()
        .find(|module| module["name"] == "phone_intl")
        .unwrap();
    assert_eq!(phone_intl["lookups"], json!([]));
    assert_eq!(phone_intl["offline_in"], json!(["phone"]));
    assert_eq!(ripestat.unwrap()["offline_in"], json!([]));
    // And every name a scan may choose it by, so Clone can restore a scan that chose a
    // Spiderfoot module: `sfp_whois` stands for both RDAP and Whoxy.
    assert_eq!(
        ripestat.unwrap()["spiderfoot"],
        json!(["ripestat", "sfp_ripestat", "sfp_ripe"])
    );
    let whois: Vec<&Value> = modules
        .iter()
        .filter(|module| {
            module["spiderfoot"]
                .as_array()
                .unwrap()
                .contains(&json!("sfp_whois"))
        })
        .map(|module| &module["name"])
        .collect();
    assert_eq!(whois, [&json!("whoxy"), &json!("rdap")]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The source label of every provider whose `API` constant in `src/` names a key slot, read
/// from the source text, so a keyed provider that [`key_slots`] leaves out is still found.
fn keyed_api_sources() -> Vec<String> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let Some(start) = text.find("\npub const API: Api = Api {") else {
            continue;
        };
        let constant = &text[start..];
        let constant = &constant[..constant.find("\n};").unwrap()];
        if !constant.contains("key: Some(") {
            continue;
        }
        // Each one is labelled with its module's `SOURCE`.
        assert!(constant.contains("source: SOURCE,"), "{}", path.display());
        let label = text
            .split("pub const SOURCE: &str = \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap();
        sources.push(label.to_owned());
    }
    sources
}

/// Every module that takes a key shows its slots and whether one is set: each one the module
/// list marks as needing a key, and each whose provider's `API` constant names a key, required
/// or optional.
#[test]
fn every_module_that_takes_a_key_shows_its_slots_and_whether_one_is_set() {
    let (api, dir) = api("keyed");
    let settings = body(&api.handle("GET", "/api/settings", ""));
    let modules = settings["modules"].as_array().unwrap();
    let from_source = keyed_api_sources();
    assert!(
        from_source.iter().any(|source| source == "certspotter") && from_source.len() > 15,
        "the source text names the keyed providers: {from_source:?}"
    );
    let keyed: BTreeSet<String> = reachable_modules()
        .iter()
        .filter(|module| module.access == "operator_key")
        .map(|module| module.name.to_owned())
        .chain(from_source)
        .collect();
    for name in &keyed {
        let module = modules
            .iter()
            .find(|module| module["name"] == name.as_str())
            .unwrap_or_else(|| panic!("{name} is not on the Settings page"));
        assert!(
            module["key_env"]
                .as_array()
                .is_some_and(|slots| !slots.is_empty()),
            "{name} lists no key slot"
        );
        assert!(module["configured"].is_boolean(), "{name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every slot the Settings page lists for a module is a slot a provider declares (or that
/// slot's fallback alias), so the page can always say where the operator gets the key.
#[test]
fn every_key_slot_has_a_provider_row() {
    let declared: BTreeSet<&str> = crate::provider_credentials::PROVIDERS
        .iter()
        .flat_map(|provider| provider.slots.iter().copied())
        .chain(
            crate::provider_credentials::SLOT_FALLBACKS
                .iter()
                .map(|(_, alias)| *alias),
        )
        .collect();
    let orphans: Vec<(&str, &str)> = key_slots()
        .into_iter()
        .flat_map(|(module, slots)| slots.into_iter().map(move |slot| (module, slot)))
        .filter(|(_, slot)| !declared.contains(slot))
        .collect();
    assert!(
        orphans.is_empty(),
        "these module key slots have no provider row to say where the key comes from: \
             {orphans:?}"
    );
}

/// The records of an RFC 4180 document: quoted fields may hold commas, doubled quotes and
/// line breaks.
fn csv_records(text: &str) -> Vec<Vec<String>> {
    let (mut records, mut record, mut field) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut chars) = (false, text.chars().peekable());
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (false, '"') => quoted = true,
            (false, ',') => record.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            (_, c) => field.push(c),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

/// The per-type summary counts each type's elements and distinct values.
fn assert_summary_counts(elements: &[Value], summary: &Value) {
    let mut by_type: std::collections::BTreeMap<&str, (u64, std::collections::BTreeSet<&str>)> =
        std::collections::BTreeMap::new();
    for element in elements {
        let entry = by_type
            .entry(element["type"].as_str().unwrap())
            .or_default();
        entry.0 += 1;
        entry.1.insert(element["data"].as_str().unwrap());
    }
    let summary = summary.as_array().unwrap();
    assert_eq!(summary.len(), by_type.len());
    for row in summary {
        let (total, unique) = &by_type[row["type"].as_str().unwrap()];
        assert_eq!(row["total"].as_u64(), Some(*total), "{row}");
        assert_eq!(row["unique"].as_u64(), Some(unique.len() as u64), "{row}");
    }
}

/// The graph holds a node per element (same data, type and module) plus the root, an edge
/// from each element's saved source, and no edge to a node it lacks.
fn assert_graph_holds(elements: &[Value], graph: &Value) {
    let nodes = graph["nodes"].as_array().unwrap();
    let edges = graph["edges"].as_array().unwrap();
    assert_eq!(
        nodes.len(),
        elements.len() + 1,
        "every element plus the root"
    );
    let node = |id: &Value| nodes.iter().find(|node| node["id"] == *id);
    for element in elements {
        let found = node(&element["id"]).unwrap_or_else(|| panic!("no node for {element}"));
        for field in ["data", "type", "module"] {
            assert_eq!(
                found[field], element[field],
                "{field} of node {}",
                element["id"]
            );
        }
        if element["source"].is_string() && node(&element["source"]).is_some() {
            assert!(
                edges
                    .iter()
                    .any(|edge| edge["source"] == element["source"]
                        && edge["target"] == element["id"]),
                "no edge into {}",
                element["id"]
            );
        }
    }
    for edge in edges {
        assert!(
            node(&edge["source"]).is_some() && node(&edge["target"]).is_some(),
            "{edge}"
        );
    }
}

/// Every view the web page reads of one saved scan says the same thing, field by field: the
/// detail's count, `/elements`, the JSON and CSV exports, the per-type summary, the graph (a
/// node per element plus the root, an edge from each element's source) and the correlations
/// in JSON and CSV. A view that drifts from the others shows the operator a different scan.
#[test]
fn every_view_of_a_saved_scan_agrees_field_by_field() {
    let (api, dir) = api("views");
    let id = finished(&api);
    let get = |route: &str, query: &str| {
        let response = api.handle("GET", &format!("/api/scans/{id}{route}"), query);
        assert_eq!(response.status, 200, "{route}?{query}: {}", response.text());
        response
    };
    let detail = body(&get("", ""));
    let elements = body(&get("/elements", ""));
    let elements = elements.as_array().unwrap();
    let count = usize::try_from(detail["elements"].as_u64().unwrap()).unwrap();
    assert!(count > 1, "the fixture scan holds more than its seed");
    assert_eq!(elements.len(), count);

    let exported = body(&get("/export", "format=json"));
    let exported = exported.as_array().unwrap();
    assert_eq!(exported.len(), count);
    for (element, row) in elements.iter().zip(exported) {
        for (field, export_field) in [
            ("id", "id"),
            ("type", "event_type"),
            ("data", "data"),
            ("module", "module"),
            ("source", "source"),
            ("source_data", "source_data"),
            ("confidence", "confidence"),
        ] {
            assert_eq!(
                element[field], row[export_field],
                "{field} of {}",
                element["id"]
            );
        }
        assert_eq!(
            element["fp"].as_bool().unwrap_or(false),
            row["false_positive"].as_bool().unwrap_or(false)
        );
    }

    let csv_response = get("/export", "format=csv");
    let csv = csv_response.text();
    let mut lines = csv.lines();
    assert_eq!(lines.next(), Some("Updated,Type,Module,Source,F/P,Data"));
    let rows: Vec<&str> = lines.collect();
    assert_eq!(rows.len(), count);
    for (element, line) in elements.iter().zip(&rows) {
        let fields: Vec<&str> = line.splitn(6, ',').collect();
        assert_eq!(fields[1], element["type"].as_str().unwrap(), "{line}");
        assert_eq!(fields[2], element["module"].as_str().unwrap(), "{line}");
        assert_eq!(
            fields[3],
            element["source_data"].as_str().unwrap(),
            "{line}"
        );
        assert_eq!(fields[4], if element["fp"] == true { "1" } else { "0" });
        assert_eq!(
            fields[5].trim_matches('"'),
            element["data"].as_str().unwrap(),
            "{line}"
        );
    }

    assert_summary_counts(elements, &body(&get("/summary", "")));
    assert_graph_holds(elements, &body(&get("/graph", "")));
    let correlations = body(&get("/correlations", ""));
    let correlations_csv_response = get("/correlations", "format=csv");
    let correlations_csv = correlations_csv_response.text();
    assert_eq!(
        correlations.as_array().unwrap().len(),
        csv_records(&correlations_csv).len() - 1
    );
    let _ = std::fs::remove_dir_all(dir);
}
