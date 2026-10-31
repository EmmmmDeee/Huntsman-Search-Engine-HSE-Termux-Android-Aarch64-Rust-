use super::analysis::inspect_label;
use super::guard::{fixed_time_eq, host_is_allowed_for_loopback};
use super::lookup::header_filename;
use super::page::{INDEX_HTML, PAGE_ID, PAGE_ID_SLOT};
use super::response::response_head;
use crate::base64;
use std::collections::BTreeSet;
use std::path::Path;

use super::*;
use crate::keys;
use crate::keys::Keys;
use crate::provider_credentials::PROVIDERS;
use crate::scan_service::{INSPECT_KIND, ScanService};
use crate::scan_store::ScanStatus;
use std::thread;

/// A loopback bind for the pure-router tests. The DNS-rebinding guard is active
/// for loopback binds, so requests here carry a loopback `Host` or none at all.
fn loopback_bind() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

/// A public bind, the only kind whose API needs the token.
fn public_bind() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}

/// The bind of a server started with `token`: a token is used only on a public bind.
fn bind_for(token: Option<&str>) -> SocketAddr {
    if token.is_some() {
        public_bind()
    } else {
        loopback_bind()
    }
}

#[test]
fn rhinser_catalogue_http_contract_is_read_only_and_complete() {
    let request = "GET /api/rhinser/catalog HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n";
    let answer = response_for_request(request, None, loopback_bind());
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
    let body = answer.split_once("\r\n\r\n").unwrap().1;
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    let categories = parsed["categories"].as_array().unwrap();
    assert_eq!(categories.len(), 11);
    assert_eq!(
        categories
            .iter()
            .map(|category| category["tools"].as_array().unwrap().len())
            .sum::<usize>(),
        83
    );
    let refusal = response_for_request(
        "GET /api/rhinser/catalog HTTP/1.1\r\nHost: public.example\r\n\r\n",
        Some("secret"),
        public_bind(),
    );
    assert!(refusal.starts_with("HTTP/1.1 401"), "{refusal}");
}

#[test]
fn local_evidence_cannot_be_read_from_a_public_bind_even_with_token() {
    for path in ["/evidence", "/api/evidence"] {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: public.example\r\nAuthorization: Bearer secret\r\n\r\n"
        );
        let answer = response_for_request(&request, Some("secret"), public_bind());
        assert!(answer.starts_with("HTTP/1.1 403"), "{path}: {answer}");
    }
}

#[test]
fn evidence_html_has_a_dedicated_script_free_policy() {
    let headers = response_head(200, "text/html; charset=utf-8; hse=dossier", 10, "");
    assert!(headers.contains("script-src 'none'; style-src 'sha256-"));
    assert!(!headers.contains("unsafe-inline"));
    assert!(headers.contains("frame-ancestors 'none'"));
}

/// Running out of descriptors or memory must not end `serve`, and losing the pending
/// connection must not even pause it; only a listener that can never accept again ends it.
#[test]
fn only_an_unusable_listener_ends_the_accept_loop() {
    use std::io::{Error as IoError, ErrorKind};
    // Linux and Android numbers: EMFILE, ENFILE, ENOMEM, ENOBUFS.
    for raw in [24, 23, 12, 105] {
        assert_eq!(
            AcceptFailure::of(&IoError::from_raw_os_error(raw)),
            AcceptFailure::Transient,
            "errno {raw}"
        );
    }
    for kind in [ErrorKind::WouldBlock, ErrorKind::OutOfMemory] {
        assert_eq!(
            AcceptFailure::of(&IoError::from(kind)),
            AcceptFailure::Transient
        );
    }
    // The one dequeued connection: EPERM, EPROTO, EOPNOTSUPP, ENETUNREACH, ECONNABORTED,
    // ECONNRESET, EHOSTUNREACH. EOPNOTSUPP is `Unsupported` from Rust 1.88, which must not
    // make it fatal.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    for raw in [1, 71, 95, 101, 103, 104, 113] {
        assert_eq!(
            AcceptFailure::of(&IoError::from_raw_os_error(raw)),
            AcceptFailure::Retry,
            "errno {raw}"
        );
    }
    for kind in [
        ErrorKind::Interrupted,
        ErrorKind::ConnectionAborted,
        ErrorKind::ConnectionReset,
        ErrorKind::HostUnreachable,
    ] {
        assert_eq!(
            AcceptFailure::of(&IoError::from(kind)),
            AcceptFailure::Retry
        );
    }
    assert_eq!(
        AcceptFailure::of(&IoError::from_raw_os_error(EBADF)),
        AcceptFailure::Fatal
    );
    // EINVAL: the socket is not listening.
    assert_eq!(
        AcceptFailure::of(&IoError::from_raw_os_error(22)),
        AcceptFailure::Fatal
    );
    // ENOTSOCK: std leaves it `Uncategorized`, so it is named by number.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert_eq!(
        AcceptFailure::of(&IoError::from_raw_os_error(88)),
        AcceptFailure::Fatal
    );
    assert_eq!(
        AcceptFailure::of(&IoError::from(ErrorKind::Unsupported)),
        AcceptFailure::Fatal
    );
}

#[test]
fn accept_pauses_back_off_to_a_ceiling_and_reset_on_success() {
    let mut failures = AcceptFailures::default();
    let pauses: Vec<_> = (0..12).map(|_| failures.pause()).collect();
    assert_eq!(pauses[0], ACCEPT_PAUSE_FIRST);
    assert!(pauses.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(pauses[11], ACCEPT_PAUSE_MOST);
    failures.recovered();
    assert_eq!(failures.pause(), ACCEPT_PAUSE_FIRST);
}

/// At a descriptor limit every finishing connection lets one `accept` succeed and the next
/// one fail again, so a notice per failure run would print once per request served.
#[test]
fn the_accept_notice_is_rate_limited_across_failure_runs() {
    let start = Instant::now();
    let mut failures = AcceptFailures::default();
    assert!(failures.notice_due(start), "the first failure is told");
    let _ = failures.pause();
    assert!(!failures.notice_due(start), "not again within the run");
    for seconds in [0, 1, 29] {
        failures.recovered();
        assert!(
            !failures.notice_due(start + Duration::from_secs(seconds)),
            "a new run {seconds} s later is not told again"
        );
        let _ = failures.pause();
    }
    failures.recovered();
    assert!(failures.notice_due(start + ACCEPT_NOTICE_EVERY));
}

/// Per-connection failures cost nothing to retry, until a run of them says the trouble is
/// not one connection.
#[test]
fn per_connection_failures_retry_at_once_until_a_burst() {
    let mut failures = AcceptFailures::default();
    assert!((0..RETRY_BURST).all(|_| failures.retry_at_once()));
    assert!(!failures.retry_at_once());
    failures.recovered();
    assert!(failures.retry_at_once());
}

#[test]
fn implicit_bind_stays_loopback_without_an_explicit_setting() {
    assert_eq!(resolve_serve_bind(None), DEFAULT_BIND);
    assert_eq!(resolve_serve_bind(Some("127.0.0.1:9000")), "127.0.0.1:9000");
    assert_eq!(resolve_serve_bind(Some("0.0.0.0:43210")), "0.0.0.0:43210");
}

#[test]
fn config_defaults_and_public_token_requirement_are_explicit() {
    let local = ServeConfig::parse(DEFAULT_BIND, None).unwrap();
    assert!(local.bind.ip().is_loopback());
    assert!(!local.needs_token());
    assert!(ServeConfig::parse("0.0.0.0:8080", None).is_err());
    assert!(ServeConfig::parse("0.0.0.0:8080", Some("   ".into())).is_err());
    assert!(
        ServeConfig::parse("0.0.0.0:8080", Some("token".into()))
            .unwrap()
            .needs_token()
    );
    assert_eq!(
        ServeConfig::parse("localhost:9000", None).unwrap().bind,
        "127.0.0.1:9000".parse::<SocketAddr>().unwrap()
    );
}

/// The phone's web UI asked for a token on every load once the installer gave the service
/// one (seen 2026-10-14, "remove these weird token requirements"). A loopback server now
/// needs none, whatever `HSE_AUTH_TOKEN` holds: every endpoint answers without
/// `Authorization`, and health tells the page not to ask.
#[test]
fn a_loopback_server_needs_no_token_even_when_one_is_supplied() {
    let lookups = echo_lookups();
    for bind in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080"] {
        for token in [None, Some("phone-service-token"), Some("   ")] {
            let config = ServeConfig::parse(bind, token.map(str::to_owned)).unwrap();
            assert!(!config.needs_token(), "{bind} {token:?}");
            let routes = Routes {
                lookups: Some(lookups.clone()),
                research: None,
                radar: None,
                cells: None,
                track: None,
                analyze: echo_seeds().analyze,
                inspect: None,
                investigate: None,
                scans: None,
                keys_home: None,
            };
            let ask = |path: &str| {
                text(respond(
                    &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
                    &config,
                    &routes,
                ))
            };
            for path in [
                "/",
                "/api/modules",
                "/api/command",
                "/api/analyze?seeds=a",
                "/api/lookup?q=a",
            ] {
                let answer = ask(path);
                assert!(
                    answer.starts_with("HTTP/1.1 200"),
                    "{bind} {token:?} {path}: {answer}"
                );
            }
            assert!(ask("/api/health").contains("\"auth\": \"none\""));
        }
    }
}

#[test]
fn pure_router_serves_health_and_protected_metadata() {
    let health = response_for_request(
        "GET /api/health HTTP/1.1\r\n\r\n",
        Some("secret"),
        public_bind(),
    );
    assert!(health.starts_with("HTTP/1.1 200"));
    assert!(health.contains("\"status\": \"ok\""));

    assert!(health.contains(&format!(
        "\"build_sha\": \"{}\"",
        crate::diagnostics::embedded_build_sha()
    )));

    let denied = response_for_request(
        "GET /api/modules HTTP/1.1\r\n\r\n",
        Some("secret"),
        public_bind(),
    );
    assert!(denied.starts_with("HTTP/1.1 401"));

    let allowed = response_for_request(
        "GET /api/modules HTTP/1.1\r\nAuthorization: bearer secret\r\n\r\n",
        Some("secret"),
        public_bind(),
    );
    assert!(allowed.starts_with("HTTP/1.1 200"));
    assert!(allowed.contains("\"modules\""));
}

#[test]
fn wifi_radar_requires_same_origin_lookup_header_and_public_bind_token() {
    let config = ServeConfig::parse("0.0.0.0:8080", Some("secret".into())).unwrap();
    let handler: RadarHandler = Arc::new(|| {
        crate::wifi_radar::parse_scan(
            br#"[{"bssid":"3C:5A:B4:11:22:33","ssid":"test","rssi":-58,"timestamp":100000000}]"#,
            Some(1000.0),
        )
        .map_err(|e| LookupError {
            status: 422,
            message: e.to_string(),
        })
    });
    let routes = Routes {
        radar: Some(Radar {
            handler,
            live: Arc::new(AtomicUsize::new(0)),
        }),
        ..Routes::default()
    };
    let request = |method: &str, headers: &str| {
        text(respond(
            &format!("{method} /api/radar/wifi HTTP/1.1\r\n{headers}\r\n"),
            &config,
            &routes,
        ))
    };
    let auth = "Authorization: Bearer secret\r\n";
    let lookup = "X-Huntsman-Lookup: 1\r\n";
    assert!(request("GET", lookup).starts_with("HTTP/1.1 401"));
    assert!(request("GET", auth).starts_with("HTTP/1.1 403"));
    assert!(
        request(
            "GET",
            &format!("{auth}{lookup}Sec-Fetch-Site: cross-site\r\n")
        )
        .starts_with("HTTP/1.1 403")
    );
    assert!(request("POST", &format!("{auth}{lookup}")).starts_with("HTTP/1.1 405"));
    assert!(request("HEAD", &format!("{auth}{lookup}")).starts_with("HTTP/1.1 405"));
    let result = request(
        "GET",
        &format!("{auth}{lookup}Sec-Fetch-Site: same-origin\r\n"),
    );
    assert!(result.starts_with("HTTP/1.1 200"), "{result}");
    let body: serde_json::Value =
        serde_json::from_str(result.split("\r\n\r\n").nth(1).unwrap_or_default()).unwrap();
    assert_eq!(body["source"], "termux-wifi-scaninfo");
    assert_eq!(body["status"], "stale_only");
    assert_eq!(body["observations"][0]["age_secs"], 900.0);
    assert!(body["observations"][0]["sighting"]["latitude"].is_null());

    // Without an installed sensor adapter the route refuses rather than
    // manufacturing a zero-observation success response.
    let missing = text(respond(
        &format!("GET /api/radar/wifi HTTP/1.1\r\n{auth}{lookup}\r\n"),
        &config,
        &Routes::default(),
    ));
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
}

#[test]
fn wifi_radar_busy_and_adapter_error_are_failures_not_empty_scans() {
    let config = ServeConfig::parse("127.0.0.1:8080", None).unwrap();
    let live = Arc::new(AtomicUsize::new(1));
    let routes = Routes {
        radar: Some(Radar {
            handler: Arc::new(|| {
                Err(LookupError {
                    status: 503,
                    message: "Termux:API unavailable".into(),
                })
            }),
            live: Arc::clone(&live),
        }),
        ..Routes::default()
    };
    let ask = || {
        text(respond(
            "GET /api/radar/wifi HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
            &config,
            &routes,
        ))
    };
    assert!(ask().starts_with("HTTP/1.1 503"));
    live.store(0, Ordering::SeqCst);
    let error = ask();
    assert!(error.starts_with("HTTP/1.1 503"));
    assert!(error.contains("Termux:API unavailable"));
}

/// A track write refusal must propagate its 503 status through the
/// guarded HTTP route instead of being reported as an internal 500.
#[test]
fn radar_track_write_unavailable_is_http_503() {
    let config = ServeConfig::parse("127.0.0.1:8080", None).unwrap();
    let track: TrackHandler = Arc::new(|| {
        Err(LookupError {
            status: 503,
            message: "tracking log is busy".into(),
        })
    });
    let routes = Routes {
        track: Some(Sensor {
            handler: track,
            live: Arc::new(AtomicUsize::new(0)),
        }),
        ..Routes::default()
    };
    let answer = text(respond(
        "POST /api/radar/track HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
        &config,
        &routes,
    ));
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.contains("tracking log is busy"));
}

/// The cells Android reports and the track log are read from the page through the Wi-Fi
/// radar's own guards: the lookup header, same origin, one method, no parameters and no body,
/// and a refusal rather than an invented reading where no adapter is installed.
#[test]
fn cell_radar_and_track_sweeps_are_served_under_the_wifi_radar_guards() {
    let config = ServeConfig::parse("127.0.0.1:8080", None).unwrap();
    let cells: CellsHandler = Arc::new(|| {
        crate::cell_radar::parse_cells(
            br#"[{"type":"gsm","mcc":505,"mnc":1,"lac":17,"cid":91,"registered":true,"dbm":-83},{"type":"lte","mcc":505,"mnc":1,"tac":19,"ci":12345,"registered":false,"dbm":-101}]"#,
        )
        .map_err(|e| LookupError {
            status: 422,
            message: e.to_string(),
        })
    });
    let track: TrackHandler = Arc::new(|| {
        let sweeps: Vec<crate::radar::LoggedSweep> = (0..3)
            .map(|i| {
                crate::radar::LoggedSweep::new(
                    1_700_000_000 + i * 600,
                    Some(format!("gsm:505-01-17-{i}")),
                    [crate::radar::LoggedDevice {
                        mac: "3c:5a:b4:11:22:33".into(),
                        name: None,
                    }],
                )
            })
            .collect();
        Ok(crate::radar::track(&sweeps, 0))
    });
    let routes = Routes {
        cells: Some(Sensor {
            handler: cells,
            live: Arc::new(AtomicUsize::new(0)),
        }),
        track: Some(Sensor {
            handler: track,
            live: Arc::new(AtomicUsize::new(0)),
        }),
        ..Routes::default()
    };
    let ask = |method: &str, path: &str, headers: &str| {
        text(respond(
            &format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n"),
            &config,
            &routes,
        ))
    };
    let lookup = "X-Huntsman-Lookup: 1\r\n";
    assert!(ask("GET", "/api/radar/cells", "").starts_with("HTTP/1.1 403"));
    assert!(ask("POST", "/api/radar/cells", lookup).starts_with("HTTP/1.1 405"));
    assert!(ask("GET", "/api/radar/track", lookup).starts_with("HTTP/1.1 405"));
    assert!(ask("POST", "/api/radar/track", "").starts_with("HTTP/1.1 403"));
    assert!(
        ask("GET", "/api/radar/cells?x=1", lookup).starts_with("HTTP/1.1 400"),
        "parameters"
    );
    assert!(
        ask(
            "POST",
            "/api/radar/track",
            &format!("{lookup}Content-Length: 3\r\n")
        )
        .starts_with("HTTP/1.1 400"),
        "body"
    );

    let answer = ask("GET", "/api/radar/cells", lookup);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let body: serde_json::Value =
        serde_json::from_str(answer.split("\r\n\r\n").nth(1).unwrap_or_default()).unwrap();
    assert_eq!(body["source"], "termux-telephony-cellinfo");
    assert_eq!(body["observations"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        body["observations"][0]["sighting"]["network_id"],
        "gsm:505-01-17-91"
    );
    assert_eq!(body["observations"][0]["mcc"], "505");
    assert_eq!(body["observations"][0]["mnc"], "01");
    assert_eq!(body["observations"][0]["registered"], true);
    assert!(body["observations"][0]["sighting"]["latitude"].is_null());

    let answer = ask("POST", "/api/radar/track", lookup);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let body: serde_json::Value =
        serde_json::from_str(answer.split("\r\n\r\n").nth(1).unwrap_or_default()).unwrap();
    assert_eq!(body["sweeps"], 3);
    assert_eq!(body["located_sweeps"], 3);
    assert_eq!(body["distinct_cells"], 3);
    assert_eq!(body["followers"][0]["mac"], "3c:5a:b4:11:22:33");
    assert_eq!(body["followers"][0]["distinct_cells"], 3);
    assert_eq!(body["recurring"][0]["sweeps_seen"], 3);

    for (method, path) in [("GET", "/api/radar/cells"), ("POST", "/api/radar/track")] {
        let missing = text(respond(
            &format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{lookup}\r\n"),
            &config,
            &Routes::default(),
        ));
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
    }
}

/// The Radar table shows every field the OS cache gives for a network, not only the coarse
/// band: the exact frequency, the channel width, the security capabilities and the OS clock the
/// age is computed from, which before reached only the exported JSON.
#[test]
fn the_radar_table_shows_every_observation_field() {
    for needed in [
        "o.frequency_mhz??''",
        "o.channel_bandwidth_mhz??''",
        "o.capabilities||o.sighting?.encryption||''",
        "o.os_timestamp_us??''",
        "<th>MHz</th><th>Width (MHz)</th><th>Security</th><th>OS clock (µs)</th>",
    ] {
        assert!(INDEX_HTML.contains(needed), "the page lacks {needed}");
    }
}

/// A correlation rule file that did not load is named on the Settings panel with its reason,
/// and a rules listing that failed for any reason but a missing scan API is shown, not hidden.
#[test]
fn the_settings_panel_names_rules_that_did_not_load() {
    for needed in [
        "if(r.error){put(tr,'',el('div','alert','Not loaded: '+(r.id||'')+' · '+r.error))",
        "rules.filter(r=>!r.error).length",
        "if(/^HTTP 404/.test(String(e&&e.message||e)))$('rules-p').hidden=true;else fail('gerror'",
    ] {
        assert!(INDEX_HTML.contains(needed), "the page lacks {needed}");
    }
}

/// The Radar tab offers both reads and the sweep from the page, each only on a press, through
/// the routes above.
#[test]
fn the_radar_tab_reads_cells_and_logs_sweeps_from_the_page() {
    for needed in [
        r#"id="rcread""#,
        r#"id="rcrows""#,
        r#"id="rtrack""#,
        r#"id="rtrows""#,
        r#"id="rrrows""#,
        "api('/api/radar/cells')",
        "api('/api/radar/track',{method:'POST'})",
        "kind:'network',depth:0",
    ] {
        assert!(INDEX_HTML.contains(needed), "the page lacks {needed}");
    }
}

/// A tab open across an upgrade notices it: the page is served with the id of the page this
/// build embeds, health names the same id, and filling it in leaves the policy's hashes valid.
#[test]
fn the_page_and_health_name_one_page_id_and_the_policy_still_matches() {
    assert!(
        PAGE_ID.len() == 16 && PAGE_ID.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{}",
        *PAGE_ID
    );
    assert!(INDEX_HTML.contains(PAGE_ID_SLOT), "the page keeps the slot");
    let page = response_for_request("GET / HTTP/1.1\r\n\r\n", None, loopback_bind());
    let body = page.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert!(
        body.contains(&format!(
            r#"<meta name="huntsman-page" content="{}">"#,
            *PAGE_ID
        )),
        "the served page carries its id"
    );
    assert_eq!(
        inline_block(body, "script"),
        inline_block(INDEX_HTML, "script")
    );
    assert_eq!(
        inline_block(body, "style"),
        inline_block(INDEX_HTML, "style")
    );
    let health = response_for_request("GET /api/health HTTP/1.1\r\n\r\n", None, loopback_bind());
    let health = health.split("\r\n\r\n").nth(1).unwrap_or_default();
    let health: serde_json::Value = serde_json::from_str(health.trim_end())
        .unwrap_or_else(|e| panic!("health is not JSON: {e}"));
    assert_eq!(health["page"], PAGE_ID.as_str());
}

/// Every `200 OK` JSON answer shares one content type and ends in exactly one newline,
/// the contract [`json_ok`] now owns in one place (as [`json_error`] owns the failure one).
/// Each route handler builds its own body, so a handler reverting to a hand-rolled
/// `response(200, …)` could drift the content type or newline; this pins all three
/// JSON success routes to the shared shape.
#[test]
fn every_json_ok_route_shares_one_content_type_and_a_single_trailing_newline() {
    for path in [
        "/api/health",
        "/api/modules",
        "/api/command",
        "/api/blueprint",
    ] {
        let answer = response_for_request(
            &format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n"),
            Some("secret"),
            loopback_bind(),
        );
        assert!(answer.starts_with("HTTP/1.1 200"), "{path}: {answer}");
        assert_eq!(
            header(&answer, "Content-Type"),
            Some("application/json; charset=utf-8"),
            "{path} content type"
        );
        let body = answer.split("\r\n\r\n").nth(1).unwrap_or_default();
        assert!(
            body.ends_with('\n') && !body.ends_with("\n\n"),
            "{path} body must end in exactly one newline: {body:?}"
        );
        // The body before that newline is valid JSON.
        serde_json::from_str::<serde_json::Value>(body.trim_end_matches('\n'))
            .unwrap_or_else(|e| panic!("{path} body is not JSON: {e}"));
    }
}

/// A token-protected server said only `{"error":"unauthorized"}`, and health gave no sign a
/// token was needed, so the page could not tell the operator what to do (seen on a phone,
/// 2026-10-14). Health now says whether the token is needed, and a refusal names the remedy
/// and carries the standard challenge.
#[test]
fn health_says_whether_a_token_is_needed_and_a_refusal_names_the_remedy() {
    let health =
        |token| response_for_request("GET /api/health HTTP/1.1\r\n\r\n", token, bind_for(token));
    assert!(health(Some("secret")).contains("\"auth\": \"token\""));
    assert!(health(None).contains("\"auth\": \"none\""));

    for path in [
        "/api/modules",
        "/api/command",
        "/api/analyze?seeds=a",
        "/api/blueprint?format=docx",
    ] {
        let denied = response_for_request(
            &format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n"),
            Some("secret"),
            public_bind(),
        );
        assert!(denied.starts_with("HTTP/1.1 401"), "{path}: {denied}");
        assert_eq!(
            header(&denied, "WWW-Authenticate"),
            Some("Bearer realm=\"huntsman-recon\"")
        );
        let body = denied.split("\r\n\r\n").nth(1).unwrap_or_default();
        let error: serde_json::Value = serde_json::from_str(body).unwrap();
        let error = error["error"].as_str().unwrap_or_default();
        assert!(
            error.starts_with("unauthorized") && error.contains("HSE_AUTH_TOKEN"),
            "{error}"
        );
    }
}

/// The phone's page asked for a token on every load (2026-10-14). It now asks only when health
/// says the server needs one, which only a public bind does: the token panel and the notice
/// start hidden, a call carries `Authorization` only then, and a loopback answer clears a token
/// an earlier page stored. A public bind still gets the field, the `#token=` fragment and the
/// prompt on a refusal.
/// Provenance the API answers reaches the screen: when each source was queried, the module and
/// false-positive flag of every graph node, every data type in the legend (no first-20 cut),
/// each Inspect reader's claim with its recording time and the full report, and a bulk action
/// that names the scans it could not act on instead of stopping at the first refusal.
#[test]
fn the_page_reaches_the_saved_scan_analysis_and_entity_assessment() {
    // /analyze and /reality are read-only routes the server answered that the page offered no
    // control for; a phone browser cannot add the lookup header to a typed URL, so they were
    // unreachable from the UI.
    let script = inline_block(INDEX_HTML, "script");
    assert!(INDEX_HTML.contains("<a class=\"tab\" data-tab=\"analysis\">Analysis</a>"));
    assert!(INDEX_HTML.contains("<div id=\"pane-analysis\" hidden>"));
    assert!(script.contains(
        "const TABS=['summary','correlations','browse','graph','analysis','settings','log'];"
    ));
    assert!(script.contains("else if(tab==='analysis')await analysis();"));
    assert!(script.contains("const r=await api(base()+'/analyze');"));
    assert!(script.contains("api(base()+'/reality?uid='+enc(x.entity))"));
    assert!(script.contains("button('Source attribution'"));
}

#[test]
fn the_page_shows_the_provenance_the_api_answers() {
    let script = inline_block(INDEX_HTML, "script");
    assert!(INDEX_HTML.contains("<th>Source</th><th>Outcome</th><th>Observed</th><th>Detail</th>"));
    assert!(
        script.contains("fill('srcs',src,o=>[o.module,'',when(o.observed_at_unix*1000),why(o)]);")
    );
    assert!(
        script.contains("(i.first_observed_unix?' · first '+when(i.first_observed_unix*1000):'')")
    );
    assert!(script.contains("(i.category?' · '+i.category:'')+(i.outcome?' · '+i.outcome:'')"));
    assert!(script.contains("module:n.module,fp:!!n.fp,"));
    assert!(script.contains("(n.module?' · '+n.module:'')+(n.fp?' · false positive':'')"));
    assert!(script.contains("for(const t of types){"));
    assert!(!script.contains("types.slice(0,20)"));
    assert!(script.contains("lg.append(el('span','',flagged+' flagged false positive'))"));
    assert!(INDEX_HTML.contains("<th>source</th><th>claim</th><th>recorded</th>"));
    assert!(INDEX_HTML.contains("<th>source</th><th>field</th><th>value</th><th>recorded</th>"));
    assert!(
        INDEX_HTML.contains(
            r#"<details><summary>Full report</summary><pre id="ireport"></pre></details>"#
        )
    );
    assert!(script.contains("claims.push([src,x.summary,at]);"));
    assert!(script.contains("at=when(x.provenance?.recorded_at_unix*1000)"));
    assert!(script.contains("$('ireport').textContent=r.text||'';"));
    assert!(script.contains("when(e.observed_at_unix*1000)"));
    assert!(script.contains("(o.observed_at_unix?' at '+when(o.observed_at_unix*1000):'')"));
    assert!(
        script.contains("failed.push(((scans.find(s=>s.id===id)||{}).name||id)+': '+e.message)")
    );
    assert!(script.contains("fail(where,(ids.length-failed.length)+' of '+ids.length+' done · failed: '+failed.join(' · '))"));
}

#[test]
fn the_page_asks_for_a_token_only_when_the_server_needs_one() {
    let script = inline_block(INDEX_HTML, "script");
    assert!(INDEX_HTML.contains(r#"<p class="alert warn" id="authnote" role="alert" hidden></p>"#));
    assert!(INDEX_HTML.contains(r#"<div class="panel" id="tokenpanel" hidden>"#));
    assert!(script.contains("if(needsToken&&token)h.Authorization='Bearer '+token"));
    assert!(script.contains("if(b.auth==='token'){\n        needsToken=true;"));
    // A stored token is tried without fetching a body: HEAD answers 401 or 200 and nothing else.
    assert!(script.contains("refused(await call('/api/command',{},{method:'HEAD'}))"));
    assert!(script.contains("else{needsToken=false;token='';store.set('hse-token','');"));
    assert!(script.contains("const refused=res=>{if(res.r.status===401){askToken();return true}"));
    assert_eq!(script.matches("refused(res)").count(), 3);
    // Every request goes through `call`, which adds the header, except an export, which is
    // read as a file and sends the same headers: no bare `fetch` elsewhere.
    assert_eq!(script.matches("fetch(").count(), 2);
    assert!(script.contains("r=await fetch(path,{headers:headers(LH),"));
    assert!(script.contains("/(?:^#|&)token=([^&]*)/.exec(location.hash)"));
    assert!(script.contains("history.replaceState("));
}

/// The page is laid out as Spiderfoot 4.0's: an app bar with the locator mark, the theme switch
/// and About, Spiderfoot's New Scan, Scans and Settings plus Analyze as tabs (a bottom tab bar
/// on a phone, a top nav on a wider screen), one scan's sections under `#/scan/ID`, two scans
/// compared under `#/compare/A/B`, and a view for each.
#[test]
fn the_page_is_the_console_shell_with_a_tab_per_view() {
    assert!(INDEX_HTML.contains(r#"<header class="appbar">"#));
    assert!(INDEX_HTML.contains(r#"<nav class="navbar" aria-label="Primary">"#));
    let script = inline_block(INDEX_HTML, "script");
    assert!(script.contains(
        "const VIEWS=['scans','newscan','scan','compare','analyze','radar','inspect','settings','about'];"
    ));
    for view in [
        "newscan", "scans", "analyze", "radar", "inspect", "settings",
    ] {
        assert!(
            INDEX_HTML.contains(&format!(
                r##"<a class="navlink" data-view="{view}" href="#/{view}">"##
            )),
            "{view}"
        );
    }
    assert!(INDEX_HTML.contains(r##"<a class="iconbtn" id="nav-about" href="#/about""##));
    for view in [
        "scans", "newscan", "scan", "compare", "analyze", "radar", "settings", "about",
    ] {
        assert!(
            INDEX_HTML.contains(&format!(r#"<section id="view-{view}" hidden>"#)),
            "{view}"
        );
    }
    // Spiderfoot's sections of one scan, and the addresses an older page used.
    assert!(script.contains(
        "const TABS=['summary','correlations','browse','graph','analysis','settings','log'];"
    ));
    assert!(script.contains("({lookup:'newscan',status:'about'})[parts[0]]"));
    let style = inline_block(INDEX_HTML, "style");
    assert!(style.contains(".navbar{position:fixed;left:0;right:0;bottom:0;"));
    assert!(style.contains("@media (min-width:768px){\n.navbar{top:"));
    let icon = response_for_request(
        "GET /favicon.svg HTTP/1.1\r\nHost: localhost\r\n\r\n",
        None,
        loopback_bind(),
    );
    assert!(icon.starts_with("HTTP/1.1 200"), "{icon}");
    assert_eq!(header(&icon, "Content-Type"), Some("image/svg+xml"));
    assert!(INDEX_HTML.contains(r#"<link rel="icon" href="/favicon.svg" type="image/svg+xml">"#));
}

#[test]
fn head_has_get_content_length_but_no_body() {
    let get = response_for_request("GET /api/health HTTP/1.1\r\n\r\n", None, loopback_bind());
    let head = response_for_request("HEAD /api/health HTTP/1.1\r\n\r\n", None, loopback_bind());
    let get_len = get
        .lines()
        .find(|line| line.starts_with("Content-Length:"))
        .unwrap();
    let head_len = head
        .lines()
        .find(|line| line.starts_with("Content-Length:"))
        .unwrap();
    assert_eq!(get_len, head_len);
    assert!(head.ends_with("\r\n\r\n"));
}

#[test]
fn loopback_server_handles_one_real_request() {
    let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = thread::spawn(move || server.run_n(1).unwrap());

    let mut client = TcpStream::connect(addr).unwrap();
    client
        .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    handle.join().unwrap();

    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("huntsman-recon"));
}

fn serve_in_background() -> SocketAddr {
    let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let _ = server.run(|_| {});
    });
    addr
}

/// The largest analysis the server admits, every seed byte percent-encoded, sent with headers
/// that fill the allowance: the whole request is read and answered. With the 16 KiB request
/// cap it was refused `413`, and so was the page's own longest input (2,048 CJK characters).
#[test]
fn the_largest_admitted_analysis_is_read_whole() {
    use std::fmt::Write as _;

    let mut server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap()).unwrap();
    server.routes = echo_seeds();
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let _ = server.run(|_| {});
    });
    let seed = "é".repeat(MAX_SELECTOR_BYTES / 2);
    assert_eq!(seed.len(), MAX_SELECTOR_BYTES);
    let encoded = seed.bytes().fold(String::new(), |mut encoded, byte| {
        write!(encoded, "%{byte:02X}").unwrap();
        encoded
    });
    let head = format!(
        "GET /api/analyze?seeds={} HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\nX-Pad: ",
        vec![encoded; MAX_ANALYZE_SEEDS].join("%0A")
    );
    let bound = LARGEST_ANALYSIS_SEEDS + HEADER_ALLOWANCE;
    let request = format!("{head}{}\r\n\r\n", "p".repeat(bound - head.len() - 4));
    assert_eq!(request.len(), bound);
    assert!(request.len() > 16 * 1024);

    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{}", &response[..80]);
    let body: serde_json::Value =
        serde_json::from_str(&response[response.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(
        body["seeds"],
        serde_json::json!(vec![seed; MAX_ANALYZE_SEEDS])
    );
}

fn get_within(addr: SocketAddr, path: &str, wait: Duration) -> std::io::Result<String> {
    let mut client = TcpStream::connect(addr)?;
    client.set_read_timeout(Some(wait))?;
    client.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())?;
    let mut response = String::new();
    match client.read_to_string(&mut response) {
        // A refused connection is closed with the request unread, which resets it after the
        // reply has been delivered.
        Err(error)
            if error.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() => {}
        outcome => {
            outcome?;
        }
    }
    Ok(response)
}

/// Every response has a deadline paced by its size, not only an inspection's: a reader that
/// took a byte every few seconds held its connection's place for as long as it liked, and 32
/// of them answered every other request `503`.
#[test]
fn every_response_is_written_by_a_deadline_paced_by_its_size() {
    let now = Instant::now();
    let page = write_deadline(120 * 1024, false);
    assert!(page >= now + REQUEST_DEADLINE + Duration::from_secs(7));
    assert!(page <= Instant::now() + REQUEST_DEADLINE + Duration::from_secs(8));
    let large = write_deadline(64 * 1024 * 1024, false);
    assert!(large >= now + REQUEST_DEADLINE + Duration::from_secs(4096));
    let inspection = write_deadline(0, true);
    assert!(inspection >= now + INSPECT_DEADLINE);
}

#[test]
fn a_reader_that_never_reads_is_cut_off_at_the_write_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    // More than the socket buffers on both sides hold, so the writer blocks on the reader.
    let response = vec![b'x'; 64 * 1024 * 1024];
    let started = Instant::now();
    let error = write_within(&mut server, &response, started + Duration::from_millis(300))
        .expect_err("the reader never read");
    assert!(started.elapsed() < Duration::from_secs(3), "{error}");
}

#[test]
fn an_idle_connection_does_not_hold_up_the_next_request() {
    // A browser opens speculative connections and sends nothing on them. The accept loop used
    // to serve one connection at a time, so each of these stalled the page for IO_TIMEOUT.
    let addr = serve_in_background();
    let _idle = [
        TcpStream::connect(addr).unwrap(),
        TcpStream::connect(addr).unwrap(),
    ];
    let started = Instant::now();
    let response = get_within(addr, "/api/health", Duration::from_secs(3))
        .expect("the request was answered while other connections sat idle");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        started.elapsed() < IO_TIMEOUT,
        "the request waited for the idle connections"
    );
}

#[test]
fn connections_past_the_cap_are_answered_busy_and_their_places_come_back() {
    let addr = serve_in_background();
    let idle: Vec<TcpStream> = (0..MAX_CONNECTIONS)
        .map(|_| TcpStream::connect(addr).unwrap())
        .collect();
    let refused = get_within(addr, "/api/health", Duration::from_secs(3)).unwrap();
    assert!(
        refused.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{refused}"
    );
    assert!(refused.contains("Retry-After: 1\r\n"), "{refused}");

    drop(idle);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let response = get_within(addr, "/api/health", Duration::from_secs(3)).unwrap();
        if response.starts_with("HTTP/1.1 200") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the places never came back: {response}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Connections that send nothing, in every place for longer than `IDLE_GRACE`, kept every
/// request out for the whole read budget: `503` for 5 s, and for as long as someone renews
/// them (any app on the phone can open loopback connections). A request that finds every
/// place taken now closes the connection that has waited longest, and is served; the other
/// idle connections keep their places.
#[test]
fn a_request_at_the_cap_closes_the_longest_waiting_connection() {
    let addr = serve_in_background();
    let mut idle: Vec<TcpStream> = (0..MAX_CONNECTIONS)
        .map(|_| TcpStream::connect(addr).unwrap())
        .collect();
    thread::sleep(IDLE_GRACE + Duration::from_millis(200));

    let started = Instant::now();
    let response = get_within(addr, "/api/health", Duration::from_secs(3)).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(started.elapsed() < IDLE_GRACE, "{:?}", started.elapsed());

    let mut byte = [0_u8; 1];
    idle[0]
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(
        idle[0].read(&mut byte).unwrap(),
        0,
        "the longest waiting connection is closed"
    );
    idle[1]
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let next = idle[1].read(&mut byte).unwrap_err().kind();
    assert!(
        matches!(
            next,
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "the next one still waits: {next:?}"
    );
}

#[test]
fn statuses_carry_their_reason_phrases() {
    for (status, phrase) in [
        (408, "Request Timeout"),
        (503, "Service Unavailable"),
        (504, "Gateway Timeout"),
    ] {
        let rendered = response(status, "text/plain; charset=utf-8", "x\n", false);
        assert!(
            rendered.starts_with(&format!("HTTP/1.1 {status} {phrase}\r\n")),
            "{rendered}"
        );
    }
    assert!(
        response_for_request("REQUEST_TIMEOUT", None, loopback_bind())
            .starts_with("HTTP/1.1 408 Request Timeout")
    );
}

/// A form body within `MAX_FORM_BYTES` is read whole behind a long head: the request used to be
/// cut at `MAX_REQUEST_BYTES` in all, so a large key import behind a 9 KiB cookie header lost
/// its end and was refused as too large.
#[test]
fn a_whole_form_body_is_read_behind_a_long_head() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let body = "v".repeat(MAX_FORM_BYTES);
    let head = format!(
        "POST /api/settings/keys HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: c={}\r\nContent-Length: {}\r\n\r\n",
        "x".repeat(HEADER_ALLOWANCE + 1024),
        body.len()
    );
    let writer = thread::spawn(move || {
        client.write_all(head.as_bytes()).unwrap();
        client.write_all(body.as_bytes()).unwrap();
        client
    });
    let request = read_request(&mut server, Instant::now() + Duration::from_secs(5)).unwrap();
    let _client = writer.join().unwrap();
    let (_, read_body) = request.split_once("\r\n\r\n").expect("a head");
    assert_eq!(read_body.len(), MAX_FORM_BYTES);
}

#[test]
fn a_request_past_its_deadline_times_out_without_blocking() {
    // A deadline already in the past makes read_request stop on the first iteration and
    // return the timeout sentinel, before any blocking read. This is the whole-request
    // bound that a per-read socket timeout alone does not give against a dribbling client.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _client = TcpStream::connect(addr).unwrap(); // connects, sends nothing
    let (mut server, _) = listener.accept().unwrap();
    // A deadline captured now is already elapsed when read_request re-reads the clock,
    // so `remaining` saturates to zero on the first iteration.
    let deadline = Instant::now();
    assert_eq!(
        read_request(&mut server, deadline).unwrap(),
        "REQUEST_TIMEOUT",
        "an elapsed deadline must stop the read, not block on the silent client"
    );
    assert!(
        response_for_request("REQUEST_TIMEOUT", None, loopback_bind()).starts_with("HTTP/1.1 408"),
        "the timeout sentinel renders as 408 Request Timeout"
    );
}

#[test]
fn fixed_time_compare_requires_exact_bytes() {
    assert!(fixed_time_eq(b"abc", b"abc"));
    assert!(!fixed_time_eq(b"abc", b"abd"));
    assert!(!fixed_time_eq(b"abc", b"ab"));
}

#[test]
fn bind_parser_accepts_ipv4_and_ipv6_socket_addresses() {
    assert_eq!(
        normalize_bind("127.0.0.1:8080").unwrap().ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        normalize_bind("[::1]:8080").unwrap().ip(),
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    );
}

#[test]
fn a_client_that_sends_nothing_gets_a_408_when_its_read_times_out() {
    // A connection that never sends a byte used to be dropped without a reply, so the 408
    // that the timeout sentinel renders never reached the client.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    let config = ServeConfig::parse("127.0.0.1:0", None).unwrap();
    let handle = thread::spawn(move || handle_stream(&config, server));
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    handle.join().unwrap().unwrap();
    assert!(
        response.starts_with("HTTP/1.1 408 Request Timeout"),
        "{response}"
    );
}

#[test]
fn opaque_header_bytes_do_not_refuse_a_valid_request() {
    // RFC 9110 allows bytes outside ASCII in field values (obs-text). Refusing the whole
    // request for one such byte left a valid client with no reply at all.
    let addr = serve_in_background();
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nX-Note: caf\xe9\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[test]
fn host_allowlist_accepts_only_loopback_authorities() {
    for allowed in [
        "localhost",
        "LOCALHOST",
        "localhost:8080",
        "127.0.0.1",
        "127.0.0.1:8080",
        "127.0.0.5:8080",
        "[::1]",
        "[::1]:8080",
    ] {
        assert!(
            host_is_allowed_for_loopback(Some(allowed)),
            "{allowed} should be allowed"
        );
    }
    assert!(host_is_allowed_for_loopback(None));
    assert!(host_is_allowed_for_loopback(Some("")));
    for denied in [
        "rebind.example.com",
        "127.0.0.1.evil.com",
        "localhost.evil.com",
        "10.0.0.1:8080",
        "evil.com:127.0.0.1",
        "example.com",
    ] {
        assert!(
            !host_is_allowed_for_loopback(Some(denied)),
            "{denied} should be denied"
        );
    }
}

#[test]
fn a_loopback_server_refuses_a_rebound_host_on_every_endpoint() {
    // A page on a public origin rebound to loopback makes the browser send that
    // public name in Host. No endpoint, authenticated or not, may answer it.
    let bind = loopback_bind();
    for path in [
        "/",
        "/index.html",
        "/api/health",
        "/api/modules",
        "/api/command",
    ] {
        let rebound = response_for_request(
            &format!("GET {path} HTTP/1.1\r\nHost: rebind.example.com\r\n\r\n"),
            None,
            bind,
        );
        assert!(
            rebound.starts_with("HTTP/1.1 403 Forbidden"),
            "{path}: {rebound}"
        );
    }
}

#[test]
fn a_loopback_server_still_answers_loopback_and_hostless_requests() {
    let bind = loopback_bind();
    for host in [
        "localhost",
        "localhost:8080",
        "127.0.0.1:8080",
        "[::1]:8080",
    ] {
        let ok = response_for_request(
            &format!("GET /api/health HTTP/1.1\r\nHost: {host}\r\n\r\n"),
            None,
            bind,
        );
        assert!(ok.starts_with("HTTP/1.1 200"), "{host}: {ok}");
    }
    let hostless = response_for_request("GET /api/health HTTP/1.1\r\n\r\n", None, bind);
    assert!(hostless.starts_with("HTTP/1.1 200"), "{hostless}");
}

#[test]
fn the_host_guard_refuses_a_rebound_host_whatever_it_carries() {
    // A loopback server needs no token, so the Host guard is what keeps a rebound page
    // out: a request with a disallowed Host is refused even when it carries a token.
    let served = response_for_request(
        "GET /api/command HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer secret\r\n\r\n",
        Some("secret"),
        loopback_bind(),
    );
    assert!(served.starts_with("HTTP/1.1 403 Forbidden"), "{served}");
}

#[test]
fn a_public_bind_is_not_subject_to_the_host_guard() {
    // A non-loopback bind is intentionally public and gated by the bearer token; its
    // real Host (a public hostname, say) is unknown here, so the guard must not
    // apply or it would refuse every real request.
    let public = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
    let served = response_for_request(
        "GET /api/health HTTP/1.1\r\nHost: huntsman.example.test\r\n\r\n",
        Some("secret"),
        public,
    );
    assert!(served.starts_with("HTTP/1.1 200"), "{served}");
}

fn echo_lookups() -> Lookups {
    Lookups {
        handler: Arc::new(|query: &LookupQuery| {
            assert!(query.selector != "boom", "handler panicked");
            if query.selector == "refused" {
                return Err(LookupError {
                    status: 422,
                    message: "no".into(),
                });
            }
            if query.selector == "slow" {
                thread::sleep(Duration::from_secs(1));
            }
            Ok(LookupReport {
                route: "email",
                text: format!("{}|{}", query.kind, query.selector),
                entities: Vec::new(),
                outcomes: Vec::new(),
                scan: None,
                status: None,
            })
        }),
        live: Arc::new(AtomicUsize::new(0)),
        wait: Duration::from_secs(10),
    }
}

fn lookup(request: &str, token: Option<&str>, lookups: Option<&Lookups>) -> String {
    let routes = Routes {
        lookups: lookups.cloned(),
        research: None,
        radar: None,
        cells: None,
        track: None,
        analyze: None,
        inspect: None,
        investigate: None,
        scans: None,
        keys_home: None,
    };
    text(respond(
        request,
        &test_config(bind_for(token), token),
        &routes,
    ))
}

const HEADER: &str = "X-Huntsman-Lookup: 1\r\n";

#[test]
fn the_page_offers_every_lookup_kind_the_cli_routes() {
    // New Scan's target type is how a phone user names a kind; a kind missing from it is
    // reachable only by `auto` inference, and an SSID never is.
    let picker = &INDEX_HTML[INDEX_HTML.find(r#"<select id="skind">"#).unwrap()..];
    let picker = &picker[..picker.find("</select>").unwrap()];
    assert!(picker.starts_with(r#"<select id="skind"><option value="auto">"#));
    for kind in crate::scan_route::ScanKind::ALL {
        let option = format!("<option value=\"{}\">", kind.command());
        assert!(picker.contains(&option), "missing {option}");
    }
    assert_eq!(
        picker.matches("<option ").count(),
        1 + crate::scan_route::ScanKind::ALL.len()
    );
}

#[test]
fn lookup_is_absent_until_the_binary_installs_a_handler() {
    let got = lookup(
        &format!("GET /api/lookup?q=a HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
        None,
        None,
    );
    assert!(got.starts_with("HTTP/1.1 404"), "{got}");
}

#[test]
fn lookup_decodes_the_query_and_returns_the_report() {
    let lookups = echo_lookups();
    let got = lookup(
        &format!(
            "GET /api/lookup?kind=Email&q=ada%40example.com+x HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\n{HEADER}\r\n"
        ),
        None,
        Some(&lookups),
    );
    assert!(got.starts_with("HTTP/1.1 200"), "{got}");
    assert!(got.contains(r#""text":"email|ada@example.com x""#), "{got}");
    let auto = lookup(
        &format!("GET /api/lookup?q=x HTTP/1.1\r\n{HEADER}\r\n"),
        None,
        Some(&lookups),
    );
    assert!(auto.contains(r#""text":"auto|x""#), "{auto}");
}

#[test]
fn a_cross_site_or_headerless_lookup_never_reaches_the_handler() {
    let lookups = echo_lookups();
    for request in [
        "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\n\r\n".to_owned(),
        format!(
            "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: cross-site\r\n{HEADER}\r\n"
        ),
        format!(
            "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-site\r\n{HEADER}\r\n"
        ),
        "GET /api/lookup?q=boom HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: yes\r\n\r\n"
            .to_owned(),
    ] {
        let got = lookup(&request, None, Some(&lookups));
        assert!(got.starts_with("HTTP/1.1 403"), "{request:?} -> {got}");
    }
    let head = lookup(
        &format!("HEAD /api/lookup?q=boom HTTP/1.1\r\n{HEADER}\r\n"),
        None,
        Some(&lookups),
    );
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");
}

#[test]
fn a_configured_token_guards_lookup() {
    let lookups = echo_lookups();
    let request = format!("GET /api/lookup?q=a HTTP/1.1\r\n{HEADER}\r\n");
    assert!(lookup(&request, Some("secret"), Some(&lookups)).starts_with("HTTP/1.1 401"));
    let authed =
        format!("GET /api/lookup?q=a HTTP/1.1\r\nAuthorization: Bearer secret\r\n{HEADER}\r\n");
    assert!(lookup(&authed, Some("secret"), Some(&lookups)).starts_with("HTTP/1.1 200"));
}

#[test]
fn lookup_errors_panics_and_capacity_are_answered_and_slots_are_freed() {
    let lookups = echo_lookups();
    let ask = |q: &str| {
        lookup(
            &format!("GET /api/lookup?q={q} HTTP/1.1\r\n{HEADER}\r\n"),
            None,
            Some(&lookups),
        )
    };
    assert!(ask("boom").starts_with("HTTP/1.1 500"));
    assert_eq!(
        lookups.live.load(Ordering::Acquire),
        0,
        "a panic frees its slot"
    );
    // A client that has its answer can ask again at once: the slot is free before the answer
    // is sent, never a moment after it.
    for round in 0..500 {
        for (q, status) in [("refused", "HTTP/1.1 422"), ("a", "HTTP/1.1 200")] {
            assert!(ask(q).starts_with(status));
            assert_eq!(
                lookups.live.load(Ordering::Acquire),
                0,
                "the answered lookup {q:?} still held its slot in round {round}"
            );
        }
    }
    assert!(ask("").starts_with("HTTP/1.1 400"));
    assert!(ask(&"a".repeat(MAX_SELECTOR_BYTES + 1)).starts_with("HTTP/1.1 400"));
    lookups.live.store(MAX_LOOKUPS, Ordering::Release);
    assert!(ask("a").starts_with("HTTP/1.1 503"));
    lookups.live.store(0, Ordering::Release);
    assert!(ask("a").starts_with("HTTP/1.1 200"));
}

#[test]
fn a_lookup_without_saved_scans_answers_504_when_its_wait_runs_out() {
    let lookups = Lookups {
        wait: Duration::from_millis(100),
        ..echo_lookups()
    };
    let got = lookup(
        &format!("GET /api/lookup?q=slow HTTP/1.1\r\n{HEADER}\r\n"),
        None,
        Some(&lookups),
    );
    assert!(got.starts_with("HTTP/1.1 504"), "{got}");
    assert!(got.contains("keeps no saved scans"), "{got}");
    // The request is answered; the lookup holds its place until it ends, then frees it.
    assert_eq!(lookups.live.load(Ordering::Acquire), 1);
    let freed = Instant::now() + Duration::from_secs(5);
    while lookups.live.load(Ordering::Acquire) != 0 {
        assert!(Instant::now() < freed, "the slot was never freed");
        thread::sleep(Duration::from_millis(10));
    }
}

/// A server with lookups and saved scans over `lookup` in a scratch store, waiting `wait`.
fn saved_lookup_routes(
    tag: &str,
    lookup: crate::scan_service::ScanLookup,
    wait: Duration,
) -> (Routes, std::path::PathBuf) {
    use crate::scan_store::ScanStore;
    let dir = std::env::temp_dir().join(format!("hse-serve-lookup-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let api = ScanApi::new(
        ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
        None,
    );
    let routes = Routes {
        lookups: Some(Lookups {
            wait,
            ..echo_lookups()
        }),
        research: None,
        radar: None,
        cells: None,
        track: None,
        analyze: None,
        inspect: None,
        investigate: None,
        scans: Some(Arc::new(api)),
        keys_home: None,
    };
    (routes, dir)
}

fn found_phone(selector: &str) -> crate::scan_service::LookupOutput {
    crate::scan_service::LookupOutput {
        text: format!("report on {selector}"),
        entities: vec![
            crate::entity::Entity::builder(crate::entity::EntityKind::Phone, selector, 0.9, "s")
                .build(),
        ],
        outcomes: Vec::new(),
    }
}

fn scan_of(answer: &str) -> String {
    let body = &answer[answer.find("\r\n\r\n").unwrap() + 4..];
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    value["scan"].as_str().unwrap().to_owned()
}

const PHONE_LOOKUP: &str = "GET /api/lookup?kind=phone&q=%2B61412345678 HTTP/1.1\r\n";

#[test]
fn a_lookup_with_saved_scans_is_kept_as_a_scan_and_names_it() {
    let lookup: crate::scan_service::ScanLookup = Arc::new(
        |_kind, selector: &str, _: &crate::module_selection::Selection| Ok(found_phone(selector)),
    );
    let (routes, dir) = saved_lookup_routes("kept", lookup, Duration::from_secs(10));
    let got = scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
    assert!(got.starts_with("HTTP/1.1 200"), "{got}");
    // The report the legacy handler gave, with the scan it ran as.
    for part in [
        r#""route":"phone""#,
        r#""value":"+61412345678""#,
        r#""text":"report on +61412345678""#,
        r#""status":"FINISHED""#,
    ] {
        assert!(got.contains(part), "{part} in {got}");
    }
    let id = scan_of(&got);
    let record = scans_request(
        &routes,
        None,
        &format!("GET /api/scans/{id} HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(record.starts_with("HTTP/1.1 200"), "{record}");
    assert!(record.contains(r#""status":"FINISHED""#), "{record}");
    let listed = scans_request(
        &routes,
        None,
        &format!("GET /api/scans HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(listed.contains(&id), "{listed}");
    // A target the scan cannot route is refused before any scan is kept.
    let bad = scans_request(
        &routes,
        None,
        &format!("GET /api/lookup?kind=ip&q=nope HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
    let api = routes.scans.as_ref().unwrap();
    assert_eq!(api.service().store().list().unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_lookup_past_its_wait_answers_504_and_its_scan_runs_on_and_is_joined() {
    let gate = Arc::new(Mutex::new(()));
    let calls = Arc::new(AtomicUsize::new(0));
    let lookup: crate::scan_service::ScanLookup = {
        let (gate, calls) = (Arc::clone(&gate), Arc::clone(&calls));
        Arc::new(
            move |_kind, selector: &str, _: &crate::module_selection::Selection| {
                calls.fetch_add(1, Ordering::AcqRel);
                drop(gate.lock().unwrap_or_else(PoisonError::into_inner));
                Ok(found_phone(selector))
            },
        )
    };
    let (routes, dir) = saved_lookup_routes("wait", lookup, Duration::from_millis(150));
    let held = gate.lock().unwrap();
    let ask = || scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
    let first = ask();
    assert!(first.starts_with("HTTP/1.1 504"), "{first}");
    let id = scan_of(&first);
    assert!(first.contains(&format!("/api/scans/{id}")), "{first}");
    // A reload while it runs waits on the same scan instead of starting another.
    let reload = ask();
    assert!(reload.starts_with("HTTP/1.1 504"), "{reload}");
    assert_eq!(scan_of(&reload), id);
    let service = Arc::clone(routes.scans.as_ref().unwrap().service());
    assert_eq!(service.store().list().unwrap().len(), 1);
    drop(held);
    let done = service
        .wait(&id, Instant::now() + Duration::from_secs(10))
        .unwrap();
    assert_eq!(done.status, ScanStatus::Finished);
    assert_eq!(
        calls.load(Ordering::Acquire),
        1,
        "one lookup ran for both requests"
    );
    let results = service.store().results(&id).unwrap().unwrap();
    assert_eq!(results.entities.len(), 1, "what it found was kept");
    // Once it has ended, the same lookup is a new scan, given the time to run this time.
    let mut routes = routes;
    routes.lookups.as_mut().unwrap().wait = Duration::from_secs(10);
    let again = scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
    assert!(again.starts_with("HTTP/1.1 200"), "{again}");
    assert_ne!(scan_of(&again), id);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_saved_lookup_that_finds_nothing_answers_502_with_its_reason_and_scan() {
    let lookup: crate::scan_service::ScanLookup = Arc::new(
        |_kind, _selector: &str, _: &crate::module_selection::Selection| {
            Err("every source failed".to_owned())
        },
    );
    let (routes, dir) = saved_lookup_routes("failed", lookup, Duration::from_secs(10));
    let got = scans_request(&routes, None, &format!("{PHONE_LOOKUP}{HEADER}\r\n"));
    assert!(got.starts_with("HTTP/1.1 502"), "{got}");
    assert!(got.contains("every source failed"), "{got}");
    let id = scan_of(&got);
    let api = routes.scans.as_ref().unwrap();
    assert_eq!(
        api.service().store().get(&id).unwrap().status,
        ScanStatus::ErrorFailed
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response
        .split("\r\n\r\n")
        .next()?
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
}

#[test]
fn a_bind_failure_names_its_cause_and_what_to_pass_instead() {
    use std::io::{Error as IoError, ErrorKind};
    let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let low: SocketAddr = "0.0.0.0:80".parse().unwrap();
    let v6: SocketAddr = "[::1]:8080".parse().unwrap();
    assert_eq!(
        bind_failure(v4, &IoError::from(ErrorKind::AddrInUse)).to_string(),
        "store: serve bind 127.0.0.1:8080: another program already listens there; stop it, or pass --bind 127.0.0.1:PORT for another port (port 0 picks a free one)"
    );
    assert!(
        bind_failure(v6, &IoError::from(ErrorKind::AddrInUse))
            .to_string()
            .contains("pass --bind [::1]:PORT")
    );
    assert_eq!(
        bind_failure(low, &IoError::from(ErrorKind::PermissionDenied)).to_string(),
        "store: serve bind 0.0.0.0:80: a port below 1024 needs root, which Termux does not have; pass --bind 0.0.0.0:PORT with a port of 1024 or more"
    );
    // Above 1024 a refusal is not about root, and other failures keep the system's words.
    let refused = IoError::from(ErrorKind::PermissionDenied);
    assert_eq!(
        bind_failure(v4, &refused).to_string(),
        format!("store: serve bind 127.0.0.1:8080: {refused}")
    );
    let other = IoError::from(ErrorKind::AddrNotAvailable);
    assert_eq!(
        bind_failure(v4, &other).to_string(),
        format!("store: serve bind 127.0.0.1:8080: {other}")
    );
}

#[test]
fn every_response_refuses_framing_and_outside_loads() {
    for request in [
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
        "HEAD / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
        "GET /api/modules HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
        "GET /missing HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        "REQUEST_TOO_LARGE",
    ] {
        let response = response_for_request(request, None, loopback_bind());
        assert_eq!(
            header(&response, "X-Frame-Options"),
            Some("DENY"),
            "{request}"
        );
        let policy = header(&response, "Content-Security-Policy").unwrap_or_default();
        assert!(
            policy.starts_with("default-src 'none';"),
            "{request}: {policy}"
        );
        assert!(
            policy.ends_with("frame-ancestors 'none'"),
            "{request}: {policy}"
        );
    }
}

#[test]
fn the_page_policy_allows_exactly_the_page_inline_script_and_style() {
    let response = response_for_request(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
        None,
        loopback_bind(),
    );
    let policy = header(&response, "Content-Security-Policy").unwrap();
    // Hashes of what a browser hashes: the exact text inside each element.
    let between = |open: &str, close: &str| {
        let start = INDEX_HTML.find(open).unwrap() + open.len();
        let end = INDEX_HTML.find(close).unwrap();
        crate::base64::standard(&crate::sha256::sha256(&INDEX_HTML.as_bytes()[start..end]))
    };
    assert!(
        policy.contains(&format!(
            "script-src 'sha256-{}';",
            between("<script>", "</script>")
        )),
        "{policy}"
    );
    assert!(
        policy.contains(&format!(
            "style-src 'sha256-{}';",
            between("<style>", "</style>")
        )),
        "{policy}"
    );
    assert!(policy.contains("connect-src 'self';"), "{policy}");
    assert!(!policy.contains("unsafe"), "{policy}");
}

/// The hashes cover the two inline blocks and nothing else. A second block, an inline event
/// handler, a `style` attribute or a `javascript:` URL would be blocked by the policy, and the
/// page would break in the browser with nothing failing here.
#[test]
fn the_page_keeps_only_what_its_policy_allows() {
    assert_eq!(INDEX_HTML.matches("<script").count(), 1);
    assert_eq!(INDEX_HTML.matches("<style").count(), 1);
    assert!(INDEX_HTML.contains("<script>") && INDEX_HTML.contains("<style>"));
    let script = inline_block(INDEX_HTML, "script");
    let style = inline_block(INDEX_HTML, "style");
    assert!(!script.trim().is_empty() && !style.trim().is_empty());
    assert!(!INDEX_HTML.to_ascii_lowercase().contains("javascript:"));
    // The markup outside the two blocks: every attribute of every tag.
    let markup = INDEX_HTML.replace(script, "").replace(style, "");
    let attributes: Vec<String> = markup
        .split('<')
        .skip(1)
        .filter_map(|tag| tag.split('>').next())
        .flat_map(|tag| tag.split_whitespace().skip(1).map(str::to_ascii_lowercase))
        .collect();
    assert!(!attributes.is_empty());
    for attribute in &attributes {
        let name = attribute.split('=').next().unwrap_or_default();
        assert!(
            !(name.starts_with("on") && name.len() > 2) && name != "style",
            "the policy would block attribute {attribute:?}"
        );
    }
}

#[test]
fn the_page_never_writes_provider_text_as_markup() {
    assert!(!INDEX_HTML.contains("innerHTML"));
    assert!(!INDEX_HTML.contains("insertAdjacentHTML"));
    assert!(INDEX_HTML.contains("'X-Huntsman-Lookup':'1'"));
}

/// Some refusals are plain text, not JSON: `503 busy` at the connection cap, `413` for an
/// oversized request, `408`. The page parsed every answer as JSON before reading its status,
/// so it showed a parser error instead of the refusal. It now reads each answer as text and
/// parses JSON only when it can (checked in Chromium: a `413` reads `HTTP 413 · request too
/// large`, where it read `SyntaxError: Unexpected token 'r'`).
#[test]
fn the_page_reads_a_plain_text_refusal() {
    let script = inline_block(INDEX_HTML, "script");
    assert!(
        !script.contains(".json()"),
        "an answer parsed as JSON before its status was read"
    );
    assert!(script.contains("try{body=JSON.parse(text)}catch(_){}"));
}

fn analyses(
    handler: impl Fn(&[String]) -> Result<serde_json::Value, LookupError> + Send + Sync + 'static,
) -> Routes {
    Routes {
        lookups: None,
        radar: None,
        cells: None,
        track: None,
        analyze: Some(Arc::new(handler)),
        inspect: None,
        investigate: None,
        scans: None,
        keys_home: None,
    }
}

fn investigations(
    handler: impl Fn(&str) -> Result<LookupReport, LookupError> + Send + Sync + 'static,
) -> Routes {
    Routes {
        investigate: Some(Arc::new(handler)),
        ..Routes::default()
    }
}

/// One `POST /api/investigate` with `body` as the text, as the page sends it.
fn investigate(body: &str, extra: &str, routes: &Routes) -> String {
    text(respond(
        &format!(
            "POST {INVESTIGATE_PATH} HTTP/1.1\r\nHost: localhost\r\n{HEADER}{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
        &test_config(loopback_bind(), None),
        routes,
    ))
}

/// `POST /api/investigate` hands the body to the installed handler as text and answers its
/// report like a lookup's. The text never travels in a URL; a `GET`, a query string, a missing
/// body or a text longer than a form body is refused, the last naming the command that reads
/// a longer one; and the route answers 404 until the binary installs it.
#[test]
fn a_pasted_text_is_investigated_from_the_body() {
    let routes = investigations(|text| {
        let entities: Vec<Entity> = text
            .split_whitespace()
            .filter(|word| word.contains('@'))
            .map(|word| Entity::new(crate::entity::EntityKind::Email, word, 0.9, "investigate"))
            .collect();
        Ok(LookupReport {
            route: "investigate",
            text: format!("entities={}\n", entities.len()),
            entities,
            outcomes: Vec::new(),
            scan: None,
            status: None,
        })
    });
    let answer = investigate("call ada@example.com now", "", &routes);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let body: serde_json::Value =
        serde_json::from_str(answer.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["route"], "investigate");
    assert_eq!(body["text"], "entities=1\n");
    assert_eq!(body["entities"].as_array().map(Vec::len), Some(1), "{body}");
    assert_eq!(body["outcomes"], serde_json::json!([]));
    assert!(body.get("scan").is_none() && body.get("status").is_none());

    let config = test_config(loopback_bind(), None);
    let ask = |request: String, routes: &Routes| text(respond(&request, &config, routes));
    let none = ask(
        format!(
            "POST {INVESTIGATE_PATH} HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: 1\r\n\r\nx"
        ),
        &Routes::default(),
    );
    assert!(none.starts_with("HTTP/1.1 404"), "{none}");
    let get = ask(
        format!("GET {INVESTIGATE_PATH} HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
        &routes,
    );
    assert!(get.starts_with("HTTP/1.1 405"), "{get}");
    let in_url = ask(
        format!(
            "POST {INVESTIGATE_PATH}?text=a HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: 1\r\n\r\nx"
        ),
        &routes,
    );
    assert!(
        in_url.starts_with("HTTP/1.1 400") && in_url.contains("send the text as the body"),
        "{in_url}"
    );
    let empty = investigate("", "", &routes);
    assert!(
        empty.starts_with("HTTP/1.1 400") && empty.contains("needs the text as the body"),
        "{empty}"
    );
    let long = ask(
        format!(
            "POST {INVESTIGATE_PATH} HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: {}\r\n\r\n",
            MAX_FORM_BYTES + 1
        ),
        &routes,
    );
    assert!(
        long.starts_with("HTTP/1.1 413") && long.contains("investigate --file FILE"),
        "{long}"
    );
    let short = ask(
        format!(
            "POST {INVESTIGATE_PATH} HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: 9\r\n\r\nab"
        ),
        &routes,
    );
    assert!(
        short.starts_with("HTTP/1.1 400") && short.contains("ended before the length"),
        "{short}"
    );
    let failed = investigate(
        "x",
        "",
        &investigations(|_| {
            Err(LookupError {
                status: 422,
                message: "no text".into(),
            })
        }),
    );
    assert!(
        failed.starts_with("HTTP/1.1 422") && failed.contains("no text"),
        "{failed}"
    );
}

/// Answers with the seeds it was given, so a test can see exactly what reached the spine.
fn echo_seeds() -> Routes {
    analyses(|seeds| Ok(serde_json::json!({ "seeds": seeds })))
}

fn analyze(query: &str, extra: &str, token: Option<&str>, routes: &Routes) -> String {
    text(respond(
        &format!("GET /api/analyze?{query} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n"),
        &test_config(bind_for(token), token),
        routes,
    ))
}

#[test]
fn analysis_answers_404_until_the_binary_installs_it() {
    let response = analyze("seeds=a", "", None, &Routes::default());
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
}

#[test]
fn analysis_takes_one_seed_per_line_trimmed_and_without_blank_lines() {
    let response = analyze(
        "seeds=+alex.demo%40example.org+%0A%0A%40alexdemo%0D%0Aexample.org",
        "Sec-Fetch-Site: same-origin\r\n",
        None,
        &echo_seeds(),
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains(r#"{"seeds":["alex.demo@example.org","@alexdemo","example.org"]}"#),
        "{response}"
    );
}

/// A request the analysis cannot honour is refused before the spine runs.
#[test]
fn analysis_refuses_what_it_cannot_honour_before_it_runs() {
    let too_many = format!(
        "seeds={}",
        (0..=MAX_ANALYZE_SEEDS)
            .map(|n| format!("seed{n}.example"))
            .collect::<Vec<_>>()
            .join("%0A")
    );
    let too_long = format!("seeds={}", "a".repeat(MAX_SELECTOR_BYTES + 1));
    for (query, extra, status, fragment) in [
        ("seeds=", "", "400", "needs seeds"),
        ("seeds=+%0A+", "", "400", "needs seeds"),
        ("other=x", "", "400", "needs seeds"),
        (too_many.as_str(), "", "400", "at most 16 seeds"),
        (too_long.as_str(), "", "400", "longer than 512 bytes"),
        ("seeds=%ZZ", "", "400", "percent-encoded"),
        (
            "seeds=a",
            "Sec-Fetch-Site: cross-site\r\n",
            "403",
            "cross-site",
        ),
        (
            "seeds=a",
            "Sec-Fetch-Site: same-site\r\n",
            "403",
            "cross-site",
        ),
    ] {
        let response = analyze(query, extra, None, &echo_seeds());
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{query}: {response}"
        );
        assert!(response.contains(fragment), "{query}: {response}");
        assert!(!response.contains("\"seeds\":["), "{query} ran the spine");
    }
    let post = text(respond(
        "POST /api/analyze?seeds=a HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &test_config(loopback_bind(), None),
        &echo_seeds(),
    ));
    assert!(post.starts_with("HTTP/1.1 405"), "{post}");
}

#[test]
fn analysis_needs_the_token_when_one_is_configured() {
    let refused = analyze("seeds=a", "", Some("secret"), &echo_seeds());
    assert!(refused.starts_with("HTTP/1.1 401"), "{refused}");
    let allowed = analyze(
        "seeds=a",
        "Authorization: Bearer secret\r\n",
        Some("secret"),
        &echo_seeds(),
    );
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
}

#[test]
fn analysis_answers_with_the_status_the_spine_reports() {
    let refusing = analyses(|_| {
        Err(LookupError {
            status: 422,
            message: "no actionable seeds".into(),
        })
    });
    let response = analyze("seeds=a", "", None, &refusing);
    assert!(response.starts_with("HTTP/1.1 422"), "{response}");
    assert!(response.contains("no actionable seeds"), "{response}");
}

/// About `depth` KiB of stack: a 1 KiB frame per call, kept live across the call below it.
fn deep_stack(depth: usize) -> u64 {
    let frame = std::hint::black_box([1_u8; 1024]);
    let below = if depth == 0 { 0 } else { deep_stack(depth - 1) };
    below + u64::from(frame[depth % frame.len()])
}

/// The spine needs more stack than a connection thread has. Served from a thread with the
/// connection stack, a handler that uses about 1 MiB of stack must still answer, because the
/// analysis runs on its own thread. Run inline, it would overflow and abort the server.
#[test]
fn an_analysis_runs_off_the_small_connection_stack() {
    let deep = analyses(|_| Ok(serde_json::json!({ "sum": deep_stack(1024) })));
    let response = thread::Builder::new()
        .stack_size(HANDLER_STACK_BYTES)
        .spawn(move || analyze("seeds=a", "", None, &deep))
        .unwrap()
        .join()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains(r#"{"sum":1025}"#), "{response}");
}

/// Each correlation row says what the rule found, such as how many independent pathways
/// corroborate a link or how many pairs rest on one shared handle, beside the rule and
/// the entities it names. The page showed only the rule, its severity and the entities.
#[test]
fn the_page_shows_what_each_correlation_found() {
    let table = &INDEX_HTML[..INDEX_HTML.find(r#"<tbody id="acorrelations">"#).unwrap()];
    let header = &table[table.rfind("<thead>").unwrap()..];
    assert_eq!(
        header,
        "<thead><tr><th>rule</th><th>severity</th><th>finding</th><th>entities</th></tr></thead>"
    );
    let script = inline_block(INDEX_HTML, "script");
    let row = &script[script.find("fill('acorrelations'").unwrap()..];
    let row = &row[..row.find(';').unwrap()];
    assert!(
        row.ends_with(
            "c=>[c.rule_id+' '+c.rule_name,show(c.severity),c.description,\
             c.entity_uids.map(who).join(', ')])"
        ),
        "{row}"
    );
}

/// The bridges to saved scans reach a reader as a table, not only in the JSON. The page had no
/// place for `cross_scan`, so `serve --history` had no visible effect.
#[test]
fn the_page_draws_the_bridges_to_saved_scans() {
    let table = &INDEX_HTML[..INDEX_HTML.find(r#"<tbody id="ascans">"#).unwrap()];
    let header = &table[table.rfind("<thead>").unwrap()..];
    assert_eq!(
        header,
        "<thead><tr><th>entity</th><th>tier</th><th>saved scans</th></tr></thead>"
    );
    let script = inline_block(INDEX_HTML, "script");
    assert!(script.contains("const cross=body.cross_scan"), "{script}");
    assert!(script.contains("fill('ascans',bridged,r=>r)"), "{script}");
}

/// The page drives the analysis through the same route, refused cross-site, with no lookup
/// header: it makes no network request and spends no key.
#[test]
fn the_page_runs_the_offline_analysis() {
    assert!(INDEX_HTML.contains(r#"<form class="row" id="analyze">"#));
    assert!(INDEX_HTML.contains("call('/api/analyze?'"));
    let script = inline_block(INDEX_HTML, "script");
    let analyze_call = &script[script.find("call('/api/analyze?'").unwrap()..];
    let analyze_call = &analyze_call[..analyze_call.find(';').unwrap()];
    assert!(
        !analyze_call.contains("X-Huntsman-Lookup"),
        "{analyze_call}"
    );
}

/// A server with saved scans whose lookup finds the selector and nothing else, in a scratch
/// store; the scan has run to its end before the first request.
fn scan_routes(tag: &str) -> (Routes, String, std::path::PathBuf) {
    use crate::scan_service::{LookupOutput, ScanRequest, ScanService};
    use crate::scan_store::{ScanOptions, ScanStore};
    let dir = std::env::temp_dir().join(format!("hse-serve-scans-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let lookup = Arc::new(
        |_kind: crate::scan_route::ScanKind,
         selector: &str,
         _: &crate::module_selection::Selection| {
            Ok(LookupOutput {
                text: "report".into(),
                entities: vec![
                    crate::entity::Entity::builder(
                        crate::entity::EntityKind::Phone,
                        selector,
                        0.9,
                        "s",
                    )
                    .build(),
                ],
                outcomes: Vec::new(),
            })
        },
    );
    let api = ScanApi::new(
        ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
        None,
    );
    let id = api
        .service()
        .run(&ScanRequest {
            target: "+61412345678".into(),
            name: None,
            kind: None,
            options: ScanOptions {
                usecase: "all".into(),
                modules: Vec::new(),
                types: Vec::new(),
                depth: 0,
            },
        })
        .unwrap()
        .id;
    let routes = Routes {
        scans: Some(Arc::new(api)),
        ..Routes::default()
    };
    (routes, id, dir)
}

fn scans_request(routes: &Routes, token: Option<&str>, request: &str) -> String {
    text(respond(
        request,
        &test_config(bind_for(token), token),
        routes,
    ))
}

/// Heavy saved-scan pages and exports must not spawn unbounded 4 MiB-stack workers.
/// Even with both places occupied, the operator can still inspect status or stop the scan.
#[test]
fn saved_scan_heavy_admission_keeps_control_routes_responsive() {
    let (routes, id, dir) = scan_routes("heavy-admission");
    let api = routes.scans.as_ref().expect("scan API installed");
    let permits: Vec<_> = (0..MAX_HEAVY_SCAN_REQUESTS)
        .map(|_| {
            Slot::take_of(api.web_request_slots(), MAX_HEAVY_SCAN_REQUESTS)
                .expect("free heavy worker permit")
        })
        .collect();
    let export = format!("GET /api/scans/{id}/export?format=csv HTTP/1.1\r\n{HEADER}\r\n");
    let blocked = scans_request(&routes, None, &export);
    assert!(blocked.starts_with("HTTP/1.1 503"), "{blocked}");
    assert!(
        blocked.contains("saved-scan response capacity"),
        "{blocked}"
    );
    let status = scans_request(
        &routes,
        None,
        &format!("GET /api/scans/{id} HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let listing = scans_request(
        &routes,
        None,
        &format!("GET /api/scans HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(listing.starts_with("HTTP/1.1 200"), "{listing}");
    let stop = scans_request(
        &routes,
        None,
        &format!("POST /api/scans/{id}/stop HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(
        !stop.starts_with("HTTP/1.1 503"),
        "scan stop must bypass heavy response saturation: {stop}"
    );
    // Authorization checks precede resource admission, even during overload.
    let refused = scans_request(
        &routes,
        None,
        &format!("GET /api/scans/{id}/export?format=csv HTTP/1.1\r\n\r\n"),
    );
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    drop(permits);
    assert_eq!(api.web_request_slots().load(Ordering::Acquire), 0);
    let recovered = scans_request(&routes, None, &export);
    assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
    assert_eq!(
        api.web_request_slots().load(Ordering::Acquire),
        0,
        "finished response must release its heavy admission slot"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// An Excel export is bytes, sent whole after its headers, its length counted in bytes.
#[test]
fn an_excel_export_is_sent_as_bytes_with_its_exact_length() {
    let (routes, id, dir) = scan_routes("xlsx");
    let book = respond(
        &format!("GET /api/scans/{id}/export?format=xlsx HTTP/1.1\r\n{HEADER}\r\n"),
        &test_config(loopback_bind(), None),
        &routes,
    );
    let split = book.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let (head_bytes, body) = book.split_at(split);
    let head_text = String::from_utf8(head_bytes.to_vec()).unwrap();
    assert!(head_text.starts_with("HTTP/1.1 200"), "{head_text}");
    assert_eq!(
        header(&head_text, "Content-Type"),
        Some(crate::xlsx::CONTENT_TYPE)
    );
    assert_eq!(
        header(&head_text, "Content-Length"),
        Some(body.len().to_string().as_str())
    );
    assert!(
        header(&head_text, "Content-Disposition")
            .unwrap()
            .ends_with(".xlsx\""),
        "{head_text}"
    );
    assert!(body.starts_with(b"PK\x03\x04"));
    assert!(std::str::from_utf8(body).is_err(), "a workbook is not text");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The saved scans answer through serve with the same guards as a lookup: the header, never
/// cross-site, the token on a public bind. Reads are GET or HEAD, changes are POST, and an
/// export downloads under the name the API gives it.
#[test]
fn saved_scans_answer_through_serve_behind_the_lookup_guards() {
    let (routes, id, dir) = scan_routes("guards");
    let ask = |request: String| scans_request(&routes, None, &request);
    let list = ask(format!(
        "GET /api/scans HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: same-origin\r\n{HEADER}\r\n"
    ));
    assert!(list.starts_with("HTTP/1.1 200"), "{list}");
    assert!(list.contains(&format!("\"id\":\"{id}\"")), "{list}");
    let head = ask(format!("HEAD /api/scans HTTP/1.1\r\n{HEADER}\r\n"));
    assert!(
        head.starts_with("HTTP/1.1 200") && head.ends_with("\r\n\r\n"),
        "{head}"
    );
    for refused in [
        "GET /api/scans HTTP/1.1\r\n\r\n".to_owned(),
        format!("GET /api/scans HTTP/1.1\r\nSec-Fetch-Site: cross-site\r\n{HEADER}\r\n"),
        format!("POST /api/scans?target=x HTTP/1.1\r\nSec-Fetch-Site: same-site\r\n{HEADER}\r\n"),
        "POST /api/scans?target=x HTTP/1.1\r\nX-Huntsman-Lookup: yes\r\n\r\n".to_owned(),
    ] {
        assert!(
            ask(refused.clone()).starts_with("HTTP/1.1 403"),
            "{refused}"
        );
    }
    // A body is refused: the parameters travel in the query string.
    let body = ask(format!(
        "POST /api/scans/{id}/fp?ids=a&fp=1 HTTP/1.1\r\nContent-Length: 3\r\n{HEADER}\r\nx=1"
    ));
    assert!(body.starts_with("HTTP/1.1 400"), "{body}");
    // A header line after the blank line is body, not a header.
    let smuggled = ask("GET /api/scans HTTP/1.1\r\n\r\nX-Huntsman-Lookup: 1\r\n".to_owned());
    assert!(smuggled.starts_with("HTTP/1.1 403"), "{smuggled}");
    let export = ask(format!(
        "GET /api/scans/{id}/export?format=csv HTTP/1.1\r\n{HEADER}\r\n"
    ));
    assert!(export.starts_with("HTTP/1.1 200"), "{export}");
    assert_eq!(
        header(&export, "Content-Type"),
        Some("text/csv; charset=utf-8")
    );
    let disposition = header(&export, "Content-Disposition").unwrap();
    assert!(
        disposition.starts_with("attachment; filename=\"") && disposition.ends_with(".csv\""),
        "{disposition}"
    );
    assert!(
        export.contains("Updated,Type,Module,Source,F/P,Data"),
        "{export}"
    );
    let rerun = ask(format!(
        "POST /api/scans/{id}/rerun HTTP/1.1\r\nContent-Length: 0\r\n{HEADER}\r\n"
    ));
    assert!(rerun.starts_with("HTTP/1.1 202 Accepted"), "{rerun}");
    let read_as_post = ask(format!(
        "GET /api/scans/{id}/rerun HTTP/1.1\r\n{HEADER}\r\n"
    ));
    assert!(read_as_post.starts_with("HTTP/1.1 405"), "{read_as_post}");
    // Only the scan API takes POST.
    for path in [
        "/",
        "/api/health",
        "/api/modules",
        "/api/lookup?q=a",
        "/api/analyze?seeds=a",
    ] {
        let post = ask(format!("POST {path} HTTP/1.1\r\n{HEADER}\r\n"));
        assert!(post.starts_with("HTTP/1.1 405"), "{path}: {post}");
    }
    // A public bind needs the token for every scan route.
    let public = scans_request(
        &routes,
        Some("s3cret"),
        &format!("GET /api/eventtypes HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(public.starts_with("HTTP/1.1 401"), "{public}");
    let signed = scans_request(
        &routes,
        Some("s3cret"),
        &format!("GET /api/settings HTTP/1.1\r\nAuthorization: Bearer s3cret\r\n{HEADER}\r\n"),
    );
    assert!(signed.starts_with("HTTP/1.1 200"), "{signed}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn saved_scans_are_absent_until_the_binary_installs_them() {
    let got = response_for_request(
        &format!("GET /api/scans HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
        None,
        loopback_bind(),
    );
    assert!(got.starts_with("HTTP/1.1 404"), "{got}");
    assert!(got.contains("saved scans are not enabled"), "{got}");
}

#[test]
fn an_export_name_cannot_break_out_of_its_header() {
    assert_eq!(header_filename("a\"b\r\nX: y.csv"), "a_b__X__y.csv");
    assert_eq!(header_filename("t1-Huntsman.csv"), "t1-Huntsman.csv");
    assert_eq!(header_filename(""), "export");
}

// --- The Settings page's provider keys ---

const TEST_KEY: &str = "TEST_ONLY_SETTINGS_KEY_51c0";

fn key_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hse-serve-keys-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key_routes(home: &Path) -> Routes {
    Routes {
        keys_home: Some(home.to_path_buf()),
        ..Routes::default()
    }
}

fn key_save(routes: &Routes, form: &str, extra: &str) -> String {
    scans_request(
        routes,
        None,
        &format!(
            "POST /api/settings/keys HTTP/1.1\r\n{HEADER}{extra}Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
            form.len()
        ),
    )
}

fn answer_json(answer: &str) -> serde_json::Value {
    let (_, body) = answer.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap_or_else(|error| panic!("{error}: {body}"))
}

fn slot_state(answer: &serde_json::Value, slot: &str) -> (bool, bool) {
    let row = answer["slots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["slot"] == slot)
        .unwrap_or_else(|| panic!("{slot} is not listed"));
    (
        row["set"].as_bool().unwrap(),
        row["saved"].as_bool().unwrap(),
    )
}

#[test]
fn the_key_settings_list_every_catalogue_slot_and_a_save_reaches_the_keys_file_only() {
    let home = key_home("save");
    let routes = key_routes(&home);
    let file = home.join(keys::DEFAULT_KEYS_FILE);
    let listed = scans_request(
        &routes,
        None,
        &format!("GET /api/settings/keys HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert!(listed.starts_with("HTTP/1.1 200"), "{listed}");
    let listed = answer_json(&listed);
    let catalogue: usize = PROVIDERS.iter().map(|provider| provider.slots.len()).sum();
    assert_eq!(listed["slots"].as_array().unwrap().len(), catalogue);
    assert_eq!(listed["file"], file.display().to_string());
    assert!(
        listed["slots"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["saved"] == false)
    );

    let saved = key_save(
        &routes,
        &format!("slot=HUNTSMAN_SHODAN_KEY&value={TEST_KEY}"),
        "Sec-Fetch-Site: same-origin\r\n",
    );
    assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
    assert!(!saved.contains(TEST_KEY), "an answer never carries a key");
    assert_eq!(
        slot_state(&answer_json(&saved), "HUNTSMAN_SHODAN_KEY"),
        (true, true)
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("HUNTSMAN_SHODAN_KEY='{TEST_KEY}'\n")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // What a lookup reads is what was saved.
    let keys = Keys::for_lookup(Some(home.as_os_str())).keys;
    assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap().expose(), TEST_KEY);

    // An empty value removes the slot.
    let removed = key_save(&routes, "slot=HUNTSMAN_SHODAN_KEY&value=", "");
    assert!(removed.starts_with("HTTP/1.1 200"), "{removed}");
    assert!(!slot_state(&answer_json(&removed), "HUNTSMAN_SHODAN_KEY").1);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
    let _ = std::fs::remove_dir_all(&home);
}

/// Spiderfoot's Settings → Import API Keys: a whole `SpiderFoot.cfg`, saved in one rewrite.
#[test]
fn a_spiderfoot_key_export_is_imported_into_the_keys_file_in_one_save() {
    let home = key_home("import");
    let routes = key_routes(&home);
    let file = home.join(keys::DEFAULT_KEYS_FILE);
    std::fs::write(&file, "# mine\nHUNTSMAN_SHODAN_KEY=old-key-1234\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let wigle = base64::standard(b"TEST_ONLY_WIGLE_AID:TEST_ONLY_WIGLE_TOKEN");
    let export = format!(
        "sfp_abstractapi:phonevalidation_api_key=\nsfp_fullhunt:api_key=TEST_ONLY_UNUSED\n\
         sfp_shodan:api_key={TEST_KEY}\nsfp_spider:maxpages=100\n\
         sfp_virustotal:api_key=TEST_ONLY_VT_KEY\nsfp_wigle:api_key_encoded={wigle}\n"
    );
    let form = format!("import={}", crate::http::percent_encode_component(&export));
    let imported = key_save(&routes, &form, "Sec-Fetch-Site: same-origin\r\n");
    assert!(imported.starts_with("HTTP/1.1 200"), "{imported}");
    for value in [
        TEST_KEY,
        "TEST_ONLY_VT_KEY",
        "TEST_ONLY_WIGLE_TOKEN",
        "TEST_ONLY_UNUSED",
    ] {
        assert!(!imported.contains(value), "an answer never carries a key");
    }
    let answer = answer_json(&imported);
    assert_eq!(
        answer["imported"],
        serde_json::json!({
            "slots": [
                "HUNTSMAN_SHODAN_KEY",
                "HUNTSMAN_VIRUSTOTAL_KEY",
                "HUNTSMAN_WIGLE_USER",
                "HUNTSMAN_WIGLE_TOKEN"
            ],
            "unused": ["sfp_fullhunt:api_key"],
            "settings": 1,
        })
    );
    assert_eq!(slot_state(&answer, "HUNTSMAN_VIRUSTOTAL_KEY"), (true, true));
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!(
            "# mine\nHUNTSMAN_SHODAN_KEY='{TEST_KEY}'\nHUNTSMAN_VIRUSTOTAL_KEY='TEST_ONLY_VT_KEY'\n\
             HUNTSMAN_WIGLE_USER='TEST_ONLY_WIGLE_AID'\nHUNTSMAN_WIGLE_TOKEN='TEST_ONLY_WIGLE_TOKEN'\n"
        )
    );

    // One unreadable line saves nothing; nor does a file with no key a source takes.
    let before = std::fs::read_to_string(&file).unwrap();
    for (text, fragment) in [
        (
            "sfp_hunter:api_key=TEST_ONLY_NEW\nmy shodan key TEST_ONLY_PASTED\n",
            "nothing was imported: line 2",
        ),
        (
            "sfp_fullhunt:api_key=TEST_ONLY_UNUSED\n",
            "no Huntsman source takes sfp_fullhunt:api_key",
        ),
        ("sfp_shodan:api_key=\n", "sets no key"),
    ] {
        let form = format!("import={}", crate::http::percent_encode_component(text));
        let refused = key_save(&routes, &form, "");
        assert!(refused.starts_with("HTTP/1.1 422"), "{refused}");
        assert!(refused.contains(fragment), "{refused}");
        assert!(!refused.contains("TEST_ONLY_NEW") && !refused.contains("TEST_ONLY_PASTED"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }
    let both = key_save(&routes, "import=x&slot=HUNTSMAN_SHODAN_KEY&value=y", "");
    assert!(both.starts_with("HTTP/1.1 400"), "{both}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_key_save_is_refused_off_the_page_in_the_url_or_for_a_slot_outside_the_catalogue() {
    let home = key_home("refused");
    let routes = key_routes(&home);
    let form = format!("slot=HUNTSMAN_SHODAN_KEY&value={TEST_KEY}");
    let status = |answer: &str| answer.split(' ').nth(1).unwrap_or_default().to_owned();
    for site in ["cross-site", "same-site"] {
        let answer = key_save(&routes, &form, &format!("Sec-Fetch-Site: {site}\r\n"));
        assert_eq!(status(&answer), "403", "{answer}");
    }
    let unheaded = scans_request(
        &routes,
        None,
        &format!(
            "POST /api/settings/keys HTTP/1.1\r\nContent-Length: {}\r\n\r\n{form}",
            form.len()
        ),
    );
    assert_eq!(status(&unheaded), "403", "{unheaded}");
    let in_the_url = scans_request(
        &routes,
        None,
        &format!("POST /api/settings/keys?{form} HTTP/1.1\r\n{HEADER}\r\n"),
    );
    assert_eq!(status(&in_the_url), "400", "{in_the_url}");
    let beside_a_form = scans_request(
        &routes,
        None,
        &format!(
            "POST /api/settings/keys?{form} HTTP/1.1\r\n{HEADER}Content-Length: {}\r\n\r\n{form}",
            form.len()
        ),
    );
    assert_eq!(status(&beside_a_form), "400", "{beside_a_form}");
    assert!(!beside_a_form.contains(TEST_KEY));
    for (form, want) in [
        (format!("slot=HOME&value={TEST_KEY}"), "400"),
        (format!("slot=HUNTSMAN_NOT_A_SLOT&value={TEST_KEY}"), "400"),
        ("slot=HUNTSMAN_SHODAN_KEY&value=changeme".to_owned(), "422"),
        ("slot=HUNTSMAN_SHODAN_KEY&value=%ZZ".to_owned(), "400"),
    ] {
        let answer = key_save(&routes, &form, "");
        assert_eq!(status(&answer), want, "{form}: {answer}");
        assert!(!answer.contains(TEST_KEY) && !answer.contains("changeme"));
    }
    let got_with_a_body = scans_request(
        &routes,
        None,
        &format!("GET /api/settings/keys HTTP/1.1\r\n{HEADER}Content-Length: 3\r\n\r\na=b"),
    );
    assert_eq!(status(&got_with_a_body), "400", "{got_with_a_body}");
    assert!(
        !home.join(keys::DEFAULT_KEYS_FILE).exists(),
        "nothing was saved"
    );

    // On a public bind the token is needed; without a home there is no keys file.
    let public = text(respond(
        &format!(
            "POST /api/settings/keys HTTP/1.1\r\n{HEADER}Content-Length: {}\r\n\r\n{form}",
            form.len()
        ),
        &test_config(public_bind(), Some("tok")),
        &routes,
    ));
    assert_eq!(status(&public), "401", "{public}");
    let homeless = key_save(&Routes::default(), &form, "");
    assert_eq!(status(&homeless), "404", "{homeless}");
    let _ = std::fs::remove_dir_all(&home);
}

/// A browser may send the form after its head, in a later packet; the server reads it whole.
/// A body past the form bound is not read, and the save is refused at once.
#[test]
fn a_form_body_that_follows_its_head_is_read_whole_and_a_larger_one_is_refused_unread() {
    let home = key_home("socket");
    let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap())
        .unwrap()
        .with_keys_home(home.clone());
    let addr = server.local_addr().unwrap();
    let handle = thread::spawn(move || server.run_n(2).unwrap());
    let send = |head: String, body: &[u8]| {
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(head.as_bytes()).unwrap();
        client.flush().unwrap();
        thread::sleep(Duration::from_millis(100));
        let _ = client.write_all(body);
        let mut answer = String::new();
        let _ = client.read_to_string(&mut answer);
        answer
    };
    let form = format!("slot=HUNTSMAN_SHODAN_KEY&value={TEST_KEY}");
    let saved = send(
        format!(
            "POST /api/settings/keys HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: {}\r\n\r\n",
            form.len()
        ),
        form.as_bytes(),
    );
    assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
    let big = vec![b'a'; MAX_FORM_BYTES + 1];
    let started = Instant::now();
    let refused = send(
        format!(
            "POST /api/settings/keys HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: {}\r\n\r\n",
            big.len()
        ),
        &big,
    );
    assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "answered without waiting"
    );
    handle.join().unwrap();
    let keys = Keys::for_lookup(Some(home.as_os_str())).keys;
    assert_eq!(keys.get("HUNTSMAN_SHODAN_KEY").unwrap().expose(), TEST_KEY);
    let _ = std::fs::remove_dir_all(&home);
}

/// Every keyed module the Settings page lists has a slot it can save, so no key field is shown
/// that the server would refuse.
#[test]
fn every_keyed_module_on_the_settings_page_has_a_slot_it_can_save() {
    let (routes, _, dir) = scan_routes("keyslots");
    let settings = answer_json(&scans_request(
        &routes,
        None,
        &format!("GET /api/settings HTTP/1.1\r\n{HEADER}\r\n"),
    ));
    let saveable: BTreeSet<&str> = PROVIDERS
        .iter()
        .flat_map(|provider| provider.slots.iter().copied())
        .collect();
    let mut keyed = 0;
    for module in settings["modules"].as_array().unwrap() {
        let slots: Vec<&str> = module["key_env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slot| slot.as_str().unwrap())
            .collect();
        if slots.is_empty() {
            continue;
        }
        keyed += 1;
        assert!(
            slots.iter().any(|slot| saveable.contains(slot)),
            "{} lists {slots:?}, none of which the credential catalogue names",
            module["name"]
        );
    }
    assert!(keyed > 20, "the settings list its keyed modules: {keyed}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The page reads the key answer by these names, so a renamed field fails here rather than
/// leaving the Settings page without its key fields.
#[test]
fn the_page_reads_the_key_answer_by_its_field_names() {
    let home = key_home("reads");
    let answer = answer_json(&scans_request(
        &key_routes(&home),
        None,
        &format!("GET /api/settings/keys HTTP/1.1\r\n{HEADER}\r\n"),
    ));
    for field in ["file", "warning", "slots"] {
        assert!(answer.get(field).is_some(), "the answer has no {field}");
    }
    for field in ["slot", "set", "saved", "provider"] {
        assert!(
            answer["slots"][0].get(field).is_some(),
            "a slot row has no {field}"
        );
    }
    for read in [
        "api('/api/settings/keys')",
        "keyslots.file",
        "keyslots.warning",
        "keyslots.slots.find(k=>k.slot===s)",
        "k.saved",
        "k.set",
        "method:'POST',body:new URLSearchParams({slot,value})",
        "method:'POST',body:new URLSearchParams({import:text})",
        "keyslots.imported",
        "i.slots",
        "i.unused",
        "i.settings",
    ] {
        assert!(INDEX_HTML.contains(read), "the page no longer reads {read}");
    }
    // An import answers with the same fields, and with what it imported.
    let imported = answer_json(&key_save(
        &key_routes(&home),
        &format!("import=sfp_shodan%3Aapi_key%3D{TEST_KEY}"),
        "",
    ));
    for field in ["slots", "unused", "settings"] {
        assert!(
            imported["imported"].get(field).is_some(),
            "an import's answer has no imported.{field}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// A server whose `/api/inspect` echoes the label and every byte it was handed, so a test sees
/// exactly what reached the handler.
fn inspect_server(token: Option<&str>, bind: &str) -> (SocketAddr, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let server = Server::bind(ServeConfig::parse(bind, token.map(str::to_owned)).unwrap())
        .unwrap()
        .with_inspect(Arc::new(move |label: &str, bytes: &[u8]| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(LookupReport {
                route: "inspect",
                text: format!("{label}:{}:{:?}", bytes.len(), &bytes[..bytes.len().min(8)]),
                entities: Vec::new(),
                outcomes: Vec::new(),
                scan: None,
                status: None,
            })
        }));
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let _ = server.run(|_| {});
    });
    (addr, calls)
}

/// With saved scans on, an inspection is kept as a `FINISHED` scan of the file, named in the
/// report with every entity stamped with its id: the file's fields are the target's own raw
/// evidence, its GPS position the target's child, and the same server's scans API reads it
/// back and refuses to run it again, since the bytes were not kept. Without saved scans the
/// report says nothing of a scan.
#[test]
fn an_inspection_with_saved_scans_is_kept_as_a_finished_scan_of_the_file() {
    use crate::scan_store::ScanStore;
    let dir = std::env::temp_dir().join(format!("hse-serve-inspect-kept-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let lookup: crate::scan_service::ScanLookup = Arc::new(|_, _, _| Err("no lookup".into()));
    let api = Arc::new(ScanApi::new(
        ScanService::new(ScanStore::open(&dir).unwrap(), lookup),
        None,
    ));
    let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap())
        .unwrap()
        .with_inspect(Arc::new(|label: &str, _: &[u8]| Ok(inspected(label))))
        .with_scans(Arc::clone(&api));
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let _ = server.run(|_| {});
    });
    let answer = upload(
        addr,
        &inspect_head("holiday.jpg", 4, HEADER),
        b"\xff\xd8\xff\xd9",
    );
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let id = scan_of(&answer);
    let body: serde_json::Value =
        serde_json::from_str(&answer[answer.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(body["status"], "FINISHED", "{body}");
    for entity in body["entities"].as_array().unwrap() {
        assert_eq!(entity["scan_id"], id, "{entity}");
        for evidence in entity["evidence"].as_array().unwrap() {
            assert_eq!(evidence["provenance"]["scan_id"], id, "{evidence}");
        }
    }
    let record = api.service().store().get(&id).unwrap();
    assert_eq!(
        (
            record.status,
            record.target.as_str(),
            record.target_type.as_str(),
            record.kind.as_str()
        ),
        (
            ScanStatus::Finished,
            "holiday.jpg",
            "HSE_DOCUMENT",
            INSPECT_KIND
        )
    );
    assert_eq!(record.modules_run, ["exif"]);
    let results = api.service().store().results(&id).unwrap().unwrap();
    let kinds: Vec<(&str, &str)> = results
        .elements
        .iter()
        .map(|element| (element.kind.as_str(), element.data.as_str()))
        .collect();
    for wanted in [
        ("ROOT", "holiday.jpg"),
        ("HSE_DOCUMENT", "holiday.jpg"),
        ("PHYSICAL_COORDINATES", "48.850000,2.333333"),
    ] {
        assert!(kinds.contains(&wanted), "{wanted:?} in {kinds:?}");
    }
    let file = results
        .elements
        .iter()
        .find(|element| element.kind == "HSE_DOCUMENT")
        .unwrap();
    assert!(
        file.raw.to_string().contains("Fixture Camera 2"),
        "the file's fields are its raw evidence: {}",
        file.raw
    );
    let rerun = upload(
        addr,
        &format!(
            "POST /api/scans/{id}/rerun HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: 0\r\n\r\n"
        ),
        b"",
    );
    assert!(
        rerun.starts_with("HTTP/1.1 400") && rerun.contains("inspect the file again"),
        "{rerun}"
    );
    let (plain, _) = inspect_server(None, "127.0.0.1:0");
    let answer = upload(plain, &inspect_head("a", 1, HEADER), b"x");
    assert!(
        answer.starts_with("HTTP/1.1 200") && !answer.contains("\"scan\""),
        "{answer}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// What `exif` reads from a photo, as the inspection handler answers it.
fn inspected(label: &str) -> LookupReport {
    let provenance = || crate::entity::EvidenceProvenance::new("exif");
    let document = Entity::builder(crate::entity::EntityKind::Document, label, 0.9, "exif")
        .evidence(
            crate::entity::Evidence::new(provenance(), format!("{label} with 2 fields"))
                .with_attr("Make", "Fixture Camera 2")
                .with_attr("file_sha256", "ab"),
        )
        .build();
    let position = Entity::builder(
        crate::entity::EntityKind::Coordinates,
        "48.850000,2.333333",
        0.9,
        "exif",
    )
    .evidence(
        crate::entity::Evidence::new(provenance(), "GPS position")
            .with_attr("GPSLatitude", "48.85"),
    )
    .build();
    LookupReport {
        route: "inspect",
        text: format!("{label}: 2 entities\n"),
        entities: vec![document, position],
        outcomes: vec![SourceExecutionOutcome::success("exif", 1, 2)],
        scan: None,
        status: None,
    }
}

/// Send `head` then `body` on one connection and read the whole answer.
fn upload(addr: SocketAddr, head: &str, body: &[u8]) -> String {
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    client.write_all(head.as_bytes()).unwrap();
    let _ = client.write_all(body);
    let _ = client.shutdown(Shutdown::Write);
    let mut answer = Vec::new();
    let _ = client.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

fn inspect_head(name: &str, length: usize, extra: &str) -> String {
    format!(
        "POST /api/inspect?name={name} HTTP/1.1\r\nHost: localhost\r\n{extra}Content-Length: {length}\r\n\r\n"
    )
}

/// A file picked in the page reaches the handler byte for byte, binary and well past the form
/// bound, labelled with its file name alone: the `exif` and `docmeta` commands, reachable from
/// the phone's browser.
#[test]
fn an_uploaded_file_reaches_the_handler_whole_and_byte_exact() {
    let (addr, calls) = inspect_server(None, "127.0.0.1:0");
    let mut file = vec![0xFF, 0xD8, 0x00, 0x0D, 0x0A, 0x0D, 0x0A, 0x80];
    file.extend((0..3 * MAX_REQUEST_BYTES).map(|i| u8::try_from(i % 251).unwrap()));
    let answer = upload(
        addr,
        &inspect_head("%2Fsdcard%2FDCIM%2Fphoto.jpg", file.len(), HEADER),
        &file,
    );
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let body: serde_json::Value =
        serde_json::from_str(answer.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        body["text"],
        format!("photo.jpg:{}:{:?}", file.len(), &file[..8])
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A request the inspection would refuse is refused before its body is read, so no other
/// page, no tokenless caller and no oversized file makes the server hold a file in memory, and
/// the handler never runs.
/// A refusal written while the browser is still sending its file reaches the browser as the
/// answer, not as a reset. The second upload here is larger than any socket buffer, so its
/// writes block until the server reads or resets: the server drains the refused body after
/// answering, every write succeeds, and the `503` is read whole. Before, the server closed with
/// the body unread, the kernel answered the next segment with RST, and a browser without
/// Chrome's re-read of an answer after a reset showed a network error with no status.
#[test]
fn a_refusal_during_an_upload_is_read_not_reset() {
    let (addr, calls) = inspect_server(None, "127.0.0.1:0");
    // The one inspection place is held by an upload that has sent one byte of its ten.
    let mut holder = TcpStream::connect(addr).unwrap();
    holder
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    holder
        .write_all(inspect_head("a", 10, HEADER).as_bytes())
        .unwrap();
    holder.write_all(&[1]).unwrap();
    thread::sleep(Duration::from_millis(100));
    let file = vec![9_u8; 32 * 1024 * 1024];
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    client
        .write_all(inspect_head("b", file.len(), HEADER).as_bytes())
        .unwrap();
    // The refusal is on the wire before the body starts.
    thread::sleep(Duration::from_millis(200));
    for chunk in file.chunks(64 * 1024) {
        client
            .write_all(chunk)
            .expect("the server drains the refused upload instead of resetting");
    }
    client.shutdown(Shutdown::Write).unwrap();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.contains("already running"), "{answer}");
    // The held place was never touched: its upload completes and is inspected.
    holder.write_all(&[2; 9]).unwrap();
    let mut done = Vec::new();
    let _ = holder.read_to_end(&mut done);
    let done = String::from_utf8_lossy(&done);
    assert!(done.starts_with("HTTP/1.1 200"), "{done}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn an_inspection_is_refused_before_its_body_is_read() {
    // Each refused head announces the largest upload and is sent alone, its write side left
    // open. The gate answers it at once; a gate that admitted it would reserve the body and
    // wait on it until the read timed out, whatever the route answered afterwards.
    let refused_unread = |addr: SocketAddr, head: &str| {
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        client.write_all(head.as_bytes()).unwrap();
        let started = Instant::now();
        let mut answer = Vec::new();
        let _ = client.read_to_end(&mut answer);
        let waited = started.elapsed();
        assert!(
            waited < IO_TIMEOUT / 2,
            "{head:?} waited {waited:?} on a body"
        );
        String::from_utf8_lossy(&answer).into_owned()
    };
    let (addr, calls) = inspect_server(None, "127.0.0.1:0");
    let most = MAX_INSPECT_BYTES;
    let cases = [
        (inspect_head("a", most, ""), "403"),
        (
            inspect_head(
                "a",
                most,
                &format!("{HEADER}Sec-Fetch-Site: cross-site\r\n"),
            ),
            "403",
        ),
        (
            format!(
                "POST /api/inspect HTTP/1.1\r\nHost: evil.example\r\n{HEADER}Content-Length: {most}\r\n\r\n"
            ),
            "403",
        ),
        (
            inspect_head(
                "a",
                most,
                &format!("{HEADER}Transfer-Encoding: chunked\r\n"),
            ),
            "400",
        ),
        (inspect_head("a", most + 1, HEADER), "413"),
    ];
    for (head, want) in cases {
        let answer = refused_unread(addr, &head);
        assert!(
            answer.starts_with(&format!("HTTP/1.1 {want}")),
            "{head:?} -> {answer}"
        );
    }
    let file = vec![7_u8; 4096];
    for (head, want) in [
        (inspect_head("a", 0, HEADER), "400"),
        (
            format!("GET /api/inspect?name=a HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
            "405",
        ),
    ] {
        let answer = upload(addr, &head, &file);
        assert!(
            answer.starts_with(&format!("HTTP/1.1 {want}")),
            "{head:?} -> {answer}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (public, public_calls) = inspect_server(Some("inspect-token"), "0.0.0.0:0");
    let public = SocketAddr::from(([127, 0, 0, 1], public.port()));
    let tokenless = refused_unread(public, &inspect_head("a", most, HEADER));
    assert!(tokenless.starts_with("HTTP/1.1 401"), "{tokenless}");
    let authorized = upload(
        public,
        &inspect_head(
            "a",
            file.len(),
            &format!("{HEADER}Authorization: Bearer inspect-token\r\n"),
        ),
        &file,
    );
    assert!(authorized.starts_with("HTTP/1.1 200"), "{authorized}");
    assert_eq!(public_calls.load(Ordering::SeqCst), 1);
}

/// One inspection holds the place: a second upload meanwhile is answered `503` unread, and the
/// place is free again once the first is answered.
#[test]
fn one_inspection_at_a_time_and_its_place_comes_back() {
    let config = test_config("127.0.0.1:8080".parse().unwrap(), None);
    let routes = Routes {
        inspect: Some(Inspect {
            handler: Arc::new(|_: &str, _: &[u8]| {
                Err(LookupError {
                    status: 422,
                    message: "unused".into(),
                })
            }),
            live: Arc::new(AtomicUsize::new(0)),
        }),
        ..Routes::default()
    };
    let head = inspect_head("a", 10, HEADER);
    let (length, place) = inspect_admits(&head, &config, &routes).expect("the first is admitted");
    assert_eq!(length, 10);
    assert!(inspect_admits(&head, &config, &routes).is_none());
    let busy = text(respond_with(&head, None, &config, &routes));
    assert!(busy.starts_with("HTTP/1.1 503"), "{busy}");
    drop(place);
    assert!(inspect_admits(&head, &config, &routes).is_some());
    // An upload that ended early is named, not passed on short.
    let short = Upload {
        body: vec![1, 2, 3],
        place: inspect_admits(&head, &config, &routes).unwrap().1,
    };
    let ended = text(respond_with(&head, Some(&short), &config, &routes));
    assert!(ended.starts_with("HTTP/1.1 400"), "{ended}");
}

#[test]
fn an_inspection_label_is_a_bare_file_name() {
    assert_eq!(
        inspect_label("name=%2Fsdcard%2FDCIM%2Fa.jpg").unwrap(),
        "a.jpg"
    );
    assert_eq!(inspect_label("name=C%3A%5Cdocs%5Cb.pdf").unwrap(), "b.pdf");
    assert_eq!(inspect_label("name=x%0Ay%07.png").unwrap(), "xy.png");
    assert_eq!(inspect_label("").unwrap(), "upload");
    assert_eq!(inspect_label("name=%2F").unwrap(), "upload");
    assert!(inspect_label("name=%FF").is_err());
    let long = inspect_label(&format!("name={}", "é".repeat(400))).unwrap();
    assert!(long.len() <= MAX_INSPECT_NAME_BYTES && long.starts_with('é'));
}

/// Every browser-facing API route refuses a fetch another site started, and each route that
/// needs the page's header refuses a request without it, through the one [`page_refusal`]
/// guard, in the same words. The upload gate refuses the same requests before reading a body.
/// A sensor route whose handler is never reached: the guard refuses first.
fn unused_sensor<T>() -> Sensor<T> {
    Sensor {
        handler: Arc::new(|| {
            Err(LookupError {
                status: 422,
                message: "unused".into(),
            })
        }),
        live: Arc::new(AtomicUsize::new(0)),
    }
}

#[test]
fn every_page_route_refuses_other_sites_through_one_guard() {
    let refuse = |_: &str, _: &[u8]| -> Result<LookupReport, LookupError> {
        Err(LookupError {
            status: 422,
            message: "unused".into(),
        })
    };
    let home = key_home("guard");
    let routes = Routes {
        lookups: Some(echo_lookups()),
        research: None,
        radar: Some(unused_sensor()),
        cells: Some(unused_sensor()),
        track: Some(unused_sensor()),
        analyze: echo_seeds().analyze,
        inspect: Some(Inspect {
            handler: Arc::new(refuse),
            live: Arc::new(AtomicUsize::new(0)),
        }),
        investigate: Some(Arc::new(|_: &str| {
            Err(LookupError {
                status: 422,
                message: "unused".into(),
            })
        })),
        scans: scan_routes("guard").0.scans,
        keys_home: Some(home.clone()),
    };
    let config = test_config(loopback_bind(), None);
    let ask = |method: &str, target: &str, extra: &str| {
        let length = if method == "POST" {
            "Content-Length: 3\r\n"
        } else {
            ""
        };
        text(respond(
            &format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\n{extra}{length}\r\n"),
            &config,
            &routes,
        ))
    };
    for (method, target, noun, needs_header) in [
        ("GET", "/api/lookup?q=a", "lookup", true),
        ("GET", "/api/radar/wifi", "Wi-Fi radar request", true),
        ("GET", "/api/radar/cells", "cell radar request", true),
        ("POST", "/api/radar/track", "radar track request", true),
        ("GET", "/api/scans", "scan request", true),
        ("GET", KEYS_PATH, "key request", true),
        ("GET", "/api/analyze?seeds=a", "analysis", false),
        ("POST", "/api/inspect?name=a", "inspection", true),
        ("POST", INVESTIGATE_PATH, "investigation", true),
    ] {
        for site in ["cross-site", "same-site"] {
            let answer = ask(
                method,
                target,
                &format!("{HEADER}Sec-Fetch-Site: {site}\r\n"),
            );
            assert!(
                answer.starts_with("HTTP/1.1 403"),
                "{target} {site}: {answer}"
            );
            assert!(
                answer.contains(&format!("cross-site {noun} refused")),
                "{answer}"
            );
        }
        let bare = ask(method, target, "Sec-Fetch-Site: same-origin\r\n");
        let header_refusal = format!("{noun} needs the X-Huntsman-Lookup: 1 header");
        if needs_header {
            assert!(bare.starts_with("HTTP/1.1 403"), "{target}: {bare}");
            assert!(bare.contains(&header_refusal), "{bare}");
        } else {
            assert!(
                !bare.contains("refused") && !bare.contains("needs the X-Huntsman"),
                "{bare}"
            );
        }
    }
    for extra in ["Sec-Fetch-Site: cross-site\r\nX-Huntsman-Lookup: 1\r\n", ""] {
        let head = format!(
            "POST /api/inspect HTTP/1.1\r\nHost: localhost\r\n{extra}Content-Length: 3\r\n\r\n"
        );
        assert!(
            inspect_admits(&head, &config, &routes).is_none(),
            "{extra:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// An upload streaming its body is busy, not idle: a full server making room closes an idle
/// connection, never the one sending a file.
#[test]
fn a_full_server_never_closes_the_upload_it_is_reading() {
    let (addr, calls) = inspect_server(None, "127.0.0.1:0");
    let file = vec![7_u8; 4096];
    let mut sender = TcpStream::connect(addr).unwrap();
    sender
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    sender
        .write_all(inspect_head("a", file.len(), HEADER).as_bytes())
        .unwrap();
    sender.write_all(&file[..100]).unwrap();
    thread::sleep(Duration::from_millis(100));
    let idle: Vec<TcpStream> = (1..MAX_CONNECTIONS)
        .map(|_| TcpStream::connect(addr).unwrap())
        .collect();
    thread::sleep(IDLE_GRACE + Duration::from_millis(300));
    // One past the cap: the server closes the connection that has waited longest idle.
    let _extra = TcpStream::connect(addr).unwrap();
    thread::sleep(Duration::from_millis(300));
    sender.write_all(&file[100..]).unwrap();
    let mut answer = Vec::new();
    let _ = sender.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(idle);
}

/// Bytes a client sends after the body it announced are not the file, and do not make it look
/// short; a chunked body is refused, never handed over as the file with its framing; and a head
/// the client stopped part way through is called that, not a busy server.
#[test]
fn an_upload_is_exactly_its_content_length_and_nothing_else_passes_for_one() {
    let (addr, calls) = inspect_server(None, "127.0.0.1:0");
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = inspect_head("a", 4, HEADER).into_bytes();
    request.extend_from_slice(b"abcd\r\n");
    client.write_all(&request).unwrap();
    let mut answer = Vec::new();
    let _ = client.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("a:4:[97, 98, 99, 100]"), "{answer}");

    let chunked = b"4\r\nabcd\r\n0\r\n\r\n";
    let refused = upload(
        addr,
        &inspect_head(
            "a",
            chunked.len(),
            &format!("{HEADER}Transfer-Encoding: chunked\r\n"),
        ),
        chunked,
    );
    assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
    assert!(refused.contains("Transfer-Encoding"), "{refused}");

    let cut = upload(
        addr,
        &format!(
            "POST /api/inspect?name=a HTTP/1.1\r\nHost: localhost\r\n{HEADER}Content-Length: 10\r\n"
        ),
        b"",
    );
    assert!(cut.starts_with("HTTP/1.1 400"), "{cut}");
    assert!(cut.contains("ended before its head did"), "{cut}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// No route takes a chunked body: the router refuses `Transfer-Encoding` for every one.
#[test]
fn every_route_refuses_a_transfer_encoding() {
    let config = test_config(loopback_bind(), None);
    for (method, path) in [
        ("POST", KEYS_PATH),
        ("POST", "/api/scans?target=a"),
        ("GET", "/api/health"),
    ] {
        let answer = text(respond(
            &format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{HEADER}Transfer-Encoding: chunked\r\n\r\n"
            ),
            &config,
            &Routes::default(),
        ));
        assert!(answer.starts_with("HTTP/1.1 400"), "{path}: {answer}");
    }
}

/// A HEAD answer is the GET answer's head alone, on the JSON routes and the scan API as on the
/// page.
#[test]
fn a_head_answer_never_carries_a_body() {
    let config = test_config(loopback_bind(), None);
    let routes = Routes {
        lookups: Some(echo_lookups()),
        analyze: echo_seeds().analyze,
        inspect: Some(Inspect {
            handler: Arc::new(|_: &str, _: &[u8]| {
                Err(LookupError {
                    status: 422,
                    message: "unused".into(),
                })
            }),
            live: Arc::new(AtomicUsize::new(0)),
        }),
        ..Routes::default()
    };
    for path in [
        "/api/inspect?name=a",
        "/api/lookup?q=a",
        "/api/analyze?seeds=",
        "/api/scans",
        "/api/missing",
        "/",
    ] {
        let answer = text(respond(
            &format!("HEAD {path} HTTP/1.1\r\nHost: localhost\r\n{HEADER}\r\n"),
            &config,
            &routes,
        ));
        let (head, body) = answer.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 "), "{path}: {answer}");
        assert!(body.is_empty(), "{path}: a HEAD answer carried {body:?}");
    }
}

/// One inspection's answer is in memory at a time: while a client that has stopped reading holds
/// the one place, another upload is answered `503` unread, and once that write times out the
/// place comes back.
#[test]
fn an_answer_holds_the_inspection_place_only_until_its_write_ends() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let server = Server::bind(ServeConfig::parse("127.0.0.1:0", None).unwrap())
        .unwrap()
        .with_inspect(Arc::new(move |label: &str, _: &[u8]| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(LookupReport {
                route: "inspect",
                // Far more than the socket buffers hold, so its write waits on the reader.
                text: if label == "big" {
                    "x".repeat(32 * 1024 * 1024)
                } else {
                    String::new()
                },
                entities: Vec::new(),
                outcomes: Vec::new(),
                scan: None,
                status: None,
            })
        }));
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let _ = server.run(|_| {});
    });
    let mut stalled = TcpStream::connect(addr).unwrap();
    stalled
        .write_all(inspect_head("big", 3, HEADER).as_bytes())
        .unwrap();
    stalled.write_all(b"abc").unwrap();
    thread::sleep(Duration::from_millis(1500));
    let busy = upload(addr, &inspect_head("small", 3, HEADER), b"abc");
    assert!(busy.starts_with("HTTP/1.1 503"), "{busy}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The stalled write gives up after IO_TIMEOUT without progress, well before the 90 s deadline
    // that bounds a reader still taking a little at a time.
    let started = Instant::now();
    let after = loop {
        let answer = upload(addr, &inspect_head("small", 3, HEADER), b"abc");
        if !answer.starts_with("HTTP/1.1 503") || started.elapsed() > Duration::from_secs(60) {
            break answer;
        }
        thread::sleep(Duration::from_millis(250));
    };
    assert!(after.starts_with("HTTP/1.1 200"), "{after}");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(stalled);
}

/// A key save whose head never ended is refused for that, not as a badly encoded form.
#[test]
fn a_key_save_cut_short_is_refused_for_what_it_is() {
    let home = key_home("cut-short");
    let answer = text(respond(
        &format!("POST {KEYS_PATH} HTTP/1.1\r\nHost: localhost\r\n{HEADER}"),
        &test_config(loopback_bind(), None),
        &key_routes(&home),
    ));
    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    assert!(answer.contains("ended before its head did"), "{answer}");
}

/// `/api/events` streams scan events as Server-Sent Events: the stream announces its media type,
/// then each published event arrives as a `data:` frame of its JSON, and the connection ends when
/// the client goes away.
#[test]
fn the_event_stream_pushes_published_events_as_sse_frames() {
    use crate::serve_events::{Event, EventHub};
    use std::io::Read as _;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let hub = Arc::new(EventHub::new());
    let streaming = Arc::clone(&hub);
    let handle = thread::spawn(move || stream_events(&mut server, &streaming));

    // The subscription is taken at the start of stream_events; publish once it is live so the
    // event is not missed, then read until its frame arrives.
    thread::sleep(Duration::from_millis(150));
    hub.publish(Event::Scan {
        id: "abc123".into(),
        status: "RUNNING".into(),
        at: 7,
    });

    let mut received = String::new();
    let mut buf = [0_u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        match client.read(&mut buf) {
            Ok(n) if n > 0 => {
                received.push_str(&String::from_utf8_lossy(&buf[..n]));
                if received.contains("\"id\":\"abc123\"") {
                    break;
                }
            }
            Ok(_) | Err(_) => break,
        }
    }
    assert!(
        received.contains("Content-Type: text/event-stream"),
        "{received}"
    );
    assert!(received.contains("retry: 3000"), "{received}");
    assert!(
        received.contains("data: {\"kind\":\"scan\",\"id\":\"abc123\",\"status\":\"RUNNING\""),
        "a published scan event is one SSE data frame: {received}"
    );
    // The client going away ends the stream at the server's next write, not after the full bound.
    drop(client);
    handle.join().unwrap();
}

/// The blueprint downloads as the same Word document `huntsman-recon blueprint --docx` writes,
/// named for saving, and an unknown format is refused rather than answered as JSON.
#[test]
fn the_blueprint_downloads_as_a_word_document() {
    let ask = |query: &str| {
        let raw = respond(
            &format!("GET /api/blueprint{query} HTTP/1.1\r\n\r\n"),
            &test_config(loopback_bind(), None),
            &Routes::default(),
        );
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        (
            String::from_utf8(raw[..split].to_vec()).unwrap(),
            raw[split..].to_vec(),
        )
    };
    let (head, body) = ask("?format=docx");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        header(&head, "Content-Type"),
        Some(crate::docx::CONTENT_TYPE)
    );
    assert_eq!(
        header(&head, "Content-Disposition"),
        Some("attachment; filename=\"OSINT_APK_BLUEPRINT.docx\"")
    );
    assert_eq!(body, crate::osint_blueprint::docx());
    let (_, json) = ask("");
    let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["count"], crate::osint_blueprint::ENTRIES.len());
    assert!(ask("?format=pdf").0.starts_with("HTTP/1.1 400"));
}

/// The mobile universal research API cannot dispatch unrecognised text as a person; it
/// sends it to the injected keyless research adapter. Typed selectors only produce a scan
/// preview, so the page can show the existing New Scan source choices before any egress.
#[test]
fn universal_research_api_is_bounded_guarded_and_uses_canonical_rust_routes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let routes = Routes {
        research: Some(Research {
            handler: Arc::new(move |query| {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::json!({
                    "route": "adaptive_web_search",
                    "report": {
                        "input": query,
                        "hits": [{"url": "https://example.org", "evidence_status": "lead_only"}],
                        "stop_reason": "bounded_test",
                    },
                }))
            }),
            live: Arc::new(AtomicUsize::new(0)),
        }),
        ..Routes::default()
    };
    let config = ServeConfig::parse(DEFAULT_BIND, None).unwrap();
    let ask = |request: &str| text(respond(request, &config, &routes));
    let typed = ask(
        "GET /api/research?q=example.org HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
    );
    assert!(typed.starts_with("HTTP/1.1 200"), "{typed}");
    assert!(typed.contains("\"route\":\"scan\""), "{typed}");
    assert!(typed.contains("\"kind\":\"domain\""), "{typed}");
    assert!(typed.contains("review_scan_options_before_collection"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let plain = ask(
        "GET /api/research?q=any+research+phrase HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
    );
    assert!(plain.starts_with("HTTP/1.1 200"), "{plain}");
    assert!(
        plain.contains("\"input\":\"any research phrase\""),
        "{plain}"
    );
    assert!(plain.contains("lead_only"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for (request, status) in [
        (
            "GET /api/research?q=hello HTTP/1.1\r\nHost: localhost\r\n\r\n",
            403,
        ),
        (
            "GET /api/research?q=hello HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: cross-site\r\nX-Huntsman-Lookup: 1\r\n\r\n",
            403,
        ),
        (
            "POST /api/research?q=hello HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
            405,
        ),
        (
            "GET /api/research?q=127.0.0.1 HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
            400,
        ),
        (
            "GET /api/research?q=1.1.1.1%2F33 HTTP/1.1\r\nHost: localhost\r\nX-Huntsman-Lookup: 1\r\n\r\n",
            400,
        ),
    ] {
        let answer = ask(request);
        assert!(
            answer.starts_with(&format!("HTTP/1.1 {status}")),
            "{answer}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
