use huntsman_recon::http::Method;
use huntsman_recon::keys::Keys;
use huntsman_recon::seeknow_cli::{SeekNowCliRun, run_with_keys};

#[allow(dead_code)]
#[path = "support/seeknow_doubles.rs"]
mod seeknow_doubles;

use seeknow_doubles::{ScriptedTransport, response};

fn configured_keys() -> Keys {
    Keys::parse("HUNTSMAN_SEEKNOW_KEY=dummy-seeknow-key-for-tests\n").unwrap()
}

#[test]
fn missing_or_unknown_arguments_are_usage_and_make_no_request() {
    let transport = ScriptedTransport::new(Vec::new());
    assert_eq!(
        run_with_keys(&transport, &[], &configured_keys(), 1),
        SeekNowCliRun::Usage
    );
    assert_eq!(
        run_with_keys(&transport, &["unknown".into()], &configured_keys(), 1),
        SeekNowCliRun::Usage
    );
    assert_eq!(transport.seen.borrow().len(), 0);
}

#[test]
fn missing_key_is_missing_input_before_transport() {
    // A missing key is missing input (exit 66), consistent with `hibp` and
    // `recon stolen-tax`; it is not a permission failure (exit 77), which is reserved
    // for a credential that is present but cannot be approved or is rejected upstream.
    let transport = ScriptedTransport::new(Vec::new());
    let result = run_with_keys(&transport, &["credits".into()], &Keys::default(), 2);
    match result {
        SeekNowCliRun::Input(message) => {
            assert!(message.contains("HUNTSMAN_SEEKNOW_KEY"));
            assert!(!message.contains("dummy-seeknow-key-for-tests"));
        }
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(transport.seen.borrow().len(), 0);
}

#[test]
fn credits_and_status_use_authenticated_diagnostic_endpoints_without_printing_secret() {
    let transport = ScriptedTransport::new(vec![
        response(
            200,
            r#"{"success":true,"credits_remaining":499,"daily_limit":500}"#,
        ),
        response(200, r#"{"success":true,"status":"ok","region":"eu"}"#),
    ]);
    let keys = configured_keys();

    let credits = run_with_keys(&transport, &["credits".into()], &keys, 3);
    let status = run_with_keys(&transport, &["status".into()], &keys, 4);
    for result in [credits, status] {
        match result {
            SeekNowCliRun::Printed(text) => {
                assert!(!text.contains("dummy-seeknow-key-for-tests"));
                assert!(text.contains("outcome=success"), "{text}");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, Method::Get);
    assert!(seen[0].url.ends_with("/credits"));
    assert!(seen[1].url.ends_with("/status"));
    assert_eq!(
        seen[0].header_value("x-api-key"),
        Some("dummy-seeknow-key-for-tests")
    );
}

#[test]
fn provider_text_cannot_drive_the_terminal_or_forge_a_row_in_a_status_or_search_report() {
    let transport = ScriptedTransport::new(vec![
        response(
            200,
            r#"{"success":true,"status":"ok\u001b[2J","re\ngion":"eu\tforged"}"#,
        ),
        response(
            200,
            r#"{"success":true,"data":[{"email":"alice@example.com","name":"Jane\u001b[2J Doe","dbname":"Set\u001b[31m A"}]}"#,
        ),
    ]);
    let keys = configured_keys();
    let status = vec!["status".to_string()];
    let search = vec![
        "search".to_string(),
        "email".to_string(),
        "alice@example.com".to_string(),
    ];
    for args in [status, search] {
        match run_with_keys(&transport, &args, &keys, 7) {
            SeekNowCliRun::Printed(text) => {
                assert!(
                    text.chars()
                        .all(|c| !c.is_control() || matches!(c, '\n' | '\t')),
                    "a control character other than the report's own separators: {text:?}"
                );
                assert!(
                    !text.lines().any(|line| line.starts_with("gion")),
                    "provider text became a row of its own: {text:?}"
                );
                if args[0] == "search" {
                    assert!(
                        text.contains("person\tjane\\u{1b}[2j doe"),
                        "the entity value is shown escaped, not dropped: {text:?}"
                    );
                }
            }
            other => panic!("unexpected result for {args:?}: {other:?}"),
        }
    }
}

#[test]
fn search_defaults_to_adaptive_and_deep_is_spent_only_after_valid_zero() {
    let transport = ScriptedTransport::new(vec![
        response(200, r#"{"success":true,"data":[]}"#),
        response(
            200,
            r#"{"success":true,"data":[{"email":"alice@example.com","dbname":"Dataset A"}]}"#,
        ),
    ]);
    let result = run_with_keys(
        &transport,
        &["search".into(), "email".into(), "alice@example.com".into()],
        &configured_keys(),
        5,
    );
    match result {
        SeekNowCliRun::Printed(text) => {
            assert!(text.contains("outcome=success"), "{text}");
            assert!(text.contains("email\talice@example.com"), "{text}");
            assert!(text.contains("dataset a"), "{text}");
        }
        other => panic!("unexpected result: {other:?}"),
    }
    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].url.ends_with("/search"));
    assert!(seen[1].url.ends_with("/stealer"));
}

#[test]
fn a_200_success_false_envelope_is_unavailable_not_a_printed_zero() {
    let transport = ScriptedTransport::new(vec![
        response(
            200,
            r#"{"success":false,"error":"search backend unavailable","data":[]}"#,
        ),
        response(200, r#"{"success":false,"error":"maintenance"}"#),
    ]);
    let keys = configured_keys();

    let search = run_with_keys(
        &transport,
        &["search".into(), "email".into(), "alice@example.com".into()],
        &keys,
        8,
    );
    assert_eq!(
        search,
        SeekNowCliRun::Unavailable("SeekNow collection outcome=inconclusive".into())
    );
    let status = run_with_keys(&transport, &["status".into()], &keys, 9);
    assert_eq!(
        status,
        SeekNowCliRun::Unavailable(
            "SeekNow outcome=inconclusive detail=provider reported request failure".into()
        )
    );

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].url.ends_with("/search"));
    assert!(seen[1].url.ends_with("/status"));
}

#[test]
fn explicit_fast_only_and_deep_modes_are_distinct_and_invalid_selector_is_data_error() {
    let fast = ScriptedTransport::new(vec![response(200, r#"{"success":true,"data":[]}"#)]);
    let result = run_with_keys(
        &fast,
        &[
            "search".into(),
            "username".into(),
            "alice".into(),
            "--fast-only".into(),
        ],
        &configured_keys(),
        6,
    );
    assert!(matches!(result, SeekNowCliRun::Printed(_)));
    assert_eq!(fast.seen.borrow().len(), 1);
    assert!(fast.seen.borrow()[0].url.ends_with("/search"));

    let deep = ScriptedTransport::new(vec![response(200, r#"{"success":true,"data":[]}"#)]);
    let result = run_with_keys(
        &deep,
        &[
            "search".into(),
            "url".into(),
            "https://example.com/login".into(),
            "--deep".into(),
        ],
        &configured_keys(),
        7,
    );
    assert!(matches!(result, SeekNowCliRun::Printed(_)));
    assert_eq!(deep.seen.borrow().len(), 1);
    assert!(deep.seen.borrow()[0].url.ends_with("/stealer"));

    let unsupported_deep = ScriptedTransport::new(Vec::new());
    let result = run_with_keys(
        &unsupported_deep,
        &[
            "search".into(),
            "person".into(),
            "Alice Example".into(),
            "--deep".into(),
        ],
        &configured_keys(),
        7,
    );
    assert!(matches!(result, SeekNowCliRun::BadData(_)));
    assert_eq!(unsupported_deep.seen.borrow().len(), 0);

    let unsupported_fast = ScriptedTransport::new(Vec::new());
    let result = run_with_keys(
        &unsupported_fast,
        &[
            "search".into(),
            "machine_id".into(),
            "synthetic-machine-001".into(),
            "--fast-only".into(),
        ],
        &configured_keys(),
        7,
    );
    assert!(matches!(result, SeekNowCliRun::BadData(_)));
    assert_eq!(unsupported_fast.seen.borrow().len(), 0);

    let invalid = ScriptedTransport::new(Vec::new());
    let result = run_with_keys(
        &invalid,
        &["search".into(), "person".into(), "A".into()],
        &configured_keys(),
        8,
    );
    assert!(matches!(result, SeekNowCliRun::BadData(_)));
    assert_eq!(invalid.seen.borrow().len(), 0);
}
