//! Ported from M D's `src/modules/crtsh/tests.rs` (764ce8e). No live network: every
//! lookup runs against a scripted fake transport.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use super::*;
use crate::http::{Response, TransportFailure};

type Reply = Result<Response, TransportFailure>;

struct Script {
    replies: RefCell<VecDeque<Reply>>,
    seen: RefCell<Vec<Request>>,
}

impl Script {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: RefCell::new(replies.into()),
            seen: RefCell::new(Vec::new()),
        }
    }
    fn sent(&self) -> usize {
        self.seen.borrow().len()
    }
}

impl Transport for Script {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        self.replies
            .borrow_mut()
            .pop_front()
            .expect("unscripted request")
    }
}

#[allow(clippy::unnecessary_wraps)] // a scripted reply is a `Result`, like the transport's
fn status(code: u16, body: &str) -> Reply {
    Ok(Response {
        status: code,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    })
}

fn timeout() -> Reply {
    Err(TransportFailure {
        kind: SourceOutcomeKind::TtfbTimeout,
        detail: "timed out".into(),
        blocked: false,
    })
}

fn entry(name_value: &str) -> CrtEntry {
    CrtEntry {
        name_value: Some(name_value.into()),
        ..CrtEntry::default()
    }
}

fn run(script: &Script, kind: ReconTargetKind, seed: &str) -> Result<CrtShReport, CrtShError> {
    let pauses = Cell::new(0u32);
    let out = lookup_with_pause(script, kind, seed, "scan", &|d| {
        assert_eq!(d, TRANSIENT_PAUSE);
        pauses.set(pauses.get() + 1);
    });
    if let Ok(report) = &out {
        assert_eq!(pauses.get() + 1, report.attempts.max(1));
    }
    out
}

fn values(entities: &[Entity]) -> Vec<&str> {
    entities.iter().map(|e| e.value.as_str()).collect()
}

#[test]
fn crt_entry_deser() {
    let raw = r#"[{"issuer_ca_id":1,"issuer_name":"C=US, O=Let's Encrypt","common_name":"example.com","name_value":"example.com\nwww.example.com","id":9,"entry_timestamp":"2024","not_before":"2024-01-01","not_after":"2024-04-01","serial_number":"0a","result_count":2}]"#;
    let parsed: Vec<CrtEntry> = serde_json::from_str(raw).unwrap();
    assert_eq!(parsed[0].common_name.as_deref(), Some("example.com"));
    assert_eq!(parsed[0].serial_number.as_deref(), Some("0a"));
    let sparse: Vec<CrtEntry> = serde_json::from_str("[{}]").unwrap();
    assert!(sparse[0].name_value.is_none());
}

#[test]
fn build_query_shapes_each_kind() {
    assert_eq!(
        build_query(ReconTargetKind::Domain, " example.com "),
        Some("%.example.com".into())
    );
    assert_eq!(
        build_query(ReconTargetKind::Email, "a@example.com"),
        Some("a@example.com".into())
    );
    assert_eq!(
        build_query(ReconTargetKind::Url, "https://Sub.Example.com/x?y=1"),
        Some("%.sub.example.com".into())
    );
    assert_eq!(build_query(ReconTargetKind::Username, "someone"), None);
}

#[test]
fn apex_base_extracts_the_true_host_for_each_seed_kind() {
    assert_eq!(
        apex_base(ReconTargetKind::Url, "https://example.com/login"),
        "example.com"
    );
    assert_eq!(
        apex_base(ReconTargetKind::Email, "jane@example.com"),
        "example.com"
    );
    assert_eq!(
        apex_base(ReconTargetKind::Domain, "example.com"),
        "example.com"
    );
}

#[test]
fn parse_dn_org_extracts_first_nonempty_o_field() {
    assert_eq!(
        parse_dn_org("C=US, O=Acme CA, CN=x").as_deref(),
        Some("Acme CA")
    );
    assert_eq!(
        parse_dn_org("CN=foo, O=, O=Second").as_deref(),
        Some("Second")
    );
    assert_eq!(parse_dn_org("CN=No Org"), None);
}

#[test]
fn a_quoted_or_escaped_comma_stays_inside_the_organisation() {
    // crt.sh quotes a value that holds a comma; splitting on every comma left `"CLOUDFLARE`,
    // which no public-CA prefix matched, so Cloudflare became an "enterprise PKI" pivot.
    assert_eq!(
        parse_dn_org(r#"C=US, O="CLOUDFLARE, INC.", CN=Cloudflare TLS Issuing ECC CA 1"#)
            .as_deref(),
        Some("CLOUDFLARE, INC.")
    );
    assert_eq!(
        parse_dn_org(r#"C=US, O="thawte, Inc.", CN=thawte SSL CA - G2"#).as_deref(),
        Some("thawte, Inc.")
    );
    assert_eq!(
        parse_dn_org(r"O=Acme\, Inc, CN=x").as_deref(),
        Some("Acme, Inc")
    );
    assert_eq!(
        parse_dn_org(r#"O="Acme \"Labs\", Ltd", CN=x"#).as_deref(),
        Some(r#"Acme "Labs", Ltd"#)
    );
    assert_eq!(
        dn_attributes("CN=a + OU=b, O=c"),
        [("CN", "a"), ("OU", "b"), ("O", "c")].map(|(k, v)| (k.to_owned(), v.to_owned()))
    );
}

#[test]
fn a_quoted_public_ca_is_not_an_enterprise_issuer() {
    let entries = [
        CrtEntry {
            name_value: Some("a.example.com".into()),
            issuer_name: Some(
                r#"C=US, O="CLOUDFLARE, INC.", CN=Cloudflare TLS Issuing ECC CA 1"#.into(),
            ),
            ..CrtEntry::default()
        },
        CrtEntry {
            name_value: Some("b.example.com".into()),
            issuer_name: Some(r#"C=US, O="Acme Holdings, Ltd", CN=Acme Issuing CA"#.into()),
            ..CrtEntry::default()
        },
    ];
    let orgs: Vec<String> = build_entities(&entries, "example.com", "s")
        .into_iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| e.raw_value)
        .collect();
    assert_eq!(orgs, ["Acme Holdings, Ltd"]);
}

#[test]
fn public_cas_are_recognised_case_insensitively() {
    assert!(is_public_ca("DigiCert Inc"));
    assert!(is_public_ca("let's encrypt"));
    assert!(is_public_ca("SSL Corporation"));
    assert!(!is_public_ca("Acme Enterprise CA"));
}

#[test]
fn classifies_subdomains_dedups_and_skips_wildcards() {
    let entries = [
        entry("api.example.com\n*.example.com\napi.example.com"),
        entry("unrelated.org"),
        entry("evilexample.com"),
    ];
    let out = build_entities(&entries, "example.com", "scan");
    assert_eq!(out.len(), 3);
    let api = out.iter().find(|e| e.value == "api.example.com").unwrap();
    assert!((api.confidence - VERY_HIGH).abs() < f64::EPSILON);
    assert!(api.tags.iter().any(|t| t == tags::SUBDOMAIN));
    let evil = out.iter().find(|e| e.value == "evilexample.com").unwrap();
    assert!((evil.confidence - LOW_MEDIUM).abs() < f64::EPSILON);
    assert!(!evil.tags.iter().any(|t| t == tags::SUBDOMAIN));
    assert!(out.iter().all(|e| !e.value.starts_with('*')));
}

#[test]
fn the_apex_itself_is_never_tagged_as_its_own_subdomain() {
    let out = build_entities(&[entry("example.com\nwww.example.com")], "example.com", "s");
    assert_eq!(values(&out), ["example.com"]);
    assert_eq!(out[0].raw_value, "example.com");
    assert!(!out[0].tags.iter().any(|t| t == tags::SUBDOMAIN));
}

#[test]
fn subdomain_match_is_case_insensitive_against_base() {
    let out = build_entities(&[entry("API.Example.com")], "Example.COM", "s");
    assert_eq!(values(&out), ["api.example.com"]);
    assert!(out[0].tags.iter().any(|t| t == tags::SUBDOMAIN));
}

#[test]
fn url_seed_subdomains_are_classified_against_the_host_not_the_raw_url() {
    let script = Script::new(vec![status(200, r#"[{"name_value":"mail.example.com"}]"#)]);
    let report = run(&script, ReconTargetKind::Url, "https://example.com/login").unwrap();
    assert!(report.entities[0].tags.iter().any(|t| t == tags::SUBDOMAIN));
}

#[test]
fn surfaces_san_emails_above_min_length() {
    let out = build_entities(&[entry("jdoe@example.com\na@b")], "example.com", "s");
    assert_eq!(values(&out), ["jdoe@example.com"]);
    assert_eq!(out[0].kind, EntityKind::Email);
    assert!((out[0].confidence - HIGH_PLUS).abs() < f64::EPSILON);
}

#[test]
fn suppresses_role_mailbox_san_email() {
    let out = build_entities(
        &[entry("hostmaster@example.com\nnoreply@example.com")],
        "example.com",
        "s",
    );
    assert!(out.iter().all(|e| e.kind != EntityKind::Email), "{out:?}");
}

#[test]
fn results_emit_all_confidence_first_uncapped() {
    let mut names: Vec<String> = (0..250).map(|i| format!("host{i}.other-{i}.net")).collect();
    names.push("keep.example.com".into());
    let out = build_entities(&[entry(&names.join("\n"))], "example.com", "s");
    assert_eq!(out.len(), 251);
    assert_eq!(out[0].value, "keep.example.com");
    assert!(out.windows(2).all(|w| w[0].confidence >= w[1].confidence));
}

#[test]
fn emits_all_enterprise_ca_issuers_uncapped() {
    let entries: Vec<CrtEntry> = (0..15)
        .map(|i| CrtEntry {
            name_value: Some(format!("h{i}.example.com")),
            issuer_name: Some(format!("C=US, O=Acme Enterprise CA {i}")),
            ..CrtEntry::default()
        })
        .chain([CrtEntry {
            name_value: Some("pub.example.com".into()),
            issuer_name: Some("C=US, O=DigiCert Inc, CN=DigiCert TLS".into()),
            ..CrtEntry::default()
        }])
        .collect();
    let out = build_entities(&entries, "example.com", "s");
    let orgs: Vec<&Entity> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .collect();
    assert_eq!(orgs.len(), 15);
    let first = orgs[0];
    assert!(first.tags.iter().any(|t| t == "certificate-issuer"));
    assert!(first.tags.iter().any(|t| t == tags::DERIVED));
    assert_eq!(
        first.evidence[0]
            .attributes
            .get("signed_domain")
            .map(String::as_str),
        Some("example.com")
    );
}

#[test]
fn issuer_org_is_emitted_once_per_distinct_name_case_insensitively() {
    let entries = [
        CrtEntry {
            name_value: Some("a.example.com".into()),
            issuer_name: Some("O=Acme CA".into()),
            ..CrtEntry::default()
        },
        CrtEntry {
            name_value: Some("b.example.com".into()),
            issuer_name: Some("O=acme ca".into()),
            ..CrtEntry::default()
        },
    ];
    let out = build_entities(&entries, "example.com", "s");
    assert_eq!(
        out.iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .count(),
        1
    );
}

#[test]
fn recovers_certificate_serial_as_attribution_pivot() {
    let e = CrtEntry {
        serial_number: Some("04ab9f".into()),
        ..CrtEntry::default()
    };
    let ev = cert_evidence(&e, "x", "s");
    assert_eq!(
        ev.attributes.get("cert_serial").map(String::as_str),
        Some("04ab9f")
    );
}

#[test]
fn absent_serial_omits_the_attribute() {
    let blank = CrtEntry {
        serial_number: Some(String::new()),
        ..CrtEntry::default()
    };
    assert!(
        !cert_evidence(&blank, "x", "s")
            .attributes
            .contains_key("cert_serial")
    );
    assert!(
        !cert_evidence(&CrtEntry::default(), "x", "s")
            .attributes
            .contains_key("cert_serial")
    );
}

#[test]
fn cert_evidence_always_stamps_issuer_and_validity() {
    let e = CrtEntry {
        issuer_name: Some("CA".into()),
        not_before: Some("2024-01-01".into()),
        not_after: Some("2024-04-01".into()),
        ..CrtEntry::default()
    };
    let ev = cert_evidence(&e, "x", "s");
    assert_eq!(ev.attributes["issuer"], "CA");
    assert_eq!(ev.attributes["not_before"], "2024-01-01");
    assert_eq!(ev.attributes["not_after"], "2024-04-01");
    assert_eq!(ev.provenance.source, SRC);
}

#[test]
fn cert_evidence_stamps_empty_strings_when_fields_absent() {
    let ev = cert_evidence(&CrtEntry::default(), "x", "s");
    for key in ["issuer", "not_before", "not_after"] {
        assert_eq!(ev.attributes[key], "", "{key}");
    }
}

#[test]
fn timeout_allows_slow_but_alive_ct_json() {
    assert_eq!(TIMEOUT, Duration::from_secs(30));
    let config = transport_config();
    assert_eq!(config.timeout, TIMEOUT);
    assert_eq!(config.max_body, MAX_BODY);
}

#[test]
fn transient_retry_fires_only_for_502_503_429() {
    for code in [400u16, 401, 403, 404, 408, 429, 500, 502, 503, 504] {
        assert_eq!(
            is_transient_crt_status(code),
            matches!(code, 429 | 502 | 503),
            "{code}"
        );
    }
}

#[test]
fn a_transient_flap_is_retried_then_succeeds() {
    let script = Script::new(vec![
        status(502, "Bad Gateway"),
        status(503, "Service Unavailable"),
        status(200, r#"[{"name_value":"api.example.com"}]"#),
    ]);
    let report = run(&script, ReconTargetKind::Domain, "example.com").unwrap();
    assert_eq!(report.attempts, 3);
    assert_eq!(script.sent(), 3);
    assert_eq!(values(&report.entities), ["api.example.com"]);
}

#[test]
fn the_retry_budget_is_bounded() {
    let script = Script::new(vec![status(429, ""), status(429, ""), status(429, "")]);
    let err = run(&script, ReconTargetKind::Domain, "example.com").unwrap_err();
    assert_eq!(
        err,
        CrtShError::Status {
            status: 429,
            attempts: TRANSIENT_ATTEMPTS
        }
    );
    assert_eq!(script.sent(), 3);
}

#[test]
fn transient_transport_retries_once_but_other_failures_do_not() {
    let script = Script::new(vec![timeout(), status(200, "[]")]);
    let report = run(&script, ReconTargetKind::Domain, "example.com").unwrap();
    assert_eq!(report.attempts, 2);
    assert_eq!(script.sent(), 2);

    let script = Script::new(vec![status(500, "oops")]);
    assert_eq!(
        run(&script, ReconTargetKind::Domain, "example.com").unwrap_err(),
        CrtShError::Status {
            status: 500,
            attempts: 1
        }
    );
    assert_eq!(script.sent(), 1);

    let script = Script::new(vec![status(200, "not json")]);
    assert!(matches!(
        run(&script, ReconTargetKind::Domain, "example.com").unwrap_err(),
        CrtShError::Decode(_)
    ));
    assert_eq!(script.sent(), 1);
}

#[test]
fn a_challenge_page_is_not_an_empty_answer() {
    let script = Script::new(vec![status(
        200,
        "<html><title>Just a moment...</title>Cloudflare is checking your browser</html>",
    )]);
    assert!(matches!(
        run(&script, ReconTargetKind::Domain, "example.com").unwrap_err(),
        CrtShError::NotAnAnswer(_)
    ));
}

#[test]
fn a_challenge_page_on_a_transient_status_is_not_retried() {
    for code in [429u16, 502, 503] {
        let script = Script::new(vec![status(
            code,
            "<html><title>Just a moment...</title>Cloudflare is checking your browser</html>",
        )]);
        assert_eq!(
            run(&script, ReconTargetKind::Domain, "example.com").unwrap_err(),
            CrtShError::NotAnAnswer(SourceOutcomeKind::BotWaf),
            "{code}"
        );
        assert_eq!(script.sent(), 1, "{code}");
    }
}

#[test]
fn a_truncated_body_is_not_parsed_as_a_partial_answer() {
    let script = Script::new(vec![Ok(Response {
        status: 200,
        headers: Vec::new(),
        body: b"[]".to_vec(),
        truncated: true,
    })]);
    assert_eq!(
        run(&script, ReconTargetKind::Domain, "example.com").unwrap_err(),
        CrtShError::Truncated
    );
}

#[test]
fn request_is_a_plain_get_with_the_encoded_query_and_no_credential() {
    let script = Script::new(vec![status(200, "[]")]);
    let report = run(&script, ReconTargetKind::Domain, "example.com").unwrap();
    assert_eq!(report.entities.len(), 0);
    let seen = script.seen.borrow();
    assert_eq!(seen[0].url, "https://crt.sh/?q=%25.example.com&output=json");
    assert!(seen[0].header_value("authorization").is_none());
}

#[test]
fn a_redirect_is_not_followed() {
    let script = Script::new(vec![Ok(Response {
        status: 302,
        headers: vec![("location".into(), "https://elsewhere.example/".into())],
        body: Vec::new(),
        truncated: false,
    })]);
    assert!(matches!(
        run(&script, ReconTargetKind::Domain, "example.com").unwrap_err(),
        CrtShError::Status { status: 302, .. } | CrtShError::NotAnAnswer(_)
    ));
    assert_eq!(script.sent(), 1);
}

#[test]
fn a_username_seed_sends_nothing() {
    let script = Script::new(Vec::new());
    let report = run(&script, ReconTargetKind::Username, "someone").unwrap();
    assert_eq!(report.query, None);
    assert_eq!(report.attempts, 0);
    assert_eq!(script.sent(), 0);
}

#[test]
fn domain_query_uses_canonical_host_seed() {
    // A mixed-case, `www.`-prefixed, root-dotted seed must query the same apex
    // the entities are classified against, not a literal crt.sh never matches.
    for seed in ["Example.COM.", "www.example.com", " WWW.Example.com. "] {
        assert_eq!(
            build_query(ReconTargetKind::Domain, seed).as_deref(),
            Some("%.example.com"),
            "seed {seed:?}"
        );
    }
}

/// A root-dotted domain asks for its apex; a URL whose host is an address literal has no name
/// for crt.sh to match, so it asks nothing.
#[test]
fn build_query_on_a_root_dotted_domain_and_an_address_literal_url() {
    assert_eq!(
        build_query(ReconTargetKind::Domain, "Example.COM.").as_deref(),
        Some("%.example.com")
    );
    assert_eq!(
        build_query(ReconTargetKind::Url, "https://[2001:db8::1]/"),
        None
    );
}

fn cert(id: u64, names: &str, issuer: &str, not_before: &str, not_after: &str) -> CrtEntry {
    CrtEntry {
        id: Some(id),
        issuer_ca_id: Some(id % 7),
        common_name: names.split('\n').next().map(str::to_owned),
        name_value: Some(names.into()),
        issuer_name: Some(issuer.into()),
        not_before: Some(not_before.into()),
        not_after: Some(not_after.into()),
        entry_timestamp: Some(format!("{not_before}.5")),
        serial_number: Some(format!("{id:x}")),
    }
}

#[test]
fn a_name_on_several_certificates_keeps_every_one_once() {
    let entries = [
        cert(
            30,
            "api.example.com",
            "C=US, O=Let's Encrypt, CN=R10",
            "2026-05-01T00:00:00",
            "2026-08-01T00:00:00",
        ),
        cert(
            31,
            "api.example.com\nAPI.example.com",
            "C=US, O=\"Cloudflare, Inc.\", CN=Cloudflare TLS",
            "2026-01-01T00:00:00",
            "2027-01-01T00:00:00",
        ),
    ];
    let out = build_entities(&entries, "example.com", "s");
    assert_eq!(values(&out), ["api.example.com"]);
    let ev = &out[0].evidence;
    assert_eq!(ev.len(), 1);
    let attr = |key: &str| ev[0].attributes.get(key).map(String::as_str);
    assert_eq!(attr("certificates"), Some("2"), "{:?}", ev[0].attributes);
    assert_eq!(attr("cert_ids"), Some("30,31"));
    assert_eq!(attr("cert_serials"), Some("1e,1f"));
    assert_eq!(attr("issuer_ca_ids"), Some("2,3"));
    assert_eq!(attr("common_names"), Some("api.example.com"));
    assert_eq!(
        ev[0].attr_values("issuers").collect::<Vec<_>>(),
        [
            "C=US, O=Let's Encrypt, CN=R10",
            "C=US, O=\"Cloudflare, Inc.\", CN=Cloudflare TLS"
        ]
    );
    assert_eq!(attr("first_not_before"), Some("2026-01-01T00:00:00"));
    assert_eq!(attr("last_not_after"), Some("2027-01-01T00:00:00"));
    assert_eq!(attr("first_logged"), Some("2026-01-01T00:00:00.5"));
    assert_eq!(attr("last_logged"), Some("2026-05-01T00:00:00.5"));
    // The first certificate's own fields stay as they were.
    assert_eq!(attr("issuer"), Some("C=US, O=Let's Encrypt, CN=R10"));
    assert_eq!(attr("not_before"), Some("2026-05-01T00:00:00"));
    assert_eq!(attr("cert_serial"), Some("1e"));
}

#[test]
fn an_enterprise_issuer_keeps_every_certificate_and_name_it_signed() {
    let entries = [
        cert(
            40,
            "vpn.example.com",
            "O=Acme Issuing CA",
            "2026-01-01T00:00:00",
            "2026-06-01T00:00:00",
        ),
        cert(
            41,
            "intranet.example.com\n*.intranet.example.com",
            "O=Acme Issuing CA",
            "2026-02-01T00:00:00",
            "2026-07-01T00:00:00",
        ),
    ];
    let out = build_entities(&entries, "example.com", "s");
    let org = out
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .unwrap_or_else(|| panic!("no issuer organisation: {out:?}"));
    let attr = |key: &str| org.evidence[0].attributes.get(key).map(String::as_str);
    assert_eq!(attr("certificates"), Some("2"));
    assert_eq!(attr("cert_ids"), Some("40,41"));
    assert_eq!(
        attr("signed_names"),
        Some("vpn.example.com,intranet.example.com,*.intranet.example.com")
    );
    assert_eq!(attr("issuer_dn"), Some("O=Acme Issuing CA"));
}
