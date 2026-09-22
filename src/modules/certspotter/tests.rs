use super::*;

/// Build an `Issuance` for the pure `build_entities` tests without a live fetch.
fn issuance(dns: &[&str], issuer: Option<&str>) -> Issuance {
    Issuance {
        id: None,
        dns_names: dns.iter().map(|s| (*s).to_string()).collect(),
        issuer: issuer.map(|n| Issuer {
            name: Some(n.to_string()),
        }),
        not_before: Some("2024-01-01T00:00:00Z".into()),
        not_after: Some("2024-04-01T00:00:00Z".into()),
        cert_sha256: Some("deadbeef".into()),
    }
}

fn has_domain(es: &[Entity], value: &str) -> bool {
    es.iter()
        .any(|e| e.kind == EntityKind::Domain && e.value == value)
}

#[test]
fn accepts_domain_and_url_only() {
    let m = CertSpotter;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://x.com/a")));
    // Cert Spotter has no email search key (unlike crt.sh) and no non-host kinds.
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@x.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "u")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(
        CertSpotter.cost(),
        crate::core::module::ModuleCost::Free
    ));
}

#[test]
fn description_non_empty() {
    assert!(!CertSpotter.description().is_empty());
}

#[test]
fn produces_declares_domain_and_organisation() {
    let p = CertSpotter.produces();
    assert!(p.contains(&EntityKind::Domain));
    assert!(p.contains(&EntityKind::Organisation));
}

#[test]
fn issuance_deserialises_from_the_expanded_api_shape() {
    let json = r#"[
        {"id":"6295991939",
         "dns_names":["example.com","www.example.com","*.example.com"],
         "issuer":{"name":"C=US, O=Let's Encrypt, CN=R3"},
         "not_before":"2024-01-01T00:00:00Z",
         "not_after":"2024-04-01T00:00:00Z",
         "cert_sha256":"deadbeef"}
    ]"#;
    let entries: Vec<Issuance> = serde_json::from_str(json).expect("should succeed");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].dns_names.len(), 3);
    assert_eq!(
        entries[0].issuer.as_ref().expect("should succeed").name.as_deref(),
        Some("C=US, O=Let's Encrypt, CN=R3")
    );
    assert_eq!(entries[0].cert_sha256.as_deref(), Some("deadbeef"));
}

#[test]
fn missing_fields_degrade_gracefully() {
    // A minimal object (only dns_names) must still deserialize — every other
    // field is optional so a partial/renamed response yields fewer entities
    // rather than a hard error.
    let entries: Vec<Issuance> =
        serde_json::from_str(r#"[{"dns_names":["a.example.com"]}]"#).expect("should succeed");
    let es = build_entities(&entries, "example.com", "scan1");
    assert!(has_domain(&es, "a.example.com"));
}

#[test]
fn build_entities_classifies_subdomains_and_skips_wildcards() {
    // Note: `Entity::new` normalises domains by stripping a leading `www.`, so a
    // `mail.` subdomain is used here to assert the sub-name survives verbatim.
    let entries = vec![issuance(
        &["example.com", "mail.example.com", "*.example.com", "unrelated.org"],
        None,
    )];
    let es = build_entities(&entries, "example.com", "scan1");

    // Subdomains of the base get the high-confidence subdomain treatment.
    let sub = es
        .iter()
        .find(|e| e.value == "mail.example.com")
        .expect("subdomain present");
    assert!((sub.confidence - confidence::VERY_HIGH).abs() < 1e-9);
    assert!(sub.tags.iter().any(|t| t == tags::SUBDOMAIN));
    assert!(sub.tags.iter().any(|t| t == tags::CT_LOG));

    // An off-base name from a multi-SAN cert is retained as a lower-confidence
    // pivot but NOT tagged a subdomain of the seed.
    let other = es
        .iter()
        .find(|e| e.value == "unrelated.org")
        .expect("off-base SAN present");
    assert!((other.confidence - confidence::LOW_MEDIUM).abs() < 1e-9);
    assert!(!other.tags.iter().any(|t| t == tags::SUBDOMAIN));

    // Wildcard SANs are never emitted (not resolvable hosts).
    assert!(!has_domain(&es, "*.example.com"));

    // Regression: the apex itself is not a subdomain of itself — a single
    // cert commonly SANs both the bare apex and "www." (and this fixture's
    // apex, "example.com", is present in `entries` above). It must be kept
    // (real, useful evidence) but never tagged tags::SUBDOMAIN.
    let apex = es
        .iter()
        .find(|e| e.value == "example.com")
        .expect("apex itself present");
    assert!(
        !apex.tags.iter().any(|t| t == tags::SUBDOMAIN),
        "the apex must never be tagged as its own subdomain"
    );
}

#[test]
fn the_apex_is_never_tagged_a_subdomain_when_www_cooccurs_in_the_same_issuance() {
    // Regression, mirroring the identical, already-fixed case in the sibling
    // `crtsh` module: a single certificate's `dns_names` commonly SANs both
    // the bare apex and "www." in the SAME issuance (unlike the fixture
    // above, which never puts both spellings in one `dns_names` array). Prior
    // to normalising `name`/`base` before dedup+classification, "www.example.com"
    // independently earned `tags::SUBDOMAIN` (it IS a proper subdomain of the
    // raw base) while "example.com" independently earned no tag — but
    // `Entity::new` normalises both to the same uid ("example.com"), so
    // whichever sorted first carried its tag onto the merged apex regardless
    // of the other's (correct) verdict. The apex is not a subdomain of
    // itself — tagging it SUBDOMAIN merges directly onto the scan's own
    // anchor/subject entity for a Domain-kind seed, since `EntityKind::Domain`
    // + the apex is the identical uid — permanently mislabeling the
    // operator's own search subject as a subdomain of itself.
    let entries = vec![issuance(&["www.example.com", "example.com"], None)];
    let es = build_entities(&entries, "example.com", "scan1");
    // Only one entity should survive for the apex — both raw SANs canonicalise
    // to the same identity, so the second is a dedup, not a second pivot.
    assert_eq!(es.iter().filter(|e| e.value == "example.com").count(), 1);
    let apex = es
        .iter()
        .find(|e| e.value == "example.com")
        .expect("apex itself present");
    assert!(
        !apex.tags.iter().any(|t| t == tags::SUBDOMAIN),
        "the apex must never be tagged as its own subdomain"
    );
    assert!((apex.confidence - confidence::LOW_MEDIUM).abs() < 1e-9);
}

#[test]
fn build_entities_dedups_names_across_certificates() {
    // The same hostname appearing on many certs yields exactly one entity.
    let entries = vec![
        issuance(&["mail.example.com"], None),
        issuance(&["mail.example.com"], None),
        issuance(&["mail.example.com", "api.example.com"], None),
    ];
    let es = build_entities(&entries, "example.com", "scan1");
    let mail_count = es.iter().filter(|e| e.value == "mail.example.com").count();
    assert_eq!(mail_count, 1, "duplicate SANs must collapse to one entity");
    assert!(has_domain(&es, "api.example.com"));
}

#[test]
fn build_entities_mines_only_nonpublic_issuers() {
    // A public CA issuer adds no signal → no Organisation entity.
    let public = vec![issuance(&["a.example.com"], Some("C=US, O=Let's Encrypt, CN=R3"))];
    let es = build_entities(&public, "example.com", "scan1");
    assert!(
        !es.iter().any(|e| e.kind == EntityKind::Organisation),
        "public CA must not become an Organisation"
    );

    // A custom / enterprise CA IS a high-value attribution pivot.
    let private = vec![issuance(&["a.example.com"], Some("O=Acme Internal CA Pty Ltd, C=AU"))];
    let es = build_entities(&private, "example.com", "scan1");
    let org = es
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("non-public issuer becomes an Organisation");
    assert_eq!(org.value, "Acme Internal CA Pty Ltd");
    assert!(org.tags.iter().any(|t| t == "certificate-issuer"));
}

#[test]
fn build_entities_is_deterministic_and_confidence_sorted() {
    let entries = vec![issuance(
        &["z.example.com", "a.example.com", "unrelated.org"],
        Some("O=Acme Internal CA Pty Ltd"),
    )];
    let first = build_entities(&entries, "example.com", "scan1");
    let second = build_entities(&entries, "example.com", "scan1");
    // Reproducible order (Determinism Requirement).
    let order = |v: &[Entity]| v.iter().map(|e| e.value.clone()).collect::<Vec<_>>();
    assert_eq!(order(&first), order(&second));
    // Confidence-descending: the VERY_HIGH subdomains precede the LOW_MEDIUM off-base name.
    let confs: Vec<f64> = first.iter().map(|e| e.confidence).collect();
    assert!(
        confs.windows(2).all(|w| w[0] >= w[1]),
        "entities must be emitted confidence-descending: {confs:?}"
    );
}

// ── The `after=` cursor walk ────────────────────────────────────────────────
//
// Hermetic: a loopback listener answering a scripted sequence of responses and
// recording each request line, and a plain `reqwest::Client` (NOT
// `build_client()`, whose SSRF resolver refuses loopback). Every response is
// `Connection: close`, so each page is its own accept and the recorded count is
// the number of requests the walk made. Failure statuses are 5xx rather than
// 429: one 5xx cannot open the loopback endpoint's circuit breaker, so no test
// here can change what another sees.

/// `n` issuances whose ids run `first..first+n` — a page of the real shape.
fn page_json(first: usize, n: usize) -> String {
    let items: Vec<String> = (first..first + n)
        .map(|i| format!(r#"{{"id":"{i}","dns_names":["h{i}.example.com"]}}"#))
        .collect();
    format!("[{}]", items.join(","))
}

/// Serve `responses` in order, one per connection, returning the base URL and
/// the request line of every request received.
async fn scripted_server(
    responses: Vec<(u16, String)>,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_srv = std::sync::Arc::clone(&seen);
    tokio::spawn(async move {
        for (status, body) in responses {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let mut n = 0;
            while n < buf.len() {
                let Ok(read) = sock.read(&mut buf[n..]).await else {
                    break;
                };
                if read == 0 {
                    break;
                }
                n += read;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf[..n]);
            let line = head.lines().next().unwrap_or_default().to_string();
            seen_srv.lock().expect("request log").push(line);
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    (format!("http://{addr}/v1/issuances"), seen)
}

async fn walk(base: &str, max_pages: usize, cutoff: std::time::Duration) -> Result<Walk> {
    walk_issuances(&reqwest::Client::new(), base, "example.com", max_pages, cutoff).await
}

const GENEROUS: std::time::Duration = std::time::Duration::from_secs(60);

#[tokio::test]
async fn a_short_page_is_the_whole_answer_and_costs_one_request() {
    // The common case must stay exactly what it was: one request out of an
    // anonymous budget of ten an hour, and an answer the coverage layer may
    // treat as complete.
    let (base, seen) = scripted_server(vec![(200, page_json(1, 3))]).await;
    let w = walk(&base, MAX_PAGES, GENEROUS).await.expect("short page");
    assert_eq!(w.entries.len(), 3);
    assert!(w.cut.is_none(), "a short page is the end of the data: {:?}", w.cut);
    assert_eq!(seen.lock().expect("log").len(), 1, "no confirming request");
}

#[tokio::test]
async fn a_full_page_is_followed_from_its_last_issuance_id() {
    // FAILS before the fix: the module read one page and stopped, so the
    // second page's two subdomains were never requested and the answer was
    // reported complete.
    let (base, seen) = scripted_server(vec![
        (200, page_json(1, PAGE_SIZE)),
        (200, page_json(PAGE_SIZE + 1, 2)),
    ])
    .await;
    let w = walk(&base, MAX_PAGES, GENEROUS).await.expect("two pages");
    assert_eq!(w.entries.len(), PAGE_SIZE + 2, "both pages retrieved");
    assert!(w.cut.is_none(), "the walk reached a short page: {:?}", w.cut);
    let seen = seen.lock().expect("log").clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        !seen[0].contains("after="),
        "the first page has no cursor: {}",
        seen[0]
    );
    assert!(
        seen[1].contains(&format!("&after={PAGE_SIZE} ")),
        "the second page continues from the first page's LAST id: {}",
        seen[1]
    );
    // The page's own query is unchanged — the cursor is appended, not swapped in.
    assert!(seen[1].contains("domain=example.com&include_subdomains=true"));
}

#[tokio::test]
async fn an_empty_page_after_a_full_one_is_the_end_not_a_truncation() {
    // A corpus of exactly PAGE_SIZE issuances: the full page is followed, and
    // the API's own terminating empty array settles it.
    let (base, seen) =
        scripted_server(vec![(200, page_json(1, PAGE_SIZE)), (200, "[]".into())]).await;
    let w = walk(&base, MAX_PAGES, GENEROUS).await.expect("full then empty");
    assert_eq!(w.entries.len(), PAGE_SIZE);
    assert!(w.cut.is_none(), "{:?}", w.cut);
    assert_eq!(seen.lock().expect("log").len(), 2);
}

#[tokio::test]
async fn reaching_the_page_cap_is_reported_as_truncation() {
    let (base, seen) = scripted_server(vec![
        (200, page_json(1, PAGE_SIZE)),
        (200, page_json(PAGE_SIZE + 1, PAGE_SIZE)),
        (200, page_json(2 * PAGE_SIZE + 1, PAGE_SIZE)),
    ])
    .await;
    let w = walk(&base, 2, GENEROUS).await.expect("capped walk");
    assert_eq!(w.entries.len(), 2 * PAGE_SIZE);
    assert_eq!(seen.lock().expect("log").len(), 2, "the cap is a request bound");
    let cut = w.cut.expect("a capped walk is not complete");
    assert!(cut.contains("cap of 2 pages"), "{cut}");
}

#[tokio::test]
async fn a_later_page_failure_keeps_the_pages_already_retrieved() {
    // The pre-fix module had only one request, so this is the invariant the
    // walk must not break: evidence already retrieved is never discarded
    // because a DIFFERENT page failed — it is kept, and declared incomplete.
    let (base, _seen) = scripted_server(vec![
        (200, page_json(1, PAGE_SIZE)),
        (503, r#"{"code":"unavailable","message":"try later"}"#.into()),
    ])
    .await;
    let w = walk(&base, MAX_PAGES, GENEROUS)
        .await
        .expect("a later failure is not the module's error");
    assert_eq!(w.entries.len(), PAGE_SIZE, "page one survives");
    let cut = w.cut.expect("a walk cut by a failure is not complete");
    assert!(cut.contains("page 2"), "{cut}");
    assert!(cut.contains("503"), "the cause names the failing status: {cut}");
}

#[tokio::test]
async fn a_first_page_failure_is_still_the_modules_error() {
    // With nothing retrieved, `Ok(empty)` would be a clean negative
    // fabricated from an outage.
    let (base, _seen) = scripted_server(vec![(
        503,
        r#"{"code":"unavailable","message":"try later"}"#.into(),
    )])
    .await;
    assert!(walk(&base, MAX_PAGES, GENEROUS).await.is_err());
}

#[tokio::test]
async fn the_time_budget_stops_the_walk_before_requesting_another_page() {
    // A zero budget: the first page is always fetched, no further page is.
    let (base, seen) = scripted_server(vec![
        (200, page_json(1, PAGE_SIZE)),
        (200, page_json(PAGE_SIZE + 1, 2)),
    ])
    .await;
    let w = walk(&base, MAX_PAGES, std::time::Duration::ZERO)
        .await
        .expect("budgeted walk");
    assert_eq!(w.entries.len(), PAGE_SIZE);
    assert_eq!(seen.lock().expect("log").len(), 1);
    let cut = w.cut.expect("a walk stopped by its budget is not complete");
    assert!(cut.contains("time budget") && cut.contains("page 2"), "{cut}");
}

#[tokio::test]
async fn a_full_page_without_a_cursor_is_truncated_not_complete() {
    // Schema drift that drops `id`: the walk cannot continue, and must not
    // claim it reached the end.
    let items: Vec<String> = (0..PAGE_SIZE)
        .map(|i| format!(r#"{{"dns_names":["h{i}.example.com"]}}"#))
        .collect();
    let (base, seen) = scripted_server(vec![(200, format!("[{}]", items.join(",")))]).await;
    let w = walk(&base, MAX_PAGES, GENEROUS).await.expect("page");
    assert_eq!(seen.lock().expect("log").len(), 1);
    let cut = w.cut.expect("an unfollowable full page is not complete");
    assert!(cut.contains("no `id`"), "{cut}");
}

#[test]
fn the_cursor_is_percent_encoded_onto_the_unchanged_query() {
    assert_eq!(
        issuances_url("https://h/v1/issuances", "example.com", None),
        "https://h/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&expand=issuer"
    );
    assert_eq!(
        issuances_url("https://h/v1/issuances", "example.com", Some("a b&c")),
        "https://h/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&expand=issuer&after=a+b%26c"
    );
}

#[test]
fn a_cut_walk_reaches_the_coverage_layer_and_a_complete_one_does_not() {
    // The emission seam: `process()` returns exactly this. A `cut` that never
    // became `ModuleResult::truncation` would leave the coverage layer reading
    // a partial answer as complete — the defect this walk exists to close.
    let entries: Vec<Issuance> =
        serde_json::from_str(&page_json(1, 3)).expect("page decodes");
    let cut = walk_result(
        Walk {
            entries,
            cut: Some("the cap of 5 pages of Cert Spotter's `after=` cursor".into()),
        },
        "example.com",
        "scan1",
    );
    assert_eq!(cut.entities.len(), 3);
    let why = cut.truncation.expect("a cut walk is declared incomplete");
    assert!(why.contains("cap of 5 pages"), "{why}");

    let entries: Vec<Issuance> =
        serde_json::from_str(&page_json(1, 3)).expect("page decodes");
    let complete = walk_result(Walk { entries, cut: None }, "example.com", "scan1");
    assert_eq!(complete.entities.len(), 3);
    assert!(complete.truncation.is_none(), "a complete walk stays complete");
}

#[test]
fn the_page_id_is_read_from_the_real_response_shape() {
    // Captured shape (2026-09-22, `github.com`): `id` is a string.
    let entries: Vec<Issuance> = serde_json::from_str(
        r#"[{"id":"13962517288","tbs_sha256":"41b8","cert_sha256":"4cd1",
             "dns_names":["f.cloud.github.com"],"pubkey_sha256":"83fe",
             "not_before":"2026-02-27T20:05:17Z","not_after":"2027-03-31T20:05:16Z",
             "revoked":false}]"#,
    )
    .expect("real page decodes");
    assert_eq!(entries[0].id.as_deref(), Some("13962517288"));
}
