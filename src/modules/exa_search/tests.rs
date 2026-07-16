use super::*;

#[test]
fn accepts_identity_and_org_kinds() {
    let m = ExaSearch;
    for k in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::FullName,
        TargetKind::Domain,
        TargetKind::Organisation,
        TargetKind::Phone,
    ] {
        assert!(m.accepts(&Target::new(k, "x")));
    }
    // Not for IPs, coords, ASNs.
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn cost_is_keygated() {
    assert!(matches!(ExaSearch.cost(), ModuleCost::KeyGated));
}

fn live_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

/// One-shot local HTTP server answering with `status` + `body` — a real (not
/// mocked) transport for `fetch_exa` to hit. Mirrors the chain_intel pattern.
async fn serve_once(status: u16, body: &'static str) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let reason = if status == 200 { "OK" } else { "Error" };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body.as_bytes()).await;
        let _ = sock.flush().await;
    });
    addr
}

#[tokio::test]
async fn fetch_exa_surfaces_transport_failure_as_error() {
    // T2.129 regression: an api.exa.ai outage / unreachable host previously
    // folded into Ok(empty) — indistinguishable from "Exa found nothing" — which
    // silently truncated the whole downstream URL→Domain→web_crawler chain this
    // priority-87 module feeds. Port 1 has nothing listening (connection
    // refused): a real transport failure that must now surface as a module Err.
    let ctx = live_ctx();
    let out = fetch_exa(&ctx, "http://127.0.0.1:1/", "test-key-12345678", "q").await;
    assert!(
        out.is_err(),
        "an unreachable Exa host must surface as Err, not a swallowed empty result"
    );
}

#[tokio::test]
async fn fetch_exa_surfaces_parse_failure_on_a_200_garbage_body() {
    // A 200 whose body is not the expected JSON (truncation / contract change) is
    // a real anomaly, not "no matches" — previously swallowed into Ok(empty).
    let addr = serve_once(200, "definitely not json <<<>>>").await;
    let ctx = live_ctx();
    let out = fetch_exa(&ctx, &format!("http://{addr}/"), "test-key-12345678", "q").await;
    assert!(
        out.is_err(),
        "a 200 with an unparseable body must surface as Err, not a swallowed empty result"
    );
}

#[tokio::test]
async fn fetch_exa_keeps_404_as_a_clean_miss() {
    // The clean negative must be PRESERVED: a 404 is an honest "no matches",
    // Ok(None), not an error — so the fix surfaces outages without turning a
    // genuine empty result into noise.
    let addr = serve_once(404, "not found").await;
    let ctx = live_ctx();
    let out = fetch_exa(&ctx, &format!("http://{addr}/"), "test-key-12345678", "q").await;
    assert!(
        matches!(out, Ok(None)),
        "a 404 must stay a clean miss (Ok(None)), not an Err"
    );
}

#[test]
fn module_metadata() {
    let m = ExaSearch;
    assert_eq!(m.name(), "exa_search");
    assert_eq!(m.priority(), 87);
    assert_eq!(m.max_timeout_ms(), 20_000);
    assert!(!m.description().is_empty());
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn email_regex_matches_standard_addresses() {
    assert!(EMAIL_RE.is_match("contact alice@example.com please"));
    assert!(EMAIL_RE.is_match("bob.smith+tag@sub.example.co.uk"));
}

#[test]
fn phone_regex_matches_intl_format() {
    assert!(PHONE_RE.is_match("+44 20 7946 0958"));
    assert!(PHONE_RE.is_match("+1-555-123-4567"));
}

// ── mine_snippet ─────────────────────────────────────────────────────────────

fn snippets(text: &str) -> Vec<Entity> {
    let mut r = ModuleResult::new();
    mine_snippet(text, "scan-1", "https://example.com/page", &mut r);
    r.entities
}

#[test]
fn mine_snippet_extracts_email() {
    let ents = snippets("Contact us at sales@acme.com for pricing.");
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert_eq!(email.value, "sales@acme.com");
    assert!(email.has_tag("exa-search") && email.has_tag("web-scraped"));
    assert_eq!(
        email.evidence[0].attributes.get("source_url").map(String::as_str),
        Some("https://example.com/page")
    );
}

#[test]
fn mine_snippet_extracts_phone() {
    let ents = snippets("Call +61 2 9000 1234 for bookings.");
    let phone = ents.iter().find(|e| e.kind == EntityKind::Phone);
    assert!(phone.is_some(), "expected a Phone entity");
    let phone = phone.unwrap();
    assert!(phone.has_tag("exa-search") && phone.has_tag("web-scraped"));
}

#[test]
fn mine_snippet_rejects_too_few_digits() {
    // Only 6 digits — below the 7-digit minimum.
    let ents = snippets("Short ref: 123456");
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Phone));
}

#[test]
fn mine_snippet_empty_text_yields_nothing() {
    assert!(snippets("").is_empty());
}

#[test]
fn mine_snippet_no_matches_yields_nothing() {
    assert!(snippets("No contact information here, just prose.").is_empty());
}

#[test]
fn mine_snippet_email_lowercased() {
    let ents = snippets("Email ALICE@EXAMPLE.COM now.");
    let email = ents.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert_eq!(email.value, "alice@example.com");
}
