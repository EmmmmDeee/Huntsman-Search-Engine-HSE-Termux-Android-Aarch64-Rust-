use super::*;

fn email_target() -> Target {
    Target::new(TargetKind::Email, "jane@example.com")
}

fn build(json: &str) -> Vec<Entity> {
    let body: EpieosResp = serde_json::from_str(json).unwrap();
    build_entities(&email_target(), &body, "s")
}

// ── Module surface ──────────────────────────────────────────────────
#[test]
fn accepts_email_only() {
    let m = Epieos;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(Epieos.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    assert_eq!(Epieos.name(), "epieos");
    assert_eq!(Epieos.priority(), 92);
    assert_eq!(Epieos.max_timeout_ms(), 15_000);
    assert!(!Epieos.description().is_empty());
}

#[test]
fn parse_response() {
    let raw = r#"{"google_id":"123","name":"John Smith",
        "maps_reviews":[{"place_name":"Sydney Opera House","rating":5.0,"date":"2024-01-15"}],
        "skype":{"handle":"john.smith.au","name":"John Smith","city":"Sydney","country":"AU"}}"#;
    let r: EpieosResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.name.as_deref(), Some("John Smith"));
    assert_eq!(r.maps_reviews.unwrap().len(), 1);
}

// ── Core: full extraction incl. the recovered fields ─────────────────
#[test]
fn extracts_full_profile_with_review_rating_and_text() {
    let es = build(
        r#"{
            "google_id":"1234567890","name":"Jane Doe",
            "profile_picture":"https://lh3.googleusercontent.com/p",
            "maps_reviews":[
                {"place_name":"Sydney Opera House","rating":5.0,"text":"Stunning, came with family.","date":"2024-01-15"}
            ],
            "skype":{"handle":"jane.doe","name":"Jane Q Doe","city":"Sydney","country":"AU"},
            "calendar":{"name":"Jane Doe"}
        }"#,
    );

    // Enriched email anchor carries the Skype name (previously discarded).
    let anchor = es.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    let ev = &anchor.evidence[0];
    assert!(
        anchor.has_tag("google-account")
            && anchor.has_tag("skype")
            && anchor.has_tag("has-maps-reviews")
    );
    assert_eq!(
        ev.attributes.get("skype_name").map(String::as_str),
        Some("Jane Q Doe")
    );
    assert_eq!(
        ev.attributes.get("skype_handle").map(String::as_str),
        Some("jane.doe")
    );

    // Two DISTINCT Person leads (Google "Jane Doe" + Skype "Jane Q Doe").
    let people: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Person).collect();
    assert_eq!(people.len(), 2);
    assert!(
        people
            .iter()
            .any(|p| p.value == "Jane Doe" && p.has_tag("google"))
    );
    assert!(
        people
            .iter()
            .any(|p| p.value == "Jane Q Doe" && p.has_tag("platform:skype"))
    );

    // Skype handle → Username.
    let users: Vec<&Entity> = es
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].value, "jane.doe");

    // Addresses: the Skype location + the reviewed place (with rating + text).
    let addrs: Vec<&Entity> = es
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    let skype_loc = addrs.iter().find(|a| a.value == "Sydney, AU").unwrap();
    assert!(skype_loc.has_tag("skype"));
    let place = addrs
        .iter()
        .find(|a| a.value == "Sydney Opera House")
        .unwrap();
    assert!(place.has_tag("google-maps"));
    let pev = &place.evidence[0];
    assert_eq!(
        pev.attributes.get("rating").map(String::as_str),
        Some("5.0")
    );
    assert_eq!(
        pev.attributes.get("review_text").map(String::as_str),
        Some("Stunning, came with family.")
    );
    assert_eq!(
        pev.attributes.get("review_date").map(String::as_str),
        Some("2024-01-15")
    );
}

#[test]
fn identical_google_and_skype_names_yield_one_person() {
    let es = build(r#"{"name":"Sam Vimes","skype":{"name":"Sam Vimes"}}"#);
    assert_eq!(
        es.iter().filter(|e| e.kind == EntityKind::Person).count(),
        1
    );
}

#[test]
fn handle_like_names_are_not_persons() {
    // "janedoe" (no space) and a short skype name must not become Person.
    let es = build(r#"{"name":"janedoe","skype":{"name":"jd"}}"#);
    assert!(es.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn review_text_is_truncated_at_a_char_boundary() {
    let long = "x".repeat(400);
    let es = build(&format!(
        r#"{{"maps_reviews":[{{"place_name":"Café ☕","text":"{long}"}}]}}"#
    ));
    let place = es.iter().find(|e| e.value == "Café ☕").unwrap();
    let text = place.evidence[0].attributes.get("review_text").unwrap();
    assert_eq!(text.chars().count(), REVIEW_TEXT_CAP);
}

#[test]
fn empty_response_yields_only_the_anchor() {
    let es = build("{}");
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Email);
}

// ── Offline API emulation ────────────────────────────────────────────
//
// The live endpoint (`POST https://api.epieos.com/api/v1/email`) is key-gated
// and would send the target email to a third party. This stands in a
// hand-crafted body — the exact JSON shape the API returns — and drives it
// through the *real* module logic (`build_entities`, the same mapper `process`
// runs after `json_decode`). No key, no network, no PII leaves the host: a
// faithful emulation of a lookup.
//
// Run it as a live demo:
//   cargo test --lib epieos::tests::emulated_lookup -- --nocapture
//
// Every value below is SYNTHETIC. The resolved identity is seeded on the
// authorised self-test name (CLAUDE.md); the lookup uses the reserved
// `example.com` documentation domain so it can never be mistaken for real PII.
const EMULATED_API_RESPONSE: &str = r#"{
    "google_id": "104729183746520183927",
    "name": "Haigen Bamford",
    "profile_picture": "https://lh3.googleusercontent.com/a/emulated-avatar",
    "calendar": { "name": "Haigen Bamford" },
    "maps_reviews": [
        {
            "place_name": "Queensland Art Gallery, Brisbane QLD",
            "rating": 5.0,
            "text": "World-class GOMA exhibitions - spent the whole afternoon here.",
            "date": "2024-09-12"
        },
        {
            "place_name": "South Bank Parklands, Brisbane QLD",
            "rating": 4.0,
            "text": "Great riverside walk on the weekend.",
            "date": "2024-07-03"
        }
    ],
    "skype": {
        "handle": "haigen.bamford",
        "name": "Haigen Bamford",
        "city": "Brisbane",
        "country": "AU"
    }
}"#;

/// Render the resolved entity graph as a compact dossier (visible under
/// `--nocapture`). Pure formatting — ASCII only (Termux terminal-safe).
fn render_dossier(email: &str, entities: &[Entity]) {
    println!("\n=== EPIEOS - EMULATED EMAIL->IDENTITY RESOLUTION (offline) ===");
    println!("  Lookup:   email = {email}");
    println!("  Source:   epieos (emulated API response; no network, no key)");
    println!("  Entities: {}\n", entities.len());
    for e in entities {
        println!(
            "  [{}] {}  (conf={:.2} c_eff={:.2} class={})",
            e.kind,
            e.value,
            e.confidence,
            e.c_effective(),
            e.classify()
        );
        if !e.tags.is_empty() {
            println!("      tags: {}", e.tags.join(", "));
        }
        for ev in &e.evidence {
            println!("      - {} :: {}", ev.source, ev.summary);
            for (k, v) in &ev.attributes {
                println!("          {k} = {v}");
            }
        }
    }
    println!();
}

// ── Wire-level process() emulation — full engine code path ──────────────────
//
// A genuine `Epieos.process()` invocation runs against a local TCP server that
// returns the exact Epieos API wire format. The complete production path
// executes: key gate → POST via ctx.http → keyed_ok_or_404 → json_decode →
// build_entities. No mocks, no stubbed return values — the entities produced
// are the real HSE engine output.
//
// The endpoint override (`HUNTSMAN_EPIEOS_URL`) injects the local server
// address; `reqwest::Client::new()` (no SSRF guard) can reach 127.0.0.1.
// The key value is a dummy — it only needs to be non-None to pass the gate;
// keyed_ok_or_404 passes any 200 response through regardless.
//
// Run to view the printed dossier:
//   cargo test epieos::tests::process_against_emulated_server -- --nocapture
#[tokio::test]
async fn process_against_emulated_server_yields_genuine_entity_graph() {
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://127.0.0.1:{port}");

    // Serve one request: drain the incoming HTTP request (so reqwest's send
    // completes its write), then return a valid 200 JSON response and close.
    // Content-Length tells reqwest the body is complete without waiting for EOF.
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req_buf = vec![0u8; 8192];
        let _ = sock.read(&mut req_buf).await;
        let body = EMULATED_API_RESPONSE.as_bytes();
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        sock.write_all(headers.as_bytes()).await.unwrap();
        sock.write_all(body).await.unwrap();
    });

    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let mut keys = HashMap::new();
    keys.insert("HUNTSMAN_EPIEOS_KEY".into(), "emulated-key".into());
    keys.insert("HUNTSMAN_EPIEOS_URL".into(), endpoint);

    let ctx = crate::core::module::ModuleContext {
        scan_id: "emulated-scan".into(),
        bus,
        http: reqwest::Client::new(),
        keys,
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };

    let target = Target::new(TargetKind::Email, "haigen.bamford@example.com");
    let result = Epieos
        .process(&target, &ctx)
        .await
        .expect("process must succeed against emulated server");
    server.await.unwrap();

    render_dossier("haigen.bamford@example.com", &result.entities);

    let anchor = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("email anchor");
    assert!(anchor.has_tag("google-account"));
    assert!(anchor.has_tag("skype"));
    assert!(anchor.has_tag("has-maps-reviews"));

    // Google and Skype names agree → one deduplicated Person lead.
    let people: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    assert_eq!(people.len(), 1);
    assert_eq!(people[0].value, "Haigen Bamford");

    // Skype handle → Username.
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "haigen.bamford")
    );

    // GEOINT: Skype city + QLD reviewed places are all Address entities.
    let addrs: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    assert!(addrs.iter().any(|a| a.value == "Brisbane, AU"));
    let qag = addrs
        .iter()
        .find(|a| a.value.starts_with("Queensland Art Gallery"))
        .expect("reviewed place becomes an Address entity");
    assert!(qag.has_tag("geoint"));
    assert!(qag.has_tag("country:AU"));
    assert!(qag.has_tag("au-state:QLD"));
}

/// End-to-end emulation: an Epieos API response we synthesise locally is
/// resolved into the full identity graph by the genuine module mapper, with no
/// live call. Prints a dossier (under `--nocapture`) and asserts the extraction.
#[test]
fn emulated_lookup_resolves_full_identity_offline() {
    let email = "haigen.bamford@example.com";
    let target = Target::new(TargetKind::Email, email);

    // Mirror `process`: decode the (emulated) body, then run the real mapper.
    let body: EpieosResp =
        serde_json::from_str(EMULATED_API_RESPONSE).expect("emulated response parses");
    let entities = build_entities(&target, &body, "emulated-scan");

    render_dossier(email, &entities);

    // The enriched Email anchor carries every cross-source signal.
    let anchor = entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("email anchor");
    assert_eq!(anchor.value, email);
    assert!(anchor.has_tag("google-account"));
    assert!(anchor.has_tag("skype"));
    assert!(anchor.has_tag("has-maps-reviews"));

    // Google and Skype names agree here → one deduplicated Person lead.
    let people: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    assert_eq!(people.len(), 1);
    assert_eq!(people[0].value, "Haigen Bamford");

    // Skype handle → Username.
    assert!(
        entities
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "haigen.bamford")
    );

    // GEOINT: Skype location + both reviewed places become Address leads; the
    // QLD places pick up the Australian state/country tags.
    let addrs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    assert!(addrs.iter().any(|a| a.value == "Brisbane, AU"));
    let qag = addrs
        .iter()
        .find(|a| a.value.starts_with("Queensland Art Gallery"))
        .expect("reviewed place becomes an Address");
    assert!(qag.has_tag("geoint"));
    assert!(qag.has_tag("country:AU"));
    assert!(qag.has_tag("au-state:QLD"));
}
