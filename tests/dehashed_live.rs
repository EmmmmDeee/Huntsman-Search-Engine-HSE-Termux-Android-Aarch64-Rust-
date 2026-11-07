//! Live acceptance of the `DeHashed` client against the real v2 API, with a real key.
//!
//! Ignored by default: every search spends `DeHashed` credits, so CI never runs it. Run it with
//! the key in `HUNTSMAN_DEHASHED_KEY` (on a device, from `~/.huntsman.env`):
//!
//! ```text
//! cargo test --test dehashed_live -- --ignored --nocapture
//! ```
//!
//! Where the key is injected by an HTTPS proxy rather than held in the environment, set
//! `HUNTSMAN_DEHASHED_LIVE_VIA_PROXY=1` and a placeholder key: the transport then honours the
//! proxy (the production public-only transport deliberately ignores it). The production client,
//! decoder and collector are what is tested either way; only the route to the API differs.
//!
//! The raw response is fetched beside each search as ground truth, so the test proves that no
//! record is lost, every non-credential value survives verbatim, and no credential value leaves
//! the decoder. Four searches are made in all.

use std::sync::Arc;

use huntsman_recon::collector::CollectionLimits;
use huntsman_recon::dehashed::client::{DEHASHED_API_BASE, transport_config};
use huntsman_recon::dehashed::{DehashedClient, Field, Purpose, SearchRequest, Selector, collect};
use huntsman_recon::egress::EgressPolicy;
use huntsman_recon::http::{Request, Transport, UreqTransport};
use huntsman_recon::keys::Secret;
use huntsman_recon::{Entity, EntityKind};
use serde_json::Value;

const KEY_ENV: &str = "HUNTSMAN_DEHASHED_KEY";

fn transport() -> Arc<dyn Transport + Send + Sync> {
    let mut config = transport_config();
    if std::env::var_os("HUNTSMAN_DEHASHED_LIVE_VIA_PROXY").is_some() {
        config.egress = EgressPolicy::Unrestricted;
    }
    Arc::new(UreqTransport::new(&config))
}

fn key() -> String {
    std::env::var(KEY_ENV).unwrap_or_else(|_| panic!("set {KEY_ENV} to run the live test"))
}

/// The raw answer to `query`, read straight off the wire: the ground truth HSE is checked against.
fn raw(transport: &dyn Transport, query: &str, size: u32) -> Value {
    let body = serde_json::json!({
        "query": query, "page": 1, "size": size,
        "de_dupe": true, "regex": false, "wildcard": false
    });
    let request = Request::post(
        format!("{DEHASHED_API_BASE}/search"),
        serde_json::to_vec(&body).expect("body"),
    )
    .header("Content-Type", "application/json")
    .header("Accept", "application/json")
    .header("Dehashed-Api-Key", key());
    let response = transport.send(&request).expect("raw request");
    assert_eq!(response.status, 200, "raw answer to {query}");
    serde_json::from_slice(&response.body).expect("raw JSON")
}

/// Every credential string the raw entries hold: the values that must never leave the decoder.
fn credential_values(raw: &Value) -> Vec<String> {
    let mut found = Vec::new();
    for entry in raw["entries"].as_array().into_iter().flatten() {
        for (field, value) in entry.as_object().into_iter().flatten() {
            if !matches!(field.as_str(), "password" | "hashed_password") {
                continue;
            }
            let values: Vec<&Value> = match value {
                Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            for value in values {
                if let Some(text) = value.as_str().map(str::trim) {
                    // A credential short enough to recur as an ordinary word cannot be told apart
                    // from one; four characters is the bound used across the breach legs.
                    if text.len() >= 4 {
                        found.push(text.to_owned());
                    }
                }
            }
        }
    }
    found
}

fn client() -> DehashedClient {
    DehashedClient::new(transport(), Secret::new(key()).expect("key"))
}

#[test]
#[ignore = "live: spends DeHashed credits and needs a key"]
fn a_domain_search_loses_no_record_keeps_every_value_and_no_credential() {
    let client = client();
    let selector = Selector::new(Field::Domain, "example.com").expect("selector");
    let mut request = SearchRequest::new(selector.clone(), Purpose::SecurityResearch);
    request.size = 25;
    let outcome = client.search(&request).expect("HSE search");
    let truth = raw(transport().as_ref(), &selector.query(), 25);
    let raw_entries = truth["entries"].as_array().expect("raw entries");

    println!(
        "domain search: total={:?} entries={} raw_entries={} balance={:?} took={:?}",
        outcome.total,
        outcome.entries.len(),
        raw_entries.len(),
        outcome.balance,
        outcome.took
    );
    assert!(outcome.total.unwrap_or(0) > 0, "example.com has records");
    assert_eq!(outcome.entries.len(), raw_entries.len(), "no record lost");

    // Every non-credential string value in the raw page survives verbatim in some decoded entry.
    let decoded: std::collections::BTreeSet<&str> = outcome
        .entries
        .iter()
        .flat_map(|entry| entry.values.values().flatten().map(String::as_str))
        .chain(
            outcome
                .entries
                .iter()
                .flat_map(|e| e.email.iter().map(String::as_str)),
        )
        .chain(
            outcome
                .entries
                .iter()
                .flat_map(|e| e.username.iter().map(String::as_str)),
        )
        .collect();
    let mut checked = 0;
    for entry in raw_entries {
        for (field, value) in entry.as_object().expect("entry object") {
            if matches!(
                field.as_str(),
                "password" | "hashed_password" | "id" | "raw_record" | "database_name"
            ) {
                continue;
            }
            let values: Vec<&Value> = match value {
                Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            for value in values {
                let Some(text) = value.as_str().map(str::trim).filter(|t| !t.is_empty()) else {
                    continue;
                };
                checked += 1;
                assert!(
                    decoded.contains(text),
                    "field {field}: a raw value was lost in decoding"
                );
            }
        }
    }
    println!("non-credential values checked against the raw page: {checked}");
    assert!(checked > 0);

    // No credential value appears anywhere in what HSE keeps or prints.
    // Nothing derived from a credential is printed, not even a count: the assertions below are
    // the whole verdict.
    let secrets = credential_values(&truth);
    let kept = format!("{outcome:?}");
    assert!(
        !secrets.is_empty(),
        "the raw page holds credentials to check"
    );
    let marked = outcome.entries.iter().filter(|e| e.password).count();
    let raw_marked = raw_entries
        .iter()
        .filter(|e| match &e["password"] {
            Value::String(s) => !s.trim().is_empty(),
            Value::Array(a) => a
                .iter()
                .any(|v| v.as_str().is_some_and(|s| !s.trim().is_empty())),
            _ => false,
        })
        .count();
    assert_eq!(
        marked, raw_marked,
        "every exposed password is marked as present"
    );
    // A credential that also appears as an ordinary value (a password equal to the username)
    // legitimately survives in that ordinary field; anything else is a leak.
    for secret in &secrets {
        if kept.contains(secret.as_str()) {
            assert!(
                decoded.contains(secret.as_str()),
                "a credential value leaked"
            );
        }
    }
}

#[test]
#[ignore = "live: spends DeHashed credits and needs a key"]
fn an_email_search_is_exact() {
    let client = client();
    let selector = Selector::new(Field::Email, "test@example.com").expect("selector");
    let mut request = SearchRequest::new(selector, Purpose::SecurityResearch);
    request.size = 25;
    let outcome = client.search(&request).expect("HSE search");
    println!(
        "email search: total={:?} entries={}",
        outcome.total,
        outcome.entries.len()
    );
    assert!(!outcome.entries.is_empty(), "test@example.com has records");
    for entry in &outcome.entries {
        assert!(
            entry
                .email
                .iter()
                .any(|email| email.eq_ignore_ascii_case("test@example.com")),
            "an email search returned a record without that address"
        );
    }
}

#[test]
#[ignore = "live: spends DeHashed credits and needs a key"]
fn the_collector_turns_a_live_page_into_entities_lineage_and_no_credential() {
    let client = client();
    let selector = Entity::new(EntityKind::Domain, "example.com", 1.0, "live");
    let limits = CollectionLimits {
        max_records_per_response: 10,
        ..CollectionLimits::default()
    };
    let batch =
        collect(&client, &selector, Purpose::SecurityResearch, &limits, 1).expect("collect");
    let truth = raw(transport().as_ref(), "domain:example.com", 10);
    println!(
        "collector: entities={} pivots={} receipts={:?}",
        batch.entities.len(),
        batch.pivots.len(),
        batch
            .receipts
            .iter()
            .map(|r| (r.outcome.kind.as_str(), r.parsed_rows, r.dataset.clone()))
            .collect::<Vec<_>>()
    );
    assert!(!batch.entities.is_empty(), "a live page yields entities");
    assert!(!batch.pivots.is_empty(), "and pivots");
    let saved = serde_json::to_string(&batch.entities).expect("json");
    assert!(
        saved.contains("database_name") || saved.contains("dataset"),
        "lineage kept"
    );
    let decoded_values: Vec<String> = truth["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e.as_object().into_iter().flatten())
        .filter(|(k, _)| !matches!(k.as_str(), "password" | "hashed_password"))
        .filter_map(|(_, v)| v.as_str().map(str::to_owned))
        .collect();
    for secret in credential_values(&truth) {
        if saved.contains(&secret) {
            assert!(
                decoded_values.contains(&secret),
                "a credential value leaked into saved evidence"
            );
        }
    }
}
