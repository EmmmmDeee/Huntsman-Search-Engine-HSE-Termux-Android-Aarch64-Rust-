use super::config::enabled_from;
use super::format::{build_body, build_filename, format_utc, slug};
use super::io::write_file;
use super::query::records_filtered_dir;
use super::url::describe_url;

use serde_json::Value;

#[test]
fn disable_switch_is_opt_out_only() {
    assert!(enabled_from(None), "default must be ON");
    assert!(enabled_from(Some("1")));
    assert!(enabled_from(Some("anything")));
    assert!(!enabled_from(Some("0")));
    assert!(!enabled_from(Some("off")));
    assert!(!enabled_from(Some("False")));
    assert!(!enabled_from(Some("  off  ")));
}

#[test]
fn slug_is_human_legible_and_filesystem_safe() {
    assert_eq!(
        slug("jordanavery@gmail.com", 80),
        "jordanavery_at_gmail.com"
    );
    assert_eq!(slug("Jordan Avery", 80), "Jordan_Avery");
    assert_eq!(slug("javery88", 80), "javery88");
    // No path traversal, no slashes survive.
    assert_eq!(slug("../../etc/passwd", 80), "etc_passwd");
    // Blank / separator-only input never yields an empty component.
    assert_eq!(slug("", 80), "unknown");
    assert_eq!(slug("///", 80), "unknown");
    // Length is capped.
    assert_eq!(slug(&"a".repeat(200), 10).len(), 10);
}

#[test]
fn format_utc_matches_known_epoch_instants() {
    assert_eq!(format_utc(0), "19700101T000000Z");
    // 2026-06-06T06:14:09Z (the live test instant) — exact round value.
    assert_eq!(format_utc(1_780_726_449), "20260606T061409Z");
}

#[test]
fn build_filename_is_blatantly_self_describing() {
    let name = build_filename(
        "see_know",
        "stealer",
        "jordanavery@gmail.com",
        1_780_726_449,
        7,
    );
    assert_eq!(
        name,
        "see_know__stealer__jordanavery_at_gmail.com__20260606T061409Z__0007.json"
    );
    // A human (and the OS sort) can read who/what/when straight off the name.
    assert!(name.starts_with("see_know__stealer__"));
    assert!(name.contains("jordanavery_at_gmail.com"));
    assert!(name.ends_with("__0007.json"));
}

#[test]
fn build_body_keeps_paid_secret_in_full_with_meta_header() {
    let body = build_body(
        "see_know",
        "stealer",
        "seed@x.com",
        1_780_726_449,
        r#"{"results":[{"password":"PLAINTEXT-kept"}]}"#,
    );
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["_meta"]["provider"], "see_know");
    assert_eq!(v["_meta"]["endpoint"], "stealer");
    assert_eq!(v["_meta"]["query"], "seed@x.com");
    assert_eq!(v["_meta"]["archived_at_utc"], "20260606T061409Z");
    // The cleartext paid secret is retained, in full, structurally.
    assert_eq!(v["raw"]["results"][0]["password"], "PLAINTEXT-kept");
}

#[test]
fn build_body_falls_back_to_verbatim_string_for_non_json() {
    let body = build_body(
        "oathnet",
        "breach-search",
        "x",
        0,
        "503 Service Unavailable",
    );
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["raw"], "503 Service Unavailable");
}

#[test]
fn describe_url_derives_endpoint_and_query() {
    // Query param → query value (URL-decoded); path tail → endpoint.
    assert_eq!(
        describe_url("https://haveibeenpwned.com/api/v3/breachedaccount/a%40b.com"),
        ("breachedaccount".to_string(), "a@b.com".to_string())
    );
    assert_eq!(
        describe_url("https://crt.sh/?q=example.com&output=json"),
        ("crt.sh".to_string(), "example.com".to_string())
    );
    // No path, no query → host is both.
    assert_eq!(
        describe_url("https://api.example.org"),
        ("api.example.org".to_string(), "api.example.org".to_string())
    );
    // Credential-named params are SKIPPED so our own auth key never lands in
    // a filename / `_meta.query`; the real lookup term is used instead.
    assert_eq!(
        describe_url("https://api.example.org/v1/lookup?api_key=SECRET123456&q=target%40x.com"),
        ("lookup".to_string(), "target@x.com".to_string())
    );
    // When EVERY query param is a credential, fall back to the path/host —
    // never the secret.
    let (_, q) = describe_url("https://api.example.org/v1/ping?token=DEADBEEFSECRET");
    assert_ne!(
        q, "DEADBEEFSECRET",
        "an auth token must never become the query label"
    );
}

#[test]
fn describe_url_redacts_a_path_embedded_own_key() {
    // IPQS/ABR-style: the operator's OWN key sits in the URL PATH, not the query.
    // It must NEVER become the endpoint/query label (which lands in the archive
    // filename, `_meta`, and every dossier / one-click debug bundle). Regression
    // for the path-embedded-key leak the query-param CRED_PARAMS skip missed.
    let own = crate::util::keys::own_api_keys();
    let Some(key) = own.iter().next().cloned() else {
        return; // no embedded/own keys in this build → nothing to assert
    };
    let (endpoint, value) = describe_url(&format!(
        "https://www.ipqualityscore.com/api/json/ip/{key}/1.1.1.1"
    ));
    assert_ne!(
        endpoint, key,
        "a path-embedded API key must not become the endpoint label"
    );
    assert!(
        !endpoint.contains(&key),
        "endpoint must not contain the key"
    );
    assert_eq!(
        (endpoint.as_str(), value.as_str()),
        ("ip", "1.1.1.1"),
        "the key segment is dropped; endpoint/value are the real ones around it"
    );
}

#[test]
fn records_filtered_dir_recovers_full_responses_and_filters_by_time() {
    // Exercises the shared `records_filtered_dir` core directly (its window
    // filter, optional query-set filter, and parse) — the same core
    // `records_for_queries` builds on — rather than through a dead pub wrapper.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("hse_win_{}_{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Two in-window responses (one structured, one thin/no-entity) + one out.
    write_file(
        &dir.join(build_filename(
            "see-know",
            "search-email",
            "v@x.com",
            1000,
            1,
        )),
        &build_body(
            "see-know",
            "search-email",
            "v@x.com",
            1000,
            r#"{"results":[{"source":"INF0SEC Leaks"}]}"#,
        ),
    )
    .unwrap();
    write_file(
        &dir.join(build_filename(
            "oathnet",
            "breach-search",
            "v@x.com",
            1005,
            2,
        )),
        &build_body(
            "oathnet",
            "breach-search",
            "v@x.com",
            1005,
            r#"{"data":{"items":[{"password":"PLAINTEXT"}]}}"#,
        ),
    )
    .unwrap();
    write_file(
        &dir.join(build_filename("see-know", "search-email", "old", 50, 3)),
        &build_body("see-know", "search-email", "old", 50, r#"{"x":1}"#),
    )
    .unwrap();

    let got = records_filtered_dir(&dir, 900, 1100, None);
    assert_eq!(got.len(), 2, "only the two in-window responses");
    // Chronological order, provenance recovered, raw body intact verbatim.
    assert_eq!(got[0].provider, "see-know");
    assert_eq!(got[0].query, "v@x.com");
    assert_eq!(got[0].raw["results"][0]["source"], "INF0SEC Leaks");
    assert_eq!(got[1].raw["data"]["items"][0]["password"], "PLAINTEXT");
    // The out-of-window record is excluded.
    assert!(!got.iter().any(|r| r.query == "old"));

    // Query-set filter: same window, but restrict to a different value —
    // both in-window responses are for "v@x.com", so an unrelated query set
    // excludes them (this is what stops a neighbouring scan bleeding in).
    let mut other: std::collections::HashSet<String> = std::collections::HashSet::new();
    other.insert("someone-else@x.com".to_string());
    assert!(records_filtered_dir(&dir, 900, 1100, Some(&other)).is_empty());
    // Matching query-set keeps them.
    let mut mine: std::collections::HashSet<String> = std::collections::HashSet::new();
    mine.insert("v@x.com".to_string());
    assert_eq!(records_filtered_dir(&dir, 900, 1100, Some(&mine)).len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `FullName` seed (e.g. "Brett Lawnton") is archived under its raw,
/// case-preserving value — `slug` deliberately keeps case for a legible
/// filename (`slug_is_human_legible_and_filesystem_safe` above pins
/// `slug("Jordan Avery", 80) == "Jordan_Avery"`) — but the dossier renderer
/// builds its query set from `scan.target.value.to_lowercase()`
/// (`cli::export::renderers`). Before this fix, the cheap filename
/// pre-filter compared the two without normalising case, so it silently
/// dropped every archived file for any target with an uppercase letter —
/// i.e. virtually every Person/FullName scan — before the correct,
/// already-case-insensitive `_meta.query` check two steps later was ever
/// reached. This is what made a real "Brett Lawnton" scan's dossier report
/// "RAW SOURCE RECORDS (0 responses)" despite the archive holding real,
/// in-window, on-topic data.
#[test]
fn records_for_a_mixed_case_query_are_not_dropped_by_the_filename_prefilter() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("hse_case_{}_{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_file(
        &dir.join(build_filename(
            "oathnet",
            "breach-search",
            "Brett Lawnton",
            1000,
            1,
        )),
        &build_body(
            "oathnet",
            "breach-search",
            "Brett Lawnton",
            1000,
            r#"{"data":{"items":[{"email":"brett.lawnton@gmail.com"}]}}"#,
        ),
    )
    .unwrap();

    // Mirrors renderers.rs's `scan.target.value.to_lowercase()` exactly.
    let mut queries: std::collections::HashSet<String> = std::collections::HashSet::new();
    queries.insert("Brett Lawnton".to_lowercase());

    let got = records_filtered_dir(&dir, 900, 1100, Some(&queries));
    assert_eq!(
        got.len(),
        1,
        "an archived file for a mixed-case query must still be found when \
         the caller's query set is lower-cased"
    );
    assert_eq!(got[0].query, "Brett Lawnton");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn records_filtered_dir_matches_query_set_case_insensitively() {
    // Regression: the filename pre-filter compared the archived query slug
    // case-sensitively while the authoritative `_meta.query` check is
    // case-insensitive (`to_lowercase`). `slug()` preserves case, so a mixed-case
    // query (a name/username like `JaneSmith`) was skipped before its file was even
    // opened and silently dropped from the dossier — though the authoritative
    // check would have kept it.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("hse_case_{}_{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    write_file(
        &dir.join(build_filename("see-know", "search", "JaneSmith", 1000, 1)),
        &build_body("see-know", "search", "JaneSmith", 1000, r#"{"hit":true}"#),
    )
    .unwrap();
    // The caller passes the lower-cased query set (as the authoritative check
    // itself requires); the mixed-case archived response must still be returned.
    let mut want: std::collections::HashSet<String> = std::collections::HashSet::new();
    want.insert("janesmith".to_string());
    let got = records_filtered_dir(&dir, 900, 1100, Some(&want));
    assert_eq!(
        got.len(),
        1,
        "a mixed-case query's archived response must survive the pre-filter"
    );
    assert_eq!(got[0].query, "JaneSmith");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_file_persists_individual_named_response_on_disk() {
    // End-to-end on a temp dir (no process-env mutation): an individually
    // named file is written and reads back to the structured paid response.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("hse_raw_{}_{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let name = build_filename(
        "see_know",
        "search-email",
        "vanamill@hotmail.com",
        1_780_726_449,
        3,
    );
    let path = dir.join(&name);
    let body = build_body(
        "see_know",
        "search-email",
        "vanamill@hotmail.com",
        1_780_726_449,
        r#"{"x":1}"#,
    );
    write_file(&path, &body).expect("write succeeds");

    assert!(path.exists());
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        "see_know__search-email__vanamill_at_hotmail.com__20260606T061409Z__0003.json"
    );
    let read = std::fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&read).unwrap();
    assert_eq!(v["raw"]["x"], 1);

    let _ = std::fs::remove_dir_all(&dir);
}
