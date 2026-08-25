use super::*;

// ─── ct_eq / AuthToken ──────────────────────────────────────────────────────

#[test]
fn ct_eq_matches_identical_digests() {
    let d = Sha256::digest(b"correct-horse");
    assert!(ct_eq(&d, &d));
}

#[test]
fn ct_eq_rejects_a_differing_byte() {
    let a: [u8; 32] = Sha256::digest(b"correct-horse").into();
    let b: [u8; 32] = Sha256::digest(b"correct-horsE").into();
    assert!(!ct_eq(&a, &b));
}

#[test]
fn ct_eq_rejects_mismatched_length_without_panicking() {
    assert!(!ct_eq(&[1, 2, 3], &[1, 2, 3, 4]));
}

#[test]
fn token_matches_its_own_plaintext_and_rejects_a_prefix() {
    let t = AuthToken::new("abcd1234".to_string());
    assert!(t.matches("abcd1234"));
    assert!(!t.matches("abcd123")); // a correct prefix is not the token
    assert!(!t.matches("abcd12345"));
    assert!(!t.matches(""));
}

#[test]
fn debug_never_prints_the_plaintext() {
    let t = AuthToken::new("super-secret-value".to_string());
    let shown = format!("{t:?}");
    assert!(!shown.contains("super-secret-value"));
    assert_eq!(shown, "AuthToken(<redacted>)");
}

#[test]
fn generated_tokens_are_64_hex_chars_and_differ() {
    let a = generate_token().expect("urandom is readable in test env");
    let b = generate_token().expect("urandom is readable in test env");
    assert_eq!(a.len(), 64, "32 bytes hex-encoded is 64 chars: {a}");
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b, "two draws from /dev/urandom must not collide");
}

// ─── resolve() policy matrix ────────────────────────────────────────────────

#[test]
fn loopback_with_no_token_needs_no_enforcement() {
    let r = resolve("127.0.0.1:8080", None, false).expect("should succeed");
    assert!(r.is_none(), "the untouched default path stays open");
}

#[test]
fn loopback_with_a_supplied_token_is_still_honoured() {
    // Defence in depth: an operator behind a reverse proxy may want a token
    // even on loopback.
    let r = resolve("127.0.0.1:8080", Some("t".to_string()), false).expect("should succeed");
    assert!(r.is_some());
}

#[test]
fn nonloopback_with_no_token_and_no_opt_out_auto_generates() {
    let r = resolve("0.0.0.0:8080", None, false).expect("should succeed");
    assert!(
        r.is_some(),
        "a public bind must never silently end up unauthenticated"
    );
}

#[test]
fn nonloopback_with_allow_unauthenticated_stays_open() {
    let r = resolve("0.0.0.0:8080", None, true).expect("should succeed");
    assert!(r.is_none(), "the explicit opt-out must be honoured");
}

#[test]
fn nonloopback_with_an_explicit_token_uses_it() {
    let r = resolve("0.0.0.0:8080", Some("my-token".to_string()), false).expect("should succeed");
    assert!(r.expect("token present").matches("my-token"));
}

#[test]
fn nonloopback_with_a_blank_token_is_rejected_outright() {
    // An empty string is not "no token" (which would auto-generate) — it is a
    // configuration mistake, and must fail loudly rather than silently
    // becoming a token nobody can guess but everybody can send (the empty
    // string always matches presented("")... no: `presented()` never returns
    // Some("") from an absent header, but a blank --auth-token is still a
    // foot-gun worth rejecting at startup rather than at the first request).
    assert!(resolve("0.0.0.0:8080", Some("   ".to_string()), false).is_err());
}

// ─── presented() precedence + parsing helpers ───────────────────────────────

fn req_with(headers: &[(&str, &str)], uri: &str) -> axum::extract::Request {
    let mut b = axum::extract::Request::builder().uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(axum::body::Body::empty()).expect("request builds")
}

#[test]
fn presented_prefers_authorization_over_everything() {
    let req = req_with(
        &[
            ("authorization", "Bearer from-header"),
            ("x-hse-auth", "from-x-header"),
            ("cookie", "hse_auth=from-cookie"),
        ],
        "/?t=from-query",
    );
    assert_eq!(presented(&req).as_deref(), Some("from-header"));
}

#[test]
fn presented_falls_back_to_x_hse_auth_then_cookie_then_query() {
    assert_eq!(
        presented(&req_with(&[("x-hse-auth", "x")], "/?t=q")).as_deref(),
        Some("x")
    );
    assert_eq!(
        presented(&req_with(&[("cookie", "hse_auth=c")], "/?t=q")).as_deref(),
        Some("c")
    );
    assert_eq!(presented(&req_with(&[], "/?t=q")).as_deref(), Some("q"));
    assert_eq!(presented(&req_with(&[], "/")), None);
}

#[test]
fn cookie_value_extracts_from_a_multi_cookie_header() {
    assert_eq!(
        cookie_value("foo=bar; hse_auth=abc123; baz=qux").as_deref(),
        Some("abc123")
    );
    assert_eq!(cookie_value("foo=bar").as_deref(), None);
}

#[test]
fn query_token_splits_and_preserves_the_remainder() {
    let (t, rest) = query_token("a=1&t=secret&b=2").expect("t present");
    assert_eq!(t, "secret");
    // Order within `rest` need not match input order, but both survivors
    // must be present and `t` must be gone.
    assert!(rest.contains("a=1") && rest.contains("b=2") && !rest.contains('t'));
    assert!(query_token("a=1&b=2").is_none(), "no t param present");
}

// ─── enforce_auth, exercised through a real router ──────────────────────────

fn app(token: &str) -> Router {
    let t = Arc::new(AuthToken::new(token.to_string()));
    Router::new()
        .route("/api/v1/health", axum::routing::get(|| async { "ok" }))
        .route("/api/v1/scans", axum::routing::get(|| async { "secret" }))
        .route("/", axum::routing::get(|| async { "spa shell" }))
        .layer(axum::middleware::from_fn_with_state(t, enforce_auth))
}

use axum::Router;

async fn status_and_headers(
    app: Router,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap) {
    use tower::ServiceExt;
    let mut b = axum::extract::Request::builder().uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = app
        .oneshot(b.body(axum::body::Body::empty()).expect("request builds"))
        .await
        .expect("router responds");
    (resp.status(), resp.headers().clone())
}

#[tokio::test]
async fn health_is_reachable_with_no_credential() {
    let (status, _) = status_and_headers(app("tok"), "/api/v1/health", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_data_route_is_401_with_no_credential() {
    let (status, headers) = status_and_headers(app("tok"), "/api/v1/scans", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer")
    );
}

#[tokio::test]
async fn a_data_route_admits_the_correct_bearer_token() {
    let (status, _) = status_and_headers(
        app("tok"),
        "/api/v1/scans",
        &[("authorization", "Bearer tok")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_wrong_token_is_rejected() {
    let (status, _) = status_and_headers(
        app("tok"),
        "/api/v1/scans",
        &[("authorization", "Bearer wrong")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_spa_shell_is_also_protected_not_just_api() {
    // Unlike a layer scoped to /api alone, this middleware sits on the whole
    // app — the SPA root must be gated too.
    let (status, _) = status_and_headers(app("tok"), "/", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_valid_bootstrap_query_token_redirects_and_sets_an_httponly_cookie() {
    let (status, headers) =
        status_and_headers(app("tok"), "/api/v1/scans?t=tok&keep=me", &[]).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header present");
    assert!(location.starts_with("/api/v1/scans"));
    assert!(
        location.contains("keep=me"),
        "other params survive: {location}"
    );
    assert!(
        !location.contains("t=tok"),
        "the token itself is stripped: {location}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie present");
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Strict"), "{set_cookie}");
    assert!(set_cookie.contains("hse_auth=tok"), "{set_cookie}");
}

#[tokio::test]
async fn an_invalid_bootstrap_query_token_is_rejected_not_redirected() {
    let (status, headers) = status_and_headers(app("tok"), "/api/v1/scans?t=wrong", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn the_cookie_alone_authenticates_a_later_request() {
    let (status, _) =
        status_and_headers(app("tok"), "/api/v1/scans", &[("cookie", "hse_auth=tok")]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn options_passes_through_unauthenticated_for_cors_preflight() {
    use tower::ServiceExt;
    let resp = app("tok")
        .oneshot(
            axum::extract::Request::builder()
                .method(axum::http::Method::OPTIONS)
                .uri("/api/v1/scans")
                .body(axum::body::Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    // No route is registered for OPTIONS on this test app, so the assertion
    // that matters is that it is NOT 401 — auth did not block it.
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}
