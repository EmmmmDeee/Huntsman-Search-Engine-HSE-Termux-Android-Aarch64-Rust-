use super::*;

// ── token primitives ────────────────────────────────────────────────────────

#[test]
fn generated_token_is_256_bits_of_hex_and_never_repeats() {
    let a = generate_token().expect("/dev/urandom must be readable");
    let b = generate_token().expect("/dev/urandom must be readable");
    assert_eq!(a.len(), TOKEN_BYTES * 2, "32 bytes render as 64 hex chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b, "two mints must not collide");
}

#[test]
fn matches_accepts_the_token_and_rejects_near_misses() {
    let t = AuthToken::new("s3cret-token".to_string());
    assert!(t.matches("s3cret-token"));
    assert!(!t.matches("s3cret-toke"), "prefix must not pass");
    assert!(!t.matches("s3cret-tokenx"), "extension must not pass");
    assert!(!t.matches("S3cret-token"), "comparison is case-sensitive");
    assert!(!t.matches(""), "empty must not pass");
}

#[test]
fn ct_eq_is_length_checked_and_value_correct() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    assert!(ct_eq(b"", b""));
}

#[test]
fn debug_never_prints_the_secret() {
    let t = AuthToken::new("super-secret-value".to_string());
    let rendered = format!("{t:?}");
    assert!(
        !rendered.contains("super-secret-value"),
        "Debug leaked the token: {rendered}"
    );
}

// ── posture resolution ──────────────────────────────────────────────────────

#[test]
fn loopback_bind_requires_no_token() {
    for bind in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.1"] {
        let got = resolve(bind, None, false).expect("loopback resolve must succeed");
        assert!(got.is_none(), "{bind} must not demand a token");
    }
}

#[test]
fn non_loopback_bind_mints_a_token_when_none_supplied() {
    let got = resolve("0.0.0.0:8080", None, false)
        .expect("resolve must succeed")
        .expect("a non-loopback bind must demand a token");
    assert_eq!(got.reveal().len(), TOKEN_BYTES * 2);
}

#[test]
fn non_loopback_bind_honours_a_supplied_token() {
    let got = resolve("192.168.1.5:8080", Some("operator-chosen".to_string()), false)
        .expect("resolve must succeed")
        .expect("must demand a token");
    assert!(got.matches("operator-chosen"));
}

#[test]
fn an_empty_supplied_token_is_an_error_not_an_open_door() {
    // The dangerous silent-success case: `HSE_AUTH_TOKEN=` in a shell profile
    // must not resolve to "authentication enabled with the empty token".
    for empty in ["", "   ", "\t"] {
        let err = resolve("0.0.0.0:8080", Some(empty.to_string()), false);
        assert!(err.is_err(), "{empty:?} must be rejected outright");
    }
}

#[test]
fn explicit_opt_out_disables_enforcement_on_a_non_loopback_bind() {
    let got = resolve("0.0.0.0:8080", None, true).expect("resolve must succeed");
    assert!(got.is_none(), "--allow-unauthenticated must disable the gate");
}

#[test]
fn a_loopback_bind_still_honours_a_deliberately_supplied_token() {
    let got = resolve("127.0.0.1:8080", Some("belt-and-braces".to_string()), false)
        .expect("resolve must succeed")
        .expect("an explicit token must be honoured even on loopback");
    assert!(got.matches("belt-and-braces"));
}

// ── credential parsing ──────────────────────────────────────────────────────

#[test]
fn cookie_value_finds_the_token_among_siblings() {
    assert_eq!(
        cookie_value("theme=dark; hse_auth=abc123; other=1").as_deref(),
        Some("abc123")
    );
    assert_eq!(cookie_value("hse_auth=solo").as_deref(), Some("solo"));
    assert_eq!(cookie_value("theme=dark").as_deref(), None);
    // A cookie whose NAME merely contains ours must not match.
    assert_eq!(cookie_value("not_hse_auth=nope").as_deref(), None);
}

#[test]
fn query_token_extracts_t_and_preserves_the_rest() {
    let (t, rest) = query_token("t=abc").expect("t must be found");
    assert_eq!(t, "abc");
    assert_eq!(rest, "", "a lone t leaves an empty remainder");

    let (t, rest) = query_token("tab=1&t=abc&scan=42").expect("t must be found");
    assert_eq!(t, "abc");
    assert_eq!(
        rest, "tab=1&scan=42",
        "other params survive the bootstrap redirect"
    );

    // `tab` starts with `t` but is a different key — must not be mistaken for it.
    assert!(query_token("tab=1&scan=42").is_none());
}

// ── middleware behaviour ────────────────────────────────────────────────────

use axum::{Router, body::Body, routing::get};
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef";

/// A one-route app behind the auth middleware, as `router()` installs it.
fn guarded() -> Router {
    let token = Arc::new(AuthToken::new(TOKEN.to_string()));
    Router::new()
        .route("/api/v1/scans", get(|| async { "scan list" }))
        .route("/", get(|| async { "spa" }))
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                enforce_auth(Arc::clone(&token), req, next)
            },
        ))
}

async fn send(req: axum::http::Request<Body>) -> axum::http::Response<Body> {
    guarded().oneshot(req).await.expect("router must respond")
}

#[tokio::test]
async fn no_credential_is_rejected() {
    let resp = send(
        axum::http::Request::builder()
            .uri("/api/v1/scans")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer"),
        "the 401 must be self-describing"
    );
}

#[tokio::test]
async fn a_wrong_token_is_rejected() {
    let resp = send(
        axum::http::Request::builder()
            .uri("/api/v1/scans")
            .header(header::AUTHORIZATION, "Bearer wrong-token")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_header_is_accepted() {
    let resp = send(
        axum::http::Request::builder()
            .uri("/api/v1/scans")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn x_hse_auth_header_is_accepted() {
    let resp = send(
        axum::http::Request::builder()
            .uri("/api/v1/scans")
            .header("x-hse-auth", TOKEN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn cookie_is_accepted_without_a_redirect() {
    let resp = send(
        axum::http::Request::builder()
            .uri("/api/v1/scans")
            .header(header::COOKIE, format!("{COOKIE}={TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an established session must not re-bootstrap"
    );
}

#[tokio::test]
async fn query_bootstrap_redirects_and_sets_an_httponly_cookie() {
    let resp = send(
        axum::http::Request::builder()
            .uri(format!("/?{QUERY_KEY}={TOKEN}&tab=graph"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("a redirect must carry Location");
    assert_eq!(loc, "/?tab=graph", "the token must leave the address bar");
    assert!(
        !loc.contains(TOKEN),
        "the redirect target must not echo the token"
    );

    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("the bootstrap must pin a cookie");
    assert!(cookie.contains(&format!("{COOKIE}={TOKEN}")));
    assert!(cookie.contains("HttpOnly"), "script must not read it");
    assert!(
        cookie.contains("SameSite=Strict"),
        "a cross-site page must not ride it"
    );
}

#[tokio::test]
async fn a_wrong_query_token_does_not_set_a_cookie() {
    let resp = send(
        axum::http::Request::builder()
            .uri(format!("/?{QUERY_KEY}=not-the-token"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "a failed bootstrap must never mint a session"
    );
}

#[tokio::test]
async fn options_preflight_passes_without_a_credential() {
    // A CORS preflight carries no credentials and has no side effect; 401-ing it
    // would surface in the browser as an opaque CORS error rather than the 401
    // that tells the operator what is wrong.
    let app = guarded();
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::OPTIONS)
                .uri("/api/v1/scans")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router must respond");
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_401_body_never_reflects_what_the_client_sent() {
    let resp = send(
        axum::http::Request::builder()
            .uri("/api/v1/scans")
            .header(header::AUTHORIZATION, "Bearer leaked-guess-value")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body must read");
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("leaked-guess-value"),
        "the rejection must not echo the presented credential: {body}"
    );
}
