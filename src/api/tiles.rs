//! Map tiles for the Radar view — a loopback proxy with an on-disk cache
//! (REQ-RADAR-003).
//!
//! Why the server fetches tiles rather than the browser: the console's CSP is
//! `img-src 'self' data:` and stays that way — the SPA auto-loads nothing from
//! a third-party origin, and a tile server never sees the operator's browser,
//! its referer or where it is looking except through one request the server
//! chose to make. That request carries the crate's own User-Agent (what the
//! OpenStreetMap tile policy asks of an application), and every tile fetched
//! is kept under the data directory, so a map the operator has looked at once
//! is there without a network — which, on this tool's one platform, a phone
//! that may be offline when it matters, is the point.
//!
//! The same policy forbids heavy use of OSM's own servers by a distributed
//! application, so the upstream is one env var away (`HUNTSMAN_TILE_UPSTREAM`,
//! any `{z}/{x}/{y}` server), and `feature.map_tiles` is a kill-switch for
//! the outbound fetch: switched off, tiles already cached still serve and an
//! uncached one is a `403` the view draws as a blank tile — never a fetch the
//! operator did not know about.
//!
//! An upstream other than OSM usually wants a key, and a tile server takes it
//! in the URL — Thunderforest's documented template ends `?apikey={apikey}` —
//! so the configured template is a secret wherever it may carry one. The
//! route answers any client the server admits, so a failed fetch's `502` names
//! the upstream's host and the failure's cause, never the URL it asked for
//! (REQ-CRED-003).

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::StreamExt as _;
use serde_json::json;
use tracing::warn;

use super::handlers::bad_request;
use crate::api::AppState;

/// The env var naming the tile server, as a `{z}`/`{x}`/`{y}` template.
pub const TILE_UPSTREAM_ENV: &str = "HUNTSMAN_TILE_UPSTREAM";
/// The default upstream: OpenStreetMap's standard tile layer.
pub const DEFAULT_TILE_UPSTREAM: &str = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";
/// The deepest zoom the view offers; OSM's standard layer stops here too.
pub const MAX_ZOOM: u8 = 19;
/// A tile is a few tens of KiB; anything past this is not a tile.
const MAX_TILE_BYTES: usize = 2 * 1024 * 1024;
/// A week: tiles change rarely, the URL never, and the on-disk cache is the
/// real store — the browser's copy only saves the loopback round-trip.
const TILE_CACHE_CONTROL: &str = "public, max-age=604800";

/// Where tiles come from and where they are kept. Built once by `hse serve`
/// (from the env var, the data directory and the guarded HTTP client) and
/// shared through `AppState`, so a test hands the handler a stand-in upstream
/// and a scratch directory instead of reaching for a global.
#[derive(Debug, Clone)]
pub struct TileSource {
    upstream: String,
    cache_dir: PathBuf,
    client: reqwest::Client,
}

impl TileSource {
    #[must_use]
    pub fn new(upstream: impl Into<String>, cache_dir: PathBuf, client: reqwest::Client) -> Self {
        Self {
            upstream: upstream.into(),
            cache_dir,
            client,
        }
    }

    /// `hse serve`'s source: `HUNTSMAN_TILE_UPSTREAM` or the OSM default, the
    /// cache at `~/.huntsman/tiles`.
    #[must_use]
    pub fn from_env(client: reqwest::Client) -> Self {
        let upstream = std::env::var(TILE_UPSTREAM_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_TILE_UPSTREAM.to_string());
        Self::new(upstream, crate::util::paths::subdir("tiles"), client)
    }

    /// The upstream's host, for an error body — the part an operator needs to
    /// recognise, and the only part of the template ever disclosed: the
    /// template may carry the operator's key (`?apikey=…`, or in the path or
    /// userinfo), and `host_str` holds none of those. A template with no host
    /// to name is described, never echoed back (REQ-CRED-003).
    #[must_use]
    pub fn upstream_host(&self) -> String {
        reqwest::Url::parse(&self.upstream)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| format!("(no host: {TILE_UPSTREAM_ENV} is not an absolute URL)"))
    }

    /// The template with one tile's address substituted.
    #[must_use]
    pub fn upstream_url(&self, z: u8, x: u32, y: u32) -> String {
        self.upstream
            .replace("{z}", &z.to_string())
            .replace("{x}", &x.to_string())
            .replace("{y}", &y.to_string())
    }

    /// `<cache>/{z}/{x}/{y}.png` — the upstream's own layout, so a cache
    /// directory is itself a valid `{z}/{x}/{y}` tree.
    #[must_use]
    pub fn cache_path(&self, z: u8, x: u32, y: u32) -> PathBuf {
        self.cache_dir
            .join(z.to_string())
            .join(x.to_string())
            .join(format!("{y}.png"))
    }
}

/// A tile address is valid when `z` is within the zoom range the view offers
/// and `x`, `y` lie inside the `2^z × 2^z` grid. Anything else is a `400`,
/// never an upstream fetch: the proxy relays tiles, it does not relay URLs.
#[must_use]
pub fn valid_tile(z: u8, x: u32, y: u32) -> bool {
    if z > MAX_ZOOM {
        return false;
    }
    let n = 1u32 << z;
    x < n && y < n
}

/// The `{y}` segment as the view sends it (`123.png`) or bare (`123`).
fn parse_y(raw: &str) -> Option<u32> {
    raw.strip_suffix(".png").unwrap_or(raw).parse().ok()
}

fn png_response(bytes: Vec<u8>, origin: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(TILE_CACHE_CONTROL),
            ),
            // Which side answered — the probe and the tests read it, and an
            // operator wondering why a tile is stale can too.
            (
                HeaderName::from_static("x-hse-tile"),
                HeaderValue::from_static(origin),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// `GET /api/v1/tiles/{z}/{x}/{y}.png` — one map tile, from the cache when
/// it is there, else from the upstream (and into the cache), else a `502`
/// that says which upstream. A cached tile is served before the kill-switch
/// is consulted: that switch is about the outbound fetch, not the operator's
/// own cache.
pub async fn tile(
    State(s): State<Arc<AppState>>,
    Path((z, x, y)): Path<(u8, u32, String)>,
) -> Response {
    let Some(y) = parse_y(&y) else {
        return bad_request("tile y must be an integer, optionally with .png");
    };
    if !valid_tile(z, x, y) {
        return bad_request(format!(
            "tile out of range: z must be 0..={MAX_ZOOM} and x, y below 2^z"
        ));
    }
    let src = Arc::clone(&s.tiles);
    let path = src.cache_path(z, x, y);
    if let Ok(bytes) = tokio::fs::read(&path).await {
        return png_response(bytes, "cache");
    }
    if !crate::util::settings::map_tiles_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "map tiles switched off",
                "detail": "the tile fetch has been switched off; tiles already cached still serve",
                "enable": "re-arm it: set the feature.map_tiles toggle on (CLI: hse config feature.map_tiles on)",
            })),
        )
            .into_response();
    }
    match fetch_upstream(&src, z, x, y).await {
        Ok(bytes) => {
            // Best-effort, off the reactor: a tile that could not be cached is
            // still a tile, and the reason is disclosed, not swallowed.
            let to_cache = bytes.clone();
            match tokio::task::spawn_blocking(move || write_cached(&path, &to_cache)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(z, x, y, error = %e, "tile fetched but not cached"),
                Err(e) => warn!(z, x, y, error = %e, "tile cache write task failed"),
            }
            png_response(bytes, "upstream")
        }
        Err(detail) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "tile upstream unreachable",
                "upstream": src.upstream_host(),
                "detail": detail,
            })),
        )
            .into_response(),
    }
}

/// One tile from the upstream: a success status, an image content type and a
/// body read to a hard cap — a "tile" that is really an error page or
/// something enormous is refused before a byte of it is cached.
///
/// The `Err` is the `502`'s `detail`, so every reqwest error reaches it through
/// [`transport_error_message`]: reqwest's own `Display` appends the full
/// request URL — the expanded template, the operator's key in its query — and
/// the route answers any client the server admits (REQ-CRED-003).
///
/// [`transport_error_message`]: crate::util::http::transport_error_message
async fn fetch_upstream(src: &TileSource, z: u8, x: u32, y: u32) -> Result<Vec<u8>, String> {
    use crate::util::http::transport_error_message;
    let url = src.upstream_url(z, x, y);
    let resp = src
        .client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", transport_error_message(e)))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("upstream answered {status}"));
    }
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !content_type.starts_with("image/") {
        return Err(format!("upstream answered {content_type:?}, not an image"));
    }
    let mut bytes = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| format!("body read failed: {}", transport_error_message(e)))?;
        if bytes.len() + chunk.len() > MAX_TILE_BYTES {
            return Err(format!("upstream body exceeds {MAX_TILE_BYTES} bytes"));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err("upstream answered an empty body".to_string());
    }
    Ok(bytes)
}

/// Into the cache atomically, under owner-only directories like every other
/// file beneath the data directory.
fn write_cached(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        crate::util::atomic_file::create_dir_private(parent)?;
    }
    crate::util::atomic_file::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::*;
    use crate::util::http::test_server::{Canned, serve};

    /// A 1×1 PNG — the smallest thing that is honestly an image.
    const PNG_1X1: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
        0x77, 0x53, 0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x90,
        0xd9, 0xf1, 0x15, 0x00, 0x02, 0xbd, 0x01, 0xca, 0xf8, 0x2a, 0x2c, 0x22, 0x00, 0x00, 0x00,
        0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];

    /// A stand-in upstream on a loopback port: the PNG for every tile at
    /// z ≤ 3, a 404 deeper (an upstream failure), and a hit counter.
    async fn stub_upstream() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/{z}/{x}/{y}",
            get(move |Path((z, _x, _y)): Path<(u8, u32, String)>| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    if z <= 3 {
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "image/png")],
                            PNG_1X1,
                        )
                            .into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("stub upstream");
        });
        (format!("http://{addr}/{{z}}/{{x}}/{{y}}.png"), hits)
    }

    fn scratch_cache(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hse-tiles-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn tile_router(src: TileSource) -> axum::Router {
        axum::Router::new()
            .route("/api/v1/tiles/{z}/{x}/{y}", get(tile))
            .with_state(crate::api::test_state_with_tiles(src))
    }

    async fn get_tile(app: &axum::Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let origin = resp
            .headers()
            .get("x-hse-tile")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(resp.into_body(), 4 << 20)
            .await
            .unwrap()
            .to_vec();
        (status, origin, bytes)
    }

    #[tokio::test]
    async fn a_tile_is_fetched_once_and_served_from_the_cache_after() {
        let (upstream, hits) = stub_upstream().await;
        let cache = scratch_cache("once");
        let src = TileSource::new(upstream, cache.clone(), reqwest::Client::new());
        let app = tile_router(src.clone());

        let (status, origin, bytes) = get_tile(&app, "/api/v1/tiles/3/4/2.png").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(origin.as_deref(), Some("upstream"));
        assert_eq!(bytes, PNG_1X1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(
            src.cache_path(3, 4, 2).is_file(),
            "the tile is kept at {}",
            src.cache_path(3, 4, 2).display()
        );

        // The second read never leaves the device — and the bare `{y}` form
        // finds the same file.
        let (status, origin, bytes) = get_tile(&app, "/api/v1/tiles/3/4/2").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(origin.as_deref(), Some("cache"));
        assert_eq!(bytes, PNG_1X1);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no second upstream fetch");
    }

    #[tokio::test]
    async fn an_out_of_range_tile_never_reaches_the_upstream() {
        let (upstream, hits) = stub_upstream().await;
        let app = tile_router(TileSource::new(
            upstream,
            scratch_cache("range"),
            reqwest::Client::new(),
        ));
        for uri in [
            "/api/v1/tiles/20/0/0.png", // past MAX_ZOOM
            "/api/v1/tiles/3/8/0.png",  // x == 2^3
            "/api/v1/tiles/3/0/8.png",  // y == 2^3
            "/api/v1/tiles/3/0/x.png",  // not a number
        ] {
            let (status, _, _) = get_tile(&app, uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing was relayed");
    }

    #[tokio::test]
    async fn an_upstream_failure_is_a_502_naming_the_upstream_and_caches_nothing() {
        let (upstream, hits) = stub_upstream().await;
        let cache = scratch_cache("fail");
        let src = TileSource::new(upstream, cache, reqwest::Client::new());
        let app = tile_router(src.clone());
        let (status, origin, body) = get_tile(&app, "/api/v1/tiles/4/1/1.png").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(origin, None);
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "tile upstream unreachable");
        assert_eq!(body["upstream"], "127.0.0.1");
        assert!(
            body["detail"].as_str().unwrap_or("").contains("404"),
            "{body}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(
            !src.cache_path(4, 1, 1).exists(),
            "a failure is never cached"
        );
    }

    /// A loopback port nothing listens on — bound, read and released — so a
    /// connect to it is refused at once, as on a device that is offline.
    async fn closed_port() -> u16 {
        tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    /// A synthetic key, riding the template's query the way Thunderforest's
    /// documented `?apikey={apikey}` does. Distinctive, and short of the
    /// credential-shape guard's 16 characters: it marks a leak, it is no key.
    const TILE_KEY: &str = "TILEKEY-4F1D2C";

    /// REQ-CRED-003: a keyed upstream that fails answers a `502` naming its
    /// host and the failure's cause, and nothing of the URL it asked for — not
    /// the key, not the path, not the port. Three failures, each once a leak:
    /// a refused connect (the device offline) and a redirect loop (a captive
    /// portal, a misbehaving server) put reqwest's ` for url (…)` suffix into
    /// `detail`; a template with no host had `upstream` echo the template
    /// itself. The cause still reads, so the operator learns why.
    #[tokio::test]
    async fn a_failed_keyed_fetch_never_echoes_the_upstream_url_or_its_key() {
        let refused = closed_port().await;
        let looping = serve(
            (0..12)
                .map(|_| {
                    Canned::text(302, "")
                        .header("Location", format!("/4/1/1.png?apikey={TILE_KEY}"))
                })
                .collect(),
        )
        .await;
        let hostless = format!("(no host: {TILE_UPSTREAM_ENV} is not an absolute URL)");
        let cases = [
            (
                format!("http://127.0.0.1:{refused}/{{z}}/{{x}}/{{y}}.png?apikey={TILE_KEY}"),
                "127.0.0.1",
                "request failed: error sending request: ",
            ),
            (
                format!("{looping}/{{z}}/{{x}}/{{y}}.png?apikey={TILE_KEY}"),
                "127.0.0.1",
                "request failed: error following redirect: ",
            ),
            (
                format!("tiles.example/{{z}}/{{x}}/{{y}}.png?apikey={TILE_KEY}"),
                hostless.as_str(),
                "request failed: builder error: ",
            ),
        ];
        for (i, (template, upstream, cause)) in cases.into_iter().enumerate() {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("client");
            let src = TileSource::new(
                template.clone(),
                scratch_cache(&format!("keyed-{i}")),
                client,
            );
            let (status, origin, body) =
                get_tile(&tile_router(src.clone()), "/api/v1/tiles/4/1/1.png").await;
            let text = String::from_utf8_lossy(&body);
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{template}: {text}");
            assert_eq!(origin, None, "{text}");
            assert!(!text.contains(TILE_KEY), "the key leaked: {text}");
            assert!(
                !text.to_ascii_lowercase().contains("apikey"),
                "the key's parameter leaked, masked or not: {text}"
            );
            assert!(
                !text.contains("/4/1/1.png"),
                "the upstream URL leaked: {text}"
            );
            for port in [
                refused.to_string(),
                looping.rsplit(':').next().unwrap_or("").to_string(),
            ] {
                assert!(
                    !text.contains(&format!(":{port}")),
                    "the upstream origin leaked: {text}"
                );
            }
            let json: serde_json::Value = serde_json::from_slice(&body).expect("a JSON body");
            assert_eq!(json["error"], "tile upstream unreachable", "{text}");
            assert_eq!(json["upstream"], upstream, "{text}");
            let detail = json["detail"].as_str().unwrap_or("");
            assert!(
                detail.starts_with(cause) && detail.len() > cause.len(),
                "the failure's cause still reads: {detail}"
            );
            assert!(
                !src.cache_path(4, 1, 1).exists(),
                "a failure is never cached"
            );
        }
    }

    /// REQ-CRED-003: an upstream that drops the connection mid-tile is a `502`
    /// whose `detail` carries the cause chain through the same renderer as the
    /// send — not reqwest's bare category label — and caches nothing. (The
    /// stub is hand-rolled because `test_server` always writes an honest
    /// `Content-Length`.)
    #[tokio::test]
    async fn a_tile_cut_off_mid_body_is_a_502_with_its_cause_and_caches_nothing() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).await;
            // A promise of 4096 bytes, eight delivered, then the line drops.
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4096\r\n\r\n",
                )
                .await;
            let _ = sock.write_all(&PNG_1X1[..8]).await;
            let _ = sock.shutdown().await;
        });
        let src = TileSource::new(
            format!("http://{addr}/{{z}}/{{x}}/{{y}}.png?apikey={TILE_KEY}"),
            scratch_cache("cut"),
            reqwest::Client::new(),
        );
        let (status, _, body) =
            get_tile(&tile_router(src.clone()), "/api/v1/tiles/4/1/1.png").await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{text}");
        assert!(!text.contains(TILE_KEY), "the key leaked: {text}");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("a JSON body");
        let detail = json["detail"].as_str().unwrap_or("");
        assert!(
            detail.starts_with("body read failed: ")
                && detail.contains("error reading a body from connection"),
            "the cut's cause reads, not just reqwest's label: {detail}"
        );
        assert!(
            !src.cache_path(4, 1, 1).exists(),
            "a truncated tile is never cached"
        );
    }

    #[tokio::test]
    async fn a_cached_tile_serves_with_no_upstream_at_all() {
        // Offline: the cache holds the tile, the upstream does not exist.
        let cache = scratch_cache("offline");
        let src = TileSource::new(
            "http://127.0.0.1:9/{z}/{x}/{y}.png",
            cache,
            reqwest::Client::new(),
        );
        write_cached(&src.cache_path(2, 1, 1), PNG_1X1).expect("seed the cache");
        let app = tile_router(src);
        let (status, origin, bytes) = get_tile(&app, "/api/v1/tiles/2/1/1.png").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(origin.as_deref(), Some("cache"));
        assert_eq!(bytes, PNG_1X1);
    }

    #[test]
    fn the_template_and_the_cache_share_one_layout() {
        let src = TileSource::new(
            "https://tiles.example/{z}/{x}/{y}.png",
            PathBuf::from("/tmp/hse-tiles"),
            reqwest::Client::new(),
        );
        assert_eq!(
            src.upstream_url(17, 121_245, 74_627),
            "https://tiles.example/17/121245/74627.png"
        );
        assert_eq!(
            src.cache_path(17, 121_245, 74_627),
            PathBuf::from("/tmp/hse-tiles/17/121245/74627.png")
        );
        assert_eq!(src.upstream_host(), "tiles.example");
        assert!(valid_tile(0, 0, 0));
        assert!(valid_tile(19, (1 << 19) - 1, (1 << 19) - 1));
        assert!(!valid_tile(19, 1 << 19, 0));
        assert!(!valid_tile(20, 0, 0));
        assert_eq!(parse_y("12.png"), Some(12));
        assert_eq!(parse_y("12"), Some(12));
        assert_eq!(parse_y("12.jpg"), None);
    }
}
