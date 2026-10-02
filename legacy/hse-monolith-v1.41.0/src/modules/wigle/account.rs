//! WiGLE account introspection — `/api/v2/profile/user`.
//!
//! One non-counting endpoint that surfaces operator-visible state.
//! `emailVerified: false` means WiGLE throttles database queries until
//! the email-confirm step — a silent operational hazard surfaced by
//! `hse doctor` and the `/api/v1/stats` diagnostic block.
//!
//! The call is NOT charged against any of the four observation-type
//! budgets — it's metadata, dispatched once per process and cached in
//! `ACCOUNT_STATUS_CACHE` for subsequent reads.

/// Operator-visible WiGLE account state.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WigleAccountStatus {
    /// True if the `/profile/user` lookup reported `emailVerified == true`.
    /// `None` if the endpoint hasn't been polled this process.
    pub verified: Option<bool>,
    /// Username on the WiGLE side — the `userid` field, matching the
    /// operator's account (WiGLE pads it with a trailing space, which we
    /// trim).
    pub user: Option<String>,
    /// Last refresh time (unix seconds) — `None` if never polled.
    pub last_polled_ts: Option<u64>,
}

static ACCOUNT_STATUS_CACHE: std::sync::OnceLock<std::sync::Mutex<WigleAccountStatus>> =
    std::sync::OnceLock::new();

pub(super) fn account_status_cache() -> &'static std::sync::Mutex<WigleAccountStatus> {
    ACCOUNT_STATUS_CACHE.get_or_init(|| std::sync::Mutex::new(WigleAccountStatus::default()))
}

/// Read the cached account status. `verified == None` means the
/// `/profile/user` endpoint has not been polled yet this process.
pub fn account_status() -> WigleAccountStatus {
    account_status_cache()
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default()
}

/// Subset of the WiGLE `Person` object (`GET /api/v2/profile/user`) we
/// act on. The account name lives in `userid` and the email-verification
/// gate in `emailVerified` — the field names from the published swagger
/// `Person` schema, confirmed against the live endpoint. Parsing `user`
/// /`verified` (as an earlier build did) silently produced None for both,
/// so the throttling hazard below was never detected.
#[derive(serde::Deserialize)]
pub(super) struct ProfileUserResp {
    #[serde(default)]
    pub(super) userid: Option<String>,
    #[serde(default, rename = "emailVerified")]
    pub(super) email_verified: Option<bool>,
}

/// Pure mapping from a parsed `/profile/user` body to the cached account
/// status. WiGLE pads `userid` with a trailing space (`"MattDieg "`), so
/// trim it and treat an all-whitespace name as absent. Split out from the
/// network path so the field mapping is unit-testable.
pub(super) fn status_from_profile(body: ProfileUserResp, polled_ts: u64) -> WigleAccountStatus {
    WigleAccountStatus {
        verified: body.email_verified,
        user: body
            .userid
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty()),
        last_polled_ts: Some(polled_ts),
    }
}

/// One-shot poll of `profile/user`, caching the result in
/// `ACCOUNT_STATUS_CACHE`. Failures are silent — the status fields stay empty
/// (`verified: None`) so callers treat it as "unknown, keep going", while
/// `last_polled_ts` still records the attempt (the cache reflects that a poll
/// was made, not that it succeeded).
///
/// Does NOT consume any of the four observation-type budgets.
pub async fn refresh_account_status(
    http: &reqwest::Client,
    user: &str,
    token: &str,
) -> WigleAccountStatus {
    let now = crate::core::entity::unix_now();
    let mut status = WigleAccountStatus {
        last_polled_ts: Some(now),
        ..Default::default()
    };
    if let Ok(resp) = http
        .get("https://api.wigle.net/api/v2/profile/user")
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send()
        .await
        && resp.status().is_success()
        && let Ok(body) = crate::util::http::json_decode::<ProfileUserResp>(super::SRC, resp).await
    {
        status = status_from_profile(body, now);
    }
    if let Ok(mut g) = account_status_cache().lock() {
        *g = status.clone();
    }
    status
}

/// True if the operator's WiGLE account is confirmed unverified
/// (i.e. the email-verify step the user account page warns about
/// hasn't been completed). `false` means "verified or unknown" so
/// callers don't false-alarm on a stale cache.
pub fn is_unverified() -> bool {
    matches!(account_status().verified, Some(false))
}

/// Record that a query endpoint itself just proved the account unverified —
/// WiGLE answers `network/search` with HTTP 412 (`"Email is not verified for
/// account"`) rather than a 200 with a thinner body, so this is learned as a
/// side effect of `fetch.rs`'s normal traffic, not a dedicated poll. Leaves
/// `user` untouched (a bare 412 carries no username) and only ever narrows
/// unknown/stale state to the ground truth WiGLE just reported.
/// Warns on the TRANSITION into the unverified state, because until this existed the condition was
/// invisible where it actually costs the operator. A 412 is deliberately NOT an `Err` — one
/// unverified provider must not fail a whole scan — so `fetch.rs` converts it to an empty-but-
/// successful `Resp`, and the module then returns no entities. The result is a scan reporting
/// "1 run, 0 errored" and no networks: indistinguishable from "there is genuinely nothing here",
/// for every scan, forever, with the remedy (one click on the WiGLE account page) never surfaced.
/// The status was already recorded here for `hse doctor` / `/api/v1/stats`, but an operator running
/// `hse scan` sees neither.
///
/// Logged once per process, on the `Some(false)` transition only: a single scan can issue several
/// WiGLE sub-searches (WiFi bbox, SSID, cell, Bluetooth) that would each 412, and repeating the
/// same advice four times per scan trains the reader to ignore it.
pub(super) fn mark_unverified(now: u64) {
    if let Ok(mut g) = account_status_cache().lock() {
        let newly_unverified = g.verified != Some(false);
        g.verified = Some(false);
        g.last_polled_ts = Some(now);
        if newly_unverified {
            tracing::warn!(
                "WiGLE account is not email-verified — the API answers every query with HTTP 412, \
                 so WiGLE results will be EMPTY (not an error) until it is verified. Fix: open \
                 https://wigle.net/account and send/complete the verification email."
            );
        }
    }
}

/// The symmetric counterpart of [`mark_unverified`]: a query endpoint that
/// succeeds (any non-412 success) is equally conclusive proof the account
/// IS verified, learned from the same live traffic. Without this, a 412 seen
/// once earlier in a long-lived `hse serve`/`hse live` process — e.g. before
/// the operator completed WiGLE's email-verify step — would latch
/// `verified: Some(false)` for the rest of the process even after every
/// later query succeeds, leaving `hse doctor` / `/api/v1/stats` reporting a
/// stale "unverified" warning long after the real condition self-resolved.
pub(super) fn mark_verified(now: u64) {
    if let Ok(mut g) = account_status_cache().lock() {
        g.verified = Some(true);
        g.last_polled_ts = Some(now);
    }
}
