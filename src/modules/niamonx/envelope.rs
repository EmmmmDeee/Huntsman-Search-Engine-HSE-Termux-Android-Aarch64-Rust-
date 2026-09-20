// The response envelope, and the ONE function permitted to open it.
//
// A private submodule so the fields are unreachable from the rest of this
// file. Outside here there is no way to read `success`, no way to take `data`,
// and no way to CONSTRUCT an envelope whose flag did not come off the wire —
// so the only route from a decoded body to a payload is [`payload`], and a
// future edit cannot quietly restore the swallow this exists to prevent
// (REQ-NIAMONX-001). serde needs no visibility to fill the fields, and
// `peek` hands out a borrow for the dataguard check without surrendering the
// flag.

use super::{Error, Result, SRC};
use serde::Deserialize;

/// The shape all three endpoints share: a success flag beside an optional
/// payload. One generic type in place of three structurally identical ones.
#[derive(Deserialize)]
pub(super) struct Envelope<T> {
    success: bool,
    data: Option<T>,
}

impl<T> Envelope<T> {
    /// Borrow the payload WITHOUT consuming the envelope or revealing the
    /// flag — for `check_dataguard_key_failure`, which must read a provider
    /// error message out of the body before the success verdict is taken.
    pub(super) fn peek(&self) -> Option<&T> {
        self.data.as_ref()
    }

    /// Build an envelope from parts — **tests only**.
    ///
    /// `cfg(test)` on purpose: the seal above is the whole point, and a
    /// constructor available to production code would undo it by letting a
    /// caller forge a flag the wire never sent. `cfg(test)` is a
    /// compile-time switch reaching only this library's own tests, so the
    /// shipped build still has exactly one route from a body to a payload.
    #[cfg(test)]
    pub(super) fn from_parts(success: bool, data: Option<T>) -> Self {
        Self { success, data }
    }
}

/// The answer inside a 200 body, or an error naming why there isn't one
/// (REQ-NIAMONX-001). **Pure.**
///
/// `success: false` is the provider reporting that the CALL failed — not that
/// it found nothing. A genuine no-results answer carries `success: true` and
/// says so further in: `pbs_v1` with `data.status == "not_found"`, `ulp_search`
/// with `stats.total == 0`, `breaches_s_v2` with its own inner
/// `data.niamonx_success`. Four things in this repository agree on that, and
/// none of them needed a live key to read:
///
/// 1. `emit_pbs_v1`'s `data.status == "not_found"` check — the one its comment
///    calls "the documented no-results response" — sits behind `resp.data`, and
///    so behind `success`. It could not be reached at all if a miss arrived as
///    `success: false`.
/// 2. Each fetch above says "empty results arrive as 200+body" where it refuses
///    a 404.
/// 3. `breaches_s_v2` carries TWO flags at two levels; only the inner one is
///    about results, which leaves the outer one to be about the call.
/// 4. `tests::pbs_v1_skips_not_found_status` — the module's own fixture for a
///    miss — is written `success: true` with `status: "not_found"`. No fixture
///    in the file sets `success: false`, for any endpoint.
///
/// Returning the PAYLOAD rather than the envelope is what makes this
/// unskippable: the emitters take the payload, so no caller can reach one
/// without coming through here. Before this, each emitter opened with
/// `if !resp.success { return; }` — a silent return from a function returning
/// `()`, which structurally CANNOT report a failure. The provider said the call
/// failed and the module reported no findings, which is the one thing
/// `core::coverage::ProviderOutcome` exists to forbid.
///
/// ASSUMPTION, recorded as one: the four signals above are read off this
/// repository, not observed from the live API. If `success: false` turns out to
/// be an ordinary miss, this converts every miss into an endpoint error, and
/// three of those trip the key cascade. The direction is still the safer one —
/// a named failure an operator sees beats a silent "clean" verdict — and the
/// message names the endpoint and the flag so a wrong firing is one log line
/// away from being diagnosed.
pub(super) fn payload<T>(endpoint: &str, env: Envelope<T>) -> Result<T> {
    if !env.success {
        return Err(Error::module(
            SRC,
            format!(
                "niamonx {endpoint} answered success:false — the call failed; a \
                 no-results answer carries success:true"
            ),
        ));
    }
    env.data.ok_or_else(|| {
        Error::module(
            SRC,
            format!("niamonx {endpoint} answered success:true with no `data` object"),
        )
    })
}
