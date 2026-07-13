//! Shared confidence tiering for existence-probe modules (`username_search`,
//! `social_probe`, `streaming_probe`): whether a site's detection rule
//! actually inspected response BODY content for a positive/negative marker,
//! or only a bare HTTP status code — which soft-404/SPA-shell sites can
//! return for ANY handle, existent or not, making a status-only hit a
//! weaker, unverified lead. All three modules independently computed this
//! identical `(confidence, verified)` pair from their own per-module
//! detection-rule types; this is the one place the magic numbers now live.

/// `body_verified`: true when the detection rule actually inspected the
/// response body for a positive/negative marker, not just a status code.
#[must_use]
pub fn detection_strength(body_verified: bool) -> (f64, bool) {
    if body_verified {
        (0.92, true)
    } else {
        (0.74, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_verified_is_high_confidence_and_verified() {
        assert_eq!(detection_strength(true), (0.92, true));
    }

    #[test]
    fn status_only_is_lower_confidence_and_unverified() {
        assert_eq!(detection_strength(false), (0.74, false));
    }
}
