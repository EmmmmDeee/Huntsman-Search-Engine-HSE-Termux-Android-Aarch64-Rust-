//! Redaction for shareable output. Rebuilt from the monolith's `util::redact`.
//! Pure, no I/O.
//!
//! Two operations: coarsen a coordinate to one decimal place (about 11 km) and
//! scrub known secrets from free text. The monolith replaced secrets one at a
//! time with `str::replace`, so a secret that was a substring of another left the
//! longer one half exposed, partly overlapping secrets left their tails in
//! the clear, and a secret equal to a piece of the mask text re-matched. Here
//! every occurrence of every secret is found in the original text, overlapping
//! and touching spans are merged, and each merged span becomes one mask.
//! Coarsening is not anonymisation: ~11 km still places a person in a suburb.

use crate::geoint::parse_latlon;

/// Fixed and content-free: no length hint, no prefix.
pub const REDACTED: &str = "[redacted]";

/// Secrets shorter than this are not scrubbed. A one-letter "secret" would mask
/// unrelated text. Callers that must hide short values should drop the field.
pub const MIN_SECRET_LEN: usize = 4;

fn round1(x: f64) -> String {
    let v = (x * 10.0).round() / 10.0;
    let v = if v == 0.0 { 0.0 } else { v };
    format!("{v:.1}")
}

/// `lat,lon` to one decimal place. `None` when the pair is malformed, non-finite,
/// or out of range, so a bad value is never emitted as a plausible place. Rounding
/// can land exactly on a bound (89.96 gives 90.0), which is still valid.
#[must_use]
pub fn coarsen_latlon(raw: &str) -> Option<String> {
    let (lat, lon) = parse_latlon(raw).ok()?;
    Some(format!("{},{}", round1(lat), round1(lon)))
}

/// Replace every occurrence of every secret in `text` with [`REDACTED`].
/// Overlapping or touching matches become one mask, so no fragment of a secret
/// survives next to another. Matching is exact and case-sensitive.
#[must_use]
pub fn scrub_secrets(text: &str, secrets: &[&str]) -> String {
    let needles: Vec<&str> = secrets
        .iter()
        .copied()
        .filter(|s| s.len() >= MIN_SECRET_LEN)
        .collect();
    if needles.is_empty() {
        return text.to_owned();
    }
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (start, _) in text.char_indices() {
        let rest = &text[start..];
        if let Some(len) = needles
            .iter()
            .filter(|n| rest.starts_with(**n))
            .map(|n| n.len())
            .max()
        {
            spans.push((start, start + len));
        }
    }
    // Longest match per start, then merge: a span that starts inside the previous
    // one extends it, whether it overlaps or merely touches.
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut i = 0;
    while i < spans.len() {
        let (start, mut end) = spans[i];
        i += 1;
        while i < spans.len() && spans[i].0 <= end {
            end = end.max(spans[i].1);
            i += 1;
        }
        out.push_str(&text[cursor..start]);
        out.push_str(REDACTED);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // exact 0.0/1.0 sentinels are the contract under test
mod tests {
    use super::*;

    #[test]
    fn coordinates_are_coarsened_and_validated() {
        assert_eq!(
            coarsen_latlon("-27.4698,153.0251").as_deref(),
            Some("-27.5,153.0")
        );
        assert_eq!(
            coarsen_latlon(" 0.04 , -0.04 ").as_deref(),
            Some("0.0,0.0"),
            "negative zero folds"
        );
        assert_eq!(
            coarsen_latlon("89.96,179.96").as_deref(),
            Some("90.0,180.0")
        );
        for bad in [
            "", "1", "a,b", "NaN,0", "inf,0", "91,0", "0,181", "999,999", "1,2,3",
        ] {
            assert_eq!(coarsen_latlon(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn coarsening_is_idempotent_and_never_moves_far() {
        for raw in [
            "-27.4698,153.0251",
            "51.5007,-0.1246",
            "0.05,0.05",
            "-89.99,-179.99",
        ] {
            let once = coarsen_latlon(raw).unwrap();
            assert_eq!(coarsen_latlon(&once).as_deref(), Some(once.as_str()));
            let (a, b) = parse_latlon(raw).unwrap();
            let (c, d) = parse_latlon(&once).unwrap();
            assert!(
                (a - c).abs() <= 0.05 + 1e-9 && (b - d).abs() <= 0.05 + 1e-9,
                "{raw}"
            );
        }
    }

    #[test]
    fn every_occurrence_is_masked_and_text_around_it_is_kept() {
        let text = "pw hunter22 then hunter22 again";
        assert_eq!(
            scrub_secrets(text, &["hunter22"]),
            "pw [redacted] then [redacted] again"
        );
        assert_eq!(
            scrub_secrets("héllo wörld-secret ünï", &["wörld-secret"]),
            "héllo [redacted] ünï"
        );
        assert_eq!(scrub_secrets(text, &[]), text);
    }

    #[test]
    fn short_secrets_are_ignored_and_never_panic() {
        assert_eq!(scrub_secrets("a b abc", &["a", "abc", ""]), "a b abc");
        assert_eq!(scrub_secrets("", &["secret"]), "");
    }

    #[test]
    fn a_secret_inside_a_longer_secret_leaves_no_fragment() {
        let out = scrub_secrets("token=abcd1234efgh", &["abcd", "abcd1234efgh"]);
        assert_eq!(out, "token=[redacted]");
    }

    #[test]
    fn overlapping_secrets_merge_into_one_mask() {
        let out = scrub_secrets("xxabcdefyy", &["abcd", "cdef"]);
        assert_eq!(out, "xx[redacted]yy", "no tail of either secret survives");
        let out = scrub_secrets("aaaaaa", &["aaaa"]);
        assert_eq!(out, "[redacted]", "overlapping matches of one secret merge");
    }

    #[test]
    fn a_secret_that_matches_the_mask_text_is_not_rescanned() {
        let out = scrub_secrets("pw=hunter22", &["hunter22", "redacted"]);
        assert_eq!(out, "pw=[redacted]");
        let again = scrub_secrets(&out, &["hunter22"]);
        assert_eq!(again, out, "idempotent");
    }

    #[test]
    fn no_secret_survives_in_any_output() {
        let secrets = ["alpha-key", "key-beta99", "beta99-gamma"];
        let text = "a alpha-key-beta99-gamma b key-beta99 c";
        let out = scrub_secrets(text, &secrets);
        assert!(
            secrets.iter().all(|s| !out.contains(s)),
            "a secret survived"
        );
        assert_eq!(out, "a [redacted] b [redacted] c");
    }
}
