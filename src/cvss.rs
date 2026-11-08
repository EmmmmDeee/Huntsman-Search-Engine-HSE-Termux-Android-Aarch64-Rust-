//! Offline CVSS v3.0/v3.1 base-score computation from a vector string, so a CVE's severity can be
//! derived from the vector alone when no numeric score is on hand (for example when the NVD leg is
//! rate-limited but OSV returned a `CVSS:3.1/...` vector). Pure, deterministic, and matching the
//! FIRST CVSS v3.1 specification's metric weights and Roundup rule.
//!
//! Only the Base metrics are read; temporal and environmental metrics are ignored. A vector that is
//! not a well-formed v3.0/v3.1 base vector yields `None` rather than a guessed score.

/// A computed CVSS base score (0.0..=10.0) and its qualitative severity band.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Base {
    pub score: f64,
    pub severity: Severity,
}

/// The CVSS v3.1 qualitative severity rating of a base score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// The band a base score falls in, per the CVSS v3.1 qualitative scale. **Pure.**
    #[must_use]
    pub fn of(score: f64) -> Self {
        if score <= 0.0 {
            Self::None
        } else if score < 4.0 {
            Self::Low
        } else if score < 7.0 {
            Self::Medium
        } else if score < 9.0 {
            Self::High
        } else {
            Self::Critical
        }
    }
}

/// The value of metric `key` in a `CVSS:3.x/...` vector, upper-cased. **Pure.**
fn metric<'a>(vector: &'a str, key: &str) -> Option<&'a str> {
    vector.split('/').find_map(|part| {
        let (k, v) = part.split_once(':')?;
        k.eq_ignore_ascii_case(key).then_some(v)
    })
}

/// The CVSS v3.1 Roundup: the smallest one-decimal value not less than `x`, computed on scaled
/// integers to avoid binary-float surprises, exactly as the specification defines it. **Pure.**
fn roundup(x: f64) -> f64 {
    let scaled = (x * 100_000.0).round();
    if scaled % 10_000.0 == 0.0 {
        scaled / 100_000.0
    } else {
        ((scaled / 10_000.0).floor() + 1.0) / 10.0
    }
}

/// The CVSS v3.0/v3.1 base score of `vector`, or `None` when it is not a well-formed base vector
/// (wrong prefix, or a missing or unrecognised base metric). **Pure.**
#[must_use]
pub fn base_score(vector: &str) -> Option<Base> {
    let version = vector.strip_prefix("CVSS:")?;
    if !(version.starts_with("3.0/") || version.starts_with("3.1/")) {
        return None;
    }
    let av = match metric(vector, "AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match metric(vector, "AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let ui = match metric(vector, "UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let scope_changed = match metric(vector, "S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let pr = match (metric(vector, "PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let impact_metric = |value: &str| match value {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let c = impact_metric(metric(vector, "C")?)?;
    let i = impact_metric(metric(vector, "I")?)?;
    let a = impact_metric(metric(vector, "A")?)?;

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    let score = if impact <= 0.0 {
        0.0
    } else if scope_changed {
        roundup(f64::min(1.08 * (impact + exploitability), 10.0))
    } else {
        roundup(f64::min(impact + exploitability, 10.0))
    };
    Some(Base {
        score,
        severity: Severity::of(score),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(v: &str) -> f64 {
        base_score(v).expect("a valid vector").score
    }

    #[track_caller]
    fn assert_score(v: &str, want: f64) {
        assert!(
            (score(v) - want).abs() < 1e-9,
            "{v} = {} want {want}",
            score(v)
        );
    }

    #[test]
    fn known_vectors_match_published_scores() {
        // Log4Shell (CVE-2021-44228): 10.0 CRITICAL.
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0);
        // EternalBlue (CVE-2017-0144): 8.1 HIGH.
        assert_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1);
        // A scope-unchanged medium: 6.5.
        assert_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 6.5);
        // All-none impact is 0.0 NONE.
        assert_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0);
        // v3.0 is accepted with the same weights.
        assert_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0);
    }

    #[test]
    fn severity_bands_follow_the_scale() {
        assert_eq!(Severity::of(0.0), Severity::None);
        assert_eq!(Severity::of(3.9), Severity::Low);
        assert_eq!(Severity::of(4.0), Severity::Medium);
        assert_eq!(Severity::of(7.0), Severity::High);
        assert_eq!(Severity::of(9.0), Severity::Critical);
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn a_malformed_or_unsupported_vector_is_none() {
        assert!(base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
        assert!(base_score("not a vector").is_none());
        assert!(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H").is_none()); // missing A
        assert!(base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_none()); // bad AV
    }

    #[test]
    fn roundup_matches_the_spec_examples() {
        assert!((roundup(4.0) - 4.0).abs() < 1e-9);
        assert!((roundup(4.01) - 4.1).abs() < 1e-9);
        assert!((roundup(6.5) - 6.5).abs() < 1e-9);
    }
}
