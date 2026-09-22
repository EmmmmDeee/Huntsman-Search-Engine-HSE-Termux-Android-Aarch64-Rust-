//! The Public Suffix List, and the one algorithm that reads it.
//!
//! A registrable domain (eTLD+1) is the unit of registration: every host under
//! it answers to one registrant. HSE draws that boundary for credential safety
//! (`util::http::ssrf::same_site` decides whether a redirect may carry an API
//! key), for attribution (the correlator's organisation and look-alike rules
//! group domains by it), and for enumeration (`dns_intel` decides what is an
//! apex). Every one of those is only as right as the suffix list underneath.
//!
//! It was a 39-entry hand-curated table, and it held no Vietnamese second
//! level at all, although Vietnam is this project's primary jurisdiction:
//! `registrable_domain("shop.acme.com.vn")` answered `com.vn`, so every
//! Vietnamese company shared one "registrable domain", and a credentialed
//! redirect from `api.provider.com.vn` to `attacker.com.vn` was judged
//! same-site (REQ-PSL-001). The same held for every multi-label suffix the
//! table did not list (`co.kr`, `com.tw`, `co.th`, …) and for every shared
//! hosting suffix (`github.io`, `blogspot.com`, …), where unrelated
//! registrants sit side by side.
//!
//! ## The data
//!
//! `public_suffix_list.dat` is Mozilla's Public Suffix List, **vendored
//! verbatim** from <https://publicsuffix.org/list/public_suffix_list.dat> —
//! both the ICANN and the PRIVATE sections, since the boundary is used for
//! credential and attribution decisions where a `github.io` tenant is a
//! different party. It is licensed MPL-2.0 (its header says so and is kept);
//! MPL-2.0 is file-level, so shipping the unmodified file inside a larger
//! proprietary work is permitted provided the file itself stays MPL and
//! available, as it is here. The version is the `// VERSION:` line in the
//! file. To refresh it, replace the file with a fresh download and run the
//! tests; nothing else changes. No crate dependency, no network at runtime.
//!
//! ## The algorithm
//!
//! The list's own specification (<https://publicsuffix.org/list/>), exactly:
//! of the rules that match a name, an **exception** rule (`!www.ck`) wins and
//! its public suffix is the rule minus its leftmost label; otherwise the rule
//! with the **most labels** wins, a **wildcard** (`*.ck`) matching any one
//! label in its place; if nothing matches, the prevailing rule is `*` — the
//! TLD alone. Rules are compared in Unicode, so a punycode host
//! (`xn--85x722f.xn--55qx5d.cn`) is matched through its Unicode form and
//! answered in the form it was asked in.
//!
//! `test_psl.txt` is the list project's own conformance suite (public domain,
//! vendored verbatim); every case in it runs as a unit test.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The vendored list, verbatim.
const LIST: &str = include_str!("public_suffix_list.dat");

struct Rules {
    /// Plain rules: `com.au`, `github.io`.
    exact: HashSet<&'static str>,
    /// Wildcard rules, stored WITHOUT their `*.`: `*.ck` is held as `ck`.
    wildcard: HashSet<&'static str>,
    /// Exception rules, stored WITHOUT their `!`: `!www.ck` is held as `www.ck`.
    exception: HashSet<&'static str>,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut rules = Rules {
            exact: HashSet::new(),
            wildcard: HashSet::new(),
            exception: HashSet::new(),
        };
        // Per the list's format: one rule per line, the rule is the text up to
        // the first whitespace, and `//` starts a comment line.
        for line in LIST.lines() {
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            if rule.starts_with("//") {
                continue;
            }
            if let Some(rule) = rule.strip_prefix('!') {
                rules.exception.insert(rule);
            } else if let Some(rule) = rule.strip_prefix("*.") {
                rules.wildcard.insert(rule);
            } else {
                rules.exact.insert(rule);
            }
        }
        rules
    })
}

/// How many trailing labels of `name` form its public suffix. `name` is
/// lowercase with no empty label. **Pure.**
///
/// Candidates are tried longest first, so the first match is the rule with the
/// most labels; at each length the exception rule is tried before the others,
/// because an exception overrides the wildcard it carves out of.
fn suffix_label_count(name: &str) -> usize {
    let rules = rules();
    let starts: Vec<usize> = std::iter::once(0)
        .chain(name.match_indices('.').map(|(at, _)| at + 1))
        .collect();
    let labels = starts.len();
    for (i, &at) in starts.iter().enumerate() {
        let candidate = &name[at..];
        if rules.exception.contains(candidate) {
            return labels - i - 1;
        }
        if rules.exact.contains(candidate) {
            return labels - i;
        }
        if let Some(&parent) = starts.get(i + 1)
            && rules.wildcard.contains(&name[parent..])
        {
            return labels - i;
        }
    }
    // The prevailing rule when none matches: `*`, the TLD alone.
    1
}

/// The registrable domain (eTLD+1) of `host` under the Public Suffix List, or
/// `None` when `host` has none — it is itself a public suffix (`com.au`,
/// `github.io`), a single label, empty, or carries an empty label (a leading
/// dot, `a..b`). **Pure.** Trims, lowercases, drops one trailing dot.
pub(super) fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return None;
    }
    let labels = host.split('.').count();
    // The list's rules are in Unicode. A punycode host is matched through its
    // Unicode form, which has the same labels; anything that does not convert
    // label-for-label is matched as written.
    let unicode = url::quirks::domain_to_unicode(&host);
    let suffix = if !unicode.is_empty() && unicode.split('.').count() == labels {
        suffix_label_count(&unicode)
    } else {
        suffix_label_count(&host)
    };
    if labels <= suffix {
        return None;
    }
    Some(
        host.split('.')
            .skip(labels - suffix - 1)
            .collect::<Vec<_>>()
            .join("."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list project's own conformance suite, every case. Its format is
    /// `checkPublicSuffix(input, expected);` with `null` for "none"; commented
    /// cases (`//checkPublicSuffix`) are the ones the project itself disables.
    #[test]
    fn the_official_conformance_suite_passes_in_full() {
        let suite = include_str!("test_psl.txt");
        let mut ran = 0;
        let mut failures = Vec::new();
        for line in suite.lines().map(str::trim) {
            let Some(args) = line
                .strip_prefix("checkPublicSuffix(")
                .and_then(|l| l.strip_suffix(");"))
            else {
                continue;
            };
            let (input, want) = args.split_once(", ").expect("two arguments");
            let arg = |s: &str| (s != "null").then(|| s.trim_matches('\'').to_string());
            let (input, want) = (arg(input), arg(want));
            let got = input.as_deref().and_then(registrable_domain);
            ran += 1;
            if got != want {
                failures.push(format!("{input:?} -> {got:?}, want {want:?}"));
            }
        }
        // Vacuity guard: the suite's live cases, counted. A parser that stopped
        // matching would otherwise pass on zero cases.
        assert_eq!(ran, 78, "the vendored suite has 78 live cases");
        assert!(
            failures.is_empty(),
            "{} of {ran} official cases failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn the_vendored_list_is_the_whole_list() {
        // Both sections, the version stamp, and the rule shapes the algorithm
        // distinguishes — so a truncated or mangled refresh fails here rather
        // than quietly shrinking every boundary back to the TLD.
        assert!(LIST.contains("// ===BEGIN ICANN DOMAINS==="));
        assert!(LIST.contains("// ===BEGIN PRIVATE DOMAINS==="));
        assert!(LIST.contains("// VERSION: "));
        let rules = rules();
        assert!(
            rules.exact.len() > 9_000,
            "only {} plain rules",
            rules.exact.len()
        );
        for rule in [
            "com.au",
            "com.vn",
            "gov.vn",
            "name.vn",
            "co.uk",
            "github.io",
        ] {
            assert!(rules.exact.contains(rule), "missing {rule}");
        }
        assert!(rules.wildcard.contains("ck"));
        assert!(rules.exception.contains("www.ck"));
    }

    #[test]
    fn every_vietnamese_second_level_is_a_suffix() {
        // REQ-PSL-001: FAILS on the 39-entry table, which had none of them and
        // answered `com.vn` for every Vietnamese commercial domain. The list is
        // VNNIC's published namespace, the same source `util::domain_vn` cites.
        for sld in [
            "com", "net", "org", "edu", "gov", "ac", "biz", "info", "name", "pro", "health", "int",
        ] {
            assert_eq!(
                registrable_domain(&format!("shop.acme.{sld}.vn")).as_deref(),
                Some(format!("acme.{sld}.vn").as_str()),
                "{sld}.vn"
            );
        }
        assert_eq!(
            registrable_domain("com.vn"),
            None,
            "a suffix has no registrable domain"
        );
    }

    #[test]
    fn a_shared_hosting_tenant_is_its_own_registrant() {
        assert_eq!(
            registrable_domain("alice.github.io").as_deref(),
            Some("alice.github.io")
        );
        assert_ne!(
            registrable_domain("alice.github.io"),
            registrable_domain("mallory.github.io")
        );
    }

    #[test]
    fn a_punycode_host_is_answered_in_the_form_it_was_asked_in() {
        assert_eq!(
            registrable_domain("www.xn--85x722f.xn--55qx5d.cn").as_deref(),
            Some("xn--85x722f.xn--55qx5d.cn")
        );
    }
}
