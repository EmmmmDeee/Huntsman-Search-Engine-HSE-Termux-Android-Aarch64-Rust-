//! The cooldown policy itself: the on-disk `dep-cooldown.toml` schema, and
//! the pure decision of which resolved packages violate it. No network, no
//! clock reads — `now` is always passed in, so the decision is exact and
//! reproducible in tests instead of racing the wall clock.

use std::collections::HashSet;

use serde::Deserialize;
use time::OffsetDateTime;

/// Cooldown window used when neither `--cooldown-days` nor `dep-cooldown.toml`'s
/// `cooldown_days` sets one. A freshly published crate version is exactly the
/// moment a stolen publish token or hijacked maintainer account is most likely
/// to slip a compromised release through unnoticed; RustSec/crates.io
/// typically catch and yank a malicious release within days, not hours, so a
/// short window still buys real detection time without meaningfully delaying
/// legitimate updates.
pub const DEFAULT_COOLDOWN_DAYS: u32 = 4;

/// On-disk schema for `dep-cooldown.toml`. Unknown keys are a hard error
/// (`deny_unknown_fields`) so a typo'd field name (e.g. `cooldown-days` for
/// `cooldown_days`) fails loudly at parse time instead of being silently
/// ignored and leaving the operator's intended policy unapplied.
#[derive(Debug, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub cooldown_days: Option<u32>,
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

/// One explicitly allow-listed `(name, version)` exception, with the reason a
/// human recorded when adding it — mirrors `deny.toml`'s `[advisories] ignore`
/// convention of a named, documented exception rather than a blanket bypass.
/// Matches by exact version only, so allow-listing today's release doesn't
/// silently exempt every future one too.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub reason: String,
}

/// Parse a `dep-cooldown.toml` policy file.
pub fn parse_policy_file(raw: &str) -> Result<PolicyFile, toml::de::Error> {
    toml::from_str(raw)
}

/// A crates.io package resolved against its actual publish timestamp.
#[derive(Debug, Clone)]
pub struct PackagePublish {
    pub name: String,
    pub version: String,
    pub published_at: OffsetDateTime,
}

/// A package inside the cooldown window and not allow-listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub name: String,
    pub version: String,
    /// Negative when `published_at` is after `now` (clock skew, or a registry
    /// timestamp anomaly) — treated as maximally fresh rather than clamped to
    /// zero, so it still reads as an obvious violation rather than looking
    /// like a same-day publish.
    pub days_since_publish: i64,
    pub cooldown_days: u32,
}

/// Decide which of `published` violate `cooldown_days`, given `now` and the
/// `allow`-list.
pub fn find_violations(
    now: OffsetDateTime,
    cooldown_days: u32,
    published: &[PackagePublish],
    allow: &[AllowEntry],
) -> Vec<Violation> {
    let allowed: HashSet<(&str, &str)> = allow
        .iter()
        .map(|a| (a.name.as_str(), a.version.as_str()))
        .collect();

    published
        .iter()
        .filter(|p| !allowed.contains(&(p.name.as_str(), p.version.as_str())))
        .filter_map(|p| {
            let days = (now - p.published_at).whole_days();
            (days < i64::from(cooldown_days)).then(|| Violation {
                name: p.name.clone(),
                version: p.version.clone(),
                days_since_publish: days,
                cooldown_days,
            })
        })
        .collect()
}

/// Whether `dep-cooldown` should report failure, given what it found.
///
/// Two conditions fail the gate, deliberately NOT both gated on `strict`: a
/// real cooldown violation always fails (the entire point of the tool), and
/// a *complete* verification failure — every crates.io lookup failed despite
/// there being dependencies in scope — always fails too, regardless of
/// `strict`. Without that second condition this gate fails OPEN: if the
/// registry is unreachable (an outage, a blocked egress, a corporate proxy)
/// `published` comes back empty, so `find_violations` finds nothing to flag
/// and the caller would otherwise report "OK" having verified zero
/// dependencies — silently downgrading a security gate to a no-op pass on
/// exactly the routine failure mode (crates.io down, rate-limited, blocked)
/// a scheduled/CI-triggered run is most likely to hit. `strict` only
/// escalates a *partial* fetch failure (some packages verified, some did
/// not) from a warning to a hard failure — the tool's advisory-quality
/// default tolerates an isolated, transient single-package lookup failure
/// without failing an otherwise-clean run.
pub fn should_fail(
    violations: &[Violation],
    fetch_errors: &[crate::registry::FetchError],
    total_packages: usize,
    strict: bool,
) -> bool {
    let complete_verification_failure = total_packages > 0 && fetch_errors.len() == total_packages;
    !violations.is_empty() || complete_verification_failure || (strict && !fetch_errors.is_empty())
}

#[cfg(test)]
mod tests {
    include!("policy_tests.rs");
}
