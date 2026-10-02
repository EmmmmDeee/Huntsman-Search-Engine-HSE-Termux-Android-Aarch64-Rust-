//! Runtime capabilities, kept separate from platform identity.
//!
//! # Why this module exists
//!
//! `crate::is_termux()` answers "which platform is this?". Several call sites
//! were using it to answer a different question: "how much time and bandwidth
//! can this host afford?". Those are not the same question, and conflating them
//! produces a concrete defect:
//!
//! * The per-module timeout cap (`core::engine::timeout`) documents its own
//!   reasoning entirely in resource terms — "low-power, metered, often-flaky
//!   mobile connection" — but keyed it on `is_termux()`.
//! * A small container instance (½–1 vCPU, 512 MB) is *more* constrained than a
//!   modern flagship phone, and `is_termux()` is false there. Such a host was
//!   therefore handed the full desktop budget, letting a pathological module
//!   burn 90–120 s per target on hardware that can least afford it.
//!
//! So identity stays in [`crate::is_termux`] and is used only for *reporting*
//! (diagnostics, environment export). Anything that changes engine behaviour
//! asks a capability question here instead.
//!
//! # Detection policy
//!
//! Capabilities are derived from observable facts and are overridable by an
//! explicit operator setting, because a detector is a heuristic and the operator
//! has ground truth. Detection is cached: these values cannot change within a
//! process, and probing `/proc` per module call would be pointless work.

use std::sync::OnceLock;

/// Operator override for the resource profile. `constrained` or `full`.
///
/// An explicit setting always wins over detection — the operator knows their
/// deployment shape better than a CPU count does.
pub const RESOURCE_PROFILE_ENV: &str = "HSE_RESOURCE_PROFILE";

/// At or below this many usable cores, treat the host as constrained.
///
/// One core means every concurrent module contends with the runtime itself;
/// two is the smallest tier most PaaS free/hobby plans offer.
const CONSTRAINED_MAX_CPUS: usize = 2;

/// At or below this much total RAM (MiB), treat the host as constrained.
///
/// 1 GiB is the common small-container allowance and roughly where a scan's
/// working set starts competing with the OS page cache.
const CONSTRAINED_MAX_MEM_MIB: u64 = 1024;

/// Whether this host should run with trimmed time and bandwidth budgets.
///
/// True when the operator says so, when running under Termux (a phone is
/// constrained by construction — battery, thermal envelope, metered radio), or
/// when the detected CPU/memory falls at or below the thresholds above.
///
/// Cached after first call.
pub fn is_resource_constrained() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(detect_resource_constrained)
}

/// Uncached detection: read the environment and the live signals, then decide.
///
/// The decision itself is factored into [`decide_constrained`], a pure function
/// of its inputs, so it is unit-testable without mutating process environment or
/// pretending to be a phone. This wrapper only gathers the inputs; env mutation
/// in a test would also be `unsafe` under edition 2024, which the crate forbids.
fn detect_resource_constrained() -> bool {
    decide_constrained(
        std::env::var(RESOURCE_PROFILE_ENV).ok().as_deref(),
        crate::is_termux(),
        usable_cpus(),
        total_memory_mib(),
    )
}

/// Pure resource-profile policy over already-gathered signals.
///
/// * `override_val` — the raw `HSE_RESOURCE_PROFILE` value, if set.
/// * `is_termux` — platform identity (a phone is constrained by construction).
/// * `cpus` / `mem_mib` — detected capacity, `None` where the probe could not
///   read a value (treated as "no evidence of constraint", never as "plenty").
fn decide_constrained(
    override_val: Option<&str>,
    is_termux: bool,
    cpus: Option<usize>,
    mem_mib: Option<u64>,
) -> bool {
    match override_val {
        Some("constrained") => return true,
        Some("full") => return false,
        // An unrecognised value is not silently honoured as either answer:
        // fall through to detection rather than guessing what was meant.
        _ => {}
    }

    if is_termux {
        return true;
    }
    if matches!(cpus, Some(n) if n <= CONSTRAINED_MAX_CPUS) {
        return true;
    }
    matches!(mem_mib, Some(mib) if mib <= CONSTRAINED_MAX_MEM_MIB)
}

/// Cores actually available to this process.
///
/// `available_parallelism` respects cgroup CPU limits on Linux, which is what
/// makes it the right probe for a container: a 0.5-vCPU instance on a 64-core
/// host reports the quota, not the machine.
fn usable_cpus() -> Option<usize> {
    std::thread::available_parallelism().ok().map(Into::into)
}

/// Total system memory in MiB, read from `/proc/meminfo`.
///
/// Returns `None` where `/proc` is absent or unparseable rather than guessing —
/// an unknown value must not be reported as "plenty", so callers treat `None`
/// as "no evidence of constraint" and rely on the other signals.
///
/// Note this reads the *host* total, not a cgroup limit. It is a coarse signal
/// deliberately: `usable_cpus` already covers the cgroup-quota case, and the
/// operator override covers anything either detector gets wrong.
fn total_memory_mib() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_constrained_profile_wins() {
        // Bypasses detection entirely: true regardless of the host signals,
        // even a 64-core box with terabytes of RAM.
        assert!(decide_constrained(
            Some("constrained"),
            false,
            Some(64),
            Some(999_999)
        ));
    }

    #[test]
    fn an_explicit_full_profile_wins_even_on_a_small_host() {
        // The operator's word beats a 1-core / low-RAM detection: someone who
        // pins `full` has decided to accept the latency.
        assert!(!decide_constrained(Some("full"), true, Some(1), Some(256)));
    }

    #[test]
    fn an_unrecognised_profile_falls_through_to_detection() {
        // A typo must change nothing: the result must equal the no-override run
        // over identical signals, on both a constrained and an ample host.
        let small = (false, Some(1usize), Some(512u64));
        assert_eq!(
            decide_constrained(Some("sm0l"), small.0, small.1, small.2),
            decide_constrained(None, small.0, small.1, small.2),
        );
        let big = (false, Some(32usize), Some(131_072u64));
        assert_eq!(
            decide_constrained(Some("sm0l"), big.0, big.1, big.2),
            decide_constrained(None, big.0, big.1, big.2),
        );
    }

    #[test]
    fn a_small_host_is_detected_as_constrained() {
        assert!(
            decide_constrained(None, false, Some(1), Some(8192)),
            "1 vCPU"
        );
        assert!(
            decide_constrained(None, false, Some(16), Some(512)),
            "512 MiB"
        );
        assert!(
            decide_constrained(None, true, Some(8), Some(8192)),
            "termux"
        );
    }

    #[test]
    fn an_ample_host_is_not_constrained() {
        assert!(!decide_constrained(None, false, Some(16), Some(65_536)));
    }

    #[test]
    fn an_unreadable_probe_is_no_evidence_not_plenty() {
        // Both probes failing on a non-termux host must not be reported as
        // constrained: absence of a reading is not a reading of "small".
        assert!(!decide_constrained(None, false, None, None));
    }

    #[test]
    fn memory_probe_either_parses_or_declines() {
        // Must never panic, and must never report an absurd value that would
        // mislabel a large host as constrained.
        if let Some(mib) = total_memory_mib() {
            assert!(mib > 0, "a parsed MemTotal is positive");
        }
    }

    #[test]
    fn cpu_probe_either_reports_at_least_one_or_declines() {
        if let Some(n) = usable_cpus() {
            assert!(n >= 1);
        }
    }

    #[test]
    fn the_cached_accessor_is_stable_within_a_process() {
        assert_eq!(is_resource_constrained(), is_resource_constrained());
    }
}
