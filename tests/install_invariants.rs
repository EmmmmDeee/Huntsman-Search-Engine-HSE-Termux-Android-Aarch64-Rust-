//! Invariants for the Termux wrapper scripts `install.sh` generates.
//!
//! `install.sh` writes several standalone shell programs into `$PREFIX/bin` via
//! quoted heredocs (`hse-bg`, `hse-watch`, the Termux:Boot script). They are
//! real, shipped programs that no Rust test would otherwise ever look at, and
//! `bash -n`/ShellCheck only see the *installer*, not the text it emits. These
//! guards read the emitted bodies back out of `install.sh` and pin the
//! properties that are easy to get wrong and impossible to notice off-device.

use std::fs;
use std::path::Path;

fn install_sh() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh")).unwrap()
}

/// The body of the quoted heredoc introduced by `<<'TAG'`, i.e. everything up to
/// the line that is exactly `TAG`. Panics if the heredoc is absent, so renaming
/// a wrapper fails loudly here instead of silently skipping its checks.
fn heredoc(script: &str, tag: &str) -> String {
    let open = format!("<<'{tag}'");
    let start = script
        .find(&open)
        .unwrap_or_else(|| panic!("install.sh no longer contains a `{open}` heredoc"));
    let after = &script[start + open.len()..];
    let end = after
        .lines()
        .scan(0usize, |off, l| {
            let at = *off;
            *off += l.len() + 1;
            Some((at, l))
        })
        .find(|(_, l)| l.trim_end() == tag)
        .unwrap_or_else(|| panic!("unterminated `{tag}` heredoc in install.sh"))
        .0;
    after[..end].to_string()
}

/// A shell comment cannot execute, so a wrapper is free to *mention* the raw
/// wake-lock calls while explaining why it does not make them. Only real code
/// is checked. (The shebang, written outside the heredoc, is not seen here.)
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// Every generated program that must not touch the raw Termux wake-lock.
const WAKE_LOCK_WRAPPERS: &[&str] = &["WRAPPER", "WATCH", "BOOT"];

/// The long-lived programs that must actively MANAGE the shared lock. The
/// Termux:Boot script is deliberately absent: it only launches the two below,
/// each of which registers itself, so a lock of its own would be an unowned
/// holder nothing ever releases.
const WAKE_LOCK_MANAGERS: &[&str] = &["WRAPPER", "WATCH"];

#[test]
fn generated_wrappers_never_release_the_shared_wake_lock_directly() {
    // Termux's `termux-wake-lock` / `termux-wake-unlock` act on ONE app-wide
    // lock — they are not reference counted. `hse-bg` and `hse-watch` are
    // designed to run at the same time (the Termux:Boot script starts BOTH, and
    // docs/AUTONOMY.md documents that as the set-and-forget configuration), so a
    // direct `termux-wake-unlock` in either one releases the lock the OTHER is
    // still relying on. The observable failure is silent and severe: stop the
    // web UI with `hse-bg stop` and the still-running `hse-watch` loses wake-lock
    // protection, so Android kills unattended collection at screen-off.
    //
    // Therefore no generated wrapper may call the raw unlock. They must go
    // through the refcounted helper, which only drops the shared lock once the
    // last holder is gone.
    let script = install_sh();
    let mut offenders = Vec::new();
    for tag in WAKE_LOCK_WRAPPERS {
        let body = heredoc(&script, tag);
        for (i, line) in body.lines().enumerate().filter(|(_, l)| !is_comment(l)) {
            // The helper's own definition is not one of these wrappers.
            if line.contains("termux-wake-unlock") {
                offenders.push(format!(
                    "heredoc {tag} line {}: releases the shared wake-lock directly: {}",
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "generated wrapper(s) call `termux-wake-unlock` directly, which yanks the \
         process-global wake-lock out from under a concurrently-running wrapper \
         (hse-bg + hse-watch are started together by the boot script). Route every \
         release through the refcounted helper instead:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn wrappers_acquire_the_wake_lock_through_the_refcounted_helper() {
    // The mirror of the check above: acquiring must also be registered, or the
    // refcount can never know a second holder exists.
    let script = install_sh();
    let mut offenders = Vec::new();
    for tag in WAKE_LOCK_WRAPPERS {
        let body = heredoc(&script, tag);
        for (i, line) in body.lines().enumerate().filter(|(_, l)| !is_comment(l)) {
            let l = line.trim();
            // `termux-wake-lock` may only appear as part of the helper call, not
            // as a bare invocation.
            if l.contains("termux-wake-lock") {
                offenders.push(format!(
                    "heredoc {tag} line {}: acquires the shared wake-lock directly: {l}",
                    i + 1
                ));
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "generated wrapper(s) call `termux-wake-lock` directly instead of registering \
         with the refcounted helper, so the helper cannot tell how many holders \
         remain:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn long_running_wrappers_actually_manage_the_shared_wake_lock() {
    // The mirror image of the two checks above, and the reason they are not
    // enough on their own: forbidding the RAW calls is satisfied just as well by
    // a wrapper that stopped doing wake-lock management altogether. That would
    // silently reintroduce the original bug — Android killing the process at
    // screen-off — while every "no raw call" assertion still passed. So the
    // long-lived programs must be shown to acquire AND release through the
    // helper, and to source it in the first place.
    let script = install_sh();
    let mut missing = Vec::new();
    for tag in WAKE_LOCK_MANAGERS {
        let body = heredoc(&script, tag);
        let code: String = body
            .lines()
            .filter(|l| !is_comment(l))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in [
            "HSE_WAKELOCK_HELPER",
            "hse_wakelock_acquire",
            "hse_wakelock_release",
        ] {
            if !code.contains(needle) {
                missing.push(format!("heredoc {tag} never calls `{needle}`"));
            }
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "a long-running wrapper stopped managing the shared wake-lock. Dropping \
         management entirely still satisfies the \"no raw termux-wake-* calls\" \
         guards, but reintroduces screen-off kills:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn generated_wrappers_do_not_hardcode_the_termux_prefix() {
    // A literal `/data/data/com.termux/files/usr` shebang breaks every Termux
    // fork and any install whose prefix differs. `install.sh` knows the real
    // prefix at generation time, so the emitted programs should carry it rather
    // than a compiled-in guess.
    let script = install_sh();
    let mut offenders = Vec::new();
    for tag in ["WRAPPER", "WATCH", "BOOT", "WAKELOCK"] {
        // WAKELOCK may not exist yet in older revisions; skip rather than panic.
        if !script.contains(&format!("<<'{tag}'")) {
            continue;
        }
        let body = heredoc(&script, tag);
        for (i, line) in body.lines().enumerate().filter(|(_, l)| !is_comment(l)) {
            if line.contains("/data/data/com.termux") {
                offenders.push(format!(
                    "heredoc {tag} line {}: hardcodes the Termux prefix: {}",
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "generated wrapper(s) hardcode `/data/data/com.termux`, which breaks Termux \
         forks and non-default prefixes — emit the resolved $PREFIX instead:\n  {}",
        offenders.join("\n  ")
    );
}
