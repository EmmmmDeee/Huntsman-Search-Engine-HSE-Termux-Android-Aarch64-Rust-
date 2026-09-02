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

#[test]
fn tty_detection_happens_before_stdout_is_redirected_into_a_pipe() {
    // `exec > >(tee -a "$LOG_FILE") 2>&1` replaces fd 1 with a PIPE (process
    // substitution always yields one). Every `[ -t 1 ]` / `[ -t 0 && -t 1 ]`
    // evaluated after that point is therefore unconditionally FALSE — not
    // "usually false", not "false when piped", but false on every install
    // including a fully interactive one.
    //
    // That silently disabled two things on real devices: colour output, and —
    // far worse — the `termux-setup-storage` prompt, so `~/storage` was never
    // linked and every sensor module (device_sensors, signal_radar, wifi_intel,
    // cell_intel) no-opped. The installer would cheerfully report success while
    // the GEOINT half of the product was inert.
    //
    // So interactivity must be sampled BEFORE the redirect and cached.
    let script = install_sh();
    // Locate the redirect by LINE, skipping comments — the explanation above it
    // necessarily quotes `exec > >(tee …)`, and a naive substring search would
    // match that prose instead of the command it describes.
    let redirect_line = script
        .lines()
        .position(|l| !is_comment(l) && l.contains("exec > >(tee"))
        .expect("install.sh no longer mirrors output into the log with `exec > >(tee …)`");
    let mut late = Vec::new();
    for (i, line) in script.lines().enumerate() {
        if is_comment(line) || i <= redirect_line {
            continue;
        }
        if line.contains("-t 1") || line.contains("-t 0") {
            late.push(format!("install.sh:{}: {}", i + 1, line.trim()));
        }
    }
    assert!(
        late.is_empty(),
        "install.sh tests for a terminal AFTER `exec > >(tee …)` has already made \
         fd 1 a pipe, so the test can never be true — colour and the \
         termux-setup-storage prompt are dead code. Sample interactivity before \
         the redirect and cache it (e.g. INTERACTIVE=1):\n  {}",
        late.join("\n  ")
    );
}

/// A shell comment cannot execute, so a wrapper is free to *mention* the raw
/// wake-lock calls while explaining why it does not make them. Only real code
/// is checked. (The shebang, written outside the heredoc, is not seen here.)
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

#[test]
fn play_store_termux_is_detected_and_rejected_before_any_package_work() {
    // Termux from the Play Store is abandoned (Google blocked its
    // self-update in 2020) — `pkg`/`apt-get` mirror access fails deep into
    // the install with a confusing, unrelated-looking network error.
    // Detecting it up front and dying with the exact remediation (reinstall
    // from F-Droid) turns that into an instant, actionable failure instead
    // of a mystery one 10+ steps later. This has no automated coverage
    // anywhere else in the repo (confirmed: `termux-build-info`/`playstore`
    // appear nowhere under `tests/` or `src/` besides this test).
    let script = install_sh();
    let detect_line = script
        .lines()
        .position(|l| !is_comment(l) && l.contains("termux-build-info"))
        .expect(
            "install.sh no longer reads termux-build-info — the Play Store \
             Termux detector may have been removed",
        );
    // Must be nested inside the IS_TERMUX detection branch (a few lines
    // above this file's own `IS_TERMUX=1`), so a refactor that hoists it
    // above Termux detection — and thus stats an absolute Termux-only path
    // on every OS — is caught here rather than silently changing behavior
    // on non-Termux hosts.
    let before: String = script
        .lines()
        .take(detect_line)
        .filter(|l| !is_comment(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        before.contains("IS_TERMUX=1"),
        "the termux-build-info read must be inside the IS_TERMUX detection branch"
    );
    let window: String = script
        .lines()
        .skip(detect_line)
        .take(8)
        .filter(|l| !is_comment(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        window.to_lowercase().contains("playstore"),
        "the Play Store marker check has gone missing or been renamed: {window}"
    );
    assert!(
        window.contains("-qi") || window.contains("grep -i"),
        "the Play Store marker match must be case-insensitive (grep -qi/-i): {window}"
    );
    assert!(
        window.contains("die "),
        "an abandoned Play Store Termux must be a hard failure (die), not a \
         warning that lets the broken install proceed: {window}"
    );
    assert!(
        window.contains("f-droid.org"),
        "the failure message must point the operator at the actual fix (F-Droid): {window}"
    );
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
