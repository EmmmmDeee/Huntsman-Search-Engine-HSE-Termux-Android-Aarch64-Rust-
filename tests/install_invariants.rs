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
/// Termux:Boot script is deliberately absent: it only launches the others,
/// each of which registers itself, so a lock of its own would be an unowned
/// these lists were first written and unguarded until
/// `every_wake_lock_touching_heredoc_is_guarded` started deriving the set.
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

/// The lists above are hand-maintained; this derives the set from install.sh
/// itself so a new generated program that touches the shared wake-lock (the
/// cannot ship without joining the guards.
#[test]
fn every_wake_lock_touching_heredoc_is_guarded() {
    let script = install_sh();
    let mut tags: Vec<String> = script
        .lines()
        .filter_map(|l| {
            let i = l.find("<<'")?;
            let rest = &l[i + 3..];
            let end = rest.find('\'')?;
            Some(rest[..end].to_string())
        })
        .collect();
    tags.sort();
    tags.dedup();
    assert!(
        tags.len() >= 5,
        "expected install.sh's generated-program heredocs, saw {tags:?}"
    );
    let mut unguarded = Vec::new();
    for tag in &tags {
        if tag == "WAKELOCK" {
            continue; // the refcounted helper's own definition
        }
        let body = heredoc(&script, tag);
        let touches = body
            .lines()
            .filter(|l| !is_comment(l))
            .any(|l| l.contains("hse_wakelock_") || l.contains("termux-wake-"));
        if touches && !WAKE_LOCK_WRAPPERS.contains(&tag.as_str()) {
            unguarded.push(tag.clone());
        }
    }
    assert!(
        unguarded.is_empty(),
        "install.sh heredoc(s) touch the shared wake-lock but are not in \
         WAKE_LOCK_WRAPPERS (and, if long-running, WAKE_LOCK_MANAGERS): {unguarded:?}"
    );
}

/// `df -m` is not portable to the target platform, and using it kills the
/// installer outright.
///
/// Observed on a real Termux aarch64 device: an install whose every step
/// succeeded — binary written, revision verified, wrappers installed, keys
/// provisioned, `hse doctor` run — ended in `Installation failed (exit 1)`, and
/// `hse update` reported `error: installer exited 1`. The cause was a single
/// `df -Pm` in the OPTIONAL local-AI step. Termux's toybox `df` has no `-m`, so
/// it exits 1; `2>/dev/null` hides the diagnostic; `set -o pipefail` promotes it
/// to a failed pipeline; a bare assignment inherits that status; and `set -e`
/// kills the shell before any of that function's `return 0` guards can run.
///
/// The installer had already learned this once — its preflight disk check
/// carries a comment saying toybox "does NOT implement `-m`" and uses `-Pk`
/// with an `NF >= 4` guard and a `|| true`. This pins that lesson so the
/// portable form cannot silently regress at a second call site.
#[test]
fn no_df_invocation_uses_the_non_portable_megabyte_flag() {
    let script = install_sh();
    // Find `df` as a COMMAND word, then read the option bundle after it.
    //
    // The command word is rarely the bare token `df`: in this script the real
    // call site reads `avail=$(df -Pk ...`, so the token is `avail=$(df`. An
    // earlier version of this check compared tokens against `"df"` and so
    // passed happily on a file that still contained `df -Pm` — a lock that
    // locked nothing. Match on the boundary character before `df` instead.
    fn df_options(line: &str) -> Vec<&str> {
        let mut out = Vec::new();
        for (i, _) in line.match_indices("df") {
            let before_ok = line[..i]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.');
            let rest = &line[i + 2..];
            // A command word is followed by whitespace, and `df` must not be a
            // suffix of a longer word (`pdf`, `dfu`) nor a path component.
            if !before_ok || !rest.starts_with(char::is_whitespace) {
                continue;
            }
            out.extend(
                rest.split_whitespace()
                    .take_while(|w| w.starts_with('-'))
                    .collect::<Vec<_>>(),
            );
        }
        out
    }
    let offenders: Vec<String> = script
        .lines()
        .enumerate()
        .filter(|(_, l)| !is_comment(l))
        // A `df` call whose option bundle carries `m`: `-m`, `-Pm`, `-hm`, …
        .filter(|(_, l)| df_options(l).iter().any(|w| w.contains('m')))
        .map(|(n, l)| format!("install.sh:{}: {}", n + 1, l.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "toybox `df` (Termux) has no `-m`, and under `set -euo pipefail` that \
         exits the whole installer — use the `df -Pk` + `NF >= 4` + `|| true` \
         form the preflight check already established: {offenders:?}"
    );
}

/// Revision resolution runs before git is installed, so it must not need git.
///
/// Observed on a fresh Termux device: `git unavailable — cannot resolve the
/// target revision`, then a sha256-verified prebuilt rejected, then a full
/// on-device Rust build — the one outcome the prebuilt path exists to avoid.
/// The cause is ordering: `resolve_target_sha` runs at the top of the script
/// while the `pkg install` that provides git is ~20 lines further down, so on a
/// first install `git ls-remote` could never succeed.
///
/// Moving the package install earlier would be the wrong fix — it forces the
/// whole toolchain on someone a prebuilt would have served. So the resolver
/// gained a curl-based GitHub API path, and this pins both halves of the
/// invariant: the ordering that makes git unavailable, and the git-free
/// fallback that copes with it.
#[test]
fn revision_resolution_does_not_depend_on_a_package_installed_later() {
    let script = install_sh();
    let line_of = |needle: &str| {
        script
            .lines()
            .position(|l| l.contains(needle) && !is_comment(l))
            .unwrap_or_else(|| panic!("install.sh no longer contains `{needle}`"))
    };
    let resolve_at = line_of("resolve_target_sha || true");
    let git_installed_at = line_of("Installing Termux packages");
    assert!(
        resolve_at < git_installed_at,
        "sanity: this guard exists because resolution (line {}) precedes the \
         package install that provides git (line {})",
        resolve_at + 1,
        git_installed_at + 1
    );

    // Therefore the resolver must have a path that works without git.
    assert!(
        script.contains("_sha_via_github_api"),
        "resolve_target_sha runs before git exists, so it needs a git-free \
         fallback — otherwise every first install rejects its prebuilt and pays \
         for a full source build"
    );
    let api_fn = script
        .split_once("_sha_via_github_api() {")
        .expect("the fallback must be a real function")
        .1;
    assert!(
        api_fn.contains("api.github.com"),
        "the git-free fallback must actually resolve the ref remotely"
    );
}

/// Never claim a revision MISMATCH when the revision was never resolved.
///
/// The device transcript said `built from a different commit than main` on a run
/// whose previous line was `cannot resolve the target revision` — asserting the
/// result of a comparison that never happened. Same class as `hse doctor`
/// reporting "no failure streak" from a tracker it never populated.
#[test]
fn a_prebuilt_is_never_called_wrong_when_the_target_is_unknown() {
    let script = install_sh();
    // The LOG LINE, not the comment above it that quotes the same text — an
    // earlier version of this check matched its own explanatory comment and
    // passed regardless of the code.
    let (n, _) = script
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("built from a different commit than") && !is_comment(l))
        .expect("install.sh no longer emits the mismatch message");
    // The claim must sit behind a check that the target is actually known.
    let all: Vec<&str> = script.lines().collect();
    let window = all[n.saturating_sub(6)..n].join("\n");
    assert!(
        window.contains("-n \"$TARGET_SHA\""),
        "the mismatch message must sit behind a `[[ -n \"$TARGET_SHA\" ]]` guard: \
         with no resolved target the honest statement is that it could not be \
         checked, not that the binary is wrong"
    );
}
