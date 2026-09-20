//! Invariants for the Termux wrapper scripts `install.sh` generates.
//!
//! `install.sh` writes several standalone shell programs into `$PREFIX/bin` via
//! quoted heredocs (`hse-bg`, `hse-watch`, the Termux:Boot script). They are
//! real, shipped programs that no Rust test would otherwise ever look at, and
//! `bash -n`/ShellCheck only see the *installer*, not the text it emits. These
//! guards read the emitted bodies back out of `install.sh` and pin the
//! properties that are easy to get wrong and impossible to notice off-device.

mod reconciler_harness;

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
    for tag in ["WRAPPER", "WATCH", "BOOT", "WAKELOCK", "TEST"] {
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

// removed-integration-cleanup: begin — this test names the artifacts the
// installer purges, and is exempt from the live-tree name ban for that reason.
#[test]
fn an_upgrade_purges_the_retired_local_ai_wrapper() {
    // Releases up to 2026-09-04 wrote an `hse-ai` wrapper that ran a local
    // model server under the shared HSE wake-lock, put a model name in
    // ~/.huntsman.env and kept a pid/log pair in ~/.cache. Removing the
    // integration from the tree did nothing about a device that already had
    // all of that: the wrapper stayed executable after the code using it was
    // gone. The installer's idempotent upgrade path must retire it — and must
    // do so AFTER `hse provision` has written the env file it edits, and only
    // inside the region the architecture lock exempts from the name ban.
    // Built from parts so no line of THIS file carries a whole marker: the
    // architecture lock's walker toggles on marker lines, and a literal
    // "…: end" here would end the exemption for this test early.
    const MARK: &str = "removed-integration-cleanup";
    let script = install_sh();
    let begin = script
        .find(&format!("{MARK}: begin"))
        .expect("install.sh carries the removed-integration cleanup region");
    let end = script[begin..]
        .find(&format!("{MARK}: end"))
        .map(|i| begin + i)
        .expect("the cleanup region is terminated");
    let region = &script[begin..end];
    for needle in [
        "purge_removed_integration() {",
        "\"$HSE_BIN_DIR/hse-ai\"",
        "hse-ai.pid",
        "hse-ai.log",
        "^HUNTSMAN_OLLAMA_MODEL=",
        "purge_removed_integration || log_warn",
    ] {
        assert!(
            region.contains(needle),
            "the cleanup region must contain `{needle}`; region was:\n{region}"
        );
    }
    let provision = script
        .find("provision --env-only --discover")
        .expect("install.sh delegates key provisioning to `hse provision`");
    assert!(
        provision < begin,
        "the purge edits ~/.huntsman.env, so it must run after `hse provision` has written it"
    );
    let record = script
        .find("HUNTSMAN_INSTALL_DIR=%s")
        .expect("install.sh records HUNTSMAN_INSTALL_DIR for `hse update`");
    assert!(
        end < record,
        "the purge must run before the env file is rewritten for HUNTSMAN_INSTALL_DIR"
    );
}
// removed-integration-cleanup: end

#[test]
fn the_boot_script_is_regenerated_when_it_is_the_installers_own() {
    // hse-bg, hse-watch and the wake-lock helper are rewritten on every
    // install, so upgrades pick up their fixes; the Termux:Boot script was the
    // one write-once exception, so a device that installed before the boot
    // body gained `hse-watch start` never received it. It is now regenerated
    // whenever the installer can call the existing file its own — marked, or
    // consisting only of comments and `hse-*` commands — and stamped with the
    // managed marker so the next upgrade recognises it without the heuristic.
    let script = install_sh();
    let block = script
        .split("BOOT_SCRIPT=\"$BOOT_DIR/hse-autostart\"")
        .nth(1)
        .expect("install.sh installs a Termux:Boot script");
    let guard = block
        .lines()
        .find(|l| l.contains("if [[ ! -f \"$BOOT_SCRIPT\" ]]"))
        .expect("the boot script has an existence guard");
    assert!(
        guard.contains("_hse_is_owned \"$BOOT_SCRIPT\""),
        "a managed boot script must be regenerated, not kept forever: {guard}"
    );
    assert!(
        block.contains(
            "grep -qvE '^[[:space:]]*(#|hse-(bg|watch)([[:space:]]|$)|$)' \"$BOOT_SCRIPT\""
        ),
        "an unmarked script from an earlier installer (comments and hse-* commands only) must be recognised as ours"
    );
    assert!(
        block.contains("printf '# %s\\n' \"$HSE_MANAGED_MARKER\" >> \"$BOOT_SCRIPT\""),
        "the regenerated boot script must carry the managed marker"
    );
    let body = heredoc(block, "BOOT");
    assert!(
        body.contains("hse-bg start") && body.contains("hse-watch start"),
        "the boot body starts both long-running wrappers"
    );
}

#[test]
fn hse_test_is_an_owned_path_wrapper_and_never_touches_operator_state() {
    // Observed on-device 2026-09-15: a curl-pipe prebuilt install left the
    // operator at `~` with no source tree, so the README's next command
    // (`scripts/standard-test.sh`) 404'd. `hse-test` is the PATH-level
    // replacement: same acceptance run, installed next to `hse`, isolated
    // HOME so it cannot read/write ~/.huntsman.env or the operator DB.
    let script = install_sh();
    assert!(
        script.contains("HSE_OWNED_NAMES=(hse hse-bg hse-watch hse-wakelock hse-test)"),
        "hse-test must be in HSE_OWNED_NAMES so stale copies are purged and the \
         current one is never treated as a duplicate"
    );
    assert!(
        script.contains("TEST_WRAPPER=\"$HSE_BIN_DIR/hse-test\""),
        "install.sh must write hse-test into the bin dir"
    );
    let body = heredoc(&script, "TEST");
    assert!(
        body.contains("export HOME=\"$RUN_HOME\""),
        "hse-test must isolate HOME so the acceptance run cannot touch operator state"
    );
    assert!(
        body.contains("mktemp -d"),
        "the isolated HOME must be a throwaway directory"
    );
    assert!(
        body.contains("--output dossier"),
        "the acceptance run must print the full unredacted dossier"
    );
    assert!(
        !body.contains("termux-wake-") && !body.contains("hse_wakelock_"),
        "hse-test is a foreground one-shot; it must not hold a wake-lock"
    );
    assert!(
        script.contains("hse-autoupdate.stamp")
            && script.find("hse-autoupdate.stamp").unwrap()
                < script
                    .find("hse\" provision --env-only --discover")
                    .unwrap(),
        "the auto-update throttle stamp must be written BEFORE `hse provision`, \
         which is the first CLI invocation and used to spawn a background rebuild"
    );
}

#[test]
fn post_install_quick_start_names_hse_test() {
    let script = install_sh();
    let start = script
        .find("CLI quick start:")
        .expect("install.sh prints a CLI quick start");
    let block = &script[start..];
    assert!(
        block.contains("hse-test"),
        "the post-install quick start must name `hse-test` so a curl-pipe \
         operator is not sent to `scripts/standard-test.sh` from ~"
    );
}

// ─── Functional coverage of the post-install verify-and-rollback path ────────
//
// Everything above reads install.sh as text. The rollback branch, though, only
// fires on a *botched* upgrade — an install that reports the wrong revision —
// and is therefore invisible on every healthy run, so a transcription-style
// text assertion could never prove it actually restores anything. install.sh
// exposes the logic as the function `hse_verify_or_rollback` plus a
// `__verify_or_rollback` test hook that runs just that function in isolation
// and exits with its status. These tests drive the REAL installer code (not a
// copy of it) against fake binaries and assert the true filesystem outcome:
// when verification fails, the previous binary is put back.

#[cfg(unix)]
fn write_exec(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).unwrap();
    let mut perm = fs::metadata(path).unwrap().permissions();
    perm.set_mode(0o755);
    fs::set_permissions(path, perm).unwrap();
}

#[cfg(unix)]
fn run_verify(home: &Path, installed: &Path, rollback: &str, target: &str) -> std::process::Output {
    use std::process::Command;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    Command::new("bash")
        .arg(script)
        .arg("__verify_or_rollback")
        .arg(installed)
        .arg(rollback)
        .arg(target)
        // Only HOME is required (install.sh's log dir lives under it); a fresh
        // temp HOME keeps the run from touching the developer's real cache.
        .env("HOME", home)
        .env_remove("HSE_ALLOW_SHA_MISMATCH")
        .output()
        .expect("run install.sh __verify_or_rollback")
}

#[cfg(unix)]
#[test]
fn rollback_restores_the_previous_binary_when_verification_fails() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".cache")).unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();

    // The freshly-installed binary reports the WRONG revision …
    let installed = bin.join("hse");
    write_exec(
        &installed,
        "#!/bin/sh\n[ \"$1\" = build-sha ] && echo 0000000000000000000000000000000000000000\n",
    );
    // … and the previous binary was preserved before the atomic swap.
    let rollback = bin.join(".hse.prev.test");
    write_exec(&rollback, "#!/bin/sh\necho I-AM-THE-PREVIOUS-BINARY\n");

    let target = "1111111111111111111111111111111111111111";
    let out = run_verify(&home, &installed, rollback.to_str().unwrap(), target);

    assert!(
        !out.status.success(),
        "a wrong-revision install must fail, not silently pass"
    );
    // The whole point of the rollback: the device is left on the previous
    // WORKING binary, never a wrong-but-newer-looking one.
    let restored = fs::read_to_string(&installed).unwrap();
    assert!(
        restored.contains("I-AM-THE-PREVIOUS-BINARY"),
        "the previous binary must be restored over the failed install, got:\n{restored}"
    );
    assert!(
        !rollback.exists(),
        "the rollback copy must be cleaned up after it is used"
    );
}

#[cfg(unix)]
#[test]
fn a_verified_install_keeps_the_new_binary_and_drops_the_rollback_copy() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".cache")).unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();

    let target = "2222222222222222222222222222222222222222";
    let installed = bin.join("hse");
    write_exec(
        &installed,
        &format!("#!/bin/sh\n[ \"$1\" = build-sha ] && echo {target}\n"),
    );
    let rollback = bin.join(".hse.prev.test");
    write_exec(&rollback, "#!/bin/sh\necho OLD\n");

    let out = run_verify(&home, &installed, rollback.to_str().unwrap(), target);

    assert!(
        out.status.success(),
        "a matching revision must verify clean"
    );
    let kept = fs::read_to_string(&installed).unwrap();
    assert!(
        kept.contains(target),
        "the verified new binary must be kept in place"
    );
    assert!(
        !rollback.exists(),
        "the rollback copy must be discarded once verification passes"
    );
}

#[cfg(unix)]
#[test]
fn an_unresolved_target_revision_is_accepted_without_a_rollback() {
    // Mirrors the elif branch: the build produced no verifiable revision
    // (TARGET_SHA empty). The standing contract is to WARN, not fail, and to
    // leave the installed binary in place — pin it so a later edit can't
    // silently turn an unverifiable-but-intended build into a hard failure.
    let tmp = tempfile::tempdir().expect("temp dir");
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".cache")).unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();

    let installed = bin.join("hse");
    write_exec(&installed, "#!/bin/sh\necho unused\n");

    let out = run_verify(&home, &installed, "", "");
    assert!(
        out.status.success(),
        "an unresolved target revision must be accepted (warn), not fail the install"
    );
    assert!(
        installed.exists(),
        "the installed binary must be left in place when no revision could be resolved"
    );
}

#[test]
fn the_installer_delegates_post_install_verification_to_the_tested_function() {
    // The functional proofs above are only meaningful if the REAL install flow
    // calls the same function they drive, rather than re-growing an inline copy
    // the tests never touch. Pin the single authority: the flow delegates, and
    // no inline transcription of the check survives alongside it.
    let s = install_sh();
    assert!(
        s.contains("hse_verify_or_rollback \"$HSE_BIN_DIR/hse\" \"$ROLLBACK_BIN\" \"$TARGET_SHA\""),
        "the install flow must delegate post-install verification to hse_verify_or_rollback"
    );
    assert!(
        !s.contains("INSTALLED_SHA="),
        "post-install verification must live only in hse_verify_or_rollback, not re-inlined"
    );
}

// ─── Termux:API detection and the capability reconciler ─────────────────────
//
// install.sh's Termux:API step used to probe `termux-info` to decide whether
// the `termux-api` package was installed. `termux-info` ships in `termux-tools`
// on EVERY Termux install, so `pkg install termux-api` never ran and the
// installer reported "termux-api CLI present" on devices that had no sensor
// tool at all (provenance: 69b17eb, PR #585). The installer now probes the
// canonical core-tool list and judges an install by its postcondition;
// `scripts/reconcile.sh` applies the same change to an older checkout as a
// snapshot → patch → verify → rollback transaction. These guards pin the
// installer's shape, hold the reconciler's embedded block byte-for-byte
// against it, and drive the transaction end to end through bash + git.

fn reconciler_sh() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/reconcile.sh")).unwrap()
}

/// The body of `<<'TAG'` … `TAG` as the shell sees it: `heredoc` returns the
/// text from just after the opening tag (i.e. the rest of that line first), so
/// drop that remainder and the newline that precedes the terminator.
fn heredoc_body(script: &str, tag: &str) -> String {
    let raw = heredoc(script, tag);
    let (_, body) = raw.split_once('\n').expect("heredoc opener line");
    body.strip_suffix('\n').unwrap_or(body).to_string()
}

/// The single-quoted scalar `NAME='…'` defined at the reconciler's top level.
fn reconciler_scalar<'a>(reconciler: &'a str, name: &str) -> &'a str {
    let open = format!("{name}='");
    let line = reconciler
        .lines()
        .find(|l| l.starts_with(&open))
        .unwrap_or_else(|| panic!("scripts/reconcile.sh no longer defines `{name}`"));
    line[open.len()..]
        .strip_suffix('\'')
        .expect("closing quote")
}

/// The reconciler's fixed block, rendered exactly as it writes it: the
/// `INSTALLER_FIX_REGION` template with the tool list substituted from the
/// script's own top-level TERMUX_API_CORE_TOOLS definition.
fn reconciler_fix_region(reconciler: &str) -> String {
    let tools = reconciler
        .lines()
        .find_map(|l| l.strip_prefix("TERMUX_API_CORE_TOOLS=("))
        .and_then(|rest| rest.strip_suffix(')'))
        .expect("scripts/reconcile.sh defines TERMUX_API_CORE_TOOLS at top level");
    heredoc_body(reconciler, "INSTALLER_FIX_REGION").replace("@TERMUX_API_CORE_TOOLS@", tools)
}

/// Presence is not readiness: the installer must probe the sensor tools it
/// actually needs, and must judge `pkg install` by re-probing them — never by
/// `termux-info` (always present) or by pkg's exit status.
#[test]
fn termux_api_detection_probes_the_core_tools_by_postcondition() {
    let script = install_sh();
    let sentinels: Vec<String> = script
        .lines()
        .enumerate()
        .filter(|(_, l)| !is_comment(l) && l.contains("termux-info"))
        .map(|(n, l)| format!("install.sh:{}: {}", n + 1, l.trim()))
        .collect();
    assert!(
        sentinels.is_empty(),
        "`termux-info` ships in termux-tools on every Termux install, so it proves \
         nothing about the termux-api package:\n  {}",
        sentinels.join("\n  ")
    );
    let defs = script
        .lines()
        .filter(|l| l.trim().starts_with("TERMUX_API_CORE_TOOLS=("))
        .count();
    assert_eq!(
        defs, 1,
        "the core-tool list is defined exactly once in install.sh"
    );

    let lines: Vec<&str> = script.lines().collect();
    let pkg_at = lines
        .iter()
        .position(|l| !is_comment(l) && l.contains("pkg install -y termux-api"))
        .expect("install.sh still installs termux-api");
    let window = &lines[pkg_at..pkg_at + 3];
    assert!(
        !window.iter().any(|l| l.contains("&& ok")),
        "a success line must not be chained to pkg's exit status: {window:?}"
    );
    let after = |from: usize, needle: &str| -> usize {
        lines[from..]
            .iter()
            .position(|l| !is_comment(l) && l.contains(needle))
            .map_or_else(
                || panic!("`{needle}` must follow line {}", from + 1),
                |i| from + i,
            )
    };
    let hash_at = after(pkg_at, "hash -r");
    let reprobe_at = after(hash_at, "$(termux_api_missing_tools)");
    let report_at = after(reprobe_at, "ok \"Installed termux-api");
    assert!(
        pkg_at < hash_at && hash_at < reprobe_at && reprobe_at < report_at,
        "order must be: pkg install → hash -r → re-probe the same tool set → report"
    );
}

/// The reconciler rewrites an older checkout's block into the one that ships:
/// its embedded fix must BE the installer's block, byte for byte, and its
/// embedded defect must be gone from the installer.
#[test]
fn the_reconciler_writes_exactly_the_installer_block_that_ships() {
    let script = install_sh();
    let reconciler = reconciler_sh();
    let fix = reconciler_fix_region(&reconciler);
    assert_eq!(
        script.matches(&fix).count(),
        1,
        "install.sh must contain the reconciler's rendered fixed block verbatim, exactly \
         once. If the installer's termux-api block was edited on purpose, update the \
         INSTALLER_FIX_REGION heredoc in scripts/reconcile.sh to match.\n--- block ---\n{fix}"
    );
    let bug = heredoc_body(&reconciler, "INSTALLER_BUG_REGION");
    assert!(
        !script.contains(&bug),
        "install.sh still carries the defective block"
    );
    let sentinel = reconciler_scalar(&reconciler, "INSTALLER_BUG_SENTINEL");
    assert!(
        bug.lines().any(|l| l == sentinel),
        "the sentinel the reconciler locates the defect by must be a line of the \
         defective block it embeds"
    );
    assert!(
        bug.lines().next().is_some_and(|l| !l.trim().is_empty()),
        "the defective block must open with the line the reconciler anchors on"
    );
}

#[cfg(unix)]
/// `bash -n FILE1 FILE2` syntax-checks only FILE1 — FILE2 becomes its `$1` —
/// so a joint invocation covers less than it reads as covering. Every
/// `bash -n` in the CI workflow and the local gate must name exactly one
/// script. (Found by review on this very change, which first shipped the
/// joint form in ci.yml.)
#[test]
fn every_bash_syntax_check_names_exactly_one_script() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut seen = 0;
    for rel in [".github/workflows/ci.yml", "scripts/gate.sh"] {
        let text = fs::read_to_string(root.join(rel)).unwrap();
        for (i, line) in text.lines().enumerate().filter(|(_, l)| !is_comment(l)) {
            let Some(rest) = line.split("bash -n").nth(1) else {
                continue;
            };
            let args: Vec<&str> = rest
                .split_whitespace()
                .take_while(|w| !matches!(*w, "&&" | "||" | "|" | ";") && !w.starts_with('#'))
                .collect();
            assert_eq!(
                args.len(),
                1,
                "{rel}:{}: `bash -n` must check one script per invocation: {}",
                i + 1,
                line.trim()
            );
            seen += 1;
        }
    }
    assert!(
        seen >= 4,
        "expected the install.sh + reconcile.sh checks in both files, saw {seen}"
    );
}

mod reconciler_transaction {
    use super::*;
    use std::process::Command;

    /// A throwaway git checkout holding a defective installer.
    struct Fixture {
        dir: tempfile::TempDir,
        /// install.sh's bytes as committed — what a rollback must restore.
        before: String,
    }

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git must be installed to drive the reconciler tests");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Today's installer with the fixed block swapped back to the defective
    /// one, committed in a fresh repo — the shape every affected device holds.
    fn defective_checkout() -> Fixture {
        let reconciler = reconciler_sh();
        let fix = reconciler_fix_region(&reconciler);
        let bug = heredoc_body(&reconciler, "INSTALLER_BUG_REGION");
        let installer = install_sh();
        assert_eq!(installer.matches(&fix).count(), 1);
        let before = installer.replacen(&fix, &bug, 1);
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("install.sh"), &before).unwrap();
        fs::write(dir.path().join("README.md"), "fixture\n").unwrap();
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["add", "."]);
        git(
            dir.path(),
            &["commit", "-q", "-m", "fixture: defective installer"],
        );
        Fixture { dir, before }
    }

    /// The host's `PATH` minus `cargo`: every executable on the host's `PATH`
    /// is mirrored by symlink into one directory (first hit wins, as lookup
    /// does), except the cargo front-end, so the reconciler's Rust
    /// verification is an honest environment skip rather than a full build of
    /// this crate inside the fixture. Dropping whole directories would not do:
    /// on a distro or Termux install `cargo` shares `/usr/bin` or `$PREFIX/bin`
    /// with `git`, `bash` and everything else the fixture needs.
    fn path_without_cargo(mirror: &Path) -> std::ffi::OsString {
        fs::create_dir_all(mirror).expect("mirror dir");
        let host = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&host) {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let link = mirror.join(&name);
                if name == "cargo" || fs::symlink_metadata(&link).is_ok() {
                    continue;
                }
                let target = fs::canonicalize(entry.path()).unwrap_or_else(|_| entry.path());
                let _ = std::os::unix::fs::symlink(target, link);
            }
        }
        mirror.as_os_str().to_os_string()
    }

    /// Run the real reconciler in the fixture (`--repo-only --json` plus
    /// `extra`) and return its exit code and parsed final state.
    fn reconcile(fx: &Fixture, extra: &[&str]) -> (i32, serde_json::Value) {
        let path = path_without_cargo(&fx.dir.path().join("path-without-cargo"));
        let mut args = vec!["--repo-only", "--json"];
        args.extend_from_slice(extra);
        reconciler_harness::run(
            fx.dir.path(),
            &args,
            &[
                ("PATH", path.as_os_str()),
                ("HOME", fx.dir.path().as_os_str()),
            ],
        )
    }

    fn installer_in(fx: &Fixture) -> String {
        fs::read_to_string(fx.dir.path().join("install.sh")).unwrap()
    }

    fn tracked_changes(fx: &Fixture) -> String {
        let out = Command::new("git")
            .args(["status", "--porcelain", "--untracked-files=no"])
            .current_dir(fx.dir.path())
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn dry_run_and_verify_only_classify_the_defect_and_touch_nothing() {
        for (flag, mutation) in [("--dry-run", "would_apply"), ("--verify-only", "none")] {
            let fx = defective_checkout();
            let (code, json) = reconcile(&fx, &[flag]);
            assert_eq!(
                code, 2,
                "{flag}: a defective repository is degraded: {json}"
            );
            assert_eq!(
                json["repository"]["source"], "bug_present",
                "{flag}: {json}"
            );
            assert_eq!(json["repository"]["mutation"], mutation, "{flag}: {json}");
            assert_eq!(
                json["repository"]["final_state"], "bug_present",
                "{flag}: {json}"
            );
            assert_eq!(
                json["exit_code"], 2,
                "{flag}: the JSON carries the exit code"
            );
            assert_eq!(installer_in(&fx), fx.before, "{flag} must not mutate");
            assert_eq!(tracked_changes(&fx), "", "{flag} must leave the tree clean");
        }
    }

    #[test]
    fn the_transaction_patches_the_defect_into_the_shipped_installer_byte_for_byte() {
        let fx = defective_checkout();
        let (code, json) = reconcile(&fx, &[]);
        // No cargo on PATH: Rust verification is an environment skip, which is
        // reported as such and keeps the state at PATCH_APPLIED, never VERIFIED.
        assert_eq!(code, 2, "{json}");
        let r = &json["repository"];
        assert_eq!(r["source"], "bug_present", "{json}");
        assert_eq!(r["mutation"], "applied", "{json}");
        assert_eq!(r["shell_verify"], "pass", "{json}");
        assert_eq!(r["structural_verify"], "pass", "{json}");
        assert_eq!(r["rust_verify"], "skipped_environment", "{json}");
        assert_eq!(r["final_state"], "patch_applied", "{json}");
        assert_eq!(
            installer_in(&fx),
            install_sh(),
            "the patched installer must be exactly the one that ships"
        );
        assert_eq!(
            tracked_changes(&fx),
            " M install.sh\n",
            "only install.sh changes"
        );

        // Idempotent: on the fixed shape a second run rewrites nothing.
        git(fx.dir.path(), &["commit", "-q", "-am", "patched"]);
        let (code, json) = reconcile(&fx, &[]);
        assert_eq!(code, 0, "{json}");
        assert_eq!(json["repository"]["source"], "already_fixed", "{json}");
        assert_eq!(json["repository"]["mutation"], "unchanged", "{json}");
        assert_eq!(json["repository"]["final_state"], "already_fixed", "{json}");
        assert_eq!(tracked_changes(&fx), "");
    }

    /// A stand-in `cargo` at the front of the fixture's PATH, with a stub
    /// `Cargo.toml` so the preflight sees a crate. Every subcommand succeeds
    /// unless the environment says otherwise: `STUB_NO_RUN_EXIT` is the status
    /// of the pre-patch `cargo test … --no-run`, `STUB_RUN_EXIT` that of the
    /// post-patch test run. No real cargo is involved, so the attribution rule
    /// is exercised deterministically and in milliseconds.
    fn stub_cargo(fx: &Fixture) -> std::ffi::OsString {
        let bin = fx.dir.path().join("stub-cargo");
        fs::create_dir_all(&bin).unwrap();
        let cargo = bin.join("cargo");
        fs::write(
            &cargo,
            "#!/usr/bin/env bash\ncase \"$*\" in\n\
             \"test --locked --test install_invariants --no-run\") exit \"${STUB_NO_RUN_EXIT:-0}\" ;;\n\
             \"test --locked --test install_invariants\") exit \"${STUB_RUN_EXIT:-0}\" ;;\n\
             *) exit 0 ;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&cargo, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        fs::write(
            fx.dir.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        git(fx.dir.path(), &["add", "Cargo.toml"]);
        git(
            fx.dir.path(),
            &["commit", "-q", "-m", "fixture: stub crate"],
        );
        let mirror = path_without_cargo(&fx.dir.path().join("path-without-cargo"));
        std::env::join_paths([bin.as_os_str().to_os_string(), mirror])
            .expect("PATH with stub cargo")
    }

    /// Run the reconciler as `reconcile` does, but with the stub cargo on PATH
    /// and the given stub exit statuses.
    fn reconcile_with_stub_cargo(
        fx: &Fixture,
        no_run_exit: &str,
        run_exit: &str,
    ) -> (i32, serde_json::Value) {
        let path = stub_cargo(fx);
        reconciler_harness::run(
            fx.dir.path(),
            &["--repo-only", "--json"],
            &[
                ("PATH", path.as_os_str()),
                ("HOME", fx.dir.path().as_os_str()),
                ("STUB_NO_RUN_EXIT", std::ffi::OsStr::new(no_run_exit)),
                ("STUB_RUN_EXIT", std::ffi::OsStr::new(run_exit)),
            ],
        )
    }

    /// Rust verification is attributed by measurement. What fails BEFORE the
    /// patch is the environment's (a skip that keeps the patch and stops at
    /// PATCH_APPLIED); what fails only AFTER it is the patch's (a rollback);
    /// and a run that passes both halves is the only way to VERIFIED.
    #[test]
    fn rust_verification_is_attributed_by_measurement() {
        // Pre-patch build failure: environment. Patch kept, never a pass.
        let fx = defective_checkout();
        let (code, json) = reconcile_with_stub_cargo(&fx, "101", "0");
        assert_eq!(code, 2, "{json}");
        let r = &json["repository"];
        assert_eq!(r["mutation"], "applied", "{json}");
        assert_eq!(r["rust_verify"], "skipped_environment", "{json}");
        assert_eq!(r["final_state"], "patch_applied", "{json}");
        assert_eq!(installer_in(&fx), install_sh(), "the patch stays applied");
        assert!(
            json["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("unpatched tree"),
            "the reason must say the failure predates the patch: {json}"
        );

        // Post-patch test failure: the patch's. Rolled back and proven.
        let fx = defective_checkout();
        let before = installer_in(&fx);
        let (code, json) = reconcile_with_stub_cargo(&fx, "0", "101");
        assert_eq!(code, 6, "{json}");
        let r = &json["repository"];
        assert_eq!(r["mutation"], "rolled_back", "{json}");
        assert_eq!(r["shell_verify"], "pass", "{json}");
        assert_eq!(r["structural_verify"], "pass", "{json}");
        assert_eq!(r["rust_verify"], "fail", "{json}");
        assert_eq!(r["rollback"], "verified", "{json}");
        assert_eq!(r["final_state"], "failed", "{json}");
        assert_eq!(
            installer_in(&fx),
            before,
            "rollback restores the pre-run bytes"
        );
        assert_eq!(tracked_changes(&fx), "");

        // Both halves pass: VERIFIED, exit 0, patch kept.
        let fx = defective_checkout();
        let (code, json) = reconcile_with_stub_cargo(&fx, "0", "0");
        assert_eq!(code, 0, "{json}");
        let r = &json["repository"];
        assert_eq!(r["mutation"], "applied", "{json}");
        assert_eq!(r["rust_verify"], "pass", "{json}");
        assert_eq!(r["final_state"], "verified", "{json}");
        assert_eq!(installer_in(&fx), install_sh());
    }

    #[test]
    fn a_failed_required_verification_rolls_the_tree_back_and_proves_it() {
        let fx = defective_checkout();
        // Make `git diff --check` — a required structural check — reject the
        // patch: the fixed block is space-indented, so this whitespace rule
        // flags every added line. Nothing in the reconciler is bypassed.
        git(
            fx.dir.path(),
            &["config", "core.whitespace", "indent-with-non-tab"],
        );
        let (code, json) = reconcile(&fx, &[]);
        assert_eq!(code, 6, "{json}");
        let r = &json["repository"];
        assert_eq!(r["mutation"], "rolled_back", "{json}");
        assert_eq!(r["structural_verify"], "fail", "{json}");
        assert_eq!(r["rollback"], "verified", "{json}");
        assert_eq!(r["final_state"], "failed", "{json}");
        assert_eq!(
            installer_in(&fx),
            fx.before,
            "rollback must restore the pre-run bytes"
        );
        assert_eq!(
            tracked_changes(&fx),
            "",
            "rollback must leave the tree clean"
        );
    }

    #[test]
    fn a_dirty_tree_refuses_mutation() {
        let fx = defective_checkout();
        fs::write(fx.dir.path().join("README.md"), "edited\n").unwrap();
        let (code, json) = reconcile(&fx, &[]);
        assert_eq!(code, 4, "{json}");
        assert_eq!(json["repository"]["source"], "bug_present", "{json}");
        assert_eq!(json["repository"]["mutation"], "refused", "{json}");
        assert_eq!(json["repository"]["final_state"], "dirty", "{json}");
        assert_eq!(installer_in(&fx), fx.before);
    }

    #[test]
    fn an_unrecognised_source_shape_is_refused_not_guessed() {
        let fx = defective_checkout();
        // Same sentinel line, but the block around it is not the known one.
        let altered = fx.before.replacen(
            "# the APK from F-Droid is the actual sensor bridge.",
            "# (edited by hand)",
            1,
        );
        assert_ne!(altered, fx.before, "the fixture must actually be altered");
        fs::write(fx.dir.path().join("install.sh"), &altered).unwrap();
        git(fx.dir.path(), &["commit", "-q", "-am", "hand-edited"]);
        let (code, json) = reconcile(&fx, &[]);
        assert_eq!(code, 3, "{json}");
        assert_eq!(json["repository"]["source"], "unknown", "{json}");
        assert_eq!(json["repository"]["mutation"], "refused", "{json}");
        assert_eq!(
            installer_in(&fx),
            altered,
            "an unknown shape is never touched"
        );
    }

    #[test]
    fn verify_only_proves_the_shipped_installer_is_at_the_fixed_shape() {
        let fx = defective_checkout();
        fs::write(fx.dir.path().join("install.sh"), install_sh()).unwrap();
        git(fx.dir.path(), &["commit", "-q", "-am", "shipped installer"]);
        let (code, json) = reconcile(&fx, &["--verify-only"]);
        assert_eq!(code, 0, "{json}");
        assert_eq!(json["repository"]["source"], "already_fixed", "{json}");
        assert_eq!(json["repository"]["mutation"], "unchanged", "{json}");
        assert_eq!(json["repository"]["shell_verify"], "pass", "{json}");
        assert_eq!(json["repository"]["structural_verify"], "pass", "{json}");
        assert_eq!(json["repository"]["final_state"], "already_fixed", "{json}");
        assert_eq!(tracked_changes(&fx), "");
    }
}

#[cfg(unix)]
/// Every SKIP of the `wasm-ui/pkg drift check` must go through the one helper
/// that states what the skip costs on a branch touching `hse-core/` or
/// `wasm-ui/src/`.
///
/// That check cannot run without an exactly-pinned toolchain, so `gate.sh`
/// skips rather than risk a false failure — correct, and documented in its
/// header. But a skip is harmless only when nothing feeding the browser bundle
/// changed. `hse-core` is compiled INTO wasm-ui, so on a branch that touches it
/// the skip is the difference between a green local run and a red
/// sibling-crates job. Two consecutive cycles shipped exactly that: a bland
/// "tool not installed" SKIP, then CI red on
/// `DRIFT: wasm-ui/pkg/hse_wasm_ui_bg.wasm does not match a fresh regeneration`.
///
/// The escalation lives in `skip_wasm_drift`. This pins that no branch of the
/// dispatch can bypass it — a new precondition added to that `if`/`elif` chain
/// calling bare `skip` would silently restore the quiet failure mode.
#[test]
fn every_wasm_drift_skip_states_what_the_skip_costs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = fs::read_to_string(root.join("scripts/gate.sh")).unwrap();

    let mut helper_calls = 0;
    for (i, line) in text.lines().enumerate().filter(|(_, l)| !is_comment(l)) {
        // The helper's own definition necessarily contains both spellings.
        if line.contains("skip_wasm_drift()") {
            continue;
        }
        if line.contains("skip_wasm_drift") {
            helper_calls += 1;
        }
        // A bare `skip "wasm-ui/pkg drift check"` bypasses the escalation.
        assert!(
            !line.contains(r#"skip "wasm-ui/pkg drift check""#),
            "scripts/gate.sh:{}: skip this check via `skip_wasm_drift` so the \
             branch-touches-hse-core warning is attached: {}",
            i + 1,
            line.trim()
        );
    }
    assert!(
        helper_calls >= 6,
        "expected every precondition branch to route through skip_wasm_drift, \
         saw {helper_calls} call(s) — if a branch was removed, confirm it was \
         not replaced by a bare `skip`"
    );

    // The escalation must actually CONSULT the paths compiled into the bundle,
    // or it is a warning that can never fire.
    //
    // Scoped to the `git diff` invocations on purpose. Written first as a
    // substring search over the whole block, this assertion passed while the
    // paths were deleted from the diff commands \u2014 because the warning PROSE
    // ("THIS BRANCH CHANGES hse-core/ OR wasm-ui/src/") contains them too. It
    // was matching the sentence, not the check.
    // Windowed to the stakes block. A whole-file filter also catches the
    // manifest-path-filter check further down, whose own `git diff` names
    // `hse-core/Cargo.toml` but not `wasm-ui/src/` \u2014 an unrelated line failing
    // an assertion about this one.
    let stakes_block = {
        let start = text
            .find("WASM_DRIFT_STAKES=\"\"")
            .expect("gate.sh must compute WASM_DRIFT_STAKES");
        let end = text[start..]
            .find("skip_wasm_drift()")
            .expect("the stakes block must be followed by the helper it feeds");
        &text[start..start + end]
    };
    let diff_lines: Vec<&str> = stakes_block
        .lines()
        .filter(|l| !is_comment(l) && l.contains("git diff --quiet"))
        .collect();
    assert!(
        diff_lines.len() >= 2,
        "expected the working-tree and origin/main...HEAD diffs to both test the \
         bundle's source paths, saw {}",
        diff_lines.len()
    );
    for path in ["hse-core/", "wasm-ui/src/"] {
        assert!(
            diff_lines.iter().all(|l| l.contains(path)),
            "every stakes `git diff` must test {path}, which is compiled into \
             wasm-ui/pkg/; got {diff_lines:?}"
        );
    }
}
