//! The publish step. It applies the agent's patch to a checkout of main, checks the result against
//! the path policy, commits it on ai-fix/issue-N, pushes that branch, and opens a pull request
//! against main. It never merges.
//!
//! The patch is data. Nothing from it is executed here, and the policy checks what the patch does to
//! main. The gate tested the commit GATED_SHA, so the change is published only while main is still
//! that commit. Git works in the current directory, which is the checkout of main. It never works in
//! the repository that this binary was built from, which the trusted build keeps apart from the
//! checkout.
//!
//! Environment: REPO and GATED_SHA are required. PUSH_TOKEN authenticates git as an HTTP header, so
//! neither the remote URL nor the checkout's configuration keeps it; it is not needed when REMOTE_URL
//! names the remote. GH_TOKEN is read by gh. HAS_PAT is "true" when PUSH_TOKEN is a personal or app
//! token, not the workflow token. REMOTE_URL pushes to that URL instead of origin, and DRY_RUN=1 skips
//! the pull request, and gh, after the push.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use serde_json::Value;

use crate::error::{self, Error, Result};
use crate::issue_fix::{guard, prompt};
use crate::proc;

const USAGE: &str = "usage: xtask issue-fix publish ISSUE_JSON CHANGE_DIR";
const SUMMARY_CHARS: usize = 4000;
const NO_SUMMARY: &str = "(no summary returned)";
const COMMIT_BODY: &str = "Produced by the issue-fix workflow. It passed the path policy and the full repair gate. It needs review before merge.";
const WORKFLOW_TOKEN_NOTE: &str = "This pull request was opened with the workflow token. GitHub does not start CI for pull requests opened that way, so start CI from the Actions tab or set the ISSUE_FIX_TOKEN secret.";
const REVIEW_NOTE: &str = "Needs human review. This pull request does not merge automatically.";

/// `issue-fix publish ISSUE_JSON CHANGE_DIR`. Publishes the change in CHANGE_DIR as a branch and a
/// pull request, after the checks in the module's header. A refusal names its reason on standard
/// error and returns status 1, and malformed input returns status 64.
pub fn run(args: &[String]) -> ExitCode {
    let [issue_json, change_dir] = args else {
        return error::usage(USAGE);
    };
    let plan = match prepare(Path::new(issue_json), change_dir) {
        Ok(plan) => plan,
        Err(problem) => return error::report("publish", &problem),
    };
    // The policy checks the staged change against main, before the commit, as the original did. Its
    // own refusal is printed by the guard, so its status is returned unchanged.
    let policy = guard::run(&["HEAD".to_owned()]);
    if policy != ExitCode::SUCCESS {
        return policy;
    }
    match finish(&plan) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => error::report("publish", &problem),
    }
}

/// What the checks before the policy established, and what the rest of publish needs.
struct Plan {
    repo: String,
    number: String,
    title: String,
    branch: String,
    remote: String,
    /// The HTTP header that authenticates git, when the push goes to origin.
    header: Option<String>,
    main: String,
    change_dir: String,
    has_pat: bool,
    dry_run: bool,
}

/// Checks the environment, the issue, the patch, and the remote, then applies the patch to a new
/// branch and checks that it changes something. Everything here runs before the policy.
fn prepare(issue_json: &Path, change_dir: &str) -> Result<Plan> {
    let repo = required_env("REPO", "REPO must be set")?;
    let gated = required_env(
        "GATED_SHA",
        "GATED_SHA must name the commit the gate tested",
    )?;
    let issue = prompt::read_issue(issue_json)?;
    let number = prompt::issue_text(&issue, "number");
    let title = prompt::issue_text(&issue, "title");
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Refused(format!(
            "issue number is not numeric: {number}"
        )));
    }
    let patch = format!("{change_dir}/change.patch");
    if !fs::metadata(&patch).is_ok_and(|meta| meta.len() > 0) {
        return Err(Error::Refused(format!("there is no patch at {patch}")));
    }

    // The gate tested GATED_SHA. Publishing from any other main would ship a change the gate did not
    // see, so main must still be that commit.
    let main = git_output(&["rev-parse", "HEAD"])?;
    if main != gated {
        return Err(Error::Refused(format!(
            "main is {main}, but the gate tested {gated}; main moved while the run was in progress, so label the issue again"
        )));
    }

    let branch = format!("ai-fix/issue-{number}");
    let remote_url = std::env::var("REMOTE_URL")
        .ok()
        .filter(|url| !url.is_empty());
    let header = if remote_url.is_some() {
        None
    } else {
        Some(push_header()?)
    };
    let remote = remote_url.unwrap_or_else(|| "origin".to_owned());

    // An existing branch is never overwritten. The maintainer decides what to do with it.
    match remote_status(
        header.as_deref(),
        &["ls-remote", "--exit-code", "--heads", &remote, &branch],
    ) {
        0 => {
            return Err(Error::Refused(format!(
                "{branch} already exists on the remote; delete or rename it, then label the issue again"
            )));
        }
        2 => {}
        other => {
            return Err(Error::Refused(format!(
                "could not read the remote heads (exit {other})"
            )));
        }
    }

    git_ok(&["checkout", "-q", "-b", &branch])?;
    if git_code(&["apply", "--index", &patch])? != 0 {
        let short = git_output(&["rev-parse", "--short", "HEAD"]).unwrap_or_default();
        return Err(Error::Refused(format!(
            "the patch does not apply to {short}"
        )));
    }
    match git_code(&["diff", "--cached", "--quiet", "--no-ext-diff"])? {
        0 => {
            return Err(Error::Refused("the patch changes nothing".to_owned()));
        }
        1 => {}
        other => {
            return Err(Error::Refused(format!("git diff failed (exit {other})")));
        }
    }

    Ok(Plan {
        repo,
        number,
        title,
        branch,
        remote,
        header,
        main,
        change_dir: change_dir.to_owned(),
        has_pat: std::env::var("HAS_PAT").is_ok_and(|value| value == "true"),
        dry_run: std::env::var("DRY_RUN").is_ok_and(|value| value == "1"),
    })
}

/// Commits the staged change, pushes the branch, and opens the pull request. A dry run stops after
/// the push, and it makes no gh call.
fn finish(plan: &Plan) -> Result<()> {
    let subject = format!("Fix #{}: {}", plan.number, plan.title);
    let refs = format!("Refs #{}. {COMMIT_BODY}", plan.number);
    git_ok(&[
        "-c",
        "user.name=issue-fix",
        "-c",
        "user.email=issue-fix@users.noreply.github.com",
        "commit",
        "-q",
        "-m",
        &subject,
        "-m",
        &refs,
    ])?;

    // The lease names the branch as absent, so a branch that appears between the listing and this
    // push is refused rather than moved, and the push never overwrites anything.
    let lease = format!("--force-with-lease=refs/heads/{}:", plan.branch);
    remote_ok(
        plan.header.as_deref(),
        &["push", "-q", &lease, &plan.remote, &plan.branch],
    )?;

    if plan.dry_run {
        println!(
            "publish: dry run pushed {} and skipped the pull request",
            plan.branch
        );
        return Ok(());
    }

    let summary = model_summary(&format!("{}/agent.json", plan.change_dir))?;
    let body = pull_request_body(&plan.number, &summary, &plan.main, plan.has_pat);
    let title = subject;
    gh_pr_create(&plan.repo, &plan.branch, &title, &body)
}

fn required_env(name: &str, message: &str) -> Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(Error::Refused(message.to_owned())),
    }
}

/// The HTTP header that carries PUSH_TOKEN to git, as the original built it: basic authentication with
/// the x-access-token user. The header is never printed.
fn push_header() -> Result<String> {
    let token = required_env("PUSH_TOKEN", "PUSH_TOKEN must be set")?;
    let encoded = base64_encode(format!("x-access-token:{token}").as_bytes());
    Ok(format!("AUTHORIZATION: basic {encoded}"))
}

/// A git command for the remote. With a header, the header goes on the command line and nowhere
/// else. The command line is never printed, so the header does not reach an error message.
fn remote_git(header: Option<&str>, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    if let Some(header) = header {
        command
            .arg("-c")
            .arg(format!("http.https://github.com/.extraheader={header}"));
    }
    command.args(args);
    command
}

/// The exit status of `git ls-remote`, with its output hidden. A command that cannot start reads as
/// status 127, the shell's status for it, and a signal reads as 128.
fn remote_status(header: Option<&str>, args: &[&str]) -> i32 {
    remote_git(header, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_or(127, |status| status.code().unwrap_or(128))
}

/// Runs git against the remote, with its output shown, and fails when it does not succeed. The
/// message names the arguments without the header.
fn remote_ok(header: Option<&str>, args: &[&str]) -> Result<()> {
    let shown = format!("git {}", args.join(" "));
    let status = remote_git(header, args)
        .status()
        .map_err(|source| Error::Command {
            shown: shown.clone(),
            reason: format!("could not start: {source}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Command {
            shown,
            reason: format!("exited with {status}"),
        })
    }
}

/// The exit code of a git command in the current directory, with its output shown. A command that
/// ends by signal has no code, and reads as 128.
fn git_code(args: &[&str]) -> Result<i32> {
    let shown = format!("git {}", args.join(" "));
    let status = Command::new("git")
        .args(args)
        .status()
        .map_err(|source| Error::Command {
            shown,
            reason: format!("could not start: {source}"),
        })?;
    Ok(status.code().unwrap_or(128))
}

/// Runs a git command in the current directory, with its output shown, and fails when it does not
/// succeed.
fn git_ok(args: &[&str]) -> Result<()> {
    let shown = format!("git {}", args.join(" "));
    match git_code(args)? {
        0 => Ok(()),
        code => Err(Error::Command {
            shown,
            reason: format!("exited with status {code}"),
        }),
    }
}

/// The standard output of a git command in the current directory, without its trailing newlines,
/// as command substitution keeps it.
fn git_output(args: &[&str]) -> Result<String> {
    let output = proc::git_stdout(Path::new("."), args)?;
    Ok(String::from_utf8_lossy(&output)
        .trim_end_matches('\n')
        .to_owned())
}

/// The summary of the model's run, from agent.json. It is the agent's result, or a note when there is
/// none, cut to SUMMARY_CHARS characters.
fn model_summary(agent_json: &str) -> Result<String> {
    let bytes = fs::read(agent_json).map_err(|source| Error::Io {
        path: agent_json.into(),
        source,
    })?;
    summary_of(&String::from_utf8_lossy(&bytes), agent_json)
}

/// The summary held by the agent output TEXT. Empty output has no summary, as it did under jq, and
/// output that is not a JSON object is malformed.
fn summary_of(text: &str, agent_json: &str) -> Result<String> {
    if text.trim().is_empty() {
        return Ok(String::new());
    }
    let value: Value = serde_json::from_str(text)
        .map_err(|source| Error::Invalid(format!("{agent_json} is not valid JSON: {source}")))?;
    let result = match &value {
        Value::Object(map) => map.get("result").cloned(),
        Value::Null => None,
        _ => {
            return Err(Error::Invalid(format!(
                "{agent_json} does not hold a JSON object"
            )));
        }
    };
    let text = match result {
        None | Some(Value::Null | Value::Bool(false)) => NO_SUMMARY.to_owned(),
        Some(Value::String(text)) => text,
        Some(other) => other.to_string(),
    };
    let cut: String = text.chars().take(SUMMARY_CHARS).collect();
    Ok(cut.replace('\0', "").trim_end_matches('\n').to_owned())
}

/// The pull request body. It names the issue, the summary, what the workflow checked, and the token
/// note when the workflow token opened the pull request.
fn pull_request_body(number: &str, summary: &str, main: &str, has_pat: bool) -> String {
    let mut body = String::new();
    body.push_str(&format!("Closes #{number}\n\n"));
    body.push_str(&format!("## Model summary (unreviewed)\n\n{summary}\n\n"));
    body.push_str("## What the workflow checked\n\n");
    body.push_str(&format!(
        "- Built on main at {main}, the commit the gate tested.\n"
    ));
    body.push_str("- Path policy, applied to the patch on main: changes only under src/, outside the test code, plus new files under src/ and tests/.\n");
    body.push_str("- `cargo run --locked -p xtask -- gate full` passed on the runner.\n\n");
    if !has_pat {
        body.push_str(&format!("{WORKFLOW_TOKEN_NOTE}\n\n"));
    }
    body.push_str(&format!("{REVIEW_NOTE}\n\n"));
    body.push_str("---\n_Generated by the issue-fix workflow with Claude Code_\n");
    body
}

/// Opens the pull request with gh, with the body read from standard input. gh reads GH_TOKEN from the
/// environment.
fn gh_pr_create(repo: &str, branch: &str, title: &str, body: &str) -> Result<()> {
    let args = [
        "pr",
        "create",
        "--repo",
        repo,
        "--base",
        "main",
        "--head",
        branch,
        "--title",
        title,
        "--body-file",
        "-",
    ];
    let shown = "gh pr create".to_owned();
    let mut child = Command::new("gh")
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|source| Error::Command {
            shown: shown.clone(),
            reason: format!("could not start: {source}"),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body.as_bytes())
            .map_err(|source| Error::Command {
                shown: shown.clone(),
                reason: format!("could not send the body: {source}"),
            })?;
    }
    let status = child.wait().map_err(|source| Error::Command {
        shown: shown.clone(),
        reason: format!("could not be waited for: {source}"),
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Command {
            shown,
            reason: format!("exited with {status}"),
        })
    }
}

/// Standard base64 with padding, as `base64` prints it without line breaks.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        for (slot, byte) in group.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let [first, second, third] = group;
        let word = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);
        let symbols = chunk.len() + 1;
        for index in 0u32..4 {
            if (index as usize) < symbols {
                let six = (word >> (18 - 6 * index)) & 0x3F;
                out.push(char::from(
                    ALPHABET.get(six as usize).copied().unwrap_or(b'='),
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn the_summary_is_the_result_or_a_note() {
        assert_eq!(
            summary_of(r#"{"result": "done"}"#, "a").expect("summary"),
            "done"
        );
        assert_eq!(summary_of("{}", "a").expect("summary"), NO_SUMMARY);
        assert_eq!(
            summary_of(r#"{"result": false}"#, "a").expect("summary"),
            NO_SUMMARY
        );
        assert_eq!(summary_of(r#"{"result": 7}"#, "a").expect("summary"), "7");
        assert_eq!(summary_of("  \n", "a").expect("summary"), "");
    }

    #[test]
    fn the_summary_is_cut_to_4000_characters_and_loses_trailing_newlines() {
        let long = format!(r#"{{"result": "{}"}}"#, "é".repeat(5000));
        let summary = summary_of(&long, "a").expect("summary");
        assert_eq!(summary.chars().count(), SUMMARY_CHARS);
        let short = summary_of(r#"{"result": "x\n\n"}"#, "a").expect("summary");
        assert_eq!(short, "x");
    }

    #[test]
    fn output_that_is_not_an_object_is_malformed() {
        assert!(matches!(summary_of("[1]", "a"), Err(Error::Invalid(_))));
        assert!(matches!(summary_of("{", "a"), Err(Error::Invalid(_))));
    }

    #[test]
    fn the_pull_request_names_the_issue_and_the_token_note_when_needed() {
        let without = pull_request_body("42", "ok", "abc123", false);
        assert!(without.starts_with("Closes #42\n\n"));
        assert!(without.contains("- Built on main at abc123, the commit the gate tested.\n"));
        assert!(without.contains(WORKFLOW_TOKEN_NOTE));
        let with = pull_request_body("42", "ok", "abc123", true);
        assert!(!with.contains(WORKFLOW_TOKEN_NOTE));
        assert!(with.ends_with("---\n_Generated by the issue-fix workflow with Claude Code_\n"));
    }
}
