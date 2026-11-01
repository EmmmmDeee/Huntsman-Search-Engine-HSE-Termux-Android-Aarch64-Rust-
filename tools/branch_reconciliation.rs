//! Read-only inventory of remote branches against canonical `origin/main`.
//!
//! Uses local Git history only. A divergent tip is a *review candidate*, not
//! evidence that its behavior is absent from main (squash/reimplementation can
//! already have incorporated it). Never merges, deletes, rebases, or pushes.

use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::Command;

#[derive(Default, Debug, PartialEq, Eq)]
struct Summary {
    total: usize,
    integrated: usize,
    identical: usize,
    ahead: usize,
    divergent: usize,
}

/// A *review* candidate, not proof of unique functionality.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    branch: String,
    sha: String,
    ahead: usize,
    behind: usize,
    last_epoch: u64,
}

fn order_candidates(candidates: &mut [Candidate]) {
    // Recently modified code is easier to review against the current
    // architecture. Break ties in favour of smaller integration divergence.
    candidates.sort_by(|left, right| {
        right
            .last_epoch
            .cmp(&left.last_epoch)
            .then_with(|| left.behind.cmp(&right.behind))
            .then_with(|| left.ahead.cmp(&right.ahead))
            .then_with(|| left.branch.cmp(&right.branch))
    });
}

fn git(args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .map_err(|error| format!("could not execute git {args:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("invalid Git output: {error}"))
}

fn count_commits(from: &str, to: &str) -> Result<usize, String> {
    let range = format!("{from}..{to}");
    git(&["rev-list", "--count", &range])?
        .parse()
        .map_err(|error| format!("invalid count for {range}: {error}"))
}

fn classify(ahead: usize, behind: usize) -> &'static str {
    match (ahead, behind) {
        (0, 0) => "same_tip",
        (0, _) => "already_ancestor",
        (_, 0) => "ahead_only_review",
        _ => "diverged_review",
    }
}

fn record(summary: &mut Summary, classification: &str) {
    summary.total += 1;
    match classification {
        "same_tip" => summary.identical += 1,
        "already_ancestor" => summary.integrated += 1,
        "ahead_only_review" => summary.ahead += 1,
        "diverged_review" => summary.divergent += 1,
        _ => unreachable!("classification comes from classify()"),
    }
}

fn audit(path: &str) -> Result<(Summary, Vec<Candidate>), String> {
    let main = "origin/main";
    let main_sha = git(&["rev-parse", "--verify", main])?;
    let mut branches: Vec<String> = git(&[
        "for-each-ref",
        "--format=%(refname:short)",
        "refs/remotes/origin",
    ])?
    .lines()
    .filter(|branch| *branch != main && *branch != "origin/HEAD")
    .map(str::to_owned)
    .collect();
    branches.sort();
    if branches.len() > 10_000 {
        return Err("unexpected branch cardinality (>10000); refusing unbounded audit".into());
    }

    let output = File::create(path).map_err(|e| format!("{path}: {e}"))?;
    let mut writer = BufWriter::new(output);
    writeln!(writer, "# canonical_main_sha\t{main_sha}").map_err(|e| e.to_string())?;
    writeln!(
        writer,
        "branch\tsha\tcommits_unique_to_branch\tcommits_missing_from_branch\tclassification\tlast_commit"
    )
    .map_err(|e| e.to_string())?;

    let mut summary = Summary::default();
    let mut candidates = Vec::new();
    for branch in &branches {
        let sha = git(&["rev-parse", "--verify", branch])?;
        let ahead = count_commits(main, branch)?;
        let behind = count_commits(branch, main)?;
        let classification = classify(ahead, behind);
        let timestamp = git(&["log", "-1", "--format=%ct|%cI", branch])?;
        let (epoch, last_commit) = timestamp
            .split_once('|')
            .ok_or_else(|| format!("invalid commit timestamp on {branch}"))?;
        let last_epoch: u64 = epoch
            .parse()
            .map_err(|error| format!("invalid commit epoch on {branch}: {error}"))?;
        if ahead > 0 {
            candidates.push(Candidate {
                branch: branch.clone(),
                sha: sha.clone(),
                ahead,
                behind,
                last_epoch,
            });
        }
        writeln!(
            writer,
            "{branch}\t{sha}\t{ahead}\t{behind}\t{classification}\t{last_commit}"
        )
        .map_err(|e| e.to_string())?;
        record(&mut summary, classification);
    }
    writer.flush().map_err(|e| e.to_string())?;
    order_candidates(&mut candidates);
    Ok((summary, candidates))
}

fn main() {
    let mut arguments = env::args().skip(1);
    let Some(path) = arguments.next() else {
        eprintln!("usage: branch_reconciliation OUTPUT.tsv");
        std::process::exit(2);
    };
    if arguments.next().is_some() {
        eprintln!("expected exactly one output TSV path");
        std::process::exit(2);
    }
    match audit(&path) {
        Ok((summary, candidates)) => {
            println!(
                "MAIN_BRANCH_RECONCILIATION total={} integrated={} same={} ahead_review={} diverged_review={}",
                summary.total,
                summary.integrated,
                summary.identical,
                summary.ahead,
                summary.divergent
            );
            println!("TSV: {path}; unique commits require selective code review before porting");
            println!("REVIEW_QUEUE most recently committed candidates (NOT missing-code proof):");
            for (rank, candidate) in candidates.iter().take(20).enumerate() {
                println!(
                    "REVIEW_CANDIDATE rank={} branch={} sha={} unique_commits={} main_only_commits={} last_epoch={}",
                    rank + 1,
                    candidate.branch,
                    candidate.sha,
                    candidate.ahead,
                    candidate.behind,
                    candidate.last_epoch
                );
            }
        }
        Err(error) => {
            eprintln!("MAIN_BRANCH_RECONCILIATION_FAILED: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, order_candidates, record, Candidate, Summary};

    #[test]
    fn branch_status_never_confuses_divergence_with_incorporation() {
        assert_eq!(classify(0, 0), "same_tip");
        assert_eq!(classify(0, 9), "already_ancestor");
        assert_eq!(classify(1, 0), "ahead_only_review");
        assert_eq!(classify(2, 400), "diverged_review");
    }

    #[test]
    fn candidate_queue_prioritises_recency_then_smaller_divergence() {
        let mut candidates = vec![
            Candidate {
                branch: "old".into(),
                sha: "1".into(),
                ahead: 1,
                behind: 1,
                last_epoch: 100,
            },
            Candidate {
                branch: "new-deep".into(),
                sha: "2".into(),
                ahead: 3,
                behind: 800,
                last_epoch: 200,
            },
            Candidate {
                branch: "new-shallow".into(),
                sha: "3".into(),
                ahead: 1,
                behind: 2,
                last_epoch: 200,
            },
        ];
        order_candidates(&mut candidates);
        assert_eq!(
            candidates.iter().map(|c| c.branch.as_str()).collect::<Vec<_>>(),
            ["new-shallow", "new-deep", "old"]
        );
    }

    #[test]
    fn counts_are_exhaustive_and_non_overlapping() {
        let mut summary = Summary::default();
        for classification in [
            classify(0, 0),
            classify(0, 9),
            classify(1, 0),
            classify(2, 400),
        ] {
            record(&mut summary, classification);
        }
        assert_eq!(summary.total, 4);
        assert_eq!(summary.identical, 1);
        assert_eq!(summary.integrated, 1);
        assert_eq!(summary.ahead, 1);
        assert_eq!(summary.divergent, 1);
    }
}
