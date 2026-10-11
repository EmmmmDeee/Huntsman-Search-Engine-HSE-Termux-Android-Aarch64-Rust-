//! A GitHub Actions workflow read as text. The contract tests split a workflow into its jobs and
//! steps with these rules, so both the job boundary and the step boundary are defined once here.

/// A job header is a line indented by exactly two spaces that ends with a colon.
fn is_job_header(line: &str) -> bool {
    line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':')
}

/// The text of one job, from its header to the next job header.
pub fn job(wf: &str, name: &str) -> String {
    let header = format!("  {name}:");
    let mut lines = wf.lines().skip_while(|l| *l != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("job {name:?} must exist in the workflow"));
    let body: Vec<&str> = lines.take_while(|l| !is_job_header(l)).collect();
    format!("{first}\n{}", body.join("\n"))
}

/// The text of the named step: from its `- name:` line to the next step.
pub fn step(wf: &str, name: &str) -> String {
    let header = format!("      - name: {name}");
    let mut lines = wf.lines().skip_while(|l| *l != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("step {name:?} must exist in the workflow"));
    let body: Vec<&str> = lines.take_while(|l| !l.starts_with("      - ")).collect();
    format!("{first}\n{}", body.join("\n"))
}
