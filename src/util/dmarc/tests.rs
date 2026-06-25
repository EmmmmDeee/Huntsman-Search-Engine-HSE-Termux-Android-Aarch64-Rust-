use super::*;

#[test]
fn is_dmarc_recognises_version_tag_case_insensitively() {
    assert!(is_dmarc("v=DMARC1; p=reject"));
    assert!(is_dmarc("v=dmarc1; p=none"));
    assert!(is_dmarc("V=DMARC1; p=quarantine"));
    assert!(!is_dmarc("v=spf1 -all"));
    assert!(!is_dmarc(""));
    assert!(!is_dmarc("v=DMARC"));
}

#[test]
fn parse_returns_none_for_non_dmarc() {
    assert!(parse("v=spf1 -all").is_none());
    assert!(parse("").is_none());
    assert!(parse("some random text").is_none());
}

#[test]
fn parse_basic_reject_policy() {
    let r = parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com").unwrap();
    assert_eq!(r.policy, Some(DmarcPolicy::Reject));
    assert_eq!(r.rua, vec!["dmarc@example.com"]);
    assert_eq!(r.pct, 100);
    assert_eq!(r.adkim, AlignmentMode::Relaxed);
    assert_eq!(r.aspf, AlignmentMode::Relaxed);
}

#[test]
fn parse_quarantine_with_pct() {
    let r = parse("v=DMARC1; p=quarantine; pct=50; rua=mailto:rep@x.com").unwrap();
    assert_eq!(r.policy, Some(DmarcPolicy::Quarantine));
    assert_eq!(r.pct, 50);
    assert_eq!(r.rua, vec!["rep@x.com"]);
}

#[test]
fn parse_none_policy() {
    let r = parse("v=DMARC1; p=none").unwrap();
    assert_eq!(r.policy, Some(DmarcPolicy::None));
    assert!(r.rua.is_empty());
}

#[test]
fn parse_strict_alignment() {
    let r = parse("v=DMARC1; p=reject; adkim=s; aspf=s").unwrap();
    assert_eq!(r.adkim, AlignmentMode::Strict);
    assert_eq!(r.aspf, AlignmentMode::Strict);
}

#[test]
fn parse_subdomain_policy_override() {
    let r = parse("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com").unwrap();
    assert_eq!(r.policy, Some(DmarcPolicy::Reject));
    assert_eq!(r.sp, Some(DmarcPolicy::None));
}

#[test]
fn parse_multiple_rua_and_ruf_addresses() {
    let r = parse(
        "v=DMARC1; p=reject; \
         rua=mailto:agg1@example.com,mailto:agg2@backup.org!10m; \
         ruf=mailto:for@example.com",
    )
    .unwrap();
    assert_eq!(r.rua, vec!["agg1@example.com", "agg2@backup.org"]);
    assert_eq!(r.ruf, vec!["for@example.com"]);
}

#[test]
fn parse_size_suffix_stripped() {
    // RFC 7489 §6.2 — `!10m` report-size limit must be stripped.
    let r = parse("v=DMARC1; p=none; rua=mailto:rep@x.com!10m,mailto:rep2@y.com!500k").unwrap();
    assert_eq!(r.rua, vec!["rep@x.com", "rep2@y.com"]);
}

#[test]
fn parse_ri_and_fo_fields() {
    let r = parse("v=DMARC1; p=reject; ri=3600; fo=1").unwrap();
    assert_eq!(r.ri, 3600);
    assert_eq!(r.fo.as_deref(), Some("1"));
}

#[test]
fn parse_unknown_tags_ignored() {
    // Forward-compatibility: unknown tags must not fail the parse.
    let r = parse("v=DMARC1; p=reject; newtagfuture=somevalue; rua=mailto:a@b.com").unwrap();
    assert_eq!(r.policy, Some(DmarcPolicy::Reject));
    assert_eq!(r.rua, vec!["a@b.com"]);
}

#[test]
fn parse_first_occurrence_wins_for_duplicate_tags() {
    // RFC 7489 §6.3 — leftmost value is used.
    let r = parse("v=DMARC1; p=reject; p=none").unwrap();
    assert_eq!(r.policy, Some(DmarcPolicy::Reject));
}

#[test]
fn parse_missing_policy_tag_returns_record_with_none_policy() {
    // A DMARC record without `p=` is effectively invalid per RFC 7489 §6.6.1
    // but must still parse (not return None) — policy field will be None.
    let r = parse("v=DMARC1; rua=mailto:a@b.com").unwrap();
    assert_eq!(r.policy, None);
    assert_eq!(r.rua, vec!["a@b.com"]);
}

// ── issues() ────────────────────────────────────────────────────────────────

#[test]
fn issues_missing_policy() {
    let r = parse("v=DMARC1; rua=mailto:a@b.com").unwrap();
    assert!(r.issues().contains(&DmarcIssue::MissingPolicy));
}

#[test]
fn issues_no_enforcement_and_subdomain_unprotected() {
    let r = parse("v=DMARC1; p=none").unwrap();
    let issues = r.issues();
    assert!(issues.contains(&DmarcIssue::NoEnforcement));
    assert!(issues.contains(&DmarcIssue::SubdomainUnprotected));
}

#[test]
fn issues_reject_with_sp_none_flags_subdomain() {
    let r = parse("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com").unwrap();
    let issues = r.issues();
    assert!(!issues.contains(&DmarcIssue::NoEnforcement));
    assert!(issues.contains(&DmarcIssue::SubdomainUnprotected));
}

#[test]
fn issues_partial_coverage() {
    let r = parse("v=DMARC1; p=reject; pct=75; rua=mailto:a@b.com").unwrap();
    let issues = r.issues();
    assert!(issues.contains(&DmarcIssue::PartialCoverage(75)));
}

#[test]
fn issues_no_aggregate_reports() {
    let r = parse("v=DMARC1; p=reject").unwrap();
    assert!(r.issues().contains(&DmarcIssue::NoAggregateReports));
}

#[test]
fn issues_clean_record_has_no_issues() {
    let r = parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com").unwrap();
    assert!(r.issues().is_empty(), "clean reject record: {:?}", r.issues());
}

// ── report_addresses() ───────────────────────────────────────────────────────

#[test]
fn report_addresses_deduplicates_rua_and_ruf() {
    let r = parse(
        "v=DMARC1; p=reject; \
         rua=mailto:shared@x.com,mailto:agg@x.com; \
         ruf=mailto:shared@x.com",
    )
    .unwrap();
    let addrs = r.report_addresses();
    assert_eq!(addrs.iter().filter(|&&a| a == "shared@x.com").count(), 1);
    assert!(addrs.contains(&"agg@x.com"));
}

// ── DmarcPolicy::tag() ───────────────────────────────────────────────────────

#[test]
fn policy_tags_are_stable() {
    assert_eq!(DmarcPolicy::None.tag(), "dmarc:none");
    assert_eq!(DmarcPolicy::Quarantine.tag(), "dmarc:quarantine");
    assert_eq!(DmarcPolicy::Reject.tag(), "dmarc:reject");
}

// ── DmarcIssue::tag() ────────────────────────────────────────────────────────

#[test]
fn issue_tags_are_stable() {
    assert_eq!(DmarcIssue::NoEnforcement.tag(), "dmarc:no-enforcement");
    assert_eq!(DmarcIssue::PartialCoverage(50).tag(), "dmarc:partial-coverage");
    assert_eq!(DmarcIssue::SubdomainUnprotected.tag(), "dmarc:subdomain-unprotected");
    assert_eq!(DmarcIssue::NoAggregateReports.tag(), "dmarc:no-aggregate-reports");
    assert_eq!(DmarcIssue::MissingPolicy.tag(), "dmarc:missing-policy");
}
