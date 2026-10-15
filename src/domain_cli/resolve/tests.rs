use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::source_outcome::SourceOutcomeKind;

fn domain(value: &str) -> Entity {
    Entity::new(EntityKind::Domain, value, 0.8, "scan")
}

#[test]
fn the_hosts_asked_are_the_subdomains_each_once_in_name_order() {
    let entities = [
        domain("www.example.com"),
        domain("example.com"),
        domain("mail.example.com"),
        domain("www.example.com"),
        domain("notexample.com"),
        domain("example.net"),
        Entity::new(EntityKind::Email, "ops@dev.example.com", 0.8, "scan"),
    ];
    assert_eq!(
        hosts(&entities, "example.com"),
        ["mail.example.com", "www.example.com"]
    );
}

/// Every host is asked, several at a time, and each answer lands at its host's index.
#[test]
fn every_host_is_answered_in_order() {
    let hosts: Vec<String> = (0..50).map(|n| format!("h{n}.example.com")).collect();
    let answers = resolve_all(&hosts, |host| {
        if host.starts_with("h1") && host.len() == "h1.example.com".len() {
            HostAnswer::Failed(ResolveErrorKind::Timeout, "slow".into())
        } else {
            HostAnswer::Addresses(vec![(RecordType::A, host.to_owned(), "test")])
        }
    });
    assert_eq!(answers.len(), hosts.len());
    for (host, answer) in hosts.iter().zip(&answers) {
        match answer {
            Some(HostAnswer::Addresses(records)) => assert_eq!(&records[0].1, host),
            Some(HostAnswer::Failed(..)) => assert_eq!(host, "h1.example.com"),
            other => panic!("{host}: {other:?}"),
        }
    }
}

/// Resolvers that never answer stop the leg after a few hosts instead of failing every one of
/// a long list in turn.
#[test]
fn an_outage_stops_asking_after_a_few_hosts() {
    let hosts: Vec<String> = (0..200).map(|n| format!("h{n}.example.com")).collect();
    let asked = AtomicUsize::new(0);
    let answers = resolve_all(&hosts, |_| {
        asked.fetch_add(1, Ordering::SeqCst);
        HostAnswer::Failed(ResolveErrorKind::Upstream, "offline".into())
    });
    let asked = asked.into_inner();
    assert!(
        (dns::ASK_FAILURES_BEFORE_ABORT..dns::ASK_FAILURES_BEFORE_ABORT + dns::ASK_WORKERS)
            .contains(&asked),
        "{asked} hosts asked"
    );
    assert_eq!(
        answers.iter().filter(|answer| answer.is_some()).count(),
        asked
    );
}

#[test]
fn no_host_is_no_worker() {
    assert!(resolve_all(&[], |_| HostAnswer::Unresolved).is_empty());
}

#[test]
fn the_outcome_counts_every_host_and_says_why_one_was_not_resolved() {
    let tally = Tally {
        hosts: 600,
        resolved: 300,
        addresses: 420,
        unresolved: 150,
        failed: 2,
        aborted: 0,
        first_failure: Some((ResolveErrorKind::Timeout, "slow".into())),
    };
    let outcome = tally.outcome(1);
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(outcome.found, Some(420));
    assert_eq!(
        outcome.detail.as_deref(),
        Some(
            "300 of 600 hosts resolved, 150 unresolved, 2 unanswered, 148 not asked past the \
             512-host limit"
        )
    );

    let none_resolve = Tally {
        hosts: 3,
        unresolved: 3,
        ..Tally::default()
    };
    let outcome = none_resolve.outcome(1);
    assert_eq!(outcome.kind, SourceOutcomeKind::ValidZero);
    assert_eq!(
        outcome.detail.as_deref(),
        Some("0 of 3 hosts resolved, 3 unresolved")
    );

    let outage = Tally {
        hosts: 40,
        failed: 4,
        aborted: 36,
        first_failure: Some((ResolveErrorKind::Timeout, "no answer in 5s".into())),
        ..Tally::default()
    };
    let outcome = outage.outcome(1);
    assert_eq!(outcome.kind, SourceOutcomeKind::TtfbTimeout);
    assert_eq!(outcome.found, None);
    assert_eq!(
        outcome.detail.as_deref(),
        Some("no resolver answered: 4 of 40 hosts failed, the first timeout: no answer in 5s")
    );
    assert_eq!(
        Tally {
            resolved: 1,
            addresses: 2,
            aborted: 35,
            ..outage
        }
        .counts(),
        "1 of 40 hosts resolved, 4 unanswered, 35 not asked after the resolvers stopped answering"
    );
}
