//! CLI adapter for Queensland's public, read-only traffic webcam catalogue.
//! A catalogue record does not attest that its image is current or downloadable.

use std::process::ExitCode;
use std::time::Duration;

use super::{fail, terminal_json_pretty};
use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::qld_traffic_cameras::reconcile;
use huntsman_recon::qld_traffic_cameras::{self, MAX_CAMERAS, MAX_CATALOGUE_BYTES};
use huntsman_recon::source_outcome::SourceExecutionOutcome;
use serde_json::json;

const USAGE: &str = "usage: huntsman-recon traffic-cameras [--district NAME] [--locality NAME] [--limit 1..2000] [--reconcile]";

/// The command's options, each given at most once.
struct Options<'a> {
    district: Option<&'a str>,
    locality: Option<&'a str>,
    limit: usize,
    reconcile: bool,
}

/// A filter value of at most `bound` bytes that is not blank.
fn filter_value(value: Option<&String>, bound: usize) -> Option<&str> {
    value
        .filter(|value| !value.trim().is_empty() && value.len() <= bound)
        .map(String::as_str)
}

fn options(args: &[String]) -> Option<Options<'_>> {
    let mut parsed = Options {
        district: None,
        locality: None,
        limit: MAX_CAMERAS,
        reconcile: false,
    };
    let mut limit_given = false;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--reconcile" if !parsed.reconcile => parsed.reconcile = true,
            "--district" if parsed.district.is_none() => {
                parsed.district = Some(filter_value(args.next(), 80)?);
            }
            "--locality" if parsed.locality.is_none() => {
                parsed.locality = Some(filter_value(args.next(), 120)?);
            }
            "--limit" if !limit_given => {
                limit_given = true;
                parsed.limit = args
                    .next()?
                    .parse::<usize>()
                    .ok()
                    .filter(|limit| (1..=MAX_CAMERAS).contains(limit))?;
            }
            _ => return None,
        }
    }
    Some(parsed)
}

/// The status for the sources' `outcomes`: success when every one answered; otherwise a
/// refusal before sending (77), then a source with no key configured (66), then no usable
/// answer (69).
fn status(outcomes: &[&SourceExecutionOutcome]) -> ExitCode {
    if outcomes.iter().all(|outcome| outcome.kind.is_accepted()) {
        return ExitCode::SUCCESS;
    }
    let any = |pick: fn(&SourceExecutionOutcome) -> bool| outcomes.iter().any(|o| pick(o));
    let code = if any(|o| o.kind.is_refused_before_sending()) {
        EX_NOPERM
    } else if any(|o| o.kind.is_not_configured()) {
        EX_NOINPUT
    } else {
        EX_UNAVAILABLE
    };
    for outcome in outcomes.iter().filter(|o| !o.kind.is_accepted()) {
        eprintln!("traffic-cameras: {}", outcome.reason());
    }
    ExitCode::from(code)
}

pub(super) fn run(args: &[String]) -> ExitCode {
    let Some(Options {
        district,
        locality,
        limit,
        reconcile: compare_gis,
    }) = options(args)
    else {
        return fail(EX_USAGE, USAGE);
    };
    let keys = super::credentials::lookup_keys();
    let http = UreqTransport::new(&TransportConfig {
        timeout: Duration::from_secs(20),
        max_body: MAX_CATALOGUE_BYTES,
        ..TransportConfig::default()
    });
    let now_unix = clock::unix_now();
    let mut report = qld_traffic_cameras::collect(&http, &keys, now_unix);
    // Cross-check the *unfiltered* two-source inventories so a locality filter
    // cannot manufacture missing IDs or conceal genuine source divergence.
    let gis = compare_gis.then(|| reconcile::collect_gis(&http, now_unix));
    let reconciliation = gis
        .as_ref()
        .and_then(|second| reconcile::reconcile(&report, second));
    let provider_total = report
        .outcome
        .kind
        .is_accepted()
        .then_some(report.cameras.len());
    report.cameras.retain(|entry| {
        district.is_none_or(|d| entry.district.eq_ignore_ascii_case(d))
            && locality.is_none_or(|l| entry.locality.eq_ignore_ascii_case(l))
    });
    let matching = report.cameras.len();
    report.cameras.truncate(limit);
    let rendered = terminal_json_pretty(&json!({
        "provider_total": provider_total,
        "matching": matching,
        "returned": report.cameras.len(),
        "filters": {"district":district,"locality":locality},
        "catalogue": report,
        "gis_catalogue": gis,
        "reconciliation": reconciliation,
        "disclaimer": "Publisher catalogue metadata, not verification of current imagery or recording availability."
    }));
    match rendered {
        Ok(text) => println!("{text}"),
        Err(_) => return fail(EX_DATAERR, "unable to serialize camera catalogue"),
    }
    let mut outcomes = vec![&report.outcome];
    outcomes.extend(gis.as_ref().map(|second| &second.outcome));
    status(&outcomes)
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::{EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, SourceExecutionOutcome, options, status};
    use huntsman_recon::source_outcome::SourceOutcomeKind;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn each_option_is_taken_once_and_bounded() {
        let given = args(&["--district", "Metropolitan", "--limit", "5", "--reconcile"]);
        let parsed = options(&given).expect("valid");
        assert_eq!(parsed.district, Some("Metropolitan"));
        assert_eq!(parsed.locality, None);
        assert_eq!(parsed.limit, 5);
        assert!(parsed.reconcile);
        for bad in [
            &["--limit", "0"][..],
            &["--limit", "2001"],
            &["--limit", "5", "--limit", "6"],
            &["--reconcile", "--reconcile"],
            &["--district"],
            &["--district", "  "],
            &["--locality", "a", "--locality", "b"],
            &["--bogus"],
        ] {
            assert!(options(&args(bad)).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_missing_key_a_refusal_and_no_answer_exit_differently() {
        let outcome = |kind| SourceExecutionOutcome::failed("s", 1, kind, None, "why");
        let answered = SourceExecutionOutcome::success("s", 1, 1);
        let status_of = |kinds: &[SourceOutcomeKind]| {
            let failed: Vec<SourceExecutionOutcome> = kinds.iter().map(|k| outcome(*k)).collect();
            let mut all: Vec<&SourceExecutionOutcome> = vec![&answered];
            all.extend(failed.iter());
            status(&all)
        };
        assert_eq!(status_of(&[]), ExitCode::SUCCESS);
        assert_eq!(
            status_of(&[SourceOutcomeKind::NotConfigured]),
            ExitCode::from(EX_NOINPUT)
        );
        assert_eq!(
            status_of(&[
                SourceOutcomeKind::NotConfigured,
                SourceOutcomeKind::RefusedBeforeSending
            ]),
            ExitCode::from(EX_NOPERM)
        );
        assert_eq!(
            status_of(&[SourceOutcomeKind::RateLimited]),
            ExitCode::from(EX_UNAVAILABLE)
        );
    }
}
