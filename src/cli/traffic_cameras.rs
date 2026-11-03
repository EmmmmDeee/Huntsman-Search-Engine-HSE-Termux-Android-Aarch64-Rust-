//! CLI adapter for Queensland's public, read-only traffic webcam catalogue.
//! A catalogue record does not attest that its image is current or downloadable.

use std::process::ExitCode;
use std::time::Duration;

use super::{fail, terminal_json_pretty};
use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::qld_traffic_cameras::{self, MAX_CAMERAS, MAX_CATALOGUE_BYTES};
use huntsman_recon::qld_traffic_cameras::reconcile;
use serde_json::json;

const USAGE: &str =
    "usage: huntsman-recon traffic-cameras [--district NAME] [--locality NAME] [--limit 1..2000] [--reconcile]";

pub(super) fn run(args: &[String]) -> ExitCode {
    let mut district: Option<&str> = None;
    let mut locality: Option<&str> = None;
    let mut limit: usize = MAX_CAMERAS;
    let mut compare_gis = false;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--reconcile" if !compare_gis => compare_gis = true,
            "--district" if district.is_none() => {
                let Some(value) = args.next() else {
                    return fail(EX_USAGE, USAGE);
                };
                if value.trim().is_empty() || value.len() > 80 {
                    return fail(EX_USAGE, USAGE);
                }
                district = Some(value);
            }
            "--locality" if locality.is_none() => {
                let Some(value) = args.next() else {
                    return fail(EX_USAGE, USAGE);
                };
                if value.trim().is_empty() || value.len() > 120 {
                    return fail(EX_USAGE, USAGE);
                }
                locality = Some(value);
            }
            "--limit" => {
                let Some(value) = args.next() else {
                    return fail(EX_USAGE, USAGE);
                };
                let Ok(parsed) = value.parse::<usize>() else {
                    return fail(EX_USAGE, USAGE);
                };
                if !(1..=MAX_CAMERAS).contains(&parsed) {
                    return fail(EX_USAGE, USAGE);
                }
                limit = parsed;
            }
            _ => return fail(EX_USAGE, USAGE),
        }
    }
    let http = UreqTransport::new(&TransportConfig {
        timeout: Duration::from_secs(15),
        max_body: MAX_CATALOGUE_BYTES,
        ..TransportConfig::default()
    });
    let now_unix = clock::unix_now();
    let mut report = match qld_traffic_cameras::collect(&http, now_unix) {
        Ok(report) => report,
        Err(err) => return fail(EX_DATAERR, &err.to_string()),
    };
    // Cross-check the *unfiltered* two-source inventories so a locality filter
    // cannot manufacture missing IDs or conceal genuine source divergence.
    let gis = if compare_gis {
        match reconcile::collect_gis(&http, now_unix) {
            Ok(gis) => Some(gis),
            Err(err) => return fail(EX_DATAERR, &err.to_string()),
        }
    } else {
        None
    };
    let reconciliation = gis.as_ref().and_then(|second| reconcile::reconcile(&report, second));
    let accepted = report.outcome.kind.is_accepted()
        && gis.as_ref().is_none_or(|second| second.outcome.kind.is_accepted());
    let provider_total = report.outcome.kind.is_accepted().then_some(report.cameras.len());
    if let Some(filter) = district {
        report
            .cameras
            .retain(|entry| entry.district.eq_ignore_ascii_case(filter));
    }
    if let Some(filter) = locality {
        report
            .cameras
            .retain(|entry| entry.locality.eq_ignore_ascii_case(filter));
    }
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
    if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EX_UNAVAILABLE)
    }
}
