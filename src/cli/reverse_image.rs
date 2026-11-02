//! Local image fingerprinting and opt-in, keyed external reverse-image search.
use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::reverse_image::{self, MAX_REVERSE_IMAGE_BYTES};

use super::fail;

const USAGE: &str = "usage: huntsman-recon reverse-image IMAGE-FILE [--live] [--provider google_vision|lenso|saucenao] [--json]\n--live: send image to configured Google Vision, Lenso and SauceNAO indexes (may incur charges)\nWithout --live: compute local SHA-256 only; no network requests.";

pub(super) fn reverse_image_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(EX_USAGE, USAGE);
    }
    let mut path: Option<&str> = None;
    let mut live = false;
    let mut as_json = false;
    let mut provider: Option<&str> = None;
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        match arg.as_str() {
            "--live" if !live => live = true,
            "--json" if !as_json => as_json = true,
            "--provider" if provider.is_none() => {
                let Some(name) = words.next() else {
                    return fail(EX_USAGE, USAGE);
                };
                provider = Some(name.as_str());
            }
            option if option.starts_with('-') || path.is_some() => return fail(EX_USAGE, USAGE),
            file => path = Some(file),
        }
    }
    let Some(path) = path else {
        return fail(EX_USAGE, USAGE);
    };
    let path = Path::new(path);
    // Refuse symlinks and changed inodes; never allocate beyond the image ceiling,
    // even when a file grows during the read.
    let Ok(bytes) = read_bounded(path, MAX_REVERSE_IMAGE_BYTES as u64) else {
        return fail(
            EX_NOINPUT,
            "image is unreadable, linked or larger than 4 MiB",
        );
    };
    let keys = super::credentials::lookup_keys();
    let transport = UreqTransport::new(&TransportConfig::default());
    let report = match reverse_image::search_selected(
        &transport,
        &bytes,
        &keys,
        clock::unix_now(),
        live,
        provider,
    ) {
        Ok(report) => report,
        Err(reason) => return fail(EX_DATAERR, reason),
    };
    if as_json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(_) => return fail(EX_UNAVAILABLE, "could not serialise image report"),
        }
    } else {
        println!(
            "sha256={} bytes={} live={}",
            report.image_sha256, report.bytes, report.live_requested
        );
        for status in &report.statuses {
            println!(
                "provider={} state={} results={} detail={}",
                status.provider, status.state, status.results, status.detail
            );
        }
        for matched in &report.matches {
            println!(
                "provider={} match={} source={} image={} score={}",
                matched.provider,
                matched.match_type,
                matched.source_url.as_deref().unwrap_or("none"),
                matched.image_url.as_deref().unwrap_or("none"),
                matched
                    .provider_score
                    .map_or_else(|| "none".to_owned(), |v| v.to_string())
            );
        }
    }
    if live && report.statuses.iter().all(|s| s.state == "unconfigured") {
        fail(
            EX_NOINPUT,
            "no reverse-image provider credentials configured",
        )
    } else if report.statuses.iter().any(|s| s.state == "failed") {
        fail(
            EX_UNAVAILABLE,
            "reverse-image provider(s) failed; inspect per-provider status",
        )
    } else {
        ExitCode::SUCCESS
    }
}
