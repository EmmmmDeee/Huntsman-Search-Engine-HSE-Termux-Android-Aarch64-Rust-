//! The `reverse-image` command: a local image's SHA-256, offline, or one upload to the one
//! provider the operator names with `--live --provider NAME`.

use std::path::Path;
use std::process::ExitCode;

use super::{fail, terminal_json_pretty, usage_error};
use huntsman_recon::api_leg;
use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::http::UreqTransport;
use huntsman_recon::reverse_image::{self, ImageReport, MAX_REVERSE_IMAGE_BYTES, Search};
use huntsman_recon::textnorm::escape_controls;

const USAGE: &str = "usage: huntsman-recon reverse-image IMAGE-FILE [--live --provider google_vision|lenso|saucenao] [--json]";

/// What the operator asked for: the file, the one provider that receives it (only with `--live`),
/// and JSON output.
#[derive(Debug, PartialEq, Eq)]
struct Options<'a> {
    path: &'a str,
    provider: Option<&'a str>,
    json: bool,
}

/// The command's arguments, each option at most once. `--live` and `--provider NAME` come
/// together: the operator names the one provider that receives the image, and nothing is sent
/// without both.
fn options(args: &[String]) -> Result<Options<'_>, &'static str> {
    let (mut path, mut provider) = (None, None);
    let (mut live, mut json) = (false, false);
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--live" if !live => live = true,
            "--json" if !json => json = true,
            "--provider" if provider.is_none() => {
                provider = Some(
                    words
                        .next()
                        .ok_or("--provider needs a provider name")?
                        .as_str(),
                );
            }
            option if option.starts_with('-') => return Err("unknown or repeated option"),
            file if path.is_none() => path = Some(file),
            _ => return Err("only one IMAGE-FILE is taken"),
        }
    }
    let path = path.ok_or("an IMAGE-FILE is needed")?;
    match (live, provider) {
        (true, None) => Err(
            "--live needs --provider NAME: name the one provider that receives the image; nothing was sent",
        ),
        (false, Some(_)) => Err("--provider needs --live; without --live nothing is sent"),
        (true, Some(name)) if reverse_image::provider(name).is_none() => {
            Err("unknown provider: name google_vision, lenso or saucenao")
        }
        _ => Ok(Options {
            path,
            provider,
            json,
        }),
    }
}

pub(super) fn reverse_image_cmd(args: &[String]) -> ExitCode {
    let options = match options(args) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason, USAGE),
    };
    // Refuse symlinks and changed inodes; never allocate beyond the image ceiling, even when a
    // file grows during the read.
    let Ok(bytes) = read_bounded(Path::new(options.path), MAX_REVERSE_IMAGE_BYTES as u64) else {
        return fail(
            EX_NOINPUT,
            "reverse-image: the image is unreadable, a link, or larger than 4 MiB; nothing was sent",
        );
    };
    let now = clock::unix_now();
    let report = match options.provider {
        None => reverse_image::fingerprint(&bytes, now),
        Some(name) => {
            let keys = super::credentials::lookup_keys();
            let transport = UreqTransport::new(&api_leg::transport_config());
            reverse_image::search_one(&transport, &bytes, &keys, name, now)
        }
    };
    let report = match report {
        Ok(report) => report,
        Err(reason) => {
            return fail(
                EX_DATAERR,
                &format!("reverse-image: {reason}; nothing was sent"),
            );
        }
    };
    if options.json {
        match terminal_json_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(_) => return fail(EX_UNAVAILABLE, "reverse-image: could not render the report"),
        }
    } else {
        print_text(&report);
    }
    status(&report)
}

/// The report as text: the file first, then whether a search ran, then what the provider
/// returned. Provider text is printed with its control characters escaped.
fn print_text(report: &ImageReport) {
    println!(
        "file sha256={} bytes={} format={}",
        report.file_sha256, report.file_bytes, report.format
    );
    let Some(provider) = report.provider else {
        println!(
            "no search ran: nothing was sent. --live --provider google_vision|lenso|saucenao uploads the image to that one provider"
        );
        return;
    };
    let reason = report
        .outcome
        .as_ref()
        .map_or_else(String::new, |outcome| escape_controls(&outcome.reason()));
    if let Some(upload) = &report.upload {
        let removed = if upload.metadata_removed.is_empty() {
            "none found".to_owned()
        } else {
            escape_controls(&upload.metadata_removed.join(", "))
        };
        println!(
            "uploaded to {provider}: sha256={} bytes={} metadata removed: {removed}",
            upload.sha256, upload.bytes
        );
    }
    match (report.search, report.matches.as_deref()) {
        (Search::Completed, Some(matches)) => {
            println!(
                "{provider}: search completed, {} match(es) from its own index",
                matches.len()
            );
            for matched in matches {
                println!(
                    "match={} source={} image={} score={}",
                    matched.match_type,
                    escape_controls(matched.source_url.as_deref().unwrap_or("none")),
                    escape_controls(matched.image_url.as_deref().unwrap_or("none")),
                    matched
                        .provider_score
                        .map_or_else(|| "none".to_owned(), |score| score.to_string())
                );
            }
            if report.truncated {
                println!(
                    "{provider} returned more matches than the {} kept",
                    reverse_image::MAX_MATCHES
                );
            }
        }
        (Search::Failed, _) | (Search::Completed, None) => {
            println!("{provider}: search failed, not a negative result: {reason}");
        }
        (Search::NotRun, _) => println!("no search ran: nothing was sent: {reason}"),
    }
}

/// Success offline and for a completed search; otherwise a refusal before sending (77), a
/// provider with no key configured (66), or no usable answer (69).
fn status(report: &ImageReport) -> ExitCode {
    let Some(outcome) = &report.outcome else {
        return ExitCode::SUCCESS;
    };
    if outcome.is_accepted() {
        return ExitCode::SUCCESS;
    }
    let code = if outcome.kind.is_refused_before_sending() {
        EX_NOPERM
    } else if outcome.kind.is_not_configured() {
        EX_NOINPUT
    } else {
        EX_UNAVAILABLE
    };
    fail(code, &format!("reverse-image: {}", outcome.reason()))
}

#[cfg(test)]
mod tests {
    use super::{Options, options};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn live_takes_exactly_one_named_provider_and_offline_takes_none() {
        assert_eq!(
            options(&args(&["photo.jpg"])),
            Ok(Options {
                path: "photo.jpg",
                provider: None,
                json: false
            })
        );
        assert_eq!(
            options(&args(&[
                "--live",
                "photo.jpg",
                "--provider",
                "lenso",
                "--json"
            ])),
            Ok(Options {
                path: "photo.jpg",
                provider: Some("lenso"),
                json: true
            })
        );
        for refused in [
            &["photo.jpg", "--live"][..],
            &["photo.jpg", "--provider", "lenso"][..],
            &["photo.jpg", "--live", "--provider", "everyone"][..],
            &["photo.jpg", "--live", "--provider"][..],
            &[
                "photo.jpg",
                "--live",
                "--provider",
                "lenso",
                "--provider",
                "saucenao",
            ][..],
            &["photo.jpg", "--live", "--live", "--provider", "lenso"][..],
            &["a.jpg", "b.jpg"][..],
            &["--json"][..],
            &[][..],
        ] {
            assert!(options(&args(refused)).is_err(), "{refused:?}");
        }
    }
}
