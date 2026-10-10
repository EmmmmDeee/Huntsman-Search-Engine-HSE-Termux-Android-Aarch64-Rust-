//! Scan routing and bounded batch orchestration.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::{EX_DATAERR, EX_NOINPUT, EX_USAGE, MAX_ARTIFACT_BYTES, fail};
use huntsman_recon::error::Error;
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::scan_batch::parse_seed_list;
use huntsman_recon::scan_route::{
    ScanKind, canonical_selector, explicit_people_is_name, infer_kind, inferred_people_is_name,
    parse_kind,
};
use huntsman_recon::textnorm::escape_controls;

use super::profiles::{email_cmd, people_cmd, phone_cmd, username_cmd};

pub(in crate::cli) fn scan_cmd(args: &[String]) -> ExitCode {
    let mut kind: Option<&str> = None;
    let mut input_file: Option<&str> = None;
    let mut forwarded = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "-k" | "--kind" => {
                if kind.is_some() {
                    return fail(EX_USAGE, "scan accepts only one -k/--kind");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan -k/--kind needs a value");
                };
                kind = Some(value.as_str());
                index += 2;
            }
            "--input-file" => {
                if input_file.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --input-file");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --input-file needs a value");
                };
                if value.starts_with("--") {
                    return fail(EX_USAGE, "scan --input-file needs a file path");
                }
                input_file = Some(value.as_str());
                index += 2;
            }
            value => {
                forwarded.push(value.to_owned());
                index += 1;
            }
        }
    }

    if let Some(path) = input_file {
        if !forwarded.is_empty() {
            return fail(
                EX_USAGE,
                "scan --input-file does not accept a positional selector or --save",
            );
        }
        return scan_batch_file(path, kind);
    }

    scan_one(&forwarded, kind)
}

fn scan_batch_file(path: &str, kind: Option<&str>) -> ExitCode {
    let bytes = match read_bounded(Path::new(path), MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(Error::Store(message)) => return fail(EX_NOINPUT, &message),
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    let Ok(body) = String::from_utf8(bytes) else {
        return fail(EX_DATAERR, "scan --input-file is not UTF-8");
    };
    let seeds = match parse_seed_list(&body) {
        Ok(seeds) => seeds,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };

    let total = seeds.len();
    eprintln!("batch: scanning {total} seed(s) from {path}");
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut first_failure = None;

    for (offset, seed) in seeds.iter().enumerate() {
        eprintln!("batch [{}/{}] {}", offset + 1, total, escape_controls(seed));
        let code = scan_one(std::slice::from_ref(seed), kind);
        if code == ExitCode::SUCCESS {
            succeeded += 1;
        } else {
            failed += 1;
            first_failure.get_or_insert(code);
        }
    }

    eprintln!("batch complete: {succeeded} succeeded, {failed} failed, {total} total");
    first_failure.unwrap_or(ExitCode::SUCCESS)
}

fn scan_one(forwarded: &[String], kind: Option<&str>) -> ExitCode {
    let Some(selector) = forwarded.first() else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon scan SELECTOR [-k people|email|username|phone] [--save FILE] | scan --input-file FILE [-k people|email|username|phone]",
        );
    };
    // A leading space must not hide an option from this check, or the selector would be judged
    // one name and the option passed on as part of it.
    if selector.trim_start().starts_with("--") {
        return fail(EX_USAGE, "scan needs SELECTOR before options");
    }

    let route = match kind {
        Some(value) => match parse_kind(value) {
            Ok(kind) => kind,
            Err(other) => return fail(EX_USAGE, &format!("unsupported scan kind: {other}")),
        },
        None => infer_kind(selector),
    };
    // A people route needs a name with two alphabetic tokens. The people command would skip one
    // and exit 0, which would report a refused lookup as a success, so the scan refuses it here.
    // An inferred route is a guess, so it is judged on the selector alone, as on main; an explicit
    // `-k people` is judged on the name it joins, as the people command reads it.
    if route == ScanKind::People {
        if kind.is_none() && !inferred_people_is_name(forwarded) {
            return fail(
                EX_DATAERR,
                "scan selector is not canonical: it is not a name, phone, email, or handle; pass -k people to look it up as a name",
            );
        }
        if kind.is_some() && !explicit_people_is_name(forwarded) {
            return fail(
                EX_DATAERR,
                "scan -k people needs a name: two alphabetic tokens, quoted or as separate words",
            );
        }
    }

    let Some(selector) = canonical_selector(route, selector) else {
        return fail(EX_DATAERR, "scan selector is not canonical");
    };
    let mut forwarded = forwarded.to_vec();
    forwarded[0] = selector;
    eprintln!("scan_route={}", route.command());
    match route {
        ScanKind::Email => email_cmd(&forwarded),
        ScanKind::Username => username_cmd(&forwarded),
        ScanKind::Phone => phone_cmd(&forwarded),
        ScanKind::People => people_cmd(&forwarded),
    }
}
