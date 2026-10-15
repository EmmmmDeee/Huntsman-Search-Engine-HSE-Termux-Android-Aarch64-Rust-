//! Scan routing and bounded batch orchestration.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::{MAX_ARTIFACT_BYTES, fail};
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::scan_batch::parse_seed_list;
use huntsman_recon::scan_route::{
    ScanKind, canonical_selector, explicit_people_is_name, infer_kind, inferred_people_is_name,
    parse_kind,
};
use huntsman_recon::textnorm::escape_controls;

use super::profiles::{
    domain_cmd, email_cmd, exposure_cmd, ip_cmd, network_cmd, people_cmd, phone_cmd, username_cmd,
};

pub(in crate::cli) fn scan_cmd(args: &[String]) -> ExitCode {
    let mut kind: Option<&str> = None;
    let mut input_file: Option<&str> = None;
    let mut save_dir: Option<&str> = None;
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
            "--save-dir" => {
                if save_dir.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --save-dir");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --save-dir needs a value");
                };
                if value.starts_with("--") {
                    return fail(EX_USAGE, "scan --save-dir needs a directory path");
                }
                save_dir = Some(value.as_str());
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
                "scan --input-file does not accept a positional selector or --save; use --save-dir DIR to persist every seed",
            );
        }
        return scan_batch_file(path, kind, save_dir);
    }

    if save_dir.is_some() {
        return fail(
            EX_USAGE,
            "scan --save-dir applies only to --input-file batches; use --save FILE for a single selector",
        );
    }

    scan_one(&forwarded, kind)
}

fn scan_batch_file(path: &str, kind: Option<&str>, save_dir: Option<&str>) -> ExitCode {
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
        // Each seed gets its own artifact path so concurrent persistence never
        // collides: a zero-padded 1-based index keeps names unique and ordered
        // even when two seeds sanitize to the same stem.
        let code = match save_dir {
            Some(dir) => {
                let target = per_seed_save_path(dir, offset + 1, seed);
                let forwarded = [
                    seed.clone(),
                    "--save".to_owned(),
                    target.to_string_lossy().into_owned(),
                ];
                scan_one(&forwarded, kind)
            }
            None => scan_one(std::slice::from_ref(seed), kind),
        };
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

/// The artifact path for the `index`-th seed (1-based) under `dir`.
///
/// The stem is `{index:04}-{sanitized}` so the ordinal alone guarantees a unique,
/// ordered name; the sanitized seed is a readability aid, never the uniqueness
/// guarantee. The seed is reduced to the session-id charset (ASCII alphanumeric
/// plus `.`, `_`, `-`), every other byte folded to `_`, and bounded to 60 bytes so
/// a long or adversarial seed cannot produce an unbounded or unsafe filename.
fn per_seed_save_path(dir: &str, index: usize, seed: &str) -> PathBuf {
    const MAX_STEM_BYTES: usize = 60;
    let mut stem = String::with_capacity(MAX_STEM_BYTES);
    for ch in seed.chars() {
        if stem.len() >= MAX_STEM_BYTES {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            stem.push(ch);
        } else {
            stem.push('_');
        }
    }
    let file = if stem.is_empty() {
        format!("{index:04}.json")
    } else {
        format!("{index:04}-{stem}.json")
    };
    Path::new(dir).join(file)
}

fn scan_one(forwarded: &[String], kind: Option<&str>) -> ExitCode {
    let Some(selector) = forwarded.first() else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon scan SELECTOR [-k people|email|exposure|username|phone|domain|ip|network] [--save FILE] | scan --input-file FILE [-k KIND] [--save-dir DIR]",
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
        ScanKind::Exposure => exposure_cmd(&forwarded),
        ScanKind::Username => username_cmd(&forwarded),
        ScanKind::Phone => phone_cmd(&forwarded),
        ScanKind::Domain => domain_cmd(&forwarded),
        ScanKind::Ip => ip_cmd(&forwarded),
        ScanKind::Network => network_cmd(&forwarded),
        ScanKind::People => people_cmd(&forwarded),
    }
}

#[cfg(test)]
mod tests {
    use super::per_seed_save_path;

    #[test]
    fn index_prefix_is_zero_padded_and_keeps_a_safe_stem() {
        assert_eq!(
            per_seed_save_path("out", 1, "alice@example.org"),
            std::path::Path::new("out/0001-alice_example.org.json")
        );
        assert_eq!(
            per_seed_save_path("out", 42, "Bob.Jones"),
            std::path::Path::new("out/0042-Bob.Jones.json")
        );
    }

    #[test]
    fn separators_and_control_bytes_cannot_escape_the_directory() {
        let path = per_seed_save_path("out", 7, "../../etc/passwd");
        assert_eq!(path, std::path::Path::new("out/0007-.._.._etc_passwd.json"));
        // No real parent-directory component survives sanitization.
        assert!(
            !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        );
    }

    #[test]
    fn distinct_seeds_that_sanitize_alike_still_get_distinct_paths() {
        let a = per_seed_save_path("out", 1, "a/b");
        let b = per_seed_save_path("out", 2, "a b");
        assert_ne!(a, b);
        assert_eq!(a, std::path::Path::new("out/0001-a_b.json"));
        assert_eq!(b, std::path::Path::new("out/0002-a_b.json"));
    }

    #[test]
    fn an_empty_or_fully_stripped_seed_falls_back_to_the_index() {
        assert_eq!(
            per_seed_save_path("out", 3, ""),
            std::path::Path::new("out/0003.json")
        );
    }

    #[test]
    fn a_long_seed_is_bounded_to_sixty_stem_bytes() {
        let seed = "x".repeat(500);
        let path = per_seed_save_path("out", 9, &seed);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 name");
        // "0009-" (5) + 60 stem + ".json" (5) = 70.
        assert_eq!(name, format!("0009-{}.json", "x".repeat(60)));
        assert_eq!(name.len(), 70);
    }
}
