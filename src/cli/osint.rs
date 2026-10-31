//! CLI adapter for the operator-controlled, read-only OSINT federation.

use std::path::Path;
use std::process::ExitCode;

use super::{fail, lookup, terminal_json_pretty};
use huntsman_recon::clock;
use huntsman_recon::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::federated_osint::{self, X_API_ORIGIN, X_BEARER_SLOT};
use huntsman_recon::fetch::{AuthStyle, Credential};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::geoint;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::keys::Keys;
use huntsman_recon::osint_area_risk::{self, MAX_RISK_BYTES};
use huntsman_recon::osint_casework::{self, MAX_CASE_BYTES};
use huntsman_recon::rhinser_catalog::Catalog;
use huntsman_recon::rhinser_nfc;
use huntsman_recon::rhinser_workspace::{MAX_WORKSPACE_BYTES, Workspace};
use huntsman_recon::source_outcome::SourceOutcomeKind;

pub(super) const OSINT_HELP: &str = "osint nfc apdu|ndef HEX | osint catalog [--json|--category ID|--find QUERY|--tool ID|--url ID|--query ID QUERY] | osint workspace FILE init|show|case ID TITLE|note CASE TEXT|lead CASE ID URL SUMMARY|bookmark ID|favourite ID|recent ID|search QUERY|setting KEY VALUE | osint case FILE | osint area-risk FILE LAT,LON [RADIUS_M] [CATEGORY] | osint area-compare FILE LAT,LON LAT,LON [CATEGORY] | osint x QUERY... | osint x-api QUERY... | osint local QUERY DIR | osint plan SEED... | osint lookup KIND SELECTOR [--save FILE]\n\
  case: source-linked receipts, claims, chronology, conflicts and verification priorities.\n\
  area-risk: bounded public-event pressure, never a safety guarantee.\n\
  area-compare: two locations under the same heuristic and dataset.\n\
  x: public search-engine indexed X leads (keyless; not Grok's private search).\n\
  x-api: one page of official X recent-search results; requires operator-owned HUNTSMAN_X_BEARER_TOKEN; may consume credits.\n\
  local: offline search of your own .txt/.md evidence directory; no third-party API required.\n\
  plan: offline graph and source planning using the existing Huntsman engine.\n\
  lookup: existing Huntsman typed provider lookup with public and operator-configured enrichment.\n\
  Network reports are JSON; local search and graph planning retain established CLI output. No wallet signing.";

/// Offline directory browser for all 83 reconstructed Rhinser Australian sources.
fn catalog_cmd(args: &[String]) -> ExitCode {
    let catalog = match Catalog::load() {
        Ok(catalog) => catalog,
        Err(error) => return fail(EX_DATAERR, &format!("catalogue invalid: {error}")),
    };
    match args {
        [] => {
            println!(
                "categories={} tools={} status=lead_only_unverified",
                catalog.categories.len(),
                catalog.tool_count()
            );
            for category in &catalog.categories {
                println!(
                    "category={} count={} name={}",
                    category.id,
                    category.tools.len(),
                    category.name
                );
            }
            ExitCode::SUCCESS
        }
        [flag] if flag == "--json" => emit(&catalog, true),
        [flag, id] if flag == "--category" => match catalog.category(id) {
            Some(category) => emit(category, true),
            None => fail(EX_DATAERR, "unknown catalogue category"),
        },
        [flag, query] if flag == "--find" => emit(&catalog.find(query), true),
        [flag, id] if flag == "--tool" => match catalog.tool(id) {
            Some(tool) => emit(&tool, true),
            None => fail(EX_DATAERR, "unknown catalogue tool"),
        },
        [flag, id, query] if flag == "--query" => match catalog.search_url(id, query) {
            Ok(url) => {
                println!("{url}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(EX_DATAERR, &error),
        },
        [flag, id] if flag == "--url" => match catalog.tool(id) {
            Some(tool) => {
                println!("{}", tool.tool.url);
                ExitCode::SUCCESS
            }
            None => fail(EX_DATAERR, "unknown catalogue tool"),
        },
        _ => fail(
            EX_USAGE,
            "usage: osint catalog [--json|--category ID|--find QUERY|--tool ID|--url ID|--query ID QUERY]",
        ),
    }
}

/// Read-only NFC decoder for caller-provided hex dumps; no Android radio access.
fn nfc_cmd(args: &[String]) -> ExitCode {
    let [mode, hex] = args else {
        return fail(EX_USAGE, "usage: osint nfc apdu|ndef HEX");
    };
    let bytes = match rhinser_nfc::decode_hex(hex) {
        Ok(bytes) => bytes,
        Err(error) => return fail(EX_DATAERR, &error),
    };
    match mode.as_str() {
        "apdu" => match rhinser_nfc::inspect_apdu(&bytes) {
            Ok(report) => emit(&report, true),
            Err(error) => fail(EX_DATAERR, &error),
        },
        "ndef" => match rhinser_nfc::inspect_ndef(&bytes) {
            Ok(report) => emit(&report, true),
            Err(error) => fail(EX_DATAERR, &error),
        },
        _ => fail(EX_USAGE, "usage: osint nfc apdu|ndef HEX"),
    }
}

/// Persistent, bounded, private OSINT casebook; the Rust library owns validation.
fn workspace_cmd(args: &[String]) -> ExitCode {
    let [filename, operation, rest @ ..] = args else {
        return fail(
            EX_USAGE,
            "usage: osint workspace FILE init|show|case|note|lead|bookmark|favourite|recent|search|setting ...",
        );
    };
    let path = Path::new(filename);
    if operation == "init" {
        if !rest.is_empty() {
            return fail(EX_USAGE, "usage: osint workspace FILE init");
        }
        match std::fs::symlink_metadata(path) {
            Ok(_) => return fail(EX_DATAERR, "workspace already exists"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        }
        let bytes = match serde_json::to_vec_pretty(&Workspace::default()) {
            Ok(bytes) => bytes,
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        };
        return match huntsman_recon::fsio::write_atomic(path, &bytes, MAX_WORKSPACE_BYTES) {
            Ok(()) => {
                println!("workspace_initialized");
                ExitCode::SUCCESS
            }
            Err(error) => fail_error(&error),
        };
    }

    let bytes = match read_bounded(path, MAX_WORKSPACE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return fail_error(&error),
    };
    let mut workspace = match Workspace::from_json(&bytes) {
        Ok(workspace) => workspace,
        Err(error) => return fail(EX_DATAERR, &error),
    };
    if operation == "show" {
        return if rest.is_empty() {
            emit(&workspace, true)
        } else {
            fail(EX_USAGE, "usage: osint workspace FILE show")
        };
    }
    let now = clock::unix_now();
    let outcome = match (operation.as_str(), rest) {
        ("case", [id, title]) => workspace.create_case(id, title),
        ("note", [case_id, note]) => workspace.add_note(case_id, note, now),
        ("lead", [case_id, id, url, summary]) => workspace.add_lead(case_id, id, url, summary, now),
        ("bookmark" | "favourite" | "recent", [id]) => workspace.remember_tool(id, operation),
        ("search", [query]) => workspace.remember_search(query),
        ("setting", [key, value]) => {
            if key.is_empty()
                || workspace.settings.len() >= 512 && !workspace.settings.contains_key(key)
            {
                Err("invalid setting or limit reached".to_owned())
            } else {
                workspace.settings.insert(key.clone(), value.clone());
                Ok(())
            }
        }
        _ => return fail(EX_USAGE, "invalid workspace operation or argument count"),
    };
    if let Err(error) = outcome.and_then(|()| workspace.validate()) {
        return fail(EX_DATAERR, &error);
    }
    let updated = match serde_json::to_vec_pretty(&workspace) {
        Ok(data) => data,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    match huntsman_recon::fsio::write_atomic(path, &updated, MAX_WORKSPACE_BYTES) {
        Ok(()) => {
            println!("workspace_saved");
            ExitCode::SUCCESS
        }
        Err(error) => fail_error(&error),
    }
}

fn optional_credential(
    keys: &Keys,
    slot: &'static str,
    provider: &'static str,
    origin: &'static str,
    now: u64,
) -> Result<Credential, Error> {
    let secret = keys
        .get(slot)
        .ok_or_else(|| Error::missing_credential(slot))?;
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: provider.to_owned(),
        credential_slot: slot.to_owned(),
        approved_at_unix: now,
        approval_provenance: format!(
            "operator configured {slot} for explicitly selected OSINT command"
        ),
    })?;
    Ok(Credential::new(authority, secret, AuthStyle::Bearer)?.only_for_origin(origin))
}

fn emit<T: serde::Serialize>(report: &T, success: bool) -> ExitCode {
    match terminal_json_pretty(report) {
        Ok(json) => {
            println!("{json}");
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EX_UNAVAILABLE)
            }
        }
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

fn fail_error(error: &Error) -> ExitCode {
    let code = match error {
        Error::Invalid(_) => EX_USAGE,
        Error::InvalidValue(_) => EX_DATAERR,
        Error::MissingCredential(_) => EX_NOINPUT,
        Error::Network(_) => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    };
    fail(code, &error.to_string())
}

pub(super) fn osint_cmd(args: &[String]) -> ExitCode {
    let now = clock::unix_now();
    match args {
        [mode, rest @ ..] if mode == "catalog" => catalog_cmd(rest),
        [mode, rest @ ..] if mode == "nfc" => nfc_cmd(rest),
        [mode, rest @ ..] if mode == "workspace" => workspace_cmd(rest),
        [mode, path] if mode == "case" => {
            match read_bounded(Path::new(path), MAX_CASE_BYTES as u64) {
                Ok(data) => match osint_casework::review_json(&data) {
                    Ok(report) => emit(&report, true),
                    Err(error) => fail_error(&error),
                },
                Err(error) => fail_error(&error),
            }
        }
        [mode, path, coords, rest @ ..] if mode == "area-risk" => {
            if rest.len() > 2 {
                return fail(EX_USAGE, OSINT_HELP);
            }
            let radius = match rest.first() {
                Some(raw) => match raw.parse::<f64>() {
                    Ok(value) => value,
                    Err(_) => return fail(EX_USAGE, "radius must be numeric metres"),
                },
                None => 1000.0,
            };
            let category = rest.get(1).map_or("general", String::as_str);
            match area_report(path, coords, radius, category) {
                Ok(report) => emit(&report, true),
                Err(error) => fail_error(&error),
            }
        }
        [mode, path, first, second, rest @ ..] if mode == "area-compare" => {
            if rest.len() > 1 {
                return fail(EX_USAGE, OSINT_HELP);
            }
            let category = rest.first().map_or("general", String::as_str);
            match (
                area_report(path, first, 1000.0, category),
                area_report(path, second, 1000.0, category),
            ) {
                (Ok(a), Ok(b)) => emit(&serde_json::json!({"first":a,"second":b}), true),
                (Err(error), _) | (_, Err(error)) => fail_error(&error),
            }
        }
        [mode, terms @ ..] if mode == "x" || mode == "x-api" => {
            if terms.is_empty() || terms.iter().any(|term| term.starts_with("--")) {
                return fail(EX_USAGE, OSINT_HELP);
            }
            let query = terms.join(" ");
            let transport = UreqTransport::new(&TransportConfig::default());
            let report = if mode == "x-api" {
                let keys = super::credentials::lookup_keys();
                let credential = match optional_credential(
                    &keys,
                    X_BEARER_SLOT,
                    "official_x_recent_search",
                    X_API_ORIGIN,
                    now,
                ) {
                    Ok(credential) => credential,
                    Err(error) => return fail_error(&error),
                };
                federated_osint::search_official_x(&transport, &credential, &query, now)
            } else {
                federated_osint::search_indexed_x(&transport, &query, now)
            };
            match report {
                Ok(report) => {
                    let accepted = !report.hits.is_empty()
                        && report
                            .outcomes
                            .iter()
                            .any(|outcome| outcome.kind == SourceOutcomeKind::Success);
                    emit(&report, accepted)
                }
                Err(error) => fail_error(&error),
            }
        }
        [mode, query, dir] if mode == "local" => lookup::search_cmd(&[query.clone(), dir.clone()]),
        [mode, seeds @ ..] if mode == "plan" && !seeds.is_empty() => lookup::plan_cmd(seeds),
        [mode, kind, selector, rest @ ..] if mode == "lookup" => {
            // Reuse the same CLI collection path as 'scan', including its evidence ledger,
            // source outcome classification, redaction, and optional --save support.
            if kind.starts_with('-') || selector.starts_with('-') {
                return fail(EX_USAGE, OSINT_HELP);
            }
            let mut forwarded = vec![selector.clone(), "-k".to_owned(), kind.clone()];
            forwarded.extend(rest.iter().cloned());
            lookup::scan_cmd(&forwarded)
        }
        _ => fail(EX_USAGE, OSINT_HELP),
    }
}

fn area_report(
    path: &str,
    coords: &str,
    radius: f64,
    category: &str,
) -> Result<osint_area_risk::AreaEstimate, Error> {
    let (lat, lon) = geoint::parse_latlon(coords)?;
    let bytes = read_bounded(Path::new(path), MAX_RISK_BYTES as u64)?;
    let dataset = osint_area_risk::input_json(&bytes)?;
    osint_area_risk::estimate(&dataset, lat, lon, radius, category)
}
