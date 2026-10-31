//! Binary adapter commands. Business logic stays in the library crate.

use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::fail;
use huntsman_recon::clock;
use huntsman_recon::diagnostics::TermuxState;
use huntsman_recon::entity::merge_by_uid;
use huntsman_recon::environment::SERVE_TOKEN_ENV;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::runtime::analyze_offline_with_history;
use huntsman_recon::scan_api::ScanApi;
use huntsman_recon::scan_artifact::{ArtifactError, ArtifactHistory};
use huntsman_recon::scan_route::{
    ScanKind, canonical_selector, explicit_people_is_name, infer_kind, inferred_people_is_name,
    parse_kind,
};
use huntsman_recon::source_outcome::{SourceExecutionOutcome, SourceRun};
use huntsman_recon::textnorm::one_line;
use huntsman_recon::web_server::{
    LookupError, LookupQuery, LookupReport, ServeConfig, Server, resolve_serve_bind,
};

use super::lookup::{Refused, collect, investigate_entities};
use super::scans::{default_rules_dir, default_scan_dir, open_api};

/// Printed once by `serve` under Termux. Android may stop a process that Termux started while
/// Termux is in the background or the screen is off, so the page would stop answering.
const TERMUX_BACKGROUND_HINT: &str = "serve: Android may stop this server while Termux is in the background; run termux-wake-lock to keep it running with the screen off, and on Android 12 or later see \"Keep serve running on Android\" in docs/INSTALL.md";

fn bad_selector(message: &str) -> LookupError {
    LookupError {
        status: 400,
        message: message.into(),
    }
}

/// `/api/analyze`: the offline investigation spine on the seeds, as `plan` runs it, bridged to the
/// saved scans in `history` when `serve --history` gave one.
fn web_analyze(
    seeds: &[String],
    history: Option<&ArtifactHistory>,
) -> Result<serde_json::Value, LookupError> {
    analyze_offline_with_history(seeds, history).map_err(|error| LookupError {
        status: match error {
            Error::Invalid(_) => 422,
            _ => 500,
        },
        message: error.to_string(),
    })
}

/// `/api/inspect`: the `exif` and `docmeta` commands over one uploaded file, as one report. Both read
/// the same bytes the commands read from disk; their entities for the file merge into one. A file
/// `exif` cannot decode (a PDF or another non-image, or a damaged EXIF block) keeps `docmeta`'s
/// findings and says why in an inconclusive `exif` outcome.
fn web_inspect(label: &str, bytes: &[u8]) -> Result<LookupReport, LookupError> {
    let now = clock::unix_now();
    // APK set containers are ZIP archives with nested APKs, not individual APKs.
    // Reuse the same bounded offline parser and evidence contract as `apk set`.
    if label.rsplit_once('.').is_some_and(|(_, extension)| {
        ["apks", "xapk", "apkm"]
            .iter()
            .any(|kind| extension.eq_ignore_ascii_case(kind))
    }) {
        let report =
            huntsman_recon::apk_intel::container::run(bytes, label, now).map_err(|error| {
                LookupError {
                    status: 422,
                    message: error.to_string(),
                }
            })?;
        let text = huntsman_recon::lookup_report::render(&report.entities, &report.outcomes)
            .map_err(|message| LookupError {
                status: 500,
                message,
            })?;
        return Ok(LookupReport {
            route: "inspect",
            text,
            entities: report.entities,
            outcomes: report.outcomes,
            scan: None,
            status: None,
        });
    }
    // Reuse the CLI's bounded offline parser. Archive names and signing-block IDs
    // remain unverified observations, never proof of package ownership.
    if label
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("apk"))
    {
        let report =
            huntsman_recon::apk_intel::run(bytes, label, now).map_err(|error| LookupError {
                status: 422,
                message: error.to_string(),
            })?;
        let text = huntsman_recon::lookup_report::render(&report.entities, &report.outcomes)
            .map_err(|message| LookupError {
                status: 500,
                message,
            })?;
        return Ok(LookupReport {
            route: "inspect",
            text,
            entities: report.entities,
            outcomes: report.outcomes,
            scan: None,
            status: None,
        });
    }
    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    match huntsman_recon::exif::run(bytes, label, now) {
        SourceRun::Printed { report, .. } => {
            entities.extend(report.entities);
            outcomes.extend(report.outcomes);
        }
        SourceRun::Network(why) | SourceRun::Failed(why) => {
            outcomes.push(SourceExecutionOutcome::inconclusive(
                huntsman_recon::exif::SOURCE,
                now,
                why,
            ));
        }
    }
    match huntsman_recon::docmeta::run(bytes, label, now) {
        SourceRun::Printed { report, .. } => {
            entities.extend(report.entities);
            outcomes.extend(report.outcomes);
        }
        SourceRun::Network(why) | SourceRun::Failed(why) => {
            return Err(LookupError {
                status: 422,
                message: why,
            });
        }
    }
    merge_by_uid(&mut entities);
    let text = huntsman_recon::lookup_report::render(&entities, &outcomes).map_err(|message| {
        LookupError {
            status: 500,
            message,
        }
    })?;
    Ok(LookupReport {
        route: "inspect",
        text,
        entities,
        outcomes,
        scan: None,
        status: None,
    })
}

/// `/api/investigate`: the `investigate` command over the text the page sends, as one report. The
/// classifier makes no request, so the report has no outcomes; each entity carries the
/// classifier's evidence naming the signal that found it.
fn web_investigate(text: &str) -> Result<LookupReport, LookupError> {
    let entities = investigate_entities(text);
    let text =
        huntsman_recon::lookup_report::render(&entities, &[]).map_err(|message| LookupError {
            status: 500,
            message,
        })?;
    Ok(LookupReport {
        route: "investigate",
        text,
        entities,
        outcomes: Vec::new(),
        scan: None,
        status: None,
    })
}

/// `/api/lookup` over the same routing and front-ends as `scan`.
fn web_lookup(query: &LookupQuery) -> Result<LookupReport, LookupError> {
    if let Some(result) = super::public_osint::web_lookup(query) {
        return result;
    }
    let selector = vec![query.selector.clone()];
    let kind = if query.kind == "auto" {
        let kind = infer_kind(&query.selector);
        if kind == ScanKind::People && !inferred_people_is_name(&selector) {
            return Err(bad_selector(
                "not a name, phone, email, handle, domain, BSSID or LAT,LON; choose a kind to look it up anyway",
            ));
        }
        kind
    } else {
        let kind = parse_kind(&query.kind).map_err(|_| bad_selector("unknown lookup kind"))?;
        if kind == ScanKind::People && !explicit_people_is_name(&selector) {
            return Err(bad_selector("a people lookup needs two alphabetic tokens"));
        }
        kind
    };
    let canonical = canonical_selector(kind, &query.selector)
        .ok_or_else(|| bad_selector("selector is not valid for this kind"))?;
    match collect(
        kind,
        &canonical,
        &huntsman_recon::module_selection::Selection::all(),
    ) {
        Ok(found) => Ok(LookupReport {
            route: kind.command(),
            text: found.text,
            entities: found.entities,
            outcomes: found.outcomes,
            scan: None,
            status: None,
        }),
        Err(refused) => Err(LookupError {
            status: match refused {
                Refused::Data(_) => 422,
                Refused::Network(_) | Refused::Unavailable(_) => 502,
            },
            message: refused.message().to_owned(),
        }),
    }
}

/// /api/research uses the same bounded, keyless adaptive search as `query --adaptive`.
/// The server handles capacity and same-origin controls; this adapter owns the transport.
fn web_research(query: &str) -> Result<serde_json::Value, LookupError> {
    let transport =
        huntsman_recon::http::UreqTransport::new(&huntsman_recon::http::TransportConfig::default());
    let report = huntsman_recon::web_query::adaptive_search(&transport, query, clock::unix_now())
        .map_err(|error| LookupError {
        status: if matches!(error, Error::Invalid(_)) {
            400
        } else {
            502
        },
        message: error.to_string(),
    })?;
    Ok(serde_json::json!({
        "route": "adaptive_web_search",
        "report": report,
    }))
}

/// Mobile radar reads exactly the same Termux Wi-Fi cache as the CLI.
fn web_radar() -> Result<huntsman_recon::wifi_radar::WifiScan, LookupError> {
    super::radar::capture_wifi().map_err(|message| LookupError {
        status: 503,
        message,
    })
}

/// Mobile radar reads exactly the same Termux cell report as `radar cells`.
fn web_cells() -> Result<huntsman_recon::cell_radar::CellScan, LookupError> {
    super::radar::capture_cells().map_err(|message| LookupError {
        status: 503,
        message,
    })
}

/// Mobile radar records one sweep into the same track log `radar track` keeps.
fn web_track() -> Result<huntsman_recon::radar::TrackReport, LookupError> {
    let log = super::scans::default_radar_log().ok_or_else(|| LookupError {
        status: 500,
        message: "radar track: no log; set HUNTSMAN_HOME or HOME".into(),
    })?;
    super::radar::track_live(&log)
}

/// The saved scans `serve` shows and starts: the same store, runner, correlation rules and API
/// router as `scans`, so a scan run from either shows in both. A scan a stopped server left running
/// reads `ABORTED`, and each rule error [`huntsman_recon::sf_correlate::with_dir`] reports for
/// `~/.huntsman/correlations` (a rule file that cannot be read or loaded, a rules path that cannot
/// be listed, files past the limit) is named on stderr as `scans rules` names it, and in each
/// scan's log. When there is no usable scan directory the server still
/// starts, says why on stderr, and the scan routes answer `404`; lookups and analysis are
/// unaffected.
/// The saved-scan API `serve` runs with, or `None` with the reason on stderr; its Global Settings
/// carry `continuous`, what continuous normalisation was configured with.
fn scan_api(continuous: &str) -> Option<std::sync::Arc<ScanApi>> {
    let Some(dir) = default_scan_dir() else {
        eprintln!(
            "serve: saved scans are off: set HOME or HUNTSMAN_HOME to an absolute path to keep them"
        );
        return None;
    };
    match open_api(&dir, default_rules_dir().as_deref()) {
        Ok(api) => {
            for failure in api.service().rule_errors() {
                eprintln!("{}", rule_error_line(failure));
            }
            Some(std::sync::Arc::new(api.with_global(
                super::continuous::SETTING_KEY,
                super::continuous::SETTING_DESCRIPTION,
                continuous,
            )))
        }
        Err(error) => {
            eprintln!("serve: saved scans are off: {}: {error}", dir.display());
            None
        }
    }
}

/// A rule error as serve prints it: the line `scans rules` prints, on one line with control
/// characters escaped, since a rule file's name and text are the operator's but not trusted.
fn rule_error_line(failure: &huntsman_recon::sf_correlate::RuleError) -> String {
    format!("serve: {}", one_line(&failure.to_string()))
}

/// What `serve` says about `HSE_AUTH_TOKEN` when it starts. On a public bind the page and every
/// API call except health need the token, and nothing else tells the operator so; on loopback a
/// token that was set is not used, and the operator should not wonder whether it guards anything.
/// The value is never printed, so it stays out of terminal scrollback and logs.
fn token_note(addr: std::net::SocketAddr, needs_token: bool, supplied: bool) -> Option<String> {
    if needs_token {
        Some(format!(
            "serve: this public bind needs {SERVE_TOKEN_ENV}: enter its value (echo \"${SERVE_TOKEN_ENV}\") in the page's token field, or open http://{addr}/#token=VALUE once"
        ))
    } else if supplied {
        Some(format!(
            "serve: a loopback bind needs no token, so the page and API answer without {SERVE_TOKEN_ENV}"
        ))
    } else {
        None
    }
}

/// `serve --history DIR`, loaded before the listener binds, so a bad directory stops `serve` at
/// startup instead of failing each analysis. The exit codes match `correlate --history`.
fn serve_history(dir: &str) -> Result<std::sync::Arc<ArtifactHistory>, ExitCode> {
    match ArtifactHistory::open(Path::new(dir)) {
        Ok(history) => {
            eprintln!(
                "serve: {} saved scan(s) in {dir} bridge the analysis",
                history.scan_count()
            );
            Ok(std::sync::Arc::new(history))
        }
        Err(ArtifactError::Io(error)) => {
            Err(fail(EX_NOINPUT, &format!("serve --history: {error}")))
        }
        Err(error) => Err(fail(EX_DATAERR, &format!("serve --history: {error}"))),
    }
}

/// Report the bound address and runtime background constraints without extending
/// the already substantial serve command controller.
fn report_started(
    server: &Server,
    config_needs_token: bool,
    token_supplied: bool,
) -> Result<(), ExitCode> {
    match server.local_addr() {
        Ok(addr) => {
            println!("serving=http://{addr}/");
            if let Some(note) = token_note(addr, config_needs_token, token_supplied) {
                eprintln!("{note}");
            }
            if TermuxState::current() == TermuxState::Detected {
                eprintln!("{TERMUX_BACKGROUND_HINT}");
            }
        }
        Err(error) => return Err(fail(EX_UNAVAILABLE, &error.to_string())),
    }
    Ok(())
}

pub(super) fn serve_cmd(args: &[String]) -> ExitCode {
    let hse_bind = env::var("HSE_BIND").ok();
    let mut bind = resolve_serve_bind(hse_bind.as_deref());
    let mut history_dir: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => {
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "serve --bind needs ADDR");
                };
                bind.clone_from(value);
                index += 2;
            }
            "--history" => {
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "serve --history needs DIR");
                };
                history_dir = Some(value.clone());
                index += 2;
            }
            other => {
                return fail(
                    EX_USAGE,
                    &format!(
                        "unknown serve option: {other}\nusage: huntsman-recon serve [--bind ADDR] [--history DIR]"
                    ),
                );
            }
        }
    }

    let history = match history_dir.map(|dir| serve_history(&dir)).transpose() {
        Ok(history) => history,
        Err(code) => return code,
    };

    let token = env::var(SERVE_TOKEN_ENV).ok();
    let token_supplied = token.is_some();
    let config = match ServeConfig::parse(&bind, token) {
        Ok(config) => config,
        Err(Error::MissingCredential(message)) => return fail(EX_NOINPUT, &message),
        Err(Error::Invalid(message)) => return fail(EX_DATAERR, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    let config_needs_token = config.needs_token();
    let analyze_history = history.clone();
    // Read before anything binds, so a wrong setting ends serve before it announces an address.
    let continuous = match super::continuous::configure(&super::credentials::lookup_keys()) {
        Ok(config) => config,
        Err(error) => return fail(EX_DATAERR, &format!("continuous: {error}")),
    };
    let scans = scan_api(&super::continuous::setting_value(continuous.as_ref()));
    let continuous_scans = scans.clone();
    let server = match Server::bind(config) {
        Ok(server) => {
            let server = server
                .with_lookup(std::sync::Arc::new(web_lookup))
                .with_research(std::sync::Arc::new(web_research))
                .with_radar(std::sync::Arc::new(web_radar))
                .with_radar_cells(std::sync::Arc::new(web_cells))
                .with_radar_track(std::sync::Arc::new(web_track))
                .with_inspect(std::sync::Arc::new(web_inspect))
                .with_investigate(std::sync::Arc::new(web_investigate))
                .with_analyze(std::sync::Arc::new(move |seeds: &[String]| {
                    web_analyze(seeds, analyze_history.as_deref())
                }));
            let server = match scans {
                Some(scans) => server.with_scans(scans),
                None => server,
            };
            // The Settings page saves keys into the file lookups read, so only an absolute HOME.
            match env::var_os("HOME").map(PathBuf::from) {
                Some(home) if home.is_absolute() => server.with_keys_home(home),
                _ => server,
            }
        }
        Err(Error::Store(message)) => return fail(EX_UNAVAILABLE, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    if let Err(code) = report_started(&server, config_needs_token, token_supplied) {
        return code;
    }
    if let Err(error) = super::continuous::launch(continuous, continuous_scans.as_ref()) {
        return fail(EX_DATAERR, &format!("continuous: {error}"));
    }
    // A plain write, not `eprintln!`: once stderr is closed or its reader has gone,
    // `eprintln!` panics, and the notice would end the server it reports on.
    let notice = |error: &std::io::Error| {
        let _ = writeln!(
            std::io::stderr(),
            "serve accept: {error}; waiting for open connections to finish"
        );
    };
    match server.run(notice) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{rule_error_line, web_inspect, web_investigate};
    use huntsman_recon::entity::{Entity, EntityKind};
    use huntsman_recon::source_outcome::SourceOutcomeKind;

    /// The page's text goes through the same extraction as `investigate TEXT...`: every actionable
    /// entity in it, with the classifier's signal as evidence, rendered as the command prints it;
    /// no outcome row, as nothing was asked of any source.
    #[test]
    fn pasted_text_is_investigated_as_the_command_investigates_it() {
        let report = web_investigate(
            "Seller says call +61412345678 or write to ada@example.com; site example.org",
        )
        .expect("text is investigated");
        assert_eq!(report.route, "investigate");
        assert!(report.outcomes.is_empty(), "{:?}", report.outcomes);
        let kinds: Vec<(EntityKind, &str)> = report
            .entities
            .iter()
            .map(|entity| (entity.kind.clone(), entity.raw_value.as_str()))
            .collect();
        assert!(
            kinds.contains(&(EntityKind::Email, "ada@example.com")),
            "{kinds:?}"
        );
        assert!(
            kinds.iter().any(|(kind, _)| *kind == EntityKind::Phone),
            "{kinds:?}"
        );
        for entity in &report.entities {
            assert!(
                entity.evidence.iter().any(|evidence| {
                    evidence.provenance.source == "classifier"
                        && evidence.attributes.contains_key("signal")
                }),
                "{entity:?}"
            );
        }
        assert!(
            report
                .text
                .starts_with(&format!("entities={}\n", report.entities.len())),
            "{}",
            report.text
        );
        assert!(report.text.contains("ada@example.com"), "{}", report.text);
        let none = web_investigate("nothing actionable here").expect("an empty text is a report");
        assert_eq!(none.entities.len(), 0, "{:?}", none.text);
    }

    #[test]
    fn a_rule_error_prints_on_one_line_without_driving_the_terminal() {
        let failure = huntsman_recon::sf_correlate::RuleError {
            rule: "r".into(),
            reason: "unknown type \u{1b}]0;x\u{7}\nnext".into(),
        };
        assert_eq!(
            rule_error_line(&failure),
            "serve: correlation rule r: unknown type \\u{1b}]0;x\\u{7} next"
        );
    }

    /// The value of `key` on any evidence of `entity`.
    fn attribute<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
        entity
            .evidence
            .iter()
            .find_map(|evidence| evidence.attributes.get(key).map(String::as_str))
    }

    /// One PNG chunk, with a CRC the parsers do not check.
    fn png_chunk(png: &mut Vec<u8>, kind: [u8; 4], body: &[u8]) {
        png.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        png.extend_from_slice(&kind);
        png.extend_from_slice(body);
        png.extend_from_slice(&[0; 4]);
    }

    /// Valid APK uploads use only the offline APK reader; malformed APKs fail closed
    /// instead of being silently interpreted as unrelated image/document metadata.
    #[test]
    fn uploaded_apk_uses_canonical_inventory_and_rejects_invalid_zip() {
        let name = b"AndroidManifest.xml";
        let len = u16::try_from(name.len()).unwrap();
        let mut apk = vec![0_u8; 30];
        apk[..4].copy_from_slice(b"PK\x03\x04");
        apk[26..28].copy_from_slice(&len.to_le_bytes());
        apk.extend_from_slice(name);
        let offset = u32::try_from(apk.len()).unwrap();
        let mut directory = vec![0_u8; 46];
        directory[..4].copy_from_slice(b"PK\x01\x02");
        directory[28..30].copy_from_slice(&len.to_le_bytes());
        directory.extend_from_slice(name);
        let directory_len = u32::try_from(directory.len()).unwrap();
        apk.extend_from_slice(&directory);
        let mut end = vec![0_u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&1_u16.to_le_bytes());
        end[10..12].copy_from_slice(&1_u16.to_le_bytes());
        end[12..16].copy_from_slice(&directory_len.to_le_bytes());
        end[16..20].copy_from_slice(&offset.to_le_bytes());
        apk.extend_from_slice(&end);

        let report = web_inspect("EXAMPLE.APK", &apk).expect("valid APK ZIP");
        assert_eq!(report.route, "inspect");
        assert_eq!(report.entities.len(), 1);
        assert_eq!(report.entities[0].kind, EntityKind::Document);
        assert_eq!(attribute(&report.entities[0], "apk_zip_entries"), Some("1"));
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].module, "apk_intel");
        assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
        let expected_hash = huntsman_recon::sha256::hex32(&huntsman_recon::sha256::sha256(&apk));
        assert_eq!(
            attribute(&report.entities[0], "file_sha256"),
            Some(expected_hash.as_str())
        );
        let invalid = web_inspect("broken.apk", b"not an APK").expect_err("invalid APK");
        assert_eq!(invalid.status, 422);
    }

    /// A file `exif` cannot decode keeps `docmeta`'s findings, and the `exif` outcome says why.
    #[test]
    fn an_inspected_pdf_keeps_its_document_metadata_when_exif_cannot_read_it() {
        let pdf =
            b"%PDF-1.4\n1 0 obj\n<< /Title (T) >>\nendobj\ntrailer\n<< /Info 1 0 R >>\n%%EOF\n";
        let report = web_inspect("a.pdf", pdf).expect("a PDF is inspected");
        let document = report
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Document)
            .expect("a document entity for the file");
        assert_eq!(attribute(document, "info:Title"), Some("T"));
        let kinds: Vec<_> = report
            .outcomes
            .iter()
            .map(|outcome| (outcome.module.as_str(), outcome.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("exif", SourceOutcomeKind::Inconclusive),
                ("docmeta", SourceOutcomeKind::Success)
            ]
        );
        assert!(
            report.outcomes[0]
                .detail
                .as_deref()
                .is_some_and(|detail| detail.starts_with("a.pdf: not a JPEG"))
        );
    }

    /// A PNG's `eXIf` block and its text chunks reach one document entity: `exif` reads the
    /// first, `docmeta` the second, and their entities for the file merge.
    #[test]
    fn an_inspected_png_merges_its_exif_and_text_into_one_document() {
        // A little-endian TIFF block whose IFD0 holds one ASCII Make tag, "Abc".
        let mut tiff = b"II*\0\x08\0\0\0\x01\0".to_vec();
        tiff.extend_from_slice(&[0x0F, 0x01, 2, 0, 4, 0, 0, 0]);
        tiff.extend_from_slice(b"Abc\0");
        tiff.extend_from_slice(&[0; 4]);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png_chunk(&mut png, *b"IHDR", &[0; 13]);
        png_chunk(&mut png, *b"tEXt", b"Comment\0hello");
        png_chunk(&mut png, *b"eXIf", &tiff);
        png_chunk(&mut png, *b"IEND", &[]);
        let report = web_inspect("shot.png", &png).expect("a PNG is inspected");
        let documents: Vec<_> = report
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Document)
            .collect();
        assert_eq!(documents.len(), 1, "{:?}", report.entities);
        assert_eq!(attribute(documents[0], "exif_Make"), Some("Abc"));
        assert_eq!(attribute(documents[0], "png:Comment"), Some("hello"));
        assert!(
            report
                .outcomes
                .iter()
                .all(|outcome| outcome.kind == SourceOutcomeKind::Success)
        );
    }
}
