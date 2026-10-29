//! Binary adapter commands. Business logic stays in the library crate.

use std::env;
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use super::{RECON_USAGE, fail, usage_error};
use huntsman_recon::canonical::{canonical_domain, canonical_email, canonical_url};
use huntsman_recon::clock;
use huntsman_recon::credential_origin::{
    AuthenticationAuthority, CredentialFingerprint, OperatorCredentialRef,
};
use huntsman_recon::crtsh::{self, CrtShError};
use huntsman_recon::dns;
use huntsman_recon::egress::EgressPolicy;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fetch::{Credential, FetchOptions, fetch};
use huntsman_recon::fetch_cli::{FETCH_USAGE, FetchArgs};
use huntsman_recon::hibp::cli::HibpCommand;
use huntsman_recon::hibp::client::HibpConfig;
use huntsman_recon::http::{Request, TransportConfig, UreqTransport, parse_http_uri};
use huntsman_recon::keys::Keys;
use huntsman_recon::lookup_report::entity_row;
use huntsman_recon::recon::ReconTargetKind;
use huntsman_recon::seeknow_cli::{SEEKNOW_USAGE, SeekNowCliRun};
use huntsman_recon::source_outcome::recommended_action;
use huntsman_recon::stolen_tax::{self, StolenTaxError, StolenTaxReport};
use huntsman_recon::textnorm::escape_controls;

pub(super) fn hibp_cmd(args: &[String]) -> ExitCode {
    // The HIBP command checks the arguments first, so bad arguments are a usage error (64). A
    // keyed subcommand with well-formed arguments and no key is refused by its keyed leg, before
    // any request, as a missing key (66).
    let transport = std::sync::Arc::new(UreqTransport::new(
        &HibpConfig::default().transport_config(),
    ));
    ExitCode::from(
        HibpCommand::production(
            crate::cli::credentials::hibp_key_loader(&crate::cli::credentials::lookup_keys()),
            transport,
        )
        .run(
            args,
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        ),
    )
}

pub(super) fn dehashed_cmd(args: &[String]) -> ExitCode {
    use huntsman_recon::dehashed::{cli, client};
    let http: std::sync::Arc<dyn huntsman_recon::http::Transport + Send + Sync> =
        std::sync::Arc::new(UreqTransport::new(&TransportConfig::default()));
    ExitCode::from(cli::run(
        args,
        || {
            let keys = crate::cli::credentials::lookup_keys();
            client::key_from_sources(&keys)
        },
        http,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ))
}

pub(super) fn seeknow_cmd(args: &[String]) -> ExitCode {
    let transport = UreqTransport::new(&TransportConfig::default());
    let now = clock::unix_now();
    match huntsman_recon::seeknow_cli::run(&transport, args, env::var_os("HOME").as_deref(), now) {
        SeekNowCliRun::Usage => fail(EX_USAGE, SEEKNOW_USAGE),
        SeekNowCliRun::Printed(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        SeekNowCliRun::BadData(msg) => fail(EX_DATAERR, &msg),
        SeekNowCliRun::Input(msg) => fail(EX_NOINPUT, &msg),
        SeekNowCliRun::NoPerm(msg) => fail(EX_NOPERM, &msg),
        SeekNowCliRun::Unavailable(msg) => fail(EX_UNAVAILABLE, &msg),
    }
}

pub(super) fn recon_cmd(args: &[String]) -> ExitCode {
    match args {
        [source, target] if source == "crtsh" => crtsh_cmd(target),
        [source, target] if source == "dns" => dns_cmd(target),
        [source, query] if source == "stolen-tax" => stolen_tax_cmd(query, None),
        [source, query, flag, file] if source == "stolen-tax" && flag == "--keys" => {
            stolen_tax_cmd(query, Some(file))
        }
        _ => fail(EX_USAGE, RECON_USAGE),
    }
}

fn print_entities(entities: &[huntsman_recon::entity::Entity]) {
    for e in entities {
        println!("{}", entity_row(e, &e.value));
    }
}

fn dns_cmd(target: &str) -> ExitCode {
    if target.trim().is_empty() {
        return fail(EX_USAGE, RECON_USAGE);
    }
    let Some(target) = canonical_domain(target) else {
        return fail(EX_DATAERR, &format!("bad domain: {}", target.trim()));
    };
    let transport = UreqTransport::new(&dns::transport_config());
    match dns::lookup_domain(&transport, &target) {
        None => fail(EX_DATAERR, &format!("bad domain: {target}")),
        Some(report) => {
            let empty = report.answers.is_empty();
            print!("{}", report.render());
            if empty {
                ExitCode::from(EX_UNAVAILABLE)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

fn crtsh_cmd(target: &str) -> ExitCode {
    let target = target.trim();
    if target.is_empty() {
        return fail(EX_USAGE, RECON_USAGE);
    }
    let (kind, target) = if target.contains("://") {
        let Some(url) = canonical_url(target) else {
            return fail(EX_DATAERR, &format!("bad url: {target}"));
        };
        (ReconTargetKind::Url, url)
    } else if target.contains('@') {
        let Some(email) = canonical_email(target) else {
            return fail(EX_DATAERR, &format!("bad email: {target}"));
        };
        (ReconTargetKind::Email, email)
    } else {
        let Some(domain) = canonical_domain(target) else {
            return fail(EX_DATAERR, &format!("bad domain: {target}"));
        };
        (ReconTargetKind::Domain, domain)
    };
    let transport = UreqTransport::new(&crtsh::transport_config());
    match crtsh::lookup(&transport, kind, &target, "cli") {
        Ok(report) => {
            print_entities(&report.entities);
            println!(
                "query={} attempts={} entities={}",
                escape_controls(report.query.as_deref().unwrap_or("none")),
                report.attempts,
                report.entities.len()
            );
            ExitCode::SUCCESS
        }
        Err(e @ CrtShError::Refused(_)) => fail(EX_NOPERM, &e.to_string()),
        Err(e) => fail(EX_UNAVAILABLE, &e.to_string()),
    }
}

fn stolen_tax_cmd(query: &str, keys_file: Option<&String>) -> ExitCode {
    if query.trim().is_empty() {
        return fail(EX_USAGE, RECON_USAGE);
    }
    // The key comes from the --keys file when one is given, and otherwise from the places every
    // lookup reads: $HOME/.huntsman.env, then the environment. A slot the file lacks falls back
    // to the environment, as the README documents.
    let keys = match keys_file {
        Some(path) => match Keys::resolve(Some(Path::new(path.as_str())), None) {
            Ok(resolved) => resolved.keys,
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        },
        None => crate::cli::credentials::lookup_keys(),
    };
    if !huntsman_recon::breach_hybrid::stolen_tax_allowed(keys.get(stolen_tax::KEY_SLOT).is_some())
    {
        return fail(
            EX_NOINPUT,
            &format!(
                "stolen-tax: no API key for this keyed lookup (set {})",
                stolen_tax::KEY_SLOT
            ),
        );
    }
    let now = clock::unix_now();
    let transport = UreqTransport::new(&stolen_tax::transport_config());
    match stolen_tax::lookup(&transport, &keys, query, "cli", now) {
        Ok(report) => {
            print_entities(&report.entities);
            let fingerprint = keys
                .get(stolen_tax::KEY_SLOT)
                .map(|secret| secret.fingerprint());
            print!(
                "{}",
                stolen_tax_summary(
                    &report,
                    fingerprint.as_ref().map(CredentialFingerprint::short)
                )
            );
            ExitCode::SUCCESS
        }
        Err(e @ StolenTaxError::MissingKey) => fail(EX_NOINPUT, &e.to_string()),
        Err(e @ StolenTaxError::Refused(_)) => fail(EX_NOPERM, &e.to_string()),
        Err(e @ (StolenTaxError::Failed(_) | StolenTaxError::BudgetExhausted { .. })) => {
            fail(EX_UNAVAILABLE, &e.to_string())
        }
    }
}

/// The lines `recon stolen-tax` prints after the entity rows: each failed and skipped path, the
/// key's short fingerprint, the rows that matched but name no breach or stealer host, then the
/// totals and any truncation note. **Pure.**
fn stolen_tax_summary(report: &StolenTaxReport, credential: Option<&str>) -> String {
    let mut text = String::new();
    for failure in &report.failed_paths {
        let _ = writeln!(
            text,
            "failed_path={} reason={}",
            failure.path,
            escape_controls(&failure.reason)
        );
    }
    for path in &report.skipped_paths {
        let _ = writeln!(
            text,
            "skipped_path={path} reason=not sent, {}s lookup budget exhausted",
            stolen_tax::LOOKUP_BUDGET.as_secs()
        );
    }
    if let Some(credential) = credential {
        let _ = writeln!(text, "credential={credential}");
    }
    if report.unnamed_rows > 0 {
        let _ = writeln!(text, "unnamed_rows={}", report.unnamed_rows);
    }
    let _ = writeln!(
        text,
        "entities={} partial={}",
        report.entities.len(),
        report.truncation.is_some()
    );
    if let Some(note) = &report.truncation {
        let _ = writeln!(text, "truncation={note}");
    }
    text
}

pub(super) fn fetch_cmd(args: &[String]) -> ExitCode {
    let parsed = match FetchArgs::parse(args) {
        Ok(p) => p,
        Err(e) => return usage_error(e, FETCH_USAGE),
    };
    let credential = match build_credential(&parsed) {
        Ok(c) => c,
        Err(e) => return fail(EX_NOINPUT, &e.to_string()),
    };
    let transport = UreqTransport::new(&TransportConfig {
        timeout: parsed.timeout,
        egress: if parsed.allow_private {
            EgressPolicy::Unrestricted
        } else {
            EgressPolicy::PublicOnly
        },
        ..TransportConfig::default()
    });
    let now = clock::unix_now();
    let fetched = match fetch(
        &transport,
        Request::get(parsed.url.clone()),
        credential.as_ref(),
        &FetchOptions {
            max_redirects: parsed.max_redirects,
            ..FetchOptions::default()
        },
        "cli",
        now,
    ) {
        Ok(f) => f,
        Err(e) => return fail(EX_NOPERM, &e.to_string()),
    };
    let kind = fetched.outcome.kind;
    println!(
        "status={} outcome={} action={} redirects={} url={}",
        fetched
            .outcome
            .http_status
            .map_or_else(|| "none".into(), |s| s.to_string()),
        kind.as_str(),
        recommended_action(kind).as_str(),
        fetched.redirects,
        fetched.final_url,
    );
    if let Some(detail) = &fetched.outcome.detail {
        println!("detail={detail}");
    }
    if let Some(fp) = &fetched.credential_sent {
        println!("credential={}", fp.short());
    }
    match fetched.response {
        Some(response) => {
            if parsed.print_body {
                println!("{}", response.text());
            }
            ExitCode::SUCCESS
        }
        None => ExitCode::from(EX_UNAVAILABLE),
    }
}

fn build_credential(args: &FetchArgs) -> Result<Option<Credential>, Error> {
    let Some((slot, style)) = &args.auth else {
        return Ok(None);
    };
    let resolved = Keys::resolve(args.keys_file.as_deref(), env::var_os("HOME").as_deref())?;
    if let Some(warning) = &resolved.warning {
        eprintln!("{warning}");
    }
    let keys = resolved.keys;
    let secret = keys
        .get(slot)
        .ok_or_else(|| Error::Invalid(format!("credential {slot} is not configured")))?;
    let host = parse_http_uri(&args.url)?
        .host()
        .unwrap_or_default()
        .to_owned();
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: host,
        credential_slot: slot.clone(),
        approved_at_unix: clock::unix_now(),
        approval_provenance: "operator supplied --bearer/--header on the command line".into(),
    })?;
    Ok(Some(Credential::new(authority, secret, style.clone())?))
}

#[cfg(test)]
mod tests {
    use super::stolen_tax_summary;
    use huntsman_recon::entity::{Entity, EntityKind};
    use huntsman_recon::source_outcome::SourceOutcomeKind;
    use huntsman_recon::stolen_tax::{PathFailure, StolenTaxReport};

    #[test]
    fn a_stolen_tax_row_that_names_no_breach_is_counted_before_the_totals() {
        let report = StolenTaxReport {
            entities: Vec::new(),
            failed_paths: vec![PathFailure {
                path: "snusbase",
                kind: SourceOutcomeKind::TtfbTimeout,
                reason: "no response (TtfbTimeout)".into(),
            }],
            skipped_paths: Vec::new(),
            truncation: Some("0 retrieved".into()),
            unnamed_rows: 2,
        };
        assert_eq!(
            stolen_tax_summary(&report, Some("0123456789ab")),
            "failed_path=snusbase reason=no response (TtfbTimeout)\n\
             credential=0123456789ab\n\
             unnamed_rows=2\n\
             entities=0 partial=true\n\
             truncation=0 retrieved\n"
        );

        // A report whose every row names its breach prints no count.
        let named = StolenTaxReport {
            entities: vec![Entity::new(
                EntityKind::Credential,
                "breach:DB",
                0.65,
                "cli",
            )],
            failed_paths: Vec::new(),
            skipped_paths: Vec::new(),
            truncation: None,
            unnamed_rows: 0,
        };
        assert_eq!(
            stolen_tax_summary(&named, None),
            "entities=1 partial=false\n"
        );
    }
}
