//! Binary adapter commands. Business logic stays in the library crate.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn hibp_cmd(args: &[String]) -> ExitCode {
    ExitCode::from(HibpCommand::production().run(
        args,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ))
}

pub(super) fn seeknow_cmd(args: &[String]) -> ExitCode {
    let transport = UreqTransport::new(&TransportConfig::default());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
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
        println!(
            "{}\t{}\t{:.2}\t{}",
            serde_json::to_value(&e.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            escape_controls(&e.value),
            e.confidence,
            escape_controls(&e.tags.join(","))
        );
    }
}

fn dns_cmd(target: &str) -> ExitCode {
    let target = target.trim();
    if target.is_empty() {
        return fail(EX_USAGE, RECON_USAGE);
    }
    let transport = UreqTransport::new(&dns::transport_config());
    match dns::lookup_domain(&transport, target) {
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
    let kind = if target.contains("://") {
        ReconTargetKind::Url
    } else if target.contains('@') {
        ReconTargetKind::Email
    } else {
        ReconTargetKind::Domain
    };
    let transport = UreqTransport::new(&crtsh::transport_config());
    match crtsh::lookup(&transport, kind, target, "cli") {
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
    let keys = match keys_file {
        Some(path) => match Keys::load(Path::new(path)) {
            Ok(keys) => keys,
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        },
        None => Keys::from_env(),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let transport = UreqTransport::new(&stolen_tax::transport_config());
    match stolen_tax::lookup(&transport, &keys, query, "cli", now) {
        Ok(report) => {
            print_entities(&report.entities);
            for failure in &report.failed_paths {
                println!(
                    "failed_path={} reason={}",
                    failure.path,
                    escape_controls(&failure.reason)
                );
            }
            for path in &report.skipped_paths {
                println!(
                    "skipped_path={path} reason=not sent, {}s lookup budget exhausted",
                    stolen_tax::LOOKUP_BUDGET.as_secs()
                );
            }
            if let Some(secret) = keys.get(stolen_tax::KEY_SLOT) {
                println!("credential={}", &secret.fingerprint().as_str()[..12]);
            }
            println!(
                "entities={} partial={}",
                report.entities.len(),
                report.truncation.is_some()
            );
            if let Some(note) = &report.truncation {
                println!("truncation={note}");
            }
            ExitCode::SUCCESS
        }
        Err(e @ StolenTaxError::MissingKey) => fail(EX_NOINPUT, &e.to_string()),
        Err(e @ StolenTaxError::Refused(_)) => fail(EX_NOPERM, &e.to_string()),
        Err(e @ (StolenTaxError::Failed(_) | StolenTaxError::BudgetExhausted { .. })) => {
            fail(EX_UNAVAILABLE, &e.to_string())
        }
    }
}

pub(super) fn fetch_cmd(args: &[String]) -> ExitCode {
    let parsed = match FetchArgs::parse(args) {
        Ok(p) => p,
        Err(e) => return fail(EX_USAGE, &format!("{e}\n{FETCH_USAGE}")),
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
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
        serde_json::to_value(kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        serde_json::to_value(recommended_action(kind))
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        fetched.redirects,
        fetched.final_url,
    );
    if let Some(detail) = &fetched.outcome.detail {
        println!("detail={detail}");
    }
    if let Some(fp) = &fetched.credential_sent {
        println!("credential={}", &fp.as_str()[..12]);
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
        approved_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        approval_provenance: "operator supplied --bearer/--header on the command line".into(),
    })?;
    Ok(Some(Credential::new(authority, secret, style.clone())?))
}
