//! Native H1DR4 keyless public reads. Original server payloads are retained in every report.
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use super::{fail, terminal_json_pretty};
use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::h1dr4::{self, Bounds, Resource};
use huntsman_recon::http::{TransportConfig, UreqTransport};

pub const HELP: &str = "h1dr4 search QUERY... [--pages 1..3] [--limit 1..20] [--save FILE] | h1dr4 case CASE_ID [--limit 1..200] [--tip TIP_ID] [--save FILE] | h1dr4 rewards [--limit 1..20] [--save FILE] | h1dr4 onchain-stats [--save FILE]\nKeyless public-only read; bounded pages. Output retains complete source response JSON and SHA-256. Third-party claims stay unverified. --save writes a private, atomic, non-overwriting report.";

fn transport() -> UreqTransport {
    UreqTransport::new(&TransportConfig {
        timeout: Duration::from_secs(16),
        max_body: 4 * 1024 * 1024,
        ..TransportConfig::default()
    })
}

pub(super) fn run(args: &[String]) -> ExitCode {
    let Some((action, rest)) = args.split_first() else {
        return fail(EX_USAGE, HELP);
    };
    let mut terms = Vec::new();
    let mut pages = 1_u8;
    let mut limit: Option<u16> = None;
    let mut save: Option<&str> = None;
    let mut tip_id: Option<&str> = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--pages" | "--limit" | "--save" | "--tip" => {
                let flag = rest[index].as_str();
                let Some(value) = rest.get(index + 1) else {
                    return fail(EX_USAGE, HELP);
                };
                match flag {
                    "--pages" => match value.parse() {
                        Ok(v) => pages = v,
                        Err(_) => return fail(EX_USAGE, HELP),
                    },
                    "--limit" => match value.parse() {
                        Ok(v) => limit = Some(v),
                        Err(_) => return fail(EX_USAGE, HELP),
                    },
                    "--save" => save = Some(value),
                    "--tip" => tip_id = Some(value),
                    _ => unreachable!(),
                }
                index += 2;
            }
            value if value.starts_with("--") => return fail(EX_USAGE, HELP),
            value => {
                terms.push(value);
                index += 1;
            }
        }
    }
    let (resource, chosen_limit) = match action.as_str() {
        "search" if !terms.is_empty() && tip_id.is_none() => {
            (Resource::Search(terms.join(" ")), limit.unwrap_or(20))
        }
        "case" if terms.len() == 1 => (Resource::Case(terms[0].to_owned()), limit.unwrap_or(200)),
        "rewards" if terms.is_empty() && tip_id.is_none() => {
            (Resource::OfficialRewards, limit.unwrap_or(20))
        }
        "onchain-stats" if terms.is_empty() && tip_id.is_none() => {
            (Resource::OnchainStats, limit.unwrap_or(1))
        }
        _ => return fail(EX_USAGE, HELP),
    };
    if tip_id
        .is_some_and(|id| id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()))
    {
        return fail(EX_USAGE, "tip ID must be a positive decimal identifier");
    }
    let bounds = Bounds {
        pages,
        limit: chosen_limit,
    };
    if let Err(reason) = bounds.checked(&resource) {
        return fail(EX_USAGE, reason);
    }
    let mut report = match h1dr4::retrieve(&transport(), &resource, bounds, clock::unix_now()) {
        Ok(r) => r,
        Err(reason) => return fail(EX_UNAVAILABLE, &reason),
    };
    if let Some(tip) = tip_id {
        let found = report
            .records
            .iter()
            .any(|r| r.kind == "tip" && r.source_record_id == tip);
        // All source JSON remains byte-for-byte in pages. A missing tip in a bounded
        // response is not evidence it does not exist elsewhere in the upstream case.
        report
            .records
            .retain(|r| r.kind == "case" || (r.kind == "tip" && r.source_record_id == tip));
        report.returned_count = report.records.len();
        if !found {
            report
                .limitations
                .push("Requested tip not found in this bounded page; absence is not established");
        }
    }
    let output = match terminal_json_pretty(&report) {
        Ok(value) => value,
        Err(_) => return fail(EX_DATAERR, "cannot serialize the H1DR4 report"),
    };
    if let Some(path) = save {
        let path = Path::new(path);
        if path.as_os_str().is_empty() || path.symlink_metadata().is_ok() {
            return fail(
                EX_IOERR,
                "refusing to overwrite an existing H1DR4 evidence file",
            );
        }
        if let Err(e) =
            huntsman_recon::fsio::write_atomic_private(path, output.as_bytes(), 16 * 1024 * 1024)
        {
            return fail(EX_IOERR, &format!("cannot save H1DR4 evidence: {e}"));
        }
    }
    println!("{output}");
    if report.pages.iter().any(|p| p.schema_warning.is_some()) || report.pagination_stalled {
        return ExitCode::from(EX_UNAVAILABLE);
    }
    if tip_id.is_some() && !report.records.iter().any(|r| r.kind == "tip") {
        return ExitCode::from(EX_UNAVAILABLE);
    }
    ExitCode::SUCCESS
}
