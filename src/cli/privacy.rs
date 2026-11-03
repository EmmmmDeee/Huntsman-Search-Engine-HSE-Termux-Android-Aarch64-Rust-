//! Local-only exposure assessment of a supplied public evidence graph.
use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::privacy_audit::{MAX_GRAPH_BYTES, assess_public_graph};

use super::{fail, terminal_json_pretty};

pub(super) const PRIVACY_HELP: &str = "privacy-audit PUBLIC-GRAPH.json\nOffline, read-only privacy exposure assessment of a source-backed public entity graph. Refuses symlinks, bad sources, dangling relationships and files over 1 MiB. Emits JSON with evidence-scoped exposure categories. It does not access accounts, verify identity, query private data or make network requests.";

pub(super) fn privacy_cmd(args: &[String]) -> ExitCode {
    let [file] = args else {
        return fail(EX_USAGE, PRIVACY_HELP);
    };
    let bytes = match read_bounded(Path::new(file), MAX_GRAPH_BYTES) {
        Ok(bytes) => bytes,
        Err(e) => return fail(EX_NOINPUT, &e.to_string()),
    };
    let report = match assess_public_graph(&bytes) {
        Ok(report) => report,
        Err(e) => return fail(EX_DATAERR, &e),
    };
    match terminal_json_pretty(&report) {
        Ok(body) => {
            println!("{body}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &format!("cannot serialize privacy audit: {e}")),
    }
}
