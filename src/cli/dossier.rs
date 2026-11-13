//! Offline entry points into the same dossier loader used by the HTTP routes.

use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::dossier_view::{self, DossierError};
use huntsman_recon::exit::{EX_CONFIG, EX_DATAERR, EX_IOERR, EX_NOINPUT};

use super::{fail, terminal_json_pretty, usage_error};

const USAGE: &str = "dossier check [REGISTER] | verify BUNDLE_DIR | install BUNDLE_DIR";
pub(super) const HELP: &str = "dossier check [REGISTER] | verify BUNDLE_DIR | install BUNDLE_DIR
Check a register or verify an extracted correlation bundle against its checksums, media and indexes. Install verifies first, then writes the exact register bytes to HUNTSMAN_DOSSIER_PATH or ~/.huntsman/dossier/register.json. Existing different bytes are preserved. Both web routes read that same path. All three operations are offline.";

pub(super) fn run(args: &[String]) -> ExitCode {
    let result = match args {
        [command] if command == "check" => {
            dossier_view::load().map(|document| report_register(&document))
        }
        [command, path] if command == "check" => {
            dossier_view::read(Path::new(path)).map(|document| report_register(&document))
        }
        [command, path] if command == "verify" || command == "install" => {
            dossier_view::verify_bundle(Path::new(path)).and_then(|verified| {
                if command == "install" {
                    verified.dossier.install()?;
                }
                Ok(terminal_json_pretty(&verified.report))
            })
        }
        _ => return usage_error("expected a dossier subcommand and its arguments", USAGE),
    };
    match result {
        Ok(Ok(report)) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Ok(Err(error)) => fail(EX_IOERR, &error.to_string()),
        Err(error) => {
            let code = match &error {
                DossierError::NoPath => EX_CONFIG,
                DossierError::Missing | DossierError::Read(_) => EX_NOINPUT,
                DossierError::TooLarge | DossierError::Invalid(_) => EX_DATAERR,
                DossierError::Install(_) => EX_IOERR,
            };
            fail(code, &error.to_string())
        }
    }
}

fn report_register(dossier: &dossier_view::Dossier) -> serde_json::Result<String> {
    terminal_json_pretty(&serde_json::json!({
        "indexed_records": dossier.record_count(),
        "register_sha256": dossier.sha256(),
    }))
}
