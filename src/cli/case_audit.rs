//! Offline CLI adapter for public-company OSINT case-package validation.
use std::fs::File;
use std::io::Read;
use std::process::ExitCode;

use huntsman_recon::evidence_register::case_audit::{
    MAX_ADVERT_BYTES, MAX_CASE_BYTES, audit_case,
};
use huntsman_recon::exit::{EX_DATAERR, EX_USAGE};

use super::fail;

fn bounded_read(path: &str, cap: usize) -> Result<Vec<u8>, String> {
    let input = File::open(path).map_err(|e| format!("cannot open case input: {e}"))?;
    let mut bytes = Vec::new();
    input
        .take(u64::try_from(cap).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read case input: {e}"))?;
    if bytes.len() > cap {
        return Err("case input exceeds bounded size".into());
    }
    Ok(bytes)
}

pub(super) fn case_check_cmd(args: &[String]) -> ExitCode {
    let [package, advert] = args else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon case-check CASE-JSON ORIGINAL-ADVERT-TEXT",
        );
    };
    let case_bytes = match bounded_read(package, MAX_CASE_BYTES) {
        Ok(bytes) => bytes,
        Err(e) => return fail(EX_DATAERR, &e),
    };
    let advert_bytes = match bounded_read(advert, MAX_ADVERT_BYTES) {
        Ok(bytes) => bytes,
        Err(e) => return fail(EX_DATAERR, &e),
    };
    match audit_case(&case_bytes, &advert_bytes) {
        Ok(audit) => {
            println!("case={}", audit.case_id);
            println!("sources={}", audit.source_count);
            println!("claims={}", audit.claim_count);
            println!("unresolved_claim_ids={}", audit.unresolved_claim_ids.join(","));
            println!("original_publication_unknown={}", audit.original_publication_unknown);
            println!("original_year_unknown={}", audit.original_year_unknown);
            println!("case_structure=verified; external_claims=not_verified_by_this_command");
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &e),
    }
}
