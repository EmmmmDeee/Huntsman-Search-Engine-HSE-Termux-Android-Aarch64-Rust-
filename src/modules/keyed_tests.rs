//! Every key-gated module refuses to run without its credential.
//!
//! PROVIDER FAILURE ≠ ZERO EVIDENCE (RULE.md; `core::coverage`). A keyed module
//! that returns `Ok(empty)` when its key is unset is recorded by dispatch as
//! `ModuleDone { found: 0 }`, which coverage aggregates to `CleanNegative` —
//! "queried, holds nothing on this subject" — the one outcome the design
//! treats as a real negative. Fourteen modules did exactly that, so on any
//! scan where the operator had not configured DeHashed, Hunter, FullContact,
//! SecurityTrails and the rest, those providers were counted as having
//! searched and found nothing, `coverage_verdict` left them out of
//! `unavailable_count`, and `is_exhaustive()` could report a sweep nobody
//! made. `Error::MissingKey` is the contract: dispatch renders it as a
//! "needs API key" skip that coverage reads as `NotAttempted`.
use std::collections::HashMap;

use crate::core::error::Error;
use crate::core::module::{Module, ModuleContext};
use crate::core::scan::{Target, TargetKind};

fn keyless_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "keyless".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

/// A well-formed value for each kind, so a module's input validation cannot
/// mask the key check.
fn probe_value(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Email => "probe@example.com",
        TargetKind::Domain => "example.com",
        TargetKind::Phone => "+61412345678",
        TargetKind::Url => "https://example.com/",
        TargetKind::Username => "jane_example",
        TargetKind::IpAddress => "203.0.113.7",
        TargetKind::Organisation => "Example Pty Ltd",
        TargetKind::FullName => "Jane Example",
        _ => "example.com",
    }
}

#[tokio::test]
async fn a_keyed_module_without_its_key_is_a_missing_key_skip_not_a_clean_negative() {
    let cases: Vec<(Box<dyn Module>, &str)> = vec![
        (
            Box::new(crate::modules::builtwith::BuiltWith),
            "HUNTSMAN_BUILTWITH_KEY",
        ),
        (
            Box::new(crate::modules::dehashed::DeHashed),
            "HUNTSMAN_DEHASHED_KEY",
        ),
        (
            Box::new(crate::modules::emailrep::EmailRep),
            "HUNTSMAN_EMAILREP_KEY",
        ),
        (
            Box::new(crate::modules::epieos::Epieos),
            "HUNTSMAN_EPIEOS_KEY",
        ),
        (Box::new(crate::modules::fofa::Fofa), "HUNTSMAN_FOFA_KEY"),
        (
            Box::new(crate::modules::fullcontact::FullContact),
            "HUNTSMAN_FULLCONTACT_KEY",
        ),
        (
            Box::new(crate::modules::hunter_io::HunterIo),
            "HUNTSMAN_HUNTER_KEY",
        ),
        (
            Box::new(crate::modules::netlas::Netlas),
            "HUNTSMAN_NETLAS_KEY",
        ),
        (
            Box::new(crate::modules::numverify::NumVerify),
            "HUNTSMAN_NUMVERIFY_KEY",
        ),
        (
            Box::new(crate::modules::opensanctions::OpenSanctions),
            "HUNTSMAN_OPENSANCTIONS_KEY",
        ),
        (
            Box::new(crate::modules::securitytrails::SecurityTrails),
            "HUNTSMAN_SECTRAILS_KEY",
        ),
        (Box::new(crate::modules::seon::Seon), "HUNTSMAN_SEON_KEY"),
        (
            Box::new(crate::modules::trove_au::TroveAu),
            "HUNTSMAN_TROVE_KEY",
        ),
        (
            Box::new(crate::modules::whoisxml::WhoisXml),
            "HUNTSMAN_WHOISXML_KEY",
        ),
        (
            Box::new(crate::modules::contact_enrich::ContactEnrich),
            "HUNTSMAN_NUMVERIFY_KEY",
        ),
    ];
    let ctx = keyless_ctx();
    let mut wrong = Vec::new();
    for (module, env) in &cases {
        // contact_enrich is keyed only on its phone path; every other module
        // is keyed on everything it consumes.
        let kind = if module.name() == "contact_enrich" {
            TargetKind::Phone
        } else {
            *module
                .consumes()
                .first()
                .expect("a keyed module consumes something")
        };
        let target = Target::new(kind, probe_value(kind));
        match module.process(&target, &ctx).await {
            Err(Error::MissingKey(k)) if k == *env => {}
            other => wrong.push(format!(
                "{} on {kind:?}: expected Err(MissingKey({env})), got {}",
                module.name(),
                match &other {
                    Ok(r) => format!(
                        "Ok({} entities) — a clean negative for a provider never asked",
                        r.entities.len()
                    ),
                    Err(e) => format!("Err({e:?})"),
                }
            )),
        }
    }
    assert!(
        wrong.is_empty(),
        "keyed modules that misreport a missing credential as a result:\n{}",
        wrong.join("\n")
    );
}
