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
use crate::core::module::ModuleContext;
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

/// Modules exempt from the invariant, each with the reason it cannot hold.
///
/// Keep this list empty unless a module genuinely cannot honour the contract.
/// An entry here is a claim that must stay true, not a way to silence a
/// failure.
const EXEMPT: &[(&str, &str)] = &[(
    "proxycurl",
    "vendor sunset the whole API; the module never dispatches, key or no key,      so there is no keyed call to skip. Its Ok(empty) is its own false clean      negative and is tracked separately (REQ-KEYSKIP-001 follow-up).",
)];

/// Every key-gated module in the REGISTRY — not a hand-written list.
///
/// The predecessor of this test enumerated fifteen modules by hand. The
/// registry carried forty-nine that declare `requires_key`, and **twenty** of
/// the remainder returned `Ok(empty)` without a key: stolen_tax, exa_search,
/// censys, breachdirectory, intelx, leakix, criminal_ip, onyphe, zoomeye,
/// binaryedge, c99, fullhunt, pulsedive, passivetotal, ipqs, proxycurl,
/// threatfox, opencellid, abn_lookup, hlr_cnam. The invariant was real and
/// enforced; the ENUMERATION was the hole, so a module could be keyed and
/// simply never listed.
///
/// Driving it from `registry()` closes that permanently: a new keyed module is
/// covered the moment it is registered, with nothing to remember.
#[tokio::test]
async fn every_keyed_module_in_the_registry_refuses_without_its_key() {
    let ctx = keyless_ctx();
    let mut wrong = Vec::new();
    let mut checked = 0usize;
    for module in crate::modules::registry() {
        if !module.provider_descriptor().requires_key {
            continue;
        }
        if let Some((_, why)) = EXEMPT.iter().find(|(n, _)| *n == module.name()) {
            assert!(!why.is_empty(), "an exemption must carry its reason");
            continue;
        }
        // contact_enrich is keyed only on its phone path; every other module is
        // keyed on everything it consumes.
        let kind = if module.name() == "contact_enrich" {
            TargetKind::Phone
        } else {
            match module.consumes().first() {
                Some(k) => *k,
                None => continue,
            }
        };
        let target = Target::new(kind, probe_value(kind));
        checked += 1;
        match module.process(&target, &ctx).await {
            Err(Error::MissingKey(_)) => {}
            other => wrong.push(format!(
                "{} on {kind:?}: expected Err(MissingKey(..)), got {}",
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
        checked >= 45,
        "the registry should yield ~49 keyed modules; got {checked} — has the \
         descriptor's requires_key stopped being populated?"
    );
    assert!(
        wrong.is_empty(),
        "keyed modules that do not refuse without a key ({} of {checked}):\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
}
