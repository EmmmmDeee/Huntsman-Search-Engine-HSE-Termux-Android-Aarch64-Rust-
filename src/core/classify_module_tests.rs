use super::*;
use crate::core::cancel::CancelHandle;
use std::collections::HashMap;

/// A scan context wired to a live broadcast bus, returning the receiver so a test can
/// assert what the module published. Mirrors `core::module::tests::make_ctx`.
fn ctx_with_rx() -> (ModuleContext, tokio::sync::broadcast::Receiver<Event>) {
    let (bus, rx) = tokio::sync::broadcast::channel(64);
    let ctx = ModuleContext {
        scan_id: "classify-test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: HashMap::new(),
        cancel: CancelHandle::new(),
    };
    (ctx, rx)
}

#[test]
fn accepts_unstructured_text_only() {
    let m = ClassifyModule;
    assert!(
        m.accepts(&Target::new(TargetKind::FullName, "Kyle Diegmann")),
        "a multi-word value is unstructured text"
    );
    assert!(
        m.accepts(&Target::new(
            TargetKind::Organisation,
            "reach us at a@b.example or +61412345678"
        )),
        "a free-text blob is accepted"
    );
    assert!(
        !m.accepts(&Target::new(TargetKind::Email, "kyle@example.com")),
        "a clean single token is already typed by the detector"
    );
    assert!(
        !m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")),
        "a structured single token is not re-classified"
    );
}

#[test]
fn declares_valid_contracts() {
    let m = ClassifyModule;
    assert_eq!(m.name(), "classifier");
    assert_eq!(m.priority(), 200, "runs first");
    assert!(m.is_passive(), "pure/offline");
    assert!(!m.description().is_empty());
    assert!(!m.attack_techniques().is_empty(), "must declare a recon technique");
    assert!(!m.produces().is_empty());
    assert!(
        m.consumes().contains(&TargetKind::FullName),
        "explicit free-text consume set"
    );
}

#[tokio::test]
async fn process_emits_reinjectable_seeds_from_text() {
    let m = ClassifyModule;
    let (ctx, _rx) = ctx_with_rx();
    let target = Target::new(
        TargetKind::FullName,
        "Kyle at kyle.d@example.com, host 8.8.8.8, ABN 51 824 753 556, site https://acme.example",
    );
    let res = m.process(&target, &ctx).await.expect("should succeed");

    assert!(!res.entities.is_empty(), "extracted typed entities from the blob");
    for e in &res.entities {
        assert!(
            e.tags.iter().any(|t| t == "auto-seed"),
            "every emission is tagged auto-seed"
        );
        assert!(
            TargetKind::from_entity_kind(&e.kind).is_some(),
            "{:?} must be re-injectable as a seed",
            e.kind
        );
    }
    // The checksum-valid ABN and the dotted-quad IP both survived as seeds.
    assert!(res.entities.iter().any(|e| e.kind == EntityKind::AbnAcn));
    assert!(res.entities.iter().any(|e| e.kind == EntityKind::IpAddress));
    assert!(res.entities.iter().any(|e| e.kind == EntityKind::Email));
}

#[tokio::test]
async fn output_pivots_into_a_new_scan_cycle() {
    // STEP FOUR proof: an entity the classifier produced is itself a valid scan target —
    // the output is a valid input, so the next cycle can run.
    let m = ClassifyModule;
    let (ctx, _rx) = ctx_with_rx();
    let target = Target::new(TargetKind::FullName, "see https://example.com and 8.8.8.8");
    let res = m.process(&target, &ctx).await.expect("should succeed");

    let seed = res
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("an IP seed was produced");
    // Re-inject: produced kind → scannable TargetKind, value re-types to the same kind.
    assert!(
        TargetKind::from_entity_kind(&seed.kind).is_some(),
        "the produced entity has a scan target"
    );
    assert_eq!(
        TargetKind::detect(&seed.value),
        TargetKind::IpAddress,
        "the output value round-trips to a fresh IP target — a valid input for cycle N+1"
    );
}

#[tokio::test]
async fn below_floor_candidates_are_announced_not_discarded() {
    // A 16-digit run is neither a valid ABN (wrong length/checksum) nor a dialable phone
    // (too long): it classifies as a weak residual → not a seed, but it is published on
    // the bus as EntityExcluded, so nothing is discarded without first being classified.
    let m = ClassifyModule;
    let (ctx, mut rx) = ctx_with_rx();
    let target = Target::new(TargetKind::Organisation, "internal ref 1234567890123456 noted");
    let _ = m.process(&target, &ctx).await.expect("should succeed");

    let mut saw_exclusion = false;
    while let Ok(ev) = rx.try_recv() {
        if let EventKind::EntityExcluded { reason, .. } = ev.kind
            && reason.starts_with("classified_below_reinjection_floor")
        {
            saw_exclusion = true;
        }
    }
    assert!(
        saw_exclusion,
        "a classified-but-weak candidate must be announced on the event bus"
    );
}
