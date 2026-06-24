//! Offline, no-network proof that the HSE engine executes **real** logic and emits
//! **real** output without any external API call.
//!
//! ```text
//! cargo run --example offline_seed                 # authorised self-test seed
//! cargo run --example offline_seed -- "Jane Q Public"
//! ```
//!
//! It runs the *real* `name_intel` module — a genuinely offline identity-derivation
//! module (pure permutation, no HTTP) — against a `FullName` seed, then feeds the
//! derived entities through the *real* [`diagnostics::analyse`] and [`audit::audit`]
//! analysis pipeline. Every value printed is computed by the same code paths the
//! live engine runs. Nothing here touches the network, an external API, GPS / Wi-Fi
//! / BLE, or any Android runtime, and nothing is mocked, faked, or simulated — the
//! HTTP client is merely *constructed* (it issues no request) because the module
//! signature requires one, and `name_intel` never uses it.

use std::collections::HashMap;

use huntsman_search_engine::audit::{self, AuditEntity, LogSignals};
use huntsman_search_engine::core::cancel::CancelHandle;
use huntsman_search_engine::core::module::{Module, ModuleContext};
use huntsman_search_engine::core::scan::{Target, TargetKind};
use huntsman_search_engine::modules::name_intel::NameIntel;
use huntsman_search_engine::util::diagnostics;
use huntsman_search_engine::util::proxy::ProxyPool;

fn main() {
    let seed = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Haigen Bamford".to_string());

    println!("════════════════════════════════════════════════════════════");
    println!("  HSE — offline legitimate-execution proof (no API / network)");
    println!("════════════════════════════════════════════════════════════");
    println!("seed (FullName): {seed}\n");

    let scan_id = "offline-demo";
    let target = Target::new(TargetKind::FullName, seed.as_str());

    // A fully local module context. `build_client()` only *constructs* a rustls
    // HTTP client — it issues no request — and `name_intel` never touches it.
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let ctx = ModuleContext {
        scan_id: scan_id.into(),
        bus,
        http: huntsman_search_engine::util::http::build_client(),
        keys: HashMap::new(),
        cancel: CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(ProxyPool::new()),
    };

    // ── Run the REAL name_intel module, fully offline ────────────────────────
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    let result = rt
        .block_on(NameIntel.process(&target, &ctx))
        .expect("name_intel offline process");
    let entities = result.entities;

    println!(
        "── name_intel derived {} entities (offline permutation) ──",
        entities.len()
    );
    for e in entities.iter().take(24) {
        let kind = e.kind.to_string();
        println!(
            "  {kind:<11} C={:.2}  C_eff={:.2}  {}",
            e.confidence,
            e.c_effective(),
            e.value
        );
    }
    if entities.len() > 24 {
        println!("  … {} more", entities.len() - 24);
    }

    // ── REAL analysis pipeline over the derived entities ─────────────────────
    let diag = diagnostics::analyse(scan_id, "name", &seed, 0, &entities);
    println!("\n── diagnostics::analyse (real) ──");
    println!("  entity-kind counts : {:?}", diag.entity_kind_counts);
    for h in diag.optimization_hints.iter().take(4) {
        println!("  hint: {h}");
    }

    let audit_entities: Vec<AuditEntity> = entities.iter().map(AuditEntity::from_entity).collect();
    let report = audit::audit(&audit_entities, LogSignals::default());
    println!("\n── audit::audit self-scorecard (real) ──");
    println!("  score      : {}/100  ({})", report.score, report.grade());
    println!(
        "  noise ratio: {:.0}% candidate-tier",
        report.noise_ratio * 100.0
    );
    println!("  findings   : {}", report.findings.len());

    println!(
        "\n✓ {} entities derived + analysed by real engine code, fully offline —",
        entities.len()
    );
    println!("  no API, no network, no GPS/Wi-Fi/BLE/Android, nothing mocked.");
}
