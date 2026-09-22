//! REQ-SKIPCLASS-001 — a query a module **declined to send** must never be
//! reported as a provider that answered and found nothing.
//!
//! Ten modules guard a minimum-query-quality floor before spending a provider
//! call: too few discriminating name tokens, a one-or-two character search
//! term. Every one of them then returned `Ok(ModuleResult::new())`. Dispatch
//! records an empty result as `ModuleDone { found: 0 }`, and `core::coverage`
//! aggregates that to [`ProviderOutcome::CleanNegative`] — documented as *"the
//! only outcome that is a real negative"* and the one `settles_absence()`
//! trusts. So "I declined to ask" was reported as "I asked, and the provider
//! holds nothing on this subject".
//!
//! `Error::Skipped` exists for exactly this and says so in its own doc: a
//! deliberate non-query is *"never `Ok(empty)`"*. Ten other modules already use
//! it. Each site here already carried a comment stating why it refused — the
//! reason was written down and then thrown away.
//!
//! **This lock lives at the module boundary, one row per call site**, because a
//! helper-level test proves the helper and says nothing about who calls it
//! (REQ-GEOGATE-001: *a fix is only as permanent as its least-locked call
//! site*). Every floor is checked BEFORE any network call, so each row is
//! hermetic — no socket is opened.
//!
//! The class is **not** uniform, and that is the point of listing it per row:
//! `Scoped` where the provider could have answered and the operator closes the
//! gap by asking better (`is_coverage_gap()` true), `NotApplicable` where the
//! provider would have rejected the query outright.

use huntsman_search_engine::core::{
    cancel::CancelHandle,
    error::Error,
    event::SkipClass,
    module::{Module, ModuleContext},
    scan::{Target, TargetKind},
};

/// A context whose HTTP client **cannot reach anything**: every request is
/// routed at a closed loopback port and capped at 250 ms, so it fails in
/// microseconds without a packet leaving the machine.
///
/// Both tests need this, for opposite reasons. The floor rows must not open a
/// socket at all — an offline client turns "it tried to fetch" into a loud,
/// instant transport error instead of a silent pass. The above-the-floor rows
/// deliberately DO proceed past the guard, and must not spend a real provider
/// call (nor download OFAC's entire SDN list) to prove it.
fn ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://127.0.0.1:1").expect("static proxy URL"))
        .connect_timeout(std::time::Duration::from_millis(250))
        .timeout(std::time::Duration::from_millis(250))
        .build()
        .expect("offline client");
    ModuleContext {
        scan_id: "query-floor".into(),
        bus,
        http,
        keys: std::collections::HashMap::new(),
        cancel: CancelHandle::new(),
    }
}

/// One row per module that refuses a too-weak query before querying.
type Row = (&'static str, TargetKind, &'static str, SkipClass);

fn rows() -> Vec<Row> {
    use TargetKind::*;
    vec![
        // A sanctions screen is the highest-stakes row: AU-114 grades a
        // designation Critical, so the operator's due-diligence answer rests on
        // the ABSENCE of a finding. `name_tokens("Al Zawahiri")` is a single
        // token once the 3-char floor drops "Al" (pinned in parse_tests.rs).
        ("sanctions_ofac", FullName, "Al Zawahiri", SkipClass::Scoped),
        ("asic_banned_orgs", Organisation, "Acme", SkipClass::Scoped),
        ("asic_persons", FullName, "Madonna", SkipClass::Scoped),
        ("asic_business_names", Organisation, "Ab", SkipClass::Scoped),
        ("acnc_charities", Organisation, "Ab", SkipClass::Scoped),
        ("gleif_lei", Organisation, "Ab", SkipClass::Scoped),
        ("wikidata", FullName, "Ab", SkipClass::Scoped),
        ("opencorporates", Organisation, "Ab", SkipClass::Scoped),
        ("data_gov_au", Organisation, "Ab", SkipClass::Scoped),
        // The one row that is NOT Scoped — RansomLook's own comment says the
        // API rejects the query, which is NotApplicable's exact wording:
        // "asking would have been rejected upstream, so its silence carries no
        // information about the subject either way".
        ("ransomlook", Organisation, "A", SkipClass::NotApplicable),
    ]
}

fn module_by_name(name: &str) -> Box<dyn Module> {
    use huntsman_search_engine::modules;
    match name {
        "sanctions_ofac" => Box::new(modules::sanctions_ofac::SanctionsOfac),
        "asic_banned_orgs" => Box::new(modules::asic_banned_orgs::AsicBannedOrgs),
        "asic_persons" => Box::new(modules::asic_persons::AsicPersons),
        "asic_business_names" => Box::new(modules::asic_business_names::AsicBusinessNames),
        "acnc_charities" => Box::new(modules::acnc_charities::AcncCharities),
        "gleif_lei" => Box::new(modules::gleif_lei::GleifLei),
        "wikidata" => Box::new(modules::wikidata::Wikidata),
        "opencorporates" => Box::new(modules::opencorporates::OpenCorporates),
        "data_gov_au" => Box::new(modules::data_gov_au::DataGovAu),
        "ransomlook" => Box::new(modules::ransomlook::RansomLook),
        other => panic!("unregistered module in the query-floor table: {other}"),
    }
}

#[tokio::test]
async fn a_query_below_the_floor_is_a_typed_skip_at_every_call_site() {
    let ctx = ctx();
    for (name, kind, weak, want_class) in rows() {
        let target = Target::new(kind, weak);
        // Every floor is pre-network, so this must not open a socket.
        let out = module_by_name(name).process(&target, &ctx).await;

        let err = match out {
            Ok(r) => panic!(
                "{name}: a query it declined to send answered Ok with {} entities — dispatch \
                 records that as ModuleDone{{found:0}}, which coverage aggregates to \
                 CleanNegative: 'queried, holds nothing on this subject' for a provider that \
                 was never asked",
                r.entities.len()
            ),
            Err(e) => e,
        };
        let Error::Skipped { class, reason } = err else {
            panic!("{name}: expected a typed Error::Skipped, got {err}");
        };
        assert_eq!(class, want_class, "{name}: wrong skip class");
        assert!(
            reason.contains(weak),
            "{name}: the reason must name the value it declined: {reason}"
        );
        // `Skipped.reason`'s own contract: it "must never read as 'found
        // nothing'". The shared `Error::query_too_weak` fixes the disclaimer so
        // no site can drift out of it.
        assert!(
            reason.contains("never asked"),
            "{name}: the reason must say the provider was never asked: {reason}"
        );
        let lower = reason.to_lowercase();
        for forbidden in ["no match", "found nothing", "no results", "no record"] {
            assert!(
                !lower.contains(forbidden),
                "{name}: a skip reason must not read as a negative result ({forbidden:?}): {reason}"
            );
        }
    }
}

/// Non-vacuity: the table must not be passing because every module refuses
/// everything. A query comfortably ABOVE each floor must clear the guard — so
/// whatever happens next, it is not this skip.
///
/// The client is offline ([`ctx`]), so the call past the guard dies as a
/// transport error in microseconds. That is the proof: reaching the transport
/// at all means the floor let the query through. Only an `Error::Skipped`
/// carrying the too-weak reason would mean the guard fired.
#[tokio::test]
async fn a_query_above_the_floor_clears_the_guard_everywhere() {
    let ctx = ctx();
    for (name, kind, _, _) in rows() {
        let target = Target::new(kind, "Australian Mutual Provident Society");
        match module_by_name(name).process(&target, &ctx).await {
            Err(Error::Skipped { reason, .. }) if reason.contains("not queried:") => panic!(
                "{name}: a well-formed multi-token query was refused by the query floor — the \
                 guard rejects everything, so the table above proves nothing: {reason}"
            ),
            _ => {}
        }
    }
}
