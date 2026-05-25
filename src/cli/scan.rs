//! `hse scan` — single-run scan with full ScanOptions surface.

use crate::{
    core::{
        module::ModuleContext,
        scan::{Scan, ScanOptions, Target},
    },
    util::{http::build_client, keys, uid::scan_id},
};

use super::{build_runtime, parse_target_kind, split_csv, truncate};

pub(super) struct ScanCmd {
    pub kind: String,
    pub value: String,
    pub modules: Option<String>,
    pub exclude: Option<String>,
    pub throttle_ms: u64,
    pub min_confidence: Option<f64>,
    pub free_only: bool,
    pub passive_only: bool,
    pub module_timeout_ms: Option<u64>,
    pub depth: u32,
    pub min_expand_confidence: f64,
    pub max_entities: Option<usize>,
    pub max_wall_time_secs: Option<u64>,
    pub max_concurrent: usize,
    pub output: String,
}

pub(super) async fn cmd_scan(cmd: ScanCmd) -> crate::core::error::Result<()> {
    let target_kind = parse_target_kind(&cmd.kind)?;
    let target = Target::new(target_kind, cmd.value.clone());

    let options = ScanOptions {
        modules: split_csv(cmd.modules),
        exclude_modules: split_csv(cmd.exclude).unwrap_or_default(),
        throttle_ms: cmd.throttle_ms,
        max_concurrent: cmd.max_concurrent,
        module_timeout_ms: cmd.module_timeout_ms,
        min_confidence: cmd.min_confidence,
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth: cmd.depth,
        min_expand_confidence: cmd.min_expand_confidence,
        max_entities: cmd.max_entities,
        max_wall_time_secs: cmd.max_wall_time_secs,
        scan_tags: Vec::new(),
        notes: None,
    };

    let sid = scan_id(target_kind.canonical_str(), &cmd.value);
    let (store, bus, engine) = build_runtime(64)?;

    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: keys::load(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let scan = engine.run(scan, target, ctx).await?;
    let entities = store.entities_for_scan(&sid)?;
    let correlations = store.correlations_for_scan(&sid)?;

    if cmd.output == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "scan": scan,
                "entities": entities,
                "correlations": correlations,
            }))?
        );
    } else {
        println!(
            "\nScan {} — {} entities for {}={}\n",
            &sid[..8],
            entities.len(),
            cmd.kind,
            cmd.value
        );
        println!(
            "{:<16} {:<46} {:>6} {:>6}  CLASS",
            "KIND", "VALUE", "CONF", "C_EFF"
        );
        println!("{}", "-".repeat(86));
        for e in &entities {
            let val = truncate(&e.value, 46);
            println!(
                "{:<16} {:<46} {:>6.3} {:>6.3}  {}",
                e.kind.to_string(),
                val,
                e.confidence,
                e.c_effective(),
                e.classify()
            );
        }
        if !correlations.is_empty() {
            println!("\n{} correlations:\n", correlations.len());
            println!(
                "{:<10} {:<10} {:<40} DESCRIPTION",
                "RULE", "SEVERITY", "NAME"
            );
            println!("{}", "-".repeat(86));
            for c in &correlations {
                println!(
                    "{:<10} {:<10} {:<40} {}",
                    c.rule_id,
                    c.severity.to_string(),
                    truncate(&c.rule_name, 40),
                    c.description
                );
            }
        }
    }
    Ok(())
}
