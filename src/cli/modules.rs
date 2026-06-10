//! `hse modules` — list the module catalogue as a text table or as JSON,
//! optionally filtered by category. The JSON form mirrors the
//! `/api/v1/modules` shape so the CLI output can be `jq`-ed exactly like the
//! HTTP endpoint.

use super::cost_label;
use crate::core::error::{Error, Result};
use crate::core::scan::{Target, TargetKind};
use crate::modules::registry;

pub(super) fn cmd_modules(category_filter: Option<String>, as_json: bool) -> Result<()> {
    let mut mods = registry();
    mods.sort_by_key(|m| std::cmp::Reverse(m.priority()));

    // Optional category filter — case-insensitive exact match against
    // the snake_case category name (e.g. `--category geo`, `--category
    // dns_recon`). Pre-strip the operator's input to match the
    // canonical form ModuleCategory::as_str returns.
    let category_filter_lc = category_filter.as_ref().map(|s| s.to_lowercase());
    let filtered: Vec<_> = mods
        .iter()
        .filter(|m| match &category_filter_lc {
            Some(needle) => m.category().as_str() == needle.as_str(),
            None => true,
        })
        .collect();

    if as_json {
        // Same shape as /api/v1/modules — operators can `jq` the
        // output the same way they'd `jq` the HTTP endpoint.
        let infos: Vec<_> = filtered.iter().map(|m| m.info()).collect();
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "modules": infos,
            "count": infos.len(),
        }))
        .map_err(|e| Error::Other(format!("json: {e}")))?;
        println!("{body}");
        return Ok(());
    }

    println!(
        "{:<26} {:>4}  {:<14} {:<10} {:<8} ACCEPTS",
        "MODULE", "PRI", "CATEGORY", "COST", "PASSIVE"
    );
    println!("{}", "-".repeat(96));

    let target_kinds = [
        ("email", TargetKind::Email),
        ("username", TargetKind::Username),
        ("phone", TargetKind::Phone),
        ("domain", TargetKind::Domain),
        ("url", TargetKind::Url),
        ("ip", TargetKind::IpAddress),
        ("cidr", TargetKind::Cidr),
        ("asn", TargetKind::Asn),
        ("name", TargetKind::FullName),
        ("coords", TargetKind::Coordinates),
        ("address", TargetKind::Address),
        ("org", TargetKind::Organisation),
        ("abn", TargetKind::AbnAcn),
        ("apikey", TargetKind::ApiKey),
    ];

    for m in &filtered {
        let accepts: Vec<&str> = target_kinds
            .iter()
            .filter(|(_, k)| m.accepts(&Target::new(*k, "")))
            .map(|(label, _)| *label)
            .collect();
        let cost = cost_label(m.cost());
        let passive = if m.is_passive() { "yes" } else { "no" };
        println!(
            "{:<26} {:>4}  {:<14} {:<10} {:<8} {}",
            m.name(),
            m.priority(),
            m.category().as_str(),
            cost,
            passive,
            accepts.join(",")
        );
    }
    if filtered.is_empty() {
        if let Some(f) = category_filter {
            eprintln!("\nNo modules in category '{f}'.");
            eprintln!(
                "Valid: dns_recon / breach / infrastructure / search / geo / social /\n       email / phone / corporate / threat / sensor / people / web / other"
            );
        }
    } else {
        println!("\n{} module(s) total.", filtered.len());
        // MITRE ATT&CK Reconnaissance (TA0043) coverage across the listed
        // modules — the standard vocabulary for what OSINT collection this set
        // performs. Sorted, deduplicated, each shown with its technique name.
        let mut techniques: Vec<&str> = filtered
            .iter()
            .flat_map(|m| m.attack_techniques().iter().copied())
            .collect();
        techniques.sort_unstable();
        techniques.dedup();
        if !techniques.is_empty() {
            println!(
                "\nMITRE ATT&CK {} ({}) coverage — {} technique(s):",
                crate::core::attack::TACTIC_NAME,
                crate::core::attack::TACTIC_ID,
                techniques.len()
            );
            for id in techniques {
                let name = crate::core::attack::technique(id).map_or("", |t| t.name);
                println!("  {id:<11} {name}");
            }
        }
    }
    Ok(())
}
