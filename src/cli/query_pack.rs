//! `hse query-pack` — generate the manual operator query pack for a target.
//!
//! Thin CLI over [`crate::core::query_pack`]: it constructs a [`Target`] from the
//! value (kind auto-detected, or `--kind`), stamps the current time, and prints
//! the ranked manual queries as a table or JSON. All generation is offline and
//! deterministic; nothing is fetched.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::error::{Error, Result};
use crate::core::query_pack::{ManualQuery, generate};
use crate::core::scan::{Target, TargetKind};

use super::{parse_target_kind, truncate};

pub(super) async fn cmd_query_pack(value: String, kind: String, output: String) -> Result<()> {
    let v = value.trim();
    if v.is_empty() {
        return Err(Error::InvalidTarget(
            "query-pack value is empty — pass a target, e.g. \
             `hse query-pack alice@example.com`"
                .to_string(),
        ));
    }

    // Resolve output format before anything else, mirroring `hse query`.
    let json = match output.as_str() {
        "json" => true,
        "table" => false,
        other => {
            return Err(Error::Other(format!(
                "unknown --output format {other:?} (expected `table` or `json`)"
            )));
        }
    };

    // An omitted (or `auto`) --kind is inferred from the value, exactly as
    // `hse scan` does; an explicit kind is parsed and validated.
    let target_kind: TargetKind = if kind.is_empty() || kind.eq_ignore_ascii_case("auto") {
        crate::core::scan::detect_kind(v)
    } else {
        parse_target_kind(&kind)?
    };
    let target = Target::new(target_kind, v.to_string());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let pack = generate(&target, now);

    if json {
        print_json(&target, &pack);
    } else {
        print_table(&target, &pack);
    }
    Ok(())
}

fn print_table(target: &Target, pack: &[ManualQuery]) {
    if pack.is_empty() {
        println!(
            "No manual providers apply to a {} target — the manual pack covers \
             identity/exposure kinds (email, username, domain, phone, name, IP, …).",
            target.kind.canonical_str()
        );
        return;
    }
    println!(
        "Manual query pack for {} {:?} — {} provider quer{} \
         (DISCOVERY / EXPOSURE VERIFICATION only; run each by hand)",
        target.kind.canonical_str(),
        truncate(target.value.trim(), 60),
        pack.len(),
        if pack.len() == 1 { "y" } else { "ies" }
    );
    if let Some(first) = pack.first() {
        println!("parent_query_id: {}", first.parent_query_id);
    }
    println!();
    for q in pack {
        println!("{:>2}. {}  [{}]", q.rank, q.provider, q.manual_entrypoint);
        println!("      query: {:?}  ({})", q.query, q.query_type);
        println!("      expect: {}", q.expected_result_class);
    }
}

fn print_json(target: &Target, pack: &[ManualQuery]) {
    let items: Vec<_> = pack
        .iter()
        .map(|q| {
            serde_json::json!({
                "provider": q.provider,
                "rank": q.rank,
                "query": q.query,
                "query_type": q.query_type,
                "manual_entrypoint": q.manual_entrypoint,
                "expected_result_class": q.expected_result_class,
                "parent_query_id": q.parent_query_id,
                "generated_at": q.generated_at,
            })
        })
        .collect();
    let body = serde_json::json!({
        "target": target.value.trim(),
        "target_kind": target.kind.canonical_str(),
        "purpose": "DISCOVERY / EXPOSURE VERIFICATION / CORRELATION",
        "count": pack.len(),
        "queries": items,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into())
    );
}
