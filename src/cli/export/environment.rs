//! Environment fingerprint for the debug bundle.

/// Environment fingerprint for the debug bundle: the build, host, module set,
/// and key-PRESENCE (names only — never values) under which a scan ran. This is
/// what makes "why did module X find nothing?" answerable from the artifact
/// alone — almost always an absent key or a missing `curl`, not a bug — and lets
/// configuration/environment drift between two bundles be diffed (Determinism
/// Requirement names config/env drift as a thing to detect and report).
///
/// Deliberately secret-free: only the NAMES of present `HUNTSMAN_*` keys are
/// listed, never their values. Per-process-stable (version, target, registry,
/// key presence don't change mid-process), so it does not break the bundle's
/// byte-determinism for a fixed host.
pub(super) fn render_environment() -> String {
    use std::fmt::Write as _;
    let loaded = crate::util::keys::load();
    let mut present: Vec<&str> = loaded
        .keys()
        .filter(|k| k.starts_with("HUNTSMAN_"))
        .map(String::as_str)
        .collect();
    present.sort_unstable();
    let absent: Vec<&&str> = crate::util::keys::KNOWN_KEYS
        .iter()
        .filter(|k| !loaded.contains_key(**k))
        .collect();

    let mods = crate::modules::registry();
    let mut by_cost: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for m in &mods {
        *by_cost.entry(super::super::cost_label(m.cost())).or_default() += 1;
    }
    let cost_summary = by_cost
        .iter()
        .map(|(c, n)| format!("{c} {n}"))
        .collect::<Vec<_>>()
        .join(", ");

    let curl = std::process::Command::new("curl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut s = String::new();
    let _ = writeln!(s, "\n── ENVIRONMENT (reconstructable scan context) ──");
    let _ = writeln!(s, "  hse_version : {}", crate::VERSION);
    let _ = writeln!(
        s,
        "  build_target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    let _ = writeln!(
        s,
        "  source      : {} files, {} LOC (full manifest in the SOURCE FILES section)",
        crate::source_manifest::SOURCE_FILES.len(),
        crate::source_manifest::SOURCE_TOTAL_LINES,
    );
    let _ = writeln!(
        s,
        "  termux      : {}",
        if crate::is_termux() {
            "detected"
        } else {
            "not detected"
        }
    );
    let _ = writeln!(
        s,
        "  curl        : {} (search_engines/social_probe/oathnet shell out to it)",
        if curl {
            "present"
        } else {
            "MISSING — those modules return nothing"
        }
    );
    let _ = writeln!(
        s,
        "  modules     : {} registered ({cost_summary})",
        mods.len()
    );
    // The full module-file roster, so the bundle reflects EVERY module the binary
    // carries — including ones that never dispatched on this scan. Grouped by cost
    // tier and sorted, so a `grep 'module=<name>'` in the SCAN SEQUENCE / logs can
    // be cross-checked against the complete inventory.
    {
        let mut by_tier: std::collections::BTreeMap<&str, Vec<&str>> =
            std::collections::BTreeMap::new();
        for m in &mods {
            by_tier
                .entry(super::super::cost_label(m.cost()))
                .or_default()
                .push(m.name());
        }
        for names in by_tier.values_mut() {
            names.sort_unstable();
        }
        for (tier, names) in &by_tier {
            let _ = writeln!(s, "    {tier:<10} ({}) {}", names.len(), names.join(", "));
        }
    }
    let _ = writeln!(
        s,
        "  keys_present: {}",
        if present.is_empty() {
            "(none — all free modules still run)".to_string()
        } else {
            present.join(", ")
        }
    );
    let _ = writeln!(
        s,
        "  keys_absent : {} (modules needing these skip cleanly, not errors){}",
        absent.len(),
        if absent.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                absent.iter().map(|k| **k).collect::<Vec<_>>().join(", ")
            )
        }
    );
    s
}
