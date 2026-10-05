//! Environment fingerprint for the debug bundle.

/// Whether a working `curl` is on `PATH` (a `curl --version` that exits 0).
/// `search_engines`, `social_probe`, and `oathnet` shell out to it, so its
/// absence silently returns nothing from a whole class of modules — the single
/// most common "why did this find nothing?" cause on a fresh Termux install.
/// Single-sourced so the environment fingerprint and the system bundle's
/// issue-detector agree on one detection.
pub(super) fn curl_present() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The debug bundle's key inventory, split by whether each slot holds a usable
/// credential — the SAME test ([`crate::util::keys::is_configured_value`]) the
/// modules apply when they resolve their key.
///
/// It used to split on the key's NAME alone: every loaded `HUNTSMAN_*` slot was
/// "present" and only a name missing from the env file was "absent". But
/// `hse provision` writes a full template of `insert_..._here` slots, and
/// modules reject those via [`crate::util::keys::resolve_key`] — so the
/// scan-7258fc07 bundle listed SEEKNOW, DEHASHED, INTELX, EXA, OATHNET and a
/// dozen more under `keys_present` with `keys_absent : 0`, while its own SCAN
/// SEQUENCE held 247 "needs API key" skips for exactly those keys. The section
/// exists to answer "why did module X find nothing?", and it answered it
/// wrongly. This is the name-versus-credential confusion `is_configured_value`
/// documents, already fixed for `hse doctor`, provision and the key pool.
///
/// Pure over the loaded map (no `$HOME`, no env), so it is testable and
/// deterministic: both lists are sorted.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct KeyInventory<'a> {
    /// `HUNTSMAN_*` slots holding a configured value, sorted.
    pub(super) present: Vec<&'a str>,
    /// Known keys with no configured value — missing, blank, or an unedited
    /// template placeholder — sorted (`KNOWN_KEYS` order is not relied on).
    pub(super) absent: Vec<&'static str>,
    /// How many of `absent` are present by NAME but hold a blank value or a
    /// template placeholder, so the operator can tell "never provisioned" from
    /// "provisioned, never filled in".
    pub(super) unfilled: usize,
}

pub(super) fn key_inventory(
    loaded: &std::collections::HashMap<String, String>,
) -> KeyInventory<'_> {
    use crate::util::keys::{KNOWN_KEYS, is_configured_value};
    let mut present: Vec<&str> = loaded
        .iter()
        .filter(|(k, v)| k.starts_with("HUNTSMAN_") && is_configured_value(v))
        .map(|(k, _)| k.as_str())
        .collect();
    present.sort_unstable();
    let mut absent: Vec<&'static str> = KNOWN_KEYS
        .iter()
        .copied()
        .filter(|k| !loaded.get(*k).is_some_and(|v| is_configured_value(v)))
        .collect();
    absent.sort_unstable();
    let unfilled = absent.iter().filter(|k| loaded.contains_key(**k)).count();
    KeyInventory {
        present,
        absent,
        unfilled,
    }
}

/// Environment fingerprint for the debug bundle: the build, host, module set,
/// and key-PRESENCE (names only — never values) under which a scan ran. This is
/// what makes "why did module X find nothing?" answerable from the artifact
/// alone — almost always an absent key or a missing `curl`, not a bug — and lets
/// configuration/environment drift between two bundles be diffed (Determinism
/// Requirement names config/env drift as a thing to detect and report).
///
/// A key is "present" only when its slot holds a configured value — see
/// [`key_inventory`]; a template placeholder is reported absent, because that
/// is how every module treats it.
///
/// Deliberately secret-free: only the NAMES of `HUNTSMAN_*` keys are listed,
/// never their values. Per-process-stable (version, target, registry,
/// key presence don't change mid-process), so it does not break the bundle's
/// byte-determinism for a fixed host.
pub(super) fn render_environment(curl: bool) -> String {
    use std::fmt::Write as _;
    let loaded = crate::util::keys::load();
    let KeyInventory {
        present,
        absent,
        unfilled,
    } = key_inventory(&loaded);

    let mods = crate::modules::registry();
    let mut by_cost: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for m in &mods {
        *by_cost.entry(super::cost_label(m.cost())).or_default() += 1;
    }
    let cost_summary = by_cost
        .iter()
        .map(|(c, n)| format!("{c} {n}"))
        .collect::<Vec<_>>()
        .join(", ");

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
                .entry(super::cost_label(m.cost()))
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
        "  keys_absent : {} (modules needing these skip cleanly, not errors){}{}",
        absent.len(),
        if unfilled == 0 {
            String::new()
        } else {
            format!(" — {unfilled} provisioned but unfilled (blank or template placeholder)")
        },
        if absent.is_empty() {
            String::new()
        } else {
            format!(": {}", absent.join(", "))
        }
    );
    s
}
