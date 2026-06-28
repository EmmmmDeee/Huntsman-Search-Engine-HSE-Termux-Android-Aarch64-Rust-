//! `hse config` — view/set persistent capability toggles (universal
//! toggleability). No args lists all known toggles; `hse config <key> <on|off>`
//! sets one (persisted to `~/.huntsman/settings.json`).

use crate::core::error::{Error, Result};
use serde_json::{Value, json};

fn parse_on_off(v: &str) -> Option<bool> {
    match v.to_lowercase().as_str() {
        "on" | "true" | "1" | "yes" | "enable" | "enabled" => Some(true),
        "off" | "false" | "0" | "no" | "disable" | "disabled" => Some(false),
        _ => None,
    }
}

fn mark(on: bool) -> &'static str {
    if on { "● on" } else { "○ off" }
}

/// One toggle rendered for JSON output, matching the `{ key, name, enabled }`
/// shape the web Settings panel consumes (`/api/v1/settings/toggles`). `name`
/// is the key with its namespace prefix stripped so the UI can show a bare
/// label (`google`, not `engine.google`).
fn toggle_json(key: &str, enabled: bool) -> Value {
    let name = key
        .strip_prefix("engine.")
        .or_else(|| key.strip_prefix("feature."))
        .or_else(|| key.strip_prefix("module."))
        .unwrap_or(key);
    json!({ "key": key, "name": name, "enabled": enabled })
}

/// Build the full toggle inventory as the `groups` object the Settings page
/// consumes. The CLI has no live engine handle (that lives in `AppState`), so
/// the third group carries stored module *overrides* rather than the entire
/// module registry — every other key still reports its current resolved state.
fn inventory_json(
    feature_toggles: &[(String, bool)],
    engine_toggles: &[(String, bool)],
    module_overrides: &[(String, bool)],
) -> Value {
    let features: Vec<Value> = feature_toggles
        .iter()
        .map(|(k, on)| toggle_json(k, *on))
        .collect();
    let engines: Vec<Value> = engine_toggles
        .iter()
        .map(|(k, on)| toggle_json(k, *on))
        .collect();
    let modules: Vec<Value> = module_overrides
        .iter()
        .map(|(k, on)| toggle_json(k, *on))
        .collect();
    let count = features.len() + engines.len() + modules.len();
    json!({
        "groups": [
            { "group": "features", "label": "Features", "toggles": features },
            { "group": "engines", "label": "Search engines", "toggles": engines },
            { "group": "modules", "label": "Modules", "toggles": modules },
        ],
        "count": count,
    })
}

/// Print a serde value as pretty JSON to stdout (the contract every other
/// `--json` command in the CLI follows so output is `jq`-able).
fn print_json(v: &Value) -> Result<()> {
    let body = serde_json::to_string_pretty(v).map_err(|e| Error::Other(format!("json: {e}")))?;
    println!("{body}");
    Ok(())
}

pub fn cmd_config(key: Option<String>, value: Option<String>, as_json: bool) -> Result<()> {
    match (key, value) {
        // Set a toggle.
        (Some(k), Some(v)) => {
            let on = parse_on_off(&v)
                .ok_or_else(|| Error::Other(format!("value must be on/off (got '{v}')")))?;
            crate::util::settings::set_bool(&k, on)
                .map_err(|e| Error::Other(format!("could not persist setting: {e}")))?;
            if as_json {
                print_json(&toggle_json(&k, on))
            } else {
                println!("{k} = {}", mark(on));
                Ok(())
            }
        }
        // Show one toggle. An unset key resolves to its in-code default — `on`
        // for engines/modules, the registered default for a `feature.*` key
        // (e.g. `feature.regional` is off) — so the display matches what a scan
        // would actually apply.
        (Some(k), None) => {
            let default = crate::util::settings::default_for(&k);
            let on = crate::util::settings::get_bool(&k, default);
            if as_json {
                print_json(&toggle_json(&k, on))
            } else {
                println!("{k} = {}", mark(on));
                Ok(())
            }
        }
        // List all known toggles.
        (None, _) => {
            // Features (capability switches that aren't a single engine/module).
            let feature_toggles = crate::util::settings::feature_toggles();
            let engine_toggles = crate::modules::search_engines::engine_toggles();
            // Any stored override not already shown above (e.g. per-module toggles).
            let mut shown: std::collections::BTreeSet<&str> =
                engine_toggles.iter().map(|(k, _)| k.as_str()).collect();
            shown.extend(feature_toggles.iter().map(|(k, _)| k.as_str()));
            let others: Vec<(String, bool)> = crate::util::settings::overrides()
                .into_iter()
                .filter(|(k, _)| !shown.contains(k.as_str()))
                .collect();

            if as_json {
                return print_json(&inventory_json(&feature_toggles, &engine_toggles, &others));
            }

            println!("\nCapability toggles — set with `hse config <key> <on|off>`\n");
            println!("Features:");
            for (k, on) in &feature_toggles {
                println!("  {k:<26} {}", mark(*on));
            }
            println!("\nSearch engines (default on):");
            for (k, on) in &engine_toggles {
                println!("  {k:<26} {}", mark(*on));
            }
            if !others.is_empty() {
                println!("\nOverrides (modules):");
                for (k, on) in &others {
                    println!("  {k:<26} {}", mark(*on));
                }
            }
            println!(
                "\nAny module can be toggled too: `hse config module.<name> off` \
                 (names from `hse modules`).\n"
            );
            Ok(())
        }
    }
}
