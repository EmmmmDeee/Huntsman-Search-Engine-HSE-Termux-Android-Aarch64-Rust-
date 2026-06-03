//! `hse config` — view/set persistent capability toggles (universal
//! toggleability). No args lists all known toggles; `hse config <key> <on|off>`
//! sets one (persisted to `~/.huntsman/settings.json`).

use crate::core::error::{Error, Result};

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

pub fn cmd_config(key: Option<String>, value: Option<String>) -> Result<()> {
    match (key, value) {
        // Set a toggle.
        (Some(k), Some(v)) => {
            let on = parse_on_off(&v)
                .ok_or_else(|| Error::Other(format!("value must be on/off (got '{v}')")))?;
            crate::util::settings::set_bool(&k, on)
                .map_err(|e| Error::Other(format!("could not persist setting: {e}")))?;
            println!("{k} = {}", mark(on));
            Ok(())
        }
        // Show one toggle. An unset key resolves to its in-code default — `on`
        // for engines/modules, the registered default for a `feature.*` key
        // (e.g. `feature.regional` is off) — so the display matches what a scan
        // would actually apply.
        (Some(k), None) => {
            let default = crate::util::settings::default_for(&k);
            println!(
                "{k} = {}",
                mark(crate::util::settings::get_bool(&k, default))
            );
            Ok(())
        }
        // List all known toggles.
        (None, _) => {
            println!("\nCapability toggles — set with `hse config <key> <on|off>`\n");
            // Features (capability switches that aren't a single engine/module).
            let feature_toggles = crate::util::settings::feature_toggles();
            println!("Features:");
            for (k, on) in &feature_toggles {
                println!("  {k:<26} {}", mark(*on));
            }
            let engine_toggles = crate::modules::search_engines::engine_toggles();
            println!("\nSearch engines (default on):");
            for (k, on) in &engine_toggles {
                println!("  {k:<26} {}", mark(*on));
            }
            // Any stored override not already shown above (e.g. per-module toggles).
            let mut shown: std::collections::BTreeSet<&str> =
                engine_toggles.iter().map(|(k, _)| k.as_str()).collect();
            shown.extend(feature_toggles.iter().map(|(k, _)| k.as_str()));
            let others: Vec<_> = crate::util::settings::overrides()
                .into_iter()
                .filter(|(k, _)| !shown.contains(k.as_str()))
                .collect();
            if !others.is_empty() {
                println!("\nOverrides (modules):");
                for (k, on) in others {
                    println!("  {k:<26} {}", mark(on));
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
