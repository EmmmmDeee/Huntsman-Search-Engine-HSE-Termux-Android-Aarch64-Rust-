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
        // Show one toggle (defaults to on if never set).
        (Some(k), None) => {
            println!("{k} = {}", mark(crate::util::settings::get_bool(&k, true)));
            Ok(())
        }
        // List all known toggles.
        (None, _) => {
            println!("\nCapability toggles — set with `hse config <key> <on|off>`\n");
            let engine_toggles = crate::modules::search_engines::engine_toggles();
            println!("Search engines (default on):");
            for (k, on) in &engine_toggles {
                println!("  {k:<26} {}", mark(*on));
            }
            // Any stored override not already shown above.
            let shown: std::collections::BTreeSet<&str> =
                engine_toggles.iter().map(|(k, _)| k.as_str()).collect();
            let others: Vec<_> = crate::util::settings::overrides()
                .into_iter()
                .filter(|(k, _)| !shown.contains(k.as_str()))
                .collect();
            if !others.is_empty() {
                println!("\nOther toggles:");
                for (k, on) in others {
                    println!("  {k:<26} {}", mark(on));
                }
            }
            println!();
            Ok(())
        }
    }
}
