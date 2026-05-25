use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::{
    entity::unix_now,
    error::{Error, Result},
    event::EventKind,
    module::ModuleContext,
    scan::{Scan, ScanOptions, Target, TargetKind},
};
use crate::storage::store::Store;
use crate::util::{http::build_client, keys, uid::scan_id};

const ENV_TEMPLATE: &str = include_str!("env_template.txt");

const PLACEHOLDER_PREFIX: &str = "insert_";
const PLACEHOLDER_SUFFIX: &str = "_here";

fn parse_kv(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.is_empty() {
        return None;
    }
    let eq = trimmed.find('=')?;
    let key = trimmed[..eq].trim();
    if !key.starts_with("HUNTSMAN_") {
        return None;
    }
    let rest = trimmed[eq + 1..].trim_start();
    let value = if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        rest[..end].to_string()
    } else {
        rest.split(['#', ' ', '\t']).next()?.to_string()
    };
    Some((key.to_string(), value))
}

fn is_placeholder(value: &str) -> bool {
    value.starts_with(PLACEHOLDER_PREFIX) && value.ends_with(PLACEHOLDER_SUFFIX)
}

pub fn merge_template(existing: &str, template: &str) -> String {
    let mut real_values: BTreeMap<String, String> = BTreeMap::new();
    for line in existing.lines() {
        if let Some((k, v)) = parse_kv(line)
            && !is_placeholder(&v)
            && !v.is_empty()
        {
            real_values.insert(k, v);
        }
    }

    let mut seen_in_template: BTreeMap<String, ()> = BTreeMap::new();

    let mut out = String::with_capacity(template.len() + 256);
    for line in template.lines() {
        if let Some((k, _)) = parse_kv(line) {
            seen_in_template.insert(k.clone(), ());
            if let Some(real) = real_values.get(&k) {
                out.push_str(&format!("{k}=\"{real}\"\n"));
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }

    let leftover: Vec<(&String, &String)> = real_values
        .iter()
        .filter(|(k, _)| !seen_in_template.contains_key(*k))
        .collect();
    if !leftover.is_empty() {
        out.push_str("\n# --- USER-CUSTOM KEYS (not in template) ---\n");
        for (k, v) in leftover {
            out.push_str(&format!("{k}=\"{v}\"\n"));
        }
    }
    out
}

fn write_env_file(path: &Path, contents: &str) -> Result<Option<PathBuf>> {
    let backup = if path.exists() {
        let bak = path.with_extension(format!("env.bak.{}", unix_now()));
        fs::copy(path, &bak).map_err(|e| {
            Error::Other(format!(
                "backup {} → {}: {e}",
                path.display(),
                bak.display()
            ))
        })?;
        Some(bak)
    } else {
        None
    };

    let tmp = path.with_extension("env.provision.tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| Error::Other(format!("open {}: {e}", tmp.display())))?;
        f.write_all(contents.as_bytes())
            .map_err(|e| Error::Other(format!("write {}: {e}", tmp.display())))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, contents.as_bytes())
            .map_err(|e| Error::Other(format!("write {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        Error::Other(format!(
            "rename {} → {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(backup)
}

pub fn cmd_provision_env(dry_run: bool) -> Result<()> {
    let path = PathBuf::from(keys::env_path());
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let merged = merge_template(&existing, ENV_TEMPLATE);

    let (template_keys, real_keys, custom_keys) = count_keys(&existing);

    println!("==> Phase: env merge");
    println!("    target file:    {}", path.display());
    println!("    template keys:  {template_keys}");
    println!("    real values:    {real_keys}");
    println!("    custom keys:    {custom_keys} (not in template, will be preserved)");

    if dry_run {
        println!("    (--dry-run; no changes written)");
        println!("\n--- merged content preview ---");
        println!("{merged}");
        return Ok(());
    }

    let backup = write_env_file(&path, &merged)?;
    if let Some(bak) = backup {
        println!("    backed up to:   {}", bak.display());
    }
    println!("    wrote:          {} (mode 0600)", path.display());
    Ok(())
}

fn count_keys(existing: &str) -> (usize, usize, usize) {
    let template_keys = ENV_TEMPLATE
        .lines()
        .filter_map(parse_kv)
        .map(|(k, _)| k)
        .collect::<std::collections::BTreeSet<_>>();
    let mut real = 0usize;
    let mut custom = 0usize;
    for line in existing.lines() {
        if let Some((k, v)) = parse_kv(line)
            && !is_placeholder(&v)
            && !v.is_empty()
        {
            if template_keys.contains(&k) {
                real += 1;
            } else {
                custom += 1;
            }
        }
    }
    (template_keys.len(), real, custom)
}

pub async fn cmd_provision_verify() -> Result<()> {
    use crate::modules::registry;

    println!("==> Phase: verify");

    let mods = registry();
    println!(
        "    modules:        {} registered ({} free, {} key-gated, {} paid)",
        mods.len(),
        mods.iter()
            .filter(|m| matches!(m.cost(), crate::core::module::ModuleCost::Free))
            .count(),
        mods.iter()
            .filter(|m| matches!(m.cost(), crate::core::module::ModuleCost::KeyGated))
            .count(),
        mods.iter()
            .filter(|m| matches!(m.cost(), crate::core::module::ModuleCost::Paid))
            .count(),
    );
    println!("    db path:        {}", crate::default_db_path());
    println!("    keys path:      {}", keys::env_path());

    let loaded = keys::load();
    let real_count = loaded
        .iter()
        .filter(|(k, v)| k.starts_with("HUNTSMAN_") && !is_placeholder(v) && !v.is_empty())
        .count();
    let placeholder_count = loaded
        .iter()
        .filter(|(k, v)| k.starts_with("HUNTSMAN_") && is_placeholder(v))
        .count();
    println!(
        "    keys loaded:    {real_count} real, {placeholder_count} placeholders awaiting values"
    );

    println!("    smoke test:     passive-only scan against example.com…");
    let SmokeResult {
        entity_count,
        correlation_count,
        missing_keys,
        completed,
    } = run_smoke(
        Target::new(TargetKind::Domain, "example.com"),
        ScanOptions {
            passive_only: true,
            ..Default::default()
        },
    )
    .await?;
    println!(
        "                    {} {entity_count} entit{}, {correlation_count} correlation{}",
        if completed { "✓" } else { "!" },
        if entity_count == 1 { "y" } else { "ies" },
        if correlation_count == 1 { "" } else { "s" },
    );

    let oathnet_real = loaded
        .get("HUNTSMAN_OATHNET_KEY")
        .map(|v| !is_placeholder(v) && !v.is_empty())
        .unwrap_or(false);
    if oathnet_real {
        println!("    missing-key:    HUNTSMAN_OATHNET_KEY populated — sub-test skipped");
    } else {
        let mk = run_smoke(
            Target::new(TargetKind::Domain, "example.com"),
            ScanOptions {
                modules: Some(vec!["oathnet_pro".into()]),
                ..Default::default()
            },
        )
        .await?;
        let saw_oathnet = mk.missing_keys.iter().any(|k| k == "HUNTSMAN_OATHNET_KEY");
        if saw_oathnet {
            println!(
                "    missing-key:    ✓ engine reported `missing key: HUNTSMAN_OATHNET_KEY` and \
                returned a clean envelope (no panic)"
            );
        } else {
            println!(
                "    missing-key:    ! oathnet_pro ran without reporting a missing key — \
                expected error not observed"
            );
        }
        for k in &missing_keys {
            if k != "HUNTSMAN_OATHNET_KEY" {
                println!("                    (also missing: {k})");
            }
        }
    }

    Ok(())
}

struct SmokeResult {
    entity_count: usize,
    correlation_count: usize,
    missing_keys: Vec<String>,
    completed: bool,
}

async fn run_smoke(target: Target, options: ScanOptions) -> Result<SmokeResult> {
    let store = Arc::new(Store::open(&crate::default_db_path())?);
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let engine = Arc::new(crate::core::engine::ScanEngine::new(
        crate::modules::registry(),
        Arc::clone(&store),
        bus.clone(),
    ));

    let sid = scan_id(target.kind.canonical_str(), &target.value);
    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);

    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus: bus.clone(),
        http: build_client(),
        keys: keys::load(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let mut rx = bus.subscribe();

    let completed = engine.run(scan.clone(), target, ctx).await.is_ok();

    let entities = store.entities_for_scan(&sid).unwrap_or_default();
    let correlations = store.correlations_for_scan(&sid).unwrap_or_default();

    let mut missing_keys = Vec::<String>::new();
    while let Ok(ev) = rx.try_recv() {
        if let EventKind::ModuleError { error, .. } = &ev.kind
            && let Some(rest) = error.strip_prefix("missing key: ")
        {
            missing_keys.push(rest.to_string());
        }
    }

    Ok(SmokeResult {
        entity_count: entities.len(),
        correlation_count: correlations.len(),
        missing_keys,
        completed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template_for_test() -> &'static str {
        "# top comment\n\
         HUNTSMAN_OATHNET_KEY=\"insert_oathnet_pro_key_here\"\n\
         HUNTSMAN_SHODAN_KEY=\"insert_shodan_key_here\"\n\
         HUNTSMAN_HIBP_KEY=\"insert_haveibeenpwned_key_here\"\n"
    }

    #[test]
    fn merge_preserves_real_values() {
        let existing = "HUNTSMAN_OATHNET_KEY=\"real-rotated-key-abc\"\n";
        let merged = merge_template(existing, template_for_test());
        assert!(merged.contains("HUNTSMAN_OATHNET_KEY=\"real-rotated-key-abc\""));
        // Other placeholders stay.
        assert!(merged.contains("HUNTSMAN_SHODAN_KEY=\"insert_shodan_key_here\""));
    }

    #[test]
    fn merge_keeps_placeholders_for_unset_keys() {
        let merged = merge_template("", template_for_test());
        assert!(merged.contains("HUNTSMAN_OATHNET_KEY=\"insert_oathnet_pro_key_here\""));
        assert!(merged.contains("HUNTSMAN_SHODAN_KEY=\"insert_shodan_key_here\""));
        assert!(merged.contains("HUNTSMAN_HIBP_KEY=\"insert_haveibeenpwned_key_here\""));
    }

    #[test]
    fn merge_preserves_top_comment() {
        let merged = merge_template("", template_for_test());
        assert!(merged.starts_with("# top comment"));
    }

    #[test]
    fn merge_appends_user_custom_keys() {
        let existing = "HUNTSMAN_CUSTOM_INTEGRATION_KEY=\"my-secret\"\n";
        let merged = merge_template(existing, template_for_test());
        assert!(merged.contains("# --- USER-CUSTOM KEYS"));
        assert!(merged.contains("HUNTSMAN_CUSTOM_INTEGRATION_KEY=\"my-secret\""));
    }

    #[test]
    fn merge_ignores_blank_and_comment_lines_in_existing() {
        let existing = "\n# a comment\nHUNTSMAN_SHODAN_KEY=\"actual-key\"\n";
        let merged = merge_template(existing, template_for_test());
        assert!(merged.contains("HUNTSMAN_SHODAN_KEY=\"actual-key\""));
    }

    #[test]
    fn parse_kv_handles_quoted_and_unquoted() {
        assert_eq!(
            parse_kv("HUNTSMAN_X=\"abc\""),
            Some(("HUNTSMAN_X".into(), "abc".into()))
        );
        assert_eq!(
            parse_kv("HUNTSMAN_X=plain"),
            Some(("HUNTSMAN_X".into(), "plain".into()))
        );
        assert_eq!(parse_kv("# comment"), None);
        assert_eq!(parse_kv(""), None);
        assert_eq!(parse_kv("OTHER_VAR=ignored"), None);
    }

    #[test]
    fn placeholder_detection() {
        assert!(is_placeholder("insert_oathnet_pro_key_here"));
        assert!(is_placeholder("insert_x_here"));
        assert!(!is_placeholder("real-value-xyz"));
        assert!(!is_placeholder(""));
        assert!(!is_placeholder("insert_x"));
        assert!(!is_placeholder("x_here"));
    }

    #[test]
    fn merge_against_full_template_is_idempotent() {
        // Apply the merge twice with the same input — the second pass
        // must produce identical output (deterministic + stable).
        let existing = "HUNTSMAN_OATHNET_KEY=\"real-a\"\nHUNTSMAN_SHODAN_KEY=\"real-b\"\n";
        let once = merge_template(existing, ENV_TEMPLATE);
        let twice = merge_template(&once, ENV_TEMPLATE);
        assert_eq!(
            once, twice,
            "merge_template must be idempotent against the canonical template"
        );
    }
}
