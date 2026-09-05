//! `hse batch` — the plaintext bulk-query list, from a seed or a stored scan.
//! The derivation and rendering live in `app::batch`; this is argument
//! handling and where the text goes.

use crate::app::batch::{self, Rendered, Selector, sites};
use crate::core::error::{Error, Result};
use crate::core::scan::detect_kind;
use crate::util::oathnet_batch::BatchOptions;

/// Parsed `batch` arguments (mirrors the clap variant; a struct so the body is
/// testable without clap).
pub struct BatchArgs {
    pub scan_id: Option<String>,
    pub value: Option<String>,
    pub kind: Option<String>,
    pub site: Vec<String>,
    pub bare: bool,
    pub out: Option<String>,
    pub format: String,
    pub no_permute: bool,
    pub synthesize_emails: bool,
    pub max: usize,
}

/// The providers `--site` selected (all when empty), or an error naming the
/// unknown ids and the known ones.
pub fn resolve_sites(site: &[String]) -> Result<Vec<&'static sites::Site>> {
    let wanted: Vec<&str> = site
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if wanted.is_empty() {
        return Ok(sites::SITES.iter().collect());
    }
    let mut chosen = Vec::new();
    let mut unknown = Vec::new();
    for w in wanted {
        match sites::find(w) {
            Some(s) if !chosen.iter().any(|c: &&sites::Site| c.id == s.id) => chosen.push(s),
            Some(_) => {}
            None => unknown.push(w.to_string()),
        }
    }
    if !unknown.is_empty() {
        return Err(Error::Other(format!(
            "batch: unknown --site {} — known providers: {}",
            unknown.join(", "),
            sites::ids().join(", ")
        )));
    }
    Ok(chosen)
}

/// Render the chosen providers for the selectors, as text or JSON.
pub fn render_output(
    sites: &[&'static sites::Site],
    selectors: &[Selector],
    subject: &str,
    format: &str,
    bare: bool,
) -> Result<String> {
    let rendered: Vec<Rendered> = sites.iter().map(|s| batch::render(s, selectors)).collect();
    match format.trim().to_ascii_lowercase().as_str() {
        "text" | "txt" => Ok(batch::to_text(&rendered, bare)),
        "json" => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "subject": subject,
            "selectors": selectors,
            "providers": rendered,
        }))?),
        other => Err(Error::Other(format!(
            "batch: unknown --format {other:?} (expected `text` or `json`)"
        ))),
    }
}

pub fn cmd_batch(args: BatchArgs) -> Result<()> {
    if args.site.iter().any(|s| s.eq_ignore_ascii_case("help")) {
        for s in sites::SITES {
            println!("{:<12} {} — {}", s.id, s.name, s.url);
        }
        return Ok(());
    }
    let sites = resolve_sites(&args.site)?;

    let (subject, selectors) = match (&args.scan_id, &args.value) {
        (Some(raw), _) => batch::from_scan(raw)?,
        (None, Some(value)) => {
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err(Error::Other("batch: --value must not be empty".into()));
            }
            let kind = match args
                .kind
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
            {
                Some(k) => super::parse_target_kind(k)?,
                None => detect_kind(&value),
            };
            let opts = BatchOptions {
                include_stealer: true,
                permute_handles: !args.no_permute,
                synthesize_emails: args.synthesize_emails,
                recurse_depth: 0,
                max_queries: args.max,
            };
            let selectors = batch::selectors_from_seed(kind, &value, &opts);
            if selectors.is_empty() {
                return Err(Error::Other(format!(
                    "batch: nothing to ask about for {value:?} (kind {}) — breach sites index \
                     email / username / name / phone / ip / domain seeds",
                    kind.canonical_str()
                )));
            }
            (value, selectors)
        }
        (None, None) => {
            return Err(Error::Other(
                "batch: give a seed with --value (kind auto-detected) or a stored scan with --scan-id".into(),
            ));
        }
    };

    let text = render_output(&sites, &selectors, &subject, &args.format, args.bare)?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, &text)
                .map_err(|e| Error::Other(format!("batch: could not write {path}: {e}")))?;
            eprintln!(
                "wrote {} selector(s) for {} provider(s) to {path}",
                selectors.len(),
                sites.len()
            );
        }
        None => print!("{text}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::batch::SelectorKind;

    #[test]
    fn site_selection_accepts_comma_lists_and_names_unknown_ids() {
        assert_eq!(resolve_sites(&[]).unwrap().len(), sites::SITES.len());
        let two = resolve_sites(&["oathnet,seeknow".to_string()]).unwrap();
        assert_eq!(
            two.iter().map(|s| s.id).collect::<Vec<_>>(),
            vec!["oathnet", "seeknow"]
        );
        let dup = resolve_sites(&["oathnet".to_string(), "OATHNET".to_string()]).unwrap();
        assert_eq!(dup.len(), 1, "a provider named twice renders once");
        let err = resolve_sites(&["nowhere".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("nowhere") && err.contains("oathnet"), "{err}");
    }

    #[test]
    fn json_output_carries_the_subject_selectors_and_providers() {
        let sels = vec![Selector {
            kind: SelectorKind::Email,
            value: "a@b.c".into(),
        }];
        let sites = resolve_sites(&["oathnet".to_string()]).unwrap();
        let out = render_output(&sites, &sels, "a@b.c", "json", false).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["subject"], "a@b.c");
        assert_eq!(v["providers"][0]["site"], "oathnet");
        assert_eq!(v["providers"][0]["lines"][0], "a@b.c");
        assert!(render_output(&sites, &sels, "x", "yaml", false).is_err());
    }
}
