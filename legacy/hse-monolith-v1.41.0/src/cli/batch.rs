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
    /// Provider class when no `--site` narrows it: `breach`, `genealogy`, `all`.
    pub class: String,
    pub bare: bool,
    pub out: Option<String>,
    pub format: String,
    pub no_permute: bool,
    pub synthesize_emails: bool,
    pub max: usize,
}

/// The providers `--site` / `--class` selected, or an error naming the unknown
/// ids/class and the known ones. A thin wrapper over [`sites::resolve`] — the
/// one authority the CLI and the API `batch.txt` share so their provider
/// selection can never drift — that adds the `batch:` command prefix.
pub fn resolve_sites(site: &[String], class: &str) -> Result<Vec<&'static sites::Site>> {
    let refs: Vec<&str> = site.iter().map(String::as_str).collect();
    sites::resolve(&refs, class).map_err(|m| Error::Other(format!("batch: {m}")))
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
            println!(
                "{:<20} {:<10} {} — {}",
                s.id,
                s.class.as_str(),
                s.name,
                s.url
            );
        }
        return Ok(());
    }
    let sites = resolve_sites(&args.site, &args.class)?;

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
        // The default class is breach: no --site renders the breach providers,
        // never the genealogy ones — the pre-class behaviour, preserved.
        let breach: Vec<&str> = sites::SITES
            .iter()
            .filter(|s| s.class == sites::SiteClass::Breach)
            .map(|s| s.id)
            .collect();
        assert_eq!(resolve_sites(&[], "breach").unwrap().len(), breach.len());
        assert_eq!(
            resolve_sites(&[], "").unwrap().len(),
            breach.len(),
            "an empty --class is the breach default"
        );
        assert!(
            resolve_sites(&[], "genealogy")
                .unwrap()
                .iter()
                .all(|s| s.class == sites::SiteClass::Genealogy),
            "--class genealogy renders only genealogy providers"
        );
        assert_eq!(
            resolve_sites(&[], "all").unwrap().len(),
            sites::SITES.len(),
            "--class all renders every provider"
        );
        let two = resolve_sites(&["oathnet,seeknow".to_string()], "breach").unwrap();
        assert_eq!(
            two.iter().map(|s| s.id).collect::<Vec<_>>(),
            vec!["oathnet", "seeknow"]
        );
        // Naming a provider includes it whatever its class — a genealogy id
        // resolves even under the breach default.
        let named = resolve_sites(&["ancestry".to_string()], "breach").unwrap();
        assert_eq!(
            named.iter().map(|s| s.id).collect::<Vec<_>>(),
            vec!["ancestry"]
        );
        let dup = resolve_sites(&["oathnet".to_string(), "OATHNET".to_string()], "breach").unwrap();
        assert_eq!(dup.len(), 1, "a provider named twice renders once");
        let err = resolve_sites(&["nowhere".to_string()], "breach")
            .unwrap_err()
            .to_string();
        assert!(err.contains("nowhere") && err.contains("oathnet"), "{err}");
        let bad_class = resolve_sites(&[], "nope").unwrap_err().to_string();
        assert!(
            bad_class.contains("nope") && bad_class.contains("genealogy"),
            "{bad_class}"
        );
    }

    #[test]
    fn json_output_carries_the_subject_selectors_and_providers() {
        let sels = vec![Selector {
            kind: SelectorKind::Email,
            value: "a@b.c".into(),
        }];
        let sites = resolve_sites(&["oathnet".to_string()], "breach").unwrap();
        let out = render_output(&sites, &sels, "a@b.c", "json", false).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["subject"], "a@b.c");
        assert_eq!(v["providers"][0]["site"], "oathnet");
        assert_eq!(v["providers"][0]["class"], "breach");
        assert_eq!(v["providers"][0]["lines"][0], "a@b.c");
        assert!(render_output(&sites, &sels, "x", "yaml", false).is_err());
    }
}
