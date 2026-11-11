//! A conservative universal research entry point over existing Huntsman capabilities.
//!
//! No new HTTP client, persistence model or execution engine. Unknown terms go through the
//! existing keyless adaptive web query; exact, supported identifiers use the existing scan path.

use std::process::ExitCode;

use huntsman_recon::exit::EX_USAGE;
use huntsman_recon::research_route::{self, ResearchAction};

use super::{fail, lookup};

pub(super) const RESEARCH_HELP: &str = "research [--plan] [--all] [--single] TERM...\nAutonomously research exact public identifiers with a bounded, evidence-driven fetch-expand-fetch crawl (two expansion generations); general phrases use the established keyless adaptive web search. A geographic coordinate uses the geocode route. --single restores a single typed scan without pivots. --plan prints the chosen route without network access. --all selects 13 keyless engines for a free-text adaptive query, with the existing 110-second overall budget. Existing provider and key requirements still apply; no root or runtime LLM is required.";

pub(super) fn research_cmd(args: &[String]) -> ExitCode {
    let mut preview = false;
    let mut all = false;
    let mut single = false;
    let mut offset = 0;
    while let Some(flag) = args.get(offset).map(String::as_str) {
        match flag {
            "--plan" if !preview => preview = true,
            "--all" if !all => all = true,
            "--single" if !single => single = true,
            _ => break,
        }
        offset += 1;
    }
    let terms = &args[offset..];
    if terms.is_empty() || terms.iter().any(|value| value.starts_with("--")) {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon research [--plan] [--all] [--single] TERM...",
        );
    }

    let input = terms.join(" ");
    let action = match research_route::plan(&input) {
        Ok(action) => action,
        Err(message) => return fail(EX_USAGE, message),
    };
    match action {
        ResearchAction::Targeted { kind, selector } => {
            // The existing recursive collector infers the kind of each seed. A canonical
            // username loses its leading @, so put it back before recursive dispatch.
            // Coordinates retain the existing geocode path rather than changing to Wi-Fi.
            let recursive = !single && kind != huntsman_recon::scan_route::ScanKind::Place;
            if preview {
                if recursive {
                    println!(
                        "route=recursive_scan\tkind={}\tmax_generations=2",
                        kind.command()
                    );
                } else {
                    println!("route=scan\tkind={}", kind.command());
                }
                return ExitCode::SUCCESS;
            }
            if recursive {
                let seed = if kind == huntsman_recon::scan_route::ScanKind::Username {
                    format!("@{selector}")
                } else {
                    selector
                };
                lookup::scan_cmd(&[
                    "--recurse".into(),
                    seed,
                    "--max-generations".into(),
                    "2".into(),
                ])
            } else {
                // Explicit kind retains the precise single-scan/coordinate routing.
                lookup::scan_cmd(&[selector, "-k".into(), kind.command().into()])
            }
        }
        ResearchAction::AdaptiveWeb { query } => {
            if preview {
                // `--all` changes only this route, so only its preview names the engine set.
                let engines = if all { "\tengines=all" } else { "" };
                println!("route=adaptive_web_search\tkeyless=true{engines}");
                return ExitCode::SUCCESS;
            }
            if all {
                lookup::query_cmd(&["--adaptive".into(), "--all".into(), query])
            } else {
                lookup::query_cmd(&["--adaptive".into(), query])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ResearchAction, research_route};

    #[test]
    fn a_dry_run_is_offline_for_arbitrary_terms_and_known_indicators() {
        assert_eq!(
            research_route::plan("anything goes"),
            Ok(ResearchAction::AdaptiveWeb {
                query: "anything goes".into()
            })
        );
        assert_eq!(
            research_route::plan("example.org"),
            Ok(ResearchAction::Targeted {
                kind: huntsman_recon::scan_route::ScanKind::Domain,
                selector: "example.org".into()
            })
        );
    }
}
