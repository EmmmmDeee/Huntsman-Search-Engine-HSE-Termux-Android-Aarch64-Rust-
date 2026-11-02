//! A conservative universal research entry point over existing Huntsman capabilities.
//!
//! No new HTTP client, persistence model or execution engine. Unknown terms go through the
//! existing keyless adaptive web query; exact, supported identifiers use the existing scan path.

use std::process::ExitCode;

use huntsman_recon::exit::EX_USAGE;
use huntsman_recon::research_route::{self, ResearchAction};

use super::{fail, lookup};

pub(super) const RESEARCH_HELP: &str = "research [--plan] [--fast|--all] TERM...\nResearch arbitrary text using an existing Huntsman capability. Recognised exact identifiers use the established typed scan route; general phrases use the keyless adaptive web search. A coordinate point uses geocode rather than the older scan radio-area default. --plan selects and prints the route offline without fetching. All 16 engines are searched by default for free text; --fast selects Bing, Brave, and Mojeek. --all remains accepted for compatibility. A typed scan can invoke existing configured source integrations; for guaranteed keyless research use query --adaptive. Does not require root or a runtime LLM.";

pub(super) fn research_cmd(args: &[String]) -> ExitCode {
    let mut preview = false;
    let mut all = false;
    let mut fast = false;
    let mut offset = 0;
    while let Some(flag) = args.get(offset).map(String::as_str) {
        match flag {
            "--plan" if !preview => preview = true,
            "--all" if !all && !fast => all = true,
            "--fast" if !fast && !all => fast = true,
            _ => break,
        }
        offset += 1;
    }
    let terms = &args[offset..];
    if terms.is_empty() || terms.iter().any(|value| value.starts_with("--")) {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon research [--plan] [--fast|--all] TERM...",
        );
    }

    let input = terms.join(" ");
    let action = match research_route::plan(&input) {
        Ok(action) => action,
        Err(message) => return fail(EX_USAGE, message),
    };
    match action {
        ResearchAction::Targeted { kind, selector } => {
            if preview {
                println!("route=scan\tkind={}", kind.command());
                return ExitCode::SUCCESS;
            }
            // An explicit kind prevents inference changing the target after canonicalisation.
            lookup::scan_cmd(&[selector, "-k".into(), kind.command().into()])
        }
        ResearchAction::AdaptiveWeb { query } => {
            if preview {
                println!("route=adaptive_web_search\tkeyless=true");
                return ExitCode::SUCCESS;
            }
            if fast {
                lookup::query_cmd(&["--adaptive".into(), "--fast".into(), query])
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
