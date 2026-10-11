//! `docs/PROVIDER_CREDENTIALS.md` is the operator's copy of the credential manifest. Its table
//! lists each provider's slots, and its template is what an operator copies into the keys file.
//! Both must name exactly the slots `provider_credentials::PROVIDERS` declares, so a provider
//! added or renamed in code cannot leave the operator's copy behind.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use huntsman_recon::provider_credentials::PROVIDERS;

fn manifest_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/PROVIDER_CREDENTIALS.md");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The slot names in the doc's table: the code spans in its provider rows that begin `HUNTSMAN_`.
fn table_slots(doc: &str) -> BTreeSet<String> {
    doc.lines()
        .filter(|line| line.starts_with("| "))
        .flat_map(|line| line.split('`').skip(1).step_by(2))
        .filter(|span| span.starts_with("HUNTSMAN_"))
        .map(str::to_owned)
        .collect()
}

/// The slot names in the doc's template: the left side of each `NAME=` line in its dotenv fence.
fn template_slots(doc: &str) -> BTreeSet<String> {
    let mut inside = false;
    let mut slots = BTreeSet::new();
    for line in doc.lines() {
        match line {
            "```dotenv" => inside = true,
            "```" => inside = false,
            _ if inside => {
                if let Some((name, _)) = line.split_once('=') {
                    slots.insert(name.to_owned());
                }
            }
            _ => {}
        }
    }
    slots
}

#[test]
fn the_manifest_doc_names_exactly_the_declared_slots() {
    let declared: BTreeSet<String> = PROVIDERS
        .iter()
        .flat_map(|provider| provider.slots.iter().map(|slot| (*slot).to_owned()))
        .collect();
    let doc = manifest_doc();
    assert_eq!(table_slots(&doc), declared, "the provider table");
    assert_eq!(template_slots(&doc), declared, "the private template");
}

#[test]
fn the_doc_parsers_find_the_slots_they_are_compared_with() {
    // A parser that found nothing would make the comparison above pass vacuously.
    let doc = manifest_doc();
    assert!(table_slots(&doc).contains("HUNTSMAN_CENSYS_SECRET"));
    assert!(table_slots(&doc).contains("HUNTSMAN_SHODAN_KEY"));
    assert!(template_slots(&doc).contains("HUNTSMAN_WIGLE_USER"));
    assert!(!PROVIDERS.is_empty());
}
