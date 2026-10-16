//! End-to-end front-end for `huntsman-recon username`.

use std::path::PathBuf;

use crate::bluesky_user;
use crate::canonical::canonical_handle;
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::github_user;
use crate::http::Transport;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::SourceExecutionOutcome;
use crate::username_sites;
use crate::username_variants::{VARIANT_CONFIDENCE, variants};
use crate::validation::{ValueKind, is_placeholder_entity};

pub const USERNAME_USAGE: &str = "usage: huntsman-recon username HANDLE [--save FILE]";
pub const USERNAME_HELP: &str = "\
username HANDLE [--save FILE]
Derive deterministic handle variants and query keyless public GitHub, Bluesky and additional site profiles. --save FILE writes an unverified ledger that verify can reload.";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameArgs {
    pub username: String,
    pub save: Option<PathBuf>,
}

impl UsernameArgs {
    /// # Errors
    /// Invalid/missing handle, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("username needs exactly one HANDLE".into()));
        }
        let username = canonical_username(&positional[0])?;
        Ok(Self { username, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UsernameRun {
    Printed { text: String, report: Report },
    Failed(String),
}

/// Run deterministic variants and the keyless public-profile collectors, each when the
/// transport's lookup asks its module ([`Transport::runs_module`]).
#[must_use]
pub fn run<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    username: &str,
    now_unix: u64,
) -> UsernameRun {
    let username = match canonical_username(username) {
        Ok(username) => username,
        Err(error) => return UsernameRun::Failed(error.to_string()),
    };
    let scan_id = crate::entity::scan_id("username", &username);
    let mut report = Report {
        entities: derived_entities(&username, &scan_id),
        outcomes: Vec::new(),
    };

    if transport.runs_module(github_user::SRC) {
        collect_github(transport, keys, &username, &scan_id, now_unix, &mut report);
    }
    if transport.runs_module(bluesky_user::SRC) {
        collect_bluesky(transport, &username, &scan_id, now_unix, &mut report);
    }
    if transport.runs_module(username_sites::SOURCE) {
        collect_sites(transport, &username, &scan_id, now_unix, &mut report);
    }
    merge_by_uid(&mut report.entities);

    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => UsernameRun::Printed { text, report },
        Err(message) => UsernameRun::Failed(message),
    }
}

fn collect_sites<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) {
    match username_sites::lookup(transport, username, now_unix) {
        Ok(hits) => {
            report.entities.extend(username_sites::entities(&hits, username, scan_id));
            report.outcomes.push(username_sites::outcome(&hits, now_unix));
        }
        Err(error) => report.outcomes.push(SourceExecutionOutcome::inconclusive(
            username_sites::SOURCE,
            now_unix,
            error.to_string(),
        )),
    }
}

/// `raw` as the username lookups key on: `@` and surrounding space removed, lower-cased, ASCII
/// letters, digits, `.`, `_` and `-` only, and not a placeholder. `exposure` uses the same rule.
///
/// # Errors
/// [`Error::InvalidValue`] for a value that breaks the rule.
pub fn canonical_username(raw: &str) -> Result<String, Error> {
    let value = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::invalid_value("invalid username selector"));
    }
    let canonical = canonical_handle(&value)
        .ok_or_else(|| Error::invalid_value("invalid username selector"))?;
    if is_placeholder_entity(&ValueKind::Username, &canonical) {
        return Err(Error::invalid_value("placeholder username selector"));
    }
    Ok(value)
}

fn derived_entities(username: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    let mut seed = Entity::new(EntityKind::Username, username, 0.99, scan_id);
    seed.tag("seed");
    seed.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        "operator-supplied username selector",
    ));
    entities.push(seed);

    for variant in variants(username) {
        let mut entity = Entity::new(EntityKind::Username, &variant, VARIANT_CONFIDENCE, scan_id);
        entity.tag("derived");
        entity.tag("variant");
        entity.tag("candidate");
        entity.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan("username_variants", scan_id),
                format!("Handle normalization variant of '{username}'"),
            )
            .with_attr("source_username", username)
            .with_attr("derivation", "handle_variant")
            .inferred(),
        );
        entities.push(entity);
    }
    entities
}

fn collect_github<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    username: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) {
    match github_user::lookup(transport, keys, username, scan_id, now_unix) {
        Ok(found) => {
            report.entities.extend(found.entities);
            report.outcomes.push(found.outcome);
        }
        Err(error) => report.outcomes.push(SourceExecutionOutcome::inconclusive(
            github_user::SRC,
            now_unix,
            error.to_string(),
        )),
    }
}

fn collect_bluesky<T: Transport + ?Sized>(
    transport: &T,
    username: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) {
    match bluesky_user::lookup(transport, username, scan_id, now_unix) {
        Ok(found) => {
            report.entities.extend(found.entities);
            report.outcomes.push(found.outcome);
        }
        Err(error) => report.outcomes.push(SourceExecutionOutcome::inconclusive(
            bluesky_user::SRC,
            now_unix,
            error.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::unexpected_controls;

    struct Fake {
        replies: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn new(replies: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }

    fn response(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn parses_handle_and_save() {
        let parsed =
            UsernameArgs::parse(&["@Jane.Doe".into(), "--save".into(), "out.json".into()]).unwrap();
        assert_eq!(parsed.username, "jane.doe");
        assert_eq!(parsed.save, Some(PathBuf::from("out.json")));
    }

    #[test]
    fn rejects_path_and_placeholder_selectors() {
        assert!(UsernameArgs::parse(&["../root".into()]).is_err());
        assert!(UsernameArgs::parse(&["username".into()]).is_err());
    }

    #[test]
    fn run_combines_variants_github_and_bluesky() {
        let github = r#"{
          "login":"jane-doe",
          "id":7,
          "html_url":"https://github.com/jane-doe",
          "name":"Jane Citizen",
          "email":"jane@example.org"
        }"#;
        let bluesky = r#"{
          "handle":"jane-doe.bsky.social",
          "displayName":"Jane Citizen",
          "did":"did:plc:oky5czdrnfjpqslsw2a5iclo"
        }"#;
        let fake = Fake::new(vec![Ok(response(200, github)), Ok(response(200, bluesky))]);
        match run(&fake, &Keys::default(), "jane-doe", 1) {
            UsernameRun::Printed { text, report } => {
                assert!(text.contains("github_user\tsuccess"), "{text}");
                assert!(text.contains("bluesky_user\tsuccess"), "{text}");
                assert!(text.contains("lineage="), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.kind == EntityKind::Email)
                );
            }
            other @ UsernameRun::Failed(_) => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_profile_name_cannot_drive_the_terminal_or_forge_a_row() {
        let github = r#"{
          "login":"jane-doe",
          "id":7,
          "html_url":"https://github.com/jane-doe",
          "name":"Jane\u001b[2J Citizen\nforged\tcolumn"
        }"#;
        let bluesky = r#"{
          "handle":"jane-doe.bsky.social",
          "displayName":"Jane\u001b]0;title\u0007 Citizen",
          "did":"did:plc:oky5czdrnfjpqslsw2a5iclo"
        }"#;
        let fake = Fake::new(vec![Ok(response(200, github)), Ok(response(200, bluesky))]);
        let UsernameRun::Printed { text, report } = run(&fake, &Keys::default(), "jane-doe", 1)
        else {
            panic!("the lookup should print a report");
        };
        assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.raw_value.contains('\u{1b}')),
            "the profile text reached the entities, which is what the report must neutralise"
        );
        assert!(
            unexpected_controls(&text, &['\n', '\t']).is_empty(),
            "a control character other than the report's own separators: {text:?}"
        );
        assert!(
            !text.lines().any(|line| line.starts_with("forged")),
            "profile text became a row of its own: {text:?}"
        );
        assert!(
            text.contains("Jane\\u{1b}[2J Citizen\\nforged\\tcolumn"),
            "{text:?}"
        );
    }

    #[test]
    fn one_clean_miss_does_not_erase_the_other_source() {
        let bluesky = r#"{"handle":"nobody.bsky.social"}"#;
        let fake = Fake::new(vec![Ok(response(404, "")), Ok(response(200, bluesky))]);
        match run(&fake, &Keys::default(), "nobody", 1) {
            UsernameRun::Printed { report, .. } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
                assert_eq!(report.outcomes[1].kind, SourceOutcomeKind::Success);
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.has_tag("bluesky"))
                );
            }
            other @ UsernameRun::Failed(_) => panic!("{other:?}"),
        }
    }
}
