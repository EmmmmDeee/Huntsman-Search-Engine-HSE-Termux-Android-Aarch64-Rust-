//! End-to-end front-end for `huntsman-recon username`.
//!
//! Derives deterministic handle variants and queries the keyless public GitHub, Bluesky, Keybase
//! and Mastodon profiles, `TikTok` self-published bio contacts, and recent public Wikipedia edits. When no
//! profile source answered, the lookup ends from its rows through
//! [`crate::source_outcome::SourceReach`]: a request refused before sending is a refusal (exit
//! 77), otherwise no usable response (exit 69). The handle's own derived variants are not a
//! finding, so they never keep such a lookup from failing.

use std::path::PathBuf;

use crate::bluesky_user;
use crate::canonical::canonical_handle;
use crate::concurrent::{self, Job};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::github_user;
use crate::http::Transport;
use crate::keybase;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::mastodon_user;
use crate::source_outcome::{SourceExecutionOutcome, SourceReach, SourceRun};
use crate::tiktok_public_contact;
use crate::username_variants::{VARIANT_CONFIDENCE, variants};
use crate::validation::{ValueKind, is_placeholder_entity};
use crate::wikipedia;

pub const USERNAME_USAGE: &str = "usage: huntsman-recon username HANDLE [--save FILE]";
pub const USERNAME_HELP: &str = "\
username HANDLE [--save FILE]
Derive handle variants and query public GitHub, Bluesky, Keybase, Mastodon, TikTok self-published bio contacts and Wikipedia contributions. Email contacts are self-declared candidates, not proven mailbox owners. --save FILE writes an unverified ledger.";

/// One source's answer: what it found and its outcome, or the refusal that stopped it.
type Found = Result<(Vec<Entity>, SourceExecutionOutcome), Error>;

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
        let (raw, save) = LookupTokens::single(args, "username needs exactly one HANDLE")?;
        let username = canonical_username(&raw)?;
        Ok(Self { username, save })
    }
}

/// How a username lookup ended. A lookup no profile source answered ends through
/// [`SourceReach`]: a refusal is [`UsernameRun::Network`] (exit 77), no response is
/// [`UsernameRun::Failed`] (exit 69); otherwise it prints.
pub type UsernameRun = SourceRun<Report>;

/// Run deterministic variants and the keyless public-profile sources, each when the transport's
/// lookup asks its module ([`Transport::runs_module`]), all at once.
#[must_use]
pub fn run<T: Transport + Sync + ?Sized>(
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

    // Each source asks a different server about the handle alone, so they run at once and the
    // lookup takes as long as the slowest of them. Their answers are folded in this order, so the
    // report is the one they gave when they ran one after another.
    let (name, scan) = (username.as_str(), scan_id.as_str());
    let sources: [(&str, Job<'_, Found>); 6] = [
        (
            github_user::SRC,
            Box::new(move || {
                github_user::lookup(transport, keys, name, scan, now_unix)
                    .map(|found| (found.entities, found.outcome))
            }),
        ),
        (
            bluesky_user::SRC,
            Box::new(move || {
                bluesky_user::lookup(transport, name, scan, now_unix)
                    .map(|found| (found.entities, found.outcome))
            }),
        ),
        (
            keybase::SRC,
            Box::new(move || {
                keybase::lookup(transport, name, scan, now_unix)
                    .map(|found| (found.entities, found.outcome))
            }),
        ),
        (
            wikipedia::SRC,
            Box::new(move || {
                wikipedia::lookup(transport, name, scan, now_unix)
                    .map(|found| (found.entities, found.outcome))
            }),
        ),
        (
            mastodon_user::SRC,
            Box::new(move || {
                mastodon_user::lookup(transport, name, scan, now_unix)
                    .map(|found| (found.entities, found.outcome))
            }),
        ),
        (
            tiktok_public_contact::SRC,
            Box::new(move || {
                tiktok_public_contact::lookup(transport, name, scan, now_unix)
                    .map(|found| (found.entities, found.outcome))
            }),
        ),
    ];
    let (modules, jobs): (Vec<&str>, Vec<Job<'_, Found>>) = sources
        .into_iter()
        .filter(|(module, _)| transport.runs_module(module))
        .unzip();
    for (module, found) in modules.into_iter().zip(concurrent::all(jobs)) {
        match found {
            Ok((entities, outcome)) => {
                report.entities.extend(entities);
                report.outcomes.push(outcome);
            }
            // A URL the guarded fetch refused before sending names nothing about the handle.
            Err(error @ Error::Network(_)) => {
                report
                    .outcomes
                    .push(SourceExecutionOutcome::refused_before_sending(
                        module,
                        now_unix,
                        error.to_string(),
                    ));
            }
            Err(error) => report.outcomes.push(SourceExecutionOutcome::inconclusive(
                module,
                now_unix,
                error.to_string(),
            )),
        }
    }
    merge_by_uid(&mut report.entities);

    // When no profile source answered, the lookup ends from its rows: a request refused before
    // sending is a refusal (exit 77), else no usable response (exit 69). The handle's own derived
    // variants are not a finding, so they do not keep such a lookup from failing.
    if let Some(run) =
        SourceReach::of(&report.outcomes).unanswered(&format!("no source answered for {username}"))
    {
        return run;
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => UsernameRun::Printed { text, report },
        Err(message) => UsernameRun::Failed(message),
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
    let seed_uid = seed.uid.clone();
    entities.push(seed);

    for variant in variants(username) {
        let mut entity = Entity::new(EntityKind::Username, &variant, VARIANT_CONFIDENCE, scan_id);
        // A variant that differs from the seed only by separators (john.doe, john_doe, johndoe)
        // is the seed's own identity: merged into it, it would tag the operator's seed as a
        // derived candidate.
        if entity.uid == seed_uid {
            continue;
        }
        entity.tag(crate::tags::DERIVED);
        entity.tag("variant");
        entity.tag(crate::tags::CANDIDATE);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seed_stays_the_operators_seed_after_its_variants_are_merged() {
        let mut entities = derived_entities("john.doe", "scan");
        merge_by_uid(&mut entities);
        let seed = entities
            .iter()
            .find(|entity| entity.has_tag("seed"))
            .expect("seed");
        assert_eq!(seed.tags, ["seed"], "the seed absorbed a variant");
        assert!(
            entities
                .iter()
                .filter(|entity| entity.uid == seed.uid)
                .count()
                == 1,
            "{entities:?}"
        );
    }

    use crate::http::{Request, Response, TransportFailure};
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::unexpected_controls;

    const GITHUB: &str = "api.github.com";
    const BLUESKY: &str = "public.api.bsky.app";
    const KEYBASE: &str = "keybase.io";
    const WIKIPEDIA: &str = "en.wikipedia.org";
    const MASTODON: &str = "mastodon.social";
    const TIKTOK: &str = "www.tiktok.com";

    /// Answers each source by its host, as the sources run at once and in no fixed order; a host
    /// with no reply answers nothing, which no source may take for absence.
    struct Fake {
        replies: Vec<(&'static str, Response)>,
    }

    impl Fake {
        fn new(replies: Vec<(&'static str, Response)>) -> Self {
            Self { replies }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.replies
                .iter()
                .find(|(host, _)| request.url.starts_with(&format!("https://{host}/")))
                .map(|(_, reply)| reply.clone())
                .ok_or_else(|| TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: format!("no reply scripted for {}", request.url),
                    blocked: false,
                })
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
    fn a_blocked_transport_refuses_the_whole_username_lookup() {
        // Every profile leg builds a request that the blocked egress refuses before sending, so no
        // source answered and the lookup refuses (exit 77) from its rows, naming the first refused
        // leg, rather than printing an empty report. The reason carries the egress refusal
        // (`network: …`), never a reached-but-silent transport failure.
        let UsernameRun::Network(why) = run(
            &crate::test_support::Refusing,
            &Keys::default(),
            "janedoe",
            1,
        ) else {
            panic!("a fully-blocked username lookup did not refuse");
        };
        assert!(
            why.starts_with(&format!("{}: ", github_user::SRC)),
            "the refusal names the first profile leg: {why}"
        );
        assert!(
            why.contains("network:"),
            "the refusal is an egress refusal, not a transport failure: {why}"
        );
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
        let fake = Fake::new(vec![
            (GITHUB, response(200, github)),
            (BLUESKY, response(200, bluesky)),
            (WIKIPEDIA, response(200, r#"{"query":{"usercontribs":[]}}"#)),
        ]);
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
            other => panic!("{other:?}"),
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
        let fake = Fake::new(vec![
            (GITHUB, response(200, github)),
            (BLUESKY, response(200, bluesky)),
            (WIKIPEDIA, response(200, r#"{"query":{"usercontribs":[]}}"#)),
        ]);
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
        let keybase = r#"{"status":{"code":0,"name":"OK"},"them":[null]}"#;
        let fake = Fake::new(vec![
            (GITHUB, response(404, "")),
            (BLUESKY, response(200, bluesky)),
            (KEYBASE, response(200, keybase)),
            (WIKIPEDIA, response(200, r#"{"query":{"usercontribs":[]}}"#)),
            (MASTODON, response(404, r#"{"error":"Record not found"}"#)),
        ]);
        match run(&fake, &Keys::default(), "nobody", 1) {
            UsernameRun::Printed { report, text } => {
                assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
                assert_eq!(report.outcomes[1].kind, SourceOutcomeKind::Success);
                assert_eq!(report.outcomes[2].kind, SourceOutcomeKind::ValidZero);
                assert!(text.contains("keybase\t"), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.has_tag("bluesky"))
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn keybase_proofs_reach_the_combined_report() {
        let github = r#"{"login":"max","id":1,"html_url":"https://github.com/max"}"#;
        let bluesky = r#"{"handle":"max.bsky.social"}"#;
        let keybase = r#"{
          "status":{"code":0,"name":"OK"},
          "them":[{
            "basics":{"username":"max","username_cased":"max"},
            "proofs_summary":{"by_presentation_group":{
              "twitter":[{"proof_type":"twitter","nametag":"maxtaco","service_url":"https://twitter.com/maxtaco"}]
            }}
          }]
        }"#;
        let fake = Fake::new(vec![
            (GITHUB, response(200, github)),
            (BLUESKY, response(200, bluesky)),
            (KEYBASE, response(200, keybase)),
            (WIKIPEDIA, response(200, r#"{"query":{"usercontribs":[]}}"#)),
            (MASTODON, response(404, r#"{"error":"Record not found"}"#)),
        ]);
        let UsernameRun::Printed { report, text } = run(&fake, &Keys::default(), "max", 1) else {
            panic!("the lookup should print a report");
        };
        assert!(text.contains("keybase\tsuccess"), "{text}");
        assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.has_tag("keybase")
                    && entity.kind == EntityKind::Username
                    && entity.value == "maxtaco")
        );
    }

    /// The sources run at once, yet the report lists them in one fixed order, so a lookup reads
    /// the same however its answers raced.
    #[test]
    fn every_source_answers_in_a_fixed_order() {
        let fake = Fake::new(vec![
            (GITHUB, response(404, "")),
            (BLUESKY, response(200, r#"{"handle":"max.bsky.social"}"#)),
            (
                KEYBASE,
                response(200, r#"{"status":{"code":0,"name":"OK"},"them":[null]}"#),
            ),
            (WIKIPEDIA, response(200, r#"{"query":{"usercontribs":[]}}"#)),
            (MASTODON, response(404, r#"{"error":"Record not found"}"#)),
            (TIKTOK, response(404, "")),
        ]);
        for _ in 0..8 {
            let UsernameRun::Printed { report, .. } = run(&fake, &Keys::default(), "max", 1) else {
                panic!("the lookup should print a report");
            };
            let modules: Vec<&str> = report.outcomes.iter().map(|o| o.module.as_str()).collect();
            assert_eq!(
                modules,
                [
                    github_user::SRC,
                    bluesky_user::SRC,
                    keybase::SRC,
                    wikipedia::SRC,
                    mastodon_user::SRC,
                    tiktok_public_contact::SRC
                ]
            );
        }
    }

    /// Each source waits on its own server, so six 200 ms requests answer in about 200 ms,
    /// not the second they took one after another.
    #[test]
    fn the_sources_run_at_once() {
        struct Slow(Fake);
        impl Transport for Slow {
            fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
                std::thread::sleep(std::time::Duration::from_millis(200));
                self.0.send(request)
            }
        }
        let slow = Slow(Fake::new(vec![
            (GITHUB, response(404, "")),
            (
                BLUESKY,
                response(200, r#"{"handle":"maxslow.bsky.social"}"#),
            ),
            (
                KEYBASE,
                response(200, r#"{"status":{"code":0,"name":"OK"},"them":[null]}"#),
            ),
            (WIKIPEDIA, response(200, r#"{"query":{"usercontribs":[]}}"#)),
            (MASTODON, response(404, r#"{"error":"Record not found"}"#)),
            (TIKTOK, response(404, "")),
        ]));
        let started = std::time::Instant::now();
        let UsernameRun::Printed { report, .. } = run(&slow, &Keys::default(), "maxslow", 1) else {
            panic!("the lookup should print a report");
        };
        let took = started.elapsed();
        assert_eq!(report.outcomes.len(), 6);
        assert!(
            took < std::time::Duration::from_millis(800),
            "six 200 ms sources took {took:?}"
        );
    }

    #[test]
    fn wikipedia_edits_reach_the_combined_report() {
        let wiki = r#"{"query":{"usercontribs":[
          {"user":"Max","revid":900001,"title":"Reconnaissance","timestamp":"2024-05-01T00:00:00Z","comment":"typo"}
        ]}}"#;
        let fake = Fake::new(vec![
            (GITHUB, response(404, "")),
            (BLUESKY, response(200, r#"{"handle":"max.bsky.social"}"#)),
            (
                KEYBASE,
                response(200, r#"{"status":{"code":0,"name":"OK"},"them":[null]}"#),
            ),
            (WIKIPEDIA, response(200, wiki)),
            (MASTODON, response(404, r#"{"error":"Record not found"}"#)),
        ]);
        let UsernameRun::Printed { report, text } = run(&fake, &Keys::default(), "max", 1) else {
            panic!("the lookup should print a report");
        };
        assert!(text.contains("wikipedia\tsuccess"), "{text}");
        assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Url
                    && entity.has_tag(crate::tags::WIKIPEDIA_EDIT)
                    && entity.value.contains("oldid=900001"))
        );
    }
}
