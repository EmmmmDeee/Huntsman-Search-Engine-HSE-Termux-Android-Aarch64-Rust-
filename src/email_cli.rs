//! End-to-end front-end for `huntsman-recon email`.
//!
//! The selector is canonicalised once, legacy-compatible deterministic email
//! derivations are produced locally, then the public Gravatar profile, Duolingo's
//! account-by-email lookup and the keys.openpgp.org key index are queried through the
//! shared transport. Evidence is rendered with lineage. Saving is handled by
//! the L7 `lookup_save` module, and `lookup_args` reads the `--save` option.
//! [`run_keyed`] then runs every indicator source for an address (`IPQualityScore`, the Hunter
//! verifier, Whoxy reverse WHOIS) whose key is configured; with no key it is exactly [`run`].

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::canonical::canonical_email;
use crate::domains::{
    is_freemail, is_infrastructure_mail_domain, is_role_localpart, is_social_platform,
    registrable_domain, split_email,
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::gravatar;
use crate::http::Transport;
use crate::indicator_legs;
use crate::indicator_sources::Indicator;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::SourceExecutionOutcome;
use crate::textnorm::upper_first;
use crate::{duolingo, openpgp_keys};

pub const EMAIL_USAGE: &str = "usage: huntsman-recon email ADDR [--save FILE]";
pub const EMAIL_HELP: &str = "\
email ADDR [--save FILE]
Canonicalise ADDR, derive deterministic email pivots, and query its public Gravatar profile, any Duolingo account registered to it, and any OpenPGP key published for it on keys.openpgp.org. Kickbox Open says, from the domain alone, whether it is a disposable-mail provider. Each keyed source runs when its key is set: IPQualityScore (HUNTSMAN_IPQS_KEY), the Hunter.io verifier (HUNTSMAN_HUNTER_KEY) and Whoxy reverse WHOIS (HUNTSMAN_WHOXY_KEY). --save FILE writes an unverified ledger that verify can reload.";

const CONF_DOMAIN: f64 = 0.80;
const CONF_USERNAME_CORPORATE: f64 = 0.70;
const CONF_USERNAME_FREEMAIL: f64 = 0.55;
const CONF_PERSON_CORPORATE: f64 = 0.55;
const CONF_PERSON_FREEMAIL: f64 = 0.45;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailArgs {
    pub email: String,
    pub save: Option<PathBuf>,
}

impl EmailArgs {
    /// # Errors
    /// Invalid or missing address, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("email needs exactly one ADDR".into()));
        }
        let email = canonical_email(&positional[0])
            .ok_or_else(|| Error::invalid_value("invalid email address"))?;
        Ok(Self { email, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EmailRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

type Collected = Result<(Vec<Entity>, SourceExecutionOutcome), Error>;
type Source<T> = fn(&T, &str, &str, u64) -> Collected;

/// The keyless public lookups `email` runs, in order. Each is one request.
fn sources<T: Transport + ?Sized>() -> [Source<T>; 3] {
    [
        |t, email, scan, now| {
            gravatar::lookup(t, email, scan, now).map(|r| (r.entities, r.outcome))
        },
        |t, email, scan, now| {
            duolingo::lookup(t, email, scan, now).map(|r| (r.entities, r.outcome))
        },
        |t, email, scan, now| {
            openpgp_keys::lookup(t, email, scan, now).map(|r| (r.entities, r.outcome))
        },
    ]
}

/// Run one deterministic email enrichment plus the keyless public lookups.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, email: &str, now_unix: u64) -> EmailRun {
    let Some(email) = canonical_email(email) else {
        return EmailRun::Failed("invalid email address".into());
    };
    let scan_id = crate::entity::scan_id("email", &email);
    let mut report = Report {
        entities: derive_entities(&email, &scan_id),
        outcomes: Vec::new(),
    };

    for source in sources::<T>() {
        match source(transport, &email, &scan_id, now_unix) {
            Ok((entities, outcome)) => {
                report.entities.extend(entities);
                report.outcomes.push(outcome);
            }
            Err(Error::Network(msg)) => return EmailRun::Network(msg),
            Err(err) => return EmailRun::Failed(err.to_string()),
        }
    }
    merge_by_uid(&mut report.entities);

    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => EmailRun::Printed { text, report },
        Err(msg) => EmailRun::Failed(msg),
    }
}

/// [`run`], then every indicator source for the address that `keys` enables.
#[must_use]
pub fn run_keyed<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    email: &str,
    now_unix: u64,
) -> EmailRun {
    let mut report = match run(transport, email, now_unix) {
        EmailRun::Printed { report, .. } => report,
        other => return other,
    };
    let Some(seed) = report.entities.first() else {
        return EmailRun::Failed("email lookup produced no entity".into());
    };
    let (email, scan_id) = (seed.raw_value.clone(), seed.scan_id.clone());
    if indicator_legs::planned(Indicator::Email(&email), keys).is_empty() {
        return match lookup_report::render(&report.entities, &report.outcomes) {
            Ok(text) => EmailRun::Printed { text, report },
            Err(msg) => EmailRun::Failed(msg),
        };
    }
    let legs = indicator_legs::run(
        transport,
        keys,
        Indicator::Email(&email),
        &scan_id,
        now_unix,
    );
    report.entities.extend(legs.entities);
    report.outcomes.extend(legs.outcomes);
    merge_by_uid(&mut report.entities);
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => EmailRun::Printed { text, report },
        Err(msg) => EmailRun::Failed(msg),
    }
}

fn derive_entities(email: &str, scan_id: &str) -> Vec<Entity> {
    let Some((local, domain)) = split_email(email) else {
        return Vec::new();
    };
    let (local, domain) = (local.as_str(), domain.as_str());
    let mut entities = Vec::new();
    add_seed(email, scan_id, &mut entities);

    if domain_is_specific(domain) {
        let mut entity = Entity::new(EntityKind::Domain, domain, CONF_DOMAIN, scan_id);
        entity.tag("derived");
        entity.tag("email-domain");
        entity.add_evidence(
            derived_evidence(scan_id, email, "domain")
                .with_attr("derived_domain", domain)
                .inferred(),
        );
        entities.push(entity);
    }

    if !is_role_localpart(local) {
        derive_usernames(local, domain, email, scan_id, &mut entities);
        derive_person(local, domain, email, scan_id, &mut entities);
    }
    entities
}

fn add_seed(email: &str, scan_id: &str, entities: &mut Vec<Entity>) {
    let mut entity = Entity::new(EntityKind::Email, email, 0.99, scan_id);
    entity.tag("seed");
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        "operator-supplied email selector",
    ));
    entities.push(entity);
}

fn derived_evidence(scan_id: &str, email: &str, derivation: &str) -> Evidence {
    Evidence::new(
        EvidenceProvenance::for_scan("email_parse", scan_id),
        format!("Derived from {email}"),
    )
    .with_attr("source_email", email)
    .with_attr("derivation", derivation)
}

fn domain_is_specific(domain: &str) -> bool {
    let registrable = registrable_domain(domain).unwrap_or_else(|| domain.to_string());
    !is_freemail(domain)
        && !is_freemail(&registrable)
        && !is_social_platform(domain)
        && !is_infrastructure_mail_domain(domain)
}

fn derive_usernames(
    local: &str,
    domain: &str,
    email: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    let local = local.to_ascii_lowercase();
    let detagged = local.split('+').next().unwrap_or(&local);
    let mut candidates = BTreeSet::new();
    candidates.insert(local.clone());
    candidates.insert(detagged.to_owned());

    let stripped = detagged.trim_end_matches(char::is_numeric);
    if stripped.len() > 2 {
        candidates.insert(stripped.to_owned());
    }

    let collapsed: String = detagged
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    if collapsed.len() > 2 {
        candidates.insert(collapsed);
    }

    candidates.extend(
        detagged
            .split(['.', '_', '-'])
            .filter(|part| part.len() > 2)
            .map(str::to_owned),
    );
    add_name_shape_variants(detagged, &mut candidates);

    let confidence = if is_freemail(domain) {
        CONF_USERNAME_FREEMAIL
    } else {
        CONF_USERNAME_CORPORATE
    };
    for candidate in candidates.into_iter().filter(|value| !value.is_empty()) {
        let mut entity = Entity::new(EntityKind::Username, &candidate, confidence, scan_id);
        entity.tag("derived");
        entity.add_evidence(
            derived_evidence(scan_id, email, "local_part")
                .with_attr("candidate", &candidate)
                .inferred(),
        );
        entities.push(entity);
    }
}

fn add_name_shape_variants(local: &str, candidates: &mut BTreeSet<String>) {
    let parts: Vec<&str> = local
        .split(['.', '_', '-'])
        .filter(|part| part.len() >= 2 && part.chars().all(char::is_alphabetic))
        .collect();
    if parts.len() != 2 {
        return;
    }
    let first = parts[0];
    let last = parts[1];
    let Some(first_initial) = first.chars().next() else {
        return;
    };
    let Some(last_initial) = last.chars().next() else {
        return;
    };
    candidates.insert(format!("{first_initial}{last}"));
    candidates.insert(format!("{first}{last_initial}"));
    candidates.insert(format!("{first_initial}.{last}"));
    candidates.insert(format!("{first}_{last}"));
    candidates.insert(format!("{first}-{last}"));
}

fn derive_person(
    local: &str,
    domain: &str,
    email: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    let detagged = local
        .split('+')
        .next()
        .unwrap_or(local)
        .to_ascii_lowercase();
    let parts: Vec<&str> = detagged.split(['.', '_', '-']).collect();
    if parts.len() != 2
        || parts
            .iter()
            .any(|part| part.len() < 2 || !part.chars().all(char::is_alphabetic))
    {
        return;
    }
    let confidence = if is_freemail(domain) {
        CONF_PERSON_FREEMAIL
    } else {
        CONF_PERSON_CORPORATE
    };
    let name = format!("{} {}", upper_first(parts[0]), upper_first(parts[1]));
    let mut entity = Entity::new(EntityKind::Person, &name, confidence, scan_id);
    entity.tag("derived");
    entity.tag("email-inferred");
    if is_freemail(domain) {
        entity.tag("freemail-inferred");
    }
    entity.add_evidence(
        derived_evidence(scan_id, email, "firstname.lastname")
            .with_attr("pattern", "firstname.lastname")
            .inferred(),
    );
    entities.push(entity);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::ScriptedTransport;

    use crate::source_outcome::SourceOutcomeKind;

    #[test]
    fn parse_accepts_one_email_and_save() {
        let parsed = EmailArgs::parse(&[
            "Jane.Doe@Example.com".into(),
            "--save".into(),
            "out.json".into(),
        ])
        .unwrap();
        assert_eq!(parsed.email, "jane.doe@example.com");
        assert_eq!(parsed.save, Some(PathBuf::from("out.json")));
    }

    #[test]
    fn parse_rejects_missing_extra_or_invalid_email() {
        assert!(EmailArgs::parse(&[]).is_err());
        assert!(EmailArgs::parse(&["a@example.com".into(), "b@example.com".into()]).is_err());
        assert!(EmailArgs::parse(&["not-an-email".into()]).is_err());
    }

    #[test]
    fn derivation_matches_legacy_high_value_shapes() {
        let entities = derive_entities("jane.doe@acme.example", "scan");
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain && entity.value == "acme.example")
        );
        for expected in ["janedoe", "jdoe", "jane_doe"] {
            assert!(
                entities.iter().any(|entity| {
                    entity.kind == EntityKind::Username && entity.raw_value == expected
                }),
                "missing raw username variant {expected}"
            );
        }
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Person && entity.value == "jane doe")
        );
    }

    #[test]
    fn role_mailbox_does_not_mint_person_or_username() {
        let entities = derive_entities("info@acme.example", "scan");
        assert!(
            !entities
                .iter()
                .any(|entity| { matches!(entity.kind, EntityKind::Person | EntityKind::Username) })
        );
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain)
        );
    }

    #[test]
    fn shared_split_contract_for_derivation() {
        let has_domain = |e: &str| {
            derive_entities(e, "scan")
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain)
        };
        assert!(!has_domain("Jane.Doe@Gmail.COM."));
        assert!(!has_domain("bounce@mailgun.net"));
        assert!(!has_domain("ops@eu.mailgun.net"));
        assert!(derive_entities("a@b@acme.example", "scan").is_empty());
        assert!(derive_entities("@acme.example", "scan").is_empty());
        assert!(has_domain(" Jane@Acme.Example "));
    }

    #[test]
    fn freemail_does_not_mint_provider_domain() {
        let entities = derive_entities("jane.doe@gmail.com", "scan");
        assert!(
            !entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Domain)
        );
        assert!(
            entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Person
                    && (entity.confidence - CONF_PERSON_FREEMAIL).abs() < f64::EPSILON)
        );
    }

    fn reply(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    /// Gravatar, Duolingo and keys.openpgp.org, in the order `run` asks them.
    fn three(gravatar: Response, duolingo: Response, openpgp: Response) -> ScriptedTransport {
        ScriptedTransport::new(vec![Ok(gravatar), Ok(duolingo), Ok(openpgp)])
    }

    fn nothing_found() -> ScriptedTransport {
        three(
            reply(404, ""),
            reply(200, r#"{"users":[]}"#),
            reply(404, "No key found"),
        )
    }

    #[test]
    fn run_combines_derivation_and_public_profile() {
        let body = r#"{"entry":[{"displayName":"Jane Doe","preferredUsername":"janed"}]}"#;
        let transport = three(
            reply(200, body),
            reply(200, r#"{"users":[]}"#),
            reply(404, ""),
        );
        match run(&transport, "jane.doe@acme.example", 1) {
            EmailRun::Printed { text, report } => {
                assert!(text.contains("gravatar\tsuccess"), "{text}");
                assert!(text.contains("lineage="), "{text}");
                assert!(
                    report
                        .entities
                        .iter()
                        .any(|entity| entity.kind == EntityKind::Username)
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn guesses_made_from_the_address_are_never_more_than_one_source() {
        // jane.doe@acme.example yields janedoe, jane_doe and jane-doe, which merge. None of them has
        // a source that corroborates: they are guesses from the address the operator typed.
        match run(&nothing_found(), "jane.doe@acme.example", 1) {
            EmailRun::Printed { report, .. } => {
                let guesses: Vec<_> = report
                    .entities
                    .iter()
                    .filter(|entity| entity.kind == EntityKind::Username)
                    .collect();
                assert!(guesses.len() > 1, "{guesses:?}");
                for guess in guesses {
                    assert_eq!(guess.source_count(), 1, "{}", guess.value);
                    assert!(
                        guess.c_effective() <= guess.confidence + 1e-9,
                        "{} was raised from {} to {}",
                        guess.value,
                        guess.confidence,
                        guess.c_effective()
                    );
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_public_profile_keeps_offline_derivations() {
        match run(&nothing_found(), "jane.doe@gmail.com", 1) {
            EmailRun::Printed { report, .. } => {
                assert_eq!(report.outcomes.len(), 3);
                assert!(
                    report
                        .outcomes
                        .iter()
                        .all(|outcome| outcome.kind == SourceOutcomeKind::ValidZero),
                    "{:?}",
                    report.outcomes
                );
                assert!(!report.entities.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn every_public_lookup_runs_and_reports_its_own_outcome() {
        let duolingo = r#"{"users":[{"id":7,"username":"janedoe_learns","name":"Jane Doe","creationDate":1500000000}]}"#;
        let key = "info:1:1\npub:ABCDEF0123456789:1:255:1600000000::\nuid:Jane%20Doe%20%3Cjane@work.example%3E:1600000000::\n";
        let transport = three(reply(404, ""), reply(200, duolingo), reply(200, key));
        let EmailRun::Printed { text, report } = run(&transport, "jane.doe@acme.example", 1) else {
            panic!("email run did not print");
        };
        let seen: Vec<String> = transport
            .seen
            .borrow()
            .iter()
            .map(|r| r.url.clone())
            .collect();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(seen[1].starts_with("https://www.duolingo.com/"), "{seen:?}");
        assert!(seen[2].starts_with("https://keys.openpgp.org/"), "{seen:?}");
        for line in [
            "gravatar\tvalid_zero",
            "duolingo\tsuccess",
            "openpgp_keys\tsuccess",
        ] {
            assert!(text.contains(line), "missing {line:?} in {text}");
        }
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.raw_value == "janedoe_learns")
        );
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "jane@work.example")
        );
        // The address's own guess and the two sources' "Jane Doe" are one person.
        let person = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person && e.value == "jane doe")
            .expect("person");
        assert!(person.source_count() >= 2, "{person:?}");
    }

    #[test]
    fn a_failing_source_does_not_hide_the_others() {
        // A drifted answer, not a 429: a rate limit would open the real host's shared pacing
        // circuit and suppress that host in every other test in this binary.
        let transport = three(
            reply(404, ""),
            reply(200, r#"{"errors":[]}"#),
            reply(404, ""),
        );
        let EmailRun::Printed { report, .. } = run(&transport, "jane.doe@acme.example", 1) else {
            panic!("email run did not print");
        };
        let kinds: Vec<_> = report
            .outcomes
            .iter()
            .map(|o| (o.module.as_str(), o.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("gravatar", SourceOutcomeKind::ValidZero),
                ("duolingo", SourceOutcomeKind::SchemaDrift),
                ("openpgp_keys", SourceOutcomeKind::ValidZero),
            ]
        );
    }

    #[test]
    fn keyed_sources_run_only_with_their_keys_and_never_echo_them() {
        let unkeyed = ScriptedTransport::new(vec![
            Ok(reply(404, "")),
            Ok(reply(200, r#"{"users":[]}"#)),
            Ok(reply(404, "No key found")),
            Ok(reply(200, r#"{"disposable":false}"#)),
        ]);
        match run_keyed(&unkeyed, &Keys::default(), "ada@example.com", 1) {
            EmailRun::Printed { text, .. } => {
                assert!(text.contains("kickbox\tvalid_zero"), "{text}");
            }
            other => panic!("{other:?}"),
        }
        let seen = unkeyed.seen.borrow();
        assert_eq!(
            seen.len(),
            4,
            "no key: only the keyless Kickbox check is added"
        );
        assert_eq!(
            seen[3].url, "https://open.kickbox.com/v1/disposable/example.com",
            "Kickbox is sent the domain, never the address"
        );
        drop(seen);

        let keys = Keys::parse(&format!(
            "{}=ipqs-test-key-0123456789\n{}=whoxy-test-key-0123456789\n{}=hunter-test-key-0123456789\n",
            crate::ipqs::KEY_SLOT,
            crate::whoxy::KEY_SLOT,
            crate::hunter::KEY_SLOT
        ))
        .unwrap();
        let transport = ScriptedTransport::new(vec![
            Ok(reply(404, "")),
            Ok(reply(200, r#"{"users":[]}"#)),
            Ok(reply(404, "No key found")),
            Ok(reply(200, r#"{"disposable":true}"#)),
            Ok(reply(
                200,
                r#"{"success":true,"valid":true,"disposable":true,"leaked":true,"fraud_score":40,"sanitized_email":"ada@example.com"}"#,
            )),
            Ok(reply(
                200,
                r#"{"status":1,"total_results":1,"search_result":[{"domain_name":"ada-lovelace.example"}]}"#,
            )),
            Ok(reply(
                200,
                r#"{"data":{"email":"ada@example.com","status":"valid","score":91,"sources":[]}}"#,
            )),
        ]);
        let (text, report) = match run_keyed(&transport, &keys, "ada@example.com", 1) {
            EmailRun::Printed { text, report } => (text, report),
            other => panic!("{other:?}"),
        };
        for source in ["kickbox", "ipqs", "whoxy", "hunter"] {
            assert!(text.contains(&format!("{source}\tsuccess")), "{text}");
        }
        assert!(!text.contains("test-key"), "{text}");
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.raw_value == "ada-lovelace.example")
        );
        let seen = transport.seen.borrow();
        let sent: Vec<(&str, bool)> = seen[4..]
            .iter()
            .map(|r| {
                let in_header = r.headers.iter().any(|(_, v)| v.contains("test-key"));
                (r.url.as_str(), in_header)
            })
            .collect();
        assert_eq!(
            sent,
            [
                (
                    "https://www.ipqualityscore.com/api/json/email?email=ada%40example.com",
                    true
                ),
                (
                    "https://api.whoxy.com/?reverse=whois&email=ada%40example.com&key=whoxy-test-key-0123456789",
                    false
                ),
                (
                    "https://api.hunter.io/v2/email-verifier?email=ada%40example.com",
                    true
                ),
            ],
            "each key goes only where its provider takes it"
        );
    }
}
